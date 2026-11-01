"""Parseurs /proc communs (homelab local et hôtes distants) et calcul des métriques dérivées."""
import re
import time

from .util import RateTracker, Ring

SECTIONS_CMD = ("echo @@stat; cat /proc/stat; echo @@mem; cat /proc/meminfo; echo @@load; cat /proc/loadavg; "
                "echo @@net; cat /proc/net/dev; echo @@disk; cat /proc/diskstats; echo @@up; cat /proc/uptime")


def split_sections(text):
    out, cur = {}, None
    for line in (text or "").splitlines():
        if line.startswith("@@"):
            cur = line[2:].strip()
            out[cur] = []
        elif cur:
            out[cur].append(line)
    return out


def read_local_sections():
    out = {}
    for name, path in (("stat", "/proc/stat"), ("mem", "/proc/meminfo"), ("load", "/proc/loadavg"),
                       ("net", "/proc/net/dev"), ("disk", "/proc/diskstats"), ("up", "/proc/uptime")):
        try:
            with open(path) as f:
                out[name] = f.read().splitlines()
        except OSError:
            out[name] = []
    return out


_SKIP_IF = re.compile(r"^(lo|veth|vnet|br-|docker|virbr|tunl|vxlan|wlan|wlp|dummy|bond|shim)")
_DISK_RX = re.compile(r"^(sd[a-z]+|nvme\d+n\d+|md\d+|vd[a-z]+|mmcblk\d+)$")


class HostMetrics:
    """Garde l'état précédent et calcule CPU %, RAM, débits réseau et disque."""

    def __init__(self):
        self.rates = RateTracker()
        self.prev_cpu = None
        self.hist = {k: Ring(900) for k in ("cpu", "mem", "rx", "tx", "load", "dread", "dwrite")}

    def update(self, sec):
        now = time.time()
        res = {}
        # CPU
        for line in sec.get("stat", []):
            if line.startswith("cpu "):
                v = list(map(int, line.split()[1:]))
                idle = v[3] + (v[4] if len(v) > 4 else 0)
                total = sum(v[:8])
                if self.prev_cpu:
                    dt, di = total - self.prev_cpu[0], idle - self.prev_cpu[1]
                    res["cpu"] = round(100 * (1 - di / dt), 1) if dt > 0 else 0
                    iow = v[4] - self.prev_cpu[2]
                    res["iowait"] = round(100 * iow / dt, 1) if dt > 0 else 0
                self.prev_cpu = (total, idle, v[4])
            elif line.startswith("cpu"):
                res["cores"] = res.get("cores", 0) + 1
        # Mémoire
        mem = {}
        for line in sec.get("mem", []):
            parts = line.split()
            if len(parts) >= 2:
                mem[parts[0].rstrip(":")] = int(parts[1]) * 1024
        if mem:
            tot, avail = mem.get("MemTotal", 0), mem.get("MemAvailable", 0)
            res["mem_total"], res["mem_avail"] = tot, avail
            res["mem_used"] = tot - avail
            res["mem"] = round(100 * (tot - avail) / tot, 1) if tot else 0
            res["mem_cache"] = mem.get("Cached", 0)
            res["swap_total"], res["swap_used"] = mem.get("SwapTotal", 0), mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)
        # Charge
        if sec.get("load"):
            p = sec["load"][0].split()
            res["load"] = [float(p[0]), float(p[1]), float(p[2])]
            res["procs"] = p[3]
        if sec.get("up"):
            res["uptime"] = float(sec["up"][0].split()[0])
        # Réseau
        ifaces, rx_tot, tx_tot = {}, 0.0, 0.0
        for line in sec.get("net", [])[2:]:
            if ":" not in line:
                continue
            name, data = line.split(":", 1)
            name = name.strip()
            f = data.split()
            rxb, txb = int(f[0]), int(f[8])
            rx = self.rates.rate(f"rx:{name}", rxb, now)
            tx = self.rates.rate(f"tx:{name}", txb, now)
            ifaces[name] = {"rx": round(rx), "tx": round(tx), "rx_total": rxb, "tx_total": txb,
                            "errs": int(f[2]) + int(f[10]), "drop": int(f[3]) + int(f[11])}
            if not _SKIP_IF.match(name) and not name.startswith("tailscale"):
                rx_tot += rx
                tx_tot += tx
        res["ifaces"] = ifaces
        res["rx"], res["tx"] = round(rx_tot), round(tx_tot)
        # Disques
        disks, rd_tot, wr_tot = {}, 0.0, 0.0
        for line in sec.get("disk", []):
            f = line.split()
            if len(f) < 14 or not _DISK_RX.match(f[2]):
                continue
            name = f[2]
            r = self.rates.rate(f"dr:{name}", int(f[5]) * 512, now)
            w = self.rates.rate(f"dw:{name}", int(f[9]) * 512, now)
            busy = self.rates.rate(f"db:{name}", int(f[12]), now) / 10  # ms/s -> %
            disks[name] = {"read": round(r), "write": round(w), "busy": round(min(busy, 100), 1)}
            if not name.startswith("md"):
                rd_tot += r
                wr_tot += w
        res["disks"] = disks
        res["dread"], res["dwrite"] = round(rd_tot), round(wr_tot)
        for k in self.hist:
            if k in res:
                self.hist[k].add(now, res[k] if k != "load" else res["load"][0])
        res["t"] = now
        return res


def parse_ss_peers(text):
    """`ss -tniH` -> {peer_ip: (bytes_out, bytes_in, [ports])} pour les sockets TCP établies."""
    peers = {}
    lines = (text or "").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line and not line[0].isspace() and i + 1 < len(lines) and lines[i + 1][:1].isspace():
            cols = line.split()
            info = lines[i + 1]
            i += 2
            if len(cols) < 4:
                continue
            local, peer = cols[-2], cols[-1]
            pip, pport = peer.rsplit(":", 1)
            lip, lport = local.rsplit(":", 1)
            pip = pip.strip("[]").replace("::ffff:", "")
            m_out = re.search(r"bytes_acked:(\d+)", info)
            m_in = re.search(r"bytes_received:(\d+)", info)
            key = (pip, int(lport) if lport.isdigit() else 0, int(pport) if pport.isdigit() else 0)
            peers[key] = (int(m_out.group(1)) if m_out else 0, int(m_in.group(1)) if m_in else 0)
        else:
            i += 1
    return peers
