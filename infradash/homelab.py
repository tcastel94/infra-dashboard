"""Collecte locale sur le homelab (lecture seule, sans droits root)."""
import glob
import json
import os
import re
import time
import urllib.request
from datetime import datetime

from .config import CADVISOR_URL, CONTAINER_INFO, HOMELAB_CONTAINER_SCHEDULES, HOMELAB_STATIC_CRONS
from .procfs import HostMetrics, parse_ss_peers, read_local_sections
from .state import STATE
from .util import TZ, RateTracker, Ring, redact, run

HM = HostMetrics()
CRATES = RateTracker()
SSRATES = RateTracker()
CHIST = {}
_spec = {"t": 0, "map": {}}
_known_containers = {}


def _http_json(url, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def temps():
    out = {}
    for h in glob.glob("/sys/class/hwmon/hwmon*"):
        try:
            name = open(f"{h}/name").read().strip()
            for t in glob.glob(f"{h}/temp*_input"):
                v = int(open(t).read()) / 1000
                lbl_f = t.replace("_input", "_label")
                lbl = open(lbl_f).read().strip() if os.path.exists(lbl_f) else name
                key = name if lbl == name else f"{name}:{lbl}"
                out[key] = max(v, out.get(key, 0))
        except (OSError, ValueError):
            continue
    cpu = max([v for k, v in out.items() if k.startswith("coretemp")] or [0])
    return {"sensors": out, "cpu": cpu, "nvme": out.get("nvme:Composite", out.get("nvme", 0))}


def fast():
    m = HM.update(read_local_sections())
    m["temps"] = temps()
    st = os.statvfs("/")
    m["root_fs"] = {"size": st.f_blocks * st.f_frsize, "free": st.f_bavail * st.f_frsize}
    m["hist"] = {k: r.list()[-150:] for k, r in HM.hist.items()}
    STATE.set("live", "homelab", m)
    # Flux TCP établis (pairs + octets)
    peers = parse_ss_peers(run(["ss", "-tniH", "state", "established"], timeout=5))
    now = time.time()
    agg = {}
    for (pip, lport, pport), (bout, bin_) in peers.items():
        k = f"{pip}|{lport}|{pport}"
        ro = SSRATES.rate("o" + k, bout, now)
        ri = SSRATES.rate("i" + k, bin_, now)
        a = agg.setdefault(pip, {"out": 0.0, "in": 0.0, "conns": 0, "ports": {}})
        a["out"] += ro
        a["in"] += ri
        a["conns"] += 1
        svc = lport if lport < pport else pport
        a["ports"][svc] = a["ports"].get(svc, 0) + 1
    STATE.set("live", "homelab_peers", agg)


def containers():
    now = time.time()
    if now - _spec["t"] > 60:
        spec = _http_json(f"{CADVISOR_URL}/api/v2.0/spec?type=docker&recursive=true")
        _spec["map"] = {k: {"name": (v.get("aliases") or [k])[0], "image": v.get("image", ""),
                            "created": v.get("creation_time"),
                            "labels": {lk: lv for lk, lv in (v.get("labels") or {}).items()
                                       if lk.startswith("com.docker.compose.")}} for k, v in spec.items()}
        _spec["t"] = now
    stats = _http_json(f"{CADVISOR_URL}/api/v2.0/stats?type=docker&recursive=true&count=1")
    out = []
    seen = set()
    for cid, samples in stats.items():
        if not samples:
            continue
        s = samples[-1]
        sp = _spec["map"].get(cid, {"name": cid[-12:], "image": "", "labels": {}})
        name = sp["name"]
        seen.add(name)
        cpu_ns = s.get("cpu", {}).get("usage", {}).get("total", 0)
        cpu = CRATES.rate(f"cpu:{name}", cpu_ns, now) / 1e9 * 100
        rxb = sum(i.get("rx_bytes", 0) for i in (s.get("network", {}).get("interfaces") or []))
        txb = sum(i.get("tx_bytes", 0) for i in (s.get("network", {}).get("interfaces") or []))
        rx, tx = CRATES.rate(f"rx:{name}", rxb, now), CRATES.rate(f"tx:{name}", txb, now)
        mem = s.get("memory", {}).get("working_set", 0)
        h = CHIST.setdefault(name, {"cpu": Ring(120), "net": Ring(120)})
        h["cpu"].add(now, round(cpu, 1))
        h["net"].add(now, round(rx + tx))
        desc, cat = CONTAINER_INFO.get(name, ("", "autre"))
        out.append({"name": name, "image": sp["image"], "cpu": round(cpu, 1), "mem": mem, "rx": round(rx), "tx": round(tx),
                    "rx_total": rxb, "tx_total": txb, "created": sp.get("created"), "state": "running",
                    "project": sp["labels"].get("com.docker.compose.project", ""), "desc": desc, "cat": cat,
                    "spark": [v for _, v in h["cpu"].list()[-40:]], "nspark": [v for _, v in h["net"].list()[-40:]]})
    # Événements : apparition / disparition / redémarrage (pas au premier passage)
    first = not _known_containers
    for c in out:
        prev = _known_containers.get(c["name"])
        if not first and prev and prev != c["created"]:
            STATE.event("warn", "homelab", f"Conteneur recréé : {c['name']}", c["image"], "container")
        elif not first and prev is None:
            STATE.event("info", "homelab", f"Nouveau conteneur : {c['name']}", c["image"], "container")
        _known_containers[c["name"]] = c["created"]
    for name in list(_known_containers):
        if name not in seen:
            STATE.event("crit", "homelab", f"Conteneur arrêté : {name}", "", "container")
            del _known_containers[name]
    out.sort(key=lambda c: -c["cpu"])
    STATE.set("live", "homelab_containers", out)


def slow():
    info = {}
    # Timers systemd
    timers = []
    try:
        for t in json.loads(run(["systemctl", "list-timers", "--all", "--output=json", "--no-pager"]) or "[]"):
            timers.append({"unit": t.get("unit"), "activates": t.get("activates"),
                           "next": (t.get("next") or 0) / 1e6 or None, "last": (t.get("last") or 0) / 1e6 or None})
    except ValueError:
        pass
    info["timers"] = timers
    # Crons lisibles
    crons = []
    for path in ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*")):
        try:
            for line in open(path):
                line = line.strip()
                if not line or line.startswith("#") or re.match(r"^[A-Z_]+=", line):
                    continue
                f = line.split()
                if f[0].startswith("@"):
                    crons.append({"schedule": f[0], "user": f[1], "command": redact(" ".join(f[2:])), "source": path})
                elif len(f) >= 7:
                    crons.append({"schedule": " ".join(f[:5]), "user": f[5], "command": redact(" ".join(f[6:])), "source": path})
        except OSError:
            continue
    user_cron = run(["crontab", "-l"])
    for line in user_cron.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not re.match(r"^[A-Z_]+=", line):
            f = line.split()
            sched = f[0] if f[0].startswith("@") else " ".join(f[:5])
            cmd = " ".join(f[1:]) if f[0].startswith("@") else " ".join(f[5:])
            crons.append({"schedule": sched, "user": "jeff", "command": redact(cmd), "source": "crontab jeff"})
    info["crons"] = crons + [dict(c) for c in HOMELAB_STATIC_CRONS] + [dict(c) for c in HOMELAB_CONTAINER_SCHEDULES]
    info["run_parts"] = {d: sorted(os.path.basename(p) for p in glob.glob(f"/etc/cron.{d}/*") if not p.endswith(".placeholder"))
                         for d in ("hourly", "daily", "weekly", "monthly")}
    # Montages
    try:
        fm = json.loads(run(["findmnt", "-J", "-b", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,SIZE,USED,AVAIL",
                             "-t", "ext4,vfat,xfs,btrfs,cifs,smb3,nfs,nfs4,fuse.sshfs,fuse.rclone"]) or "{}")
        flat = []

        def walk(nodes):
            for n in nodes:
                flat.append({k: n.get(k) for k in ("target", "source", "fstype", "size", "used", "avail")})
                walk(n.get("children", []))
        walk(fm.get("filesystems", []))
        info["mounts"] = flat
    except ValueError:
        info["mounts"] = []
    # Ports à l'écoute
    ports = set()
    for line in run(["ss", "-tlnH"]).splitlines():
        p = line.split()
        if len(p) >= 4:
            addr, port = p[3].rsplit(":", 1)
            ports.add((addr.strip("[]"), int(port)))
    info["listen"] = sorted([{"addr": a, "port": p} for a, p in ports], key=lambda x: x["port"])
    info["reboot_required"] = os.path.exists("/var/run/reboot-required")
    try:
        info["reboot_pkgs"] = open("/var/run/reboot-required.pkgs").read().split()
    except OSError:
        info["reboot_pkgs"] = []
    info["kernel"] = os.uname().release
    info["who"] = [l.split()[0] for l in run(["who"]).splitlines() if l.strip()]
    STATE.set("slow", "homelab", info)


def apt_check():
    out = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=60)
    pk = [l.split()[1] for l in out.splitlines() if l.startswith("Inst ")]
    sec = [l.split()[1] for l in out.splitlines() if l.startswith("Inst ") and "security" in l.lower()]
    STATE.set("slow", "homelab_apt", {"pending": len(pk), "security": len(sec), "packages": pk[:40], "t": time.time()})


def dns_check():
    t0 = time.time()
    out = run(["dig", "+short", "+time=2", "+tries=1", "@127.0.0.1", "debian.org", "A"], timeout=5)
    ok = bool(out.strip())
    ms = round((time.time() - t0) * 1000)
    t1 = time.time()
    blocked = run(["dig", "+short", "+time=2", "+tries=1", "@127.0.0.1", "doubleclick.net", "A"], timeout=5).strip()
    hist = STATE.get("live", "dns_hist") or []
    hist = (hist + [[round(time.time()), ms if ok else None]])[-240:]
    STATE.set("live", "dns_hist", hist)
    STATE.set("live", "dns", {"ok": ok, "ms": ms, "blocking": blocked in ("0.0.0.0", "", "::"),
                              "block_ms": round((time.time() - t1) * 1000), "t": time.time()})
    prev = STATE.get("live", "_dns_prev_ok")
    if prev is not None and prev != ok:
        STATE.event("crit" if not ok else "ok", "homelab", "DNS AdGuard " + ("en panne" if not ok else "rétabli"), "", "dns")
    STATE.set("live", "_dns_prev_ok", ok)
