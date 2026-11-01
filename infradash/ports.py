"""Ports par machine : utilisés (qui écoute, quel conteneur), réservés par des conteneurs arrêtés, conflits, ports libres.

- NAS Unraid : une commande SSH fixe en lecture seule (`ss -tulnp`, `docker ps -a`, `docker inspect` des PortBindings, vitesse des cartes réseau).
  Les ports « réservés » sont ceux de conteneurs arrêtés : ils bloqueraient leur redémarrage si un autre service prenait le port.
- Homelab : `ss -tulnp` local + ports publiés lus dans /opt/homelab/docker-compose.yml.
- clawhost (accès SSH restreint) : vue « extérieure » — connexion TCP depuis le homelab sur les ports 1-10000 et quelques ports connus.
Intégration : loop("ports", 120, ports.run) ; état slow.ports ; API GET /api/ports/free.
"""
import concurrent.futures as cf
import ipaddress
import json
import re
import socket
import time

from .config import CONTAINER_INFO, HOSTS
from .state import STATE
from .util import run as sh

NAS_CMD = ("echo @@ss; ss -tulnpH; "
           "echo @@pids; for p in $(ss -tulnpH | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do echo \"$p $(grep -o '[0-9a-f]\\{64\\}' /proc/$p/cgroup 2>/dev/null | head -1)\"; done; "
           "echo @@dock; docker ps -a --no-trunc --format '{{.ID}}|{{.Names}}|{{.State}}|{{.Image}}'; "
           "echo @@bind; docker inspect $(docker ps -aq) --format '{{.Name}}|{{.State.Status}}|{{.HostConfig.NetworkMode}}|{{json .HostConfig.PortBindings}}'; "
           "echo @@link; for i in eth0 eth1 bond0 wlan0; do [ -d /sys/class/net/$i ] && echo \"$i $(cat /sys/class/net/$i/speed 2>/dev/null) $(cat /sys/class/net/$i/operstate 2>/dev/null) $(cat /sys/class/net/$i/duplex 2>/dev/null)\"; done; "
           "echo @@range; cat /proc/sys/net/ipv4/ip_local_port_range")
KNOWN = {22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 111: "RPC", 139: "SMB (NetBIOS)", 443: "HTTPS", 445: "SMB", 631: "Impression (CUPS)", 2049: "NFS",
         3306: "MySQL/MariaDB", 5353: "mDNS", 5432: "PostgreSQL", 5037: "ADB", 6379: "Redis", 8086: "InfluxDB", 8428: "VictoriaMetrics", 9100: "node-exporter",
         11434: "Ollama", 41641: "Tailscale", 5900: "VNC (machine virtuelle)", 3389: "RDP", 27017: "MongoDB", 1883: "MQTT", 2375: "API Docker non protégée"}
DB_PORTS = {3306, 5432, 5433, 5439, 6379, 6380, 16379, 27017, 9200, 11211, 2375}
BANDS = [("Web courantes 3000-3999", 3000, 3999), ("5000-5999", 5000, 5999), ("7000-7999", 7000, 7999), ("8000-8999", 8000, 8999),
         ("9000-9999", 9000, 9999), ("Hautes 10000-19999", 10000, 19999)]
SCAN_PORTS = sorted(set(range(1, 10001)) | {18789, 18790, 32400, 41641, 8300})
_ADDR = re.compile(r"^(.*):(\d+)$")
_last = {"claw": 0}


def _bind(addr):
    a = addr.strip("[]")
    if a in ("0.0.0.0", "*", "::", ""):
        return "all"
    try:
        ip = ipaddress.ip_address(a.split("%")[0])
    except ValueError:
        return "other"
    if ip.is_loopback:
        return "local"
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return "tailscale"
    if ip.is_private and str(ip).startswith("192.168."):
        return "lan"
    return "docker" if ip.is_private else "other"


def _sections(out):
    sec, cur = {}, None
    for line in (out or "").splitlines():
        if line.startswith("@@"):
            cur = line[2:].strip()
            sec[cur] = []
        elif cur is not None and line.strip():
            sec[cur].append(line.rstrip())
    return sec


def _parse_ss(lines):
    """ss -tulnpH -> [{proto, addr, port, bind, process, pid}] (IPv4 et IPv6 fusionnés par port/processus)."""
    seen, out = {}, []
    for line in lines:
        p = line.split()
        if len(p) < 5 or p[0] not in ("tcp", "udp"):
            continue
        m = _ADDR.match(p[4])
        if not m:
            continue
        pm = re.search(r'users:\(\("([^"]*)",pid=(\d+)', line)
        proc, pid = (pm.group(1), int(pm.group(2))) if pm else ("", None)
        key = (p[0], int(m.group(2)), _bind(m.group(1)), proc)
        if key in seen:
            continue
        e = {"proto": p[0], "addr": m.group(1).strip("[]"), "port": int(m.group(2)), "bind": key[2], "process": proc, "pid": pid}
        seen[key] = e
        out.append(e)
    return out


def _service(port, container, process):
    if container and container in CONTAINER_INFO:
        return CONTAINER_INFO[container][0]
    return KNOWN.get(port) or ""


def _npm_map(ip):
    """port -> [domaines] publiés sur Internet via Nginx Proxy Manager vers cette machine."""
    out = {}
    for e in (STATE.get("slow", "nas_sched") or {}).get("npm") or []:
        if str(e.get("backend", "")).startswith(ip):
            out.setdefault(int(e["port"]), []).append(e["domain"])
    return out


def _free(used, ephemeral, extra_lo=1024):
    """Plages libres de [1024, début des ports éphémères[, et libres par bande usuelle."""
    lo, hi = extra_lo, ephemeral[0] - 1
    rng, start = [], None
    for p in range(lo, hi + 2):
        if p <= hi and p not in used:
            start = p if start is None else start
        elif start is not None:
            rng.append([start, p - 1])
            start = None
    bands = []
    for label, a, b in BANDS:
        fr = [p for p in range(a, b + 1) if p not in used and not (ephemeral[0] <= p <= ephemeral[1])]
        bands.append({"label": label, "from": a, "to": b, "free": len(fr), "total": b - a + 1, "sample": fr[:12]})
    return {"ranges": rng[:80], "n_ranges": len(rng), "bands": bands, "ephemeral": list(ephemeral), "n_free": sum(b - a + 1 for a, b in rng)}


def free_ports(host, lo, hi, n=20):
    """Ports libres entre lo et hi pour une machine (API GET /api/ports/free) ; bornes et nombre plafonnés."""
    d = ((STATE.get("slow", "ports") or {}).get("hosts") or {}).get(host)
    if not d or not d.get("ok"):
        return {"error": "machine inconnue ou pas encore relevée"}
    lo, hi, n = max(1, int(lo)), min(65535, int(hi)), max(1, min(int(n), 200))
    used = {e["port"] for e in d["ports"]}
    eph = d["free"]["ephemeral"]
    out = [p for p in range(lo, hi + 1) if p not in used and not (eph[0] <= p <= eph[1])][:n]
    return {"host": host, "from": lo, "to": hi, "ports": out, "ephemeral": eph}


def _conflicts(entries):
    out, by = [], {}
    for e in entries:
        by.setdefault((e["proto"], e["port"]), []).append(e)
    for (proto, port), es in sorted(by.items(), key=lambda x: x[0][1]):
        live = [e for e in es if e["state"] == "écoute"]
        res = [e for e in es if e["state"] == "réservé"]
        for r in res:
            others = [x for x in live if x.get("owner") != r.get("owner")]
            if others:
                o = others[0]
                out.append({"level": "crit", "port": port, "proto": proto,
                            "text": f"Le conteneur « {r['owner']} » (arrêté) réserve le port {port}/{proto}, déjà pris par {o.get('owner') or o.get('process') or 'un autre service'} : "
                                    f"il ne pourra pas redémarrer tant que ce port est occupé."})
        rs = {r["owner"] for r in res}
        if len(rs) > 1:
            out.append({"level": "warn", "port": port, "proto": proto,
                        "text": f"Les conteneurs arrêtés {', '.join(sorted(rs))} réservent tous le port {port}/{proto} : un seul pourra démarrer."})
    return out


def nas():
    from . import nas as _nasmod
    ssh = _nasmod.SSHC
    out = ssh.run(NAS_CMD, timeout=40)
    if out is None:
        return {"ok": False, "error": f"NAS injoignable en SSH ({ssh.last_error or 'pas de réponse'})"}
    sec = _sections(out)
    ids = {}
    for line in sec.get("dock", []):
        p = line.split("|")
        if len(p) >= 4:
            ids[p[0][:64]] = p[1]
    ct = {}
    for line in sec.get("dock", []):
        p = line.split("|")
        if len(p) >= 4:
            ct[p[1]] = {"state": p[2], "image": p[3], "bindings": [], "netmode": ""}
    for line in sec.get("bind", []):
        p = line.split("|", 3)
        if len(p) < 4:
            continue
        name = p[0].lstrip("/")
        if name not in ct:
            continue
        ct[name]["netmode"] = p[2]
        try:
            for cport, lst in (json.loads(p[3]) or {}).items():
                for b in lst or []:
                    if b.get("HostPort"):
                        ct[name]["bindings"].append((b.get("HostIp") or "0.0.0.0", int(b["HostPort"]), cport.split("/")[-1], cport.split("/")[0]))
        except (ValueError, AttributeError):
            pass
    pid2ct = {}
    for line in sec.get("pids", []):
        p = line.split()
        if len(p) == 2 and p[1] in ids:
            pid2ct[int(p[0])] = ids[p[1]]
    listeners = _parse_ss(sec.get("ss", []))
    bound = {}   # (proto, hostport) -> conteneur (publié par docker-proxy)
    for name, c in ct.items():
        for hip, hp, proto, _ in c["bindings"]:
            bound[(proto, hp)] = name
    npm = _npm_map(HOSTS["nas"]["ip"])
    entries, live_keys = [], set()
    for l in listeners:
        owner = pid2ct.get(l["pid"]) or (bound.get((l["proto"], l["port"])) if l["process"] in ("docker-proxy", "") or l["pid"] is None else None)
        if owner is None and l["process"] == "docker-proxy":
            owner = bound.get((l["proto"], l["port"]))
        kind = "docker" if owner else "vm" if l["process"].startswith("qemu") else "système"
        live_keys.add((l["proto"], l["port"]))
        entries.append({"port": l["port"], "proto": l["proto"], "bind": l["bind"], "addr": l["addr"], "process": l["process"], "owner": owner, "kind": kind,
                        "state": "écoute", "service": _service(l["port"], owner, l["process"]), "domains": npm.get(l["port"]) if l["proto"] == "tcp" else None})
    for name, c in ct.items():
        if c["state"] == "running":
            continue
        for hip, hp, proto, cport in c["bindings"]:
            entries.append({"port": hp, "proto": proto, "bind": _bind(hip), "addr": hip, "process": "", "owner": name, "kind": "docker", "state": "réservé",
                            "service": _service(hp, name, ""), "domains": None, "stopped": c["state"]})
    for e in entries:
        e["db"] = e["port"] in DB_PORTS
    rng = [int(x) for x in (sec.get("range") or ["32768 60999"])[0].split()][:2]
    used = {e["port"] for e in entries}
    link = {}
    for line in sec.get("link", []):
        p = line.split()
        if p and p[0] != "wlan0":
            link = {"iface": p[0], "speed_mbps": int(p[1]) if len(p) > 1 and p[1].lstrip("-").isdigit() and int(p[1]) > 0 else None,
                    "type": "wired", "duplex": p[3] if len(p) > 3 else None}
            break
    wl = next((l.split() for l in sec.get("link", []) if l.startswith("wlan0")), None)
    host_nets = sorted(n for n, c in ct.items() if c["netmode"] == "host")
    entries.sort(key=lambda e: (e["port"], e["proto"]))
    return {"ok": True, "source": "ssh", "ports": entries, "conflicts": _conflicts(entries), "free": _free(used, rng), "link": link,
            "wlan": {"present": bool(wl), "state": next((x for x in (wl or [])[1:] if x in ("up", "down", "unknown")), None)}, "host_network": host_nets,
            "n_containers": len(ct), "n_stopped": sum(1 for c in ct.values() if c["state"] != "running")}


def homelab():
    out = sh(["ss", "-tulnpH"])
    listeners = _parse_ss(out.splitlines())
    from .vulns import _parse_ports_compose
    pub, _ = _parse_ports_compose("/opt/homelab/docker-compose.yml")
    cmap = {}
    for svc, lst in pub.items():
        for hip, hp in lst:
            try:
                cmap[int(hp.split("-")[0])] = svc
            except ValueError:
                pass
    entries = []
    for l in listeners:
        owner = cmap.get(l["port"]) if l["process"] in ("", "docker-proxy") else None
        entries.append({"port": l["port"], "proto": l["proto"], "bind": l["bind"], "addr": l["addr"], "process": l["process"], "owner": owner,
                        "kind": "docker" if owner else "système", "state": "écoute", "service": _service(l["port"], owner, l["process"]) or
                        ({7070: "InfraDash", 3001: "Uptime Kuma", 3002: "Grafana", 8080: "AdGuard Home (admin)", 8085: "Dozzle"}.get(l["port"], "")),
                        "domains": None, "db": l["port"] in DB_PORTS})
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
            rng = [int(x) for x in f.read().split()][:2]
    except (OSError, ValueError):
        rng = [32768, 60999]
    entries.sort(key=lambda e: (e["port"], e["proto"]))
    used = {e["port"] for e in entries}
    from .lan import local_link
    return {"ok": True, "source": "ss local + docker-compose", "ports": entries, "conflicts": [], "free": _free(used, rng),
            "link": local_link() or {}, "host_network": [], "n_containers": len(pub), "n_stopped": 0}


def _connect(ip, port):
    s = socket.socket()
    s.settimeout(0.4)
    try:
        return port if s.connect_ex((ip, port)) == 0 else None
    except OSError:
        return None
    finally:
        s.close()


def clawhost():
    ip = HOSTS["clawhost"]["ip"]
    with cf.ThreadPoolExecutor(200) as ex:
        found = sorted(p for p in ex.map(lambda p: _connect(ip, p), SCAN_PORTS) if p)
    names = {p["port"]: p["name"] for p in HOSTS["clawhost"].get("probes", [])}
    entries = [{"port": p, "proto": "tcp", "bind": "all", "addr": ip, "process": "", "owner": None, "kind": "vu du réseau", "state": "écoute",
                "service": names.get(p) or KNOWN.get(p, ""), "domains": None, "db": p in DB_PORTS} for p in found]
    return {"ok": True, "source": "connexion TCP depuis le homelab (1-10000 + ports connus) : le SSH de clawhost est restreint, pas de nom de processus",
            "ports": entries, "conflicts": [], "free": _free(set(found), (32768, 60999)), "link": {}, "host_network": [], "n_containers": 0, "n_stopped": 0}


def run():
    """Relevé toutes les 2 min (NAS, homelab) ; clawhost toutes les 10 min (scan TCP)."""
    prev = (STATE.get("slow", "ports") or {}).get("hosts") or {}
    hosts = {}
    for key, fn in (("nas", nas), ("homelab", homelab)):
        try:
            hosts[key] = fn()
        except Exception as e:  # noqa — on garde le dernier relevé réussi
            hosts[key] = dict(prev.get(key) or {}, ok=bool((prev.get(key) or {}).get("ok")), error=f"{type(e).__name__}: {e}"[:200])
    now = time.time()
    if now - _last["claw"] > 900 or "clawhost" not in prev:
        try:
            hosts["clawhost"] = clawhost()
            _last["claw"] = now
        except Exception as e:  # noqa
            hosts["clawhost"] = dict(prev.get("clawhost") or {}, error=f"{type(e).__name__}: {e}"[:200])
    else:
        hosts["clawhost"] = prev["clawhost"]
    for k, v in hosts.items():
        v["label"] = HOSTS[k]["label"]
        v["ip"] = HOSTS[k]["ip"]
        v["t"] = v.get("t") or now
    if hosts["nas"].get("link"):
        STATE.set("slow", "host_links", {"nas": hosts["nas"]["link"], **({"homelab": hosts["homelab"]["link"]} if hosts["homelab"].get("link") else {})})
    STATE.set("slow", "ports", {"t": now, "hosts": hosts})
