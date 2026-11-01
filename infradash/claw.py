"""clawhost : sondes réseau externes + collecte par SSH en lecture seule si l'accès InfraDash est installé
(tools/clawhost-ro-setup.sh : clé ~/.ssh/infradash_clawhost limitée au homelab, sans terminal ni tunnel, et à la seule
commande imposée ~/.infradash/ro.sh qui accepte « metrics » et « inventory »)."""
import os
import re
import socket
import time
import urllib.request

from .config import HOSTS
from .procfs import SECTIONS_CMD, HostMetrics, split_sections
from .ssh import SSH
from .state import STATE
from .util import Ring, run

H = HOSTS["clawhost"]
RO_KEY = os.path.expanduser("~/.ssh/infradash_clawhost")
SSHC = SSH(H["ssh"]["user"], H["ssh"]["host"], H["ssh"]["port"], key=RO_KEY if os.path.exists(RO_KEY) else None)
RO_MODE = os.path.exists(RO_KEY)   # clé dédiée : commandes nommées interprétées par ro.sh côté clawhost
HM = HostMetrics()
LAT = {p["port"]: Ring(240) for p in H["probes"]}
PING = Ring(240)
_prev = {"up": None, "ports": {}, "ssh_try": 0}


def _tcp(host, port, timeout=2.0):
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.time() - t0) * 1000, 1)
    except OSError:
        return None


def _http(host, port, path, timeout=3):
    t0 = time.time()
    try:
        req = urllib.request.Request(f"http://{host}:{port}{path}", headers={"User-Agent": "infradash"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(300).decode(errors="ignore")
            return r.status, round((time.time() - t0) * 1000, 1), body
    except urllib.error.HTTPError as e:
        return e.code, round((time.time() - t0) * 1000, 1), ""
    except Exception:
        return None, None, ""


def ping(ip):
    out = run(["ping", "-c1", "-W1", ip], timeout=3)
    for tok in out.split():
        if tok.startswith("time="):
            return float(tok[5:])
    return None


def probes():
    ip = H["ip"]
    now = time.time()
    res = {"ip": ip, "probes": [], "t": now}
    pms = ping(ip)
    PING.add(now, pms)
    res["ping"] = pms
    up_count = 0
    for p in H["probes"]:
        d = {"port": p["port"], "name": p["name"]}
        if p["kind"] == "http":
            code, ms, body = _http(ip, p["port"], p.get("path", "/"))
            d.update({"code": code, "ms": ms, "up": code is not None and code < 500})
            if p["port"] == 18789 and body.startswith("{"):
                d["body"] = body[:120]
        else:
            ms = _tcp(ip, p["port"])
            d.update({"ms": ms, "up": ms is not None})
        LAT[p["port"]].add(now, d.get("ms"))
        d["hist"] = [v for _, v in LAT[p["port"]].list()[-60:]]
        up_count += d["up"]
        if _prev["ports"].get(p["port"]) is not None and _prev["ports"][p["port"]] != d["up"]:
            STATE.event("ok" if d["up"] else "warn", "clawhost", f"{p['name']} ({p['port']}) " + ("répond" if d["up"] else "ne répond plus"), "", "probe")
        _prev["ports"][p["port"]] = d["up"]
        res["probes"].append(d)
    up = up_count > 0 or pms is not None
    res["up"] = up
    res["ping_hist"] = [v for _, v in PING.list()[-60:]]
    # anciennes IP encore référencées ?
    res["old_ip_alive"] = {o: ping(o) is not None for o in H.get("old_ips", [])}
    if _prev["up"] is not None and _prev["up"] != up:
        STATE.event("ok" if up else "crit", "clawhost", "clawhost " + ("en ligne" if up else "injoignable"), ip, "host")
    _prev["up"] = up
    # Collecte complète si la clé SSH du homelab est autorisée (essai toutes les 10 min, sinon silencieux)
    if SSHC.ok or now - _prev["ssh_try"] > 600:
        _prev["ssh_try"] = now
        out = SSHC.run("metrics" if RO_MODE else
                       SECTIONS_CMD + "; echo @@docker; docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null", timeout=10)
        if out:
            sec = split_sections(out)
            m = HM.update(sec)
            m["hist"] = {k: r.list()[-150:] for k, r in HM.hist.items()}
            m["containers"] = [dict(zip(("name", "image", "status"), l.split("|"))) for l in sec.get("docker", []) if "|" in l]
            res["metrics"] = m
    res["ssh_access"] = bool(SSHC.ok)
    STATE.set("live", "clawhost", res)


def inventory():
    """Inventaire système de clawhost (toutes les 30 min, accès InfraDash requis) : version, mises à jour en attente,
    redémarrage requis, services en échec, disques, conteneurs. Publié dans STATE slow.claw_ssh."""
    if not RO_MODE:
        STATE.set("slow", "claw_ssh", {"installed": False, "t": time.time()})
        return
    out = SSHC.run("inventory", timeout=40)
    if not out or "@@sys" not in out:
        prev = STATE.get("slow", "claw_ssh") or {}
        STATE.set("slow", "claw_ssh", dict(prev, installed=True, ok=False, t=time.time(),
                                            error=(SSHC.last_error or "pas de réponse")[:200]))
        return
    sec = split_sections(out)
    sysv = sec.get("sys", []) + [""] * 6
    mem = {k: int(re.sub(r"\D", "", v) or 0) * 1024 for k, v in (l.split(":", 1) for l in sec.get("mem", []) if ":" in l)}
    df = []
    for l in sec.get("df", []):
        p = l.split()
        if len(p) >= 6 and p[1].isdigit():
            df.append({"fs": p[0], "size": int(p[1]), "used": int(p[2]), "free": int(p[3]), "mount": p[5]})
    upg = [l.split()[0] for l in sec.get("upgradable", []) if l.strip()]
    pk = [l.split("\t") for l in sec.get("dpkg", []) if l.count("\t") >= 4]
    dk = [dict(zip(("name", "image", "state", "status"), l.split("\t"))) for l in sec.get("docker", []) if l.count("\t") >= 3]
    STATE.set("slow", "claw_ssh", {
        "installed": True, "ok": True, "error": None, "t": time.time(), "kernel": sysv[0], "os": sysv[1],
        "uptime_s": float(sysv[2] or 0) if re.match(r"^[\d.]+$", sysv[2] or "") else None, "load": sysv[3], "cpus": sysv[4],
        "mem_total": mem.get("MemTotal"), "mem_avail": mem.get("MemAvailable"), "df": df,
        "reboot_required": (sec.get("reboot") or ["non"])[0].strip() == "oui",
        "failed_units": [u for u in sec.get("failed", []) if u.strip()], "upgradable": upg, "n_upgradable": len(upg),
        "packages": {p[1]: p[2] for p in pk}, "n_packages": len(pk), "containers": dk,
        "docker_access": not any("non accessible" in l for l in sec.get("docker", [])),
    })
