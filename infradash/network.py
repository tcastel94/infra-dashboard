"""Réseau : Tailscale, voisins LAN, exposition publique (NPM), certificats TLS, latences, speedtest."""
import json
import socket
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .config import HOSTS, KNOWN_IPS, VM_URL
from .state import STATE
from .util import RateTracker, Ring, run

TSR = RateTracker()
LAT = {k: Ring(240) for k in ("box", "nas", "clawhost", "internet")}
_prev = {"ts_online": {}, "public": {}}

OUI = {  # préfixes MAC courants -> fabricant (aide à reconnaître les appareils)
    "52:54:00": "VM (QEMU/KVM)", "d8:bb:c1": "Micro-Star (NAS)", "cc:28:aa": "ASUSTek", "00:17:88": "Philips Hue",
    "44:07:0b": "Google", "1c:53:f9": "Google", "f0:23:b9": "Ezviz/Hikvision", "48:b0:2d": "NVIDIA", "b8:bc:5b": "Samsung",
    "6c:05:d3": "Ubiquiti?", "7c:d9:5c": "Google", "14:ea:63": "Apple?", "04:17:b6": "Apple?", "c8:7f:54": "ASUSTek",
    "98:b7:85": "Shenzhen", "00:a0:de": "Yamaha", "4c:cc:6a": "Micro-Star", "f4:8c:eb": "D-Link",
    "74:d4:23": "Apple?", "30:fd:38": "Google", "ac:44:f2": "Yamaha", "98:e2:55": "Nintendo",
}


def tailscale():
    try:
        j = json.loads(run(["tailscale", "status", "--json"], timeout=6) or "{}")
    except ValueError:
        return
    now = time.time()
    peers = []
    for p in (j.get("Peer") or {}).values():
        h = p.get("HostName")
        key = p.get("PublicKey", h)
        rx, tx = p.get("RxBytes", 0), p.get("TxBytes", 0)
        d = {"host": h, "dns": (p.get("DNSName") or "").split(".")[0], "os": p.get("OS"), "online": p.get("Online"),
             "ip": (p.get("TailscaleIPs") or [""])[0], "addr": p.get("CurAddr") or "", "relay": p.get("Relay") or "",
             "direct": bool(p.get("CurAddr")), "last_seen": p.get("LastSeen"), "key_expiry": p.get("KeyExpiry"),
             "rx": round(TSR.rate("rx" + key, rx, now)), "tx": round(TSR.rate("tx" + key, tx, now)),
             "rx_total": rx, "tx_total": tx, "exit_node": p.get("ExitNodeOption", False)}
        peers.append(d)
        prev = _prev["ts_online"].get(key)
        if prev is not None and prev != d["online"]:
            STATE.event("info", "tailscale", f"{d['dns'] or h} " + ("connecté" if d["online"] else "déconnecté"), "Tailscale", "tailscale")
        _prev["ts_online"][key] = d["online"]
    self_ = j.get("Self") or {}
    STATE.set("live", "tailscale", {"self": {"host": self_.get("HostName"), "ip": (self_.get("TailscaleIPs") or [""])[0],
                                             "key_expiry": self_.get("KeyExpiry"), "online": self_.get("Online")},
                                    "tailnet": (j.get("CurrentTailnet") or {}).get("Name", ""),
                                    "magic_dns": (j.get("CurrentTailnet") or {}).get("MagicDNSSuffix", ""),
                                    "peers": sorted(peers, key=lambda x: (not x["online"], x["dns"] or "")), "t": now})


def neighbors():
    devs = []
    for line in run(["ip", "-4", "neigh"]).splitlines():
        p = line.split()
        if len(p) >= 4 and p[0].startswith("192.168.2."):
            mac = p[4] if len(p) > 4 and p[3] == "lladdr" else ""
            state = p[-1]
            known = KNOWN_IPS.get(p[0])
            devs.append({"ip": p[0], "mac": mac, "state": state, "vendor": OUI.get(mac[:8], ""),
                         "name": known[1] if known else "", "alive": state in ("REACHABLE", "DELAY", "STALE", "PROBE")})
    devs.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    STATE.set("slow", "lan", {"devices": devs, "count": sum(1 for d in devs if d["mac"]), "t": time.time()})


def latency():
    from .claw import ping
    now = time.time()
    res = {}
    for k, ip in (("box", "192.168.2.1"), ("nas", HOSTS["nas"]["ip"]), ("clawhost", HOSTS["clawhost"]["ip"]), ("internet", "1.1.1.1")):
        ms = ping(ip)
        LAT[k].add(now, ms)
        res[k] = {"ms": ms, "hist": [v for _, v in LAT[k].list()[-90:]],
                  "loss": round(100 * sum(1 for _, v in LAT[k].list()[-60:] if v is None) / max(1, len(LAT[k].list()[-60:])))}
    STATE.set("live", "latency", res)


def _cert_days(host, timeout=5):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
        exp = datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z")
        issuer = dict(x[0] for x in c.get("issuer", []))
        return (exp - datetime.now(timezone.utc).replace(tzinfo=None)).days, issuer.get("organizationName", "")
    except Exception as e:
        return None, type(e).__name__


def public_endpoints():
    sched = STATE.get("slow", "nas_sched") or {}
    npm = sched.get("npm") or []
    out = []
    now = time.time()
    for e in npm:
        dom = e["domain"]
        t0 = time.time()
        code = None
        try:
            req = urllib.request.Request(f"https://{dom}/", headers={"User-Agent": "infradash-healthcheck"}, method="GET")
            with urllib.request.urlopen(req, timeout=6, context=ssl.create_default_context()) as r:
                code = r.status
        except urllib.error.HTTPError as ex:
            code = ex.code
        except Exception:
            code = None
        ms = round((time.time() - t0) * 1000)
        prev = _prev["public"].get(dom, {})
        days, issuer = (prev.get("cert_days"), prev.get("issuer")) if now - prev.get("cert_t", 0) < 6 * 3600 else (None, None)
        cert_t = prev.get("cert_t", 0)
        if days is None and now - cert_t > 6 * 3600:
            days, issuer = _cert_days(dom)
            cert_t = now
        backend_ip = e["backend"]
        known = KNOWN_IPS.get(backend_ip)
        d = {**e, "code": code, "ms": ms, "ok": code is not None and code < 500, "cert_days": days, "issuer": issuer,
             "cert_t": cert_t, "backend_host": known[0] if known else ("nas" if backend_ip.startswith("192.168.2.3") else "")}
        if prev and prev.get("ok") != d["ok"]:
            STATE.event("ok" if d["ok"] else "crit", "internet", f"{dom} " + ("de nouveau en ligne" if d["ok"] else f"en erreur ({code})"),
                        f"→ {backend_ip}:{e['port']}", "public")
        _prev["public"][dom] = d
        out.append(d)
    STATE.set("slow", "public", {"endpoints": out, "t": now})


def _ip(s):
    """Ne garde qu'une adresse IP valide (une sortie d'erreur de dig ne doit jamais atteindre l'interface)."""
    import ipaddress
    try:
        return str(ipaddress.ip_address((s or "").strip()))
    except ValueError:
        return ""


def wan_ip():
    ip = _ip((run(["dig", "+short", "+time=3", "+tries=1", "myip.opendns.com", "@resolver1.opendns.com"], timeout=8).strip().splitlines() or [""])[-1])
    npm = (STATE.get("slow", "nas_sched") or {}).get("npm") or []
    probe = next((e["domain"] for e in npm if e["backend"].startswith("192.168.2.3")), "vault.jposyno.eu")
    dom = run(["dig", "+short", "+time=3", "+tries=1", probe, "@1.1.1.1"], timeout=8).strip().splitlines()
    STATE.set("slow", "wan", {"ip": ip, "domain_ip": _ip(dom[-1]) if dom else "", "domain": probe, "t": time.time()})


def homepage_links():
    """Vérifie que les liens internes de la page Homepage (NAS) répondent encore."""
    from .claw import _tcp
    urls = (STATE.get("slow", "nas_sched") or {}).get("homepage_urls") or []
    out = []
    for u in urls:
        p = urllib.parse.urlparse(u)
        ms = _tcp(p.hostname, p.port or 80, timeout=1.5)
        out.append({"url": u, "host": p.hostname, "port": p.port, "ok": ms is not None, "ms": ms})
    STATE.set("slow", "homepage_links", {"links": out, "t": time.time()})


def _vm(q):
    url = f"{VM_URL}/api/v1/query?" + urllib.parse.urlencode({"query": q})
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read()).get("data", {}).get("result", [])


def speedtest():
    def last(metric):
        r = _vm(f"last_over_time({metric}[6h])")
        return float(r[0]["value"][1]) if r else None
    url = f"{VM_URL}/api/v1/query_range?" + urllib.parse.urlencode({
        "query": "max_over_time(speedtest_download_bits_per_second[3h])", "start": time.time() - 14 * 86400,
        "end": time.time(), "step": "3h"})
    with urllib.request.urlopen(url, timeout=8) as r:
        dl = json.loads(r.read()).get("data", {}).get("result", [])
    url2 = url.replace("speedtest_download_bits_per_second", "speedtest_upload_bits_per_second")
    with urllib.request.urlopen(url2, timeout=8) as r:
        ul = json.loads(r.read()).get("data", {}).get("result", [])
    url3 = url.replace("speedtest_download_bits_per_second", "speedtest_ping_latency_milliseconds")
    with urllib.request.urlopen(url3, timeout=8) as r:
        pg = json.loads(r.read()).get("data", {}).get("result", [])
    STATE.set("slow", "speedtest", {
        "download": last("speedtest_download_bits_per_second"), "upload": last("speedtest_upload_bits_per_second"),
        "ping": last("speedtest_ping_latency_milliseconds"),
        "hist_dl": dl[0]["values"] if dl else [], "hist_ul": ul[0]["values"] if ul else [], "hist_ping": pg[0]["values"] if pg else [],
        "t": time.time()})
