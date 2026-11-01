"""NetScan (clawhost :3000) : inventaire du réseau local, constats, risques, bande passante, routeur — lecture seule.

Identifiants : fichier JSON créé par l'utilisateur, mode 600 conseillé (aucune valeur par défaut, aucun compte créé ici) :
  ~/.config/infradash/netscan.json  {"url": "http://192.168.2.5:3000", "username": "…", "password": "…"}
Le mot de passe ne sert qu'à POST /api/auth/login ; le cookie de session renvoyé (JWT de 7 j) reste en mémoire, jamais
sur disque ni dans l'état publié. Ensuite uniquement des GET : jamais POST /api/scans (scan) ni PATCH /api/findings
(acquittement). NetScan bloque 15 min après 5 échecs de connexion : un refus d'identifiants suspend toute tentative
jusqu'à la modification du fichier, un 429 respecte Retry-After.
Intégration : loop("netscan", 60, netscan.run) ; état publié dans STATE slow.netscan.
"""
import json
import os
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

from .config import HOSTS
from .state import STATE

CRED_FILE = os.environ.get("INFRADASH_NETSCAN_FILE", os.path.expanduser("~/.config/infradash/netscan.json"))
DEFAULT_URL = f"http://{HOSTS['clawhost']['ip']}:3000"
TIMEOUT = 10
SLOW_EVERY = 300            # baux DHCP, scans, inventaire détaillé, débit WAN 24 h
COOKIE = "ns_session"
MAX_DEVICES = 300
MAX_FINDINGS = 200

_S = {"token": None, "blocked_mtime": None, "retry_after": 0, "slow_t": 0, "slow": {}, "fails": 0}


def _cred():
    """(config, erreur) — config = {url, username, password, mtime, warn}."""
    try:
        st = os.stat(CRED_FILE)
        with open(CRED_FILE) as f:
            d = json.load(f)
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError) as e:
        return None, f"fichier d'identifiants illisible ({type(e).__name__})"
    if not isinstance(d, dict) or not d.get("username") or not d.get("password"):
        return None, "fichier d'identifiants incomplet : « username » et « password » sont requis"
    url = str(d.get("url") or DEFAULT_URL).rstrip("/")
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        return None, "« url » doit commencer par http:// ou https://"
    warn = "le fichier d'identifiants est lisible par d'autres comptes (chmod 600 conseillé)" \
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO) else None
    return {"url": url, "username": str(d["username"]), "password": str(d["password"]), "mtime": st.st_mtime, "warn": warn}, None


class _Unauth(Exception):
    pass


def _req(url, path, body=None, token=None):
    headers = {"Accept": "application/json", "User-Agent": "InfraDash (lecture seule)"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Cookie"] = f"{COOKIE}={token}"
    r = urllib.request.Request(url + path, data=data, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(r, timeout=TIMEOUT) as resp:
            return json.loads(resp.read() or b"null"), resp.headers
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise _Unauth() from None
        raise


def _login(cfg):
    """Ouvre une session ; renvoie None ou un message d'erreur (sans jamais inclure le mot de passe)."""
    if _S["blocked_mtime"] == cfg["mtime"]:
        return "identifiants refusés par NetScan : corrigez le fichier, la connexion reprendra automatiquement"
    if time.time() < _S["retry_after"]:
        return f"NetScan limite les connexions : nouvel essai dans {int(_S['retry_after'] - time.time()) + 1} s"
    try:
        _, hdr = _req(cfg["url"], "/api/auth/login", {"username": cfg["username"], "password": cfg["password"]})
    except _Unauth:
        _S["blocked_mtime"] = cfg["mtime"]   # plus aucun essai avant modification du fichier (blocage anti-force brute)
        return "identifiants refusés par NetScan : corrigez le fichier, la connexion reprendra automatiquement"
    except urllib.error.HTTPError as e:
        if e.code == 429:
            try:
                _S["retry_after"] = time.time() + int(e.headers.get("Retry-After") or 900)
            except ValueError:
                _S["retry_after"] = time.time() + 900
            return "NetScan limite les connexions (trop d'essais) : nouvel essai plus tard"
        return f"connexion à NetScan : HTTP {e.code}"
    for c in hdr.get_all("Set-Cookie") or []:
        name, _, rest = c.partition("=")
        if name.strip() == COOKIE:
            _S["token"] = rest.split(";", 1)[0]
            _S["blocked_mtime"] = None
            return None
    return "connexion à NetScan : cookie de session absent de la réponse"


def _get(cfg, path):
    """GET authentifié ; une session expirée est rouverte une fois."""
    for attempt in (0, 1):
        if not _S["token"]:
            err = _login(cfg)
            if err:
                raise RuntimeError(err)
        try:
            return _req(cfg["url"], path, token=_S["token"])[0]
        except _Unauth:
            _S["token"] = None
            if attempt:
                raise RuntimeError("session NetScan refusée après reconnexion")
    return None


def _num(v, d=0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return d


def _devices(graph, hosts):
    by_id = {h.get("id"): h for h in hosts or [] if isinstance(h, dict)}
    out = []
    for n in (graph or {}).get("nodes") or []:
        if not isinstance(n, dict) or n.get("isVirtual"):
            continue
        h = by_id.get(n.get("id")) or {}
        out.append({
            "id": n.get("id"), "label": n.get("label") or n.get("hostnameRouter") or n.get("ip") or n.get("mac"),
            "named": bool(n.get("hasLabel")), "ip": n.get("ip"), "mac": n.get("mac"), "vendor": n.get("vendor"),
            "type": n.get("deviceType") or "unknown", "known": bool(n.get("isKnown")), "infra": bool(n.get("isInfrastructure")),
            "risk": n.get("riskLevel") or "safe", "risk_score": h.get("riskScore"),
            "risk_factors": [f"{f.get('label')} (+{f.get('points')})" for f in (h.get("riskFactors") or [])[:6] if isinstance(f, dict)],
            "ports": int(_num(n.get("openPorts"))), "services": [s for s in n.get("detectedServices") or [] if isinstance(s, str)][:8],
            "mbps": round(_num(n.get("bandwidthMbps")), 2), "switch_port": n.get("switchPort"),
            "conn": n.get("connectionType") or "unknown", "up": n.get("upStatus") or "offline",
            "seen_min": n.get("lastSeenMinutesAgo"), "router_name": n.get("hostnameRouter"),
            "first_seen": h.get("firstSeen"), "last_seen": h.get("lastSeen"),
        })
    rank = {"high": 0, "medium": 1, "low": 2, "safe": 3}
    out.sort(key=lambda d: (rank.get(d["risk"], 4), d["known"], d["up"] != "up", str(d["label"]).lower()))
    return out[:MAX_DEVICES]


def _findings(rows):
    sev = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out = []
    for f in rows or []:
        if not isinstance(f, dict) or f.get("acknowledged") or f.get("autoResolvedAt"):
            continue
        c = _cve_detail(f) if f.get("category") == "cve_critical" else None
        out.append({"id": f.get("id"), "severity": f.get("severity"), "category": f.get("category"), "title": f.get("title"),
                    "detail": (c.get("description") if c else f.get("detail") or "")[:300], "host": f.get("hostLabel"), "ip": f.get("ip"),
                    "created": f.get("createdAt"),
                    "cve": {k: c.get(k) for k in ("cveId", "cvssScore", "product", "version", "nvdUrl")} if c else None})
    out.sort(key=lambda f: (sev.get(f["severity"], 9), str(f["created"] or "")), reverse=False)
    return out[:MAX_FINDINGS]


# --------------------------------------------------------------------------------------------- intégration intelligente
# Présence en direct = table ARP du homelab (DNS de tout le réseau, donc quasi tous les appareils) ; identité = NetScan,
# rattachée par MAC (ses IP datent de son dernier scan) ; noms des machines déjà suivies = InfraDash.
_CATS = [  # (catégorie, mots-clés dans nom / fabricant / type NetScan)
    ("Réseau", ("router", "switch", "d-link", "dgs-", "ubiquiti", "tp-link", "netgear")),
    ("Multimédia", ("yamaha", "apple tv", "shield", "nvidia", "bose", "webos", "lgwebos", "audiocast", "fuchsia", "google-home",
                    "chromecast", "samsung", "sonos", "roku", "rx-a", "ampli", "tv", "nintendo")),
    ("Maison connectée", ("philips", "lighting", "lumi", "xiaomi", "dreame", "nuki", "espressif", "tuya", "smart innovation", "indoorcam",
                          "cam", "rmmini", "hangzhou", "quectel", "brw", "printer", "s380", "shapes", "iot", "sm-l300", "0017886")),
    ("Mobiles", ("phone", "iphone", "ipad", "pixel", "android", "galaxy")),
    ("Ordinateurs & serveurs", ("server", "pc", "mac", "win-", "qemu", "vm", "nas", "homelab", "clawhost", "home assistant", "raspberry")),
]
_INFRA = {"nas": "NAS Unraid", "homelab": "Homelab", "clawhost": "clawhost", "ha": "Home Assistant (VM)", "box": "Routeur / Box", "pc": "PC fixe Jeff"}
_OWN_MACS = set()


def _own_macs():
    if not _OWN_MACS:
        try:
            for i in os.listdir("/sys/class/net"):
                with open(f"/sys/class/net/{i}/address") as f:
                    _OWN_MACS.add(f.read().strip().lower())
        except OSError:
            pass
    return _OWN_MACS


def _cat(*words):
    """Première source qui parle (nom, puis type NetScan, puis fabricant) : « PC JEFF » d'un fabricant de routeurs reste un PC."""
    for w in words:
        t = str(w or "").lower()
        for c, keys in _CATS:
            if t and any(k in t for k in keys):
                return c
    return "Autres"


def _ts(v):
    try:
        return time.mktime(time.strptime(str(v)[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")) - time.timezone
    except (TypeError, ValueError):
        return None


def _merge_lan(ns_devices):
    from .config import KNOWN_IPS
    live = {d["mac"].lower(): d for d in (STATE.get("slow", "lan") or {}).get("devices") or [] if d.get("mac")}
    ns = {d["mac"].lower(): d for d in ns_devices or [] if d.get("mac")}
    own = _own_macs()
    out = []
    for mac in set(live) | set(ns):
        if mac in own:
            continue
        lv, nd = live.get(mac), ns.get(mac) or {}
        ip = (lv or {}).get("ip") or nd.get("ip")
        infra = (KNOWN_IPS.get((lv or {}).get("ip") or "") or (None, None))[0] if lv else None
        infra = infra if infra in _INFRA else None
        name = (_INFRA.get(infra) if infra else None) or (nd.get("label") if nd.get("named") or nd.get("known") else None) \
            or nd.get("router_name") or nd.get("label") or (lv or {}).get("name") or ((lv or {}).get("vendor") or "").rstrip("?") or "Appareil inconnu"
        vendor = nd.get("vendor") or (lv or {}).get("vendor") or ""
        flags = []
        if lv and not nd and not infra:
            flags.append("nouveau")             # présent mais jamais vu par NetScan (hors machines déjà suivies)
        if lv and nd and nd.get("ip") and nd["ip"] != lv["ip"]:
            flags.append("ip")
        known = bool(infra or nd.get("known"))
        if not known:
            flags.append("à identifier")
        out.append({"mac": mac, "ip": ip, "alive": bool(lv and lv.get("alive")), "name": name, "vendor": vendor, "infra": infra,
                    "cat": "Ordinateurs & serveurs" if infra in ("nas", "homelab", "clawhost", "ha", "pc") else "Réseau" if infra == "box"
                    else _cat(name, nd.get("type") if nd.get("type") not in ("server", "unknown") else "", vendor),
                    "known": known, "risk": nd.get("risk") or "safe", "services": nd.get("services") or [], "ns_ip": nd.get("ip"),
                    "ns_type": nd.get("type"), "in_ns": bool(nd), "flags": flags, "ns_id": nd.get("id"),
                    "ns_conn": nd.get("conn"), "ns_mbps": nd.get("mbps"), "switch_port": nd.get("switch_port"),
                    "risk_score": nd.get("risk_score"), "risk_factors": nd.get("risk_factors") or []})
    out.sort(key=lambda d: (not d["alive"], d["cat"], str(d["name"]).lower()))
    return out


def _cve_detail(f):
    try:
        d = json.loads(f.get("detail") or "")
        return d if isinstance(d, dict) and d.get("cveId") else None
    except ValueError:
        return None


def _digest(findings, lan, scans, stats, router):
    """Synthèse : constats NetScan regroupés par appareil, CVE écartées avec la raison, état de NetScan lui-même."""
    from .config import KNOWN_IPS
    by_ip = {h["ip"]: {"name": _INFRA["homelab"], "ip": h["ip"], "infra": "homelab", "alive": True}   # le homelab lui-même (absent de son ARP)
             for h in [{"ip": ip} for ip, (k, _) in KNOWN_IPS.items() if k == "homelab"]}
    for d in lan:
        if d.get("ns_ip"):
            by_ip.setdefault(d["ns_ip"], d)
    groups, other = {}, []
    for f in findings:
        dev = by_ip.get(f.get("ip")) or {}
        c = f.get("cve")
        if c and c.get("cveId"):
            k = (dev.get("mac") or f.get("ip"), c.get("product"), str(c.get("version")))
            g = groups.setdefault(k, {"device": dev.get("name") or f.get("host"), "ip": dev.get("ip") or f.get("ip"), "mac": dev.get("mac"),
                                      "infra": dev.get("infra"), "alive": dev.get("alive", False), "product": c.get("product"),
                                      "version": str(c.get("version")), "cves": [], "max_cvss": 0})
            g["cves"].append(c["cveId"])
            g["max_cvss"] = max(g["max_cvss"], float(c.get("cvssScore") or 0))
        else:
            other.append(dict(f, device=dev.get("name") or f.get("host"), dev_ip=dev.get("ip"), infra=dev.get("infra"), alive=dev.get("alive", False)))
    active, dropped = [], []
    for g in groups.values():
        g["n"] = len(g["cves"])
        g["cves"] = sorted(set(g["cves"]), reverse=True)
        g["precise"] = bool(re.match(r"^\d+\.\d+", g["version"]))
        if g["infra"] in ("nas", "homelab", "clawhost"):
            g["why"] = (f"version imprécise (« {g['product']} {g['version']} ») sur une machine dont InfraDash vérifie la version réelle"
                        if not g["precise"] else "machine suivie par InfraDash : sa version réelle est vérifiée dans le plan")
            dropped.append(g)
        elif not g["alive"]:
            g["why"] = "appareil absent du réseau aujourd'hui (constat du dernier scan NetScan)"
            dropped.append(g)
        else:
            g["why"] = None if g["precise"] else (f"version imprécise (« {g['product']} {g['version']} ») : NetScan liste toutes les CVE de la "
                                                   f"branche {g['version']}.x ; vérifier la version réelle sur l'appareil avant d'agir")
            active.append(g)
    attention = []
    for f in other:
        cat, sev = f.get("category"), f.get("severity")
        if cat == "unknown_device" or not f.get("alive"):
            continue   # appareils à identifier : comptés à part ; appareils absents : constats périmés
        if f.get("infra") in ("nas", "homelab", "clawhost") and cat in ("open_database", "smb_exposed"):
            continue   # déjà couvert (expositions du plan de vulnérabilités) ou normal (le NAS est un serveur de fichiers)
        attention.append({"title": f.get("title"), "device": f.get("device"), "ip": f.get("dev_ip") or f.get("ip"), "severity": sev,
                          "category": cat, "detail": f.get("detail")})
    # état de NetScan lui-même
    done = [s for s in scans if s.get("status") == "done" and s.get("finishedAt")]
    last_done = _ts(done[0]["finishedAt"]) if done else None
    stuck = [s for s in scans if s.get("status") in ("running", "pending") and (_ts(s.get("startedAt")) or time.time()) < time.time() - 3 * 3600]
    issues = []
    if last_done and time.time() - last_done > 3 * 86400:
        issues.append({"level": "warn", "title": f"NetScan ne scanne plus depuis {int((time.time() - last_done) / 86400)} jours",
                       "detail": f"Dernier scan terminé le {time.strftime('%d/%m/%Y', time.localtime(last_done))}"
                       + (f" ; un scan lancé le {time.strftime('%d/%m', time.localtime(_ts(stuck[0]['startedAt'])))} sur "
                          f"{stuck[0].get('subnetText')} est bloqué « en cours »" if stuck else "")
                       + ". NetScan ne lance aucun scan tout seul (SCAN_INTERVAL_MIN n'est pas utilisé) : son inventaire (IP, appareils en ligne, constats) est périmé.",
                       "fix": "Sur clawhost (compte jeff) : SUBNET_ALLOWLIST=192.168.2.0/24 dans le .env de netscan, recréer worker et web, "
                              "puis planifier un scan régulier (cron qui ajoute un scan_job). Mode opératoire dans le README d'InfraDash."})
    if stuck and any(s.get("subnetText") and not str(s["subnetText"]).startswith("192.168.2.") for s in stuck):
        issues.append({"level": "info", "title": f"Scan NetScan sur un autre sous-réseau ({stuck[0]['subnetText']})",
                       "detail": "Le LAN est en 192.168.2.0/24 : ce sous-réseau n'existe pas ici, le worker attend sans fin.",
                       "fix": "Corriger SUBNET_ALLOWLIST dans le .env de netscan (192.168.2.0/24)."})
    if router.get("paired") and not router.get("connection"):
        issues.append({"level": "info", "title": "NetScan ne reçoit pas les données du routeur",
                       "detail": "L'intégration du routeur ASUS (192.168.2.1, SSH :2211) est active mais ne renvoie rien : débit WAN et baux DHCP vides.",
                       "fix": "Sur clawhost : docker logs netscan-worker 2>&1 | grep -i router | tail -20 pour voir l'erreur (identifiants ou SSH du routeur)."})
    return {"active": sorted(active, key=lambda g: -g["max_cvss"]), "dropped": sorted(dropped, key=lambda g: -g["n"]),
            "attention": attention[:12], "issues": issues, "last_scan_ok": last_done,
            "n_cve": sum(g["n"] for g in groups.values()), "n_cve_dropped": sum(g["n"] for g in dropped)}


def run():
    """Point d'entrée du runner (toutes les 60 s) ; ne lève jamais d'exception vers le runner."""
    cfg, cerr = _cred()
    base = {"t": time.time(), "file": CRED_FILE, "url": (cfg or {}).get("url") or DEFAULT_URL}
    if not cfg:
        _S["token"] = None
        STATE.set("slow", "netscan", dict(base, configured=False, ok=False, error=cerr))
        STATE.set("slow", "lan_devices", {"t": time.time(), "devices": _merge_lan([]), "netscan": False})
        return
    prev = STATE.get("slow", "netscan") or {}
    try:
        stats = _get(cfg, "/api/stats") or {}
        graph = _get(cfg, "/api/graph") or {}
        found = _get(cfg, "/api/findings?acknowledged=false") or []
        top_risk = _get(cfg, "/api/risk/top") or []
        top_bw = _get(cfg, "/api/bandwidth/top") or []
        router = _get(cfg, "/api/router/status") or {}
        now = time.time()
        if now - _S["slow_t"] >= SLOW_EVERY or not _S["slow"]:
            _S["slow"] = {"hosts": _get(cfg, "/api/hosts") or [], "dhcp": _get(cfg, "/api/router/dhcp") or [],
                          "scans": (_get(cfg, "/api/scans") or [])[:15], "wan": _get(cfg, "/api/router/wan?period=24h") or {}}
            _S["slow_t"] = now
        sl = _S["slow"]
        devices = _devices(graph, sl["hosts"])
        fnd = _findings(found)
        st = dict(base, configured=True, ok=True, error=None, warn=cfg["warn"], user=cfg["username"],
                  stats={k: stats.get(k) for k in ("totalHosts", "known", "unknown", "infrastructure", "totalScans", "lastScanAt", "risk")},
                  open_findings={s: sum(1 for f in fnd if f["severity"] == s) for s in ("high", "medium", "low", "info")},
                  devices=devices, findings=fnd,
                  top_risk=[{k: r.get(k) for k in ("hostId", "hostname", "riskScore", "riskLevel", "openFindings")} for r in top_risk[:5]],
                  top_bw=[{k: r.get(k) for k in ("hostId", "hostname", "in_mbps", "out_mbps", "sampledAt")} for r in top_bw[:5]],
                  router={"paired": bool(router.get("paired")), "connection": router.get("connection"), "sampled": router.get("sampledAt"),
                          "wan": {k: sl["wan"].get(k) for k in ("series", "peak_down_mbps", "peak_up_mbps", "resolution")} if isinstance(sl["wan"], dict) else {},
                          "dhcp": [{k: x.get(k) for k in ("mac", "ip", "hostname", "leaseRemaining", "isStatic", "hostLabel")}
                                   for x in sl["dhcp"] if isinstance(x, dict)][:200]},
                  scans=[{k: x.get(k) for k in ("startedAt", "finishedAt", "status", "hostsFound", "triggeredBy", "subnetText")}
                         for x in sl["scans"] if isinstance(x, dict)])
        lan = _merge_lan(devices)
        st["digest"] = _digest(fnd, lan, st["scans"], st["stats"], st["router"])
        _S["fails"] = 0
        STATE.set("slow", "netscan", st)
        STATE.set("slow", "lan_devices", {"t": time.time(), "devices": lan, "netscan": True})
    except Exception as e:  # noqa — NetScan arrêté, clawhost injoignable, réponse inattendue : on garde les dernières données
        _S["fails"] += 1
        msg = str(e) if isinstance(e, RuntimeError) else f"NetScan injoignable : {type(e).__name__}: {e}"
        keep = {k: v for k, v in prev.items() if k not in ("ok", "error", "t")} if prev.get("configured") else {}
        STATE.set("slow", "netscan", dict(keep, **base, configured=True, ok=False, error=msg[:300], stale_since=prev.get("t") if prev.get("ok") else prev.get("stale_since")))
        STATE.set("slow", "lan_devices", {"t": time.time(), "devices": _merge_lan(keep.get("devices") or []), "netscan": bool(keep)})
