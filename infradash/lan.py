"""Réseau local : découverte active, registre des appareils (nom, icône, note), type de liaison Ethernet / Wi-Fi.

- Découverte : balayage ICMP + résolution ARP du noyau du /24 du homelab (aucun outil externe, aucun droit root), puis, pour les
  appareils présents, latence, nom DNS inverse et — sur demande — sondage TCP d'une liste fixe de ports et lecture de bannières
  (SSH, titre de page web). Le sous-réseau n'est pas un paramètre : seul le réseau directement relié au homelab peut être scanné.
- Registre : data/devices.json (MAC -> nom, icône, famille, note, « de confiance », date de première vue). Au tout premier passage,
  tous les appareils présents sont enregistrés comme « existants » ; les suivants déclenchent un événement « Nouvel appareil ».
- Liaison : manuel > interface locale (machines suivies) > faisceau d'indices (NetScan, adresse MAC aléatoire, latence et gigue).
  Le débit de liaison Wi-Fi réel n'est connu que du routeur : il n'est jamais inventé.
Intégration : loop("lan.discover", 300, lan.discover), loop("lan.publish", 15, lan.publish) ; état slow.lan_inventory, slow.lan_scan.
"""
import concurrent.futures as cf
import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time

from .config import DATA_DIR, HOSTS, KNOWN_IPS
from .state import STATE

REG_FILE = os.path.join(DATA_DIR, "devices.json")
HOME_IP = HOSTS["homelab"]["ip"]
SUBNET = ipaddress.ip_network(HOME_IP + "/24", strict=False)
MIN_GAP = 20                       # s entre deux scans demandés
DEEP_EVERY = 6 * 3600              # sondage de ports automatique
ICONS = ["server", "nas", "pc", "laptop", "phone", "tablet", "watch", "tv", "speaker", "camera", "printer", "bulb", "plug", "thermo",
         "gamepad", "router", "wifi", "lock", "home", "cloud", "claw", "unknown"]
CATS = ["Réseau", "Multimédia", "Maison connectée", "Mobiles", "Ordinateurs & serveurs", "Autres"]
PROBE_PORTS = [21, 22, 23, 25, 53, 80, 81, 111, 139, 443, 445, 515, 548, 554, 631, 1400, 1883, 2049, 3000, 3389, 5000, 5001, 5555,
               5900, 6379, 7000, 8000, 8008, 8009, 8080, 8081, 8123, 8443, 8883, 9000, 9100, 32400, 62078]
HTTP_PORTS = (80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8123, 9000)
SERVICES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP", 111: "RPC", 139: "NetBIOS", 443: "HTTPS",
            445: "SMB", 515: "LPD (impression)", 548: "AFP", 554: "RTSP (flux vidéo)", 631: "IPP (impression)", 1400: "Sonos", 1883: "MQTT",
            2049: "NFS", 3000: "Web (3000)", 3389: "RDP", 5000: "Web (5000)", 5001: "Web (5001)", 5555: "ADB (Android)", 5900: "VNC",
            6379: "Redis", 7000: "AirPlay", 8000: "Web (8000)", 8008: "Chromecast", 8009: "Chromecast", 8080: "Web (8080)", 8081: "Web (8081)",
            8123: "Home Assistant", 8443: "HTTPS (8443)", 8883: "MQTT TLS", 9000: "Web (9000)", 9100: "Impression JetDirect",
            32400: "Plex", 62078: "Apple (synchro iOS)"}
RISKY = {23: "Telnet : protocole sans chiffrement ni authentification forte", 21: "FTP : identifiants en clair",
         3389: "RDP : bureau à distance exposé sur le LAN", 5900: "VNC : prise de contrôle à distance", 554: "RTSP : flux caméra potentiellement sans mot de passe",
         1883: "MQTT sans TLS : messages domotiques lisibles", 5555: "ADB ouvert : contrôle total d'un appareil Android", 6379: "Redis sans chiffrement",
         2049: "NFS : partage de fichiers à restreindre", 111: "RPC portmap exposé"}

_lock = threading.RLock()
_scan_lock = threading.Lock()
_S = {"hosts": {}, "t": 0, "deep_t": 0, "status": "idle", "progress": None, "last": None, "error": None, "started": None}
_REG = {}
_OWN = {}


# --------------------------------------------------------------------------------------------- registre
def _load():
    try:
        with open(REG_FILE) as f:
            d = json.load(f)
        if isinstance(d, dict):
            _REG.update(d.get("devices") or {})
            return bool(_REG)
    except (OSError, ValueError):
        pass
    return False


def _save():
    try:
        tmp = REG_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"devices": _REG, "saved": time.time()}, f, ensure_ascii=False)
        os.replace(tmp, REG_FILE)
    except OSError:
        pass


_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f<>]+")


def _clean(s, n):
    return _CTRL.sub(" ", str(s or "")).strip()[:n]


def set_meta(mac, fields):
    """Modifie le nom, l'icône, la famille, la note, la confiance, la liaison forcée d'un appareil connu. Toutes les entrées sont validées."""
    mac = str(mac or "").lower()
    if not _MAC.match(mac):
        return {"ok": False, "error": "adresse MAC invalide"}
    with _lock:
        if mac not in _REG:
            return {"ok": False, "error": "appareil inconnu : lancez d'abord un scan"}
        r = _REG[mac]
        if "name" in fields:
            r["name"] = _clean(fields["name"], 48)
        if "icon" in fields:
            if fields["icon"] not in ICONS + [""]:
                return {"ok": False, "error": "icône inconnue"}
            r["icon"] = fields["icon"]
        if "cat" in fields:
            if fields["cat"] not in CATS + [""]:
                return {"ok": False, "error": "famille inconnue"}
            r["cat"] = fields["cat"]
        if "note" in fields:
            r["note"] = _clean(fields["note"], 300)
        if "trusted" in fields:
            r["trusted"] = bool(fields["trusted"])
        if "conn" in fields:
            if fields["conn"] not in ("wired", "wifi", ""):
                return {"ok": False, "error": "type de liaison invalide"}
            r["conn"] = fields["conn"]
        r["ack"] = True   # toute modification vaut « vu »
        r["edited"] = time.time()
        _save()
    STATE.event("info", "lan", f"Appareil renommé / classé : {r.get('name') or mac}", f"{mac} — modifié depuis le dashboard", "lan")
    publish()
    return {"ok": True, "device": next((d for d in (STATE.get("slow", "lan_inventory") or {}).get("devices", []) if d["mac"] == mac), None)}


# --------------------------------------------------------------------------------------------- sondes
def _ping_ok(ip):
    try:
        return subprocess.run(["ping", "-c", "1", "-W", "1", "-n", ip], capture_output=True, timeout=3).returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def _rtt(ip, n=6):
    """Latence, gigue (mdev) et perte sur n paquets espacés de 0,2 s."""
    try:
        out = subprocess.run(["ping", "-c", str(n), "-i", "0.2", "-W", "1", "-q", "-n", ip], capture_output=True, text=True, timeout=n + 4).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    loss = re.search(r"([\d.]+)% packet loss", out)
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    if not m:
        return {"loss": float(loss.group(1)) if loss else 100.0}
    mn, avg, mx, dev = (float(x) for x in m.groups())
    return {"min": mn, "avg": avg, "max": mx, "jitter": dev, "loss": float(loss.group(1)) if loss else 0.0}


def _rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0][:60]
    except (OSError, UnicodeError):
        return None


def _neigh():
    """ip -> (mac, état) pour les voisins du sous-réseau ; seuls les états résolus sont gardés."""
    out = {}
    try:
        txt = subprocess.run(["ip", "-4", "neigh"], capture_output=True, text=True, timeout=5).stdout
    except (subprocess.SubprocessError, OSError):
        return out
    for line in txt.splitlines():
        p = line.split()
        if len(p) >= 5 and p[3] == "lladdr":
            try:
                if ipaddress.ip_address(p[0]) in SUBNET:
                    out[p[0]] = (p[4].lower(), p[-1])
            except ValueError:
                pass
    return out


def _tcp_open(ip, port, timeout=0.6):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def _banner(ip, port):
    """Bannière SSH ou en-tête Server + titre de page : indices d'identité, 4 Ko lus au plus."""
    try:
        with socket.create_connection((ip, port), timeout=1.5) as s:
            s.settimeout(1.5)
            if port == 22:
                return {"ssh": _clean(s.recv(120).decode("latin-1").splitlines()[0], 80)}
            s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: InfraDash\r\nConnection: close\r\n\r\n".encode())
            data = s.recv(4096).decode("latin-1", "replace")
    except (OSError, IndexError):
        return {}
    out = {}
    m = re.search(r"(?im)^server:\s*(.+)$", data)
    if m:
        out["server"] = _clean(m.group(1), 60)
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", data)
    if m:
        out["title"] = _clean(re.sub(r"\s+", " ", m.group(1)), 80)
    return out


def _probe(ip):
    """Ports TCP ouverts parmi la liste fixe + bannières. Connexions simples, sans envoi de données malformées."""
    with cf.ThreadPoolExecutor(16) as ex:
        res = list(ex.map(lambda p: p if _tcp_open(ip, p) else None, PROBE_PORTS))
    ports = [p for p in res if p]
    ban = {}
    for p in ports:
        if p == 22 or p in HTTP_PORTS:
            b = _banner(ip, p)
            if b:
                ban[p] = b
    return ports, ban


def _own_mac():
    if "mac" not in _OWN:
        mac = None
        try:
            for i in os.listdir("/sys/class/net"):
                if i == "lo":
                    continue
                with open(f"/sys/class/net/{i}/address") as f:
                    m = f.read().strip().lower()
                # l'interface qui porte l'IP du LAN : celle dont la route par défaut sort
                if os.path.exists(f"/sys/class/net/{i}/operstate") and open(f"/sys/class/net/{i}/operstate").read().strip() == "up" \
                        and not os.path.exists(f"/sys/class/net/{i}/bridge") and not i.startswith(("docker", "br-", "veth", "tailscale")):
                    mac = m
                    _OWN.update({"mac": mac, "iface": i})
                    break
        except OSError:
            pass
        _OWN.setdefault("mac", mac)
    return _OWN.get("mac")


def local_link():
    """Interface du homelab : type (Ethernet / Wi-Fi) et vitesse négociée, lus dans /sys."""
    _own_mac()
    i = _OWN.get("iface")
    if not i:
        return None
    try:
        with open(f"/sys/class/net/{i}/speed") as f:
            sp = int(f.read().strip())
    except (OSError, ValueError):
        sp = None
    return {"iface": i, "type": "wifi" if os.path.isdir(f"/sys/class/net/{i}/wireless") else "wired", "speed_mbps": sp if sp and sp > 0 else None}


# --------------------------------------------------------------------------------------------- scan
def _set(**kw):
    with _lock:
        _S.update(kw)


def discover(deep=False, manual=False):
    """Balayage du /24 : nouveaux appareils, latence, noms ; sondage de ports si deep. Un seul scan à la fois."""
    if not _scan_lock.acquire(blocking=False):
        return {"ok": False, "error": "un scan est déjà en cours"}
    t0 = time.time()
    first_run = not _REG and not os.path.exists(REG_FILE)
    try:
        _set(status="en_cours", started=t0, error=None, progress={"phase": "balayage", "done": 0, "total": 254}, deep=deep)
        ips = [str(a) for a in SUBNET.hosts() if str(a) != HOME_IP]
        done = [0]

        def one(ip):
            r = _ping_ok(ip)
            done[0] += 1
            if done[0] % 16 == 0:
                _set(progress={"phase": "balayage", "done": done[0], "total": len(ips)})
            return ip, r
        with cf.ThreadPoolExecutor(64) as ex:
            pings = dict(ex.map(one, ips))
        time.sleep(1.0)   # laisse le noyau terminer les résolutions ARP en cours
        neigh = _neigh()
        hosts = {}
        for ip, (mac, st) in neigh.items():
            alive = pings.get(ip, False) or st in ("REACHABLE", "DELAY", "PROBE")
            hosts[ip] = {"ip": ip, "mac": mac, "alive": alive, "state": st, "icmp": pings.get(ip, False)}
        own = _own_mac()
        if own:
            hosts[HOME_IP] = {"ip": HOME_IP, "mac": own, "alive": True, "state": "LOCAL", "icmp": True}
        live = [h for h in hosts.values() if h["alive"] and h["ip"] != HOME_IP]
        _set(progress={"phase": "identification", "done": 0, "total": len(live)})
        n = [0]

        def enrich(h):
            h["rtt"] = _rtt(h["ip"])
            h["hostname"] = _rdns(h["ip"])
            if deep:
                h["ports"], h["banners"] = _probe(h["ip"])
                h["deep_t"] = time.time()
            n[0] += 1
            _set(progress={"phase": "sondage des ports" if deep else "identification", "done": n[0], "total": len(live)})
        with cf.ThreadPoolExecutor(24) as ex:
            list(ex.map(enrich, live))
        now = time.time()
        with _lock:
            prev = _S["hosts"]
            for h in hosts.values():   # conserve les ports du dernier sondage profond si ce passage était léger
                old = prev.get(h["mac"]) or {}
                if not deep:
                    for k in ("ports", "banners", "deep_t"):
                        if k in old and k not in h:
                            h[k] = old[k]
            _S["hosts"] = {h["mac"]: h for h in hosts.values()}
            _S["t"] = now
            if deep:
                _S["deep_t"] = now
            new = _register(hosts.values(), now, baseline=first_run)
        res = {"t": now, "duration_s": round(now - t0, 1), "deep": deep, "alive": sum(1 for h in hosts.values() if h["alive"]),
               "new": new, "total_known": len(_REG), "manual": manual}
        _set(status="idle", progress=None, last=res)
        STATE.event("info", "lan", f"Scan du réseau : {res['alive']} appareils présents" + (f", {len(new)} nouveau(x)" if new else ""),
                    f"{res['duration_s']} s, {'avec sondage des ports' if deep else 'découverte simple'}", "lan")
        publish()
        return dict(res, ok=True)
    except Exception as e:  # noqa
        _set(status="idle", progress=None, error=f"{type(e).__name__}: {e}"[:200])
        return {"ok": False, "error": str(e)[:200]}
    finally:
        _scan_lock.release()


def _register(hosts, now, baseline=False):
    """Met le registre à jour ; renvoie la liste des MAC jamais vues (événement émis pour chacune)."""
    new = []
    for h in hosts:
        if not h["alive"] and h["mac"] not in _REG:
            continue
        r = _REG.get(h["mac"])
        if r is None:
            r = _REG[h["mac"]] = {"first_seen": now, "baseline": baseline, "ack": baseline, "ips": []}
            if not baseline:
                new.append(h["mac"])
                STATE.event("warn", "lan", f"Nouvel appareil sur le réseau : {h['ip']}",
                            f"MAC {h['mac']}" + (f", nom DNS {h['hostname']}" if h.get("hostname") else "")
                            + (" (adresse MAC aléatoire : téléphone ou montre en Wi-Fi privé ?)" if _random_mac(h["mac"]) else ""), "lan")
        if h["alive"]:
            r["last_seen"] = now
            r["last_ip"] = h["ip"]
            if h["ip"] not in r["ips"]:
                r["ips"] = (r["ips"] + [h["ip"]])[-5:]
            if h.get("hostname"):
                r["hostname"] = h["hostname"]
    _save()
    return new


def request_scan(deep=True):
    """Bouton « Scanner le réseau » : lance le scan en arrière-plan (réponse immédiate)."""
    if _scan_lock.locked():
        return {"accepted": False, "message": "Un scan est déjà en cours."}
    gap = time.time() - ((_S.get("last") or {}).get("t") or 0)
    if gap < MIN_GAP:
        return {"accepted": False, "message": f"Dernier scan il y a {int(gap)} s : réessayez dans {int(MIN_GAP - gap) + 1} s."}
    _set(status="en_cours", started=time.time(), progress={"phase": "démarrage", "done": 0, "total": 254})
    threading.Thread(target=discover, kwargs={"deep": bool(deep), "manual": True}, name="lan.scan", daemon=True).start()
    return {"accepted": True, "message": "Scan lancé : 15 à 40 s."}


def auto():
    """Boucle de fond : découverte légère toutes les 5 min, sondage de ports toutes les 6 h."""
    deep = time.time() - _S["deep_t"] > DEEP_EVERY
    discover(deep=deep)


# --------------------------------------------------------------------------------------------- liaison Ethernet / Wi-Fi
def _random_mac(mac):
    return bool(int(mac[1], 16) & 2)   # bit « administré localement » : adresse privée / aléatoire (Wi-Fi des téléphones, montres)


_WIFI_HINTS = ("espressif", "tuya", "shelly", "xiaomi", "lumi", "dreame", "smart innovation", "watch", "iphone", "ipad", "android", "galaxy", "pixel")


def classify_link(d, rtt, ov, host_link=None):
    """Type de liaison avec ses indices ; jamais de certitude affichée quand les indices divergent."""
    if ov:
        return {"type": ov, "source": "manuel", "confidence": "forte", "evidence": ["défini par vous"], "speed_mbps": (host_link or {}).get("speed_mbps")}
    if host_link:
        return {"type": host_link["type"], "source": "interface locale", "confidence": "forte", "speed_mbps": host_link.get("speed_mbps"),
                "evidence": [f"interface {host_link.get('iface', '?')} lue sur la machine" + (f", {host_link['speed_mbps']} Mb/s négociés" if host_link.get("speed_mbps") else "")]}
    wired = wifi = 0
    ev = []
    ns = d.get("ns_conn")
    if ns == "wired":
        wired += 3
        ev.append("NetScan : filaire")
    elif ns == "wifi":
        wifi += 2
        ev.append("NetScan : Wi-Fi")
    if _random_mac(d["mac"]):
        wifi += 3
        ev.append("adresse MAC aléatoire (Wi-Fi privé)")
    if rtt and rtt.get("avg") is not None and rtt.get("loss", 100) < 100:
        a, j, mx = rtt["avg"], rtt.get("jitter") or 0, rtt.get("max") or 0
        txt = f"latence {a:.1f} ms, gigue {j:.1f} ms" + (f", perte {rtt['loss']:.0f} %" if rtt.get("loss") else "")
        if a <= 0.9 and j <= 0.4 and not rtt.get("loss"):
            wired += 2
            ev.append(txt + " (typique d'un câble)")
        elif a >= 4 or j >= 3 or mx >= 25:
            wifi += 2
            ev.append(txt + " (typique du Wi-Fi)")
        elif a >= 2:
            wifi += 1
            ev.append(txt)
        else:
            ev.append(txt)
    low = f"{d.get('name', '')} {d.get('vendor', '')} {d.get('ns_type', '')}".lower()
    if any(k in low for k in _WIFI_HINTS) and not (d.get("infra")):
        wifi += 1
        ev.append("type d'appareil généralement en Wi-Fi")
    margin = abs(wired - wifi)
    if margin < 2:
        typ, conf = "unknown", "faible"
    else:
        typ, conf = ("wired" if wired > wifi else "wifi"), ("forte" if margin >= 4 else "moyenne")
    if ns in ("wired", "wifi") and typ not in ("unknown", ns):
        ev.append(f"⚠ contradiction avec NetScan ({ns}) : à vérifier ou à forcer à la main")
        conf = "faible"
    return {"type": typ, "source": "indices", "confidence": conf, "evidence": ev, "speed_mbps": None}


# --------------------------------------------------------------------------------------------- inventaire publié
def _base_name(r, d):
    return r.get("name") or d.get("name") or r.get("hostname") or d.get("vendor") or "Appareil inconnu"


def _guess_icon(d, ports):
    from .netscan import _cat
    inf = d.get("infra")
    if inf:
        return {"nas": "nas", "homelab": "server", "clawhost": "claw", "ha": "home", "box": "router", "pc": "pc"}.get(inf, "server")
    low = f"{d.get('name', '')} {d.get('vendor', '')} {d.get('ns_type', '')}".lower()
    for keys, ic in ((("camera", "cam", "indoorcam", "ezviz", "hikvision"), "camera"), (("printer", "brw", "epson", "canon", "hp ", "brother"), "printer"),
                     (("tv", "webos", "apple tv", "shield", "roku", "chromecast", "yamaha", "rx-a", "samsung"), "tv"),
                     (("sonos", "speaker", "bose", "audiocast", "google-home", "google-mini", "fuchsia", "nest", "echo"), "speaker"), (("hue", "philips", "lighting", "lumi", "ampoule"), "bulb"),
                     (("watch", "montre"), "watch"), (("ipad", "tablet", "tab "), "tablet"), (("iphone", "pixel", "galaxy", "android", "phone", "s25", "s24"), "phone"),
                     (("nintendo", "xbox", "playstation", "ps5"), "gamepad"), (("nuki",), "lock"), (("router", "switch", "d-link", "dgs-", "ubiquiti", "tp-link"), "router"),
                     (("espressif", "tuya", "shelly", "smart innovation", "iot", "plug"), "plug"), (("mac", "win-", "laptop", "pc"), "laptop")):
        if any(k in low for k in keys):
            return ic
    return {"Réseau": "router", "Multimédia": "tv", "Maison connectée": "plug", "Mobiles": "phone", "Ordinateurs & serveurs": "pc"}.get(_cat(d.get("name"), d.get("ns_type"), d.get("vendor")), "unknown")


def publish():
    """Fusionne ARP/NetScan (lan_devices), scan actif, registre et liaison -> slow.lan_inventory (appelé toutes les 15 s et après chaque action)."""
    with _lock:
        base = {d["mac"]: dict(d) for d in (STATE.get("slow", "lan_devices") or {}).get("devices") or [] if d.get("mac")}
        scan = dict(_S["hosts"])
        reg = {k: dict(v) for k, v in _REG.items()}
        scan_t = _S["t"]
        scan_state = {k: _S[k] for k in ("status", "progress", "last", "error", "started", "deep_t")}
    own = _own_mac()
    if own and own not in base:
        base[own] = {"mac": own, "ip": HOME_IP, "alive": True, "name": "Homelab", "vendor": "", "infra": "homelab", "cat": "Ordinateurs & serveurs",
                     "known": True, "risk": "safe", "services": [], "flags": [], "in_ns": False}
    for mac, h in scan.items():
        if mac not in base:
            from .netscan import _cat
            base[mac] = {"mac": mac, "ip": h["ip"], "alive": h["alive"], "name": h.get("hostname") or "Appareil inconnu", "vendor": "", "infra": None,
                         "cat": _cat(h.get("hostname")), "known": False, "risk": "safe", "services": [], "flags": ["nouveau", "à identifier"], "in_ns": False}
    hostlinks = STATE.get("slow", "host_links") or {}
    hl = {HOME_IP: local_link() and dict(local_link(), host="homelab")}
    for hk, v in hostlinks.items():
        ip = (HOSTS.get(hk) or {}).get("ip")
        if ip and v:
            hl[ip] = dict(v, host=hk)
    fresh = time.time() - scan_t < 900
    out = []
    for mac, d in base.items():
        r = reg.get(mac) or {}
        h = scan.get(mac) or {}
        if fresh and h:
            d["alive"] = bool(h.get("alive"))
            d["ip"] = h["ip"]
        ports = h.get("ports")
        ban = h.get("banners") or {}
        link = classify_link(d, h.get("rtt"), r.get("conn") or None, hl.get(d.get("ip")))
        flags = list(d.get("flags") or [])
        is_new = bool(r) and not r.get("ack") and not r.get("baseline")
        if is_new and "nouveau" not in flags:
            flags.append("nouveau")
        trusted = bool(r.get("trusted"))
        known = bool(d.get("known") or trusted or d.get("infra"))
        if trusted and "à identifier" in flags:
            flags.remove("à identifier")
        ri = [{"port": p, "service": SERVICES.get(p, str(p)), "risk": None if d.get("infra") else RISKY.get(p)} for p in (ports or [])]
        out.append({
            "mac": mac, "ip": d.get("ip"), "alive": bool(d.get("alive")), "name": r.get("name") or d.get("name") or "Appareil inconnu",
            "auto_name": d.get("name"), "custom_name": bool(r.get("name")), "hostname": h.get("hostname") or r.get("hostname"),
            "vendor": d.get("vendor") or "", "infra": d.get("infra"), "cat": r.get("cat") or d.get("cat") or "Autres", "auto_cat": d.get("cat"),
            "icon": r.get("icon") or _guess_icon(d, ports), "custom_icon": bool(r.get("icon")), "custom_conn": r.get("conn") or "", "known": known, "trusted": trusted,
            "risk": d.get("risk") or "safe", "risk_score": d.get("risk_score"), "risk_factors": d.get("risk_factors") or [],
            "services": d.get("services") or [], "ports": ri, "banners": {str(k): v for k, v in ban.items()}, "ports_t": h.get("deep_t"),
            "rtt": h.get("rtt"), "link": link, "ns_conn": d.get("ns_conn"), "ns_mbps": d.get("ns_mbps"), "switch_port": d.get("switch_port"),
            "random_mac": _random_mac(mac), "first_seen": r.get("first_seen"), "last_seen": r.get("last_seen"), "ips": r.get("ips") or [],
            "note": r.get("note") or "", "is_new": is_new, "flags": flags, "ns_ip": d.get("ns_ip"), "in_ns": d.get("in_ns"), "ns_id": d.get("ns_id"),
            "state": h.get("state")})
    out.sort(key=lambda x: (not x["alive"], not x["is_new"], x["cat"], str(x["name"]).lower()))
    STATE.set("slow", "lan_inventory", {"t": time.time(), "devices": out, "scan_t": scan_t, "new": sum(1 for x in out if x["is_new"] and x["alive"]),
                                        "link_counts": {k: sum(1 for x in out if x["alive"] and x["link"]["type"] == k) for k in ("wired", "wifi", "unknown")}})
    STATE.set("slow", "lan_scan", scan_state)


def ports_of(mac_or_ip):
    """Ports ouverts vus par le dernier sondage (utilisé par l'onglet Ports et l'architecte)."""
    with _lock:
        for h in _S["hosts"].values():
            if mac_or_ip in (h["mac"], h["ip"]):
                return list(h.get("ports") or [])
    return []


def scan_hosts():
    with _lock:
        return {h["ip"]: dict(h) for h in _S["hosts"].values()}


_load()
