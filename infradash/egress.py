"""Flux sortants (« où vont mes données ? ») : conntrack du NAS + sockets du homelab, géolocalisés hors ligne.

Confidentialité : aucune IP contactée n'est envoyée à un service tiers. Pays (DB-IP Lite), ASN (iptoasn) et
plages cloud (AWS, Google Cloud) sont téléchargés en bloc dans DATA_DIR/geo puis interrogés en mémoire ;
les PTR passent par le résolveur local (AdGuard). Lecture seule : les règles de blocage sont des suggestions.
"""
import gzip
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.request
from array import array
from bisect import bisect_right
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import egress_kb as KB
from .config import CONTAINER_INFO, DATA_DIR, KNOWN_IPS
from .state import STATE
from .util import TZ, run as sh

GEO_DIR = os.path.join(DATA_DIR, "geo")
PTR_FILE = os.path.join(DATA_DIR, "egress-ptr.json")
HIST_FILE = os.path.join(DATA_DIR, "egress-hist.json")

NAS_IP, HOMELAB_IP, HA_IP, ROUTER_IP = "192.168.2.3", "192.168.2.4", "192.168.2.240", "192.168.2.1"
ADGUARD_URL = "http://192.168.2.4:8085"
ROUTER_URL = "http://192.168.2.1"
LOCAL_DNS = "192.168.2.4"

ATTRIBUTION = ("Géolocalisation : IP Geolocation by DB-IP (https://db-ip.com), licence CC BY 4.0 — "
               "ASN : iptoasn.com (domaine public) — plages : AWS ip-ranges.json, Google Cloud cloud.json. "
               "Données interrogées localement, aucune IP n'est envoyée à un tiers.")

PTR_TTL, PTR_NEG_TTL, PTR_FAIL_TTL, PTR_MAX_PER_CYCLE = 7 * 86400, 86400, 3600, 30
HIST_KEEP = 30 * 86400
NEW_WINDOW = 86400            # « nouvelle » destination = vue pour la première fois depuis < 24 h
BASELINE = 900                # pas d'alerte pendant les 15 premières minutes d'historique
MAX_EVENTS_PER_CYCLE = 3
DOMAINS_EVERY = 6 * 3600
DNET_EVERY = 600

_PRIV4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4")]


def is_public(ip):
    """Destination Internet publique (exclut RFC1918, CGNAT/Tailscale, multicast, loopback, link-local, ULA)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 4:
        return not any(a in n for n in _PRIV4)
    return a.is_global and not a.is_multicast


def _norm(ip):
    """Forme canonique (conntrack écrit l'IPv6 en version longue)."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


# =====================================================================================================
# Bases hors ligne (téléchargement mensuel + chargement compact : tableaux triés + bisect)
# =====================================================================================================
def _dbip_urls():
    now = datetime.now(TZ)
    y, m = now.year, now.month
    py, pm = (y, m - 1) if m > 1 else (y - 1, 12)
    return [f"https://download.db-ip.com/free/dbip-country-lite-{y:04d}-{m:02d}.csv.gz",
            f"https://download.db-ip.com/free/dbip-country-lite-{py:04d}-{pm:02d}.csv.gz"]


SOURCES = {
    "dbip": {"file": "dbip-country-lite.csv.gz", "max_age": 30 * 86400, "min": 1_000_000, "kind": "gz", "urls": _dbip_urls},
    "asn": {"file": "ip2asn-v4.tsv.gz", "max_age": 30 * 86400, "min": 1_000_000, "kind": "gz",
            "urls": lambda: ["https://iptoasn.com/data/ip2asn-v4.tsv.gz"]},
    "aws": {"file": "aws-ip-ranges.json", "max_age": 7 * 86400, "min": 100_000, "kind": "json",
            "urls": lambda: ["https://ip-ranges.amazonaws.com/ip-ranges.json"]},
    "gcp": {"file": "gcp-cloud.json", "max_age": 7 * 86400, "min": 10_000, "kind": "json",
            "urls": lambda: ["https://www.gstatic.com/ipranges/cloud.json"]},
}


def _ip4int(ip):
    return int.from_bytes(socket.inet_aton(ip), "big")


def _ip6hi(ip):
    return int.from_bytes(socket.inet_pton(socket.AF_INET6, ip)[:8], "big")


class Geo:
    def __init__(self):
        self.lock = threading.Lock()
        self.c4 = self.c6 = None          # (débuts, index pays, codes)
        self.asn = None                   # (débuts, fins, numéros, {asn: (pays, org)})
        self.aws, self.gcp = {}, {}       # {longueur de préfixe: {réseau entier: région}}
        self.loaded = {}                  # source -> mtime du fichier chargé
        self.status = {k: "absent" for k in SOURCES}
        self.fail = {}                    # source -> date du dernier échec de téléchargement
        self.thread = None
        self.last_check = 0

    # --- téléchargement -------------------------------------------------------------------------
    def _download(self, name):
        src = SOURCES[name]
        dst = os.path.join(GEO_DIR, src["file"])
        for url in src["urls"]():
            tmp = dst + ".part"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "InfraDash/1.0 (homelab)"})
                with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
                    total = 0
                    while True:
                        chunk = r.read(1 << 16)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > 80_000_000:
                            raise ValueError("fichier trop gros")
                        f.write(chunk)
                if total < src["min"]:
                    raise ValueError("fichier trop petit")
                with open(tmp, "rb") as f:   # contrôle de format avant de remplacer l'ancien fichier
                    head = f.read(2)
                if src["kind"] == "gz" and head != b"\x1f\x8b":
                    raise ValueError("pas un gzip")
                if src["kind"] == "json":
                    with open(tmp) as f:
                        json.load(f)
                os.replace(tmp, dst)
                return True
            except Exception:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        self.fail[name] = time.time()
        return False

    # --- chargement -----------------------------------------------------------------------------
    def _load_dbip(self, path):
        s4, i4, s6, i6, codes = array("I"), array("H"), array("Q"), array("H"), {}
        with gzip.open(path, "rt", encoding="ascii", errors="replace") as f:
            for line in f:
                a, _, rest = line.partition(",")
                cc = rest.rstrip()[-2:]
                i = codes.get(cc)
                if i is None:
                    i = codes[cc] = len(codes)
                if ":" in a:
                    s6.append(_ip6hi(a))
                    i6.append(i)
                else:
                    s4.append(_ip4int(a))
                    i4.append(i)
        lst = [None] * len(codes)
        for k, v in codes.items():
            lst[v] = k
        return (s4, i4, lst), (s6, i6, lst)

    def _load_asn(self, path):
        st, en, nu, orgs = array("I"), array("I"), array("I"), {}
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) < 5 or p[2] == "0":
                    continue
                n = int(p[2])
                st.append(_ip4int(p[0]))
                en.append(_ip4int(p[1]))
                nu.append(n)
                if n not in orgs:
                    orgs[n] = (p[3], p[4][:80])
        return st, en, nu, orgs

    def _load_ranges(self, path, key_v4, key_region):
        with open(path) as f:
            d = json.load(f)
        out = {}
        for p in d.get("prefixes", []):
            pre, reg = p.get(key_v4), p.get(key_region)
            if not pre or not reg:
                continue
            net, _, pl = pre.partition("/")
            pl = int(pl)
            out.setdefault(pl, {})[_ip4int(net) >> (32 - pl) << (32 - pl)] = reg
        return out

    def _reload(self):
        for name, src in SOURCES.items():
            path = os.path.join(GEO_DIR, src["file"])
            try:
                mt = os.path.getmtime(path)
            except OSError:
                continue
            if self.loaded.get(name) == mt:
                continue
            try:
                if name == "dbip":
                    c4, c6 = self._load_dbip(path)
                    with self.lock:
                        self.c4, self.c6 = c4, c6
                elif name == "asn":
                    a = self._load_asn(path)
                    with self.lock:
                        self.asn = a
                elif name == "aws":
                    r = self._load_ranges(path, "ip_prefix", "region")
                    with self.lock:
                        self.aws = r
                elif name == "gcp":
                    r = self._load_ranges(path, "ipv4Prefix", "scope")
                    with self.lock:
                        self.gcp = r
                self.loaded[name] = mt
                self.status[name] = "ok"
            except Exception as e:  # fichier corrompu : on le supprimera au prochain téléchargement
                self.status[name] = f"erreur : {type(e).__name__}"

    def _maintain(self):
        try:
            os.makedirs(GEO_DIR, exist_ok=True)
            now = time.time()
            for name, src in SOURCES.items():
                path = os.path.join(GEO_DIR, src["file"])
                try:
                    age = now - os.path.getmtime(path)
                except OSError:
                    age = None
                if (age is None or age > src["max_age"]) and now - self.fail.get(name, 0) > 6 * 3600:
                    self.status[name] = "téléchargement" if age is None else self.status.get(name, "ok")
                    if not self._download(name) and age is None:
                        self.status[name] = "échec du téléchargement"
            self._reload()
        except Exception:
            pass

    def kick(self):
        """Vérifie/télécharge/charge en tâche de fond (jamais dans le chemin critique)."""
        if self.thread and self.thread.is_alive():
            return
        if time.time() - self.last_check < 3600 and all(v == "ok" for v in self.status.values()):
            return
        if time.time() - self.last_check < 300:
            return
        self.last_check = time.time()
        self.thread = threading.Thread(target=self._maintain, name="egress.geo", daemon=True)
        self.thread.start()

    def ready(self):
        return self.c4 is not None

    # --- requêtes -------------------------------------------------------------------------------
    def country(self, ip):
        try:
            if ":" in ip:
                tab, key = self.c6, _ip6hi(ip)
            else:
                tab, key = self.c4, _ip4int(ip)
        except OSError:
            return ""
        if not tab:
            return ""
        i = bisect_right(tab[0], key) - 1
        if i < 0:
            return ""
        cc = tab[2][tab[1][i]]
        return "" if cc in ("ZZ", "EU", "AP") else cc

    def asn_of(self, ip):
        a = self.asn
        if not a or ":" in ip:
            return 0, "", ""
        x = _ip4int(ip)
        i = bisect_right(a[0], x) - 1
        if i < 0 or x > a[1][i]:
            return 0, "", ""
        n = a[2][i]
        cc, org = a[3].get(n, ("", ""))
        return n, org, ("" if cc == "None" else cc)

    def cloud(self, ip):
        if ":" in ip:
            return None
        x = _ip4int(ip)
        for prov, tab in (("aws", self.aws), ("gcp", self.gcp)):
            for pl in sorted(tab, reverse=True):
                reg = tab[pl].get(x >> (32 - pl) << (32 - pl))
                if reg:
                    return prov, reg
        return None


GEO = Geo()


# =====================================================================================================
# Résolutions DNS locales : PTR (cache disque 7 j) et domaines connus (pour reconnaître les IP)
# =====================================================================================================
class Ptr:
    def __init__(self):
        self.cache = {}
        self.dirty = False
        try:
            with open(PTR_FILE) as f:
                self.cache = json.load(f)
        except (OSError, ValueError):
            pass

    @staticmethod
    def _lookup(ip):
        out = sh(["dig", "+short", "+time=1", "+tries=1", "-x", ip, f"@{LOCAL_DNS}"], timeout=4)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if not out or any(l.startswith(";;") for l in lines):
            return None                       # délai dépassé / résolveur injoignable
        names = [l.rstrip(".") for l in lines if re.match(r"^[A-Za-z0-9._-]+\.?$", l)]
        return names[0] if names else ""

    def resolve(self, ips):
        now = time.time()
        todo = []
        for ip in ips:
            c = self.cache.get(ip)
            ttl = PTR_TTL if c and c[0] else (PTR_FAIL_TTL if c and len(c) > 2 else PTR_NEG_TTL)
            if not c or now - c[1] > ttl:
                todo.append(ip)
        todo = todo[:PTR_MAX_PER_CYCLE]
        if todo:
            with ThreadPoolExecutor(max_workers=8) as ex:
                for ip, name in zip(todo, ex.map(self._lookup, todo)):
                    # échec (timeout) : mémorisé 1 h pour ne pas ralentir chaque cycle
                    self.cache[ip] = [name, now] if name is not None else ["", now, "echec"]
                    self.dirty = True
        return {ip: (self.cache.get(ip) or ["", 0])[0] for ip in ips}

    def save(self):
        if not self.dirty:
            return
        now = time.time()
        self.cache = {k: v for k, v in self.cache.items() if now - v[1] < 4 * PTR_TTL}
        _write_json(PTR_FILE, self.cache)
        self.dirty = False


PTR = Ptr()
DOMAINS = {"map": {}, "t": 0, "busy": False}   # ip -> [(domaine, cat, service)]


def _refresh_domains():
    def one(item):
        dom = item[0]
        out = sh(["dig", "+short", "+time=1", "+tries=1", dom, "A", f"@{LOCAL_DNS}"], timeout=4)
        return item, [l.strip() for l in out.splitlines() if re.match(r"^\d+\.\d+\.\d+\.\d+$", l.strip())]

    try:
        m = {}
        with ThreadPoolExecutor(max_workers=8) as ex:
            for item, ips in ex.map(one, KB.KNOWN_DOMAINS):
                for ip in ips:
                    if ip != "0.0.0.0" and is_public(ip):     # 0.0.0.0 = déjà bloqué par AdGuard
                        m.setdefault(ip, []).append(item)
        if m:
            DOMAINS["map"] = m
            DOMAINS["t"] = time.time()
    finally:
        DOMAINS["busy"] = False


def _kick_domains():
    if DOMAINS["busy"] or time.time() - DOMAINS["t"] < DOMAINS_EVERY:
        return
    if DOMAINS["t"] == 0 and time.time() - DOMAINS.get("tried", 0) < 600:
        return
    DOMAINS["busy"] = True
    DOMAINS["tried"] = time.time()
    threading.Thread(target=_refresh_domains, name="egress.domains", daemon=True).start()


def _write_json(path, obj):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, path)
    except OSError:
        pass


# =====================================================================================================
# Collecte
# =====================================================================================================
# Agrégation côté NAS : (proto, src, dst, dport, état, sport si hôte) -> nombre de connexions, destinations publiques
_CT_AWK = (r"""awk -v H=%s '{p=$3;st="";s="";d="";dp="";sp="";n=0;ur=0;"""
           r"""for(i=4;i<=NF;i++){x=$i;if(x~/^src=/){n++;if(n==1)s=substr(x,5)}"""
           r"""else if(n==1&&d==""&&x~/^dst=/)d=substr(x,5);else if(n==1&&sp==""&&x~/^sport=/)sp=substr(x,7);"""
           r"""else if(n==1&&dp==""&&x~/^dport=/)dp=substr(x,7);else if(x=="[UNREPLIED]")ur=1;else if(p=="tcp"&&i==6)st=x}"""
           r"""if(d~/^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.|0\.|f[c-f]|0000:)/)next;"""
           r"""if(s!~/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|f[c-f])/)next;"""
           r"""if(st=="")st=(ur?"UNREPLIED":"OK");if(dp=="")dp=0;if(s!=H)sp="-";"""
           r"""c[p" "s" "d" "dp" "st" "sp]++}END{for(k in c)print c[k],k}' /proc/net/nf_conntrack""") % NAS_IP
# Sockets de l'hôte NAS -> processus -> conteneur (pour les conteneurs en réseau « host » comme eufy-security-ws)
_SS_NAS = (r"""S=$(ss -tuanpH 2>/dev/null | awk '$5!~/^(127\.|\[::1\])/{n=split($5,a,":");"""
           r"""if(match($0,/\("[^"]*",pid=[0-9]+/)){x=substr($0,RSTART+2,RLENGTH-2);split(x,b,"\",pid=");"""
           r"""gsub(/ /,"_",b[1]);print $1,a[n],b[1],b[2]}}' | sort -u); echo "$S"; echo @@pcg; """
           r"""for p in $(echo "$S" | awk '{print $4}' | sort -u); do c=$(grep -o -m1 'docker/[0-9a-f]*' /proc/$p/cgroup 2>/dev/null); """
           r"""echo "$p ${c#docker/} $(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | cut -c1-120)"; done""")
_DNET = "docker network ls --format '{{.Name}} {{.Internal}}' 2>/dev/null"

CTX = {"dnet": {}, "dnet_t": 0, "nas_ok": None, "homelab_ok": None, "cycles": 0}


def _sections(out):
    sec, cur = {}, None
    for line in out.splitlines():
        if line.startswith("@@"):
            cur = line[2:].strip()
            sec[cur] = []
        elif cur:
            sec[cur].append(line)
    return sec


def _nas_maps():
    """ip -> conteneur, id (12) -> conteneur, conteneur -> infos (réseaux, catégorie)."""
    ip2name, id2name, info = {}, {}, {}
    try:
        from . import nas
        conts = dict(nas.CTX.get("containers") or {})
        ip2name.update(nas.CTX.get("ip2name") or {})
    except Exception:
        conts = {}
    for c in STATE.get("live", "nas_containers") or []:
        conts.setdefault(c.get("name"), c)
    for name, c in conts.items():
        if not name:
            continue
        nets = []
        for x in c.get("ips") or []:
            if "=" in x:
                net, ip = x.split("=", 1)
                nets.append(net)
                if ip:
                    ip2name[ip] = name
        if c.get("id"):
            id2name[c["id"][:12]] = name
        info[name] = {"nets": nets, "netmode": c.get("netmode", ""), "state": c.get("state", ""),
                      "cat": (CONTAINER_INFO.get(name) or ("", c.get("cat") or "autre"))[1],
                      "desc": (CONTAINER_INFO.get(name) or (c.get("desc") or "", ""))[0]}
    return ip2name, id2name, info


def _lan_name(ip):
    if ip in KNOWN_IPS:
        return KNOWN_IPS[ip][1]
    for d in (STATE.get("slow", "lan") or {}).get("devices", []):
        if d.get("ip") == ip:
            return d.get("name") or d.get("vendor") or ip
    return ip


def collect_nas():
    """Flux sortants vus par le conntrack du NAS (hôte, conteneurs, VM Home Assistant)."""
    from . import nas
    want_dnet = time.time() - CTX["dnet_t"] > DNET_EVERY
    cmd = "echo @@ct; " + _CT_AWK + "; echo @@ss; " + _SS_NAS + ("; echo @@dnet; " + _DNET if want_dnet else "")
    out = nas.SSHC.run(cmd, timeout=15)
    if out is None or "@@ct" not in out:
        CTX["nas_ok"] = False
        return []
    CTX["nas_ok"] = True
    sec = _sections(out)
    if want_dnet and sec.get("dnet"):
        CTX["dnet"] = {l.split()[0]: l.split()[1] == "true" for l in sec["dnet"] if len(l.split()) == 2}
        CTX["dnet_t"] = time.time()
    # port local -> (processus, conteneur)
    ip2name, id2name, info = _nas_maps()
    pid2cid, pid2cmd = {}, {}
    for l in sec.get("pcg", []):
        m = re.match(r"^(\d+) ([0-9a-f]*) ?(.*)$", l)
        if m:
            if m.group(2):
                pid2cid[m.group(1)] = m.group(2)[:12]
            pid2cmd[m.group(1)] = m.group(3).strip()
    port2proc = {}
    for l in sec.get("ss", []):
        p = l.split()
        if len(p) == 4 and p[1].isdigit():
            port2proc[(p[0], p[1])] = (KB.proc_label(p[2].replace("_", " "), pid2cmd.get(p[3], "")),
                                       id2name.get(pid2cid.get(p[3], "")))
    flows = []
    for line in sec.get("ct", []):
        p = line.split()
        if len(p) != 7 or not p[0].isdigit():
            continue
        n, proto, src, dst, dport, st, sport = int(p[0]), p[1], p[2], _norm(p[3]), p[4], p[5], p[6]
        if not is_public(dst):
            continue
        f = {"host": "nas", "proto": proto, "src_ip": src, "dst": dst, "dport": int(dport) if dport.isdigit() else 0,
             "state": st, "n": n, "process": ""}
        if src == NAS_IP:
            proc, cont = port2proc.get((proto, sport), ("", None))
            if cont:
                f.update(name=cont, kind="conteneur", process=proc)
            else:
                f.update(name="NAS Unraid (hôte)", kind="hote", process=proc)
        elif src == HA_IP:
            f.update(name="Home Assistant (VM)", kind="vm")
        elif src in ip2name:
            f.update(name=ip2name[src], kind="conteneur")
        elif src.startswith("192.168.2."):
            f.update(name=_lan_name(src), kind="appareil")
        else:
            f.update(name=f"conteneur inconnu ({src})", kind="conteneur")
        if f["kind"] == "conteneur":
            f["ccat"] = (info.get(f["name"]) or {}).get("cat", "")
        flows.append(f)
    CTX["nas_info"] = info
    return flows


def collect_homelab():
    """Sockets de l'hôte homelab (les conteneurs ne sont pas visibles sans root)."""
    out = sh(["ss", "-tuanpH"], timeout=6)
    if not out:
        CTX["homelab_ok"] = False
        return []
    CTX["homelab_ok"] = True
    listen, rows = set(), []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 6:
            continue
        proto, st, local, peer = p[0], p[1], p[4], p[5]
        lport = local.rsplit(":", 1)[-1]
        if st in ("LISTEN", "UNCONN"):
            listen.add((proto, lport))
            continue
        rows.append((proto, st, lport, peer, " ".join(p[6:])))
    agg = {}
    for proto, st, lport, peer, procs in rows:
        if (proto, lport) in listen or ":" not in peer:
            continue          # connexion entrante (port local en écoute)
        pip, pport = peer.rsplit(":", 1)
        pip = _norm(pip.strip("[]").split("%")[0].replace("::ffff:", ""))
        if not is_public(pip) or not pport.isdigit():
            continue
        m = re.search(r'\("([^"]+)",pid=(\d+)', procs)
        state = {"ESTAB": "ESTABLISHED", "TIME-WAIT": "TIME_WAIT", "SYN-SENT": "SYN_SENT"}.get(st, st.replace("-", "_"))
        proc = ""
        if m:
            try:
                with open(f"/proc/{m.group(2)}/cmdline", "rb") as fh:
                    cmdl = fh.read(300).replace(b"\0", b" ").decode("utf-8", "replace")
            except OSError:
                cmdl = ""
            proc = KB.proc_label(m.group(1), cmdl)
        k = (proto, pip, int(pport), state, proc)
        agg[k] = agg.get(k, 0) + 1
    return [{"host": "homelab", "proto": k[0], "src_ip": HOMELAB_IP, "dst": k[1], "dport": k[2], "state": k[3], "n": n,
             "process": k[4], "name": "Homelab (hôte)", "kind": "hote"} for k, n in agg.items()]


# =====================================================================================================
# Classification, localisation, risque, blocage
# =====================================================================================================
_CIDR = [(ipaddress.ip_network(c), r) for cs, r in KB.CIDR_RULES for c in cs]


def classify(ip, asn, org, ptr, ports, protos, srcnames=()):
    """-> (règle, identifiée_par)."""
    try:
        a = ipaddress.ip_address(ip)
        for net, r in _CIDR:
            if a.version == net.version and a in net:
                return r, "plage"
    except ValueError:
        pass
    # PTR / domaine très spécifiques (relais DERP, sauvegarde Unraid) avant les ports génériques (22, 3478)
    doms = DOMAINS["map"].get(ip)
    for rx, r in KB.PTR_PRIORITY_RULES:
        if ptr and rx.search(ptr):
            return r, "ptr"
        if doms and any(rx.search(item[0]) for item in doms):
            return r, "domaine"
    for proto, pset, asns, r in KB.PORT_RULES:
        if (proto is None or proto in protos) and (pset & ports) and (asns is None or asn in asns):
            return r, "port"
    if doms:
        base = KB.ASN_RULES.get(asn, {})
        shared = asn in KB.CLOUDFLARE_ASNS or base.get("cat") == "cdn"
        pick = None
        for item in doms:
            rx = item[3] if len(item) > 3 else None
            if not shared or (rx and any(re.search(rx, n, re.I) for n in srcnames)):
                pick = item
                break
        if pick:
            return {"cat": pick[1], "svc": pick[2] + (" (probable, IP partagée)" if shared else ""),
                    "adguard": [pick[0]], "anycast": base.get("anycast", False), "domain_shared": shared}, "domaine"
    for rx, r in KB.PTR_RULES:
        if ptr and rx.search(ptr):
            return r, "ptr"
    arule = KB.ASN_RULES.get(asn)
    dom = KB.ptr_service_domain(ptr)
    if dom and (not arule or arule.get("svc") in _GENERIC_HOSTING):   # PTR « parlant » : meilleur indice que l'hébergeur
        return {"cat": "cloud", "svc": f"{dom} (d'après le DNS inverse)", "adguard": [dom], "risk": "faible",
                "note": f"Identifié par son nom DNS inverse ({ptr}), hébergé chez {KB.prettify_org(org) or 'un hébergeur inconnu'}.",
                "domain_guess": True}, "ptr-nom"
    if arule:
        return arule, "asn"
    for rx, r in KB.ORG_RULES:
        if org and rx.search(org):
            return r, "org"
    return {"cat": "inconnu", "svc": KB.prettify_org(org) or "Non identifié"}, "aucun"


def locate(ip, cc, asn, ptr, rule):
    """-> (pays, région lisible, lat, lon, anycast, confiance 'haute'|'moyenne'|'faible')."""
    c, reg, la, lo, any_ = _locate(ip, cc, asn, ptr, rule)
    if reg and ("(AWS " in reg or "(Google Cloud " in reg or "d'après le nom DNS" in reg):
        conf = "haute"
    elif any_ or not c:
        conf = "moyenne" if c else "faible"
    elif asn in KB.GOOGLE_GEOFEED_ASNS:
        conf = "faible"          # Google déclare la localisation des utilisateurs servis, pas celle des serveurs
    else:
        conf = "moyenne"         # DB-IP, niveau pays
    if any_ and reg.startswith("Anycast Google"):
        conf = "faible"
    return c, reg, la, lo, any_, conf


def _ptr_city(ptr):
    """Ville déduite du PTR pour les fournisseurs qui l'y encodent de façon fiable (Tailscale, CloudFront ; pas Google)."""
    if not ptr or not KB.PTR_CITY_DOMAINS.search(ptr):
        return None
    code = None
    m = re.match(r"^derp(\d+)", ptr)
    if m:
        code = KB.TAILSCALE_DERP.get(int(m.group(1)))
    if not code:
        for lab in ptr.lower().split(".")[:-2]:
            m = re.match(r"^(?:[a-z]+-)?([a-z]{3})(?:\d|$)", lab)
            if m and m.group(1) in KB.PTR_CITY:
                code = m.group(1)
                break
    return KB.PTR_CITY.get(code) if code else None


def _locate(ip, cc, asn, ptr, rule):
    if asn in KB.CLOUDFLARE_ASNS or rule.get("anycast"):
        lbl, c, la, lo = KB.ANYCAST_POP
        return c, lbl, la, lo, True
    city = _ptr_city(ptr)
    cl = GEO.cloud(ip)
    if cl:
        prov, reg = cl
        tab = KB.AWS_REGIONS if prov == "aws" else KB.GCP_REGIONS
        name = "AWS" if prov == "aws" else "Google Cloud"
        if reg in tab:
            lbl, c, la, lo = tab[reg]
            return c, f"{lbl} ({name} {reg})", la, lo, False
        if reg.lower() == "global":
            if city:            # ex. CloudFront : le PTR donne le point de présence (cdg52 = Paris)
                lbl, c, la, lo = city
                return c, f"{lbl} (point de présence {name}, d'après le nom DNS)", la, lo, True
            c = cc or "US"
            la, lo, _ = KB.COUNTRIES.get(c, (None, None, ""))
            return c, f"Anycast {name} (réseau mondial, point de présence le plus proche)", la, lo, True
        la, lo, _ = KB.COUNTRIES.get(cc, (None, None, ""))
        return cc, f"{name} {reg}", la, lo, False
    if city:
        lbl, c, la, lo = city
        return c, f"{lbl} (d'après le nom DNS)", la, lo, False
    la, lo, _ = KB.COUNTRIES.get(cc, (None, None, ""))
    return cc, "", la, lo, False


_RISK_ORDER = {"faible": 0, "moyen": 1, "eleve": 2}
RISK_LABEL = {"faible": "faible", "moyen": "moyen", "eleve": "élevé"}
_BASE_RISK = {"dns": "moyen", "cloud": "faible", "cdn": "faible", "vpn": "faible", "messagerie": "faible",
              "iot-camera": "moyen", "push": "faible", "maj-logiciels": "faible", "stockage": "moyen",
              "streaming": "faible", "pub-tracking": "eleve", "ia": "faible", "telechargement": "faible",
              "systeme": "faible", "inconnu": "moyen"}
_GENERIC_HOSTING = {"Amazon AWS", "Google Cloud", "Microsoft (Azure / 365)", "OVHcloud", "Hetzner", "Scaleway",
                    "DigitalOcean", "Vultr", "Contabo", "Leaseweb", "IONOS", "Oracle Cloud", "Alibaba Cloud",
                    "Tencent Cloud", "Akamai Linode", "NetActuate", "netcup", "Hostinger", "Sakura Internet"}


def _bump(r, to):
    return to if _RISK_ORDER[to] > _RISK_ORDER[r] else r


def _ports_txt(d):
    return ", ".join(f"{p}/{pr}" for pr in sorted(d["protos"]) for p in sorted(d["ports"]) if (pr, p) in d["pp"])[:80]


def assess(d, rule, via):
    """Risque + explication (FR) d'une destination."""
    cat, svc = d["category"], d["service"]
    risk = rule.get("risk") or _BASE_RISK.get(cat, "moyen")
    why = []
    if rule.get("note"):
        why.append(rule["note"])
    src_names = [s["name"] for s in d["sources"]]
    if rule.get("dns_resolver"):
        bypass = [s for s in d["sources"] if s["host"] != "homelab"]
        if bypass:
            risk = _bump(risk, "moyen")
            parts = []
            for s in bypass:
                dot = any(x.startswith("853/") for x in s.get("pp") or [])
                parts.append(s["name"] + (" (DNS-over-TLS)" if dot else ""))
            why.append(f"Interroge{'nt' if len(parts) > 1 else ''} directement {svc} : {', '.join(parts)}. Ces requêtes échappent au filtrage "
                       f"AdGuard et révèlent à ce résolveur tous les noms de domaine consultés.")
    if cat == "iot-camera":
        if d["gdpr"] in ("hors_ue", "inconnu"):
            risk = _bump(risk, "eleve")
            city = d["region"].split(" (")[0] if d["region"] else ""
            place = (f"à {city}" + (f" ({d['country_name']})" if d["country_name"] and d["country_name"] != city else "")
                     if city else f"en {d['country_name'] or 'pays inconnu'}")
            why.append(f"Serveur situé {place}, hors UE : les métadonnées des caméras (identifiants des "
                       f"bases, adresses IP, horaires de connexion) y transitent, et le flux vidéo peut y être relayé "
                       f"quand la connexion directe échoue.")
        else:
            why.append("Serveur de mise en relation P2P en UE : il connaît vos caméras et votre IP publique ; "
                       "le flux vidéo peut y être relayé si la connexion directe échoue.")
        if rule.get("eufy"):
            why.append("Eufy a déjà été épinglé (2022) pour des envois vers le cloud malgré la promesse « 100 % local ».")
    if any(s.get("ccat") == "db" for s in d["sources"]):
        risk = "eleve"
        why.append("Une base de données (" + ", ".join(s["name"] for s in d["sources"] if s.get("ccat") == "db") +
                   ") ne devrait jamais joindre Internet : signe de compromission possible ou de configuration trop ouverte.")
    indexer = [s["name"] for s in d["sources"] if KB.INDEXER_SOURCES.search(s["name"])]
    if indexer and cat in ("cdn", "cloud", "inconnu") and via in ("asn", "org", "ptr", "aucun"):
        why.append(f"{', '.join(indexer)} interroge{'nt' if len(indexer) > 1 else ''} des indexeurs et sites de métadonnées : "
                   f"destination probablement l'un d'eux, hébergé chez {svc}.")
    if d.get("domains") and via != "domaine" and (cat == "cdn" or d.get("anycast")):
        why.append("IP partagée qui sert aussi : " + ", ".join(d["domains"]) + " (correspondance non certaine).")
    if cat == "inconnu":
        why.append("Service non identifié (ni plage, ni domaine, ni PTR connus).")
        if not (d["ports"] & KB.COMMON_PORTS):
            risk = _bump(risk, "eleve")
            why.append(f"Port inhabituel ({_ports_txt(d)}).")
    elif cat == "cloud" and svc in _GENERIC_HOSTING and via in ("asn", "org", "ptr") and not indexer:
        risk = _bump(risk, "moyen")
        why.append(f"Serveur loué chez {svc} : le service réellement contacté n'est pas identifiable par l'IP seule.")
    if 80 in d["ports"] and cat not in ("vpn", "maj-logiciels", "systeme"):
        risk = _bump(risk, "moyen")
        why.append("Port 80 : échange HTTP non chiffré (contenu lisible sur le trajet).")
    if d["gdpr"] == "hors_ue" and cat not in ("iot-camera",):
        unsure = " (localisation incertaine)" if d.get("geo_confidence") == "faible" else ""
        if d["country"] == "US":
            why.append(f"Serveur aux États-Unis{unsure} : transfert couvert seulement si la société adhère au "
                       f"Data Privacy Framework UE–États-Unis.")
        else:
            why.append(f"Serveur hors UE ({d['country_name']}){unsure}, pays sans décision d'adéquation RGPD.")
    if d["org_country"] == "US" and cat in ("stockage", "ia", "iot-camera", "cloud", "messagerie") and d["gdpr"] in ("ue", "eee"):
        why.append("Serveur en UE mais société américaine (soumise au CLOUD Act).")
    if d["states"].get("SYN_SENT") or (d["states"].get("UNREPLIED") and not d["states"].get("OK")):
        why.append("Tentatives sans réponse observées (service injoignable ou bloqué en amont).")
    if not why:
        why.append(f"Flux attendu de {', '.join(sorted(set(src_names)))} vers {svc}.")
    return risk, " ".join(why)


def _proto_flags(d):
    p = sorted(d["protos"])
    ports = sorted(d["ports"])
    pr = p[0] if len(p) == 1 else None
    return pr, ports


def block_options(d, rule):
    """Moyens concrets de bloquer (jamais appliqués ici)."""
    out, seen = [], set()
    dst = d["ip"]
    pr, ports = _proto_flags(d)
    pspec = (f" -p {pr} --dport {ports[0]}" if pr and len(ports) == 1 else "")
    ports_h = " ".join(f"{pr_.upper()} {p}" for pr_, p in sorted(d["pp"]))[:60]

    def add(method, how, rule_, impact=""):
        k = (method, rule_)
        if k in seen:
            return
        seen.add(k)
        e = {"method": method, "how": how, "rule": rule_}
        if impact:
            e["impact"] = impact
        out.append(e)

    names = {s["name"] for s in d["sources"]}
    kinds = {s["kind"] for s in d["sources"]}
    # 1. Réglage applicatif
    if rule.get("eufy"):
        if "Home Assistant (VM)" in names:
            add("app", "Home Assistant → module complémentaire / intégration Eufy Security : régler la connexion P2P sur "
                       "« uniquement locale » si caméras et HomeBase sont sur le même réseau, puis tester le blocage de l'UDP 32100 sortant.",
                "p2pConnectionSetup = ONLY_LOCAL",
                "Plus de flux vidéo à distance via le cloud Eufy (l'accès distant passe alors par Tailscale).")
        if "eufy-security-ws" in names or "NAS Unraid (hôte)" in names:
            add("app", "Conteneur eufy-security-ws (NAS) : dans sa configuration, passer la connexion P2P en mode local uniquement.",
                "p2pConnectionSetup = ONLY_LOCAL (config eufy-security-ws)",
                "Le cloud Eufy reste nécessaire pour l'authentification, mais plus pour la mise en relation P2P.")
        add("app", "Appli Eufy Security : désactiver les fonctions cloud inutilisées (stockage cloud, vignettes dans les notifications).",
            "Eufy → Paramètres de la HomeBase/caméra → Notifications : sans vignette")
    if rule.get("app"):
        add("app", rule["app"][0], rule["app"][1], rule.get("impact", ""))
    # 2. Contournement DNS
    if rule.get("dns_resolver"):
        if "Home Assistant (VM)" in names:
            add("dns", "Home Assistant : Paramètres → Système → Réseau → serveur DNS 192.168.2.4, puis couper le repli "
                       "DNS-over-TLS vers 1.1.1.1 du plugin DNS (terminal SSH de HA). 192.168.2.1 reste en secours : "
                       "sans lui, HA n'a plus de DNS pendant un redémarrage du homelab.",
                "ha dns options --servers dns://192.168.2.4 --servers dns://192.168.2.1 && ha dns options --fallback=false")
        if names & {"NAS Unraid (hôte)"} or any(s["host"] == "nas" and s["kind"] == "conteneur" for s in d["sources"]):
            add("dns", "NAS Unraid : Settings → Network Settings → DNS server 1 = 192.168.2.4 et DNS server 2 = 192.168.2.1, "
                       "en remplaçant TOUS les serveurs actuels (aucun résolveur public ne doit rester, même en secours), "
                       "puis vérifier depuis le NAS avec nslookup example.com ; les conteneurs héritent de ce résolveur.",
                "DNS server 1: 192.168.2.4 / DNS server 2: 192.168.2.1")
        add("routeur", f"Routeur ASUS ({ROUTER_URL}) → Pare-feu → Filtre des services réseau : liste noire du port 853 (DoT) et "
                       f"du port 53 vers Internet pour les appareils concernés ; ou LAN → DNS Director (si présent) pour "
                       f"rediriger tout le DNS vers 192.168.2.4, en exceptant 192.168.2.4 lui-même.",
            f"Source {', '.join(sorted(set(s['src_ip'] if s['kind'] != 'conteneur' else NAS_IP for s in d['sources'])))} → "
            f"destination {dst}, ports 53 et 853, TCP+UDP")
    # 3. AdGuard (efficace seulement si l'appareil utilise AdGuard)
    doms = rule.get("adguard") or []
    if doms:
        bypass = (names & {"Home Assistant (VM)", "NAS Unraid (hôte)"}) or any(s["host"] == "nas" for s in d["sources"])
        add("adguard", f"AdGuard Home ({ADGUARD_URL}) → Filtres → Règles de blocage personnalisées."
            + (" Domaine déduit de l'IP (partagée ou nom inverse) : vérifier d'abord dans le journal des requêtes."
               if rule.get("domain_shared") or rule.get("domain_guess") else "")
            + (" Inefficace tant que la source n'utilise pas AdGuard comme DNS (le NAS interroge 1.1.1.1)." if bypass else ""),
            "\n".join(f"||{x}^" for x in doms), rule.get("impact", ""))
    # 4. Au plus près de la source
    for s in d["sources"]:
        if s["kind"] == "conteneur" and s["host"] == "nas":
            if s.get("ccat") == "db":
                add("docker", f"{s['name']} : base de données → réseau Docker « internal: true » (comme boussole_internal / "
                              f"faimilymeal_backend) ; l'appli garde un 2e réseau pour sortir.",
                    "networks:\n  db_net:\n    internal: true")
            elif s["src_ip"] != NAS_IP:
                add("docker", f"{s['name']} : règle dans la chaîne DOCKER-USER du NAS, rendue persistante via le plugin "
                              f"User Scripts (« At Startup of Array », précédée d'un sleep 60). L'IP du conteneur peut "
                              f"changer au redémarrage : la fixer ou cibler le réseau.",
                    f"iptables -I DOCKER-USER -s {s['src_ip']} -d {dst}{pspec} -j DROP")
            else:   # conteneur en réseau « host »
                add("iptables", f"{s['name']} (réseau hôte) : règle OUTPUT sur le NAS, persistante via User Scripts.",
                    f"iptables -I OUTPUT -d {dst}{pspec} -j REJECT")
        elif s["kind"] == "hote" and s["host"] == "nas":
            add("iptables", "NAS (hôte) : règle OUTPUT, persistante via User Scripts (« At Startup of Array »).",
                f"iptables -I OUTPUT -d {dst}{pspec} -j REJECT")
        elif s["kind"] == "vm":
            add("iptables", "VM Home Assistant : son trafic traverse le pont br0 du NAS (filtrable grâce à br_netfilter) ; "
                            "règle FORWARD sur le NAS, persistante via User Scripts.",
                f"iptables -I FORWARD -s {HA_IP} -d {dst}{pspec} -j DROP")
        elif s["host"] == "homelab":
            add("iptables", "Homelab : règle OUTPUT (sudo), à rendre persistante dans /etc/nftables.conf.",
                f"sudo iptables -I OUTPUT -d {dst}{pspec} -j REJECT")
    # 5. Routeur (vaut pour tout le LAN ; les conteneurs NATés apparaissent comme le NAS)
    if not rule.get("dns_resolver"):
        srcs = sorted({s["src_ip"] if s["kind"] in ("vm", "appareil") or s["host"] == "homelab" else NAS_IP for s in d["sources"]})
        add("routeur", f"Routeur ASUS ({ROUTER_URL}) → Pare-feu → Filtre des services réseau (liste noire). Les conteneurs du "
                       f"NAS sortent avec l'IP du NAS : la règle s'applique alors à tout le NAS.",
            f"Source {', '.join(srcs)} → destination {dst}, {ports_h}")
    # Conséquence propre au service : vaut aussi pour les options qui coupent réellement le trafic
    imp = rule.get("impact", "")
    if imp:
        for e in out:
            if e["method"] in ("iptables", "docker", "routeur", "dns") and not e.get("impact"):
                e["impact"] = imp
    # Résolveur DNS : le blocage n'est sûr qu'APRÈS le changement de DNS de la source (prérequis, pas alternative)
    if rule.get("dns_resolver"):
        for e in out:
            if e["method"] in ("iptables", "docker", "routeur"):
                e["how"] = ("PRÉREQUIS : configurer d'abord 192.168.2.4 comme DNS de la source (option « dns » si proposée), "
                            "DNS secondaire compris, et vérifier la résolution (nslookup). " + e["how"])
                e["impact"] = ("Si la source utilise encore ce résolveur : chaque requête DNS échoue ou attend, puis bascule "
                               "sur son DNS secondaire (ex. 8.8.8.8) ; sans secours, plus aucune résolution "
                               "(docker pull, mises à jour, Tailscale…).")
    if d.get("anycast") or rule.get("domain_shared") or d.get("category") == "cdn":
        for e in out:
            if e["method"] in ("iptables", "docker", "routeur") and not rule.get("dns_resolver"):
                e["impact"] = ((e.get("impact", "") + " ") if e.get("impact") else "") + \
                    "IP partagée (CDN/anycast) : la bloquer coupe aussi d'autres sites hébergés derrière."
    return out


# =====================================================================================================
# Historique, constats, événements
# =====================================================================================================
def _load_hist():
    try:
        with open(HIST_FILE) as f:
            h = json.load(f)
        if isinstance(h, dict) and "dest" in h:
            return h
    except (OSError, ValueError):
        pass
    return {"v": 1, "created": time.time(), "cycles": 0, "dest": {}, "pairs": {}}


HIST = _load_hist()
_SAVE = {"t": 0, "dirty": False}


def _update_hist(dests, now):
    """Première/dernière vue par destination ; renvoie les nouveaux couples (source, pays/catégorie)."""
    HIST["cycles"] = HIST.get("cycles", 0) + 1
    hd, pairs = HIST["dest"], HIST["pairs"]
    new_pairs = []
    for d in dests:
        e = hd.get(d["ip"])
        if not e:
            e = hd[d["ip"]] = {"f": now, "l": now, "n": 0}
            _SAVE["dirty"] = True
        e["l"] = now
        e["n"] = e.get("n", 0) + 1
        e.update(cc=d["country"], svc=d["service"], cat=d["category"])
        e["src"] = sorted(set(e.get("src", [])) | {s["name"] for s in d["sources"]})[:12]
        d["first_seen"], d["last_seen"], d["seen_count"] = e["f"], e["l"], e["n"]
        for s in d["sources"]:
            keys = [f"{s['host']}|{s['name']}|cc:{d['country'] or '??'}"]
            if d["category"] in KB.RISKY_CATEGORIES or d["risk"] == "eleve":
                keys.append(f"{s['host']}|{s['name']}|cat:{d['category']}")
            for k in keys:
                if k not in pairs:
                    pairs[k] = [now, now]
                    new_pairs.append((k, s, d))
                    _SAVE["dirty"] = True
                else:
                    pairs[k][1] = now
    # purge 30 j
    cut = now - HIST_KEEP
    for k in [k for k, v in hd.items() if v.get("l", 0) < cut]:
        del hd[k]
    for k in [k for k, v in pairs.items() if v[1] < cut]:
        del pairs[k]
    if _SAVE["dirty"] or now - _SAVE["t"] > 300:
        _write_json(HIST_FILE, HIST)
        _SAVE.update(t=now, dirty=False)
    return new_pairs


def _emit_events(new_pairs, now):
    """Une alerte par (source, destination) nouvelle ; les plus risquées d'abord, au plus 3 par cycle."""
    if now - HIST.get("created", now) < BASELINE or HIST.get("cycles", 0) < 3:
        return          # période d'apprentissage : pas d'alertes
    grouped = {}
    for k, s, d in new_pairs:
        g = grouped.setdefault((s["host"], s["name"], d["ip"]), {"s": s, "d": d, "cc": False, "cat": False})
        g["cc" if "|cc:" in k else "cat"] = True
    items = sorted(grouped.values(), key=lambda g: (-_RISK_ORDER[g["d"]["risk"]], not g["cat"], -g["d"]["conns"]))
    for g in items[:MAX_EVENTS_PER_CYCLE]:
        s, d = g["s"], g["d"]
        where = d["country_name"] or "pays inconnu"
        if d["region"] and "(" in d["region"] and not d["anycast"]:
            where = d["region"].split(" (")[0]
        elif d.get("geo_confidence") == "faible" and d["country_name"]:
            where += " ?"          # ex. frontaux Google : pays DB-IP peu fiable
        what = KB.CATEGORIES.get(d["category"], (d["category"],))[0]
        title = f"Nouvelle destination : {s['name']} → {where} ({d['service']})"
        detail = (f"{d['ip']}{' (' + d['ptr'] + ')' if d['ptr'] else ''}, {_ports_txt(d)} — "
                  f"{'nouveau pays' if g['cc'] else ''}{' et ' if g['cc'] and g['cat'] else ''}"
                  f"{'nouvelle catégorie « ' + what + ' »' if g['cat'] else ''} pour cette source, risque {RISK_LABEL[d['risk']]}. "
                  f"{d['why'][:220]}")
        lvl = "warn" if (d["risk"] != "faible" or g["cat"]) else "info"
        STATE.event(lvl, s["host"], title, detail, "egress")
    rest = len(items) - MAX_EVENTS_PER_CYCLE
    if rest > 0:
        STATE.event("info", "nas", f"Flux sortants : {rest} autre(s) nouvelle(s) destination(s)",
                    "Voir la carte des flux sortants.", "egress")


def build_findings(dests, coverage):
    F = []
    # DNS contourné (par machine : les conteneurs du NAS héritent du résolveur de l'hôte)
    groups = {}
    for d in dests:
        if d["category"] != "dns":
            continue
        for s in d["sources"]:
            if s["host"] == "homelab":
                continue
            g = "NAS Unraid" if s["host"] == "nas" and s["kind"] in ("hote", "conteneur") else s["name"]
            e = groups.setdefault(g, {"dests": {}, "conts": set(), "dot": False, "ports": set()})
            e["dests"][d["ip"]] = d
            if s["kind"] == "conteneur":
                e["conts"].add(s["name"])
            e["ports"].update(s.get("pp") or [])
            e["dot"] = e["dot"] or any(x.startswith("853/") for x in s.get("pp") or [])
    for g, e in sorted(groups.items()):
        svcs = ", ".join(sorted({d["service"] for d in e["dests"].values()}))
        who = g + (f" (hôte + {len(e['conts'])} conteneur{'s' if len(e['conts']) > 1 else ''})" if e["conts"] else "")
        if g == "Home Assistant (VM)":
            act = ("Terminal SSH de HA : ha dns options --servers dns://192.168.2.4 --servers dns://192.168.2.1 puis "
                   "ha dns options --fallback=false (coupe le repli DNS-over-TLS vers 1.1.1.1 du plugin DNS de HA OS ; "
                   "192.168.2.1 sert de secours pendant un redémarrage du homelab)")
        elif g == "NAS Unraid":
            act = ("Unraid : Settings → Network Settings → DNS server 1 = 192.168.2.4, DNS server 2 = 192.168.2.1 "
                   "(remplacer TOUS les serveurs actuels : aucun résolveur public, même en secours), vérifier avec "
                   "nslookup ; les conteneurs suivent au redémarrage")
        else:
            act = "Configurer 192.168.2.4 comme DNS de cet appareil (DNS secondaire compris) et vérifier la résolution"
        detail = ("Ses requêtes DNS" + (" (en DNS-over-TLS, port 853)" if e["dot"] else "") +
                  " échappent à AdGuard : pas de filtrage pubs/traqueurs, pas de journal, et le résolveur externe voit "
                  "tous les domaines consultés.")
        if e["conts"]:
            detail += " Conteneurs concernés : " + ", ".join(sorted(e["conts"])) + "."
        # group : nom stable de la source (clé d'alerte indépendante du titre, qui varie avec les conteneurs)
        F.append({"level": "warn", "title": f"DNS contourné : {who} → {svcs}", "detail": detail,
                  "action": act + " ; seulement ensuite, bloquer 53/853 sortants sur le routeur ASUS sauf pour 192.168.2.4.",
                  "refs": sorted(e["dests"]), "kind": "dns", "ports": sorted(e["ports"]), "group": g})
    # Caméras / IoT
    iot = [d for d in dests if d["category"] == "iot-camera"]
    out_eu = [d for d in iot if d["gdpr"] in ("hors_ue", "inconnu")]
    if out_eu:
        places = ", ".join(sorted({(d["region"].split(" (")[0] if d["region"] else d["country_name"]) or "?" for d in out_eu}))
        srcs = ", ".join(sorted({s["name"] for d in out_eu for s in d["sources"]}))
        F.append({"level": "warn", "title": f"Caméras : mise en relation P2P via {places} (hors UE)",
                  "detail": f"{srcs} contacte{'nt' if ',' in srcs else ''} des serveurs P2P Eufy hors UE "
                            f"({len(out_eu)} IP) : identifiants des caméras et IP publique y transitent ; la vidéo peut y "
                            f"être relayée si la liaison directe échoue.",
                  "action": "Passer eufy-security-ws en P2P local uniquement (p2pConnectionSetup = ONLY_LOCAL), puis "
                            "bloquer l'UDP 32100 sortant (routeur ASUS ou iptables) et vérifier que les flux restent disponibles.",
                  "refs": [d["ip"] for d in out_eu], "kind": "iot"})
    elif iot:
        F.append({"level": "info", "title": f"Caméras : {len(iot)} serveur(s) P2P, tous en UE",
                  "detail": "Mise en relation P2P Eufy via des serveurs européens.", "action": "Rien d'urgent ; mode P2P local possible.",
                  "refs": [d["ip"] for d in iot], "kind": "iot"})
    # Bases de données qui sortent
    dbs = {}
    for d in dests:
        for s in d["sources"]:
            if s.get("ccat") == "db":
                dbs.setdefault(s["name"], []).append(d)
    for name, ds in dbs.items():
        F.append({"level": "crit", "title": f"Base de données sur Internet : {name}",
                  "detail": f"{name} contacte {len(ds)} destination(s) publique(s) ("
                            + ", ".join(f"{d['ip']} {d['service']}" for d in ds[:3]) + "). Une base ne devrait jamais sortir.",
                  "action": "Vérifier le conteneur (image, journaux), puis isoler sa base sur un réseau Docker « internal: true ».",
                  "refs": [d["ip"] for d in ds], "kind": "db"})
    # Bases joignables (potentiel) : réseaux non internes
    info = CTX.get("nas_info") or {}
    dnet = CTX.get("dnet") or {}
    if dnet:
        exposed = sorted(n for n, i in info.items() if i["cat"] == "db" and i["state"] == "running" and i["nets"]
                         and not any(dnet.get(x) for x in i["nets"]) and i["netmode"] != "none")
        if exposed:
            F.append({"level": "info", "title": f"{len(exposed)} bases de données peuvent joindre Internet",
                      "detail": "Leurs réseaux Docker ne sont pas « internal » : rien ne les empêche de sortir si elles "
                                "étaient compromises (" + ", ".join(exposed[:8]) + ("…" if len(exposed) > 8 else "") + ").",
                      "action": "Dans chaque docker-compose, placer la base sur un réseau « internal: true » partagé avec l'appli "
                                "(modèle : boussole_internal, faimilymeal_backend), l'appli gardant un réseau sortant.",
                      "refs": [], "kind": "db-hardening", "containers": exposed})
    # Destinations à risque élevé non couvertes ci-dessus
    for d in dests:
        if d["risk"] == "eleve" and d["category"] not in ("iot-camera",) and not any(s.get("ccat") == "db" for s in d["sources"]):
            F.append({"level": "warn", "title": f"Destination à risque : {d['service']} ({d['country_name'] or '?'})",
                      "detail": d["why"][:300], "action": (d["block"][0]["how"] if d["block"] else ""),
                      "refs": [d["ip"]], "kind": "risk"})
    # Nouvelles destinations
    new = [d for d in dests if d.get("is_new")]
    if new:
        # warn seulement après 24 h d'historique : avant, les flux périodiques légitimes paraissent tous « nouveaux »
        mature = time.time() - HIST.get("created", time.time()) >= NEW_WINDOW
        lvl = "warn" if mature and any(d["risk"] != "faible" for d in new) else "info"
        F.append({"level": lvl, "title": f"{len(new)} nouvelle(s) destination(s) depuis 24 h",
                  "detail": "; ".join(f"{', '.join(sorted({s['name'] for s in d['sources']}))} → {d['service']} "
                                      f"({d['country_name'] or '?'}"
                                      f"{' ?' if d['country_name'] and d.get('geo_confidence') == 'faible' else ''})"
                                      for d in new[:5]),
                  "action": "Vérifier qu'elles correspondent à une mise à jour ou à une nouvelle fonction attendue.",
                  "refs": [d["ip"] for d in new], "kind": "new"})
    # HTTP en clair
    http = [d for d in dests if 80 in d["ports"] and d["category"] not in ("vpn", "maj-logiciels", "systeme")]
    if http:
        F.append({"level": "info", "title": f"{len(http)} flux HTTP non chiffré(s)",
                  "detail": ", ".join(f"{d['service']} ({d['ip']})" for d in http[:5]),
                  "action": "Préférer HTTPS dans la configuration des applis concernées.", "refs": [d["ip"] for d in http], "kind": "http"})
    # Hors UE (synthèse)
    hors = [d for d in dests if d["gdpr"] == "hors_ue"]
    if hors:
        cc = Counter(d["country_name"] or d["country"] for d in hors)
        F.append({"level": "info", "title": f"{len(hors)} destination(s) hors UE dans {len(cc)} pays",
                  "detail": ", ".join(f"{k} ({v})" for k, v in cc.most_common(6)),
                  "action": "Normal pour les services américains (Google, Anthropic…) ; à surveiller pour les données personnelles.",
                  "refs": [d["ip"] for d in hors], "kind": "gdpr"})
    # Visibilité
    F.append({"level": "info", "title": "Visibilité partielle des flux", "detail": coverage["note"],
              "action": "Pour tout voir : journal de requêtes AdGuard, ou conntrack/NetFlow sur le routeur.", "refs": [], "kind": "coverage"})
    order = {"crit": 0, "warn": 1, "info": 2}
    F.sort(key=lambda f: order.get(f["level"], 3))
    return F


# =====================================================================================================
# Cycle principal
# =====================================================================================================
def _aggregate(flows, wan_ip):
    dests = {}
    for f in flows:
        if f["dst"] == wan_ip:
            continue          # « hairpin » vers sa propre IP publique : ne sort pas réellement
        d = dests.get(f["dst"])
        if not d:
            d = dests[f["dst"]] = {"ip": f["dst"], "ports": set(), "protos": set(), "pp": set(), "conns": 0,
                                   "states": Counter(), "src": {}}
        d["ports"].add(f["dport"])
        d["protos"].add(f["proto"])
        d["pp"].add((f["proto"], f["dport"]))
        d["conns"] += f["n"]
        d["states"][f["state"]] += f["n"]
        k = (f["host"], f["name"])
        s = d["src"].get(k)
        if not s:
            s = d["src"][k] = {"host": f["host"], "src_ip": f["src_ip"], "name": f["name"], "kind": f["kind"], "conns": 0,
                               "pp": set()}
            if f.get("ccat"):
                s["ccat"] = f["ccat"]
        s["conns"] += f["n"]
        s["pp"].add(f"{f['dport']}/{f['proto']}")
        if f.get("process") and f["process"] not in s.get("process", ""):
            s["process"] = (s.get("process", "") + ", " + f["process"]).strip(", ")[:60]
    return list(dests.values())


def _score(dests, findings):
    """Note de confidentialité 0–100 (indicative) : pénalités par constat et par destination à risque."""
    pen = 0
    for f in findings:
        pen += {"crit": 25, "warn": 10}.get(f["level"], 0)
    for d in dests:
        pen += {"eleve": 4, "moyen": 1}.get(d["risk"], 0)
    return max(0, min(100, 100 - pen))


def run():
    """Collecte + enrichissement ; écrit STATE['slow']['egress']. Ne lève jamais d'exception."""
    t0 = time.time()
    try:
        GEO.kick()
        _kick_domains()
        flows, errs = [], []
        try:
            flows += collect_nas()
        except Exception as e:
            CTX["nas_ok"] = False
            errs.append(f"nas : {type(e).__name__}: {e}")
        try:
            flows += collect_homelab()
        except Exception as e:
            CTX["homelab_ok"] = False
            errs.append(f"homelab : {type(e).__name__}: {e}")
        wan = (STATE.get("slow", "wan") or {}).get("ip", "")
        raw = _aggregate(flows, wan)
        ptrs = PTR.resolve([d["ip"] for d in raw])
        PTR.save()
        now = time.time()
        dests = []
        for r in raw:
            ip = r["ip"]
            asn, org, org_cc = GEO.asn_of(ip)
            cc = GEO.country(ip)
            ptr = ptrs.get(ip, "")
            rule, via = classify(ip, asn, org, ptr, r["ports"], r["protos"], [k[1] for k in r["src"]])
            country, region, lat, lon, anycast, conf = locate(ip, cc, asn, ptr, rule)
            if lat is None:
                lat, lon = None, None
            zone = KB.gdpr_zone(country)
            d = {"ip": ip, "ptr": ptr, "asn": asn or None, "org": KB.prettify_org(org), "org_country": org_cc,
                 "country": country or "", "country_name": (KB.COUNTRIES.get(country) or (0, 0, ""))[2],
                 "region": region, "lat": lat, "lon": lon, "anycast": anycast, "geo_confidence": conf,
                 "category": rule["cat"], "service": rule["svc"], "identified_by": via,
                 "domains": [x[0] for x in DOMAINS["map"].get(ip, [])][:3],
                 "ports": r["ports"], "protos": r["protos"], "pp": r["pp"],
                 "sources": sorted(r["src"].values(), key=lambda s: -s["conns"]), "conns": r["conns"],
                 "states": dict(r["states"]), "eu": zone in ("ue", "eee"), "gdpr": zone}
            d["risk"], d["why"] = assess(d, rule, via)
            d["block"] = block_options(d, rule)
            dests.append(d)
        new_pairs = _update_hist(dests, now)
        created = HIST.get("created", now)
        for d in dests:
            d["is_new"] = bool(d["first_seen"] >= created + BASELINE and now - d["first_seen"] < NEW_WINDOW)
        _emit_events(new_pairs, now)
        # sérialisation (ensembles -> listes triées)
        for d in dests:
            d["ports"] = sorted(d["ports"])
            d["protos"] = sorted(d["protos"])
            d["pp"] = [f"{p}/{pr}" for pr, p in sorted(d["pp"])]
            for s_ in d["sources"]:
                s_["pp"] = sorted(s_["pp"], key=lambda x: (int(x.split("/")[0]), x))
        dests.sort(key=lambda d: (-_RISK_ORDER[d["risk"]], -d["conns"]))
        # agrégats par pays
        cmap = {}
        for d in dests:
            c = d["country"] or "??"
            e = cmap.get(c)
            if not e:
                la, lo, nm = KB.COUNTRIES.get(c, (None, None, "Inconnu"))
                e = cmap[c] = {"code": c, "name": nm, "lat": la, "lon": lo, "conns": 0, "n_dest": 0,
                               "eu": d["eu"], "gdpr": d["gdpr"], "cats": Counter(), "risk": "faible"}
            e["conns"] += d["conns"]
            e["n_dest"] += 1
            e["cats"][d["category"]] += 1
            e["risk"] = _bump(e["risk"], d["risk"])
        countries = []
        for e in sorted(cmap.values(), key=lambda e: -e["conns"]):
            e["categories"] = [k for k, _ in e.pop("cats").most_common()]
            countries.append(e)
        # agrégats par source
        smap = {}
        for d in dests:
            for s in d["sources"]:
                k = (s["host"], s["name"])
                e = smap.get(k)
                if not e:
                    e = smap[k] = {"name": s["name"], "kind": s["kind"], "host": s["host"], "src_ip": s["src_ip"],
                                   "n_dest": 0, "countries": set(), "conns": 0, "categories": set(), "risk": "faible"}
                e["n_dest"] += 1
                e["conns"] += s["conns"]
                if d["country"]:
                    e["countries"].add(d["country"])
                e["categories"].add(d["category"])
                e["risk"] = _bump(e["risk"], d["risk"])
        by_source = []
        for e in sorted(smap.values(), key=lambda e: (-_RISK_ORDER[e["risk"]], -e["conns"])):
            e["countries"] = sorted(e["countries"])
            e["categories"] = sorted(e["categories"])
            by_source.append(e)
        coverage = {
            "nas": {"ok": bool(CTX["nas_ok"]), "method": "conntrack du NAS (hôte, conteneurs en bridge, VM Home Assistant)"},
            "homelab": {"ok": bool(CTX["homelab_ok"]), "method": "ss (sockets de l'hôte uniquement)"},
            "clawhost": {"ok": False, "method": "aucun accès"},
            "note": ("Vu : le NAS, ses conteneurs (bridge et host) et la VM Home Assistant via le conntrack du NAS ; les "
                     "sockets de l'hôte homelab. Non vu : les conteneurs du homelab (AdGuard, Unbound… : root requis), "
                     "clawhost (pas d'accès), les conteneurs du NAS en ipvlan (br0), les autres appareils du LAN "
                     "(téléphones, TV…). Instantané toutes les 30 s : les connexions très brèves peuvent échapper à la "
                     "mesure ; pas de volumes (compteurs d'octets conntrack désactivés)."),
        }
        findings = build_findings(dests, coverage)
        cats = Counter(d["category"] for d in dests)
        geo_ok = GEO.ready()
        data = {
            "generated_at": now, "duration_ms": round((time.time() - t0) * 1000),
            "coverage": coverage, "home": dict(KB.HOME), "attribution": ATTRIBUTION,
            "geo": {"ready": geo_ok, "sources": dict(GEO.status), "domains_known": len(DOMAINS["map"])},
            "categories": {k: {"label": v[0], "color": v[1]} for k, v in KB.CATEGORIES.items()},
            "destinations": dests, "countries": countries, "by_source": by_source, "findings": findings,
            "stats": {"n_dest": len(dests), "n_countries": len([c for c in countries if c["code"] != "??"]),
                      "n_outside_eu": sum(1 for d in dests if d["gdpr"] == "hors_ue"),
                      "n_conns": sum(d["conns"] for d in dests),
                      "by_category": dict(cats.most_common()),
                      "by_risk": {r: sum(1 for d in dests if d["risk"] == r) for r in ("eleve", "moyen", "faible")},
                      "n_new": sum(1 for d in dests if d["is_new"]),
                      "score": _score(dests, findings)},
        }
        if errs:
            data["errors"] = errs
        STATE.set("slow", "egress", data)
        return data
    except Exception as e:  # jamais d'exception vers le runner
        prev = STATE.get("slow", "egress") or {}
        prev = dict(prev)
        prev["error"] = f"{type(e).__name__}: {e}"
        STATE.set("slow", "egress", prev)
        return prev
