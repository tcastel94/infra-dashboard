"""Vulnérabilités (CVE) corrélées à l'infra : inventaire des versions (homelab, NAS, clawhost), analyse OSV / GitHub /
endoflife.date / CISA KEV / EPSS, score de risque contextualisé (exposition) et plan de correction priorisé.

Lecture seule : aucune commande ne modifie les machines (dpkg-query, apt-get -s, cAdvisor, une commande SSH fixe sur le
NAS — docker inspect filtré, versions, ss —, bannière SSH et page du gateway de clawhost, PING Redis, API publiques).
L'analyse tourne dans un processus Python séparé (scan()) : la mémoire du serveur reste stable.

Intégration : loop("vulns", 600, vulns.run, initial_delay=60) ; état publié dans STATE slow.vulns ;
liste complète des constats d'une action : vulns.findings_for(action_id=...) ou findings_for(component_id=...).
"""
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import date, datetime
from functools import cmp_to_key

from . import cvss
from .config import CADVISOR_URL, DATA_DIR, HOSTS
from .state import STATE
from .util import run as sh

STATE_FILE = os.path.join(DATA_DIR, "vuln-cache.json")      # état publié (léger, affichage immédiat au démarrage)
FINDINGS_FILE = os.path.join(DATA_DIR, "vuln-findings.json")  # tous les constats (findings_for)
CTX_FILE = os.path.join(DATA_DIR, "vuln-ctx.json")          # inventaire + planification (processus d'analyse)
OSV_FILE = os.path.join(DATA_DIR, "vuln-osv.json")          # détails OSV compactés (7 j)
HTTP_FILE = os.path.join(DATA_DIR, "vuln-http.json")        # GitHub, endoflife, KEV, EPSS (24 h)

INV_EVERY = 3600            # inventaire toutes les heures
SCAN_EVERY = 12 * 3600      # analyse complète toutes les 12 h
OSV_TTL = 7 * 86400
COMPACT_VER = 3             # version du format compact (un changement invalide le cache des détails)
DAY = 86400
DEADLINE = 170              # durée max d'une analyse (s)
HTTP_TIMEOUT = 20
CHILD_TIMEOUT = 300         # durée max du processus d'analyse
GH_TOKEN = os.environ.get("INFRADASH_GITHUB_TOKEN", "")

NAS_IP = HOSTS["nas"]["ip"]
HOMELAB_IP = HOSTS["homelab"]["ip"]
CLAW_IP = HOSTS["clawhost"]["ip"]
CLAW_IPS = {CLAW_IP, *HOSTS["clawhost"].get("old_ips", [])}
HOMELAB_COMPOSE = "/opt/homelab/docker-compose.yml"

EXPO_MULT = {"internet": 1.0, "lan": 0.75, "local": 0.45, "inconnue": 0.6}
PRIOS = ["critique", "haute", "moyenne", "basse"]
HOST_LABEL = {"homelab": "Homelab", "nas": "NAS", "clawhost": "clawhost"}
STATE_MAX_PER_COMP = 25     # findings détaillés par composant dans STATE (liste complète via findings_for())

_scan_lock = threading.Lock()
_mem = {"inv": None, "inv_t": 0, "scan_t": 0, "sig": None, "sources": {}}


# --- Comparaison de versions -------------------------------------------------------
def _deb_order(c):
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _deb_part(a, b):
    while a or b:
        na = re.match(r"^[^0-9]*", a).group(0)
        nb = re.match(r"^[^0-9]*", b).group(0)
        a, b = a[len(na):], b[len(nb):]
        for i in range(max(len(na), len(nb))):
            ca = _deb_order(na[i]) if i < len(na) else 0
            cb = _deb_order(nb[i]) if i < len(nb) else 0
            if ca != cb:
                return -1 if ca < cb else 1
        da = re.match(r"^[0-9]*", a).group(0)
        db = re.match(r"^[0-9]*", b).group(0)
        a, b = a[len(da):], b[len(db):]
        ia, ib = int(da or 0), int(db or 0)
        if ia != ib:
            return -1 if ia < ib else 1
    return 0


def deb_cmp(a, b):
    """Équivalent de dpkg --compare-versions (epoch:amont-révision)."""
    def split(v):
        v = (v or "").strip()
        ep = 0
        if ":" in v:
            e, v = v.split(":", 1)
            ep = int(e) if e.isdigit() else 0
        up, rev = (v.rsplit("-", 1) if "-" in v else (v, "0"))
        return ep, up, rev
    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _deb_part(ua, ub) or _deb_part(ra, rb)


def _toks(s):
    return [int(x) if x.isdigit() else x.lower() for x in re.findall(r"\d+|[A-Za-z]+", s)]


def _tok_cmp(ta, tb, pad):
    n = max(len(ta), len(tb))
    for i in range(n):
        if i >= len(ta) or i >= len(tb):
            if not pad:
                return -1 if len(ta) < len(tb) else 1
        x = ta[i] if i < len(ta) else 0
        y = tb[i] if i < len(tb) else 0
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int):
            return 1
        if isinstance(y, int):
            return -1
        return -1 if x < y else 1
    return 0


def norm_ver(v):
    v = (v or "").strip()
    v = re.sub(r"^[vV](?=\d)", "", v)
    return v.split("+", 1)[0]


def vcmp(a, b):
    """Comparaison type semver tolérante (préfixe v, pré-versions -rc/-beta inférieures à la finale)."""
    a, b = norm_ver(a), norm_ver(b)
    am, _, ap = a.partition("-")
    bm, _, bp = b.partition("-")
    c = _tok_cmp(_toks(am), _toks(bm), pad=True)
    if c:
        return c
    if ap == bp:
        return 0
    if not ap:
        return 1
    if not bp:
        return -1
    return _tok_cmp(_toks(ap), _toks(bp), pad=False)


def in_range(version, rng):
    """'< 1.37.0', '>= 2.0.0, < 3.2.4', '<= 10.10.7', '>= 1 < 2', '= 2026.7.1-2' -> True/False (None si illisible)."""
    cons = re.findall(r"(>=|<=|==|=|>|<)?\s*v?(\d[^\s,]*)", rng or "")
    if not cons:
        return None
    for op, x in cons:
        c = vcmp(version, x)
        ok = {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0, "==": c == 0, "": c == 0}[op]
        if not ok:
            return False
    return True


def _upper_bound(rng):
    """Borne '< X' d'une plage (version corrigée implicite)."""
    m = re.search(r"<\s*v?(\d[^\s,]*)", rng or "")
    return m.group(1) if m and not re.search(r"<=", rng[m.start():m.start() + 2]) else None


_PSEUDO = re.compile(r"^(?:v?0\.0\.0-|.*-0\.\d{14}-[0-9a-f]{12}$|.*\.0\.\d{14}-[0-9a-f]{12}$)")


def _pseudo(v):
    return bool(_PSEUDO.match(v or ""))


_PRE_RX = re.compile(r"-(?:alpha|beta|rc|pre|preview|a|b)(?:[.\d]|$)", re.I)


def _pre_other_branch(fixed, ver):
    """Correctif référencé = pré-version d'une autre branche que la version stable installée (ex. 0.108.0-b.16 / 0.107.79)."""
    f, v = norm_ver(fixed), norm_ver(ver)
    return bool(f and v and _PRE_RX.search(f) and not _PRE_RX.search(v) and _toks(f)[:2] != _toks(v)[:2])


# Correctifs rétroportés absents des advisories (plage limitée à la branche de développement)
_BACKPORTS = {   # (paquet, CVE/GHSA) -> première version stable corrigée
    ("github.com/AdguardTeam/AdGuardHome", "CVE-2022-32175"): "0.107.14",   # CHANGELOG AdGuard Home v0.107.14 (2022-09-29)
}


def _vmax(vs, cmp):
    vs = [v for v in vs if v]
    return max(vs, key=cmp_to_key(cmp)) if vs else None


def _vmin(vs, cmp):
    vs = [v for v in vs if v]
    return min(vs, key=cmp_to_key(cmp)) if vs else None


# --- Caches disque ---------------------------------------------------------------------
class _Cache:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = None
        self.dirty = False

    def _load(self):
        if self.data is None:
            try:
                with open(self.path) as f:
                    self.data = json.load(f)
            except (OSError, ValueError):
                self.data = {}

    def get(self, key, ttl):
        """(valeur, fraîche ?) ; valeur None si absente."""
        with self.lock:
            self._load()
            e = self.data.get(key)
        if not e:
            return None, False
        return e["d"], time.time() - e["t"] < ttl

    def put(self, key, value):
        with self.lock:
            self._load()
            self.data[key] = {"t": time.time(), "d": value}
            self.dirty = True

    def save(self, max_age=30 * DAY):
        with self.lock:
            if not self.dirty or self.data is None:
                return
            now = time.time()
            self.data = {k: v for k, v in self.data.items() if now - v["t"] < max_age}
            try:
                tmp = self.path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(self.data, f, separators=(",", ":"))
                os.replace(tmp, self.path)
                self.dirty = False
            except OSError:
                pass


OSV_CACHE = _Cache(OSV_FILE)
HTTP_CACHE = _Cache(HTTP_FILE)


# --- HTTP --------------------------------------------------------------------------------
def _http(url, data=None, timeout=HTTP_TIMEOUT, headers=None, raw=False, method=None):
    h = {"User-Agent": "infradash", "Accept": "application/json"}
    h.update(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        txt = r.read()
        if raw:
            return txt, r.headers
        return json.loads(txt)


def _http_text(url, timeout=5, limit=400_000):
    req = urllib.request.Request(url, headers={"User-Agent": "infradash"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(limit).decode(errors="ignore")


def _src(sources, name, ok, n=None, error=None):
    sources[name] = {"ok": ok, "n": n, "error": (str(error)[:200] if error else None), "t": time.time()}


# --- Inventaire ----------------------------------------------------------------------------
def _comp(id, name, version, host, kind, source, **kw):
    c = {"id": id, "name": name, "version": version or "inconnue", "host": host, "kind": kind, "source": source,
         "exposure": "inconnue", "exposure_detail": "", "osv": [], "eol": None, "gh": None}
    c.update(kw)
    return c


# Paquets Debian exposant un service réseau sur le homelab (ou utilisés par ces services)
DEB_NET = {
    "openssh": ("lan", "sshd écoute sur 0.0.0.0:22"),
    "python3.13": ("lan", "InfraDash (python3) écoute sur :7070"),
    "glibc": ("lan", "bibliothèque C utilisée par tous les services réseau (sshd…)"),
    "openssl": ("lan", "cryptographie de sshd et des services TLS"),
    "zlib": ("lan", "compression utilisée par sshd"),
    "pam": ("lan", "authentification de sshd"),
    "krb5": ("lan", "GSSAPI de sshd"),
    "systemd": ("local", "init, journal, logind (pas de service réseau exposé)"),
}
# Paquets de dépôts tiers : interrogés dans leur écosystème amont, pas dans Debian
DEB_THIRD = {"docker-ce", "containerd.io", "tailscale", "docker-compose-plugin", "docker-buildx-plugin",
             "tailscale-archive-keyring"}

OFFICIAL_IMAGES = {"postgres", "redis", "node", "python", "nginx", "alpine", "ubuntu", "debian", "mariadb", "mysql",
                   "mongo", "valkey", "busybox", "traefik", "caddy", "httpd", "memcached", "rabbitmq", "hello-world"}


def _image_repo(image):
    img = (image or "").split("@")[0]
    last = img.split("/")[-1]
    repo = img.rsplit(":", 1)[0] if ":" in last else img
    tag = last.split(":", 1)[1] if ":" in last else "latest"
    return repo, tag


def _is_custom(image):
    repo, _ = _image_repo(image)
    if repo.startswith("localhost/"):
        return True
    return "/" not in repo and repo.split("/")[-1] not in OFFICIAL_IMAGES


def _bad_label(v):
    """Labels de version hérités de l'image de base (ex. '24.04' d'Ubuntu) ou non informatifs."""
    return not v or v in ("latest", "release", "stable") or bool(re.match(r"^\d{2}\.04$", v))


def _clean_label(v):
    v = (v or "").strip()
    m = re.match(r"^v?(\d+(?:\.\d+)+)", v)
    return m.group(1) if m else v


# Labels compose (working_dir, service) : l'image peut les fixer elle-même -> validés avant toute commande root
_SAFE_WD = re.compile(r"^/[A-Za-z0-9_][A-Za-z0-9_./-]*$")
_SAFE_SVC = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def _safe_wd(wd):
    return bool(wd and _SAFE_WD.match(wd) and "/../" not in wd + "/")


def _cri_disabled(txt):
    """Config containerd : plugin CRI désactivé ? True/False ; None si config absente ou illisible (dans le doute, rien n'est écarté)."""
    if txt is None:
        return None
    m = re.search(r"^\s*disabled_plugins\s*=\s*\[([^\]]*)\]", txt, re.M)
    return bool(m and re.search(r"""["'](?:io\.containerd\.grpc\.v1\.)?cri["']""", m.group(1)))


def _parse_ports_compose(path):
    """Ports publiés par service dans un docker-compose.yml (analyse simple, sans dépendance YAML)."""
    out, svc, in_services, in_ports, netmode = {}, None, False, False, {}
    try:
        lines = open(path).read().splitlines()
    except OSError:
        return out, netmode
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        ind = len(line) - len(line.lstrip())
        s = line.strip()
        if ind == 0:
            in_services = s.startswith("services:")
            svc, in_ports = None, False
            continue
        if not in_services:
            continue
        if ind == 2 and s.endswith(":"):
            svc, in_ports = s[:-1].strip("'\""), False
            out.setdefault(svc, [])
            continue
        if svc and ind == 4:
            in_ports = s.startswith("ports:")
            if s.startswith("network_mode:"):
                netmode[svc] = s.split(":", 1)[1].strip().strip("'\"")
            continue
        if svc and in_ports and s.startswith("-"):
            item = s[1:].strip().strip("'\"").split("/")[0]
            parts = item.split(":")
            if len(parts) == 3:
                out[svc].append((parts[0], parts[1]))
            elif len(parts) == 2:
                out[svc].append(("0.0.0.0", parts[0]))
    return out, netmode


def _yaml_scalar(v):
    """Valeur d'une ligne YAML « clé: valeur » sans commentaire ni guillemets."""
    v = re.sub(r"\s+#.*$", "", (v or "").strip())
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def _parse_compose_build(lines):
    """Services d'un docker-compose filtré côté NAS : image (telle qu'écrite), build (context, dockerfile), container_name."""
    svcs, svc, in_svcs, s_ind, p_ind, in_build = {}, None, False, None, None, False
    for raw in lines:
        m = re.match(r"^(\s*)([A-Za-z0-9_.-]+):\s*(.*?)\s*$", raw)
        if not m:
            continue
        ind, k, rawv = len(m.group(1)), m.group(2), re.sub(r"\s+#.*$", "", m.group(3))
        v = _yaml_scalar(rawv)
        if ind == 0:
            in_svcs, svc, s_ind = k == "services", None, None
            continue
        if not in_svcs:
            continue
        s_ind = ind if s_ind is None else s_ind
        if ind <= s_ind:
            svc = svcs.setdefault(k, {}) if ind == s_ind and not v else None
            p_ind, in_build = None, False
            continue
        if svc is None:
            continue
        p_ind = ind if p_ind is None else p_ind
        if ind == p_ind:
            in_build = k == "build" and not v
            if k == "build":
                svc["context"] = v or svc.get("context") or "."
            elif k == "image":
                svc.update(image=v, image_raw=rawv, image_simple=raw.strip() == f"image: {rawv}")
            elif k == "container_name":
                svc["container_name"] = v
        elif in_build and k in ("context", "dockerfile"):
            svc[k] = v
    return svcs


_FROM_RX = re.compile(r"^\s*FROM\s+((?:--\S+\s+)*)(\S+)(?:\s+AS\s+(\S+))?", re.I)
_ARG_RX = re.compile(r"^\s*ARG\s+([A-Za-z_]\w*)=(\S+)", re.I)


def _dockerfile_bases(lines):
    """Images de base d'un Dockerfile : lignes FROM (étapes internes et scratch écartées), ARG global résolu.
    Seuls les ARG utilisés par un FROM sont conservés."""
    args, stages, out, seen_from = {}, set(), [], False
    for ln in lines:
        m = _FROM_RX.match(ln)
        if not m:
            a = _ARG_RX.match(ln)
            if a and not seen_from:   # seuls les ARG placés avant le 1er FROM sont utilisables dans un FROM
                args[a.group(1)] = (_yaml_scalar(a.group(2)), ln.strip())
            continue
        seen_from = True
        ref, line, arg = m.group(2), ln.strip(), None
        v = re.fullmatch(r"\$\{?(\w+)\}?", ref)
        if v and v.group(1) in args:
            arg = v.group(1)
            ref, line = args[arg]
        elif "$" in ref:
            ref = None   # référence composée (node:${VER}-alpine) : à modifier à la main
        if ref is None or (ref.lower() not in stages and ref.lower() != "scratch"):
            simple = (line == f"ARG {arg}={ref}") if arg else (line == f"FROM {ref}" or line.startswith(f"FROM {ref} "))
            out.append({"ref": ref, "line": line, "arg": arg, "simple": simple})
        if m.group(3):
            stages.add(m.group(3).lower())
    return out


def _parse_build(lines):
    """Section @@build : services des projets compose et images de base des Dockerfiles, par dossier de projet."""
    projects, cur, kind, path, buf = {}, None, None, None, []

    def flush():
        if cur is None or not path or not _safe_wd(path):
            return
        if kind == "C":
            for k, s in _parse_compose_build(buf).items():   # fichiers override : fusion dans l'ordre
                d = cur["services"].setdefault(k, {})
                if "image" in s or "compose" not in d:
                    d["compose"] = path   # fichier où l'image est écrite (celui à modifier)
                d.update(s)
        elif kind == "D":
            cur["dockerfiles"][path] = _dockerfile_bases(buf)

    for line in lines:
        m = re.match(r"^#([WCD]) (/\S*)$", line)
        if not m:
            buf.append(line)
            continue
        flush()
        buf = []
        if m.group(1) == "W":
            cur = projects.setdefault(m.group(2), {"services": {}, "dockerfiles": {}}) if _safe_wd(m.group(2)) else None
            kind, path = None, None
        else:
            kind, path = m.group(1), m.group(2)
    flush()
    return projects


def _build_info(projects, wd, svc, name, image):
    """Déclaration de l'image d'un conteneur : fichier compose, image écrite, Dockerfile et ses images de base.
    Un conteneur créé hors compose (docker run, sans labels) est rattaché au projet qui le déclare (container_name)."""
    orphan, p = False, projects.get(wd) if wd else None
    s = p["services"].get(svc) if p else None
    if s is None and not wd:
        for pwd, pp in sorted(projects.items()):
            k = next((k for k, ss in pp["services"].items() if ss.get("container_name") == name
                      and ss.get("image", image) == image), None)
            if k:
                p, s, wd, svc, orphan = pp, pp["services"][k], pwd, k, True
                break
    if s is None or not _SAFE_SVC.match(svc or ""):
        return None
    bi = {"wd": wd, "service": svc, "orphan": orphan, "compose": s.get("compose"), "image": s.get("image"),
          "image_raw": s.get("image_raw"), "image_simple": s.get("image_simple", False), "build": False}
    ctx = s.get("context")
    if ctx is not None and "://" not in ctx and not ctx.startswith("git@"):
        base = os.path.normpath(os.path.join(wd, ctx))
        df = s.get("dockerfile")
        cands = [os.path.normpath(os.path.join(base, df))] if df else \
            [os.path.join(base, "Dockerfile"), os.path.join(base, "dockerfile")]   # BuildKit accepte « dockerfile »
        path = next((x for x in cands if x in p["dockerfiles"]), cands[0])
        if _safe_wd(path):
            bi.update(build=True, dockerfile=os.path.relpath(path, wd), dockerfile_found=path in p["dockerfiles"],
                      bases=p["dockerfiles"].get(path, []))
    return bi


def _npm_entries():
    npm = (STATE.get("slow", "nas_sched") or {}).get("npm") or _mem.get("npm") or []
    return [e for e in npm if e.get("domain")]


def _npm_lookup(npm, ips, port):
    port = str(port)
    return [e["domain"] for e in npm if e.get("backend") in ips and str(e.get("port")) == port]


def _expo_from_bindings(binds, npm, ips, running=True, extra=""):
    """binds = [(ip, port_hote)] -> (exposition, détail)."""
    if not running:
        return "local", "conteneur arrêté"
    pub = []
    for ip, port in binds:
        doms = _npm_lookup(npm, ips, port)
        if doms and ip not in ("127.0.0.1", "::1"):
            pub.append(f"{', '.join(sorted(set(doms)))} → :{port}")
    if pub:
        return "internet", "publié via Nginx Proxy Manager : " + " ; ".join(sorted(set(pub)))
    lan = sorted({p for ip, p in binds if ip not in ("127.0.0.1", "::1")}, key=lambda x: int(x) if x.isdigit() else 0)
    if lan:
        return "lan", "port(s) " + ", ".join(lan) + " publié(s) sur le LAN" + extra
    if binds:
        return "local", "port(s) publié(s) sur 127.0.0.1 uniquement"
    return "local", "aucun port publié (réseau Docker interne)"


def _inv_homelab(sources):
    comps = []
    sources.pop("inventaire:homelab-conteneurs", None)
    st = STATE.get("slow", "homelab") or {}
    # Paquets Debian (regroupés par paquet source)
    out = sh(["dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n"], timeout=40)
    srcs, bins = {}, {}
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 5 or not p[0].startswith("ii"):
            continue
        _, pkg, ver, src, sver = p
        src, sver = src or pkg, sver or ver
        bins[pkg] = ver
        if src.startswith("linux-signed") or src == "linux" or src in DEB_THIRD or pkg in DEB_THIRD:
            continue
        srcs.setdefault((src, sver), []).append(pkg)
    if not srcs:
        _src(sources, "inventaire:homelab", False, 0, "dpkg-query sans résultat")
        return None
    for (src, sver), pk in sorted(srcs.items()):
        expo, det = DEB_NET.get(src, ("local", "paquet sans service réseau exposé"))
        comps.append(_comp(f"homelab:deb:{src}", src, sver, "homelab", "paquet-os", "dpkg (paquet source)",
                           exposure=expo, exposure_detail=det, osv=[["Debian:13", src, sver]], bins=sorted(pk)[:12],
                           action_key="homelab:apt", rem="apt-homelab"))
    # Noyau : version en cours d'exécution (un noyau plus récent peut être installé en attente de redémarrage)
    rel = os.uname().release
    kver = bins.get(f"linux-image-{rel}")
    inst = _vmax([v for k, v in bins.items() if re.match(r"^linux-image-\d", k)], deb_cmp)
    reboot = os.path.exists("/var/run/reboot-required")
    if kver:
        det = "pile réseau du noyau (exposition LAN), la plupart des CVE noyau sont locales"
        comps.append(_comp("homelab:noyau", "Noyau Linux (Debian)", kver, "homelab", "noyau", f"uname -r ({rel})",
                           exposure="lan", exposure_detail=det, osv=[["Debian:13", "linux", kver]],
                           installed=inst, reboot_required=reboot, action_key="homelab:noyau", rem="kernel-homelab"))
    try:
        dv = open("/etc/debian_version").read().strip()
    except OSError:
        dv = None
    comps.append(_comp("homelab:os", "Debian", dv, "homelab", "os", "/etc/debian_version", exposure="lan",
                       exposure_detail="hôte du LAN (192.168.2.4)", eol=["debian", "13", dv], eol_patch=True,
                       action_key="homelab:apt", rem="apt-homelab"))
    # Versions candidates d'apt (simulation, sans verrou ni droits root)
    avail = {}
    for line in sh(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=60).splitlines():
        m_ = re.match(r"^Inst (\S+) \[[^\]]*\] \((\S+)", line)
        if m_:
            avail[m_.group(1)] = m_.group(2)
    # Logiciels de dépôts tiers (Docker, Tailscale)
    dce = bins.get("docker-ce")
    if dce:
        v = re.sub(r"^\d+:", "", dce).split("-")[0]
        comps.append(_comp("homelab:docker-ce", "Docker Engine", v, "homelab", "service", "dpkg (dépôt Docker)",
                           exposure="local", exposure_detail="démon local (socket Unix), surface d'attaque = images/conteneurs",
                           osv=[["Go", "github.com/docker/docker", v]], eol=["docker-engine", None, v], eol_patch=True,
                           action_key="homelab:docker", rem="apt-docker", available=avail.get("docker-ce")))
    cio = bins.get("containerd.io")
    if cio:
        v = cio.split("-")[0]
        try:
            with open("/etc/containerd/config.toml") as fh:
                cri_off = _cri_disabled(fh.read())
        except OSError:
            cri_off = None
        comps.append(_comp("homelab:containerd", "containerd", v, "homelab", "runtime", "dpkg (containerd.io)",
                           exposure="local", exposure_detail="runtime de conteneurs local",
                           osv=[["Go", "github.com/containerd/containerd/v2", v]], action_key="homelab:docker", rem="apt-docker",
                           available=avail.get("containerd.io"), cri_disabled=cri_off))
    m = re.search(r"runc version (\S+)", sh(["runc", "--version"], timeout=5))
    if m:
        comps.append(_comp("homelab:runc", "runc", m.group(1), "homelab", "runtime", "runc --version (containerd.io)",
                           exposure="local", exposure_detail="runtime OCI local",
                           osv=[["Go", "github.com/opencontainers/runc", m.group(1)]], action_key="homelab:docker", rem="apt-docker"))
    ts = bins.get("tailscale")
    if ts:
        comps.append(_comp("homelab:tailscale", "Tailscale", ts, "homelab", "service", "dpkg (dépôt Tailscale)",
                           exposure="lan", exposure_detail="nœud du tailnet (100.115.23.106)",
                           osv=[["Go", "tailscale.com", ts]], action_key="homelab:tailscale", rem="apt-tailscale",
                           available=avail.get("tailscale")))
    # Conteneurs (labels cAdvisor + points de version applicatifs)
    try:
        spec = _http(f"{CADVISOR_URL}/api/v2.0/spec?type=docker&recursive=true", timeout=8)
    except Exception as e:  # noqa
        spec = {}
        _src(sources, "inventaire:homelab-conteneurs", False, 0, e)
    if not spec and "inventaire:homelab-conteneurs" not in sources:
        _src(sources, "inventaire:homelab-conteneurs", False, 0, "cAdvisor n'a renvoyé aucun conteneur")
    ports, netmode = _parse_ports_compose(HOMELAB_COMPOSE)
    npm = _npm_entries()

    def metric(url, rx):
        try:
            m_ = re.search(rx, _http_text(url, timeout=4))
            return m_.group(1) if m_ else None
        except Exception:
            return None
    n_ct = 0
    for v in spec.values():
        name = (v.get("aliases") or ["?"])[0]
        image = v.get("image", "")
        lb = v.get("labels") or {}
        svc = lb.get("com.docker.compose.service", name)
        wd = lb.get("com.docker.compose.project.working_dir", "/opt/homelab")
        lab = lb.get("org.opencontainers.image.version", "")
        repo, tag = _image_repo(image)
        ver, src, osv, eol, extra = None, "label OCI", [], None, {}
        if "adguardhome" in repo:
            ver = _clean_label(lab)
            osv = [["Go", "github.com/AdguardTeam/AdGuardHome", ver]]
            prod = "AdGuard Home"
        elif "victoria-metrics" in repo:
            ver = _clean_label(lab) or metric("http://127.0.0.1:8428/metrics", r'short_version="v?([^"]+)"')
            osv = [["Go", "github.com/VictoriaMetrics/VictoriaMetrics", ver]]
            prod = "VictoriaMetrics"
        elif "dozzle" in repo:
            ver = _clean_label(lab)
            osv = [["Go", "github.com/amir20/dozzle", ver]]
            prod = "Dozzle"
        elif "speedtest-tracker" in repo:
            ver, prod = _clean_label(lab), "Speedtest Tracker"
        elif repo.endswith("grafana/grafana"):
            try:
                ver, src = _http("http://127.0.0.1:3002/api/health", timeout=4).get("version"), "API /api/health"
            except Exception:
                ver = None
            osv = [["Go", "github.com/grafana/grafana", ver]] if ver else []
            eol = ["grafana", None, ver]
            prod = "Grafana"
        elif "node-exporter" in repo:
            ver = metric("http://127.0.0.1:9100/metrics", r'node_exporter_build_info\{[^}]*version="([^"]+)"')
            src, prod = "métrique node_exporter_build_info", "node-exporter"
            osv = [["Go", "github.com/prometheus/node_exporter", ver]] if ver else []
        elif "cadvisor" in repo:
            ver = metric(f"{CADVISOR_URL}/metrics", r'cadvisorVersion="v?([^"]+)"')
            src, prod = "métrique cadvisor_version_info", "cAdvisor"
            osv = [["Go", "github.com/google/cadvisor", ver]] if ver else []
        elif "uptime-kuma" in repo:
            prod = "Uptime Kuma"
            try:
                html = _http_text("http://127.0.0.1:3001/dashboard", timeout=4)
                js = re.search(r'src="(/assets/index-[^"]+\.js)"', html)
                if js:
                    m_ = re.search(r'frontendVersion\(\)\{return"([^"]+)"', _http_text("http://127.0.0.1:3001" + js.group(1), timeout=6, limit=5_000_000))
                    ver = m_.group(1) if m_ else None
                    src = "bundle web (frontendVersion), API protégée"
            except Exception:
                ver = None
            osv = [["npm", "uptime-kuma", ver]] if ver else []
        elif "unbound" in repo:
            prod, src = "Unbound", "aucune version exposée (label vide)"
        elif repo in ("python",):
            prod = "Python (image " + image + ")"
            cyc = re.match(r"(\d+\.\d+)", tag)
            eol = ["python", cyc.group(1) if cyc else None, None]
            src = "tag d'image"
        else:
            prod, ver = name, _clean_label(lab) or None
        expo, det = _expo_from_bindings(ports.get(svc, []), npm, {HOMELAB_IP}, True)
        if netmode.get(svc) == "host":
            expo, det = "lan", "réseau hôte"
        n_ct += 1
        comps.append(_comp(f"homelab:ct:{name}", prod, ver, "homelab", "appli", src, container=name, image=image,
                           exposure=expo, exposure_detail=det, osv=[q for q in osv if q[2]], eol=eol, eol_patch=True,
                           workdir=wd, service=svc, compose=True, action_key=f"homelab:ct:{name}", rem="homelab-ct", **extra))
    _src(sources, "inventaire:homelab", True, len(comps), None if spec else "conteneurs indisponibles (cAdvisor)")
    return comps


NAS_CMD = (
    "echo @@sys; echo \"unraid|$(cat /etc/unraid-version 2>/dev/null)\"; echo \"kernel|$(uname -r)\"; "
    "echo \"openssh|$(ssh -V 2>&1)\"; echo \"samba|$(smbd -V 2>/dev/null)\"; echo \"tailscale|$(tailscale version 2>/dev/null | head -1)\"; "
    "echo \"nginx|$(nginx -v 2>&1)\"; echo \"php|$(php -v 2>/dev/null | head -1)\"; echo \"openssl|$(openssl version 2>/dev/null)\"; "
    "echo \"containerd|$(containerd --version 2>/dev/null)\"; echo \"runc|$(runc --version 2>/dev/null | head -1)\"; "
    "echo \"containerd_cri|$(grep -m1 '^disabled_plugins' /var/run/docker/containerd/containerd.toml 2>/dev/null)\"; "
    "echo @@dockerver; docker version --format '{{json .}}' 2>/dev/null; "
    "echo @@inspect; docker inspect $(docker ps -aq) --format '{{json .Name}}{{\"\\t\"}}{{json .Config.Image}}{{\"\\t\"}}"
    "{{json .Config.Labels}}{{\"\\t\"}}{{range .Config.Env}}{{$k := index (split . \"=\") 0}}"
    "{{if or (eq $k \"PG_VERSION\") (eq $k \"REDIS_VERSION\") (eq $k \"NODE_VERSION\") (eq $k \"PYTHON_VERSION\") "
    "(eq $k \"NPM_BUILD_VERSION\") (eq $k \"OPENRESTY_VERSION\")}}{{.}};{{end}}{{end}}{{\"\\t\"}}"
    "{{json .HostConfig.NetworkMode}}{{\"\\t\"}}{{json .NetworkSettings.Ports}}{{\"\\t\"}}{{json .State.Status}}{{\"\\t\"}}"
    "{{range .Mounts}}{{if .RW}}{{.Type}}:{{.Source}}|{{end}}{{end}}' 2>/dev/null; "
    # Déclaration des images (plan de correction) : clés du compose sans valeur ou image/build/context/dockerfile/
    # container_name, et lignes FROM + ARG globaux des Dockerfiles. Rien d'autre (ni environnement ni secrets).
    "echo @@build; docker inspect $(docker ps -aq) --format '{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}"
    "|{{index .Config.Labels \"com.docker.compose.project.config_files\"}}' 2>/dev/null | sort -u | while IFS='|' read -r wd cf; do "
    "case \"$wd\" in /mnt/*/appdata/?*|/boot/config/?*|/root/?*|/opt/?*) ;; *) continue;; esac; echo \"#W $wd\"; "
    "echo \"$cf\" | tr ',' '\\n' | while read -r f; do [ -f \"$f\" ] && echo \"#C $f\" && grep -E "
    "'^[[:space:]]*[A-Za-z0-9_.-]+:[[:space:]]*$|^[[:space:]]*(image|build|context|dockerfile|container_name):' \"$f\"; done; "
    "find \"$wd\" -maxdepth 3 \\( -name node_modules -o -name .git \\) -prune -o -type f \\( -iname 'dockerfile*' -o -name Containerfile \\) "
    "-size -200k -print 2>/dev/null | head -40 | while read -r f; do echo \"#D $f\"; "
    "awk '/^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]/{s=1; print; next} !s && /^[[:space:]]*[Aa][Rr][Gg][[:space:]]/' \"$f\"; done; done; "
    "echo @@listen;ss -tlnpH 2>/dev/null | awk '{print $4, $6}'; "
    "echo @@npm; for f in /mnt/user/appdata/NginxProxyManager/nginx/proxy_host/*.conf; do "
    "sn=$(grep -m1 -oP 'server_name\\s+\\K[^;]+' $f); fw=$(grep -m1 -oP 'set \\$server\\s+\"?\\K[^\";]+' $f); "
    "fp=$(grep -m1 -oP 'set \\$port\\s+\\K[^;]+' $f); echo \"$sn|$fw|$fp\"; done 2>/dev/null; "
    "echo @@clawinv; d=$(ls -1d /mnt/user/backups/clawhost/*/ 2>/dev/null | tail -1); "
    "[ -n \"$d\" ] && awk '/^# conteneurs/{f=1;next} /^# /{f=0} f' \"${d}inventaire-systeme.txt\" 2>/dev/null; echo @@end"
)

# Produits reconnus dans les images du NAS : (motif image, clé, nom, options)
NAS_PRODUCTS = [
    (r"vaultwarden/server", "vaultwarden", "Vaultwarden", {"gh": "dani-garcia/vaultwarden", "gh_pkgs": ["vaultwarden"], "probe": (80, "/api/version", None)}),
    (r"immich-app/immich-server", "immich", "Immich", {"gh": "immich-app/immich", "gh_pkgs": ["immich", "immich-server"]}),
    (r"jellyfin", "jellyfin", "Jellyfin", {"gh": "jellyfin/jellyfin", "gh_pkgs": ["jellyfin", "Jellyfin.Server", "jellyfin-server"], "probe": (8096, "/System/Info/Public", "Version")}),
    (r"ollama/ollama", "ollama", "Ollama", {"go": "github.com/ollama/ollama", "probe": (11434, "/api/version", "version")}),
    (r"forgejo/runner", "forgejo-runner", "Forgejo Runner", {}),
    (r"forgejo/forgejo", "forgejo", "Forgejo", {"eol_slug": "forgejo"}),
    (r"gethomepage/homepage", "homepage", "Homepage", {"gh": "gethomepage/homepage", "gh_pkgs": ["homepage"]}),
    (r"nginx-proxy-manager", "npm", "Nginx Proxy Manager", {"gh": "NginxProxyManager/nginx-proxy-manager", "gh_pkgs": ["nginx-proxy-manager"]}),
    (r"(^|/)postgres$|pgvector|timescaledb", "postgresql", "PostgreSQL", {"eol_slug": "postgresql", "db": "PG_VERSION"}),
    (r"(^|/)redis$", "redis", "Redis", {"eol_slug": "redis", "db": "REDIS_VERSION"}),
    (r"(^|/)valkey", "valkey", "Valkey", {"eol_slug": "valkey"}),
    (r"flaresolverr", "flaresolverr", "FlareSolverr", {}),
    (r"browserless", "browserless", "Browserless (Chromium)", {}),
    (r"rommapp/romm", "romm", "RomM", {}),
    (r"eufy-security-ws", "eufy-security-ws", "eufy-security-ws", {}),
    (r"searcharr", "searcharr", "Searcharr", {}),
    (r"linuxserver/([\w-]+)", None, None, {}),
    (r"binhex/arch-([\w-]+)", None, None, {}),
]


def _sections(out):
    sec, cur = {}, None
    for line in out.splitlines():
        if line.startswith("@@"):
            cur = line[2:].strip()
            sec[cur] = []
        elif cur:
            sec[cur].append(line)
    return sec


def _hostport(ports, cport):
    for b in (ports or {}).get(f"{cport}/tcp") or []:
        if b.get("HostPort"):
            return b["HostPort"]
    return None


def _cycle_hint(tag, pattern=r"(\d+(?:\.\d+)?)"):
    m = re.search(pattern, tag or "")
    return m.group(1) if m else None


def _inv_nas(sources):
    from . import nas   # import tardif : évite de créer la connexion SSH à l'import
    sources.pop("inventaire:nas-conteneurs", None)
    out = nas.SSHC.run(NAS_CMD, timeout=45)
    if not out or "@@sys" not in out:
        _src(sources, "inventaire:nas", False, 0, f"SSH NAS : {nas.SSHC.last_error or 'pas de réponse'}")
        return None, [], False
    sec = _sections(out)
    sysv = {}
    for line in sec.get("sys", []):
        if "|" in line:
            k, v = line.split("|", 1)
            sysv[k] = v.strip()
    # Écoutes TCP de l'hôte (port -> processus)
    listen = {}
    for line in sec.get("listen", []):
        p = line.split(None, 1)
        if not p or ":" not in p[0]:
            continue
        addr, port = p[0].rsplit(":", 1)
        m = re.search(r'"([^"]+)"', p[1] if len(p) > 1 else "")
        listen.setdefault(port, {"proc": m.group(1) if m else "?", "addrs": set()})["addrs"].add(addr.strip("[]"))
    npm = []
    for line in sec.get("npm", []):
        p = line.split("|")
        if len(p) >= 3 and p[0]:
            npm.append({"domain": p[0].split()[0], "backend": p[1], "port": p[2]})
    npm = npm or _npm_entries()
    comps = []
    # Composants système Unraid
    webgui_doms = [f"{e['domain']} → :{e['port']}" for e in npm if e["backend"] == NAS_IP
                   and listen.get(str(e["port"]), {}).get("proc") == "nginx" and str(e["port"]) not in ("80", "81", "443")]
    gui_expo = ("internet", "webGUI Unraid publié via Nginx Proxy Manager : " + " ; ".join(webgui_doms)) if webgui_doms \
        else ("lan", "webGUI Unraid sur le LAN")
    uv = re.search(r'version="?([^"\s]+)', sysv.get("unraid", ""))
    os_kw = {"action_key": "nas:unraid-os", "rem": "unraid-os"}
    risks = []
    if webgui_doms:
        risks.append({"rid": "unraid-webgui-internet", "score": 72,
                      "title": "interface d'administration Unraid publiée sur Internet",
                      "detail": "webGUI Unraid (nginx :15000, accès root) publié via Nginx Proxy Manager : " + " ; ".join(webgui_doms),
                      "action_title": "Ne plus exposer le webGUI Unraid sur Internet",
                      "fix": "Unraid déconseille d'exposer son interface d'administration : supprimer le proxy host "
                             + ", ".join(d.split(" →")[0] for d in webgui_doms) + " dans Nginx Proxy Manager (ou, a minima, lui "
                             "associer une Access List limitée aux IP de confiance) et administrer le NAS via Tailscale "
                             "(http://100.69.109.39:15000), déjà en place. Seul le retrait du proxy host est détecté par le "
                             "dashboard : une Access List réduit le risque mais laissera ce constat affiché.", "commands": []})
    comps.append(_comp("nas:os", "Unraid OS", uv.group(1) if uv else None, "nas", "os", "/etc/unraid-version",
                       exposure=gui_expo[0], exposure_detail=gui_expo[1], risks=risks, **os_kw))
    kv = sysv.get("kernel", "")
    if kv:
        base = kv.split("-")[0]
        comps.append(_comp("nas:noyau", "Noyau Linux (Unraid)", base, "nas", "noyau", "uname -r", exposure="lan",
                           exposure_detail="pile réseau du NAS", eol=["linux", None, base], eol_patch=True, **os_kw))
    m = re.search(r"OpenSSH_([\w.]+)", sysv.get("openssh", ""))
    if m:
        a = listen.get("22", {}).get("addrs", set())
        det = "sshd sur " + ", ".join(sorted(a)) if a else "sshd"
        comps.append(_comp("nas:openssh", "OpenSSH", m.group(1), "nas", "service", "ssh -V", exposure="lan",
                           exposure_detail=det, **os_kw))
    m = re.search(r"Version\s+([\d.]+)", sysv.get("samba", ""))
    if m:
        comps.append(_comp("nas:samba", "Samba", m.group(1), "nas", "service", "smbd -V", exposure="lan",
                           exposure_detail="partages SMB (445) sur le LAN et Tailscale", eol=["samba", None, m.group(1)],
                           eol_patch=True, **os_kw))
    m = re.search(r"nginx/([\d.]+)", sysv.get("nginx", ""))
    if m:
        comps.append(_comp("nas:nginx", "nginx (webGUI Unraid)", m.group(1), "nas", "service", "nginx -v",
                           exposure=gui_expo[0], exposure_detail=gui_expo[1], eol=["nginx", None, m.group(1)], eol_patch=True, **os_kw))
    m = re.search(r"PHP ([\d.]+)", sysv.get("php", ""))
    if m:
        comps.append(_comp("nas:php", "PHP (webGUI Unraid)", m.group(1), "nas", "runtime", "php -v",
                           exposure=gui_expo[0], exposure_detail=gui_expo[1], eol=["php", None, m.group(1)], eol_patch=True, **os_kw))
    m = re.search(r"OpenSSL ([\d.]+)", sysv.get("openssl", ""))
    if m:
        comps.append(_comp("nas:openssl", "OpenSSL", m.group(1), "nas", "runtime", "openssl version",
                           exposure=gui_expo[0], exposure_detail="utilisé par nginx (webGUI) et sshd", eol=["openssl", None, m.group(1)],
                           eol_patch=True, **os_kw))
    try:
        dv = json.loads("".join(sec.get("dockerver", [])) or "{}")
        dver = (dv.get("Server") or {}).get("Version")
    except ValueError:
        dver = None
    if dver:
        comps.append(_comp("nas:docker", "Docker Engine", dver, "nas", "service", "docker version", exposure="local",
                           exposure_detail="démon local, surface d'attaque = images/conteneurs",
                           osv=[["Go", "github.com/docker/docker", dver]], eol=["docker-engine", None, dver], eol_patch=True, **os_kw))
    m = re.search(r"\sv?(\d+\.\d+\.\d+)", sysv.get("containerd", ""))
    if m:
        comps.append(_comp("nas:containerd", "containerd", m.group(1), "nas", "runtime", "containerd --version",
                           exposure="local", exposure_detail="runtime de conteneurs local",
                           osv=[["Go", "github.com/containerd/containerd/v2", m.group(1)]],
                           cri_disabled=_cri_disabled(sysv.get("containerd_cri")), **os_kw))
    m = re.search(r"runc version (\S+)", sysv.get("runc", ""))
    if m:
        comps.append(_comp("nas:runc", "runc", m.group(1), "nas", "runtime", "runc --version", exposure="local",
                           exposure_detail="runtime OCI local", osv=[["Go", "github.com/opencontainers/runc", m.group(1)]], **os_kw))
    tv = sysv.get("tailscale", "").strip()
    if re.match(r"^\d+\.\d+", tv):
        comps.append(_comp("nas:tailscale", "Tailscale (plugin)", tv, "nas", "service", "tailscale version", exposure="lan",
                           exposure_detail="nœud du tailnet", osv=[["Go", "tailscale.com", tv]],
                           action_key="nas:tailscale", rem="unraid-plugin"))
    # Conteneurs
    n_ct = 0
    projects = _parse_build(sec.get("build", []))
    for line in sec.get("inspect", []):
        p = line.split("\t")
        if len(p) < 7:
            continue
        try:
            name = json.loads(p[0]).lstrip("/")
            image = json.loads(p[1]) or ""
            labels = json.loads(p[2]) or {}
            env = dict(kv.split("=", 1) for kv in p[3].split(";") if "=" in kv)
            netmode = json.loads(p[4]) or ""
            ports = json.loads(p[5]) or {}
            status = json.loads(p[6]) or ""
        except ValueError:
            continue
        n_ct += 1
        running = status == "running"
        repo, tag = _image_repo(image)
        lab = labels.get("org.opencontainers.image.version", "")
        bv = re.search(r"version:-\s*v?([\w.\-]+)", labels.get("build_version", ""))
        wd = labels.get("com.docker.compose.project.working_dir")
        if wd and not _safe_wd(wd):
            wd = None   # label non conforme (fixable par l'image) : traité comme un conteneur hors compose
        svc = labels.get("com.docker.compose.service") or name
        custom = _is_custom(image)
        binds = [(b.get("HostIp") or "0.0.0.0", b.get("HostPort")) for v in ports.values() for b in (v or []) if b.get("HostPort")]
        if netmode == "host":
            expo, det = "lan", "réseau hôte (tous les ports du conteneur sur le LAN)"
        elif netmode == "br0":
            expo, det = "lan", "IP dédiée sur le LAN (br0)"
        else:
            expo, det = _expo_from_bindings(binds, npm, {NAS_IP}, running)
        key, prod, opts = None, None, {}
        for rx, k, nm, o in NAS_PRODUCTS:
            m = re.search(rx, repo)
            if m:
                key, prod, opts = k, nm, o
                if k is None:
                    key, prod = m.group(1), m.group(1).replace("-", " ").title()
                break
        if key == "npm" and running:
            expo, det = "internet", "reverse proxy public (ports 80/443 de l'hôte)"
        ver, src = None, "label OCI"
        if opts.get("db"):
            ver = (env.get(opts["db"]) or "").split("-")[0] or None
            src = f"variable {opts['db']}"
        elif opts.get("probe") and running:
            cport, path, field = opts["probe"]
            hp = _hostport(ports, cport)
            if hp:
                try:
                    j = _http(f"http://{NAS_IP}:{hp}{path}", timeout=5)
                    ver = _clean_label(j.get(field) if field else j) if (field and isinstance(j, dict)) or isinstance(j, str) else None
                    src = f"API http://{NAS_IP}:{hp}{path}"
                except Exception:
                    ver = None
        if not ver and key == "npm":
            ver, src = env.get("NPM_BUILD_VERSION"), "variable NPM_BUILD_VERSION"
        if not ver and not _bad_label(lab):
            ver, src = _clean_label(lab), "label org.opencontainers.image.version"
        if not ver and bv:
            ver, src = _clean_label(bv.group(1)), "label build_version"
        if not ver:
            src = "version non exposée par l'image"
        cyc_hint = None
        if opts.get("eol_slug") == "postgresql":
            cyc_hint = ver.split(".")[0] if ver else _cycle_hint(tag, r"(\d+)")
        elif opts.get("eol_slug") in ("redis", "valkey"):
            cyc_hint = ".".join(ver.split(".")[:2]) if ver else _cycle_hint(tag)
        elif opts.get("eol_slug") == "forgejo":
            cyc_hint = (ver.split(".")[0] + ".0") if ver else (_cycle_hint(tag, r"^(\d+)") + ".0" if _cycle_hint(tag, r"^(\d+)") else None)
        rem = "nas-custom" if custom else ("nas-compose" if wd else "unraid-template")
        pinned = bool(re.match(r"^\d+(\.\d+)?(-[a-z]+)?$|^pg\d+$", tag))
        # Montages en écriture (sauvegarde à froid avant une montée de branche) : hors fichiers système
        rw = [m.split(":", 1)[1] for m in (p[7].split("|") if len(p) > 7 else []) if ":" in m]
        rw = sorted({s for s in rw if _safe_wd(s) and not re.match(r"^/(etc|dev|proc|sys|tmp|run|var/run)(/|$)", s)})
        base = dict(container=name, image=image, exposure=expo, exposure_detail=det, workdir=wd, service=svc,
                    compose=bool(wd), custom=custom, tag=tag, pinned=pinned, running=running, state=status,
                    action_key=f"nas:ct:{name}", rem=rem, rw_mounts=rw)
        bi = _build_info(projects, wd, svc, name, image)
        if bi:
            base["build"] = bi
        cid = f"nas:ct:{name}"
        lan_binds = [(ip, hp) for ip, hp in binds if ip not in ("127.0.0.1", "::1")] if running else []
        risks = []
        if key == "ollama" and ver and lan_binds and src.startswith("API"):
            hp = lan_binds[0][1]
            risks.append({"rid": "ollama-api-sans-auth", "score": 75 if expo == "internet" else 50,
                          "title": "API Ollama sans authentification ouverte sur le " + ("Internet" if expo == "internet" else "LAN"),
                          "detail": f"http://{NAS_IP}:{hp}/api/* répond sans identifiant (publié sur {lan_binds[0][0]}:{hp}) : "
                                    "n'importe quel appareil du réseau peut lister, télécharger, supprimer des modèles et "
                                    "consommer le GPU",
                          "action_title": "Restreindre l'accès à l'API Ollama (sans authentification)",
                          "fix": "Ollama n'a pas d'authentification : dans le template Unraid, publier le port en "
                                 "127.0.0.1:11434 si seuls des conteneurs locaux l'utilisent, sinon le limiter aux clients "
                                 "légitimes (homelab 192.168.2.4, clawhost 192.168.2.5) par pare-feu, ou le placer derrière "
                                 "Nginx Proxy Manager avec une Access List. Ne jamais le publier sur Internet. Le dashboard ne "
                                 "détecte que la publication en 127.0.0.1 (ou le retrait du port) : un pare-feu ou une Access "
                                 "List laissera ce constat affiché.", "commands": []})
        if key == "ollama" and lan_binds and not src.startswith("API"):
            base["risk_unknown"] = "ollama-api-sans-auth"   # API muette : sonde ratée, pas une preuve de correction
        if key == "redis" and lan_binds:
            reply = ""
            try:
                with socket.create_connection((NAS_IP, int(lan_binds[0][1])), timeout=2) as sk:
                    sk.sendall(b"PING\r\n")   # commande en lecture seule
                    reply = sk.recv(64).decode(errors="ignore").strip()
            except (OSError, ValueError):
                pass
            if not reply or reply.startswith("-LOADING"):
                base["risk_unknown"] = "redis-lan-sans-mdp"     # pas de réponse exploitable (≠ -NOAUTH)
            if reply.startswith("+PONG"):
                ports_txt = ", ".join(sorted({hp for _, hp in lan_binds}))
                risks.append({"rid": "redis-lan-sans-mdp", "score": 56,
                              "title": f"Redis sans mot de passe publié sur le LAN (port {ports_txt})",
                              "detail": f"{name} : PING sur {NAS_IP}:{lan_binds[0][1]} répond +PONG sans authentification "
                                        "(lecture/écriture de toutes les données possibles depuis le LAN)",
                              "action_title": "Protéger les Redis publiés sans mot de passe",
                              "fix": "Retirer la publication du port (section ports: du compose) si seuls les conteneurs du "
                                     "projet utilisent Redis, sinon la limiter à 127.0.0.1 et ajouter requirepass "
                                     "(command: redis-server --requirepass …) en mettant à jour l'URL côté application.",
                              "commands": []})
        if key == "postgresql" and lan_binds:
            ports_txt = ", ".join(sorted({hp for _, hp in lan_binds}))
            risks.append({"rid": "postgres-lan", "score": 25,
                          "title": f"PostgreSQL publié sur le LAN (port {ports_txt})",
                          "detail": f"{name} : port {ports_txt} publié sur toutes les interfaces du NAS",
                          "action_title": "Ne plus publier les bases PostgreSQL sur le LAN",
                          "fix": "Si la base ne sert qu'aux conteneurs du projet, supprimer la publication du port dans le "
                                 "compose (le réseau Docker interne suffit) ou la limiter à 127.0.0.1:PORT:5432.",
                          "commands": []})
        primary = None
        if prod:
            osv = [["Go", opts["go"], ver]] if opts.get("go") and ver else []
            eol = [opts["eol_slug"], cyc_hint, ver] if opts.get("eol_slug") else None
            kind = "appli"
            if key in ("postgresql", "redis", "valkey"):
                kind = "service"
                base["merge_key"] = f"nas:{key}:{ver or tag}"
            primary = _comp(cid, prod, ver, "nas", kind, src, osv=osv, eol=eol, eol_patch=True,
                            gh=opts.get("gh"), gh_pkgs=opts.get("gh_pkgs"), product=key, risks=risks, **base)
            comps.append(primary)
        elif custom:
            primary = _comp(cid, f"Image maison {repo.split('/')[-1]}", None, "nas", "appli", "image construite localement",
                            product="custom", **base)
            comps.append(primary)
        else:
            primary = _comp(cid, repo.split("/")[-1], ver, "nas", "appli", src, product=repo, **base)
            comps.append(primary)
        # Runtimes embarqués (Node, Python) : pour une image maison, c'est l'élément à faire évoluer
        if not opts.get("db"):
            for envk, rname, slug in (("NODE_VERSION", "Node.js", "nodejs"), ("PYTHON_VERSION", "Python", "python")):
                rv = norm_ver(env.get(envk, ""))
                if not rv:
                    continue
                cyc = rv.split(".")[0] if slug == "nodejs" else ".".join(rv.split(".")[:2])
                rk = dict(base)
                if custom:
                    rk["merge_key"] = f"nas:custom:{slug}:{cyc}"
                comps.append(_comp(f"{cid}:{slug}", f"{rname} ({name})", rv, "nas", "runtime", f"variable {envk}",
                                   eol=[slug, cyc, rv], eol_patch=True, runtime_of=cid, **rk))
    if not n_ct:
        _src(sources, "inventaire:nas-conteneurs", False, 0, "aucun conteneur listé (service Docker arrêté ?)")
    _src(sources, "inventaire:nas", True, len(comps))
    _mem["npm"] = npm or _mem.get("npm") or []
    return (comps, sec.get("clawinv", []) + ["@@npm"] + [f"{e['domain']}|{e['backend']}|{e['port']}" for e in npm],
            bool(sec.get("clawinv")))


def _inv_claw(sources, clawinv):
    comps = []
    npm = []
    inv_lines, seen_npm = [], False
    for line in clawinv:
        if line == "@@npm":
            seen_npm = True
            continue
        if seen_npm:
            p = line.split("|")
            if len(p) >= 3:
                npm.append({"domain": p[0], "backend": p[1], "port": p[2]})
        else:
            inv_lines.append(line)
    npm = npm or _npm_entries()
    probes = {str(p["port"]): p["name"] for p in HOSTS["clawhost"].get("probes", [])}
    errs = []
    # OpenSSH (bannière)
    try:
        with socket.create_connection((CLAW_IP, HOSTS["clawhost"]["ssh"]["port"]), timeout=4) as s:
            banner = s.recv(200).decode(errors="ignore").strip()
    except OSError as e:
        banner = ""
        errs.append(f"bannière SSH : {e}")
    m = re.match(r"SSH-2\.0-OpenSSH_([\w.]+)\s+Ubuntu-(\S+)", banner)
    if m:
        dv = f"1:{m.group(1)}-{m.group(2)}"
        comps.append(_comp("clawhost:openssh", "OpenSSH (Ubuntu)", dv, "clawhost", "paquet-os",
                           f"bannière SSH :{HOSTS['clawhost']['ssh']['port']} ({banner})", exposure="lan",
                           exposure_detail=f"sshd sur le port {HOSTS['clawhost']['ssh']['port']} (LAN)",
                           osv=[["Ubuntu:24.04:LTS", "openssh", dv]], action_key="clawhost:apt", rem="claw-apt"))
    comps.append(_comp("clawhost:os", "Ubuntu", "24.04", "clawhost", "os", "configuration (pas d'accès SSH)", exposure="lan",
                       exposure_detail="hôte du LAN (192.168.2.5)", eol=["ubuntu", "24.04", None], action_key="clawhost:apt", rem="claw-apt"))
    # OpenClaw (build de l'interface du gateway)
    try:
        html = _http_text(f"http://{CLAW_IP}:18789/", timeout=5, limit=200_000)
        bid = re.search(r'data-openclaw-control-ui-build-id="([^"]+)"', html)
        term = 'data-openclaw-terminal-enabled="true"' in html
        ver = re.match(r"(\d+\.\d+\.\d+(?:-\d+)?)", bid.group(1)).group(1) if bid else None
    except Exception as e:  # noqa
        ver, term = None, False
        errs.append(f"OpenClaw : {e}")
    doms = _npm_lookup(npm, CLAW_IPS, 18789)
    det = "gateway :18789 joignable depuis tout le LAN" + (" (terminal web activé)" if term else "")
    risks = []
    if term and ver:
        risks.append({"rid": "openclaw-terminal-lan", "score": 28,
                      "title": "interface OpenClaw avec terminal web joignable depuis le LAN",
                      "detail": f"http://{CLAW_IP}:18789/ répond sur le LAN avec data-openclaw-terminal-enabled=\"true\"",
                      "action_title": "Restreindre le gateway OpenClaw (terminal web activé)",
                      "fix": "Vérifier que le gateway exige un jeton fort ; s'il n'est utilisé que localement ou via Tailscale, "
                             "le lier à 127.0.0.1/l'IP Tailscale ou filtrer le port 18789 avec ufw (le dashboard ne verra la correction "
                             "que si le homelab 192.168.2.4 est lui aussi filtré) ; "
                             "désactiver le terminal web s'il n'est pas utilisé.", "commands": []})
    comps.append(_comp("clawhost:openclaw", "OpenClaw", ver, "clawhost", "appli", "attribut data-openclaw-control-ui-build-id",
                       exposure="internet" if doms else "lan", exposure_detail=(", ".join(doms) + " ; " if doms else "") + det,
                       osv=[["npm", "openclaw", ver]] if ver else [], gh="openclaw/openclaw", gh_pkgs=["openclaw"], risks=risks,
                       action_key="clawhost:openclaw", rem="claw-openclaw"))
    # Conteneurs (inventaire de la sauvegarde nocturne sur le NAS)
    seen_ports = set()
    for line in inv_lines:
        p = line.split("\t")
        if len(p) < 3 or not p[2].startswith("Up"):
            continue
        name, image = p[0].strip(), p[1].strip()
        repo, tag = _image_repo(image)
        expo, det = "inconnue", "ports non visibles sans accès SSH"
        for port, pname in probes.items():
            toks = re.findall(r"[a-z0-9]+", pname.lower())
            if toks and all(t in name.lower() for t in toks):
                doms = _npm_lookup(npm, CLAW_IPS, port)
                seen_ports.add(port)
                bk = sorted({e["backend"] for e in npm if e["backend"] in CLAW_IPS and str(e["port"]) == port})
                expo, det = (("internet", ", ".join(doms) + f" → :{port} (backend {', '.join(bk)})")
                             if doms else ("lan", f"port {port} sur le LAN"))
        if re.search(r"(^|/)postgres$", repo):
            cyc = _cycle_hint(tag, r"(\d+)")
            comps.append(_comp(f"clawhost:ct:{name}", "PostgreSQL", None, "clawhost", "service", f"tag d'image ({image})",
                               container=name, image=image, exposure="local" if expo == "inconnue" else expo,
                               exposure_detail="base interne de Netscan" if expo == "inconnue" else det,
                               eol=["postgresql", cyc, None], action_key=f"clawhost:ct:{name}", rem="claw-ct", tag=tag))
        else:
            comps.append(_comp(f"clawhost:ct:{name}", f"Image maison {name}" if _is_custom(image) else repo, None, "clawhost",
                               "appli", "inventaire de sauvegarde (version non exposée)", container=name, image=image,
                               exposure=expo, exposure_detail=det, action_key=f"clawhost:ct:{name}", rem="claw-ct", tag=tag))
    # Services publiés sur Internet sans conteneur identifié (ex. FitCoach)
    for e in npm:
        if e["backend"] in CLAW_IPS and str(e["port"]) not in seen_ports and str(e["port"]) != "18789":
            port = str(e["port"])
            seen_ports.add(port)
            doms = _npm_lookup(npm, CLAW_IPS, port)
            comps.append(_comp(f"clawhost:svc:{port}", probes.get(port, f"Service :{port}"), None, "clawhost", "appli",
                               "sonde réseau (version non exposée)", exposure="internet",
                               exposure_detail=", ".join(doms) + f" → :{port} (backend {e['backend']})",
                               action_key=f"clawhost:svc:{port}", rem="claw-svc"))
    _src(sources, "inventaire:clawhost", not errs or len(comps) > 2, len(comps), "; ".join(errs) or None)
    return comps


def _carry_risks(comps, prev_list):
    """Sonde ratée (pas de réponse, ≠ réponse négative) : le risque observé à la collecte précédente est reconduit
    une seule fois, pour qu'un raté ponctuel ne fasse ni disparaître l'action ni relancer l'analyse."""
    old = {c["id"]: c for c in prev_list}
    for c in comps or []:
        rid = c.pop("risk_unknown", None)
        o = old.get(c["id"])
        if rid and o and not any(r["rid"] == rid for r in c.get("risks") or []):
            c["risks"] = (c.get("risks") or []) + [dict(r, carried=True) for r in o.get("risks") or []
                                                   if r["rid"] == rid and not r.get("carried")]


def collect_inventory(sources=None):
    """Inventaire des composants versionnés des 3 machines (dégradation propre : un hôte injoignable garde son
    inventaire précédent)."""
    sources = sources if sources is not None else {}
    prev = {}
    for c in (_mem.get("inv") or []):
        prev.setdefault(c["host"], []).append(c)
    inv = []
    try:   # NAS en premier : ses entrées Nginx Proxy Manager servent aussi à l'exposition des conteneurs du homelab
        n, clawinv, claw_ok = _inv_nas(sources)
    except Exception as e:  # noqa
        n, clawinv, claw_ok = None, [], False
        _src(sources, "inventaire:nas", False, 0, f"{type(e).__name__}: {e}")
    _carry_risks(n, prev.get("nas", []))
    if n is not None and "inventaire:nas-conteneurs" in sources:   # Docker arrêté : conteneurs de la collecte précédente
        ids = {c["id"] for c in n}
        n += [dict(c, stale=True) for c in prev.get("nas", [])
              if c["id"] not in ids and (c["id"].startswith("nas:ct:") or c["id"] == "nas:docker")]
    try:
        h = _inv_homelab(sources)
    except Exception as e:  # noqa
        h = None
        _src(sources, "inventaire:homelab", False, 0, f"{type(e).__name__}: {e}")
    if h is not None and "inventaire:homelab-conteneurs" in sources:
        h += [dict(c, stale=True) for c in prev.get("homelab", []) if c["id"].startswith("homelab:ct:")]
    inv += h if h is not None else [dict(c, stale=True) for c in prev.get("homelab", [])]
    inv += n if n is not None else [dict(c, stale=True) for c in prev.get("nas", [])]
    sources.pop("inventaire:clawhost-conteneurs", None)
    try:
        cl = _inv_claw(sources, clawinv)
        # Sonde en échec : garder la dernière version connue (OpenSSH, OpenClaw)
        old = {c["id"]: c for c in prev.get("clawhost", [])}
        ids = {c["id"] for c in cl}
        for i, c in enumerate(cl):
            o = old.get(c["id"])
            if o and c.get("version") in (None, "inconnue") and o.get("version") not in (None, "inconnue"):
                # version conservée pour le suivi des CVE ; un risque de configuration n'est reconduit qu'une fois
                # (ex. gateway OpenClaw qui ne répond plus au LAN après filtrage : retiré au 2e échec consécutif)
                cl[i] = dict(o, stale=True, risks=[] if o.get("stale") else o.get("risks") or [])   # retiré au 2e échec
        cl += [dict(o, stale=True) for i, o in old.items() if i == "clawhost:openssh" and i not in ids]
        if not claw_ok:   # liste des conteneurs absente (NAS injoignable, sauvegarde nocturne en cours ou manquante)
            _src(sources, "inventaire:clawhost-conteneurs", False, 0, "liste des conteneurs absente de la dernière sauvegarde")
            cl += [dict(o, stale=True) for i, o in old.items() if i.startswith("clawhost:ct:") and i not in ids]
        inv += cl
    except Exception as e:  # noqa
        _src(sources, "inventaire:clawhost", False, 0, f"{type(e).__name__}: {e}")
        inv += [dict(c, stale=True) for c in prev.get("clawhost", [])]
    return inv


def _signature(inv):
    return sorted(f"{c['id']}={c.get('version')}|{c.get('exposure')}" + ("|cri-off" if c.get("cri_disabled") else "")
                  + "".join("|" + r["rid"] for r in sorted(c.get("risks") or [], key=lambda r: r["rid"]))
                  + (f"|{c.get('installed')}|{int(bool(c.get('reboot_required')))}" if c.get("rem") == "kernel-homelab" else "")
                  # Dockerfile ou tag modifié (sed appliqué, pas encore reconstruit) : les commandes proposées changent
                  + ("|" + ",".join(b["ref"] or "?" for b in (c.get("build") or {}).get("bases") or []) + "|"
                     + str((c.get("build") or {}).get("image")) if c.get("build") else "")
                  for c in inv)


# --- Sources d'analyse ------------------------------------------------------------------
_KERNEL_PREFIX = re.compile(r"^\s*In the Linux kernel, the following vulnerability has been resolved:\s*", re.I)


def _clean_md(t):
    """Texte brut à partir d'un extrait Markdown (titres, gras, code, liens)."""
    t = re.sub(r"(?m)^\s*#+\s*(Summary|Résumé|Description|Details|Impact)?\s*$", " ", t or "")
    t = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", t)
    t = re.sub(r"\*\*|`|^\s*[#>]+\s*", "", t, flags=re.M)
    t = re.sub(r"\s+", " ", t).strip()
    return re.sub(r"^#*\s*(Summary|Description|Résumé|Details|Overview)\s*:?\s+", "", t, flags=re.I)


def _compact(rec, ecos):
    """Réduit un enregistrement OSV aux champs utiles (cache disque léger)."""
    al = list(dict.fromkeys((rec.get("aliases") or []) + (rec.get("upstream") or [])))
    aff = []
    lka = None
    for a in rec.get("affected") or []:
        pk = a.get("package") or {}
        e = pk.get("ecosystem", "")
        if e not in ecos:
            continue
        rngs = []
        for r in a.get("ranges") or []:
            if r.get("type") in ("ECOSYSTEM", "SEMVER"):
                rngs.append([[k, v] for ev in r.get("events", []) for k, v in ev.items()])
        es = a.get("ecosystem_specific") or {}
        ds = a.get("database_specific") or {}
        lka = lka or ds.get("last_known_affected_version_range")
        vers = a.get("versions") or []
        aff.append({"e": e, "n": pk.get("name"), "r": rngs, "u": es.get("urgency") or ds.get("urgency"),
                    "v": vers if (e not in ("Debian:13",) and not e.startswith("Ubuntu") and len(vers) < 400) else []})
    sev = [[s.get("type"), s.get("score")] for s in rec.get("severity") or []]
    for a in rec.get("affected") or []:
        for s in a.get("severity") or []:
            sev.append([s.get("type"), s.get("score")])
    refs = []
    for r in rec.get("references") or []:
        if r.get("type") in ("ADVISORY", "FIX", "WEB", "REPORT") and r.get("url") and len(refs) < 3:
            refs.append(r["url"])
    raw = rec.get("details") or ""
    summ = (rec.get("summary") or "").strip()
    m = _KERNEL_PREFIX.match(raw)
    if m:   # CVE noyau : le titre est le premier paragraphe après la formule d'usage
        raw = raw[m.end():]
        summ = summ or re.split(r"\n|\s{2,}", raw.strip(), 1)[0].strip()
    det = _clean_md(raw)
    return {"id": rec["id"], "cv": COMPACT_VER, "al": al, "s": _clean_md(summ)[:200], "d": det[:420],
            "p": (rec.get("published") or "")[:10], "sv": sev, "ds": (rec.get("database_specific") or {}).get("severity"),
            "lka": lka, "aff": aff, "refs": refs}


def _osv_query(keys, deadline, errors):
    """querybatch (≤ 1000 requêtes/appel, pagination par requête) -> {(eco, pkg, ver): [ids]}.
    Les résultats sont mis en cache : en cas d'échec, le dernier résultat connu est réutilisé."""
    res = {k: [] for k in keys}
    done = set()
    pending = [(k, None) for k in keys]
    pages = 0
    while pending and time.time() < deadline and pages < 30:
        chunk, pending = pending[:1000], pending[1000:]
        qs = []
        for (e, n, v), tok in chunk:
            q = {"package": {"ecosystem": e, "name": n}, "version": v}
            if tok:
                q["page_token"] = tok
            qs.append(q)
        try:
            d = _http("https://api.osv.dev/v1/querybatch", {"queries": qs}, timeout=HTTP_TIMEOUT * 2)
        except Exception as e:  # noqa
            errors.append(f"querybatch : {e}")
            break
        pages += 1
        for (k, _), r in zip(chunk, d.get("results") or []):
            res[k] += [x["id"] for x in r.get("vulns") or []]
            if r.get("next_page_token"):
                pending.append((k, r["next_page_token"]))
            else:
                done.add(k)
    stale = unk = 0
    for k in keys:
        ck = "osvq:" + "|".join(k)
        if k in done:
            HTTP_CACHE.put(ck, res[k])
        else:
            old, _ = HTTP_CACHE.get(ck, DAY)
            if old is not None:
                res[k] = old
                stale += 1
            else:
                unk += 1
    if stale:
        errors.append(f"{stale} requête(s) servie(s) depuis le cache")
    if unk:
        errors.append(f"{unk} version(s) non vérifiée(s) (OSV injoignable, pas de cache)")
    return res, unk


OSV_DEBIAN_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip"


def _osv_bulk_debian(todo, ecos, out, errors):
    """Export OSV complet de Debian (~80 Mo, 2-3 s) : bien plus rapide que des milliers de GET /v1/vulns/{id}
    (l'API limite le débit à ~5 req/s par client). Le fichier est supprimé après extraction."""
    import zipfile
    path = os.path.join(DATA_DIR, "osv-debian.zip.tmp")
    got = set()
    try:
        req = urllib.request.Request(OSV_DEBIAN_ZIP, headers={"User-Agent": "infradash"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r, open(path, "wb") as f:
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                f.write(b)
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            for i in todo:
                if f"{i}.json" in names:
                    rec = _compact(json.loads(z.read(f"{i}.json")), ecos)
                    OSV_CACHE.put(i, rec)
                    out[i] = rec
                    got.add(i)
    except Exception as e:  # noqa
        errors.append(f"export OSV Debian : {e}")
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return got


def _osv_details(ids, ecos, deadline, errors):
    out, todo = {}, []
    for i in ids:
        rec, fresh = OSV_CACHE.get(i, OSV_TTL)
        if rec is not None:
            out[i] = rec
        if not fresh or (rec or {}).get("cv") != COMPACT_VER:
            todo.append(i)
    deb = [i for i in todo if i.startswith(("DEBIAN-", "DSA-", "DLA-", "DTSA-"))]
    bulk = 0
    if len(deb) > 60:
        got = _osv_bulk_debian(deb, ecos, out, errors)
        bulk = len(got)
        todo = [i for i in todo if i not in got]

    def fetch(i):
        if time.time() > deadline:
            return i, None, "délai dépassé"
        try:
            return i, _compact(_http(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(i)}"), ecos), None
        except Exception as e:  # noqa
            return i, None, str(e)
    fails = 0
    if todo:
        with ThreadPoolExecutor(max_workers=8) as ex:
            for i, rec, err in ex.map(fetch, todo):
                if rec:
                    OSV_CACHE.put(i, rec)
                    out[i] = rec
                else:
                    fails += 1
    if fails:
        errors.append(f"{fails} détail(s) OSV non récupéré(s) (cache utilisé si présent)")
    return out, len(todo) - fails + bulk


class _GH:
    """Client GitHub non authentifié (60 req/h) : cache 24 h, arrêt propre sur quota épuisé."""

    def __init__(self):
        self.blocked = None
        self.calls = 0
        self.errors = []

    def get(self, url, ttl=DAY, paginate=0):
        cached, fresh = HTTP_CACHE.get("gh:" + url, ttl)
        if fresh:
            return cached
        if self.blocked:
            return cached
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if GH_TOKEN:
            h["Authorization"] = f"Bearer {GH_TOKEN}"
        items, nxt, n = [], url, 0
        try:
            while nxt and n <= paginate:
                body, hdr = _http(nxt, headers=h, raw=True)
                self.calls += 1
                n += 1
                d = json.loads(body)
                if isinstance(d, list):
                    items += d
                else:
                    items = d
                    break
                m = re.search(r'<([^>]+)>;\s*rel="next"', hdr.get("Link") or "")
                nxt = m.group(1) if m else None
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                reset = e.headers.get("X-RateLimit-Reset")
                when = datetime.fromtimestamp(int(reset)).strftime("%H:%M") if reset and reset.isdigit() else "?"
                self.blocked = f"quota GitHub atteint (réinitialisation à {when})"
                self.errors.append(self.blocked)
            elif e.code == 404:
                HTTP_CACHE.put("gh:" + url, [])
                return []
            else:
                self.errors.append(f"{url.split('github.com')[-1]} : HTTP {e.code}")
            return cached
        except Exception as e:  # noqa
            self.errors.append(f"{url.split('github.com')[-1]} : {e}")
            return cached
        HTTP_CACHE.put("gh:" + url, items)
        return items


def _gh_compact_adv(a):
    v = [{"pkg": (x.get("package") or {}).get("name"), "eco": (x.get("package") or {}).get("ecosystem"),
          "range": x.get("vulnerable_version_range"), "patched": x.get("patched_versions") or x.get("first_patched_version")}
         for x in a.get("vulnerabilities") or []]
    cv = (a.get("cvss_severities") or {}).get("cvss_v3") or a.get("cvss") or {}
    cv4 = (a.get("cvss_severities") or {}).get("cvss_v4") or {}
    return {"ghsa": a.get("ghsa_id"), "cve": a.get("cve_id"), "summary": _clean_md(a.get("summary") or ""), "severity": a.get("severity"),
            "vector": cv.get("vector_string") or cv4.get("vector_string"), "score": cv.get("score") or cv4.get("score"),
            "published": (a.get("published_at") or "")[:10], "url": a.get("html_url"), "vulns": v,
            "desc": _clean_md(a.get("description") or "")[:300]}


def _gh_repo_advisories(gh, repo):
    """Advisories publiées du dépôt ; pagination limitée (les plus récentes d'abord)."""
    url = f"https://api.github.com/repos/{repo}/security-advisories?per_page=100&state=published"
    raw = gh.get(url, paginate=2 if repo.startswith("openclaw/") else 0)
    if raw is None:
        return None
    if raw and isinstance(raw[0], dict) and "ghsa_id" in raw[0]:
        raw = [_gh_compact_adv(a) for a in raw]
        HTTP_CACHE.put("gh:" + url, raw)
    return raw


def _gh_affects(gh, eco, pkg, version):
    url = (f"https://api.github.com/advisories?ecosystem={eco}&affects={urllib.parse.quote(pkg + '@' + version, safe='')}"
           f"&per_page=100")
    raw = gh.get(url)
    if raw is None:
        return None
    if raw and isinstance(raw[0], dict) and "ghsa_id" in raw[0]:
        raw = [_gh_compact_adv(a) for a in raw]
        HTTP_CACHE.put("gh:" + url, raw)
    return raw


def _gh_latest(gh, repo):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    d = gh.get(url)
    if isinstance(d, dict) and d.get("tag_name"):
        d = {"tag": d["tag_name"], "published": (d.get("published_at") or "")[:10]}
        HTTP_CACHE.put("gh:" + url, d)
    return d if isinstance(d, dict) and d.get("tag") else None


def _eol_data(slug, errors):
    url = f"https://endoflife.date/api/{slug}.json"
    cached, fresh = HTTP_CACHE.get("eol:" + slug, DAY)
    if fresh:
        return cached
    try:
        d = _http(url)
        d = [{k: c.get(k) for k in ("cycle", "eol", "latest", "lts", "support", "releaseDate")} for c in d]
        HTTP_CACHE.put("eol:" + slug, d)
        return d
    except Exception as e:  # noqa
        errors.append(f"{slug} : {e}")
        return cached


_MANIFESTS = ("application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,"
              "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json")


def _reg_image(ref, errors):
    """Image publiée sous ce tag (linux/amd64) : date de construction, variables *_VERSION et label de version, lues
    dans sa configuration via l'API du registre (accès anonyme). Seul le nom de l'image est envoyé.
    Quota : Docker Hub compte chaque GET de manifeste comme un pull (quota anonyme partagé par l'IP publique, donc
    aussi par les vrais docker pull du NAS). Un HEAD (non décompté) donne l'empreinte du tag ; le contenu n'est relu
    que si l'éditeur a publié une nouvelle image. Après un 429, le registre est laissé tranquille 1 h."""
    key = "reg:" + ref
    cached, fresh = HTTP_CACHE.get(key, 6 * 3600)
    if fresh:
        return cached
    repo, tag = _image_repo(ref)
    p = repo.split("/")
    if len(p) > 1 and ("." in p[0] or ":" in p[0] or p[0] == "localhost"):
        reg, name = p[0], "/".join(p[1:])
    else:
        reg, name = "registry-1.docker.io", repo if "/" in repo else "library/" + repo
    reg = {"docker.io": "registry-1.docker.io", "lscr.io": "ghcr.io"}.get(reg, reg)
    if HTTP_CACHE.get("regwait:" + reg, 3600)[1]:
        return cached
    tok = []

    def call(path, accept, method="GET"):
        for _ in range(2):
            h = {"Accept": accept, "User-Agent": "infradash"}
            if tok:
                h["Authorization"] = "Bearer " + tok[0]
            req = urllib.request.Request(f"https://{reg}/v2/{name}/{path}", headers=h, method=method)
            try:
                with urllib.request.urlopen(req, timeout=8) as r:
                    return r.headers if method == "HEAD" else json.loads(r.read(4_000_000))
            except urllib.error.HTTPError as e:   # 401 : jeton anonyme selon le défi WWW-Authenticate du registre
                if e.code == 429:
                    HTTP_CACHE.put("regwait:" + reg, 1)
                ch = e.headers.get("WWW-Authenticate") or ""
                kv = dict(re.findall(r'(\w+)="([^"]*)"', ch))
                if e.code != 401 or tok or not ch.lower().startswith("bearer") or not kv.get("realm", "").startswith("https://"):
                    raise
                q = urllib.parse.urlencode({k: v for k, v in kv.items() if k in ("service", "scope")})
                j = _http(kv["realm"] + ("?" + q if q else ""), timeout=8)
                tok.append(j.get("token") or j.get("access_token") or "")
        raise RuntimeError("authentification refusée")

    try:
        dig = call(f"manifests/{tag}", _MANIFESTS, "HEAD").get("Docker-Content-Digest")
        known = HTTP_CACHE.get("regd:" + dig, 30 * DAY)[0] if dig else None
        if known:   # même image qu'au dernier contrôle : aucun GET de manifeste
            HTTP_CACHE.put(key, known)
            HTTP_CACHE.put("regd:" + dig, known)
            return known
        m = call(f"manifests/{dig or tag}", _MANIFESTS)
        if "manifests" in m:
            d = next((x for x in m["manifests"] if (x.get("platform") or {}).get("os") == "linux"
                      and (x.get("platform") or {}).get("architecture") == "amd64"), None)
            if not d:
                raise RuntimeError("pas de variante linux/amd64")
            m = call(f"manifests/{d['digest']}", d.get("mediaType") or _MANIFESTS)
        cfg = call(f"blobs/{m['config']['digest']}", "application/json")
        c = cfg.get("config") or {}
        env = dict(x.split("=", 1) for x in c.get("Env") or [] if "=" in x and x.split("=", 1)[0].endswith("_VERSION"))
        out = {"created": (cfg.get("created") or "")[:10], "env": env,
               "version": (c.get("Labels") or {}).get("org.opencontainers.image.version")}
        HTTP_CACHE.put(key, out)
        if dig:
            HTTP_CACHE.put("regd:" + dig, out)
        return out
    except Exception as e:  # noqa
        errors.append(f"{ref} : {e}")
        return cached


def _remote_version(info, slug):
    """Version d'un produit ou d'un runtime dans une image publiée (None si l'image ne l'indique pas)."""
    if not info:
        return None
    k = {"nodejs": "NODE_VERSION", "python": "PYTHON_VERSION", "postgresql": "PG_VERSION", "redis": "REDIS_VERSION"}.get(slug)
    v = (info.get("env") or {}).get(k) if k else (None if _bad_label(info.get("version")) else info.get("version"))
    return norm_ver(_clean_label(v.split("-")[0])) if v else None


def _kev(errors):
    cached, fresh = HTTP_CACHE.get("kev", DAY)
    if fresh:
        return cached
    try:
        d = _http("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=HTTP_TIMEOUT)
        kev = {v["cveID"]: [v.get("dateAdded"), v.get("dueDate"), v.get("knownRansomwareCampaignUse"), v.get("vulnerabilityName")]
               for v in d.get("vulnerabilities") or []}
        HTTP_CACHE.put("kev", kev)
        return kev
    except Exception as e:  # noqa
        errors.append(str(e))
        return cached


def _epss(cves, deadline, errors):
    out, todo = {}, []
    for c in cves:
        v, fresh = HTTP_CACHE.get("epss:" + c, DAY)
        if v is not None:
            out[c] = v
        if not fresh:
            todo.append(c)
    batches = [todo[i:i + 100] for i in range(0, len(todo), 100)]

    def fetch(b):
        if time.time() > deadline:
            return b, None, "délai dépassé"
        try:
            return b, _http("https://api.first.org/data/v1/epss?cve=" + ",".join(b)), None
        except Exception as e:  # noqa
            return b, None, str(e)
    fails = 0
    with ThreadPoolExecutor(max_workers=4) as ex:
        for b, d, err in ex.map(fetch, batches):
            if d is None:
                fails += 1
                continue
            got = {x["cve"]: [float(x.get("epss") or 0), float(x.get("percentile") or 0)] for x in d.get("data") or []}
            for c in b:
                v = got.get(c, [0.0, 0.0])
                HTTP_CACHE.put("epss:" + c, v)
                out[c] = v
    if fails:
        errors.append(f"{fails} lot(s) EPSS en échec")
    return out


# --- Évaluation -----------------------------------------------------------------------------
def _range_affects(evs, ver, cmp):
    """Évalue une plage OSV (événements triés) pour une version."""
    def key(ev):
        return ev[1]
    evs = sorted(evs, key=cmp_to_key(lambda a, b: cmp(key(a), key(b)) if key(a) != "0" and key(b) != "0"
                                      else (-1 if key(a) == "0" and key(b) != "0" else (1 if key(b) == "0" and key(a) != "0" else 0))))
    aff = False
    for k, v in evs:
        if k == "introduced" and (v == "0" or cmp(ver, v) >= 0):
            aff = True
        elif k == "fixed" and v != "0" and cmp(ver, v) >= 0:
            aff = False
        elif k == "last_affected" and cmp(ver, v) > 0:
            aff = False
    return aff


def _best_cvss(sv, ds=None, label=None):
    """(score, vecteur, approx) à partir des sévérités OSV ; libellé textuel en dernier recours."""
    best = (None, None, False)
    order = {"CVSS_V3": 0, "CVSS_V4": 1, "CVSS_V2": 2}
    for t, s in sorted(sv or [], key=lambda x: order.get(x[0], 9)):
        if t in order and s:
            sc, _, approx = cvss.base_score(s)
            if sc is not None:
                return sc, s, approx
    lbl = ds or label
    if lbl:
        return cvss.score_from_label(lbl), None, True
    return best


def _cve_of(ids):
    for i in ids:
        if i.startswith("CVE-"):
            return i
    return None


def _first_sentence(t, n=120):
    t = (t or "").strip()
    m = re.match(r"(.{20,%d}?[.!?])(\s|$)" % n, t)
    s = m.group(1) if m else t[:n]
    return s + ("…" if not m and len(t) > n else "")


def _finding_base(comp, fid, aliases, title, summary, refs, source, published):
    return {"id": fid, "aliases": aliases[:6], "title": title, "summary": summary, "component_id": comp["id"],
            "component": comp["name"], "version": comp.get("version"), "host": comp["host"],
            "container": comp.get("container"), "exposure": comp["exposure"], "exposure_detail": comp["exposure_detail"],
            "refs": refs[:3], "source": source, "published": published}


def _score(f, mult_override=None):
    base = f.get("cvss")
    if base is None:
        base = 5.0
    mult = EXPO_MULT.get(f["exposure"], 0.6) if mult_override is None else mult_override
    av = f.get("av")
    if av in ("L", "P"):
        mult = min(mult, EXPO_MULT["local"])
    elif av == "A":
        mult = min(mult, EXPO_MULT["lan"])
    s = base * 10 * mult
    if f.get("kev"):
        s += 25
    if f.get("epss"):
        s += 20 * f["epss"] + (5 if (f.get("epss_pct") or 0) >= 0.95 else 0)
    if f.get("cap") is not None:
        s = min(s, f["cap"])
    return int(round(max(0, min(100, s))))


def _prio(s):
    if s >= 80:
        return "critique"
    if s >= 55:
        return "haute"
    if s >= 30:
        return "moyenne"
    return "basse"


# --- Remédiation ----------------------------------------------------------------------------
def _tagc(cycle):
    """'15.0' -> '15' (tag d'image d'une branche)."""
    return re.sub(r"\.0$", "", cycle) if cycle else cycle


def _ssh_prefix(host):
    return {"nas": "ssh root@192.168.2.3", "clawhost": "ssh -p 2211 openclaw@192.168.2.5"}.get(host)


def _ct_commands(c):
    wd, svc = c.get("workdir"), c.get("service") or c.get("container")
    if (wd and not _safe_wd(wd)) or not svc or not _SAFE_SVC.match(svc):
        return []   # labels non conformes (fixables par l'image) : aucune commande root générée
    if c.get("product") == "immich" and wd:
        # Immich : tous les services du projet se mettent à jour ensemble (procédure officielle)
        return [f"cd {wd} && docker compose pull && docker compose up -d"]
    if c["host"] == "homelab":
        return [f"cd {wd or '/opt/homelab'} && sudo docker compose pull {svc} && sudo docker compose up -d {svc}"]
    if c.get("rem") == "nas-custom" and wd:
        return [f"cd {wd} && docker compose build --pull {svc} && docker compose up -d {svc}"]
    if wd:
        return [f"cd {wd} && docker compose pull {svc} && docker compose up -d {svc}"]
    return []


RUNTIME_IMAGES = {"nodejs": "node", "python": "python"}   # image officielle qui fournit le runtime
TAG_BUMP_OK = {"forgejo", "redis", "valkey"}   # changement de branche par simple tag (migration au démarrage)
BACKUP_DIR = "/mnt/user/backups"


def _tag_split(tag):
    m = re.match(r"^(v?)(\d+(?:\.\d+)*)(.*)$", tag or "")
    return (m.group(1), m.group(2), m.group(3)) if m else None


def _bump_ref(ref, ver, branch):
    """node:20-alpine3.19 -> node:24-alpine (changement de branche) ; python:3.11.15-slim -> python:3.11.18-slim."""
    repo, tag = _image_repo(ref)   # un digest épinglé (@sha256:…) est retiré
    t = _tag_split(tag)
    if not t:
        return None
    suf = t[2]
    if branch:   # variantes propres à l'ancienne branche
        suf = re.sub(r"^-alpine\d+(\.\d+)*", "-alpine", suf)
        suf = re.sub(r"^-(bullseye|buster)", "-bookworm", suf)
    return f"{repo}:{t[0]}{ver}{suf}"


def _ere(s):
    """Échappement pour une expression sed -E (délimiteur #)."""
    return re.sub(r"([.^$*+?()\[\]{}|\\#])", r"\\\1", s)


def _sed_bases(edits):
    """Expressions sed remplaçant des images de base : ligne FROM, ou ARG global qui la fixe."""
    out = []
    for b, new in edits:
        old = _ere(b["ref"])
        if b["arg"]:
            out.append(f"s#^ARG {b['arg']}={old}$#ARG {b['arg']}={new}#" if b["simple"] else
                       f"s#^([[:space:]]*ARG[[:space:]]+{b['arg']}=\"?){old}#\\1{new}#I")
        elif b["simple"]:
            out.append(f"s#^FROM {old}( |$)#FROM {new}\\1#")
        else:
            out.append(f"s#^([[:space:]]*FROM[[:space:]].*){old}([[:space:]]|$)#\\1{new}\\2#I")
    return _dedupe(out)


def _sed_image(bi, new):
    """Expression sed remplaçant l'image d'un service dans son docker-compose (None si non modifiable sans risque)."""
    raw = bi.get("image_raw") or ""
    if not raw or "'" in raw:
        return None
    q = '"' if len(raw) > 1 and raw[0] == raw[-1] == '"' else ""
    if bi.get("image_simple"):
        return f"s#image: {_ere(raw)}$#image: {q}{new}{q}#"
    return f"s#^([[:space:]]*image:[[:space:]]*){_ere(raw)}([[:space:]]|$)#\\1{q}{new}{q}\\2#"


def _sed_cmd(exprs, files):
    return "sed -i.bak -E " + " ".join(f"-e '{x}'" if len(exprs) > 1 else f"'{x}'" for x in exprs) + " " + " ".join(files)


def _backup_cmd(c, wd, tagname):
    """Archive à froid du projet et des montages en écriture situés hors du dossier du projet."""
    paths = [wd] + [m for m in c.get("rw_mounts") or [] if m != wd and not m.startswith(wd + "/")]
    dest = f"{BACKUP_DIR}/{c['container']}-avant-{tagname}-$(date +%F).tar.gz"
    if len(paths) == 1:
        return f"tar -czf {dest} -C {os.path.dirname(wd)} {os.path.basename(wd)}"
    return f"tar -czf {dest} -C / " + " ".join(x.lstrip("/") for x in paths)


def _pull_check(ref, checks, info, verb):
    """Le pull (ou build --pull) de ce tag apporterait-il le correctif ? checks = [(nom, slug, installée, voulue)].
    Renvoie (utile, remarque) ; (True, None) quand l'image publiée ne permet pas de conclure."""
    if not info:
        return True, None
    when = f" (construite le {info['created']})" if info.get("created") else ""
    for nm, slug, have, want in checks:
        rv = _remote_version(info, slug)
        if not (rv and have and want) or have == "inconnue":
            continue
        if vcmp(rv, norm_ver(want)) >= 0:
            return True, f"Vérifié sur le registre : {ref}{when} contient {nm} {rv}, {verb} apporte le correctif."
        if vcmp(rv, norm_ver(have)) <= 0:
            return False, (f"Vérifié sur le registre : {ref}{when} contient encore {nm} {rv} : {verb} ne changerait rien "
                           f"pour l'instant. Attendre une image reconstruite par l'éditeur (le dashboard la détectera) "
                           f"ou le lui signaler.")
        return True, f"Vérifié sur le registre : {ref}{when} contient {nm} {rv} ({verb} améliore, mais pas encore {want})."
    return True, None


def _waiting_title(title):
    """« Mettre à jour l'image X (…) » -> « Attendre une image corrigée de X (…) » (rien à lancer pour l'instant)."""
    m = re.match(r"^(?:Mettre à jour|Reconstruire) (?:l'image (?:maison )?)?(.*)$", title)
    if not m:
        return title
    rest = m.group(1)
    return "Attendre une image corrigée " + ("d'" if rest[:1].lower() in "aeiouyhéè" else "de ") + rest


def _lag_checks(c, eols, rto, target, e):
    """Versions qu'une nouvelle image du conteneur doit apporter : produit ou runtime embarqué en retard, cible CVE."""
    out = [(x["component"].split(" (")[0], x["product"], x["version"], x.get("latest")) for x in eols
           if x["status"] == "en retard" and (x["component_id"] == c["id"] or rto.get(x["component_id"]) == c["id"])]
    if target and not e:
        out.append((c["name"].split(" (")[0], c.get("product"), c.get("version"), target))
    return out


def _ct_plan(comps, eols, target, remote=None):
    """Commandes qui corrigent vraiment les conteneurs d'une action, déduites des Dockerfiles et docker-compose lus
    sur le NAS : un « build --pull » ou un « pull » seul ne sort jamais d'une branche figée (FROM node:20…, tag :10).
    Renvoie (commandes, remarques, conteneurs en attente d'une image corrigée). Les fichiers modifiés gardent un .bak."""
    eby = {e["component_id"]: e for e in eols}
    rto = {x["id"]: x.get("runtime_of") for x in comps}
    remote = remote or {}
    projs, notes, done, waiting = {}, [], set(), []
    for c in comps:
        if c.get("runtime_of") and not c.get("custom"):
            continue   # runtime fourni par une image tierce : couvert par la mise à jour du conteneur
        ct, bi, e = c.get("container"), c.get("build"), eby.get(c["id"])
        if not ct or ct in done:
            continue
        done.add(ct)
        if not bi or c["host"] != "nas":   # pas de déclaration lue (homelab, conteneur hors compose) : commande générique
            if not c.get("custom") and c.get("image"):
                useful, note = _pull_check(c["image"], _lag_checks(c, eols, rto, target, e), remote.get(c["image"]), "un pull")
                notes += [note] if note else []
                if not useful:
                    waiting.append(ct)
                    continue
            for cm in _ct_commands(c):
                projs.setdefault(("raw", cm), {"raw": cm})
            continue
        wd, svc = bi["wd"], bi["service"]
        P = projs.setdefault(wd, {"prepull": [], "backup": [], "sed_df": {}, "sed_img": [], "build": {}, "pull": [],
                                  "rm": [], "up": [], "logs": [], "all": False})
        if c.get("product") == "immich":   # procédure officielle : tous les services du projet ensemble
            P["all"] = True
            continue
        if c.get("custom"):
            if not bi.get("build"):
                notes.append(f"{ct} : aucune section build pour le service {svc} dans {bi.get('compose') or 'le compose'} : "
                             f"reconstruire l'image depuis ses sources.")
                continue
            if not bi.get("dockerfile_found"):
                notes.append(f"{ct} : Dockerfile {wd}/{bi['dockerfile']} introuvable : vérifier la section build du compose.")
            edits = []
            img = RUNTIME_IMAGES.get(e["product"]) if e and c.get("runtime_of") else None
            if img:
                bases = bi.get("bases") or []
                mine = [b for b in bases if b["ref"] and _image_repo(b["ref"])[0].split("/")[-1] == img]
                for b in mine:
                    t = _tag_split(_image_repo(b["ref"])[1])
                    if not t:
                        continue   # tag flottant (lts, latest…) : un build --pull suffit
                    parts = t[1].split(".")
                    cyc = parts[0] if e["product"] == "nodejs" else ".".join(parts[:2])
                    if e["status"] == "fin de vie" and e.get("next_cycle") and cyc == e["cycle"]:
                        edits.append((b, _bump_ref(b["ref"], _tagc(e["next_cycle"]), True)))
                    elif e["status"] == "en retard" and len(parts) >= 3 and e.get("latest"):
                        edits.append((b, _bump_ref(b["ref"], e["latest"], False)))   # version exacte figée
                if e["status"] == "fin de vie" and not edits:
                    other = sorted({b["ref"] or b["line"] for b in bases if b not in mine})
                    if other:
                        notes.append(f"{ct} : {bi['dockerfile']} part de {', '.join(other)}, qui embarque {img} {e['cycle']} : "
                                     f"remplacer cette image de base par une version sur {img}:{_tagc(e['next_cycle'])} avant de reconstruire.")
            if img and not edits and e["status"] == "en retard":
                vs = [_pull_check(r, [(e["component"].split(" (")[0], e["product"], e["version"], e.get("latest"))],
                                  remote.get(r), "le build --pull") for r in dict.fromkeys(b["ref"] for b in mine)]
                notes += [n for _, n in vs if n]
                if vs and not any(u for u, _ in vs):
                    waiting.append(ct)
                    continue
            exprs = tuple(_sed_bases([x for x in edits if x[1]]))
            if exprs:
                files = P["sed_df"].setdefault(exprs, [])
                if bi["dockerfile"] not in files:
                    files.append(bi["dockerfile"])
            P["build"].setdefault((bi["dockerfile"], bi.get("image") or svc), svc)   # image partagée : un seul build
        else:
            t = _tag_split(c.get("tag"))
            stuck = bool(e and e["status"] == "fin de vie" and t and t[1] in (e["cycle"], _tagc(e["cycle"])))
            new = None
            if stuck and e.get("next_cycle"):
                if c.get("product") not in TAG_BUMP_OK:
                    continue   # PostgreSQL & co : changement de version majeure hors simple tag (texte de l'action)
                new = _bump_ref(c["image"], _tagc(e["next_cycle"]), True)
            elif t and len(t[1].split(".")) >= 3:   # tag figé sur une version exacte : le pull ne bougerait pas
                want = (e or {}).get("latest") or target
                if want and vcmp(norm_ver(want), norm_ver(t[1])) > 0:
                    new = _bump_ref(c["image"], want, False)
            if new:
                expr = _sed_image(bi, new) if bi.get("image") == c.get("image") and bi.get("compose") else None
                if not expr:
                    notes.append(f"{ct} : passer l'image en {new} dans {bi.get('compose') or 'le docker-compose.yml'} "
                                 f"(ligne image: non modifiable automatiquement).")
                    continue
                P["sed_img"].append((os.path.relpath(bi["compose"], wd), expr))
                if stuck:   # nouvelle image téléchargée avant l'arrêt : coupure courte, rien n'est arrêté si elle manque
                    P["prepull"].append(new)
                    P["backup"].append((c, svc, _image_repo(new)[1]))
                    P["logs"].append(svc)
                else:
                    P["pull"].append(svc)
            elif stuck:
                continue
            else:
                useful, note = _pull_check(c["image"], _lag_checks(c, eols, rto, target, e), remote.get(c.get("image")), "un pull")
                if note:
                    notes.append(note)
                if not useful:
                    waiting.append(ct)
                    continue
                P["pull"].append(svc)
        P["up"].append(svc)
        if bi.get("orphan"):
            P["rm"].append(ct)
            notes.append(f"{ct} n'a pas été créé par docker compose (aucun label), mais {bi['compose']} le déclare "
                         f"(container_name: {ct}) : la commande le supprime puis le recrée depuis ce fichier ; vérifier avant "
                         f"que ports, volumes et .env y correspondent.")
    cmds = []
    for wd, P in projs.items():
        if "raw" in P:
            cmds.append(P["raw"])
            continue
        cd = f"cd {wd} &&"
        if P["all"]:
            cmds.append(f"{cd} docker compose pull && docker compose up -d")
            continue
        steps = [f"docker pull {r}" for r in _dedupe(P["prepull"])]
        for c, svc, tg in P["backup"]:   # à froid : conteneur arrêté pendant l'archive
            steps.append(f"docker compose stop {svc} && {_backup_cmd(c, wd, tg)}")
        steps += [_sed_cmd(list(x), fs) for x, fs in P["sed_df"].items()]
        steps += [_sed_cmd([x], [f]) for f, x in _dedupe(P["sed_img"])]
        run = []
        if P["build"]:
            run.append("docker compose build --pull " + " ".join(_dedupe(P["build"].values())))
        if P["pull"]:
            run.append("docker compose pull " + " ".join(_dedupe(P["pull"])))
        if P["rm"]:
            run.append("docker rm -f " + " ".join(_dedupe(P["rm"])))
        if P["up"]:
            run.append("docker compose up -d " + " ".join(_dedupe(P["up"])))
        if run:
            steps.append(" && ".join(run))
        if not steps:
            continue
        # Une seule chaîne par projet (une étape échoue -> la suite ne part pas) ; « && » en fin de ligne = suite
        cmds.append(f"{cd} {steps[0]}" + "".join(f" &&\n  {s}" for s in steps[1:]))
        if P["logs"]:
            cmds.append(f"sleep 30; cd {wd} && docker compose logs --tail 40 " + " ".join(_dedupe(P["logs"])))
    return cmds, notes, waiting


def _dedupe(lines):
    out, seen = [], set()
    for x in lines:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _eol_lines(eols, c0, comps):
    """Phrases fin de vie / retard, une seule fois par (branche, version) même si plusieurs conteneurs."""
    lines = []
    grp = {}
    for e in eols:
        grp.setdefault((e["status"], e["product"], e["cycle"], e["version"], e["latest"]), []).append(e)
    for (status, prod, cyc, ver, latest), es in grp.items():
        e = es[0]
        nm = e["component"].split(" (")[0]
        ctn = sorted({x.get("container") for x in es if x.get("container")})
        where = f" ({', '.join(ctn)})" if len(ctn) > 1 else ""
        nxt, best = _tagc(e.get("next_cycle")), _tagc(e.get("best_cycle"))
        alt = f" ou {best}" if best and best != nxt else ""
        sup = (" LTS" if e.get("next_lts") else "") + (f" (support jusqu'au {e['next_eol']})" if e.get("next_eol") else "")
        if status == "fin de vie":
            if c0.get("runtime_of") and c0.get("custom") and nxt:
                img = RUNTIME_IMAGES.get(prod, prod)
                skip = "".join(f" ; {img}:{_tagc(s)} est écartée, son support s'arrête dès le {d}" for s, d in e.get("skip") or [])
                lines.append(f"{nm} {cyc} est en fin de vie depuis le {e['eol_date']} ({e['days_past']} j){where}. Un "
                             f"« docker compose build --pull » ne suffit pas : il reprend la même image de base {img}:{cyc}…, "
                             f"qui ne reçoit plus de correctifs. Il faut passer les lignes FROM des Dockerfiles en "
                             f"{img}:{nxt}{sup}{skip}" + (f" ; {img}:{best} est aussi possible" if alt else "") +
                             ", puis reconstruire, relancer et tester chaque application (les dépendances sont réinstallées au build).")
            elif c0.get("pinned") and not c0.get("runtime_of") and nxt:
                repo = _image_repo(c0.get("image"))[0]
                head = (f"Le tag {c0.get('image')} est figé sur la branche {cyc}, en fin de vie depuis le {e['eol_date']} "
                        f"({e['days_past']} j) : un pull de ce tag ne récupère rien de neuf.")
                if prod == "postgresql":
                    lines.append(head + f" PostgreSQL ne change pas de version majeure par simple changement de tag (format "
                                 f"des données incompatible) : sauvegarde pg_dumpall, nouveau conteneur postgres:{nxt}{sup} sur "
                                 f"un volume vide, puis restauration (ou pg_upgrade).")
                elif c0.get("rem") == "unraid-template":
                    lines.append(head + f" Sauvegarder l'appdata du conteneur à l'arrêt, puis Unraid → Docker → "
                                 f"{c0.get('container')} → Edit → Repository : {repo}:{nxt}{sup} → Apply, et vérifier les journaux.")
                elif prod == "forgejo":
                    a, b = re.match(r"^(\d+)", cyc or ""), re.match(r"^(\d+)", nxt)
                    rel = f" {int(a.group(1)) + 1} à {nxt}" if a and b and int(a.group(1)) + 1 < int(b.group(1)) else f" {nxt}"
                    lines.append(head + f" Forgejo passe directement à la dernière branche (migration de la base au "
                                 f"démarrage, sans installer les versions intermédiaires) : sauvegarde à froid, image "
                                 f"{repo}:{nxt}{sup}, redémarrage, puis contrôle des journaux. Lire avant les notes de version"
                                 f"{rel} (changements de configuration incompatibles). Retour arrière : restaurer l'archive et "
                                 f"le docker-compose.yml.bak (une base migrée ne redémarre pas sur l'ancienne version).")
                else:
                    lines.append(head + f" Sauvegarder (données + configuration), lire les notes de version, puis passer "
                                 f"l'image en {repo}:{nxt}{sup} dans le docker-compose.yml, pull + up et vérifier les journaux.")
            else:
                lines.append(f"{nm} {cyc} en fin de vie depuis le {e['eol_date']} ({e['days_past']} j){where}"
                             + (f" : migrer vers la branche {nxt}{alt}." if nxt else "."))
        elif status == "fin de vie proche":
            lines.append(f"{nm} {cyc} arrive en fin de vie le {e['eol_date']}{where} : planifier la migration"
                         + (f" vers {nxt}{alt}." if nxt else "."))
        else:
            vers = sorted({x["version"] for x in es if x.get("version")}, key=cmp_to_key(vcmp))
            vtxt = "/".join(vers) or ver
            if cyc:
                how = (" — reconstruire l'image avec --pull." if c0.get("custom") else
                       (" — correctif à récupérer en mettant à jour l'image." if not c0.get("runtime_of") else
                        " — runtime fourni par l'image : mettre à jour l'image si l'éditeur l'a reconstruite."))
                lines.append(f"{nm} {vtxt} en retard sur le dernier correctif de la branche {cyc} ({latest}){where}{how}")
            else:
                lines.append(f"{nm} {vtxt} : dernière version publiée {latest}.")
    return lines


def _remediate(key, comps, findings, eols, gh_latest, remote=None):
    """Titre, texte, commandes et version cible d'une action (en français, concret)."""
    c0 = comps[0]
    rem = c0.get("rem")
    expo = [f for f in findings if f.get("kind") == "exposition"]
    if expo and len(expo) == len(findings) and not eols:
        r = expo[0]["_risk"]
        ctn = sorted({f.get("container") for f in expo if f.get("container")})
        title = r["action_title"] + (f" ({len(ctn)} conteneurs)" if len(ctn) > 1 else "")
        det = "; ".join(sorted({f["summary"] for f in expo}))
        return title, _join([r["fix"], f"Constat : {det}."]), list(r.get("commands") or []), None
    # Correctif en pré-version d'une autre branche : jamais proposé comme cible (vérifier le rétroportage)
    pre = [f for f in findings if f.get("prerelease_only")]
    fixable = [f for f in findings if f.get("fixed") and not f.get("nofix") and not f.get("prerelease_only")
               and f.get("kind") != "exposition"]
    nofix = [f for f in findings if f.get("nofix")]
    is_deb = rem in ("apt-homelab", "kernel-homelab", "claw-apt")
    cmp = deb_cmp if is_deb else vcmp
    target = _vmax([f["fixed"] for f in fixable], cmp)
    lines, cmds = [], []
    eol_fin = [e for e in eols if e["status"] == "fin de vie"]
    eol_lag = [e for e in eols if e["status"] == "en retard"]
    latest = gh_latest.get(c0.get("gh")) if c0.get("gh") else None
    ctn = sorted({c.get("container") for c in comps if c.get("container")})
    if rem == "apt-homelab":
        pk = {}
        for f in fixable:
            d = pk.setdefault(f["component"], {"from": f["version"], "to": f["fixed"], "n": 0})
            d["n"] += 1
            if deb_cmp(f["fixed"], d["to"]) > 0:
                d["to"] = f["fixed"]
        top = sorted(pk.items(), key=lambda kv: -kv[1]["n"])
        title = (f"Mettre à jour {len(pk)} paquet(s) Debian du homelab ({len(fixable)} CVE corrigée(s))" if pk
                 else "Paquets Debian du homelab")
        if pk:
            lines.append("Correctifs disponibles dans les dépôts Debian : " +
                         ", ".join(f"{n} {d['from']} → {d['to']} ({d['n']} CVE)" for n, d in top[:15]) +
                         (f" et {len(top) - 15} autre(s)" if len(top) > 15 else "") + ".")
            cmds = ["sudo apt update && sudo apt full-upgrade"]
            if any(n in ("glibc", "openssl", "systemd", "openssh") for n in pk):
                lines.append("Redémarrer ensuite les services concernés (sudo needrestart) ou le homelab.")
        lines += _eol_lines(eols, c0, comps)
        return title, _join(lines), cmds, None
    if rem == "kernel-homelab":
        inst = c0.get("installed")
        need_new = [f for f in fixable if inst and deb_cmp(f["fixed"], inst) > 0]
        by_reboot = len(fixable) - len(need_new)
        top = sorted(fixable, key=lambda f: -f["score"])[:3]
        if need_new:
            title = f"Mettre à jour le noyau ({c0['version']} → {target}) puis redémarrer le homelab"
            cmds = ["sudo apt update && sudo apt full-upgrade", "sudo reboot"]
            lines.append(f"{by_reboot} CVE sont déjà corrigées par le noyau installé {inst} (en attente de redémarrage) ; "
                         f"{len(need_new)} nécessitent un noyau plus récent ({target}).")
        else:
            title = f"Redémarrer le homelab sur le noyau {inst} (déjà installé)"
            cmds = ["sudo reboot"]
            lines.append(f"Le noyau en cours d'exécution ({c0['version']}) est vulnérable à {len(fixable)} CVE corrigées "
                         f"par le noyau {inst}, déjà installé : un redémarrage suffit"
                         + (" (/var/run/reboot-required présent)." if c0.get("reboot_required") else "."))
        if top:
            lines.append("Les plus sérieuses : " + ", ".join(f"{f['id']} (CVSS {f['cvss']})" for f in top if f.get("cvss")) + ".")
        lines.append("Prévoir une courte coupure DNS (AdGuard) et de la supervision pendant le redémarrage.")
        return title, _join(lines), cmds, inst if not need_new else target
    if rem in ("apt-docker", "unraid-os"):
        per = {}
        for f in fixable:
            per.setdefault(f["component"], []).append(f)
        bits = [f"{n} {fs[0]['version']} : {len(fs)} vulnérabilité(s), corrigé en {_vmax([x['fixed'] for x in fs], vcmp)}"
                for n, fs in sorted(per.items(), key=lambda kv: -max(x["score"] for x in kv[1]))]
        for e in eol_fin:
            bits.append(f"{e['component']} {e['version']} en fin de vie depuis le {e['eol_date']}")
        for e in eol_lag:
            bits.append(f"{e['component']} {e['version']} → {e['latest']}")
        if rem == "apt-docker":
            title = "Mettre à jour Docker Engine / containerd / runc du homelab"
            lines.append("; ".join(bits) + "." if bits else "")
            av = [f"{'docker-ce' if c['id'].endswith('docker-ce') else 'containerd.io'} "
                  f"{re.sub(r'^[0-9]+:', '', c['available']).split('-')[0]}" for c in comps if c.get("available")]
            if av:
                lines.append("Disponible dès maintenant via apt (dépôt Docker) : " + ", ".join(av) + ".")
            lines.append("Le redémarrage du démon Docker relance les conteneurs du homelab (restart: unless-stopped).")
            cmds = ["sudo apt update && sudo apt install --only-upgrade docker-ce docker-ce-cli containerd.io",
                    "cd /opt/homelab && sudo docker compose up -d"]
            return title, _join(lines), cmds, None
        title = "Mettre à jour Unraid OS (noyau, Samba, nginx/PHP, OpenSSL, Docker, containerd, runc intégrés)"
        lines.append("Ces composants sont fournis par Unraid et ne se mettent à jour qu'avec l'OS : " + "; ".join(bits) + ".")
        lines.append("Procédure : sauvegarder la clé USB (Main → Flash → Flash Backup), puis Tools → Update OS si une version "
                     "plus récente est proposée, lire les notes de version et redémarrer le NAS (arrêt de l'array et des conteneurs).")
        lines.append("Si Unraid n'a pas encore publié de version intégrant ces correctifs, limiter l'exposition (webGUI hors "
                     "Internet, SMB/SSH réservés au LAN et à Tailscale).")
        return title, _join(lines), [], None
    if rem == "apt-tailscale":
        return (f"Mettre à jour Tailscale du homelab ({c0['version']} → {target or 'dernière'})",
                "Mise à jour depuis le dépôt Tailscale.", ["sudo apt update && sudo apt install --only-upgrade tailscale"], target)
    if rem == "unraid-plugin":
        return (f"Mettre à jour le plugin Tailscale du NAS ({c0['version']} → {target or 'dernière'})",
                "Unraid : Plugins → Check for Updates → Tailscale.", [], target)
    if rem == "claw-apt":
        title = "Mettre à jour les paquets Ubuntu de clawhost"
        if fixable:
            lines.append(f"{len(fixable)} CVE corrigée(s) : openssh {c0['version']} → {target}.")
        lines += _eol_lines(eols, c0, comps)
        lines.append("Pas d'accès SSH depuis le homelab : à lancer sur clawhost.")
        return title, _join(lines), ["ssh -p 2211 openclaw@192.168.2.5", "sudo apt update && sudo apt upgrade"], target
    if latest and c0.get("version") not in (None, "inconnue") and vcmp(norm_ver(latest["tag"]), c0["version"]) > 0:
        lt = norm_ver(latest["tag"])
        if not target or vcmp(lt, target) > 0:
            target = lt
    if rem == "claw-openclaw":
        title = f"Mettre à jour OpenClaw sur clawhost ({c0['version']} → {target or 'dernière'})"
        if fixable:
            lines.append(f"{len(fixable)} advisory(s) GitHub corrigée(s) au-delà de la version installée.")
        if latest:
            lines.append(f"Dernière version publiée : {norm_ver(latest['tag'])} ({latest['published']}).")
        lines.append("Mettre à jour avec la méthode d'installation utilisée (npm i -g openclaw@latest si installé via npm), "
                     "puis redémarrer le gateway.")
        return title, _join(lines), ["ssh -p 2211 openclaw@192.168.2.5", "npm install -g openclaw@latest"], target
    # Conteneurs (homelab, NAS, clawhost)
    lag_prim = [e for e in eol_lag if not by_rt(comps, e)]
    if lag_prim and not target:
        target = _vmax([e["latest"] for e in lag_prim], vcmp)
    if latest:   # la ligne « dernière version publiée » remplace le constat de retard GitHub
        eols = [e for e in eols if e.get("source") != "github-release"]
    many = len(ctn) > 1
    nm = c0["name"].split(" (")[0]
    vtxt = c0["version"] if c0.get("version") not in (None, "inconnue") else ""
    runtime_only = all(c.get("runtime_of") for c in comps if c["id"] in {f["component_id"] for f in findings} |
                       {e["component_id"] for e in eols}) and not fixable and not nofix
    if c0.get("runtime_of") and c0.get("custom"):
        cyc = (eols[0]["cycle"] if eols else "")
        what = f"l'image maison {ctn[0]}" if len(ctn) == 1 else f"{len(ctn)} images maison"
        nx = _tagc(eol_fin[0].get("next_cycle")) if eol_fin else None
        if eol_fin and nx:
            title = f"Passer {what} de {nm} {cyc} (fin de vie) à {nm} {nx}"
        elif eol_fin:
            title = f"Reconstruire {what} sur {nm} {cyc} (fin de vie)" if len(ctn) > 1 else \
                f"Reconstruire {what} ({nm} {cyc} en fin de vie)"
        else:
            vers = "/".join(sorted({e["version"] for e in eols if e.get("version")}, key=cmp_to_key(vcmp)))
            title = f"Reconstruire {what} ({nm} {vers or cyc} → {eols[0]['latest'] if eols else '?'})"
        target = None if eol_fin else (eols[0]["latest"] if eols else None)
    elif runtime_only:
        rt = next((c for c in comps if c.get("runtime_of")), c0)
        prim = next((c for c in comps if not c.get("runtime_of")), c0)
        e = eols[0] if eols else None
        title = f"Mettre à jour l'image {prim['name']}" + (f" ({rt['name'].split(' (')[0]} {rt['version']} → {e['latest']})" if e else "")
        target = None
    elif fixable:
        title = f"Mettre à jour {nm} {vtxt}".strip() + (f" → {target}" if target else "")
    elif nofix:
        title = f"Réduire l'exposition de {nm} ({len(nofix)} vulnérabilité(s) sans correctif)"
    elif eol_fin:
        nx = eol_fin[0].get("next_cycle")
        title = f"Passer {nm} {vtxt or eol_fin[0]['cycle']} (fin de vie) à la branche {_tagc(nx)}" if nx else \
            f"{nm} {vtxt or eol_fin[0]['cycle']} en fin de vie"
        target = eol_fin[0].get("next_latest") if nx else None
    elif target:
        title = f"Mettre à jour {nm} {vtxt} → {target}".replace("  ", " ")
    elif pre:
        title = f"Vérifier le correctif de {', '.join(f['id'] for f in pre[:3])} dans la branche stable de {nm}"
    else:
        title = f"Mettre à jour {nm}"
    if many and not (c0.get("runtime_of") and c0.get("custom")):
        title += f" ({len(ctn)} conteneurs)"
    if fixable:
        lines.append(f"{len(fixable)} vulnérabilité(s) corrigée(s) dans une version ultérieure (cible ≥ "
                     f"{_vmax([f['fixed'] for f in fixable], vcmp)}).")
    for f in pre:
        lines.append(f"{f['id']} : seule version corrigée référencée = pré-version {f['fixed']}, d'une autre branche que "
                     f"{f['version']} : vérifier dans le changelog si le correctif a été rétroporté dans la branche stable "
                     f"(non confirmé, priorité abaissée) ; ne pas passer en bêta.")
    if target and re.search(r"-(b|beta|rc|alpha)\.?\d*", target, re.I):
        lines.append(f"La seule version corrigée référencée est une pré-version ({target}) : vérifier dans l'advisory si le "
                     f"correctif a été intégré à la branche stable ; sinon limiter l'exposition plutôt que passer en bêta.")
    if target and not eol_fin and c0.get("version") not in (None, "inconnue") and \
            _toks(norm_ver(target))[:1] != _toks(norm_ver(c0["version"]))[:1]:
        lines.append(f"Montée de version majeure ({c0['version']} → {target}) : sauvegarder d'abord (base de données + "
                     f"configuration), lire les notes de version (changements incompatibles) puis mettre à jour.")
    lines += _eol_lines(eols, c0, comps)
    if nofix:
        lines.append(f"{len(nofix)} vulnérabilité(s) sans version corrigée publiée : réduire l'exposition en attendant.")
        if c0["exposure"] == "internet":
            lines.append("Exposé sur Internet : ajouter une Access List dans Nginx Proxy Manager ou retirer temporairement le domaine.")
        elif c0["exposure"] == "lan":
            lines.append("Publier le port en 127.0.0.1 si l'accès LAN n'est pas nécessaire, ou filtrer par pare-feu.")
    for f in expo:
        lines.append(f["_risk"]["fix"])
    if latest and target and vcmp(norm_ver(latest["tag"]), target) == 0:
        lines.append(f"Dernière version publiée : {norm_ver(latest['tag'])} ({latest['published']}).")
    if rem in ("homelab-ct", "nas-compose", "nas-custom"):
        cmds, notes, waiting = _ct_plan(comps, eols, target, remote)
        lines += notes
        if c0.get("custom") and any("sed -i.bak" in cm for cm in cmds):
            lines.append("Chaque Dockerfile modifié garde une copie .bak (retour arrière : remettre le .bak puis relancer "
                         "la même commande build/up).")
        if c0["host"] == "nas" and cmds:
            cmds = ["ssh root@192.168.2.3"] + cmds
        if waiting and not cmds:
            title = _waiting_title(title)
    elif rem == "unraid-template" and c0.get("pinned") and eol_fin:
        pass   # procédure dans le texte de fin de vie : « Check for Updates » ne change pas de branche
    elif rem == "unraid-template":
        rto = {x["id"]: x.get("runtime_of") for x in comps}
        prim = next((c for c in comps if not c.get("runtime_of")), c0)
        useful, note = _pull_check(prim.get("image"), _lag_checks(prim, eols, rto, target, None),
                                   (remote or {}).get(prim.get("image")), "« Apply Update »")
        lines += [note] if note else []
        if useful:
            lines.append(f"Unraid : onglet Docker → Check for Updates → Apply Update sur « {', '.join(ctn)} ».")
        else:
            title = _waiting_title(title)
    elif rem in ("claw-ct", "claw-svc"):
        lines.append("Sur clawhost (pas d'accès SSH depuis le homelab) : mettre à jour le projet concerné "
                     "(docker compose pull && docker compose up -d, ou reconstruire l'image maison).")
    if pre and not (fixable or nofix or eols or expo or target):
        cmds = []   # rien à mettre à jour : une commande de pull ne changerait rien
    if c0.get("exposure") == "internet" and not nofix:
        lines.append(f"Exposé sur Internet ({c0['exposure_detail']}).")
    return title, _join(lines), cmds, target


def by_rt(comps, e):
    """Le constat concerne-t-il un runtime embarqué (Node/Python) plutôt que le produit ?"""
    c = next((x for x in comps if x["id"] == e["component_id"]), None)
    return bool(c and c.get("runtime_of"))


def _join(lines):
    return " ".join(_dedupe([x.strip() for x in lines if x and x.strip()]))


# --- Analyse ---------------------------------------------------------------------------------
def _analyze(inv, sources):
    t0 = time.time()
    deadline = t0 + DEADLINE
    by_id = {c["id"]: c for c in inv}
    # 1) OSV : requêtes groupées puis détails
    keys = sorted({tuple(q) for c in inv for q in c.get("osv") or [] if q[2]})
    ecos = sorted({k[0] for k in keys})
    err = []
    hits, unk = _osv_query(keys, deadline, err)
    ids = sorted({i for v in hits.values() for i in v})
    recs, fetched = _osv_details(ids, ecos, min(deadline, t0 + 110), err)
    missing = [i for i in ids if i not in recs]
    _src(sources, "osv", (bool(hits) and not err[:1] or bool(recs)) and not unk, len(ids), "; ".join(err) or None)
    sources["osv"]["unchecked"] = unk
    sources["osv"]["queries"] = len(keys)
    sources["osv"]["fetched"] = fetched
    sources["osv"]["missing"] = len(missing)
    # 2) GitHub (advisories de dépôts, vérifications Go, dernières versions)
    gh = _GH()
    gh_adv, gh_latest = {}, {}
    for c in inv:
        r = c.get("gh")
        if r and r not in gh_adv:
            gh_adv[r] = _gh_repo_advisories(gh, r)
            gh_latest[r] = _gh_latest(gh, r)
    # 3) endoflife.date
    eerr = []
    slugs = sorted({c["eol"][0] for c in inv if c.get("eol")})
    eold = {s: _eol_data(s, eerr) for s in slugs}
    _src(sources, "endoflife", len([s for s in slugs if eold.get(s)]) == len(slugs), len(slugs), "; ".join(eerr) or None)
    # 4) KEV
    kerr = []
    kev = _kev(kerr) or {}
    _src(sources, "kev", bool(kev) and not kerr, len(kev), "; ".join(kerr) or None)

    findings, nofix_deb, dismissed = [], {}, []
    go_verify = {}   # (pkg, ver) -> [candidats à confirmer]
    for c in inv:
        cand = {}
        for q in c.get("osv") or []:
            eco, pkg, ver = q
            for vid in hits.get(tuple(q), []):
                rec = recs.get(vid)
                if not rec:
                    continue
                al = [vid] + [a for a in rec["al"] if a != vid]
                cve = _cve_of(al) or (vid[7:] if vid.startswith("DEBIAN-CVE-") else None)
                key = cve or next((a for a in al if a.startswith("GHSA-")), vid)
                affs = [a for a in rec["aff"] if a["e"] == eco and a["n"] == pkg]
                sc, vec, approx = _best_cvss(rec["sv"], rec.get("ds"), next((s for t, s in rec["sv"] if t == "Ubuntu"), None))
                if eco.startswith(("Debian", "Ubuntu")):
                    cmp = deb_cmp
                    fixes = [v for a in affs for r in a["r"] for k, v in r if k == "fixed"]
                    fx = [f for f in fixes if deb_cmp(f, ver) > 0]
                    urg = next((a["u"] for a in affs if a.get("u")), None)
                    if eco.startswith("Ubuntu"):
                        urg = urg or next((s for t, s in rec["sv"] if t == "Ubuntu"), None)
                    urg = (urg or "").strip("*").strip() or None
                    if fixes and not fx:
                        dismissed.append({"id": key, "component": c["name"], "host": c["host"], "reason": "déjà corrigé dans la version installée"})
                        continue
                    fixed = _vmin(fx, deb_cmp)
                    if not fixed or urg in ("unimportant", "end-of-life", "negligible"):
                        d = nofix_deb.setdefault(c["id"], {"component_id": c["id"], "package": c["name"], "host": c["host"],
                                                           "version": ver, "n": 0, "n_nofix": 0, "n_unimportant": 0,
                                                           "max_cvss": None, "kev": False, "ids": [], "_cves": []})
                        if key in d["_cves"]:
                            continue
                        d["_cves"].append(key)
                        if urg in ("unimportant", "negligible"):
                            d.setdefault("_unimp", []).append(key)
                        d["n"] += 1
                        d["n_nofix" if not fixed else "n_unimportant"] += 1
                        if sc is not None and (d["max_cvss"] is None or sc > d["max_cvss"]):
                            d["max_cvss"] = sc
                        d["ids"].append([key, sc or 0])
                        continue
                    title = _first_sentence(rec["s"] or rec["d"])
                    f = _finding_base(c, key, al, f"{c['name']} : {title}", rec["d"][:220] or rec["s"], rec["refs"],
                                      f"osv:{eco}", rec["p"])
                    f.update({"fixed": fixed, "urgency": urg, "cvss": sc, "cvss_vector": vec, "nofix": False, "verified": True,
                              "av": cvss.attack_vector(vec) if vec else None, "cvss_approx": approx})
                    if urg == "low":
                        f["cap"] = 54
                    if c.get("kind") == "noyau" and not f["av"]:
                        f["av"], f["av_assumed"] = "L", True   # CVE noyau sans vecteur : majoritairement locales
                    if c.get("rem") == "kernel-homelab":
                        inst = c.get("installed")
                        f["reboot_only"] = bool(inst and deb_cmp(fixed, inst) <= 0)
                    prev = cand.get(key)
                    if not prev or (f["cvss"] or 0) > (prev["cvss"] or 0):
                        cand[key] = f
                    continue
                # Écosystèmes applicatifs (Go, npm)
                cmp = vcmp
                fixed, proper_eval = None, False
                for a in affs:
                    if ver in (a.get("v") or []):
                        proper_eval = True
                    for r in a["r"]:
                        evs = [(k, v) for k, v in r if not _pseudo(v)]
                        if not evs:
                            continue
                        if _range_affects(evs, ver, cmp):
                            proper_eval = True
                            fx = [v for k, v in evs if k == "fixed" and cmp(v, ver) > 0]
                            if fx:
                                m_ = _vmin(fx, cmp)
                                fixed = m_ if not fixed or cmp(m_, fixed) < 0 else fixed
                bp = next((_BACKPORTS[(pkg, x)] for x in al if (pkg, x) in _BACKPORTS), None)
                if bp and cmp(ver, bp) >= 0:
                    dismissed.append({"id": key, "component": c["name"], "host": c["host"],
                                      "reason": f"corrigé dans la branche stable {bp} (rétroportage absent de l'advisory)"})
                    continue
                title = _first_sentence(rec["s"] or rec["d"])
                f = _finding_base(c, key, al, f"{c['name']} : {title}", rec["d"][:220] or rec["s"], rec["refs"],
                                  f"osv:{eco}", rec["p"])
                f.update({"fixed": fixed, "cvss": sc, "cvss_vector": vec, "nofix": not fixed, "verified": True,
                          "av": cvss.attack_vector(vec) if vec else None, "cvss_approx": approx,
                          "_ghsa": [x for x in al if x.startswith("GHSA-")],
                          "_lka": rec.get("lka")})
                if fixed and _pre_other_branch(fixed, ver):
                    # Seul correctif = bêta d'une branche parallèle : souvent rétroporté en stable -> non vérifié, priorité basse
                    f["verified"], f["cap"], f["prerelease_only"] = False, 29, True
                if eco == "Go" and not fixed:
                    # Plages Go peu fiables (chemins de module sans /vN, pseudo-versions) : confirmation par GitHub
                    f["verified"] = False
                    go_verify.setdefault((pkg, ver), []).append((c, f))
                elif not proper_eval and not fixed:
                    f["verified"] = False
                prev = cand.get(key)
                if not prev or (bool(f["fixed"]) and not prev["fixed"]) or ((f["cvss"] or 0) > (prev["cvss"] or 0) and bool(f["fixed"]) == bool(prev["fixed"])):
                    if prev:
                        f["aliases"] = list(dict.fromkeys(f["aliases"] + prev["aliases"]))[:6]
                        if f["cvss"] is None:
                            f["cvss"], f["cvss_vector"], f["av"] = prev["cvss"], prev.get("cvss_vector"), prev.get("av")
                    cand[key] = f
                elif prev:
                    prev["aliases"] = list(dict.fromkeys(prev["aliases"] + f["aliases"]))[:6]
        # Advisories GitHub de dépôt (Vaultwarden, Immich, Jellyfin, OpenClaw, Homepage, NPM)
        if c.get("gh") and c.get("version") and gh_adv.get(c["gh"]):
            pkgs = {p.lower() for p in c.get("gh_pkgs") or []}
            for a in gh_adv[c["gh"]]:
                vs = a.get("vulns") or []
                rel = [v for v in vs if (v.get("pkg") or "").lower() in pkgs] or (vs if len(vs) == 1 and not (vs[0].get("pkg") or "").startswith("@") else [])
                hit = None
                for v in rel:
                    ok = in_range(c["version"], v.get("range"))
                    pv_ = re.search(r"\d[\w.\-]*", v.get("patched") or "")
                    # Plage sans borne haute mais version corrigée connue (ex. '>=10.8.0' / 10.8.10) : borne implicite
                    if ok and pv_ and vcmp(c["version"], pv_.group(0)) >= 0:
                        ok = False
                    if ok:
                        hit = v
                        break
                if not hit:
                    continue
                key = a.get("cve") or a["ghsa"]
                if key in cand:
                    continue
                pv = re.search(r"\d[\w.\-]*", hit.get("patched") or "") or re.search(r"\d[\w.\-]*", _upper_bound(hit.get("range")) or "")
                inferred = False
                if not pv:
                    # '<= X' sans version corrigée : corrigé au plus tard dans la dernière version publiée si elle est > X
                    m_le = re.search(r"<=\s*v?(\d[\w.\-]*)", hit.get("range") or "")
                    lt = gh_latest.get(c["gh"])
                    if m_le and lt and vcmp(norm_ver(lt["tag"]), m_le.group(1)) > 0:
                        pv, inferred = re.search(r"\d[\w.\-]*", norm_ver(lt["tag"])), True
                sc, vec = a.get("score"), a.get("vector")
                if not sc and vec:
                    sc = cvss.base_score(vec)[0]
                if not sc:
                    sc = cvss.score_from_label(a.get("severity"))
                f = _finding_base(c, key, [x for x in (a.get("cve"), a["ghsa"]) if x],
                                  f"{c['name']} : {_clean_md(a.get('summary') or '')}"[:160],
                                  _clean_md(a.get("desc") or a.get("summary") or "")[:220], [a.get("url")] if a.get("url") else [],
                                  f"github:{c['gh']}", a.get("published"))
                f.update({"fixed": pv.group(0) if pv else None, "cvss": sc, "cvss_vector": vec, "nofix": not pv,
                          "verified": True, "av": cvss.attack_vector(vec) if vec else None, "range": hit.get("range")})
                if inferred:
                    f["fixed_inferred"] = True
                cand[key] = f
        findings += list(cand.values())
        # Constats d'exposition vérifiés (configuration, pas de CVE)
        for r in c.get("risks") or []:
            f = _finding_base(c, f"EXPO-{r['rid']}", [], f"{c['name']} : {r['title']}", r["detail"], [], "exposition", None)
            f.update({"kind": "exposition", "fixed": None, "cvss": None, "cvss_vector": None, "nofix": False,
                      "verified": True, "av": None, "_akey": f"expo:{r['rid']}", "_risk": r, "risk_score": r["score"]})
            findings.append(f)

    # 5) Confirmation des advisories Go sans version corrigée via GitHub (affects=module@version)
    for (pkg, ver), lst in go_verify.items():
        aff = _gh_affects(gh, "go", pkg, ver)
        if aff is None:
            for c, f in lst:
                f["cap"] = 54
                f["nofix"] = True
            continue
        idx = {}
        for a in aff:
            for k in (a.get("ghsa"), a.get("cve")):
                if k:
                    idx[k] = a
        for c, f in lst:
            a = next((idx[k] for k in [f["id"]] + f["aliases"] if k in idx), None)
            if not a:
                f["_dismiss"] = "non confirmé par GitHub pour cette version (plage Go/pseudo-version d'OSV)"
                continue
            f["verified"] = True
            rng = next((v.get("range") for v in a.get("vulns") or [] if v.get("pkg") == pkg and in_range(ver, v.get("range"))), None)
            ub = _upper_bound(rng) if rng else None
            pv = next((v.get("patched") for v in a.get("vulns") or [] if v.get("pkg") == pkg and v.get("patched")), None)
            fix = ub if ub and not _pseudo(ub) else (pv if pv and not _pseudo(pv) else None)
            f["fixed"], f["nofix"], f["range"] = fix, not fix, rng
            if f["cvss"] is None and a.get("score"):
                f["cvss"], f["cvss_vector"] = a["score"], a.get("vector")
    # Plugin CRI de containerd désactivé (config lue sur l'hôte) : CVE propres à l'API CRI (Kubernetes) inapplicables
    for f in findings:
        if (by_id.get(f["component_id"]) or {}).get("cri_disabled") and re.search(r"\bCRI\b", f["title"]):
            f["_dismiss"] = "plugin CRI de containerd désactivé (Docker seul, pas de Kubernetes)"
    kept = []
    for f in findings:
        if f.get("_dismiss"):
            dismissed.append({"id": f["id"], "component": f["component"], "host": f["host"], "reason": f["_dismiss"]})
        else:
            kept.append(f)
    findings = kept
    _src(sources, "github", not gh.errors, gh.calls, "; ".join(dict.fromkeys(gh.errors)) or None)
    sources["github"]["repos"] = len(gh_adv)

    # 6) EPSS + KEV + score
    cves = sorted({_cve_of([f["id"]] + f["aliases"]) for f in findings if _cve_of([f["id"]] + f["aliases"])} |
                  {k for d in nofix_deb.values() for k in d["_cves"] if k.startswith("CVE-")})
    perr = []
    epss = _epss(cves, deadline, perr) if cves else {}
    _src(sources, "epss", not perr, len(epss), "; ".join(perr) or None)
    for f in findings:
        f.setdefault("kind", "cve")
        if f.get("kind") == "exposition":
            f.update({"epss": None, "epss_pct": None, "kev": False, "kev_due": None, "kev_ransomware": False,
                      "severity": cvss.label(f["risk_score"] / 10), "score": f["risk_score"], "priority": _prio(f["risk_score"])})
            continue
        cve = _cve_of([f["id"]] + f["aliases"])
        e = epss.get(cve) if cve else None
        f["epss"], f["epss_pct"] = (round(e[0], 4), round(e[1], 3)) if e else (None, None)
        k = kev.get(cve) if cve else None
        f["kev"] = bool(k)
        f["kev_due"] = k[1] if k else None
        f["kev_ransomware"] = (k[2] == "Known") if k else False
        f["severity"] = cvss.label(f.get("cvss"))
        if f.get("nofix") and not f.get("verified"):
            f["cap"] = min(f.get("cap") or 100, 54)
        f["score"] = _score(f)
        f["priority"] = _prio(f["score"])
        f["n_critical"] = 0
    for d in nofix_deb.values():
        unimp = set(d.pop("_unimp", []))
        d["kev_ids"] = [k for k in d["_cves"] if k in kev and k not in unimp][:5]
        d["kev"] = bool(d["kev_ids"])
        es = [epss[k][0] for k in d["_cves"] if k in epss]
        d["max_epss"] = round(max(es), 4) if es else None
        recent = [k for k in d["_cves"] if k in epss and k not in unimp and int(k.split("-")[1]) >= date.today().year - 3]
        d["top_epss"] = [[k, round(epss[k][0], 4)] for k in sorted(recent, key=lambda k: -epss[k][0])[:3] if epss[k][0] >= 0.1]
        d["top"] = [i for i, _ in sorted(d["ids"], key=lambda x: -x[1])[:5]]
        d["priority"] = "basse"
        del d["ids"], d["_cves"]

    # 7) Fin de vie / retard de version
    today = date.today()
    eols = []
    for c in inv:
        if not c.get("eol"):
            continue
        slug, cyc, ver = c["eol"]
        data = eold.get(slug) or []
        cycles = {str(x["cycle"]): x for x in data}
        entry = None
        cands = [cyc] if cyc else []
        if ver:
            p = norm_ver(ver).split(".")
            cands += [".".join(p[:i]) for i in range(len(p), 0, -1)]
            cands += [p[0] + ".0"]
        for cc in cands:
            if cc and cc in cycles:
                entry = cycles[cc]
                break
        if not entry:
            continue
        ev = entry.get("eol")
        eol_date, passed = None, False
        if isinstance(ev, str):
            try:
                eol_date = datetime.strptime(ev, "%Y-%m-%d").date()
                passed = eol_date <= today
            except ValueError:
                pass
        elif ev is True:
            passed = True
        latest = entry.get("latest")
        behind = bool(ver and latest and c.get("eol_patch") and vcmp(norm_ver(ver), latest) < 0)
        # Branches maintenues plus récentes (LTS de préférence) pour les migrations
        ti = today.isoformat()
        newer = [x for x in data if (x.get("eol") is False or (isinstance(x.get("eol"), str) and x["eol"] > ti))
                 and vcmp(str(x["cycle"]), str(entry["cycle"])) > 0]
        lts_e = [x for x in newer if x.get("lts") is True or (isinstance(x.get("lts"), str) and x["lts"] <= ti)]
        lts = [str(x["cycle"]) for x in lts_e]
        best = _vmax(lts, vcmp) or _vmax([str(x["cycle"]) for x in newer], vcmp)

        def left(x):   # jours de support restants
            ev = x.get("eol")
            return 10 ** 5 if ev is False else ((datetime.strptime(ev, "%Y-%m-%d").date() - today).days
                                                if isinstance(ev, str) and re.match(r"^\d{4}-\d\d-\d\d$", ev) else 0)
        # Cible conseillée : la plus ancienne branche (LTS de préférence) encore soutenue au moins 12 mois,
        # sinon celle soutenue le plus longtemps (migrer vers une branche qui meurt dans 6 mois ne règle rien)
        pool = lts_e or newer
        ok = [x for x in pool if left(x) >= 365]
        pick = (min(ok, key=lambda x: cmp_to_key(vcmp)(str(x["cycle"]))) if ok else max(pool, key=left)) if pool else None
        nxt = str(pick["cycle"]) if pick else None
        skip = [(str(x["cycle"]), x["eol"]) for x in pool if pick and vcmp(str(x["cycle"]), nxt) < 0 and isinstance(x.get("eol"), str)]
        soon = bool(eol_date and not passed and (eol_date - today).days <= 90)
        status = "fin de vie" if passed else ("en retard" if behind else ("fin de vie proche" if soon else None))
        if not status:
            continue
        gap = 1
        if behind:
            a, b = _toks(norm_ver(ver)), _toks(latest)
            if len(a) == len(b) and a[:-1] == b[:-1] and isinstance(a[-1], int) and isinstance(b[-1], int):
                gap = b[-1] - a[-1]
        eols.append({"component_id": c["id"], "component": c["name"], "host": c["host"], "container": c.get("container"),
                     "product": slug, "version": ver, "cycle": str(entry["cycle"]), "eol_date": eol_date.isoformat() if eol_date else None,
                     "latest": latest, "days_past": (today - eol_date).days if (eol_date and passed) else 0, "status": status,
                     "behind": gap if behind else 0, "next_cycle": nxt, "best_cycle": best, "exposure": c["exposure"],
                     "next_eol": pick.get("eol") if pick and isinstance(pick.get("eol"), str) else None,
                     "next_latest": pick.get("latest") if pick else None, "next_lts": bool(pick and str(pick["cycle"]) in lts),
                     "skip": sorted(skip, key=lambda s: cmp_to_key(vcmp)(s[0]))})
    # Retard sur la dernière version publiée (GitHub releases)
    for c in inv:
        lt = gh_latest.get(c.get("gh")) if c.get("gh") else None
        if lt and c.get("version") and c["version"] != "inconnue" and vcmp(norm_ver(lt["tag"]), c["version"]) > 0 \
                and not any(e["component_id"] == c["id"] for e in eols):
            eols.append({"component_id": c["id"], "component": c["name"], "host": c["host"], "container": c.get("container"),
                         "product": c.get("product") or c["name"], "version": c["version"], "cycle": None, "eol_date": None,
                         "latest": norm_ver(lt["tag"]), "days_past": 0, "status": "en retard", "behind": 1,
                         "next_cycle": None, "best_cycle": None, "exposure": c["exposure"], "source": "github-release"})

    # 7b) Images publiées : un pull (ou build --pull) du même tag apporterait-il vraiment le correctif ?
    lag = {e["component_id"] for e in eols if e["status"] == "en retard"} | \
        {f["component_id"] for f in findings if f.get("fixed") and not f.get("nofix")}
    refs = []
    for c in inv:
        if c["id"] not in lag or c["host"] not in ("nas", "homelab"):
            continue
        if c.get("custom"):
            refs += [b["ref"] for b in (c.get("build") or {}).get("bases") or [] if b.get("ref")]
        else:
            prim = by_id.get(c["runtime_of"]) if c.get("runtime_of") else c
            if prim and prim.get("image") and not prim.get("custom"):
                refs.append(prim["image"])
    refs = [r for r in dict.fromkeys(refs) if "$" not in r and not r.startswith("localhost/")][:40]
    remote, rerr = {}, []
    if refs and time.time() < deadline - 15:
        ex = ThreadPoolExecutor(2)   # au-delà, le limiteur de débit DNS (AdGuard) retarde les requêtes de 5 s
        futs = {ex.submit(_reg_image, r, rerr): r for r in refs}
        wait(futs, timeout=max(5, min(30, deadline - time.time() - 10)))
        ex.shutdown(wait=False, cancel_futures=True)
        remote = {r: f.result() for f, r in futs.items() if f.done() and not f.cancelled() and f.result()}
        _src(sources, "registres", len(remote) == len(refs), len(refs),
             "; ".join(rerr[:3]) or (None if len(remote) == len(refs) else "délai dépassé"))

    # 8) Plan de correction : regroupement par action
    groups = {}
    for c in inv:
        k = c.get("merge_key") or c.get("action_key") or c["id"]
        if c.get("runtime_of") and not c.get("custom"):
            k = by_id.get(c["runtime_of"], {}).get("action_key", k)
        c["_akey"] = k
    for f in findings:
        k = f.get("_akey") or by_id[f["component_id"]]["_akey"]
        groups.setdefault(k, {"f": [], "e": []})["f"].append(f)
    for e in eols:
        k = by_id[e["component_id"]]["_akey"]
        groups.setdefault(k, {"f": [], "e": []})["e"].append(e)
    actions = []
    for k, g in groups.items():
        comps = [c for c in inv if c["_akey"] == k] or [by_id[i] for i in dict.fromkeys(f["component_id"] for f in g["f"])]
        comps.sort(key=lambda c: (bool(c.get("runtime_of")), c["id"]))
        c0 = comps[0]
        fs = sorted(g["f"], key=lambda f: -f["score"])
        # Score lié à la fin de vie / au retard (sans CVE connue)
        escore = 0
        for e in g["e"]:
            ex = e["exposure"]
            if e["status"] == "fin de vie":
                s = (60 + (10 if e["days_past"] > 365 else 0)) * {"internet": 1.15, "lan": 0.9, "local": 0.5}.get(ex, 0.7)
            elif e["status"] == "fin de vie proche":
                s = 25
            else:
                s = (15 + 5 * min(e.get("behind") or 1, 5)) * EXPO_MULT.get(ex, 0.6)
            escore = max(escore, int(round(s)))
        max_score = max([f["score"] for f in fs] + [escore])
        fcomp = {f["component_id"] for f in fs}
        ecomp = {e["component_id"] for e in g["e"]}
        title, text, cmds, target = _remediate(k, comps, fs, g["e"], gh_latest, remote)
        # Garde-fou : jamais de « mise à jour » vers une version inférieure ou égale à celle installée
        try:
            if (target and c0.get("version") and c0.get("rem") != "apt-homelab" and re.match(r"^v?\d", str(target))
                    and re.match(r"^v?\d", str(c0["version"])) and vcmp(str(target), str(c0["version"])) <= 0):
                target = None
        except Exception:
            pass
        prio = _prio(max_score)
        expo = max((c["exposure"] for c in comps), key=lambda x: ["inconnue", "local", "lan", "internet"].index(x) if x in
                   ("inconnue", "local", "lan", "internet") else 0)
        cexp = next((c for c in comps if c["exposure"] == expo), c0)
        ctn = sorted({c.get("container") for c in comps if c.get("container")})
        comp_name = c0["name"]
        if c0.get("rem") == "apt-homelab":
            comp_name = "Paquets Debian (homelab)"
        elif c0.get("rem") == "unraid-os":
            comp_name = "Unraid OS et composants intégrés"
        elif c0.get("rem") == "apt-docker":
            comp_name = "Docker Engine / containerd / runc (homelab)"
        for f in fs:
            f["remediation"] = _finding_rem(f, by_id[f["component_id"]])
            f["commands"] = cmds
        # Version affichée : celle d'Unraid pour l'OS (pas celle du 1er sous-composant), aucune pour les groupes apt
        if c0.get("rem") == "unraid-os":
            aver = next((c.get("version") for c in comps if c["id"] == "nas:os"), None)
        elif c0.get("rem") in ("apt-homelab", "apt-docker"):
            aver = None
        else:
            aver = c0.get("version")
        actions.append({
            "id": k, "component_id": c0["id"] if c0.get("rem") not in ("apt-homelab", "unraid-os") else k,
            "component": comp_name, "host": c0["host"], "container": ctn[0] if len(ctn) == 1 else None,
            "containers": ctn, "version": aver,
            "target_version": target, "priority": prio, "max_score": max_score, "n_findings": len(fs),
            "n_critical": sum(1 for f in fs if f["priority"] == "critique"),
            "n_nofix": sum(1 for f in fs if f.get("nofix")),
            "kev": any(f["kev"] for f in fs), "exposure": expo, "exposure_detail": cexp["exposure_detail"],
            "title": title, "remediation": text, "commands": cmds, "ssh": _ssh_prefix(c0["host"]),
            "findings": [f["id"] for f in fs[:60]], "eol": [{k2: e[k2] for k2 in ("component", "status", "cycle", "eol_date", "latest", "days_past", "version")} for e in g["e"]],
            "components": [{"id": c["id"], "name": c["name"], "version": c.get("version")} for c in comps
                           if c["id"] in fcomp or c["id"] in ecomp][:40],
            "component_ids": sorted(c["id"] for c in comps if c["id"] in fcomp or c["id"] in ecomp),
            "kind": "exposition" if fs and all(f.get("kind") == "exposition" for f in fs) and not g["e"] else c0.get("rem"),
        })
    # Action de suivi des CVE Debian/Ubuntu sans correctif (agrégées, priorité basse)
    nd = sorted(nofix_deb.values(), key=lambda d: (not d["kev"], -(d["max_cvss"] or 0), -d["n"]))
    for host in sorted({d["host"] for d in nd}):
        hd = [d for d in nd if d["host"] == host]
        tot = sum(d["n"] for d in hd)
        actions.append({
            "id": f"{host}:sans-correctif", "component_id": f"{host}:sans-correctif",
            "component": "Paquets Debian sans correctif" if host == "homelab" else "Paquets Ubuntu sans correctif",
            "host": host, "container": None, "containers": [], "version": None, "target_version": None, "priority": "basse",
            "max_score": 0, "n_findings": tot, "n_critical": 0, "n_nofix": tot, "kev": any(d["kev"] for d in hd),
            "exposure": "local", "exposure_detail": "",
            "title": f"Surveiller {tot} CVE sans correctif {('Debian' if host == 'homelab' else 'Ubuntu')} ({len(hd)} paquets)",
            "remediation": ("Pas de correctif publié par la distribution, ou CVE jugées sans importance (urgence « unimportant ») : "
                            "aucune action immédiate. Laisser unattended-upgrades actif ; elles disparaîtront avec les mises à jour. "
                            "Paquets les plus concernés : " + ", ".join(f"{d['package']} ({d['n']})" for d in sorted(hd, key=lambda d: -d['n'])[:8]) + "."),
            "commands": [], "ssh": None, "findings": [], "eol": [], "components": [], "kind": "nofix-distro",
        })
    actions.sort(key=lambda a: (PRIOS.index(a["priority"]), -a["max_score"], -a["n_findings"]))
    for i, a in enumerate(actions):
        a["rank"] = i + 1

    # 9) Statistiques
    by_prio = {p: 0 for p in PRIOS}
    by_host = {h: {p: 0 for p in PRIOS} for h in HOST_LABEL}
    by_source = {}
    for f in findings:
        by_prio[f["priority"]] += 1
        by_host.setdefault(f["host"], {p: 0 for p in PRIOS})[f["priority"]] += 1
        s = f["source"].split(":")[0] + (":" + f["source"].split(":")[1] if f["source"].startswith("osv:") else "")
        by_source[s] = by_source.get(s, 0) + 1
    scanned = sum(1 for c in inv if (c.get("osv") or (c.get("gh") and c.get("version") not in (None, "inconnue")) or c.get("eol")))
    stats = {
        "by_priority": by_prio, "by_host": by_host, "by_source": by_source,
        "actions_by_priority": {p: sum(1 for a in actions if a["priority"] == p) for p in PRIOS},
        "total_components": len(inv), "scanned_components": scanned,
        "unknown_versions": sum(1 for c in inv if c.get("version") in (None, "inconnue")),
        "findings": len(findings), "kev": sum(1 for f in findings if f["kev"]),
        "nofix_distro": sum(d["n"] for d in nd), "dismissed": len(dismissed),
        "eol": sum(1 for e in eols if e["status"] == "fin de vie"), "outdated": sum(1 for e in eols if e["status"] == "en retard"),
        "duration_s": round(time.time() - t0, 1),
        # Sources sans données (échec sans cache, ex. démarrage à froid hors ligne) : résultat incomplet, pas « 0 vulnérabilité »
        "incomplete": [n for n, ok in (("osv", sources["osv"]["ok"]), ("kev", bool(kev))) if not ok],
    }
    stats["partial"] = bool(missing) or bool(stats["incomplete"])
    for f in findings:
        for k in [k for k in f if k.startswith("_")] + ["cap", "n_critical"]:
            f.pop(k, None)
    findings.sort(key=lambda f: (-f["score"], f["component_id"]))
    eols.sort(key=lambda e: (e["status"] != "fin de vie", -e["days_past"], e["component"]))
    return findings, actions, eols, nd, dismissed, stats


def _finding_rem(f, c):
    """Phrase de remédiation courte propre au constat."""
    if f.get("kind") == "exposition":
        return f["_risk"]["fix"]
    if f.get("nofix"):
        return "Pas de version corrigée publiée : réduire l'exposition (" + (c.get("exposure_detail") or c["exposure"]) + ")."
    if f.get("prerelease_only"):
        return f"Seul correctif référencé : pré-version {f['fixed']} d'une autre branche : vérifier son rétroportage dans la branche stable."
    if c.get("rem") == "kernel-homelab":
        if f.get("reboot_only"):
            return f"Corrigé dans {f['fixed']}, déjà installé : redémarrer le homelab."
        return f"Corrigé dans {f['fixed']} : apt full-upgrade puis redémarrer."
    if c.get("rem") == "apt-homelab":
        return f"Corrigé dans {f['fixed']} : sudo apt update && sudo apt full-upgrade."
    if c.get("rem") == "claw-apt":
        return f"Corrigé dans {f['fixed']} : sudo apt update && sudo apt upgrade sur clawhost."
    if c.get("rem") in ("unraid-os",):
        return f"Corrigé en amont dans {f['fixed']} : mettre à jour Unraid (Tools → Update OS)."
    return f"Corrigé dans {f['fixed']} : mettre à jour {c['name']}."


def _inv_public(inv):
    """Inventaire allégé pour l'interface : paquets Debian sans constat regroupés en une ligne."""
    out, deb_rest = [], []
    for c in inv:
        if c.get("rem") == "apt-homelab" and c["kind"] == "paquet-os" and not c.get("_has"):
            deb_rest.append(c)
            continue
        d = {k: c.get(k) for k in ("id", "name", "version", "host", "kind", "source", "container", "image", "exposure",
                                    "exposure_detail", "osv", "eol", "gh") if c.get(k) is not None or k in ("osv", "eol", "gh")}
        d["n_findings"] = c.get("_has", 0)
        if c.get("stale"):
            d["stale"] = True
        out.append(d)
    if deb_rest:
        out.append({"id": "homelab:deb:*", "name": f"{len(deb_rest)} autres paquets Debian (sans CVE corrigeable)",
                    "version": "—", "host": "homelab", "kind": "paquet-os", "source": "dpkg-query (paquets source)",
                    "exposure": "local", "exposure_detail": "", "osv": [["Debian:13", "*", f"{len(deb_rest)} paquets"]],
                    "eol": None, "gh": None, "n_findings": 0, "aggregate": len(deb_rest)})
    return out


def _publish(inv, findings, actions, eols, nd, dismissed, stats, sources, scan_t):
    """Construit l'état exposé (allégé) et le persiste (état léger + données complètes séparées)."""
    cnt = {}
    for f in findings:
        cnt[f["component_id"]] = cnt.get(f["component_id"], 0) + 1
    for c in inv:
        c["_has"] = cnt.get(c["id"], 0)
    per = {}
    slim = []
    for f in findings:   # déjà triés par score
        n = per.get(f["component_id"], 0)
        if n < STATE_MAX_PER_COMP:
            slim.append(f)
        per[f["component_id"]] = n + 1
    dis_reasons = {}
    for d in dismissed:
        dis_reasons[d["reason"]] = dis_reasons.get(d["reason"], 0) + 1
    st = {
        "generated_at": scan_t, "next_refresh": (_mem.get("scan_t") or scan_t) + SCAN_EVERY, "inventory_at": _mem.get("inv_t") or scan_t,
        "sources": sources, "inventory": _inv_public(inv), "findings": slim,
        "findings_truncated": {k: v - STATE_MAX_PER_COMP for k, v in per.items() if v > STATE_MAX_PER_COMP},
        "actions": actions, "eol": eols,
        "nofix_distro": {"total": sum(d["n"] for d in nd), "packages": nd[:60]},
        "dismissed": {"total": len(dismissed), "by_reason": dis_reasons, "sample": dismissed[:25]},
        "stats": stats,
    }
    STATE.set("slow", "vulns", st)
    _write_json(FINDINGS_FILE, findings)
    _save_persisted(inv)
    return st


def _write_json(path, data):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"), default=str)
        os.replace(tmp, path)
    except OSError:
        pass


def _save_persisted(inv):
    """État léger (lu par le serveur) + contexte de planification (inventaire, signature) pour le processus d'analyse."""
    _write_json(STATE_FILE, STATE.get("slow", "vulns") or {})
    _write_json(CTX_FILE, {"inv": [{k: v for k, v in c.items() if not k.startswith("_") and k != "bins"} for c in inv or []],
                           "inv_t": _mem.get("inv_t"), "scan_t": _mem.get("scan_t"), "sig": _mem.get("sig"),
                           "sources": _mem.get("sources") or {}, "npm": _mem.get("npm") or []})


def _load_state():
    """Recharge l'état léger publié (affichage immédiat au démarrage, puis après chaque analyse)."""
    try:
        with open(STATE_FILE) as f:
            st = json.load(f)
    except (OSError, ValueError):
        return None
    if isinstance(st, dict) and "state" in st and "actions" not in st:   # ancien format
        st = st["state"]
    if st:
        STATE.set("slow", "vulns", st)
    return st


def _load_ctx():
    try:
        with open(CTX_FILE) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return
    _mem.update({"inv": d.get("inv"), "inv_t": d.get("inv_t") or 0, "scan_t": d.get("scan_t") or 0, "sig": d.get("sig"),
                 "sources": d.get("sources") or {}, "npm": d.get("npm") or []})


def _scan(force):
    """Travail effectif (processus d'analyse) : inventaire si dû, analyse si due ou si l'inventaire a changé."""
    _load_ctx()
    now = time.time()
    due_inv = force or _mem.get("inv") is None or now - (_mem.get("inv_t") or 0) >= INV_EVERY
    due_scan = force or now - (_mem.get("scan_t") or 0) >= SCAN_EVERY
    if not (due_inv or due_scan):
        return
    sources = dict(_mem.get("sources") or {})
    inv = _mem.get("inv")
    if due_inv:
        inv = collect_inventory(sources)
        _mem["inv"], _mem["inv_t"] = inv, now
        sig = _signature(inv)
        if sig != _mem.get("sig"):
            due_scan = True
        _mem["sig"] = sig
    _mem["sources"] = sources
    if not due_scan:
        st = _load_state()
        if st:
            STATE.set("slow", "vulns", dict(st, sources=sources, inventory_at=_mem["inv_t"]))
        _save_persisted(inv)
        return
    findings, actions, eols, nd, dismissed, stats = _analyze(inv, sources)
    # Analyse incomplète (détails OSV manquants, OSV/KEV injoignables sans cache) : nouvelle tentative dans ~15 min au lieu de 12 h
    done = time.time()
    _mem["scan_t"] = done - (SCAN_EVERY - 900 if stats.get("partial") else 0)
    _mem["sources"] = sources
    _publish(inv, findings, actions, eols, nd, dismissed, stats, sources, done)
    OSV_CACHE.save()
    HTTP_CACHE.save(max_age=7 * DAY)


def _child(force):
    """Point d'entrée du processus d'analyse (mémoire isolée du serveur)."""
    import fcntl
    lock = open(os.path.join(DATA_DIR, "vuln-scan.lock"), "a+")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.stderr.write("@@erreur une analyse précédente est encore en cours (processus orphelin)\n")
        sys.exit(2)
    try:
        _scan(force)
    except Exception as e:  # noqa
        import traceback
        traceback.print_exc()
        sys.stderr.write(f"@@erreur {type(e).__name__}: {e}\n")
        sys.exit(2)


def _due():
    """Le serveur ne lance le processus d'analyse que si un inventaire ou une analyse est dû."""
    try:
        with open(CTX_FILE) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return True
    now = time.time()
    return now - (d.get("inv_t") or 0) >= INV_EVERY or now - (d.get("scan_t") or 0) >= SCAN_EVERY


def scan(force=False):
    """Inventaire (toutes les heures) puis analyse (toutes les 12 h, ou si l'inventaire a changé). force=True : tout.
    Le travail s'exécute dans un processus Python séparé (~60 Mo pendant l'analyse, rendus ensuite au système) ;
    une seule exécution à la fois : un appel concurrent renvoie l'état courant. Renvoie l'état publié."""
    if not force and not _due():
        return STATE.get("slow", "vulns")
    if not _scan_lock.acquire(blocking=False):
        return STATE.get("slow", "vulns")
    try:
        return _run_child(force)[0]
    finally:
        _scan_lock.release()


def _run_child(force):
    """Lance le processus d'analyse (verrou _scan_lock déjà pris) ; renvoie (état publié, erreur ou None)."""
    prev = STATE.get("slow", "vulns") or {}
    code = ("import sys; sys.path.insert(0, %r); from infradash import vulns; vulns._child(%r)"
            % (os.path.dirname(os.path.dirname(os.path.abspath(__file__))), bool(force)))
    err = None
    try:
        p = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=CHILD_TIMEOUT,
                           stdin=subprocess.DEVNULL)
        if p.returncode != 0:
            m = re.search(r"@@erreur (.+)", p.stderr or "")
            err = m.group(1) if m else (p.stderr or "").strip()[-300:] or f"code {p.returncode}"
    except subprocess.TimeoutExpired:
        err = f"analyse interrompue après {CHILD_TIMEOUT} s"
    st = _load_state() or prev
    if err:
        src = dict(st.get("sources") or {})
        _src(src, "analyse", False, None, err)
        st = dict(st, sources=src)
        STATE.set("slow", "vulns", st)
    _notify(prev, st)
    return st, err


# --- Revérification à la demande (après une correction) ------------------------------------------
REFRESH_FILE = os.path.join(DATA_DIR, "vuln-refresh.json")
REFRESH_GAP = 60            # délai minimal entre deux revérifications manuelles (s) : OSV/GitHub ménagés
REFRESH_MAX_H = 12          # revérifications manuelles par heure au plus
REFRESH_WAIT = CHILD_TIMEOUT + 60   # attente max d'une analyse automatique déjà en cours
_refresh = {"status": "jamais"}
_refresh_hist = []          # instants des revérifications acceptées (dernière heure)
_refresh_mx = threading.Lock()
HOST_DU = {"homelab": "du homelab", "nas": "du NAS", "clawhost": "de clawhost"}


def _publish_refresh(**kw):
    with _refresh_mx:
        _refresh.update(kw)
        snap = json.loads(json.dumps(_refresh, default=str))
    STATE.set("derived", "vulns_refresh", snap)
    return snap


def refresh_status():
    with _refresh_mx:
        return json.loads(json.dumps(_refresh, default=str))


def _aview(a):
    return {"id": a["id"], "title": a.get("title") or a.get("component") or a["id"], "host": a.get("host"),
            "priority": a.get("priority"), "n": a.get("n_findings") or 0, "version": a.get("version"),
            "target": a.get("target_version"), "score": a.get("max_score") or 0, "component": a.get("component"),
            "kind": a.get("kind"), "exposure": a.get("exposure"), "exposure_detail": a.get("exposure_detail"),
            "nc": len(a.get("component_ids") or a.get("containers") or [])}


_CMP = ("n", "version", "priority", "score", "exposure", "nc")
_BEFORE = _CMP + ("title", "target")


def _pi(p):
    return PRIOS.index(p) if p in PRIOS else len(PRIOS)


def _trend(o, n):
    """> 0 : mieux (moins de CVE, moins de composants concernés, priorité plus basse, score plus bas)."""
    return (o["n"] - n["n"]) or (o["nc"] - n["nc"]) or (_pi(n["priority"]) - _pi(o["priority"])) or (o["score"] - n["score"])


def _doubt(st, a):
    """Raison de douter de la disparition d'une action (ou de la relecture de ses composants) ; None si tout a été relu."""
    if (st.get("stats") or {}).get("partial"):
        return "l'analyse est incomplète (une source de vulnérabilités était injoignable)"
    host = a.get("host")
    if ((st.get("sources") or {}).get(f"inventaire:{host}") or {}).get("ok") is False:
        return f"l'inventaire {HOST_DU.get(host, host)} n'a pas pu être relu"
    cids = set(a.get("component_ids") or [])
    stale = cids & {c["id"] for c in st.get("inventory") or [] if c.get("stale")}
    if not stale:
        return None
    if all(c.startswith("homelab:ct:") for c in stale):
        return "les conteneurs du homelab n'ont pas pu être relus (cAdvisor injoignable)"
    if all(c.startswith("nas:ct:") or c == "nas:docker" for c in stale):
        return "les conteneurs du NAS n'ont pas pu être listés (service Docker arrêté ?)"
    if all(c.startswith("clawhost:ct:") for c in stale):
        return "la liste des conteneurs de clawhost (sauvegarde nocturne) n'a pas pu être relue"
    if "clawhost:openclaw" in stale:
        return "le gateway OpenClaw n'a pas répondu à la sonde"
    return f"certains composants {HOST_DU.get(host, host)} n'ont pas pu être relus"


def _successor(a, new):
    """Action qui reprend les composants d'une action disparue dont l'identifiant porte une version
    (ex. nas:postgresql:16.13 -> nas:postgresql:16.14 encore en retard). Jamais une action d'exposition."""
    if a.get("kind") == "exposition":
        return None
    cids = set(a.get("component_ids") or [])
    return next((x for x in new.values() if x["id"] != a["id"] and x.get("kind") == a.get("kind") and x.get("kind") != "exposition"
                 and x.get("host") == a.get("host") and cids & set(x.get("component_ids") or [])), None)


def _moved_up(a, b):
    """Les composants communs ont-ils monté de version ?"""
    ov = {c["id"]: c.get("version") for c in a.get("components") or []}
    nv = {c["id"]: c.get("version") for c in b.get("components") or []}
    ok = lambda v: v not in (None, "inconnue", "")
    return any(ok(ov[i]) and ok(nv.get(i)) and vcmp(str(nv[i]), str(ov[i])) > 0 for i in ov if i in nv)


def _diff(prev, st, focus):
    """Bilan avant / après : actions résolues, améliorées, aggravées, nouvelles, à confirmer ; verdict sur l'action ciblée."""
    old = {a["id"]: a for a in prev.get("actions") or []}
    new = {a["id"]: a for a in st.get("actions") or []}
    resolved, uncertain, improved, worse, added = [], [], [], [], []
    moved, succ = {}, set()
    owner = {c: x["id"] for x in old.values() if x.get("kind") != "exposition" for c in x.get("component_ids") or []}
    for k, a in old.items():
        if k in new:
            continue
        v = _aview(a)
        b = _successor(a, new)
        if b:   # identifiant lié à la version : l'action continue sous un autre identifiant
            succ.add(b["id"])
            up = _moved_up(a, b)
            nb = _aview(b)
            moved[k] = dict(nb, before={x: v[x] for x in _BEFORE}, moved_from=k, up=up)
            if up:
                improved.append(moved[k])
            continue
        why = _doubt(st, a)
        if why:
            uncertain.append(dict(v, why=why))
        else:
            resolved.append(v)
    for k, a in new.items():
        if k in old:
            o, n = _aview(old[k]), _aview(a)
            if tuple(o[x] for x in _CMP) == tuple(n[x] for x in _CMP):
                continue
            n["before"] = {x: o[x] for x in _BEFORE}
            t = _trend(o, n)
            gained = set(a.get("component_ids") or []) - set(old[k].get("component_ids") or [])
            moved_in = bool(gained) and all(owner.get(c) not in (None, k) for c in gained)   # composants venus d'une autre action
            if t > 0:
                improved.append(n)
            elif t < 0 and k not in succ and not moved_in:   # regroupement de composants, pas aggravation
                worse.append(n)
            # sinon : seule la version a changé, même risque (ex. Redis mis à jour mais toujours sans mot de passe)
        elif k not in succ:
            added.append(_aview(a))
    key = lambda v: (_pi(v["priority"]), -v["score"])
    out = {"resolved": sorted(resolved, key=key), "uncertain": sorted(uncertain, key=key), "improved": sorted(improved, key=key),
           "worse": sorted(worse, key=key), "added": sorted(added, key=key),
           "before": len(old), "after": len(new), "partial": bool((st.get("stats") or {}).get("partial"))}
    if focus and focus in old:
        o, n = old[focus], new.get(focus)
        ov = _aview(o)
        if n is None and focus in moved:
            m = moved[focus]
            v = dict(m, verdict="ameliore" if m["up"] else "toujours", moved_to=m["id"], id=focus, reread=_doubt(st, new[m["id"]]) is None)
        elif n is None:
            u = next((x for x in uncertain if x["id"] == focus), None)
            v = dict(ov, verdict="incertain", why=u["why"]) if u else dict(ov, verdict="corrige")
        else:
            nv = _aview(n)
            t = _trend(ov, nv) if tuple(ov[x] for x in _CMP) != tuple(nv[x] for x in _CMP) else 0
            cids = set(n.get("component_ids") or [])
            snap = bool(cids) and all(c.startswith("clawhost:ct:") for c in cids)   # lus dans la sauvegarde nocturne
            v = dict(nv, verdict="ameliore" if t > 0 else "aggrave" if t < 0 else "toujours",
                     before={x: ov[x] for x in _BEFORE}, reread=_doubt(st, n) is None and not snap, snapshot=snap)
        out["focus"] = v
    return out


def _refresh_worker(focus):
    t0 = time.time()
    try:
        prev = STATE.get("slow", "vulns") or {}
        got = _scan_lock.acquire(blocking=False)
        if not got:
            _publish_refresh(phase="attente")            # une analyse automatique tourne : on attend sa fin, puis on relance tout
            got = _scan_lock.acquire(timeout=REFRESH_WAIT)
        if not got:
            st, err = prev, "une analyse automatique est toujours en cours, réessayez dans quelques minutes"
        else:
            try:
                _publish_refresh(phase="analyse", analysis_started=time.time())
                st, err = _run_child(True)
            except Exception as e:  # noqa
                st, err = STATE.get("slow", "vulns") or prev, f"{type(e).__name__}: {e}"
            finally:
                _scan_lock.release()
        fresh = (st.get("generated_at") or 0) > (prev.get("generated_at") or 0)
        if not err and not fresh:
            err = "l'analyse n'a pas produit de nouveau résultat"
        d = _diff(prev, st, focus) if fresh else None
        changes = {k: len(d[k]) for k in ("resolved", "improved", "uncertain", "worse", "added")} if d else {}
        extra = {"last_change_t": time.time()} if any(changes[k] for k in ("resolved", "improved", "worse", "added") if k in changes) else {}
        snap = _publish_refresh(status="erreur" if err else "ok", phase=None, finished=time.time(),
                                duration_s=round(time.time() - t0, 1), error=err, diff=d, generated_at=st.get("generated_at"), **extra)
        _write_json(REFRESH_FILE, snap)
        if d and any(changes.values()):
            lbl = {"resolved": "résolue(s)", "improved": "améliorée(s)", "uncertain": "à confirmer", "worse": "aggravée(s)",
                   "added": "nouvelle(s)"}
            hosts = {x["host"] for k in changes for x in d[k]}
            STATE.event("ok" if changes["resolved"] or changes["improved"] else "info", hosts.pop() if len(hosts) == 1 else "homelab",
                        "Vulnérabilités revérifiées", ", ".join(f"{n} {lbl[k]}" for k, n in changes.items() if n), "securite")
        if d:
            from . import runner
            runner.kick("derived.slow", "forecast", "scores", "alerts")   # vues dérivées rafraîchies sans attendre leur cycle
    except Exception as e:  # noqa
        snap = _publish_refresh(status="erreur", phase=None, finished=time.time(), duration_s=round(time.time() - t0, 1),
                                error=f"{type(e).__name__}: {e}", diff=None)
        _write_json(REFRESH_FILE, snap)


def request_refresh(focus=None):
    """Revérification manuelle : inventaire des 3 machines + analyse complète, dans un fil à part. Une à la fois,
    REFRESH_GAP s entre deux et REFRESH_MAX_H par heure. focus = identifiant d'une action du plan (verdict dédié)."""
    st = STATE.get("slow", "vulns") or {}
    ids = {a["id"] for a in st.get("actions") or []}
    focus = focus if isinstance(focus, str) and focus else None
    now = time.time()
    with _refresh_mx:
        cur = json.loads(json.dumps(_refresh, default=str))
        if cur.get("status") == "en_cours" and now - (cur.get("started") or 0) < REFRESH_WAIT + CHILD_TIMEOUT + 60:
            return dict(cur, accepted=False, message="Revérification déjà en cours.")
        retry = (cur.get("finished") or 0) + REFRESH_GAP
        if now < retry:
            return dict(cur, accepted=False, retry_at=retry, message=f"Nouvelle revérification possible dans {int(retry - now) + 1} s.")
        _refresh_hist[:] = [t for t in _refresh_hist if now - t < 3600]
        if len(_refresh_hist) >= REFRESH_MAX_H:
            retry = _refresh_hist[0] + 3600
            return dict(cur, accepted=False, retry_at=retry, message=f"Limite de {REFRESH_MAX_H} revérifications par heure atteinte : "
                                                                      f"prochaine possible dans {int((retry - now) / 60) + 1} min.")
        if focus and focus not in ids:
            when = time.strftime("%H:%M", time.localtime(st.get("generated_at") or now))
            return dict(cur, accepted=False, message=f"Cette action n'est déjà plus dans le plan : l'analyse de {when} "
                                                      "a pris la correction en compte.")
        last = cur.get("duration_s") or ((st.get("stats") or {}).get("duration_s") or 60) + 30
        keep = {k: cur[k] for k in ("last_change_t",) if k in cur}
        _refresh.clear()
        _refresh.update(keep, status="en_cours", phase="analyse", started=now, focus=focus, trigger="manuel", expected_s=last)
        _refresh_hist.append(now)
    snap = _publish_refresh()
    _write_json(REFRESH_FILE, snap)   # un redémarrage pendant la revérification sera signalé au rechargement
    try:
        threading.Thread(target=_refresh_worker, args=(focus,), daemon=True, name="vulns-refresh").start()
    except RuntimeError as e:
        snap = _publish_refresh(status="erreur", phase=None, finished=time.time(), error=str(e))
        return dict(snap, accepted=False, message=f"Revérification impossible : {e}")
    return dict(snap, accepted=True, message="Revérification lancée : inventaire des 3 machines puis analyse complète.")


def _load_refresh():
    try:
        with open(REFRESH_FILE) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return
    if isinstance(d, dict) and d.get("status"):
        if d["status"] == "en_cours":   # serveur arrêté pendant une revérification
            d.update(status="erreur", phase=None, finished=d.get("started") or time.time(), diff=None,
                     error="revérification interrompue par un redémarrage du serveur")
        with _refresh_mx:
            _refresh.clear()
            _refresh.update(d)
        STATE.set("derived", "vulns_refresh", d)


def _notify(prev, st):
    """Événement au journal quand de nouvelles actions critiques apparaissent."""
    if not prev or not st or st.get("generated_at") == prev.get("generated_at"):
        return
    old = {a["id"] for a in prev.get("actions") or [] if a["priority"] == "critique"}
    new = [a for a in st.get("actions") or [] if a["priority"] == "critique" and a["id"] not in old]
    for a in new[:3]:
        STATE.event("crit", a["host"], f"Vulnérabilité critique : {a['title']}", a.get("exposure_detail") or "", "securite")


def run():
    """Point d'entrée du runner (toutes les 10 min) : ne travaille que si c'est dû, ne lève jamais d'exception."""
    try:
        scan()
    except Exception as e:  # noqa
        st = STATE.get("slow", "vulns") or {}
        src = dict(st.get("sources") or {})
        _src(src, "analyse", False, None, f"{type(e).__name__}: {e}")
        STATE.set("slow", "vulns", dict(st, sources=src))


def findings_for(component_id=None, action_id=None):
    """Liste complète (non tronquée) des constats d'un composant ou d'une action du plan (lue sur disque)."""
    try:
        with open(FINDINGS_FILE) as f:
            fs = json.load(f)
    except (OSError, ValueError):
        fs = []
    if action_id:
        st = STATE.get("slow", "vulns") or {}
        a = next((x for x in st.get("actions") or [] if x["id"] == action_id), None)
        ids = set((a or {}).get("component_ids") or [])
        return [f for f in fs if f["component_id"] in ids]
    if component_id:
        return [f for f in fs if f["component_id"] == component_id]
    return fs


_load_state()
_load_refresh()
