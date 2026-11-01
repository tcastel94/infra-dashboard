"""Exécution sûre des commandes du plan de correction (vulnérabilités), depuis l'interface.

Principes (aucun ne dépend du navigateur) :
1. Le navigateur n'envoie JAMAIS de commande : seulement l'identifiant d'une action du plan et un numéro de commande. Le serveur
   relit la commande qu'il a lui-même générée (STATE slow.vulns).
2. La commande est analysée par une grammaire stricte, jeton par jeton (pas de shell pour l'interpréter) : cd dans un dossier
   autorisé, docker compose pull / build --pull / up -d / stop / logs, docker pull, docker rm -f d'un conteneur connu, sed -i.bak -E
   avec une substitution s#…#…# sans drapeau dangereux, tar vers /mnt/user/backups, sleep. Tout le reste est refusé avec la raison.
3. Chaque étape est reconstruite à partir des jetons validés et citée avec shlex.quote : aucune injection possible.
4. Deux temps : « plan » (vérifications préalables en lecture seule : dossiers, services du compose, espace disque, images actuelles
   conservées pour revenir en arrière) puis « exécution », qui exige l'empreinte du plan affiché ET la phrase secrète.
5. Désactivé tant que ~/.config/infradash/exec.json n'existe pas (tools/exec-setup.py) ; phrase secrète hachée (scrypt), verrouillage
   15 min après 5 échecs ; une exécution à la fois, 6 par heure ; arrêt à la première erreur ; sauvegarde .bak / tar avant toute
   modification de fichier ; journal d'audit data/remedy-audit.jsonl + journal de l'interface ; sortie tronquée et expurgée.
Seul le NAS (SSH root par clé) et le homelab (sudo sans mot de passe, s'il est configuré) peuvent exécuter ; clawhost reste en lecture seule.
"""
import hashlib
import hmac
import json
import os
import re
import shlex
import subprocess
import threading
import time
import uuid

from .config import DATA_DIR, HOSTS
from .state import STATE
from .util import redact

CFG_FILE = os.environ.get("INFRADASH_EXEC_FILE", os.path.expanduser("~/.config/infradash/exec.json"))
AUDIT_FILE = os.path.join(DATA_DIR, "remedy-audit.jsonl")
PLAN_TTL = 600
MAX_RUNS_H = 6
LOCK_AFTER, LOCK_S = 5, 900
BACKUP_DIR = "/mnt/user/backups"
ROOTS = {"nas": ("/mnt/user/appdata/", "/mnt/cache/appdata/"), "homelab": ("/opt/homelab",)}
TIMEOUTS = {"pull": 1200, "build": 2400, "up": 600, "stop": 300, "logs": 30, "dpull": 1200, "rm": 60, "sed": 30, "tar": 1800, "sleep": 130, "cd": 5}
_DB_IMG = re.compile(r"postgres|mysql|mariadb|mongo|timescale|pgvector|influx", re.I)

SVC = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
IMG = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,200}(:[A-Za-z0-9._-]{1,128})?(@sha256:[0-9a-f]{64})?$")
ABS = re.compile(r"^/[A-Za-z0-9_./-]{1,200}$")
REL = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}$")
SED = re.compile(r"^s#([A-Za-z0-9 .:_/@^$()\[\]|\\*+?\"=-]*)#([A-Za-z0-9 .:_/@^$()\[\]|\\*+?\"=-]*)#I?$")

_mx = threading.Lock()
_run_lock = threading.Lock()
_PLANS = {}
_HIST = []
_FAIL = {"n": 0, "until": 0}
_RUN = {}
_PLAN_T = [0]


# --------------------------------------------------------------------------------------------- configuration et secret
def config():
    """(cfg, erreur) — cfg = {salt, hash, hosts}. Absent ou illisible : exécution désactivée."""
    try:
        st = os.stat(CFG_FILE)
        with open(CFG_FILE) as f:
            d = json.load(f)
    except FileNotFoundError:
        return None, "non configurée"
    except (OSError, ValueError) as e:
        return None, f"fichier illisible ({type(e).__name__})"
    if st.st_mode & 0o077:
        return None, "droits trop larges sur le fichier de configuration (chmod 600 requis)"
    if not d.get("enabled") or not d.get("salt") or not d.get("hash"):
        return None, "désactivée dans le fichier de configuration"
    return d, None


def hash_pin(pin, salt):
    return hashlib.scrypt(pin.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32).hex()


def _check_pin(pin):
    cfg, err = config()
    if not cfg:
        return False, f"Exécution désactivée : {err}."
    now = time.time()
    with _mx:
        if _FAIL["until"] > now:
            return False, f"Trop d'échecs : exécution verrouillée encore {int((_FAIL['until'] - now) / 60) + 1} min."
    ok = isinstance(pin, str) and 0 < len(pin) <= 200 and hmac.compare_digest(hash_pin(pin, bytes.fromhex(cfg["salt"])), cfg["hash"])
    with _mx:
        if ok:
            _FAIL["n"] = 0
            return True, ""
        _FAIL["n"] += 1
        if _FAIL["n"] >= LOCK_AFTER:
            _FAIL.update(n=0, until=now + LOCK_S)
            STATE.event("crit", "dashboard", "Exécution des corrections verrouillée 15 min", f"{LOCK_AFTER} phrases secrètes erronées", "remedy")
    time.sleep(1.0)
    return False, "Phrase secrète incorrecte."


_SUDO = [0, False]


def sudo_ok():
    """sudo sans mot de passe disponible pour le compte du dashboard ? (résultat gardé 60 s)"""
    if time.time() - _SUDO[0] > 60:
        try:
            _SUDO[1] = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5).returncode == 0
        except (subprocess.SubprocessError, OSError):
            _SUDO[1] = False
        _SUDO[0] = time.time()
    return _SUDO[1]


def caps():
    cfg, err = config()
    hosts = {"nas": True, "homelab": sudo_ok(), "clawhost": False}
    return {"enabled": bool(cfg), "reason": err, "hosts": hosts, "locked_until": _FAIL["until"] if _FAIL["until"] > time.time() else None,
            "setup": "python3 ~/infra-dashboard/tools/exec-setup.py", "max_per_hour": MAX_RUNS_H,
            "why_host": {"homelab": None if hosts["homelab"] else "sudo demande un mot de passe : les commandes du homelab restent à copier",
                         "clawhost": "accès SSH restreint à la lecture seule (par conception)"}}


# --------------------------------------------------------------------------------------------- analyse de la grammaire
class Refused(Exception):
    pass


def _tokens(cmd):
    cmd = cmd.replace("$(date +%F)", "__DATE__").replace("\n", " ")
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|<>()")
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError as e:
        raise Refused(f"commande mal formée ({e})")


def _under(path, roots):
    return any(path == r.rstrip("/") or path.startswith(r if r.endswith("/") else r + "/") for r in roots)


def _check_abs(p, what):
    if not ABS.match(p) or ".." in p.split("/"):
        raise Refused(f"{what} invalide : {p[:60]}")
    return p


def _split(toks):
    """Découpe en commandes sur && et ; (seuls séparateurs admis)."""
    out, cur = [], []
    for t in toks:
        if t in ("&&", ";", "&", ";;"):
            if t in ("&", ";;") or not cur:
                raise Refused("séparateur non autorisé")
            out.append(cur)
            cur = []
        elif re.fullmatch(r"[;&|<>()]+", t):
            raise Refused(f"opérateur shell « {t} » non autorisé")
        else:
            cur.append(t)
    if cur:
        out.append(cur)
    return out


def parse(host, cmd, today=None):
    """Chaîne du plan -> liste d'étapes validées {kind, argv, cwd, sudo, text} ; Refused sinon."""
    today = today or time.strftime("%F")
    steps, cwd = [], None
    roots = ROOTS.get(host)
    if not roots:
        raise Refused("exécution impossible sur cette machine (accès en lecture seule)")
    for argv in _split(_tokens(cmd)):
        argv = [a.replace("__DATE__", today) for a in argv]
        sudo = False
        if argv[0] == "sudo":
            if host != "homelab":
                raise Refused("sudo hors du homelab")
            sudo, argv = True, argv[1:]
        elif host == "homelab" and argv[0] in ("docker",):
            raise Refused("sur le homelab, docker doit être lancé avec sudo (le plan l'indique)")
        if not argv:
            raise Refused("commande vide")
        head = argv[0]
        if head == "cd" and len(argv) == 2:
            cwd = _check_abs(argv[1], "dossier")
            if not _under(cwd, roots):
                raise Refused(f"dossier hors des zones autorisées : {cwd}")
            steps.append({"kind": "cd", "argv": ["cd", cwd], "cwd": cwd, "sudo": False, "text": f"Aller dans {cwd}"})
            continue
        if head == "sleep" and len(argv) == 2 and argv[1].isdigit() and int(argv[1]) <= 120:
            steps.append({"kind": "sleep", "argv": argv, "cwd": None, "sudo": False, "text": f"Attendre {argv[1]} s"})
            continue
        if head == "docker" and len(argv) >= 2 and argv[1] == "compose":
            if host == "homelab" and not sudo:
                raise Refused("docker sans sudo sur le homelab")
            if not cwd:
                raise Refused("docker compose sans dossier de projet (cd manquant)")
            sub, rest = argv[2] if len(argv) > 2 else "", argv[3:]
            if sub == "pull":
                kind, label, flags = "pull", "Télécharger la nouvelle image", []
            elif sub == "build" and rest[:1] == ["--pull"]:
                kind, label, flags, rest = "build", "Reconstruire l'image (base mise à jour)", ["--pull"], rest[1:]
            elif sub == "up" and rest[:1] == ["-d"]:
                kind, label, flags, rest = "up", "Recréer et redémarrer", ["-d"], rest[1:]
            elif sub == "stop":
                kind, label, flags = "stop", "Arrêter", []
            elif sub == "logs" and rest[:1] == ["--tail"] and len(rest) >= 2 and rest[1].isdigit() and int(rest[1]) <= 200:
                kind, label, flags, rest = "logs", "Lire les derniers journaux de", ["--tail", rest[1]], rest[2:]
            else:
                raise Refused(f"sous-commande docker compose non autorisée : {' '.join(argv[2:5])[:50]}")
            for s in rest:
                if not SVC.match(s):
                    raise Refused(f"nom de service invalide : {s[:40]}")
            steps.append({"kind": kind, "argv": ["docker", "compose", sub] + flags + rest, "cwd": cwd, "sudo": sudo, "services": rest,
                          "text": f"{label} {', '.join(rest) if rest else 'tous les services du projet'}"})
            continue
        if head == "docker" and len(argv) == 3 and argv[1] == "pull" and IMG.match(argv[2]):
            steps.append({"kind": "dpull", "argv": argv, "cwd": None, "sudo": sudo, "text": f"Télécharger l'image {argv[2]}"})
            continue
        if head == "docker" and len(argv) >= 4 and argv[1:3] == ["rm", "-f"]:
            names = argv[3:]
            if not all(SVC.match(n) for n in names) or not all(_known_container(host, n) for n in names):
                raise Refused("docker rm -f : conteneur inconnu du dashboard")
            steps.append({"kind": "rm", "argv": argv, "cwd": None, "sudo": sudo, "text": f"Supprimer le conteneur {', '.join(names)} (recréé juste après)"})
            continue
        if head == "sed" and len(argv) >= 5 and argv[1:3] == ["-i.bak", "-E"]:
            rest, exprs = argv[3:], []
            while len(rest) >= 2 and rest[0] == "-e":
                exprs.append(rest[1])
                rest = rest[2:]
            if not exprs and rest:
                exprs, rest = [rest[0]], rest[1:]
            files = rest
            if not exprs or not files:
                raise Refused("sed : expression ou fichier manquant")
            for x in exprs:
                if not SED.match(x) or "'" in x or "$(" in x or "${" in x:
                    raise Refused("sed : seule une substitution s#…#…# (sans drapeau autre que I) est autorisée")
                if _DB_IMG.search(x):
                    raise Refused("changement de version d'une base de données : sauvegarde logique (dump) et restauration à faire à la main")
            for fl in files:
                if not REL.match(fl) or ".." in fl.split("/"):
                    raise Refused(f"fichier invalide : {fl[:50]}")
            if not cwd:
                raise Refused("sed sans dossier de projet")
            steps.append({"kind": "sed", "argv": ["sed", "-i.bak", "-E"] + [y for x in exprs for y in ("-e", x)] + files, "cwd": cwd, "sudo": False,
                          "files": files, "text": f"Modifier {', '.join(files)} (copie .bak conservée) : {' ; '.join(exprs)[:160]}"})
            continue
        if head == "tar" and len(argv) >= 6 and argv[1] == "-czf" and argv[3] == "-C":
            if host != "nas":
                raise Refused("sauvegarde tar prévue pour le NAS")
            dest, base, names = argv[2], argv[4], argv[5:]
            if not re.fullmatch(re.escape(BACKUP_DIR) + r"/[A-Za-z0-9._-]{1,150}\.tar\.gz", dest):
                raise Refused(f"destination de sauvegarde hors de {BACKUP_DIR}")
            if base != "/":
                _check_abs(base, "dossier")
            for n in names:
                if not REL.match(n) or ".." in n.split("/"):
                    raise Refused(f"chemin invalide : {n[:50]}")
                full = os.path.normpath(os.path.join(base, n))
                if not full.startswith("/mnt/"):
                    raise Refused(f"sauvegarde hors de /mnt : {full}")
            steps.append({"kind": "tar", "argv": argv, "cwd": None, "sudo": False, "dest": dest, "src": [os.path.normpath(os.path.join(base, n)) for n in names],
                          "text": f"Sauvegarder {', '.join(names)} dans {dest}"})
            continue
        raise Refused(f"commande non autorisée : {' '.join(argv)[:70]}")
    if not steps:
        raise Refused("commande vide")
    return steps


def _known_container(host, name):
    key = "nas_containers" if host == "nas" else "homelab_containers"
    return any(c.get("name") == name for c in STATE.get("live", key) or [])


# --------------------------------------------------------------------------------------------- catalogue
def _commands(a):
    ssh = a.get("ssh")
    return [(i, c) for i, c in enumerate(a.get("commands") or []) if c != ssh and not str(c).startswith("ssh ")]


def _host_reason(host):
    if host == "clawhost":
        return "accès SSH de clawhost en lecture seule : à copier et lancer vous-même"
    if host == "homelab" and not sudo_ok():
        return "sudo sans mot de passe non configuré sur le homelab : à copier et lancer vous-même"
    return None


def catalog():
    """Par action du plan : chaque commande, exécutable ou non (avec la raison), et ses étapes lisibles."""
    v = STATE.get("slow", "vulns") or {}
    out = {}
    for a in v.get("actions") or []:
        items = []
        for i, c in _commands(a):
            try:
                reason, steps = _host_reason(a["host"]), None
                if reason is None:
                    steps = parse(a["host"], c)
                items.append({"index": i, "executable": steps is not None, "reason": reason, "steps": [s["text"] for s in steps or []]})
            except Refused as e:
                items.append({"index": i, "executable": False, "reason": str(e), "steps": []})
        if items:
            out[a["id"]] = items
    return {"caps": caps(), "actions": out, "t": time.time(), "vulns_t": v.get("generated_at")}


# --------------------------------------------------------------------------------------------- exécution d'une étape
def _clean_out(s):
    s = redact(s or "")
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    s = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", s)
    s = "\n".join(l for l in s.splitlines() if not l.startswith(("mux_client_", "ControlSocket ")))   # bruits du multiplexage SSH
    return s[-3000:]


def _remote(step, cwd_override=None):
    parts = []
    cwd = step.get("cwd") or cwd_override
    if cwd:
        parts.append("cd " + shlex.quote(cwd))
    parts.append(shlex.join(step["argv"]))
    return "{ " + " && ".join(parts) + "; } 2>&1"


def _exec(host, step, timeout=None):
    """(rc, sortie) — NAS : SSH (jetons cités), homelab : sous-processus direct sans shell."""
    timeout = timeout or TIMEOUTS.get(step["kind"], 120)
    t0 = time.time()
    try:
        if step["kind"] == "sleep":
            time.sleep(int(step["argv"][1]))
            return 0, ""
        if host == "nas":
            from . import nas
            p = subprocess.run(nas.SSHC._base(timeout) + [_remote(step)], capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
            return p.returncode, _clean_out(p.stdout + p.stderr)
        argv = (["sudo", "-n"] if step.get("sudo") else []) + step["argv"]
        p = subprocess.run(argv, cwd=step.get("cwd"), capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, _clean_out(p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return 124, f"délai de {timeout // 60} min dépassé après {int(time.time() - t0)} s (la commande peut encore tourner sur la machine : vérifiez avec docker ps)"
    except (OSError, subprocess.SubprocessError) as e:
        return 255, f"{type(e).__name__}: {e}"[:300]


def _ro(host, cmd, timeout=25):
    """Vérification préalable en lecture seule (commande fixe construite ici avec des jetons validés)."""
    return _exec(host, {"kind": "check", "argv": ["sh", "-c", cmd], "cwd": None, "sudo": False}, timeout) if host != "nas" else _exec_ro_nas(cmd, timeout)


def _exec_ro_nas(cmd, timeout):
    from . import nas
    try:
        p = subprocess.run(nas.SSHC._base(timeout) + ["{ " + cmd + "; } 2>&1"], capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, _clean_out(p.stdout)
    except (subprocess.SubprocessError, OSError) as e:
        return 255, f"{type(e).__name__}"


def preflight(host, steps):
    """Contrôles en lecture seule avant d'autoriser l'exécution : renvoie (checks, ok, avertissements, état actuel des images)."""
    checks, warns, before = [], [], []

    def add(ok, text, level=None):
        checks.append({"ok": ok, "text": text, "level": level or ("ok" if ok else "crit")})
    if host == "nas":
        rc, _ = _ro(host, "true", 10)
        add(rc == 0, "NAS joignable en SSH")
        if rc:
            return checks, False, warns, before
    dirs = list(dict.fromkeys(s["cwd"] for s in steps if s.get("cwd") and s["kind"] != "cd"))
    for d in dirs:
        q = shlex.quote(d)
        rc, out = _ro(host, f"test -d {q} && ls {q} | grep -E '^(docker-)?compose\\.ya?ml$' | head -1", 15)
        add(rc == 0 and bool(out.strip()), f"Dossier {d} présent avec un fichier compose" if rc == 0 and out.strip() else f"Dossier {d} ou fichier compose introuvable")
        if rc or not out.strip():
            continue
        pre = "sudo -n " if host == "homelab" else ""
        rc, svc = _ro(host, f"cd {q} && {pre}docker compose config --services", 30)
        have = set(svc.split()) if rc == 0 else set()
        wanted = {x for s in steps if s.get("cwd") == d for x in s.get("services", [])}
        miss = sorted(wanted - have)
        add(rc == 0 and not miss, "Services demandés présents dans le compose : " + ", ".join(sorted(wanted)) if wanted and rc == 0 and not miss
            else ("compose illisible : " + svc[-120:] if rc else f"Service(s) absent(s) du compose : {', '.join(miss)}"))
        if rc == 0 and not miss:
            targets = " ".join(shlex.quote(x) for x in sorted(wanted))
            rc2, cur = _ro(host, f"cd {q} && {pre}docker compose ps -q {targets} | xargs -r {pre}docker inspect -f '{{{{.Name}}}} {{{{.Config.Image}}}} {{{{.Image}}}}'", 30)
            if rc2 == 0:
                before += [{"dir": d, "line": l.strip()[:200]} for l in cur.splitlines() if l.strip()][:20]
    for s in steps:
        if s["kind"] == "sed":
            for fl in s["files"]:
                p = shlex.quote(os.path.join(s["cwd"], fl))
                rc, _ = _ro(host, f"test -f {p} && test -w {p}", 10)
                add(rc == 0, f"Fichier {os.path.join(s['cwd'], fl)} présent et modifiable")
        if s["kind"] == "tar":
            rc, out = _ro(host, f"df -Pk {BACKUP_DIR} | tail -1 | awk '{{print $4}}'; du -sk {' '.join(shlex.quote(x) for x in s['src'])} 2>/dev/null | awk '{{t+=$1}}END{{print t}}'", 120)
            nums = [int(x) for x in out.split() if x.isdigit()]
            if rc == 0 and len(nums) >= 2:
                free, need = nums[0], nums[1]
                add(free > need * 1.3 + 1024, f"Espace pour la sauvegarde : {need // 1024} Mo à archiver, {free // 1048576} Go libres dans {BACKUP_DIR}")
            else:
                add(False, f"Espace de sauvegarde illisible dans {BACKUP_DIR}")
    if host == "nas":
        try:
            from . import actions
            st, pct = actions._parity_state()
            if st == "en_cours":
                warns.append(f"Un contrôle de parité est en cours ({pct} %) : téléchargements et reconstructions ralentiront le NAS.")
        except Exception:  # noqa
            pass
        if any(s["kind"] in ("build", "pull") for s in steps):
            rc, out = _ro(host, "df -Pk /var/lib/docker 2>/dev/null | tail -1 | awk '{print $4}'", 15)
            if rc == 0 and out.strip().isdigit():
                free = int(out.strip())
                add(free > 3 * 1048576, f"Espace libre pour Docker : {free // 1048576} Go", "ok" if free > 3 * 1048576 else "warn")
    return checks, all(c["ok"] or c["level"] == "warn" for c in checks), warns, before


def _impact(host, steps):
    """Phrase d'impact : services redémarrés et criticité (bases, reverse proxy, DNS)."""
    from .config import CONTAINER_INFO
    ups = [x for s in steps if s["kind"] == "up" for x in (s.get("services") or ["*"])]
    if not ups:
        return ""
    if "*" in ups:
        return "Tous les services du projet seront recréés (interruption de quelques secondes à une minute)."
    cats = {CONTAINER_INFO.get(n, ("", ""))[1] for n in ups}
    crit = [n for n in ups if CONTAINER_INFO.get(n, ("", ""))[1] in ("db", "infra", "securite")]
    return (f"Redémarrage de {', '.join(ups)}" + (f" — attention, service sensible ({', '.join(crit)}) : coupure brève des applis qui en dépendent." if crit else " : coupure brève du service."))


def _fingerprint(host, steps):
    return hashlib.sha256(json.dumps([host] + [[s["argv"], s.get("cwd"), s.get("sudo")] for s in steps], sort_keys=True).encode()).hexdigest()[:16]


# --------------------------------------------------------------------------------------------- API : plan puis exécution
def _find(aid, idx):
    v = STATE.get("slow", "vulns") or {}
    a = next((x for x in v.get("actions") or [] if x.get("id") == aid), None)
    if not a:
        return None, None, "Cette action n'est plus dans le plan (il a été recalculé)."
    for i, c in _commands(a):
        if i == idx:
            return a, c, None
    return a, None, "Commande introuvable dans cette action."


def plan(aid, idx, ip=""):
    """Étape 1 (sans phrase secrète, lecture seule) : valide la commande, lance les vérifications, renvoie le plan à confirmer."""
    try:
        idx = int(idx)
    except (TypeError, ValueError):
        return {"ok": False, "error": "numéro de commande invalide"}
    with _mx:   # les vérifications interrogent le NAS : au plus une préparation toutes les 2 s
        if time.time() - _PLAN_T[0] < 2:
            return {"ok": False, "error": "Préparation trop rapprochée : réessayez dans un instant."}
        _PLAN_T[0] = time.time()
    a, cmd, err = _find(str(aid)[:200], idx)
    if err:
        return {"ok": False, "error": err}
    host = a["host"]
    try:
        reason = _host_reason(host)
        if reason:
            raise Refused(reason)
        steps = parse(host, cmd)
    except Refused as e:
        return {"ok": False, "refused": True, "error": str(e), "command": cmd}
    checks, ok, warns, before = preflight(host, steps)
    now = time.time()
    pid = uuid.uuid4().hex[:12]
    fp = _fingerprint(host, steps)
    rollback = []
    for s in steps:
        if s["kind"] == "sed":
            rollback += [f"cp {os.path.join(s['cwd'], f)}.bak {os.path.join(s['cwd'], f)}" for f in s["files"]]
        if s["kind"] == "tar":
            rollback.append(f"sauvegarde : {s['dest']}")
    if before:
        rollback.append("images actuelles (pour revenir en arrière en les épinglant dans le compose) : " + " ; ".join(b["line"] for b in before[:6]))
    p = {"plan_id": pid, "fingerprint": fp, "action": a["id"], "index": idx, "host": host, "title": a.get("title"), "command": cmd,
         "steps": [{"kind": s["kind"], "text": s["text"]} for s in steps], "checks": checks, "preflight_ok": ok, "warnings": warns,
         "impact": _impact(host, steps), "rollback": rollback, "expires": now + PLAN_TTL, "t": now}
    with _mx:
        for k in [k for k, v in _PLANS.items() if v["expires"] < now]:
            del _PLANS[k]
        _PLANS[pid] = dict(p, _steps=steps)
    return dict(p, ok=True, caps=caps())


def execute(plan_id, fingerprint, pin, ip=""):
    """Étape 2 : exige l'empreinte du plan affiché et la phrase secrète, puis lance l'exécution en arrière-plan."""
    ok, msg = _check_pin(pin)
    if not ok:
        STATE.event("warn", "dashboard", "Tentative d'exécution refusée", f"{msg} (depuis {ip})", "remedy")
        return {"ok": False, "error": msg}
    now = time.time()
    with _mx:
        p = _PLANS.get(str(plan_id)[:20])
        _HIST[:] = [t for t in _HIST if now - t < 3600]
        if not p or p["expires"] < now:
            return {"ok": False, "error": "Plan expiré : relancez la préparation."}
        if not hmac.compare_digest(str(fingerprint or ""), p["fingerprint"]):
            return {"ok": False, "error": "L'empreinte ne correspond pas au plan affiché."}
        if not p["preflight_ok"]:
            return {"ok": False, "error": "Les vérifications préalables ont échoué : corrigez-les puis préparez à nouveau."}
        if len(_HIST) >= MAX_RUNS_H:
            return {"ok": False, "error": f"Limite de {MAX_RUNS_H} exécutions par heure atteinte."}
        a, cmd, err = _find(p["action"], p["index"])
        if err or cmd != p["command"]:
            return {"ok": False, "error": "Le plan de correction a changé depuis l'affichage : préparez à nouveau."}
        if not _run_lock.acquire(blocking=False):
            return {"ok": False, "error": "Une exécution est déjà en cours."}
        _HIST.append(now)
        del _PLANS[p["plan_id"]]
    run = {"run_id": uuid.uuid4().hex[:10], "status": "en_cours", "action": p["action"], "host": p["host"], "title": p["title"], "started": now,
           "steps": [{"text": s["text"], "kind": s["kind"], "status": "attente"} for s in p["_steps"]], "ip": ip, "fingerprint": p["fingerprint"]}
    _RUN.clear()
    _RUN.update(run)
    _publish()
    STATE.event("warn", p["host"], f"Correction lancée depuis le dashboard : {p['title']}", f"{len(run['steps'])} étapes, depuis {ip}", "remedy")
    threading.Thread(target=_worker, args=(p,), daemon=True, name="remedy").start()
    return {"ok": True, "run": _public()}


def _worker(p):
    host, steps = p["host"], p["_steps"]
    ok = True
    try:
        for i, s in enumerate(steps):
            st = _RUN["steps"][i]
            st.update(status="en_cours", t0=time.time())
            _publish()
            if s["kind"] == "cd":
                st.update(status="ok", out="", dur=0)
                continue
            rc, out = _exec(host, s)
            st.update(status="ok" if rc == 0 else "erreur", rc=rc, out=out, dur=round(time.time() - st["t0"], 1))
            _publish()
            if rc != 0:
                ok = False
                for later in _RUN["steps"][i + 1:]:
                    later["status"] = "annulé"
                break
        _RUN.update(status="ok" if ok else "erreur", finished=time.time())
    except Exception as e:  # noqa
        ok = False
        _RUN.update(status="erreur", finished=time.time(), error=f"{type(e).__name__}: {e}"[:200])
    finally:
        _audit(p, ok)
        STATE.event("ok" if ok else "crit", host, f"Correction {'terminée' if ok else 'en échec'} : {p['title']}",
                    " → ".join(f"{s['kind']}:{s['status']}" for s in _RUN["steps"]), "remedy")
        _publish()
        _run_lock.release()
    if ok:
        try:
            from . import vulns
            vulns.request_refresh(p["action"])   # revérification des versions réellement installées (jamais de faux « corrigé »)
            _RUN["recheck"] = True
        except Exception:  # noqa
            pass
        _publish()


def _audit(p, ok):
    rec = {"t": time.time(), "run_id": _RUN.get("run_id"), "ip": _RUN.get("ip"), "host": p["host"], "action": p["action"], "command": p["command"],
           "fingerprint": p["fingerprint"], "ok": ok, "steps": [{k: s.get(k) for k in ("kind", "text", "status", "rc", "dur", "out")} for s in _RUN["steps"]]}
    try:
        with open(AUDIT_FILE, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        os.chmod(AUDIT_FILE, 0o600)
    except OSError:
        pass


def _public():
    return json.loads(json.dumps(_RUN, default=str)) if _RUN else None


def _publish():
    STATE.set("derived", "remedy", _public())


def status():
    return {"run": _public(), "caps": caps()}
