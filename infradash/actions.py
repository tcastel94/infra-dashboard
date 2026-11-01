"""Actions des axes d'amélioration : exécutées par le dashboard quand c'est sûr, sinon mode opératoire pas à pas.

Deux sortes d'actions exécutables, toutes définies ici (aucune commande venue du navigateur) :
- diagnostics en lecture seule sur le NAS (SMART sans réveiller les disques en veille, journaux d'arrêts, onduleur, Appdata Backup) ;
- une seule modification, réversible : pause / reprise du contrôle de parité via le script officiel d'Unraid
  (/usr/local/emhttp/plugins/dynamix/scripts/parity_control, celui de sa planification, qui vérifie lui-même l'état).
Chaque exécution est confirmée dans l'interface, une à la fois, tracée dans le journal ; résultats dans data/actions.json.
Tout le reste (copie hors site, configuration de plugins, onduleur, memtest…) est donné en mode opératoire.
Intégration : loop("actions", 30, actions.publish) ; POST /api/actions/run {"id": …} ; état dans STATE derived.actions.
"""
import json
import os
import re
import threading
import time

from .config import DATA_DIR
from .state import STATE

RESULTS_FILE = os.path.join(DATA_DIR, "actions.json")
MIN_GAP = 15                 # s entre deux exécutions de la même action
PARITY_CTL = "/usr/local/emhttp/plugins/dynamix/scripts/parity_control"
_lock = threading.Lock()
_results = {}
_DEV = re.compile(r"^(sd[a-z]{1,2}|nvme\d+n\d+)$")
_SMART_ATA = {"5": "secteurs réalloués", "187": "erreurs non corrigibles signalées", "188": "délais de commande",
              "197": "secteurs en attente", "198": "secteurs non corrigibles hors ligne", "199": "erreurs CRC (câble/connecteur SATA)"}


def _nas(cmd, timeout=60):
    from . import nas
    out = nas.SSHC.run(cmd, timeout=timeout)
    if out is None:
        raise RuntimeError(f"NAS injoignable en SSH ({nas.SSHC.last_error or 'pas de réponse'})")
    return out


def _mdstat():
    out = _nas("grep -E '^(mdResync|mdResyncPos|mdResyncAction|mdResyncSize)=' /proc/mdstat", 15)
    return dict(l.split("=", 1) for l in out.splitlines() if "=" in l)


def _parity_state(md=None):
    md = md if md is not None else _mdstat()
    pos, size, act = int(md.get("mdResyncPos") or 0), int(md.get("mdResyncSize") or 0), md.get("mdResyncAction", "")
    if pos <= 0 or not act.startswith("check P"):
        return "aucun", None
    pct = round(100 * pos / size, 1) if size else None
    return ("en_cours" if int(md.get("mdResync") or 0) > 0 else "en_pause"), pct


# --------------------------------------------------------------------------------------------- diagnostics
def _smart():
    ini = _nas("grep -E '^\\[|^device=' /var/local/emhttp/disks.ini", 15)
    disks, name = [], None
    for l in ini.splitlines():
        m = re.match(r'^\["?([\w]+)"?\]', l)
        if m:
            name = m.group(1)
        elif l.startswith("device=") and name and name != "flash":
            dev = l.split("=", 1)[1].strip().strip('"')
            if _DEV.match(dev):
                disks.append((name, dev))
    if not disks:
        raise RuntimeError("aucun disque trouvé dans disks.ini")
    cmd = "; ".join(f"echo @@{n}:{d}; smartctl -n standby -H -A /dev/{d} 2>&1 | head -90" for n, d in disks)
    out = _nas(cmd, 90)
    rows, bad = [], 0
    for blk in out.split("@@")[1:]:
        head, _, body = blk.partition("\n")
        n, d = head.split(":", 1)
        r = {"disk": n, "dev": d, "health": None, "issues": [], "temp": None}
        if "STANDBY" in body:
            r["health"] = "veille (non lu pour ne pas le réveiller)"
        for l in body.splitlines():
            if "overall-health" in l or "SMART Health Status" in l:
                r["health"] = l.split(":", 1)[1].strip()
            p = l.split()
            if len(p) >= 10 and p[0] in _SMART_ATA and p[9].isdigit() and int(p[9]) > 0:
                r["issues"].append(f"{_SMART_ATA[p[0]]} : {p[9]}")
            if len(p) >= 10 and p[0] in ("190", "194") and p[9].isdigit():
                r["temp"] = int(p[9])
            m = re.match(r"^(Media and Data Integrity Errors|Critical Warning|Percentage Used|Temperature):\s+(\S+)", l)
            if m:
                k, v = m.groups()
                if k == "Temperature":
                    r["temp"] = int(re.sub(r"\D", "", v) or 0)
                elif k == "Percentage Used":
                    r["wear"] = v
                elif v not in ("0", "0x00"):
                    r["issues"].append(f"{k} : {v}")
        lvl = "crit" if (r["health"] and "FAIL" in r["health"].upper()) or any(i.startswith(("secteurs", "erreurs non")) for i in r["issues"]) \
            else "warn" if any(not i.startswith("délais") for i in r["issues"]) else "ok"   # quelques délais de commande : bénins
        r["level"] = lvl
        bad += lvl != "ok"
        rows.append(r)
    crc = [r["disk"] for r in rows if any("CRC" in i for i in r["issues"])]
    summary = (f"{len(rows)} disques lus : " + (f"{bad} à surveiller" if bad else "aucun défaut SMART")
               + (f" ; erreurs CRC sur {', '.join(crc)} : câble SATA ou connecteur à changer en priorité" if crc else ""))
    return {"summary": summary, "level": "crit" if any(r["level"] == "crit" for r in rows) else "warn" if bad else "ok", "table": rows}


def _shutdowns():
    out = _nas("echo @@ups; tail -n 40 /var/log/apcupsd.events 2>/dev/null; "
               "echo @@sys; grep -h -i -E 'unclean shutdown|power failure|on battery|shutdown initiated|system halted' "
               "/var/log/syslog.1 /var/log/syslog 2>/dev/null | tail -n 20; echo @@up; uptime", 30)
    sec, cur = {}, None
    for l in out.splitlines():
        if l.startswith("@@"):
            cur = l[2:]
            sec[cur] = []
        elif cur and l.strip():
            sec[cur].append(l.strip())
    ups = [l for l in sec.get("ups", []) if re.search(r"(?i)power failure|on batter|power is back|shutdown|lost|restored", l)]
    sysl = sec.get("sys", [])
    unclean = [l for l in sysl if "unclean" in l.lower()]
    summary = (f"{len(ups)} événement(s) onduleur récent(s), {len(unclean)} arrêt(s) non propre(s) signalé(s) par Unraid"
               + (" : un arrêt brutal explique des erreurs de parité (désynchronisation), sans dommage matériel" if unclean else ""))
    return {"summary": summary, "level": "warn" if unclean else "ok", "lines": (ups[-12:] + unclean[-6:] + sec.get("up", []))[-20:]}


def _ups():
    out = _nas("grep -E '^(UPSCABLE|UPSTYPE|ONBATTERYDELAY|BATTERYLEVEL|MINUTES|TIMEOUT|KILLDELAY)\\b' /etc/apcupsd/apcupsd.conf; "
               "echo @@; apcaccess status 2>/dev/null | grep -E '^(MODEL|STATUS|LOADPCT|BCHARGE|TIMELEFT|NOMPOWER|LASTXFER|NUMXFERS|XONBATT)'", 20)
    conf, _, status = out.partition("@@")
    c = dict(l.split(None, 1) for l in conf.splitlines() if len(l.split(None, 1)) == 2)
    s = {k.strip(): v.strip() for k, v in (l.split(":", 1) for l in status.splitlines() if ":" in l)}
    lvl, notes = "ok", []
    if c.get("BATTERYLEVEL") or c.get("MINUTES"):
        notes.append(f"arrêt propre du NAS configuré : batterie ≤ {c.get('BATTERYLEVEL', '?')} % ou autonomie ≤ {c.get('MINUTES', '?')} min"
                     + (f" ou après {c['TIMEOUT']} s sur batterie" if c.get("TIMEOUT") not in (None, "0") else ""))
    else:
        lvl = "warn"
        notes.append("aucun seuil d'arrêt propre trouvé dans apcupsd.conf")
    if str(s.get("LOADPCT", "")).startswith("0.0"):
        lvl = "warn"
        notes.append("charge à 0 % : l'onduleur ne mesure pas la charge, donc l'autonomie annoncée est théorique — "
                     "vérifiez physiquement que NAS, homelab et box sont branchés sur les prises secourues")
    return {"summary": " ; ".join(notes), "level": lvl, "kv": [[k, v] for k, v in c.items()] + [[k, v] for k, v in s.items()]}


def _appdata():
    out = _nas("ls -1 /boot/config/plugins/appdata.backup/ 2>/dev/null; echo @@; "
               "for f in /boot/config/plugins/appdata.backup/config.json; do [ -f \"$f\" ] && "
               "grep -o -E '\"(destination|backupFrequency|backupFrequencyWeekday|backupFrequencyHour|keepMinBackups|deleteBackupsOlderThan)\"\\s*:\\s*\"?[^,\"}]*' \"$f\"; done", 20)
    files, _, conf = out.partition("@@")
    kv = [[m.group(1), m.group(2)] for m in re.finditer(r'"(\w+)"\s*:\s*"?([^,"}]*)', conf)]
    if not files.strip():
        return {"summary": "Appdata Backup n'est pas installé", "level": "warn", "kv": []}
    if not kv:
        return {"summary": "Appdata Backup est installé mais n'a jamais été configuré : aucune sauvegarde planifiée", "level": "warn", "kv": []}
    freq = dict(kv).get("backupFrequency", "?")
    return {"summary": f"Appdata Backup configuré (fréquence : {freq})" + (" mais désactivé" if freq in ("disabled", "") else ""),
            "level": "warn" if freq in ("disabled", "") else "ok", "kv": kv}


def _parity_pause():
    st, pct = _parity_state()
    if st != "en_cours":
        raise RuntimeError("aucun contrôle de parité en cours à mettre en pause")
    _nas(f"{PARITY_CTL} pause", 30)
    time.sleep(2)
    st2, pct2 = _parity_state()
    return {"summary": f"contrôle mis en pause à {pct2 if pct2 is not None else pct} %" if st2 == "en_pause" else f"état après la demande : {st2}",
            "level": "ok" if st2 == "en_pause" else "warn"}


def _parity_resume():
    st, pct = _parity_state()
    if st != "en_pause":
        raise RuntimeError("aucun contrôle de parité en pause à reprendre")
    _nas(f"{PARITY_CTL} resume", 30)
    time.sleep(2)
    st2, pct2 = _parity_state()
    return {"summary": f"contrôle repris à {pct2 if pct2 is not None else pct} %" if st2 == "en_cours" else f"état après la demande : {st2}",
            "level": "ok" if st2 == "en_cours" else "warn"}


ACTIONS = {
    "smart": {"title": "Lire les SMART de tous les disques", "kind": "diagnostic", "host": "nas", "fn": _smart,
              "for": ["parity-errors", "parity-root-cause", "fc:nas.disktemp"],
              "about": "smartctl en lecture seule ; un disque en veille n'est pas réveillé."},
    "shutdowns": {"title": "Chercher les arrêts brutaux et coupures de courant", "kind": "diagnostic", "host": "nas", "fn": _shutdowns,
                  "for": ["parity-root-cause", "parity-errors", "ups-shutdown"], "about": "Lecture des journaux de l'onduleur et d'Unraid."},
    "ups": {"title": "Lire la configuration d'arrêt de l'onduleur", "kind": "diagnostic", "host": "nas", "fn": _ups,
            "for": ["ups-shutdown"], "about": "apcupsd.conf et état de l'onduleur, en lecture seule."},
    "appdata": {"title": "Vérifier la configuration d'Appdata Backup", "kind": "diagnostic", "host": "nas", "fn": _appdata,
                "for": ["backup:appdata"], "about": "Lecture de la configuration du plugin, sans rien modifier."},
    "parity-pause": {"title": "Mettre le contrôle de parité en pause", "kind": "change", "host": "nas", "fn": _parity_pause,
                     "for": ["parity-tuning", "parity-errors"], "state": "en_cours",
                     "confirm": "Mettre en pause le contrôle de parité en cours ? Il reprendra exactement où il s'est arrêté avec « Reprendre » "
                                "(ou depuis Unraid → Main). Rien n'est écrit sur les disques.",
                     "about": "Script officiel d'Unraid (parity_control pause), celui de la planification des contrôles."},
    "parity-resume": {"title": "Reprendre le contrôle de parité", "kind": "change", "host": "nas", "fn": _parity_resume,
                      "for": ["parity-tuning", "parity-errors"], "state": "en_pause",
                      "confirm": "Reprendre le contrôle de parité là où il s'était arrêté (même mode que celui lancé par Unraid) ?",
                      "about": "Script officiel d'Unraid (parity_control resume)."},
}

# --------------------------------------------------------------------------------------------- modes opératoires
MODOPS = {
    "backup:appdata": {"why": "Sans elle, une panne du cache NVMe ou une erreur de manipulation fait perdre la configuration et les bases de tous les conteneurs.",
        "steps": [
            ["Unraid → Settings → Appdata Backup (plugin déjà installé)."],
            ["Destination : un partage de l'array, par ex. /mnt/user/backups/appdata (pas le cache : il faut un autre support que la source)."],
            ["Planification : quotidienne à 04:00 (après la sauvegarde de clawhost à 03:30, avant les mises à jour de conteneurs à 07:00)."],
            ["Garder 7 sauvegardes (« Keep min backups » = 7, « Delete backups older than » = 14 j) ; laisser « arrêter les conteneurs » coché pour des bases cohérentes."],
            ["Exclure les dossiers volumineux et reconstructibles (caches Plex/Jellyfin, modèles Ollama) dans « Excluded folders »."],
            ["Lancer « Backup now » une première fois et vérifier que le dossier se remplit :", "ls -lh /mnt/user/backups/appdata/"],
        ], "verify": "Le diagnostic « Vérifier la configuration d'Appdata Backup » doit afficher la fréquence choisie, et la chaîne apparaît à jour dans Sauvegardes le lendemain."},
    "offsite": {"why": "Toutes les sauvegardes (homelab, clawhost, appdata) sont sur le NAS : un vol, un incendie, un rançongiciel ou une double panne emporte tout.",
        "steps": [
            ["Choisir une destination hors de la maison : Backblaze B2 (~6 $/To/mois), Hetzner Storage Box (~4 €/To/mois) ou le VPS existant."],
            ["Installer rclone sur le NAS (Apps → « rclone » plugin) puis créer le distant chiffré : un distant « b2 » ou « sftp », puis un distant « crypt » par-dessus.", "rclone config"],
            ["Noter la phrase de passe du chiffrement dans Vaultwarden : sans elle, la copie est illisible."],
            ["Test à blanc, puis première copie :", "rclone sync /mnt/user/backups offsite-crypt:backups --dry-run --fast-list"],
            ["Planifier la copie chaque nuit à 05:00 (Settings → User Scripts → nouveau script, planification personnalisée « 0 5 * * * ») :",
             "rclone sync /mnt/user/backups offsite-crypt:backups --fast-list --transfers 4 --log-file /mnt/user/backups/offsite.log"],
            ["Tester une restauration d'un fichier une fois par trimestre :", "rclone copy offsite-crypt:backups/homelab/<fichier> /tmp/test-restauration/"],
        ], "verify": "Le journal /mnt/user/backups/offsite.log se termine sans erreur ; dans Sauvegardes, la chaîne hors site apparaîtra quand le dashboard détectera ce script."},
    "ups-shutdown": {"why": "Une coupure plus longue que la batterie provoque un arrêt brutal : parité désynchronisée et bases potentiellement corrompues.",
        "steps": [
            ["Lancer le diagnostic « Lire la configuration d'arrêt de l'onduleur » ci-dessus : il dit si les seuils sont déjà réglés."],
            ["Unraid → Settings → UPS Settings : « Battery level to initiate shutdown » = 30 %, « Runtime left to initiate shutdown » = 5 min, puis Apply."],
            ["Vérifier physiquement que le NAS, le homelab (DNS de tout le réseau) et la box sont sur les prises secourues de l'onduleur (pas sur les prises « surge only »)."],
            ["La charge mesurée à 0 % indique un onduleur qui ne remonte pas sa charge : se fier aux seuils de batterie, pas à l'autonomie affichée."],
            ["Facultatif : faire suivre l'arrêt au homelab avec apcupsd en mode client réseau (NETSERVER on côté NAS, puis sur le homelab :", "sudo apt install apcupsd"],
        ], "verify": "Le diagnostic doit afficher les nouveaux seuils ; un test débranché (à faire un soir, NAS peu chargé) doit déclencher l'arrêt propre."},
    "parity-root-cause": {"why": "Des erreurs de parité en série viennent presque toujours d'un arrêt brutal ; sinon d'un câble SATA, d'un disque ou de la RAM.",
        "steps": [
            ["Lancer « Chercher les arrêts brutaux » : un arrêt non propre récent suffit à expliquer les erreurs (parité simplement désynchronisée)."],
            ["Lancer « Lire les SMART » : des erreurs CRC désignent un câble SATA ou un connecteur ; des secteurs réalloués ou en attente, un disque à surveiller ou à remplacer."],
            ["Laisser le contrôle en cours se terminer, puis lancer un contrôle « correcting » seulement si aucun disque n'est suspect (Main → Check, case « Write corrections » cochée)."],
            ["Si les erreurs reviennent sans arrêt brutal ni défaut SMART : tester la RAM (au redémarrage, menu de boot Unraid → Memtest86+, une nuit complète)."],
        ], "verify": "Le contrôle suivant doit se terminer avec 0 erreur ; le diagnostic de parité du dashboard passe alors au vert."},
    "parity-errors": {"why": "La parité est incohérente avec les données : une panne de disque pendant cette période donnerait une reconstruction fausse.",
        "steps": [
            ["Ne pas lancer de contrôle « correcting » tant que la cause n'est pas connue (cf. « Trouver la cause des erreurs de parité »)."],
            ["Lancer « Lire les SMART » et « Chercher les arrêts brutaux » ci-dessus."],
            ["Laisser le contrôle actuel finir ; le mettre en pause aux heures chargées avec le bouton ci-dessus si le NAS ralentit."],
            ["S'assurer d'une sauvegarde récente des données critiques avant toute intervention matérielle."],
        ], "verify": "Contrôle terminé, puis contrôle suivant à 0 erreur."},
    "parity-tuning": {"why": "Un contrôle de parité de 8 To ralentit fortement le NAS pendant 1 à 2 jours.",
        "steps": [
            ["Mettre en pause maintenant avec le bouton ci-dessus, reprendre le soir."],
            ["Pour automatiser : Apps → installer « Parity Check Tuning », puis Settings → Parity Check Tuning : incréments de 23:00 à 07:00, pause si les disques chauffent au-delà de 50 °C."],
        ], "verify": "Le contrôle n'avance plus qu'en heures creuses (onglet Stockage)."},
}


def _load():
    try:
        with open(RESULTS_FILE) as f:
            d = json.load(f)
        if isinstance(d, dict):
            _results.update(d)
    except (OSError, ValueError):
        pass


def _save():
    try:
        tmp = RESULTS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_results, f, ensure_ascii=False, default=str)
        os.replace(tmp, RESULTS_FILE)
    except OSError:
        pass


def publish():
    """Catalogue publié pour l'interface (toutes les 30 s) : actions disponibles par axe, état de la parité, derniers résultats."""
    parity = None
    try:
        parity, pct = _parity_state()
    except Exception:  # noqa — NAS injoignable : les actions de parité ne sont simplement pas proposées
        pct = None
    acts = {}
    for k, a in ACTIONS.items():
        avail = a.get("state") is None or a["state"] == parity
        acts[k] = {"id": k, "title": a["title"], "kind": a["kind"], "host": a["host"], "for": a["for"], "about": a.get("about", ""),
                   "confirm": a.get("confirm"), "available": avail}
    STATE.set("derived", "actions", {"actions": acts, "modops": MODOPS, "results": dict(_results), "running": _lock.locked(),
                                     "parity": {"state": parity, "pct": pct}, "t": time.time()})


def run(aid):
    """Exécute une action du catalogue (identifiant seulement) ; renvoie le résultat. Une action à la fois."""
    a = ACTIONS.get(aid if isinstance(aid, str) else "")
    if not a:
        return {"ok": False, "error": "action inconnue"}
    prev = _results.get(aid) or {}
    if time.time() - (prev.get("t") or 0) < MIN_GAP:
        return dict(prev, ok=False, error="action exécutée il y a quelques secondes : réessayez dans un instant")
    if not _lock.acquire(blocking=False):
        return {"ok": False, "error": "une autre action est en cours"}
    t0 = time.time()
    try:
        try:
            res = a["fn"]()
            r = {"ok": True, "t": time.time(), "duration_s": round(time.time() - t0, 1), **res}
        except Exception as e:  # noqa
            r = {"ok": False, "t": time.time(), "duration_s": round(time.time() - t0, 1), "error": str(e)[:300], "level": "warn"}
        _results[aid] = r
        _save()
        STATE.event("ok" if r["ok"] else "warn", a["host"], f"Action depuis le dashboard : {a['title']}",
                    r.get("summary") or r.get("error") or "", "action")
    finally:
        _lock.release()
    publish()
    return r


_load()
