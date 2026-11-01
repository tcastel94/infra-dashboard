"""Notes de santé, sécurité, résilience, maintenance et confidentialité, et axes d'amélioration.

BARÈME (déterministe, borné)
----------------------------
* Chaque problème détecté donne une pénalité brute (en points), classée dans une famille (« vulnérabilités »,
  « sauvegardes »…). Chaque famille a un plafond progressif : P = Σ pénalités jusqu'à 70 % du plafond, puis
  approche exponentielle du plafond sans jamais le dépasser (P = k + r·(1 − e^(−(Σ − k)/r)), k = 0,7·plafond,
  r = 0,3·plafond). Un seul type de problème ne peut donc pas écraser la note, et chaque correction rapporte
  toujours quelque chose (pas d'effet de seuil).
* Note de catégorie = 100 × Π_familles (1 − P_famille / 100). Chaque famille retire un pourcentage de ce qui
  reste : la note reste dans [0, 100] et ne peut pas tomber à 0 (plafonds < 100).
* items[].penalty = part effective des points perdus (100 − note), répartie au prorata des pénalités plafonnées :
  la somme des pénalités affichées vaut exactement 100 − note. items[].raw = pénalité brute du barème.
* items[].gain = points de catégorie regagnés si on corrige ce seul problème (recalcul exact) ; gain_global =
  la même chose sur la note globale. axes[].gain = gain sur la note globale de la correction entière (une
  correction peut régler plusieurs problèmes, dans plusieurs catégories).
* Note globale = moyenne pondérée des catégories disponibles : sécurité 30 %, résilience 25 %, santé 20 %,
  maintenance 15 %, confidentialité 10 % (poids renormalisés si une catégorie n'a pas de données, ex. pas
  d'analyse des flux sortants -> confidentialité absente).
* Lettres : A ≥ 90 (Excellent), B ≥ 80 (Bon), C ≥ 70 (Correct), D ≥ 55 (À améliorer), E ≥ 40 (Insuffisant),
  F < 40 (Critique).
* Les points de chaque règle sont des constantes de ce fichier (voir FAMILIES et les règles _r_*).
  L'analyse IA (derived.ai) n'entre pas dans le calcul (non déterministe) : elle est seulement rappelée.
"""
import json
import math
import os
import re
import time
from datetime import datetime

from .config import DATA_DIR
from .state import STATE
from .util import TZ

HIST_FILE = os.path.join(DATA_DIR, "scores-hist.json")
HIST_DAYS = 180

CATEGORIES = [  # (id, libellé, poids dans la note globale)
    ("sante", "Santé", 0.20),
    ("securite", "Sécurité", 0.30),
    ("resilience", "Résilience", 0.25),
    ("maintenance", "Maintenance", 0.15),
    ("confidentialite", "Confidentialité", 0.10),
]
CAT_LABEL = {c[0]: c[1] for c in CATEGORIES}
CAT_WEIGHT = {c[0]: c[2] for c in CATEGORIES}

GRADES = [(90, "A", "Excellent"), (80, "B", "Bon"), (70, "C", "Correct"), (55, "D", "À améliorer"),
          (40, "E", "Insuffisant"), (0, "F", "Critique")]
EFFORT_W = {"faible": 1, "moyen": 2, "eleve": 4}

# Familles de pénalités : id -> (catégorie, plafond en points, libellé)
FAMILIES = {
    # santé
    "dispo": ("sante", 60, "Disponibilité (machines, DNS)"),
    "services": ("sante", 12, "Services de clawhost"),
    "publics": ("sante", 20, "Domaines publics en erreur"),
    "ressources": ("sante", 25, "Ressources (mémoire, charge, disques pleins)"),
    "materiel": ("sante", 15, "Matériel (températures, erreurs disque)"),
    "conteneurs": ("sante", 25, "Conteneurs en échec"),
    "perf": ("sante", 6, "Contrôle de parité ralenti"),
    "prevision": ("sante", 15, "Saturations prévues"),
    "divers_sante": ("sante", 15, "Autres diagnostics"),
    # sécurité
    "vulns": ("securite", 40, "Vulnérabilités logicielles"),
    "expo": ("securite", 30, "Services exposés (bases, API sans authentification, interfaces d'admin)"),
    "certs": ("securite", 15, "Certificats TLS"),
    "tailscale": ("securite", 8, "Clés Tailscale"),
    "surface": ("securite", 6, "Surface d'attaque inutile (domaines orphelins)"),
    "exfil": ("securite", 24, "Bases de données qui sortent sur Internet"),
    "lan": ("securite", 15, "Réseau local (constats NetScan, appareils inconnus)"),
    "divers_securite": ("securite", 15, "Autres diagnostics"),
    # résilience
    "sauvegardes": ("resilience", 40, "Sauvegardes manquantes ou en retard"),
    "horssite": ("resilience", 15, "Pas de copie hors site (3-2-1)"),
    "parite": ("resilience", 25, "Intégrité de la parité"),
    "disques": ("resilience", 40, "Redondance des disques"),
    "energie": ("resilience", 20, "Onduleur et arrêts propres"),
    "divers_resilience": ("resilience", 15, "Autres diagnostics"),
    # maintenance
    "maj": ("maintenance", 10, "Mises à jour système en attente"),
    "reboot": ("maintenance", 8, "Redémarrage en attente"),
    "eol": ("maintenance", 30, "Logiciels en fin de vie"),
    "retard": ("maintenance", 5, "Composants en retard de correctif"),
    "latest": ("maintenance", 6, "Mises à jour automatiques sur « latest »"),
    "hygiene": ("maintenance", 6, "Hygiène (conteneurs abandonnés, liens morts)"),
    "divers_maintenance": ("maintenance", 15, "Autres diagnostics"),
    # confidentialité
    "dns": ("confidentialite", 16, "DNS contourné"),
    "iot": ("confidentialite", 15, "Caméras / IoT qui sortent"),
    "horsue": ("confidentialite", 10, "Flux hors UE"),
    "telemetrie": ("confidentialite", 10, "Télémétrie / pistage"),
    "risque": ("confidentialite", 12, "Destinations à risque / nouvelles"),
    "cloison": ("confidentialite", 6, "Cloisonnement réseau (bases pouvant sortir, HTTP en clair)"),
    "divers_confidentialite": ("confidentialite", 15, "Autres constats"),
}

# Vulnérabilités (slow.vulns.actions) : points de base par priorité x multiplicateur d'exposition x KEV
VULN_BASE = {"critique": 12, "haute": 5, "moyenne": 2, "basse": 0.4}
VULN_EXPO = {"internet": 1.5, "lan": 1.0, "inconnue": 1.0, "local": 0.5}
VULN_KEV = 1.5
VULN_NOCVE = 0.5        # action sans CVE connue (fin de vie, retard de version) : risque futur, déjà compté en maintenance
VULN_MAX_ACTION = 25
# Expositions (actions de type « exposition ») : points par exposition et priorité
EXPO_PTS = {"internet": {"critique": 20, "haute": 15, "moyenne": 8, "basse": 3},
            "lan": {"critique": 10, "haute": 6, "moyenne": 3, "basse": 1.5}}

# Catégorie des diagnostics non reconnus (par tag) ; info = 0 point
TAG_CAT = {"réseau": "sante", "stockage": "sante", "public": "sante", "docker": "sante", "backup": "resilience",
           "énergie": "resilience", "tailscale": "securite", "sécurité": "securite", "système": "maintenance",
           "planning": None}
GENERIC_PTS = {"crit": 6, "warn": 3}

_NUM = re.compile(r"(?<![A-Za-z])\d[\d   .,]*")


def _f(x, default=0.0):
    try:
        return float(str(x).replace(",", ".").split()[0])
    except (TypeError, ValueError, IndexError):
        return default


def _cut(s, n=300):
    s = " ".join(str(s or "").split())
    if len(s) <= n:
        return s
    cut = s[:n]
    p = max(cut.rfind(". "), cut.rfind(" ; "))
    return (cut[:p + 1] if p > n * 0.5 else cut.rstrip() + "…").strip()


def _plural(n, word, pl=None):
    return f"{n} {word if n == 1 else (pl or word + 's')}"


def grade_of(score):
    for lim, g, lab in GRADES:
        if score >= lim:
            return g, lab
    return "F", "Critique"


# =====================================================================================================
# Collecte des pénalités
# =====================================================================================================
class _Ctx:
    def __init__(self):
        self.items = []
        self.consumed = set()   # problèmes déjà comptés par une règle (évite les doubles comptes)

    def add(self, fam, label, raw, detail="", fix="", effort="moyen", source="", fix_id=None, axis=None, sev="warn"):
        if raw <= 0:
            return
        cat = FAMILIES[fam][0]
        self.items.append({"fam": fam, "cat": cat, "label": label, "raw": round(float(raw), 2), "detail": _cut(detail, 400),
                           "fix": _cut(fix, 320), "effort": effort if effort in EFFORT_W else "moyen", "source": source,
                           "fix_id": fix_id or f"{fam}:{label}", "axis": axis or "", "sev": sev})


def _live(k):
    return STATE.get("live", k) or {}


def _slow(k):
    return STATE.get("slow", k) or {}


# --------------------------------------------------------------------------------------------- santé
def _r_hosts(c):
    hl, nas, cl = _live("homelab"), _live("nas"), _live("clawhost")
    if hl.get("down"):
        c.add("dispo", "Homelab injoignable", 30, hl.get("error", ""), "Vérifier le homelab (192.168.2.4) : il porte le DNS de tout le réseau.",
              "moyen", "supervision", "host-homelab", "Remettre le homelab en service", "crit")
    if nas.get("down"):
        c.add("dispo", "NAS injoignable (SSH)", 35, nas.get("error", ""),
              "Vérifier l'alimentation et le réseau du NAS (192.168.2.3), puis l'accès SSH.", "moyen", "supervision", "host-nas",
              "Remettre le NAS en service", "crit")
    if cl and cl.get("up") is False:
        c.add("dispo", "clawhost injoignable", 20, f"Aucune sonde ne répond sur {cl.get('ip', '192.168.2.5')}.",
              "Vérifier clawhost : alimentation, câble réseau, IP (bail DHCP statique).", "moyen", "supervision", "host-clawhost",
              "Remettre clawhost en service", "crit")
    elif cl.get("up"):
        down = [p for p in cl.get("probes") or [] if p.get("up") is False]
        for p in down:
            c.add("services", f"clawhost : {p.get('name', 'service')} (:{p.get('port')}) ne répond plus", 4,
                  f"Sonde {p.get('kind', 'tcp')} en échec alors que la machine répond.",
                  f"Sur clawhost : vérifier le service écoutant sur le port {p.get('port')} (systemctl status / journalctl).",
                  "faible", "supervision", f"claw-probe:{p.get('port')}", f"Relancer {p.get('name', 'le service')} sur clawhost", "warn")
    dns = _live("dns")
    if dns and dns.get("ok") is False:
        c.add("dispo", "DNS du réseau (AdGuard) en panne", 15, "La résolution de debian.org via AdGuard (127.0.0.1) échoue.",
              "Vérifier les conteneurs adguardhome et unbound du homelab.", "faible", "supervision", "dns-down",
              "Rétablir le DNS AdGuard", "crit")


def _r_resources(c):
    for hid, lab in (("homelab", "Homelab"), ("nas", "NAS")):
        h = _live(hid)
        if not h or h.get("down"):
            continue
        mem = _f(h.get("mem"))
        pts = 10 if mem >= 95 else 6 if mem >= 90 else 3 if mem >= 85 else 0
        c.add("ressources", f"{lab} : mémoire à {mem:.0f} %", pts, "Au-delà de 90 %, le noyau tue des processus (OOM) ou swappe.",
              "Identifier les conteneurs les plus gourmands (onglet Conteneurs) et limiter leur mémoire.", "moyen", "supervision",
              f"mem-{hid}", f"Libérer de la mémoire sur le {lab.lower()}", "warn" if pts < 10 else "crit")
        cores = _f(h.get("cores"), 1) or 1
        load = h.get("load") or []
        l15 = _f(load[2]) if len(load) > 2 else 0
        ratio = l15 / cores
        pts = 6 if ratio >= 2 else 3 if ratio >= 1.25 else 0
        c.add("ressources", f"{lab} : charge {l15:.1f} pour {cores:.0f} cœurs (15 min)", pts,
              "Charge durablement supérieure au nombre de cœurs : processus en attente CPU ou disque.",
              "Repérer le processus ou le conteneur en cause (onglet Machines) ; décaler les tâches lourdes.", "moyen",
              "supervision", f"load-{hid}", f"Réduire la charge du {lab.lower()}")
    rf = _live("homelab").get("root_fs") or {}
    if rf.get("size"):
        pct = 100 * (rf["size"] - rf.get("free", 0)) / rf["size"]
        pts = 12 if pct >= 95 else 8 if pct >= 90 else 3 if pct >= 85 else 0
        c.add("ressources", f"Disque système du homelab à {pct:.0f} %", pts, "Un / plein bloque Docker, les journaux et AdGuard.",
              "docker system prune, journalctl --vacuum-time=14d, purger /var/backups/homelab.", "faible", "supervision",
              "homelab-rootfs", "Libérer de l'espace sur le disque du homelab", "crit" if pts >= 8 else "warn")


_AGE = [("second", 0), ("minute", 0), ("hour", 0), ("day", 1), ("week", 7), ("month", 30), ("year", 365)]
_AGE_FR = {"second": "s", "minute": "min", "hour": "h", "day": "j", "week": "sem.", "month": "mois", "year": "ans"}


def _age_days(status):
    m = re.search(r"(\d+|an|a|About an?)\s*(second|minute|hour|day|week|month|year)s?\s+ago", status or "", re.I)
    if not m:
        return 0, ""
    n = int(m.group(1)) if m.group(1).isdigit() else 1
    unit = m.group(2).lower()
    days = n * dict(_AGE)[unit]
    return days, f"{n} {_AGE_FR[unit]}"


def _r_containers(c):
    for hid, lab in (("nas", "NAS"), ("homelab", "homelab")):
        for ct in STATE.get("live", f"{hid}_containers") or []:
            name = ct.get("name", "?")
            if ct.get("health") == "unhealthy":
                c.add("conteneurs", f"{name} ({lab}) : unhealthy", 6, ct.get("status", ""),
                      f"docker logs {name} pour voir pourquoi le healthcheck échoue, puis redémarrer le conteneur.",
                      "faible", "supervision", f"ct:{name}", f"Réparer le conteneur {name}", "crit")
            if ct.get("state") == "restarting":
                c.add("conteneurs", f"{name} ({lab}) redémarre en boucle", 8, ct.get("status", ""),
                      f"docker logs {name} : corriger la configuration ou l'image fautive.", "moyen", "supervision",
                      f"ct:{name}", f"Réparer le conteneur {name}", "crit")
            if ct.get("state") == "exited" and str(ct.get("exit", "0")) not in ("0", "", "None"):
                days, age = _age_days(ct.get("status"))
                if days >= 7:
                    c.add("hygiene", f"{name} arrêté en erreur depuis {age} (code {ct.get('exit')})", 1,
                          "Conteneur abandonné : il encombre la liste et garde une image potentiellement vulnérable.",
                          f"Le supprimer s'il ne sert plus (docker rm {name}) ou le réparer.", "faible", "supervision",
                          "ct-abandoned", "Supprimer les conteneurs abandonnés", "info")
                else:
                    c.add("conteneurs", f"{name} ({lab}) arrêté en erreur (code {ct.get('exit')})", 4, ct.get("status", ""),
                          f"docker logs {name} pour comprendre l'arrêt, puis le relancer.", "faible", "supervision",
                          f"ct:{name}", f"Réparer le conteneur {name}", "warn")


# --------------------------------------------------------------------------------------------- diagnostics
def _first_int(s, default=1):
    m = re.search(r"\d[\d   ]*", s or "")
    if not m:
        return default
    try:
        return int(re.sub(r"\D", "", m.group(0)))
    except ValueError:
        return default


def _r_insights(c, has_vuln_expo):
    """Diagnostics de model.build_insights : règles explicites pour les connus, barème générique pour les autres.
    Les diagnostics déjà couverts par une règle directe (sauvegardes, conteneurs, certificats, Tailscale, onduleur,
    apt/reboot) sont ignorés ici pour ne pas compter deux fois le même problème."""
    ins = STATE.get("derived", "insights")
    if not isinstance(ins, list):
        return False
    for i in ins:
        t, lvl, det, act = i.get("title", ""), i.get("level", "info"), i.get("detail", ""), i.get("action", "")
        src = "diagnostic"
        if re.search(r"a changé d'IP", t):
            m = re.search(r"encore (\d+) domaine", det)
            n = int(m.group(1)) if m else 1
            c.add("publics", f"{_plural(n, 'domaine public', 'domaines publics')} en erreur : NPM vise l'ancienne IP de clawhost", 4 * n,
                  det, act, "faible", src, "clawhost-ip", "Fixer l'IP de clawhost et corriger NPM, Nexus et Homepage", "crit")
        elif re.search(r"domaine\(s\) public\(s\) en erreur", t):
            n = _first_int(t)
            c.add("publics", f"{_plural(n, 'domaine public', 'domaines publics')} en erreur", 6 * n, det, act, "faible", src,
                  "npm-broken", "Réparer les domaines publics en erreur", "crit")
        elif re.search(r"Nginx Proxy Manager orphelin", t):
            n = _first_int(t)
            c.add("surface", f"{_plural(n, 'domaine publié', 'domaines publiés')} sur Internet sans service derrière", 1.5 * n, det, act,
                  "faible", src, "npm-orphans", "Supprimer les proxy hosts orphelins de Nginx Proxy Manager", "warn")
        elif re.search(r"erreurs de parité dans le contrôle en cours", t):
            c.add("parite", t, 15, det + " Une parité incohérente ne permet pas de reconstruire correctement un disque qui lâcherait.",
                  act, "moyen", src, "parity-errors", "Laisser finir le contrôle de parité puis vérifier SMART et RAM", "crit")
        elif re.search(r"^Erreurs de parité récurrentes", t):
            c.add("parite", t, 6, det, act, "moyen", src, "parity-root-cause",
                  "Trouver la cause des erreurs de parité (arrêts brutaux, câbles, RAM)", "warn")
        elif re.search(r"^Contrôle de parité en cours", t):
            if lvl in ("warn", "crit"):
                c.add("perf", "Contrôle de parité anormalement lent", 3, det, act, "faible", src, "parity-tuning",
                      "Restreindre le contrôle de parité aux heures creuses", "warn")
        elif re.search(r"^NAS redémarré il y a", t):
            c.add("energie", "Arrêt non propre récent du NAS", 3, det,
                  "Vérifier que l'onduleur déclenche l'arrêt propre du NAS (Settings → UPS Settings) et consulter le syslog du dernier arrêt.",
                  "faible", src, "ups-shutdown", "Configurer l'arrêt propre du NAS sur l'onduleur", "warn")
        elif re.search(r"chaud : \d+", t):
            temp = _first_int(t.split(":")[-1], 45)
            c.add("materiel", t, 4 if temp >= 50 else 2, det, act, "moyen", src, "cooling", "Améliorer la ventilation des disques", "warn")
        elif re.search(r": DISK_", t):
            c.add("disques", f"Disque en défaut : {t}", 20, det, "Unraid → Main : remplacer ou réactiver le disque, puis reconstruire.",
                  "eleve", src, f"disk:{t.split(':')[0].strip()}", f"Remplacer le disque {t.split(':')[0].strip()}", "crit")
        elif re.search(r"erreurs de lecture/écriture", t):
            c.add("materiel", t, 5, det, "Vérifier les SMART et le câble SATA de ce disque.", "moyen", src,
                  f"diskerr:{t.split(':')[0].strip()}", f"Diagnostiquer le disque {t.split(':')[0].strip()}", "warn")
        elif re.search(r"^Cache NVMe à", t) or re.search(r"^Image Docker à", t):
            pct = _first_int(t, 85)
            pts = 12 if pct >= 95 else 8 if pct >= 90 else 4
            fid = "nas-cache" if t.startswith("Cache") else "docker-img"
            c.add("ressources", t, pts, det, act, "faible", src, fid,
                  "Libérer le cache NVMe du NAS" if fid == "nas-cache" else "Faire de la place dans docker.img", "warn")
            c.consumed.add(fid)
        elif re.search(r"bases de données exposées sur tout le LAN", t):
            if not has_vuln_expo:   # sinon déjà compté via les expositions de slow.vulns
                n = _first_int(t)
                c.add("expo", f"{_plural(n, 'base de données exposée', 'bases de données exposées')} sur tout le LAN", min(10, 2 * n),
                      det, act, "faible", src, "db-lan", "Ne plus publier les bases de données sur le LAN", "warn")
        elif re.search(r"^Mise à jour automatique des conteneurs", t):
            m = re.search(r"(\d+) conteneurs suivent", det)
            n = int(m.group(1)) if m else 10
            c.add("latest", f"{n} conteneurs en « latest » mis à jour automatiquement", 0.15 * n, det, act, "moyen", src,
                  "pin-versions", "Épingler les versions des services critiques", "info")
        elif re.search(r"lien\(s\) morts sur la page Homepage", t):
            n = _first_int(t)
            c.add("hygiene", f"{_plural(n, 'lien mort', 'liens morts')} sur Homepage", 0.5 * n, det, act, "faible", src,
                  "homepage-links", "Corriger les tuiles mortes de Homepage", "info")
        elif re.search(r"^(Sauvegarde |Aucune copie hors site|Taille de la sauvegarde)", t) \
                or re.search(r"unhealthy$|redémarre en boucle|arrêté \(code", t) \
                or re.search(r"^(Redémarrage du homelab|\d+ mises à jour en attente|Onduleur|Certificat |Clé Tailscale|Tailscale de )", t) \
                or re.search(r"^Heure de pointe", t):
            continue   # couvert par une règle directe, ou purement informatif
        else:
            pts = GENERIC_PTS.get(lvl, 0)
            cat = TAG_CAT.get(i.get("tag"), "sante")
            if pts and cat:
                c.add(f"divers_{cat}", t, pts, det, act, "moyen", src, "diag:" + _NUM.sub("#", t.lower())[:80],
                      act.split(".")[0] if act else "", lvl)
    return True


# --------------------------------------------------------------------------------------------- sécurité
def _vuln_effort(a):
    kind = a.get("kind", "")
    if kind in ("kernel-homelab", "homelab-ct", "apt-docker", "unraid-template", "claw-openclaw"):
        return "faible"
    if kind == "exposition":
        return "moyen" if re.search(r"mot de passe|authentification", a.get("title", ""), re.I) else "faible"
    if kind == "nas-compose":
        v, tv = str(a.get("version") or ""), str(a.get("target_version") or "")
        if "fin de vie" in a.get("title", "") or (v.split(".")[0] != tv.split(".")[0] and tv):
            return "moyen"
        return "faible"
    return "moyen"


def _vuln_label(a):
    if a.get("kind") == "exposition" or not a.get("n_findings"):
        return a.get("title") or a.get("component") or a.get("id")
    comp, ver = a.get("component") or a.get("id"), str(a.get("version") or "")
    if a.get("kind") == "unraid-os":   # version d'un sous-composant : trompeuse à côté de « Unraid OS »
        ver = ""
    base = comp + (f" {ver}" if ver and ver != "inconnue" and ver not in comp else "")
    n = a["n_findings"]
    expo = {"internet": " — exposé sur Internet", "lan": " — joignable depuis le LAN"}.get(a.get("exposure"), "")
    return f"{base} : {_plural(n, 'vulnérabilité')} (score max {a.get('max_score', '?')}{', KEV' if a.get('kev') else ''}){expo}"


def _r_vulns(c):
    v = STATE.get("slow", "vulns")
    if not isinstance(v, dict) or not isinstance(v.get("actions"), list):
        return False, False
    has_expo = False
    low = []   # corrections de priorité basse (hors expositions) : regroupées en une seule ligne
    for a in v["actions"]:
        prio, expo, kind = a.get("priority", "basse"), a.get("exposure", "inconnue"), a.get("kind", "")
        if kind == "nofix-distro" or not a.get("max_score"):
            continue
        det = f"Priorité {prio} · exposition {expo}" + (f" ({a['exposure_detail']})" if a.get("exposure_detail") else "") + \
              (" · présente dans le catalogue CISA KEV (exploitée activement)" if a.get("kev") else "")
        fix = a.get("title", "") + (" : " + _cut(a.get("remediation"), 220) if a.get("remediation") else "")
        # critique, KEV, ou faille haute réellement exposée sur Internet (CVE connues ou exposition directe)
        sev = "crit" if prio == "critique" or a.get("kev") or (prio == "haute" and expo == "internet" and (
            kind == "exposition" or a.get("n_findings"))) else "warn" if prio == "haute" else "info"
        if kind == "exposition":
            has_expo = True
            pts = EXPO_PTS["internet" if expo == "internet" else "lan"].get(prio, 1.5)
            c.add("expo", _vuln_label(a), pts, det, fix, _vuln_effort(a), "vulnérabilités", "vuln:" + a["id"], a.get("title"), sev)
        else:
            pts = VULN_BASE.get(prio, 0.4) * VULN_EXPO.get(expo, 1.0) * (VULN_KEV if a.get("kev") else 1) * \
                (1 if a.get("n_findings") else VULN_NOCVE)
            if prio == "basse" and not a.get("kev"):
                low.append((a, pts))
                continue
            c.add("vulns", _vuln_label(a), min(VULN_MAX_ACTION, pts), det, fix, _vuln_effort(a), "vulnérabilités",
                  "vuln:" + a["id"], a.get("title"), sev)
    if low:
        names = [a.get("component") or a.get("id") for a, _ in low]
        c.add("vulns", f"{_plural(len(low), 'correction')} de priorité basse en attente", sum(p for _, p in low),
              ", ".join(dict.fromkeys(names)), "Les appliquer au fil de l'eau (onglet Vulnérabilités → plan d'action, priorité basse).",
              "moyen", "vulnérabilités", "vuln-basse", "Appliquer les corrections de priorité basse", "info")
    return True, has_expo


def _r_exposure_fallback(c):
    """Sans analyse de vulnérabilités : API Ollama sans authentification publiée sur le LAN."""
    for ct in STATE.get("live", "nas_containers") or []:
        if ct.get("state") == "running" and re.search(r"0\.0\.0\.0:11434->", ct.get("ports") or ""):
            c.add("expo", "API Ollama sans authentification publiée sur le LAN (:11434)", 3,
                  "N'importe quel appareil du réseau peut utiliser le GPU, lister et supprimer les modèles.",
                  "Publier le port sur 127.0.0.1 ou le placer derrière un proxy avec authentification.", "faible", "supervision",
                  "vuln:expo:ollama-api-sans-auth", "Restreindre l'accès à l'API Ollama", "warn")


def _r_certs(c):
    for e in _slow("public").get("endpoints") or []:
        d = e.get("cert_days")
        if d is None:
            continue
        pts = 12 if d < 0 else 8 if d < 7 else 4 if d < 14 else 1 if d < 21 else 0
        what = "expiré" if d < 0 else f"expire dans {d} j"
        c.add("certs", f"Certificat {e['domain']} {what}", pts,
              f"Émis par {e.get('issuer') or '?'} ; Let's Encrypt (NPM) renouvelle normalement à J-30 : le renouvellement automatique échoue.",
              "Nginx Proxy Manager → SSL Certificates → Renew ; vérifier que le port 80 reste joignable pour le défi HTTP.",
              "faible", "supervision", f"cert:{e['domain']}", f"Renouveler le certificat de {e['domain']}", "crit" if d < 7 else "warn")


def _r_tailscale(c):
    now = datetime.now(TZ)
    for p in (_live("tailscale").get("peers") or []):
        exp = p.get("key_expiry")
        if not exp:
            continue
        try:
            dt = datetime.fromisoformat(exp.replace("Z", "+00:00")).astimezone(TZ)   # affichage en heure de Paris, pas UTC
        except ValueError:
            continue
        days = (dt - now).total_seconds() / 86400
        name = p.get("dns") or p.get("host")
        fid, axis = f"ts-key:{name}", f"Désactiver l'expiration de la clé Tailscale de {name}"
        fix = "Console Tailscale → Machines → « Disable key expiry » (serveurs) ; sinon ré-authentifier avec tailscale up."
        if days < 0 and not p.get("online") and p.get("os") == "linux":
            c.add("tailscale", f"Clé Tailscale de {name} expirée : nœud hors du tailnet", 2,
                  f"Expirée le {dt.strftime('%d/%m/%Y')} : plus d'accès distant de secours à cette machine.", fix, "faible",
                  "supervision", fid, axis, "warn")
        elif 0 <= days < 7 and p.get("online"):
            c.add("tailscale", f"Clé Tailscale de {name} : expire dans {int(days)} j", 4,
                  f"Expire le {dt.strftime('%d/%m/%Y %H:%M')} : le nœud décrochera du tailnet.", fix, "faible", "supervision", fid,
                  axis, "crit")   # même barème que la prévision et le centre d'alertes : critique sous 7 j, attention sous 30 j
        elif 7 <= days < 30 and p.get("online"):
            c.add("tailscale", f"Clé Tailscale de {name} : expire dans {int(days)} j", 1.5,
                  f"Expire le {dt.strftime('%d/%m/%Y')}.", fix, "faible", "supervision", fid, axis, "warn")


# --------------------------------------------------------------------------------------------- résilience
def _r_backups(c):
    bk = STATE.get("derived", "backups")
    if not isinstance(bk, dict):
        return False
    for ch in bk.get("chains") or []:
        st, lab = ch.get("status"), ch.get("label", ch.get("id"))
        if st not in ("warn", "crit"):
            continue
        if not ch.get("last_time"):
            what = "aucune sauvegarde"
        else:
            what = f"dernière il y a {_f(ch.get('age_h')):.0f} h"
        pts = (20 if ch.get("id") == "appdata" else 15) if st == "crit" else 6
        fix = "Activer le plugin Appdata Backup (déjà installé) : sauvegarde nocturne de /mnt/user/appdata, bases arrêtées proprement." \
            if ch.get("id") == "appdata" else f"Vérifier la tâche « {ch.get('when', '')} » ({ch.get('method', '')}) et ses journaux."
        c.add("sauvegardes", f"Sauvegarde {lab} : {what}", pts, ch.get("problem") or f"Destination : {ch.get('dest', '?')}.",
              fix, "faible" if ch.get("id") == "appdata" else "moyen", "sauvegardes", f"backup:{ch.get('id')}",
              "Activer la sauvegarde des appdata du NAS" if ch.get("id") == "appdata" else f"Rétablir la sauvegarde {lab}",
              "crit" if st == "crit" else "warn")
    if bk.get("offsite") is False:
        c.add("horssite", "Aucune copie hors site des sauvegardes", 15,
              "Toutes les sauvegardes finissent sur le NAS : vol, incendie, ransomware ou double panne disque emportent originaux et copies.",
              "Réplication chiffrée nocturne vers un stockage externe (restic ou rclone vers Backblaze B2, Hetzner Storage Box, ou le VPS).",
              "moyen", "sauvegardes", "offsite", "Mettre en place une copie hors site chiffrée (règle 3-2-1)", "warn")
    return True


def _r_ups_array(c):
    nslow = _slow("nas")
    if nslow:
        ups = nslow.get("ups") or {}
        status = str(ups.get("STATUS") or "")
        if not ups:
            c.add("energie", "Aucun onduleur détecté sur le NAS", 8, "Une coupure de courant arrête brutalement l'array (erreurs de parité, bases corrompues).",
                  "Brancher un onduleur USB et configurer l'arrêt propre (Settings → UPS Settings).", "moyen", "supervision", "ups",
                  "Installer un onduleur pour le NAS", "warn")
        elif "ONLINE" not in status:
            c.add("energie", f"Onduleur : {status}", 15, f"Batterie {ups.get('BCHARGE', '?')}, autonomie {ups.get('TIMELEFT', '?')}.",
                  "Vérifier l'alimentation secteur ; l'arrêt propre du NAS doit se déclencher avant la fin de la batterie.",
                  "faible", "supervision", "ups-status", "Rétablir l'alimentation secteur de l'onduleur", "crit")
        else:
            if _f(ups.get("BCHARGE"), 100) < 50:
                c.add("energie", f"Batterie de l'onduleur à {_f(ups.get('BCHARGE')):.0f} %", 5, "Autonomie réduite en cas de coupure.",
                      "Laisser recharger ; si elle reste basse, remplacer la batterie.", "moyen", "supervision", "ups-battery",
                      "Remplacer la batterie de l'onduleur")
            if str(ups.get("LOADPCT", "")).startswith("0.0"):
                c.add("energie", "Onduleur : charge non mesurée (0 %)", 2,
                      f"{ups.get('MODEL', 'Onduleur')} en ligne mais la charge n'est pas remontée : impossible de savoir ce qui est protégé.",
                      "Vérifier que NAS, homelab (DNS) et box sont sur l'onduleur, et que l'arrêt propre du NAS est configuré.",
                      "faible", "supervision", "ups-shutdown", "Configurer l'arrêt propre du NAS sur l'onduleur", "info")
    arr = _live("nas").get("array") or {}
    bad = int(_f(arr.get("mdNumInvalid"))) + int(_f(arr.get("mdNumMissing")))
    if bad:
        c.add("disques", f"Array dégradé : {_plural(bad, 'disque')} invalide(s) ou manquant(s)", 25 * bad,
              "Plus (ou moins) de redondance : une panne supplémentaire entraînerait une perte de données.",
              "Unraid → Main : remplacer le disque et reconstruire ; éviter toute écriture lourde d'ici là.", "eleve", "supervision",
              "array-degraded", "Reconstruire l'array du NAS", "crit")


# --------------------------------------------------------------------------------------------- maintenance
def _r_maint(c):
    hl, apt = _slow("homelab"), _slow("homelab_apt")
    v = STATE.get("slow", "vulns") or {}
    kinds = {}
    for a in (v.get("actions") or []) if isinstance(v, dict) else []:
        kinds.setdefault(a.get("kind"), a.get("id"))
    # même correction que l'action « noyau » / « Docker via apt » du plan de vulnérabilités : un seul axe
    reboot_fix = "vuln:" + kinds["kernel-homelab"] if kinds.get("kernel-homelab") else "homelab-reboot"
    apt_fix = "vuln:" + kinds["apt-docker"] if kinds.get("apt-docker") and any(
        "docker" in p or "containerd" in p for p in apt.get("packages") or []) else "homelab-apt"
    if hl.get("reboot_required"):
        pk = ", ".join(hl.get("reboot_pkgs") or ["noyau"])
        c.add("reboot", "Redémarrage du homelab en attente (nouveau noyau)", 6, f"Paquets : {pk}. Le noyau en cours reste l'ancien, avec ses failles.",
              "Planifier un redémarrage à une heure creuse (DNS du réseau indisponible ~1 min).", "faible", "mises à jour",
              reboot_fix, "Redémarrer le homelab sur le nouveau noyau", "warn")
    if apt.get("pending"):
        sec, n = int(_f(apt.get("security"))), int(_f(apt.get("pending")))
        pts = min(10, 1.5 * sec + 0.4 * max(0, n - sec))
        c.add("maj", f"{_plural(n, 'mise à jour', 'mises à jour')} en attente sur le homelab" + (f" dont {sec} de sécurité" if sec else ""), pts,
              ", ".join((apt.get("packages") or [])[:10]), "sudo apt update && sudo apt full-upgrade", "faible", "mises à jour",
              apt_fix, "Appliquer les mises à jour du homelab", "warn" if sec else "info")


def _r_eol(c, v):
    if not isinstance(v, dict) or not isinstance(v.get("eol"), list):
        return
    cmap = {}
    for a in v.get("actions") or []:
        for cid in (a.get("component_ids") or [a.get("component_id")]):
            if cid and cid not in cmap:
                cmap[cid] = a
    groups, outdated = {}, 0
    for e in v["eol"]:
        if e.get("status") == "fin de vie":
            k = (e.get("host"), e.get("product") or e.get("component"), e.get("cycle"))
            groups.setdefault(k, []).append(e)
        elif e.get("status") == "en retard":
            outdated += 1
    for (host, prod, cycle), es in sorted(groups.items(), key=lambda kv: str(kv[0])):
        name = re.sub(r"\s*\(.*\)$", "", es[0].get("component") or prod or "?")
        n = len(es)
        internet = any(e.get("exposure") == "internet" for e in es)
        pts = min(10, 4 * min(2, 1 + 0.25 * (n - 1)) * (1.5 if internet else 1))
        conts = sorted({e.get("container") for e in es if e.get("container")})
        act = next((cmap[e["component_id"]] for e in es if e.get("component_id") in cmap), None)
        target = es[0].get("next_cycle") or es[0].get("best_cycle")
        date = es[0].get("eol_date") or "?"
        try:
            date = datetime.strptime(date, "%Y-%m-%d").strftime("%d/%m/%Y")
        except ValueError:
            pass
        det = f"Plus de correctifs de sécurité depuis le {date}" + (f" ; {_plural(n, 'composant')} : " + ", ".join(conts[:8]) if conts else "") + \
              (" ; au moins un est exposé sur Internet" if internet else "") + "."
        fix = (act.get("title") + " : " + _cut(act.get("remediation"), 200)) if act else \
            (f"Migrer vers la branche {target}." if target else "Migrer vers une branche maintenue.")
        c.add("eol", f"{name} {cycle or ''} en fin de vie".replace("  ", " "), pts, det, fix, "moyen", "vulnérabilités",
              ("vuln:" + act["id"]) if act else f"eol:{host}:{prod}:{cycle}",
              (act.get("title") if act else f"Migrer {name} {cycle or ''} vers une branche maintenue"), "warn")
    if outdated:
        c.add("retard", f"{_plural(outdated, 'composant')} en retard sur le dernier correctif de leur branche", 0.15 * outdated,
              "Versions encore supportées mais pas à jour (voir l'onglet Vulnérabilités → Fins de vie).",
              "Mettre à jour les images (pull du même tag) et les paquets ; épingler les branches plutôt que « latest ».",
              "moyen", "vulnérabilités", "outdated", "Rattraper les correctifs mineurs en retard", "info")


# --------------------------------------------------------------------------------------------- confidentialité
def _r_egress(c):
    eg = STATE.get("slow", "egress")
    if not isinstance(eg, dict) or not isinstance(eg.get("findings"), list):
        return False
    rules = {  # kind -> (famille, points crit, points warn, points info, effort)
        "dns": ("dns", 10, 8, 0, "faible"), "iot": ("iot", 12, 10, 0, "moyen"), "risk": ("risque", 6, 4, 0, "moyen"),
        "new": ("risque", 5, 3, 0, "faible"), "http": ("cloison", 2, 1.5, 1, "moyen"), "db-hardening": ("cloison", 3, 2, 2, "moyen"),
        "db": ("exfil", 12, 8, 0, "moyen"),
    }
    for f in eg["findings"]:
        kind, lvl = f.get("kind", ""), f.get("level", "info")
        if kind in ("gdpr", "coverage"):
            continue   # synthèse / visibilité : pas un problème en soi (les destinations sont comptées plus bas)
        fam, pc, pw, pi, eff = rules.get(kind, ("divers_confidentialite", 8, 4, 0, "moyen"))
        pts = {"crit": pc, "warn": pw}.get(lvl, pi)
        who = f.get("title", "").split("→")[0].split(":")[-1].strip()
        axis = {"dns": f"Forcer le DNS via AdGuard pour {who}", "iot": "Passer les caméras en P2P local et bloquer leur sortie",
                "db": f"Couper l'accès Internet de {who}", "new": "Vérifier les nouvelles destinations sortantes",
                "http": "Passer les flux HTTP en clair en HTTPS",
                "db-hardening": "Placer les bases sur des réseaux Docker « internal »"}.get(kind)
        if kind == "risk":
            axis = "Bloquer ou justifier " + who
        c.add(fam, f.get("title", ""), pts, f.get("detail", ""), f.get("action", ""), eff, "flux sortants",
              f"egress:{kind}:" + _NUM.sub("#", who.lower())[:60], axis or f.get("title"), lvl)
    hors, tele = [], []
    for d in eg.get("destinations") or []:
        if d.get("category") == "pub-tracking":
            tele.append(d)
        elif d.get("gdpr") == "hors_ue" and d.get("category") not in ("iot-camera", "dns"):
            hors.append(d)
    if hors:
        pts = sum({"eleve": 4, "moyen": 1.5}.get(d.get("risk"), 0.3) for d in hors)
        names = sorted({f"{d.get('service') or d.get('org') or d.get('ip')} ({d.get('country_name') or d.get('country') or '?'})" for d in hors})
        c.add("horsue", f"{_plural(len(hors), 'destination')} hors UE", pts, ", ".join(names[:8]) + ("…" if len(names) > 8 else ""),
              "Vérifier ce que chaque service reçoit ; couper ceux qui ne servent pas (Flux sortants → « Comment bloquer »).",
              "moyen", "flux sortants", "egress-horsue", "Réduire les envois de données hors UE", "info")
    if tele:
        names = sorted({d.get("service") or d.get("ip") for d in tele})
        c.add("telemetrie", f"{_plural(len(tele), 'destination')} de pub / télémétrie contactée(s)", 2.5 * len(tele), ", ".join(names[:8]),
              "Désactiver la télémétrie dans les applis concernées et ajouter ces domaines aux listes de blocage AdGuard.",
              "faible", "flux sortants", "egress-telemetry", "Couper la télémétrie et la bloquer dans AdGuard", "warn")
    return True


# --------------------------------------------------------------------------------------------- prévisions
_FC_SKIP = re.compile(r"^(ts\.|cert\.|eol\.|backup\.|nas\.parity)")   # couverts par une règle directe


def _r_netscan(c):
    ns = _slow("netscan")
    if not ns.get("ok"):
        return
    url = ns.get("url") or "NetScan"
    dg = ns.get("digest") or {}
    for g in dg.get("active") or []:
        pts = (5 if g["max_cvss"] >= 9 else 3 if g["max_cvss"] >= 7 else 1.5) * (1 if g.get("precise") else 0.5)
        c.add("lan", f"{g['device']} : {g['product']} {g['version']} ({g['n']} CVE possibles)", pts,
              f"Appareil {g['ip']} présent sur le réseau ; CVSS max {g['max_cvss']}" + (f" ; {g['why']}" if g.get("why") else "") + ".",
              f"Mettre à jour {g['device']}, ou l'isoler du LAN s'il n'a plus de mises à jour.", "moyen", "réseau local",
              f"netscan:{g.get('mac') or g.get('ip')}:{g['product']}", f"Corriger {g['device']}", "crit" if g["max_cvss"] >= 9 and g.get("precise") else "warn")
    for a in dg.get("attention") or []:
        c.add("lan", f"{a['title']} — {a['device']}", 0.5, a.get("detail") or "", "Fermer le service s'il n'est pas utilisé.",
              "faible", "réseau local", f"netscan:{a['device']}:{a['category']}", f"Vérifier {a['device']}")
    unk = sum(1 for d in (_slow("lan_devices").get("devices") or []) if d.get("alive") and not d.get("known"))
    if unk:
        c.add("lan", f"{_plural(unk, 'appareil non identifié', 'appareils non identifiés')} sur le réseau", min(4, 0.25 * unk),
              "Appareils présents en ce moment mais non identifiés (ni par InfraDash, ni marqués « connus » dans NetScan) : un intrus ou un objet oublié passe inaperçu.",
              f"Dans NetScan ({url}), nommer et marquer « connu » chaque appareil légitime ; isoler ou bloquer les autres sur la box.",
              "faible", "réseau local", "netscan:unknown", "Identifier les appareils inconnus")


def _r_forecasts(c):
    fc = STATE.get("derived", "forecasts")
    if not isinstance(fc, dict) or not isinstance(fc.get("items"), list):
        return False
    for it in fc["items"]:
        sev, fid = it.get("severity"), it.get("id", "")
        if sev not in ("warn", "crit") or _FC_SKIP.match(fid):
            continue
        if fid in ("nas.cache", "nas.dockerimg") and ({"nas.cache": "nas-cache", "nas.dockerimg": "docker-img"}[fid] in c.consumed):
            continue
        eta = it.get("eta_days")
        when = f" : seuil atteint dans {eta:.1f} j".replace(".", ",") if isinstance(eta, (int, float)) else ""
        if fid == "docker.restarts":
            fam, pts = "conteneurs", 3 if sev == "warn" else 6
        elif fid == "nas.disktemp":
            fam, pts = "materiel", 3 if sev == "warn" else 6
        else:
            fam, pts = "prevision", 3 if sev == "warn" else 8
        c.add(fam, f"Prévision — {it.get('title', fid)}{when}", pts, it.get("detail", ""),
              "Anticiper avant l'échéance (voir l'onglet Prévisions).", "moyen", "prévisions", f"fc:{fid}",
              f"Anticiper : {it.get('title', fid)}", sev)
    return True


# =====================================================================================================
# Calcul
# =====================================================================================================
def capped(s, cap):
    """Plafond progressif : linéaire jusqu'à 70 % du plafond, puis approche exponentielle (jamais au-delà)."""
    k, r = 0.7 * cap, 0.3 * cap
    return s if s <= k else k + r * (1 - math.exp(-(s - k) / r))


def _cat_score(items):
    sums = {}
    for it in items:
        sums[it["fam"]] = sums.get(it["fam"], 0) + it["raw"]
    f = 1.0
    for fam, s in sums.items():
        f *= 1 - capped(s, FAMILIES[fam][1]) / 100
    return 100 * f


def _global(scores, cats):
    w = sum(CAT_WEIGHT[c] for c in cats)
    return sum(CAT_WEIGHT[c] * scores[c] for c in cats) / w if w else 0.0


def compute():
    """Calcule les notes à partir de l'état courant (fonction pure vis-à-vis de STATE : aucune écriture)."""
    c = _Ctx()
    _r_hosts(c)
    _r_resources(c)
    _r_containers(c)
    v_ok, has_expo = _r_vulns(c)
    if not v_ok:
        _r_exposure_fallback(c)
    ins_ok = _r_insights(c, has_expo)
    _r_certs(c)
    _r_tailscale(c)
    bk_ok = _r_backups(c)
    _r_ups_array(c)
    _r_maint(c)
    _r_eol(c, STATE.get("slow", "vulns"))
    eg_ok = _r_egress(c)
    fc_ok = _r_forecasts(c)
    _r_netscan(c)

    avail = {"sante": True, "securite": True, "resilience": bk_ok or bool(_slow("nas")), "maintenance": True,
             "confidentialite": eg_ok}
    cats = [k for k, _, _ in CATEGORIES if avail[k]]
    by_cat = {k: [it for it in c.items if it["cat"] == k] for k in cats}
    scores = {k: _cat_score(by_cat[k]) for k in cats}
    g = _global(scores, cats)
    wsum = sum(CAT_WEIGHT[k] for k in cats) or 1

    # gains exacts (catégorie et global) + pénalités effectives réparties au prorata
    for k in cats:
        its = by_cat[k]
        sums = {}
        for it in its:
            sums[it["fam"]] = sums.get(it["fam"], 0) + it["raw"]
        eff = {f: capped(s, FAMILIES[f][1]) for f, s in sums.items()}
        tot = sum(eff.values()) or 1
        loss = 100 - scores[k]
        for it in its:
            it["penalty"] = round(loss * eff[it["fam"]] / tot * it["raw"] / sums[it["fam"]], 1)
            without = _cat_score([x for x in its if x is not it])
            it["gain"] = round(without - scores[k], 1)
            it["gain_global"] = round(CAT_WEIGHT[k] / wsum * (without - scores[k]), 2)

    # axes d'amélioration : regroupement par correction (fix_id), gain exact sur la note globale
    groups = {}
    for it in c.items:
        if it["cat"] in scores and it["fix"]:
            groups.setdefault(it["fix_id"], []).append(it)
    axes = []
    for fid, its in groups.items():
        new = dict(scores)
        for k in {it["cat"] for it in its}:
            new[k] = _cat_score([x for x in by_cat[k] if x not in its])
        gain = _global(new, cats) - g
        if gain < 0.05:
            continue
        lead = max(its, key=lambda x: (x["raw"], x["label"]))
        effort = max((it["effort"] for it in its), key=lambda e: EFFORT_W[e])
        cat_gain = {}
        for it in its:
            cat_gain[it["cat"]] = cat_gain.get(it["cat"], 0) + it["gain_global"]
        main_cat = max(cat_gain, key=lambda k: (cat_gain[k], k))
        crit = any(it["sev"] == "crit" for it in its)
        prio = "haute" if crit or gain >= 2.5 else "moyenne" if gain >= 0.75 or any(it["sev"] == "warn" for it in its) else "basse"
        labels = []
        for it in sorted(its, key=lambda x: -x["raw"]):
            if it["label"] not in labels:
                labels.append(it["label"])
        axes.append({
            "id": fid, "title": lead["axis"] or lead["fix"].split(".")[0][:120], "category": CAT_LABEL[main_cat],
            "category_id": main_cat, "categories": sorted(cat_gain, key=lambda k: -cat_gain[k]),
            "gain": round(gain, 1), "effort": effort, "detail": _cut(" · ".join(labels), 300), "action": lead["fix"],
            "priority": prio, "n_items": len(its), "ratio": round(gain / EFFORT_W[effort], 2),
        })
    axes.sort(key=lambda a: (-a["ratio"], -a["gain"], a["title"]))

    categories = []
    for k, lab, w in CATEGORIES:
        if k not in scores:
            continue
        sc = round(scores[k], 1)
        gr, glab = grade_of(sc)
        its = sorted(by_cat[k], key=lambda x: (-x["penalty"], x["label"]))
        partial = []
        if k == "securite" and not v_ok:
            partial.append("vulnérabilités pas encore analysées")
        if k == "sante" and not ins_ok:
            partial.append("diagnostics indisponibles")
        if k == "sante" and not fc_ok:
            partial.append("prévisions indisponibles")
        ncrit = sum(1 for it in its if it["sev"] == "crit")
        if not its:
            summ = "Aucun problème détecté."
        else:
            summ = f"{_plural(len(its), 'point')} à traiter" + (f" dont {ncrit} critique{'s' if ncrit > 1 else ''}" if ncrit else "") + \
                   f" ; principal : {its[0]['label']}."
        if partial:
            summ += " Note partielle : " + ", ".join(partial) + "."
        fams = {}
        for it in its:
            fams.setdefault(it["fam"], 0)
            fams[it["fam"]] += it["raw"]
        categories.append({
            "id": k, "label": lab, "weight": w, "score": sc, "grade": gr, "grade_label": glab, "summary": _cut(summ, 260),
            "partial": bool(partial),
            "families": [{"id": f, "label": FAMILIES[f][2], "raw": round(s, 1), "effective": round(capped(s, FAMILIES[f][1]), 1),
                          "cap": FAMILIES[f][1], "capped": s > 0.7 * FAMILIES[f][1]}
                         for f, s in sorted(fams.items(), key=lambda kv: -kv[1])],
            "items": [{"label": it["label"], "penalty": it["penalty"], "raw": it["raw"], "detail": it["detail"], "fix": it["fix"],
                       "gain": it["gain"], "gain_global": it["gain_global"], "effort": it["effort"], "source": it["source"],
                       "severity": it["sev"], "family": it["fam"], "fix_id": it["fix_id"]} for it in its],
        })
    gs = round(g, 1)
    gr, glab = grade_of(gs)
    ncrit = sum(1 for it in c.items if it["sev"] == "crit" and it["cat"] in scores)
    nwarn = sum(1 for it in c.items if it["sev"] == "warn" and it["cat"] in scores)
    weakest = min(categories, key=lambda x: x["score"]) if categories else None
    summ = (f"{_plural(ncrit, 'problème critique', 'problèmes critiques')}, {nwarn} à surveiller" +
            (f" ; point faible : {weakest['label'].lower()} ({weakest['grade']})." if weakest else "."))
    ai = STATE.get("derived", "ai") or {}
    unavailable = [{"id": k, "label": CAT_LABEL[k], "reason": "analyse des flux sortants indisponible" if k == "confidentialite"
                    else "données NAS indisponibles"} for k, _, _ in CATEGORIES if k not in scores]
    return {
        "global": {"score": gs, "grade": gr, "label": glab, "summary": summ, "n_crit": ncrit, "n_warn": nwarn},
        "categories": categories, "unavailable": unavailable, "axes": axes[:30],
        "inputs": {"insights": ins_ok, "backups": bk_ok, "vulns": v_ok, "forecasts": fc_ok, "egress": eg_ok,
                   "ai_etat": ((ai.get("result") or {}).get("etat_global") if isinstance(ai, dict) else None)},
        "method": "100 × Π(1 − P/100) sur les familles (P = Σ pénalités avec plafond progressif) ; globale = moyenne pondérée "
                  "(sécurité 30 %, résilience 25 %, santé 20 %, maintenance 15 %, confidentialité 10 %).",
    }


# =====================================================================================================
# Historique quotidien
# =====================================================================================================
_H = {"loaded": False, "points": [], "saved_t": 0, "saved_sig": None}


def _hist_load():
    if _H["loaded"]:
        return
    _H["loaded"] = True
    try:
        with open(HIST_FILE) as f:
            pts = json.load(f)
        if isinstance(pts, list):
            _H["points"] = [p for p in pts if isinstance(p, dict) and p.get("date")][-HIST_DAYS:]
    except (OSError, ValueError):
        pass


def _hist_update(res):
    _hist_load()
    today = datetime.now(TZ).strftime("%Y-%m-%d")
    pt = {"date": today, "global": res["global"]["score"]}
    sc = {c["id"]: c["score"] for c in res["categories"]}
    for k, _, _ in CATEGORIES:
        pt[k] = sc.get(k)
    pts = [p for p in _H["points"] if p["date"] != today] + [pt]
    pts.sort(key=lambda p: p["date"])
    _H["points"] = pts[-HIST_DAYS:]
    sig = json.dumps(pt, sort_keys=True)
    now = time.time()
    new_day = not _H["saved_sig"] or json.loads(_H["saved_sig"]).get("date") != today
    if sig != _H["saved_sig"] and (new_day or now - _H["saved_t"] >= 600):
        try:
            tmp = HIST_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(_H["points"], f, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, HIST_FILE)
            _H["saved_t"], _H["saved_sig"] = now, sig
        except OSError:
            pass
    return _H["points"]


def run():
    """Point d'entrée du runner (toutes les 60 s)."""
    if not (isinstance(STATE.get("derived", "insights"), list) or STATE.get("live", "nas")):
        # démarrage : rien de collecté, une note vaudrait 100 à tort -> pas de note (le front affiche « calcul en cours »)
        _hist_load()
        res = {"pending": True, "history": _H["points"], "t": time.time()}
        STATE.set("derived", "scores", res)
        return res
    res = compute()
    res["history"] = _hist_update(res)
    res["t"] = time.time()
    STATE.set("derived", "scores", res)
    return res


__all__ = ["run", "compute", "grade_of", "CATEGORIES", "FAMILIES"]
