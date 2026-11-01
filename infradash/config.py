"""Configuration de l'infra et base de connaissances (descriptions des tâches planifiées)."""
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE, "data")
STATIC_DIR = os.path.join(BASE, "static")

LISTEN_HOST = os.environ.get("INFRADASH_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("INFRADASH_PORT", "7070"))

# Réseaux autorisés à consulter le dashboard (LAN + Tailscale + local)
ALLOWED_NETS = ["127.0.0.0/8", "192.168.2.0/24", "100.64.0.0/10", "::1/128", "fd7a:115c:a1e0::/48", "172.16.0.0/12"]

VM_URL = "http://127.0.0.1:8428"
CADVISOR_URL = "http://127.0.0.1:8081"

SSH_KEY = os.path.expanduser("~/.ssh/id_ed25519")

HOSTS = {
    "homelab": {
        "label": "Homelab", "hostname": "homelab-netnode", "ip": "192.168.2.4", "ts_ip": "100.115.23.106",
        "role": "Réseau, DNS & supervision", "os": "Debian 13 (trixie)", "icon": "server",
        "hw": "4 vCPU · 7,6 Go RAM · NVMe 220 Go",
    },
    "nas": {
        "label": "NAS Unraid", "hostname": "TCASTELNAS", "ip": "192.168.2.3", "ts_ip": "100.69.109.39",
        "role": "Stockage, médias, applis métier", "os": "Unraid 7.3.2", "icon": "nas",
        "hw": "i5-10500 · 64 Go RAM · RTX 3060 · 36 To",
        "ssh": {"user": "root", "host": "192.168.2.3", "port": 22},
        "node_exporter": "http://192.168.2.3:9100/metrics",
    },
    "clawhost": {
        "label": "clawhost", "hostname": "clawhost", "ip": "192.168.2.5", "ts_ip": "100.124.33.85",
        "old_ips": ["192.168.2.180"],
        "role": "Agent OpenClaw, Netscan, FitCoach", "os": "Ubuntu 24.04", "icon": "claw",
        "hw": "SSD 112 Go + 2×2,7 To + 1,8 To",
        "ssh": {"user": "openclaw", "host": "192.168.2.5", "port": 2211},
        "probes": [
            {"port": 2211, "name": "SSH", "kind": "tcp"},
            {"port": 18789, "name": "OpenClaw Gateway", "kind": "http", "path": "/health"},
            {"port": 3000, "name": "Netscan web", "kind": "http", "path": "/"},
            {"port": 18790, "name": "OpenClaw (aux.)", "kind": "tcp"},
            {"port": 8300, "name": "FitCoach", "kind": "tcp"},
        ],
    },
}

# Autres équipements connus (topologie)
KNOWN_IPS = {
    "192.168.2.1": ("box", "Routeur / Box"),
    "192.168.2.3": ("nas", "NAS Unraid"),
    "192.168.2.4": ("homelab", "Homelab"),
    "192.168.2.5": ("clawhost", "clawhost"),
    "192.168.2.180": ("clawhost-old", "clawhost (ancienne IP)"),
    "192.168.2.208": ("pc", "PC fixe Jeff"),
    "192.168.2.240": ("ha", "Home Assistant (VM)"),
    "192.168.2.164": ("ha-old", "Home Assistant (ancienne IP)"),
}

# Ports bien connus -> protocole (couleur des flux)
PORT_PROTO = {
    22: "ssh", 2211: "ssh", 2222: "ssh", 445: "smb", 139: "smb", 53: "dns", 80: "http", 443: "https",
    8443: "https", 3000: "http", 9100: "metrics", 8428: "metrics", 8081: "metrics", 41641: "tailscale",
    5432: "db", 5433: "db", 5439: "db", 6379: "db", 6380: "db", 16379: "db", 11434: "ai", 18789: "ai",
    8097: "media", 8096: "media", 9090: "media", 8112: "torrent", 58846: "torrent", 8080: "http",
}

# Descriptions des services NAS (nom de conteneur -> description courte)
CONTAINER_INFO = {
    "arrmada": ("Gestion *arr maison (frontend+API)", "apps"),
    "arrmada-db": ("Postgres d'Arrmada", "db"),
    "eufy-security-ws": ("Passerelle caméras Eufy -> Home Assistant", "domotique"),
    "ollama": ("LLM local (GPU RTX 3060)", "ia"),
    "binhex-jellyfin-1": ("Serveur média Jellyfin", "media"),
    "bazarr": ("Sous-titres automatiques", "media"),
    "binhex-delugevpn": ("Torrent derrière VPN", "download"),
    "homepage": ("Page d'accueil des services", "infra"),
    "boussole-worker-1": ("Boussole — worker", "apps"),
    "boussole-app-1": ("Boussole — appli", "apps"),
    "boussole-db-1": ("Boussole — Postgres", "db"),
    "vaultwarden": ("Coffre de mots de passe", "securite"),
    "faimilymeal": ("Menus familiaux (menu.jposyno.eu)", "apps"),
    "faimilymeal-db": ("Postgres FaimilyMeal", "db"),
    "binhex-prowlarr": ("Indexeurs *arr", "download"),
    "Nginx-Proxy-Manager-Official": ("Reverse proxy public *.jposyno.eu", "infra"),
    "binhex-sonarr": ("Séries", "download"),
    "binhex-radarr": ("Films", "download"),
    "flaresolverr": ("Contournement Cloudflare pour Prowlarr", "download"),
    "binhex-sabnzbd": ("Usenet", "download"),
    "searcharr": ("Bot Telegram de recherche *arr", "download"),
    "homeos-backend": ("HomeOS — API", "apps"),
    "homeos-frontend": ("HomeOS — interface", "apps"),
    "homeos-postgres": ("HomeOS — Postgres pgvector", "db"),
    "homeos-redis": ("HomeOS — Redis", "db"),
    "aura-dashboard": ("Aura Metrics — dashboard", "apps"),
    "aura-app": ("Aura Metrics — API (sb.jposyno.eu)", "apps"),
    "aura-worker": ("Aura — worker Celery", "apps"),
    "aura-beat": ("Aura — planificateur Celery beat", "apps"),
    "aura-redis": ("Aura — Redis", "db"),
    "aura-db": ("Aura — Postgres", "db"),
    "tjm-backend": ("Calculateur TJM", "apps"),
    "tjm-db": ("Postgres TJM", "db"),
    "nexus": ("Nexus — supervision perso / OpenClaw", "infra"),
    "nexus-db": ("Postgres Nexus", "db"),
    "nexus-redis": ("Redis Nexus", "db"),
    "jprod-workers": ("J.Prod HQ — workers", "apps"),
    "jprod-web": ("J.Prod HQ — production", "apps"),
    "jprod-redis": ("Redis J.Prod", "db"),
    "ao-match-worker": ("AO Match — worker", "apps"),
    "ao-match-web": ("AO Match — web (aomatch.jposyno.eu)", "apps"),
    "ao-match-redis": ("Redis AO Match", "db"),
    "ao-match-postgres": ("Postgres AO Match", "db"),
    "ao-match-browserless": ("Chromium headless pour scraping", "apps"),
    "aishoppinglist-scraper": ("Scraper liste de courses IA", "apps"),
    "forgejo": ("Forge Git auto-hébergée", "dev"),
    "pegasus-redis": ("Redis Pegasus", "db"),
    "pegasus-db": ("TimescaleDB Pegasus (analytics/ML)", "db"),
    "immich_server": ("Photos & vidéos Immich", "media"),
    "immich_postgres": ("Postgres Immich", "db"),
    "immich_redis": ("Redis Immich", "db"),
    "n8n": ("Automatisation n8n", "apps"),
    # homelab
    "adguardhome": ("DNS du réseau + blocage pubs", "infra"),
    "unbound": ("Résolveur DNS récursif (amont d'AdGuard)", "infra"),
    "uptime-kuma": ("Supervision de disponibilité", "infra"),
    "speedtest-tracker": ("Speedtest toutes les 3 h", "infra"),
    "dozzle": ("Logs Docker en direct", "infra"),
    "victoriametrics": ("Base de métriques (rétention 12 mois)", "infra"),
    "grafana": ("Dashboards de métriques", "infra"),
    "node-exporter": ("Métriques système du homelab", "infra"),
    "cadvisor": ("Métriques des conteneurs", "infra"),
    "speedtest-prom-bridge": ("Exporte les speedtests vers VictoriaMetrics", "infra"),
    "infra-dashboard": ("Ce dashboard", "infra"),
}

# --- Descriptions des tâches planifiées --------------------------------------------
# (motif regex sur la commande, titre, description, catégorie)
CRON_KB = [
    (r"backup-homelab\.sh", "Sauvegarde homelab",
     "Archive /opt/homelab (bases SQLite copiées à chaud), garde 7 archives locales, copie SMB vers NAS backups/homelab-netnode (30 gardées), signale le résultat à Uptime Kuma.", "backup"),
    (r"dockerupdate check", "Vérif. mises à jour Docker", "Unraid vérifie si de nouvelles images existent pour les conteneurs (notification seulement).", "maintenance"),
    (r"dynamix/scripts/monitor", "Moniteur système Unraid", "Contrôle températures, SMART, remplissage des disques et génère les notifications Unraid.", "supervision"),
    (r"mover start", "Mover Unraid", "Déplace les fichiers du cache NVMe vers l'array de disques (libère le cache).", "stockage"),
    (r"mdcmd check", "Contrôle de parité", "Lecture complète des 9 disques pour vérifier la parité (P+Q). Dure ~2 jours, charge élevée.", "stockage"),
    (r"plugincheck", "Vérif. plugins", "Recherche de mises à jour des plugins Unraid.", "maintenance"),
    (r"recyclarr\.sh sync sonarr", "Recyclarr → Sonarr", "Synchronise les profils qualité/scores TRaSH vers Sonarr.", "media"),
    (r"recyclarr\.sh sync radarr", "Recyclarr → Radarr", "Synchronise les profils qualité/scores TRaSH vers Radarr.", "media"),
    (r"ssd_trim", "TRIM SSD", "TRIM du cache NVMe (entretien des performances SSD).", "stockage"),
    (r"statuscheck", "Bilan état de l'array", "Rapport quotidien d'état des disques Unraid.", "supervision"),
    (r"unraidcheck", "Vérif. version Unraid", "Recherche de mise à jour de l'OS Unraid.", "maintenance"),
    (r"updateDocker\.php", "Auto-update conteneurs", "CA Auto Update : met à jour ET redémarre les conteneurs ayant une nouvelle image. Source fréquente de surprises le matin.", "maintenance"),
    (r"updateApplications\.php", "Auto-update plugins", "Met à jour automatiquement les plugins Unraid.", "maintenance"),
    (r"disklocation/pages/cronjob\.php start silent", "Disk Location : SMART", "Relève SMART et état d'alimentation des disques.", "supervision"),
    (r"cronjob\.php start status", "Disk Location : état", "Relève l'état de veille des disques.", "supervision"),
    (r"cronjob\.php start syslogread", "Disk Location : syslog", "Analyse le syslog pour les événements disques.", "supervision"),
    (r"page_system\.php backup", "Disk Location : sauvegarde", "Sauvegarde de la base du plugin Disk Location.", "backup"),
    (r"benchmark\.php", "Disk Location : benchmark", "Benchmark mensuel des disques.", "stockage"),
    (r"sa1 1 1", "Collecte statistiques", "Collecte sysstat pour les graphes du plugin System Stats.", "supervision"),
    (r"ArrMada Audio Stripper", "ArrMada : nettoyage audio", "Supprime les pistes audio inutiles des MKV (mkvmerge) dans les bibliothèques.", "media"),
    (r"Bilan Hebdo ArrMada", "ArrMada : bilan hebdo", "Génère le résumé hebdomadaire ArrMada.", "media"),
    (r"forgejo-backup-daily", "Sauvegarde Forgejo", "Dump complet Forgejo (DB, dépôts, config, LFS) vers backups/forgejo en .tar.zst.", "backup"),
    (r"healthchecksh", "Healthcheck NAS", "Relevé JSON : charge, réseau, disques, températures, GPU, top Docker, SMART horaire.", "supervision"),
    (r"run-parts /etc/cron\.hourly", "cron.hourly", "Scripts horaires (User Scripts « hourly »).", "systeme"),
    (r"run-parts /etc/cron\.daily", "cron.daily", "Scripts quotidiens (logrotate, tailscale-daily, User Scripts « daily »).", "systeme"),
    (r"run-parts /etc/cron\.weekly", "cron.weekly", "Scripts hebdo (User Scripts « weekly » : suppression .DS_Store).", "systeme"),
    (r"run-parts /etc/cron\.monthly", "cron.monthly", "Scripts mensuels.", "systeme"),
    (r"api/digest", "AO Match : digest", "Envoie le digest quotidien des appels d'offres.", "apps"),
    (r"scan-rss", "AO Match : scan RSS", "Scanne les flux RSS d'appels d'offres (jours ouvrés).", "apps"),
    (r"daily-pipeline\.sh collect", "Pegasus : collecte", "Pipeline quotidien Pegasus (collect → predict → notify) via webhook.", "apps"),
    (r"daily-pipeline\.sh post-mortem", "Pegasus : post-mortem", "Analyse des résultats du jour.", "apps"),
    (r"daily-pipeline\.sh train", "Pegasus : entraînement", "Ré-entraînement hebdomadaire du modèle.", "apps"),
    (r"daily-pipeline\.sh fetch-results", "Pegasus : résultats", "Récupère les résultats toutes les 30 min en journée.", "apps"),
    (r"e2scrub_all", "e2scrub", "Vérification en ligne des systèmes de fichiers ext4 sur LVM.", "systeme"),
    (r"anacron", "anacron", "Rattrape les tâches cron.daily/weekly/monthly manquées.", "systeme"),
    (r"logrotate", "logrotate", "Rotation et compression des journaux.", "systeme"),
    (r"apt-daily-upgrade", "Mises à jour auto (install)", "unattended-upgrades installe les correctifs de sécurité.", "maintenance"),
    (r"apt-daily", "Mises à jour auto (téléchargement)", "Télécharge les listes de paquets et mises à jour.", "maintenance"),
    (r"dpkg-db-backup", "Sauvegarde base dpkg", "Copie de /var/lib/dpkg (liste des paquets).", "backup"),
    (r"fwupd-refresh", "Firmware (fwupd)", "Vérifie les mises à jour de firmware.", "maintenance"),
    (r"man-db", "man-db", "Régénère l'index des pages de manuel.", "systeme"),
    (r"systemd-tmpfiles-clean", "Nettoyage /tmp", "Purge des fichiers temporaires.", "systeme"),
    (r"fstrim", "fstrim", "TRIM hebdomadaire du SSD NVMe.", "stockage"),
    (r"backup-openclaw", "Sauvegarde clawhost", "Sauvegarde quotidienne de clawhost vers NAS backups/clawhost (/etc, config et état OpenClaw, dump Netscan, projets).", "backup"),
    (r"speedtest", "Speedtest", "Test de débit Internet (Speedtest Tracker) exporté vers VictoriaMetrics.", "supervision"),
    (r"infradash-watchdog", "Watchdog dashboard", "Relance ce dashboard s'il n'est plus actif.", "supervision"),
    (r"delete\.ds_store", "Suppression .DS_Store", "Supprime les fichiers .DS_Store créés par macOS sur l'array.", "maintenance"),
    (r"set_max_map_count", "vm.max_map_count", "Règle vm.max_map_count au démarrage (requis par certains conteneurs).", "systeme"),
]
_CRON_KB = [(re.compile(p, re.I), t, d, c) for p, t, d, c in CRON_KB]


def describe(command):
    for rx, title, desc, cat in _CRON_KB:
        if rx.search(command or ""):
            return title, desc, cat
    short = (command or "").strip().split()
    title = os.path.basename(short[0]) if short else "tâche"
    return title, "", "autre"


# Tâches connues mais non lisibles en direct (crontab root du homelab protégée)
HOMELAB_STATIC_CRONS = [
    {"schedule": "30 3 * * *", "user": "root", "source": "crontab root",
     "command": "/usr/local/bin/backup-homelab.sh 2>&1 | logger -t backup-homelab",
     "note": "Lu lors de l'installation (crontab root non lisible sans sudo) ; exécution vérifiée via la fraîcheur des archives sur le NAS."},
]

# Planifications internes aux conteneurs (homelab)
HOMELAB_CONTAINER_SCHEDULES = [
    {"schedule": "0 */3 * * *", "user": "speedtest-tracker", "source": "conteneur", "command": "speedtest (SPEEDTEST_SCHEDULE)"},
]

# Chaînes de sauvegarde connues : (id, libellé, source, destination, dossier NAS, rétention, fréquence max attendue en h)
BACKUP_CHAINS = [
    {"id": "homelab", "label": "Homelab → NAS", "from": "homelab", "to": "nas",
     "src": "/opt/homelab (compose, AdGuard, Kuma, Grafana, Speedtest, VM config)",
     "dest": "/var/backups/homelab (7) + NAS backups/homelab-netnode (30)", "nas_dir": "homelab-netnode",
     "pattern": "homelab_backup_*.tar.gz", "max_age_h": 26, "when": "03:30 chaque nuit", "method": "tar.gz + SMB"},
    {"id": "clawhost", "label": "clawhost → NAS", "from": "clawhost", "to": "nas",
     "src": "/etc, config + état OpenClaw, dump Postgres Netscan, projets, inventaire",
     "dest": "NAS backups/clawhost/AAAA-MM-JJ_HHMM", "nas_dir": "clawhost", "pattern": "dirs",
     "max_age_h": 26, "when": "03:30 (+0–15 min) chaque nuit", "method": "timer systemd + CIFS"},
    {"id": "forgejo", "label": "Forgejo → backups", "from": "nas", "to": "nas",
     "src": "Forgejo (DB SQLite, dépôts, LFS, config)", "dest": "NAS backups/forgejo (.tar.zst)",
     "nas_dir": "forgejo", "pattern": "forgejo-backup-*.tar.zst", "max_age_h": 26, "when": "04:00 chaque nuit", "method": "forgejo dump + zstd"},
    {"id": "appdata", "label": "Appdata NAS", "from": "nas", "to": "nas",
     "src": "/mnt/user/appdata (bases de toutes les applis)", "dest": "NAS backups/appdata",
     "nas_dir": "appdata", "pattern": "any", "max_age_h": 26 * 7, "when": "désactivé", "method": "User Script backup_appdata (désactivé)"},
]
