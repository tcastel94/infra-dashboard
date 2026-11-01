# InfraDash

Dashboard temps réel du homelab, du NAS Unraid et de clawhost.

**URL :** http://192.168.2.4:7070 (LAN) · http://100.115.23.106:7070 (Tailscale)

## Principe

- **Lecture seule par défaut.** Les collecteurs n'exécutent que des chaînes fixes (`cat`, `grep`, `ss`, `docker ps/inspect`, `smbstatus`…), aucune entrée du navigateur n'est transmise. Seule exception, **désactivée tant qu'on ne l'active pas** : l'exécution des commandes du plan de correction (voir « Exécution sécurisée » plus bas).
- **Sans dépendance.** Python 3 standard (pas de pip) + ECharts embarqué (`static/vendor`). Fonctionne sans Internet côté navigateur (les polices Google sont optionnelles).
- **Basse priorité.** Le serveur tourne sous `jeff` avec `nice 10` et `ionice idle` (~35 Mo de RAM).
- **Accès limité** au LAN `192.168.2.0/24`, à Tailscale (`100.64.0.0/10`) et à localhost ; les autres IP reçoivent 403.
- **Secrets masqués** dans les commandes cron affichées (mots de passe, jetons, URL push…).

## Sources de données

| Machine | Comment | Fréquence |
|---|---|---|
| Homelab | `/proc`, `/sys`, `ss`, cAdvisor (127.0.0.1:8081), timers systemd, `/etc/cron*`, `apt-get -s` | 2 s → 6 h |
| NAS | SSH root par clé (ControlMaster, une seule connexion) : `/proc`, cgroups, netns des conteneurs, conntrack, `var.ini`/`disks.ini`, Docker, UPS, GPU, capteurs, SMB, crons, User Scripts, NPM | 3 s → 20 min |
| clawhost | Sondes TCP/HTTP (2211, 18789, 3000, 18790, 8300), ping, Tailscale, sauvegarde nocturne sur le NAS (`/etc`, inventaire) | 10 s → 1 h |
| Réseau | Tailscale, table ARP, domaines `*.jposyno.eu` (HTTP + TLS), liens Homepage, latences, speedtest (VictoriaMetrics) | 5 s → 30 min |

Les métriques du NAS et de clawhost sont aussi **écrites dans VictoriaMetrics** (préfixe `infradash_*`, écriture additive via `/api/v1/import/prometheus`) : historique 12 mois et utilisables dans Grafana.

## Vues

Vue d'ensemble (notes + KPI) · **Notes & axes** (santé, sécurité, résilience, maintenance, confidentialité, axes d'amélioration chiffrés, centre d'alertes) · Flux live (topologie, galaxies `#flows/nas`, `#flows/homelab`) · Machines · **Port Docker** (un terminal portuaire par machine) · **Vulnérabilités** (CVE + fins de vie corrélées aux versions réelles, plan de correction) · **Flux sortants** (carte du monde, risques, règles de blocage) · **IA & prévisions** (Ollama local + prévisions déterministes) · Planning & crons · Stockage & montages · Sauvegardes · Réseau & exposition · Diagnostics · Journal.

## Sécurité, vulnérabilités, confidentialité

- **Vulnérabilités** (`infradash/vulns.py`, toutes les 12 h) : inventaire des versions (paquets Debian du homelab, conteneurs et services du NAS, bannière SSH et build OpenClaw de clawhost) corrélé à OSV.dev, aux advisories GitHub (Vaultwarden, Immich, Jellyfin, OpenClaw), à endoflife.date, au catalogue CISA KEV et aux scores EPSS. Seuls des noms de logiciels et des numéros de version sont envoyés. L'analyse tourne dans un processus séparé ; caches dans `data/vuln-*.json`.
  - **Revérifier** (bouton en haut du plan, ou sur chaque action) : relit tout de suite les versions installées des 3 machines et refait l'analyse complète (~10 s grâce aux caches), puis affiche un bilan avant / après : actions résolues, améliorées, aggravées, nouvelles, et « à confirmer » quand une machine, Docker ou cAdvisor n'a pas pu être relu (jamais de faux « corrigé »). Une revérification à la fois, 60 s minimum entre deux, 12 par heure au plus. API : `POST /api/vulns/refresh` (en-tête `X-InfraDash: 1`, corps facultatif `{"focus": "<id d'action>"}`), `GET /api/vulns/refresh`. Bilan conservé dans `data/vuln-refresh.json`. Sans clic, l'inventaire horaire relance aussi l'analyse dès qu'une version, une exposition, un constat de configuration ou le noyau installé change.
  - **Commandes du plan de correction** (règles déterministes de `vulns.py`, pas l'IA) : déduites de ce qui est réellement déclaré sur le NAS — lignes `FROM` / `ARG` globaux des Dockerfiles et clés `image` / `build` / `container_name` des docker-compose (rien d'autre n'est lu : ni environnement ni secrets). Une branche en fin de vie n'est jamais « corrigée » par un `pull` ou un `build --pull` du même tag : la commande modifie la ligne `FROM` ou le tag (`sed -i.bak`, copie conservée), et pour un produit (Forgejo…) télécharge la nouvelle image, sauvegarde à froid le projet dans `/mnt/user/backups`, puis redémarre. Cible conseillée : la plus ancienne branche (LTS de préférence) encore soutenue au moins 12 mois. Un conteneur créé hors compose mais déclaré dans un projet (`container_name`) est recréé depuis ce fichier. Avant de proposer un `pull`, le dashboard lit la configuration de l'image publiée sur son registre (Docker Hub, ghcr.io, codeberg.org…, accès anonyme, cache 6 h, seul le nom de l'image est envoyé) : si elle contient encore la même version, l'action devient « Attendre une image corrigée… » sans commande.
  - Les onglets ouverts se rechargent seuls après un déploiement (empreinte `build` dans le flux) ; un client qui redemande `/api/vulns` en boucle est freiné côté serveur.
- **Flux sortants** (`infradash/egress.py`, toutes les 30 s) : conntrack du NAS (hôte, conteneurs, VM) et sockets de l'hôte homelab, géolocalisation **hors ligne** (DB-IP Lite pays, CC BY 4.0 — iptoasn — plages AWS/GCP) dans `data/geo/`, reverse DNS via AdGuard. Aucune IP contactée n'est envoyée à un tiers.
- **Notes & alertes** (`infradash/scores.py`, `infradash/alerts.py`) : barème déterministe documenté dans le code ; alertes dédupliquées avec acquittement. **Notification Unraid** désactivée par défaut, activable dans « Notes & axes » : c'est la seule écriture possible sur le NAS (script officiel `notify`, 10 envois / 24 h max).

## IA locale

`infradash/ai.py` interroge l'Ollama du NAS (`gemma4:e4b` avec réflexion, repli `qwen2.5:3b`) toutes les 3 h, après un nouveau problème critique, ou à la demande (~40 s sur la RTX 3060, ~3,1 Go de VRAM). Méthode v5 : le dashboard fournit des faits, actions et points positifs vérifiés et numérotés ; l'IA ne peut citer que ces identifiants (imposés par la grammaire JSON) et rédige le raisonnement (regroupement en risques, enchaînements, ordre du plan). Le dashboard recale ensuite horizon et probabilité sur les échéances réelles, ajoute toute priorité oubliée (« ajouté par le dashboard »), place la sauvegarde avant toute mise à jour majeure, coupe proprement les textes tronqués et remplace une justification attribuée à la mauvaise action. Garde-fous : rien n'est lancé si le conteneur Ollama n'a pas le GPU (runtime `nvidia`), si le GPU est occupé (> 40 %, transcodage Jellyfin) ou si la VRAM manque ; modèle déchargé 2 min après ; une analyse à la fois ; aucune commande exécutée. Variables : `INFRADASH_AI_MODEL`, `INFRADASH_AI_EVERY_H`, `INFRADASH_AI_THINK=0` (désactive la réflexion).

> Si l'auto-update recrée le conteneur Ollama sans GPU : Unraid → Docker → ollama → Edit → Extra Parameters `--runtime=nvidia` → Apply.

## Exploitation

```bash
# Démarrer (sans effet s'il tourne déjà)
~/infra-dashboard/run.sh &

# Arrêter
kill "$(cat ~/infra-dashboard/data/infradash.pid)"

# Journal
tail -f ~/infra-dashboard/logs/infradash.log
```

### Démarrage automatique (à activer une fois)

```bash
~/infra-dashboard/install-autostart.sh
```

Ajoute à la crontab de `jeff` un `@reboot` et un watchdog toutes les 2 min (verrou `flock` : jamais deux instances ; relance si l'API ne répond plus 3 fois de suite). Aucun droit root nécessaire.

### Métriques complètes de clawhost (optionnel)

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub -p 2211 openclaw@192.168.2.5
```

Le dashboard bascule automatiquement en collecte complète (CPU, RAM, réseau, conteneurs) dans les 10 minutes.

### Désinstallation

```bash
crontab -l | grep -v infradash-watchdog | crontab -
kill "$(cat ~/infra-dashboard/data/infradash.pid)"
rm -rf ~/infra-dashboard
# séries VictoriaMetrics (optionnel) :
curl -s 'http://127.0.0.1:8428/api/v1/admin/tsdb/delete_series?match[]={__name__=~"infradash_.*"}'
```

## Arborescence

```
server.py              serveur HTTP + SSE, planification des collecteurs
run.sh                 lanceur/watchdog (flock, nice, ionice, rotation du log)
infradash/config.py    machines, descriptions des tâches et des conteneurs, chaînes de sauvegarde
infradash/homelab.py   collecte locale        infradash/nas.py     collecte NAS (SSH)
infradash/claw.py      sondes clawhost        infradash/network.py Tailscale, LAN, public, TLS
infradash/model.py     planning, sauvegardes, topologie des flux, diagnostics
infradash/vm.py        VictoriaMetrics (écriture + historique)
infradash/vulns.py     vulnérabilités (+ cvss.py)    infradash/egress.py  flux sortants (+ egress_kb.py)
infradash/scores.py    notes & axes                  infradash/alerts.py  centre d'alertes, notification Unraid
infradash/forecast.py  prévisions                    infradash/ai.py      IA locale (Ollama)
static/                interface (HTML/CSS/JS, ECharts embarqué)
data/                  journal d'événements persistant, verrou, socket SSH
```

## Actions, NetScan et accès clawhost (2026-10-25)
- **Axes d'amélioration** (`infradash/actions.py`) : boutons pour les actions sûres — diagnostics en lecture seule sur le NAS (SMART sans réveiller les disques, arrêts brutaux, onduleur, Appdata Backup) et pause / reprise du contrôle de parité via le script officiel d'Unraid `parity_control` (confirmation demandée, tracé dans le journal). Le reste a un **mode opératoire** pas à pas (copie hors site, Appdata Backup, onduleur, cause des erreurs de parité). `POST /api/actions/run {"id": …}`, résultats dans `data/actions.json`.
- **Réseau local** (`infradash/netscan.py`, vue `#lan`) : lit l'API NetScan (clawhost :3000) en lecture seule. Identifiants dans `~/.config/infradash/netscan.json` (`{"url","username","password"}`, mode 600) ; le cookie de session reste en mémoire ; un refus d'identifiants suspend les essais jusqu'à modification du fichier. Constats « élevés » → alertes, constats et appareils inconnus → note Sécurité, faits pour l'IA.
- **clawhost en SSH lecture seule** : clé dédiée `~/.ssh/infradash_clawhost`, à autoriser une fois avec `ssh -p 2211 openclaw@192.168.2.5 'bash -s' < tools/clawhost-ro-setup.sh` (restrict, from=192.168.2.4, commande imposée `~/.infradash/ro.sh` : « metrics » et « inventory »).

### Remettre NetScan en route (clawhost, compte jeff)
NetScan ne lance aucun scan tout seul (`SCAN_INTERVAL_MIN` n'est lu nulle part) et son `.env` visait `192.168.50.0/24` (ancien sous-réseau de l'ASUS).
1. `cd "$(docker inspect netscan-worker --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}')"`
2. `cp .env .env.bak-$(date +%F)` puis `sed -i 's|^SUBNET_ALLOWLIST=.*|SUBNET_ALLOWLIST=192.168.2.0/24|' .env`
3. `docker compose up -d --force-recreate worker web` (web lit aussi la liste pour le bouton « Scanner maintenant »)
4. Clore le scan bloqué : `docker exec netscan-db psql -U netscan -d netscan -c "UPDATE scans SET status='failed', finished_at=now() WHERE status IN ('running','pending') AND started_at < now() - interval '3 hours'; UPDATE scan_jobs SET status='failed' WHERE status IN ('picked','pending');"`
5. Premier scan : bouton « Scanner maintenant » de NetScan, suivi avec `docker logs -f netscan-worker` jusqu'à `worker.scan_done`.
6. Scan régulier : `crontab -e` → `0 */2 * * * docker exec netscan-db psql -U netscan -d netscan -qc "INSERT INTO scan_jobs (subnet) VALUES ('192.168.2.0/24')"`

## Réseau local, ports, architecte, exécution sécurisée (2026-10-31)

### Réseau local : scanner, nommer, liaison Ethernet / Wi-Fi (`infradash/lan.py`, vue `#lan`)
- **Bouton « Scanner le réseau »** : balayage du /24 du homelab (ping + résolution ARP du noyau, sans outil externe ni root, ~15 s), latence/gigue/perte, nom DNS inverse ; avec la case « sondage des ports » : 38 ports TCP courants + bannières SSH/web. Le sous-réseau n'est pas un paramètre. Découverte légère automatique toutes les 5 min, sondage de ports toutes les 6 h.
- **Registre** `data/devices.json` (MAC → nom, icône, famille, note, « de confiance », première vue). Au premier passage tout est enregistré comme existant ; ensuite un appareil jamais vu déclenche l'événement « Nouvel appareil sur le réseau » et le badge « nouveau » jusqu'à ce que vous le validiez (enregistrer sa fiche vaut validation).
- **Fiche d'appareil** (clic sur une tuile) : nom, 22 icônes, famille, note, confiance, type de liaison forcé ; identité (IP, MAC — « aléatoire » pour le Wi-Fi privé des téléphones —, fabricant, DNS, NetScan), services ouverts avec les ports à risque (Telnet, FTP, RDP, VNC, RTSP, MQTT, ADB…), CVE, historique.
- **Ethernet / Wi-Fi** : manuel > interface locale lue dans /sys (homelab) ou par SSH (NAS : eth0 2,5 Gb/s) > faisceau d'indices (NetScan, MAC aléatoire, latence et gigue). Chaque fiche liste ses preuves et signale les contradictions. Le débit de liaison Wi-Fi (PHY) et le signal ne sont connus que du routeur : ils ne sont **pas inventés** ; sont affichés le débit négocié des machines câblées, la latence, la gigue et le débit réellement échangé avec le NAS.

### Ports (`infradash/ports.py`, vue `#ports`)
NAS (SSH : `ss -tulnp`, `docker ps -a`, PortBindings), homelab (`ss` + docker-compose) et clawhost (connexion TCP 1-10000 depuis le homelab, son SSH restant restreint). Par port : interface (toutes / LAN / local / Tailscale), service, conteneur propriétaire, publication Internet via NPM. **Ports réservés** par des conteneurs arrêtés et **conflits** (ex. un conteneur arrêté dont le port a été pris : il ne redémarrera plus). **Ports libres** par bande (3000-3999, 8000-8999…) hors plage éphémère du noyau, et recherche `GET /api/ports/free?host=nas&from=8000&to=8099&n=20`.

### Architecte IA (`infradash/architect.py`, vue `#architect`)
Des règles vérifiables détectent les incohérences (bases ouvertes au LAN, conflits de ports, conteneurs en réseau host, tags flottants avec mises à jour automatiques, objets connectés à plat avec les serveurs, services à risque, machines d'infrastructure en Wi-Fi, appareils jamais validés…) ; chaque constat a des preuves et une correction vérifiée, **disponibles sans IA**. Le bouton « Analyser l'architecture » envoie ces constats + ceux du diagnostic général à l'Ollama du NAS (mêmes garde-fous GPU que `ai.py`) avec un prompt d'architecte principal : regrouper par cause, principe d'architecture violé, état cible, 2 à 5 étapes, vérification, retour arrière, arbitrage gain/effort/risque, « à ne pas faire ». L'IA ne peut citer que des identifiants fournis ; priorité, famille et niveau global sont recalés par le dashboard sur la gravité mesurée, et toute priorité oubliée est ajoutée avec sa correction vérifiée. ~2 à 3 min, 5 min minimum entre deux demandes. Rien n'est exécuté.

### Exécution sécurisée des corrections (`infradash/remedy.py`)
**Désactivée par défaut.** Activation une fois : `python3 ~/infra-dashboard/tools/exec-setup.py` (phrase secrète de 12 caractères minimum, stockée hachée scrypt dans `~/.config/infradash/exec.json`, mode 600 exigé ; `--disable` pour couper).
1. Le navigateur n'envoie jamais de commande : un identifiant d'action du plan et un numéro. Le serveur relit la commande qu'il a lui-même générée.
2. Grammaire stricte, jeton par jeton, sans shell pour l'interpréter : `cd` dans `/mnt/user/appdata` ou `/opt/homelab`, `docker compose pull | build --pull | up -d | stop | logs`, `docker pull`, `docker rm -f` d'un conteneur connu, `sed -i.bak -E` avec une seule substitution `s#…#…#` (pas de drapeau `e`/`w`, pas de changement de version d'une base de données), `tar` vers `/mnt/user/backups`, `sleep ≤ 120`. Tout le reste est refusé avec la raison (testé : injections `;`, `$()`, tubes, `..`, `docker run`, drapeaux sed…). Chaque étape est reconstruite avec `shlex.quote`.
3. **Deux temps** : « Préparer » = vérifications en lecture seule (NAS joignable, dossier et compose présents, services existants, espace disque, parité en cours, **images actuelles conservées** pour revenir en arrière) ; puis « Exécuter » exige l'empreinte du plan affiché **et** la phrase secrète. Plan valable 10 min, usage unique ; si le plan de correction a changé entre-temps, refus.
4. Verrouillage 15 min après 5 phrases fausses ; une exécution à la fois, 6 par heure ; arrêt à la première erreur ; sortie tronquée et expurgée ; journal `data/remedy-audit.jsonl` (mode 600) + journal de l'interface ; revérification automatique du plan après succès (jamais de faux « corrigé »).
5. Périmètre : **NAS** (SSH root par clé). **Homelab** seulement si `sudo -n` fonctionne (non configuré : commandes à copier). **clawhost** reste en lecture seule (par conception) ; `apt`, `reboot`, `npm -g` ne sont jamais exécutés par le dashboard.

API : `POST /api/lan/scan`, `POST /api/lan/device`, `GET /api/lan/scan|inventory`, `GET /api/ports`, `GET /api/ports/free`, `POST /api/architect/run`, `GET /api/remedy/catalog|status`, `POST /api/remedy/plan|run` (toutes les écritures : en-tête `X-InfraDash: 1`).
