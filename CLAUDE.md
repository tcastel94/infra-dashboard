# CLAUDE.md — InfraDash

Dashboard du **homelab perso** (homelab, NAS Unraid, clawhost). Rien à voir avec Carglass ni J.Prod Consulting :
ne jamais mélanger ces contextes. Doc complète et exploitation : `README.md`.

## Sessions cloud (Claude Code sur le web) : les machines sont injoignables

Le code tourne normalement **sur le homelab** (`192.168.2.4`, utilisateur `jeff`). Dans un conteneur cloud :

| Collecteur | Comportement dans le cloud |
|---|---|
| NAS (`nas.py`, SSH root `192.168.2.3`) | Timeout SSH 6 s (`ssh.py`) → données vides |
| clawhost (`claw.py`, sondes `192.168.2.5`) | Pas de réponse → données vides |
| Homelab (`homelab.py`) | **Piège : données FAUSSES, pas absentes.** `/proc`, `/sys` et `ss` sont lus en local, donc ce sont ceux du conteneur cloud. cAdvisor (`127.0.0.1:8081`) et VictoriaMetrics (`127.0.0.1:8428`) échouent. |
| Réseau / LAN (`network.py`, `lan.py`) | Le /24 balayé est fixé sur `192.168.2.0/24` : rien ne répond |
| Vulnérabilités (`vulns.py`) | Inventaire vide ou faux → analyse sans valeur. Les appels OSV.dev / GitHub / endoflife.date passent par le proxy et peuvent être refusés. |

Règles en session cloud :
- **Ne jamais interpréter les valeurs** affichées (CPU, RAM, conteneurs, ports, notes, alertes) : elles ne décrivent pas l'infra réelle.
- Ne pas « corriger » un collecteur parce qu'il échoue dans le cloud : c'est attendu.
- La validation fonctionnelle se fait **sur le homelab**, par l'utilisateur, après un pull de la branche.

## Vérifications faisables sans réseau

```bash
# Syntaxe Python (Python 3 standard, aucune dépendance pip)
python3 -m py_compile server.py infradash/*.py tools/exec-setup.py && find . -name __pycache__ -type d -prune -exec rm -rf {} +

# Syntaxe JavaScript de l'interface
for f in static/js/*.js; do node --check "$f" || echo "ÉCHEC $f"; done

# Syntaxe des scripts shell (+ shellcheck s'il est installé)
bash -n run.sh install-autostart.sh tools/clawhost-ro-setup.sh
```

Les fonctions pures (grammaire de `remedy.py`, barèmes de `scores.py`, parseurs de `procfs.py`…) se testent sur des sorties
d'exemple écrites à la main, sans contacter de machine.

## Lancer l'interface dans le cloud (contrôle visuel uniquement)

```bash
INFRADASH_STAGING=1 INFRADASH_HOST=127.0.0.1 python3 -I server.py
```

- `INFRADASH_STAGING=1` : aucune écriture dans VictoriaMetrics, pas d'IA Ollama (GPU), aucune notification Unraid.
- `INFRADASH_HOST=127.0.0.1` : le port 7070 n'est pas exposé sur toutes les interfaces.
- Ouvrir `http://127.0.0.1:7070` (Playwright préinstallé). Le contrôle d'en-tête `Host` accepte les IP et `localhost`.
- L'écran est « dégradé » : on vérifie la mise en page et l'absence d'erreur JS, pas les valeurs.
- Arrêter le serveur et ne rien committer de `data/` ni `logs/` (déjà dans `.gitignore`).

## Validation sur le homelab (à donner à l'utilisateur)

```bash
cd ~/infra-dashboard && git pull origin <branche>
```

```bash
kill "$(cat ~/infra-dashboard/data/infradash.pid)"   # le watchdog cron relance le serveur sous 2 min
```

```bash
curl -fsS http://127.0.0.1:7070/api/health
```

Puis fournir les `curl` ciblés sur les routes `/api/...` concernées par la modification.

## Règles du projet (à respecter dans toute modification)

- **Lecture seule par défaut** : les collecteurs n'exécutent que des chaînes fixes définies dans le code ; aucune entrée du
  navigateur n'est passée à un shell. Ne jamais assouplir la grammaire de `remedy.py` ni la liste des chemins autorisés.
- **Sans dépendance** : Python 3 standard uniquement (pas de pip), ECharts embarqué dans `static/vendor`.
- Toute route d'écriture (`POST`) exige l'en-tête `X-InfraDash: 1`.
- **Jamais de faux « corrigé »** : si une machine n'a pas pu être relue, l'état est « à confirmer ».
- Secrets : rien dans le dépôt (`exec.json`, `netscan.json`, clés, `.env`) ; les commandes cron affichées sont expurgées.
- `data/` contient l'inventaire réseau réel (MAC, IP, ports, journal d'audit) : ne jamais le versionner.
- Code, commentaires, interface et doc en **français**. Toute nouvelle fonctionnalité est documentée dans `README.md`
  (section datée, comme les précédentes).
