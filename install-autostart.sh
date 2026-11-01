#!/usr/bin/env bash
# Active le démarrage automatique d'InfraDash via la crontab de jeff (aucun droit root).
set -euo pipefail
RUN="$(cd "$(dirname "$0")" && pwd)/run.sh"
if crontab -l 2>/dev/null | grep -q infradash-watchdog; then
    echo "Déjà installé :"; crontab -l | grep infradash-watchdog; exit 0
fi
{ crontab -l 2>/dev/null || true
  echo "# InfraDash : dashboard infra (http://192.168.2.4:7070), relancé automatiquement"
  echo "@reboot $RUN # infradash-watchdog"
  echo "*/2 * * * * $RUN # infradash-watchdog"
} | crontab -
echo "Démarrage automatique activé :"; crontab -l | grep infradash-watchdog
