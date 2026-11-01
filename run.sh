#!/usr/bin/env bash
# Lance InfraDash s'il ne tourne pas déjà ; appelé par la crontab de jeff (@reboot + toutes les 2 min).
# Priorité basse (nice 10, I/O idle) pour ne jamais concurrencer les services de prod.
set -u
cd "$(dirname "$(readlink -f "$0")")" || exit 1
mkdir -p data logs
PIDF=data/infradash.pid
FAILF=data/health-fails

exec 9>data/infradash.lock
if ! flock -n 9; then
    # Déjà lancé : on vérifie qu'il répond, sinon on le relance après 3 échecs consécutifs
    if curl -fsS -m 5 -o /dev/null http://127.0.0.1:7070/api/health; then
        rm -f "$FAILF"
    else
        n=$(( $(cat "$FAILF" 2>/dev/null || echo 0) + 1 ))
        echo "$n" > "$FAILF"
        pid=$(cat "$PIDF" 2>/dev/null)
        if (( n >= 3 )) && [[ -n "$pid" ]] && tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q 'server.py'; then
            echo "$(date '+%F %T') watchdog : pas de réponse ($n), redémarrage du pid $pid" >> logs/infradash.log
            kill "$pid"
            rm -f "$FAILF"
        fi
    fi
    exit 0
fi

# Rotation simple du journal
if [[ -f logs/infradash.log ]] && (( $(stat -c %s logs/infradash.log) > 5000000 )); then
    mv -f logs/infradash.log logs/infradash.log.1
fi
echo "$(date '+%F %T') démarrage d'InfraDash" >> logs/infradash.log
echo $$ > "$PIDF"
exec nice -n 10 ionice -c3 python3 -I server.py >> logs/infradash.log 2>&1
