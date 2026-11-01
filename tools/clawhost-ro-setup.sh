#!/usr/bin/env bash
# Installe sur clawhost (compte openclaw) un accès SSH en LECTURE SEULE pour InfraDash.
# À lancer depuis le homelab :   ssh -p 2211 openclaw@192.168.2.5 'bash -s' < ~/infra-dashboard/tools/clawhost-ro-setup.sh
# (mot de passe d'openclaw demandé une fois, par vous). Sans sudo, sans redémarrer sshd, réversible :
#   pour retirer l'accès : supprimer la ligne « infradash-ro@homelab » de ~/.ssh/authorized_keys et le dossier ~/.infradash
# La clé n'est acceptée que depuis 192.168.2.4, sans tunnel ni terminal, et ne peut lancer que ~/.infradash/ro.sh
# (commandes « metrics » et « inventory », lectures de /proc, dpkg, apt en simulation, systemctl, df, docker ps).
set -eu
umask 077
mkdir -p ~/.ssh ~/.infradash
cat > ~/.infradash/ro.sh <<'RO'
#!/usr/bin/env bash
# Commande imposée de la clé InfraDash : uniquement des lectures, sans secret (pas d'env, pas de docker inspect).
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
case "${SSH_ORIGINAL_COMMAND:-}" in
  inventory)
    echo "@@sys"; uname -r; . /etc/os-release && echo "$PRETTY_NAME"; cut -d' ' -f1 /proc/uptime; cut -d' ' -f1-3 /proc/loadavg; nproc
    echo "@@mem"; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo
    echo "@@df"; df -P -B1 -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2
    echo "@@reboot"; [ -f /var/run/reboot-required ] && echo oui || echo non
    echo "@@failed"; systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}'
    echo "@@upgradable"; apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | awk '/^Inst /{print $2, $3, $4}' | tr -d '[]('
    echo "@@dpkg"; dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n' 2>/dev/null | grep '^ii'
    echo "@@docker"; docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}' 2>/dev/null || echo "(docker non accessible)"
    echo "@@end" ;;
  metrics)
    echo @@stat; cat /proc/stat; echo @@mem; cat /proc/meminfo; echo @@load; cat /proc/loadavg
    echo @@net; cat /proc/net/dev; echo @@disk; cat /proc/diskstats; echo @@up; cat /proc/uptime
    echo @@docker; docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null ;;
  *) echo "InfraDash : commande refusée (lecture seule)" >&2; exit 1 ;;
esac
RO
chmod 700 ~/.infradash/ro.sh
touch ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys
grep -v 'infradash-ro@homelab' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp || true
echo 'restrict,from="192.168.2.4",command="'"$HOME"'/.infradash/ro.sh" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEVUfnfYDSv43xw6ZQq7jKfxjsEyYyoaEAt+3zxGn/Cs infradash-ro@homelab' >> ~/.ssh/authorized_keys.tmp
mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys
echo "Accès lecture seule InfraDash installé."
