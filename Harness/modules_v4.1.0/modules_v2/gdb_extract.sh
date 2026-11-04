#!/usr/bin/env bash
# HARNESS-VALIDATION v2.4.0 — extraction ciblée sessions PHP via GDB.
# Corrige audit §3.5 + revue J3 + revue v2.2 + v2.4 :
#   - Regex capture perms en groupe dédié
#   - Marqueur délimiteur unique (GDB_JSON_OUTPUT:) pour extraction fiable
#   - Fix pipefail + grep exit code 1 (fallback JSON vide si aucune session)
#   - v2.4 : pgrep -n (worker php-fpm le plus récent — détient les sessions
#     en mémoire, contrairement au master qui ne traite pas les requêtes)
#   - v2.4 : Python extrait dans gdb_extract.py (testable isolément, debug facilité)
#   - v2.4 : nullglob-safe : remplacement de `rm -f *.bin` par `find -delete`
# Prérequis : root ou CAP_SYS_PTRACE. Cible : php-fpm 7.4.
set -euo pipefail

# pgrep -n sélectionne le worker php-fpm le plus récent. C'est lui qui traite
# les requêtes PHP et détient donc les sessions en mémoire. Le master (-o,
# plus ancien) ne fork pas de requêtes et ne contient généralement pas de
# données de session vivantes.
PID=${1:-$(pgrep -n php-fpm 2>/dev/null || echo "")}
if [ -z "$PID" ]; then
    echo '{"module":"gdb_extract","error":"no_php_fpm","regions_found":0,"regions":[]}'
    exit 2
fi

OUTDIR=/tmp/harness_sess
mkdir -p "$OUTDIR"
# nullglob-safe : si aucun fichier *.bin n'existe, `rm -f "$OUTDIR"/*.bin`
# échouerait sous `set -euo pipefail` (le glob ne se dilate pas). find -delete
# ne lève jamais d'erreur même avec zéro correspondance.
find "$OUTDIR" -name "*.bin" -delete 2>/dev/null || true

# v2.4 : Python extrait dans gdb_extract.py (testable isolément, debug facilité)
# On positionne $harness_pid pour que le script Python puisse le relire via
# gdb.parse_and_eval("$harness_pid").
GDB_OUTPUT=$(gdb -q -p "$PID" -batch \
  -ex 'set pagination off' \
  -ex 'set $harness_pid = '"$PID" \
  -x "$(dirname "$0")/gdb_extract.py" \
  -ex 'detach' -ex 'quit' 2>/dev/null || true)

# Extraction : grep -o récupère uniquement la ligne après le marqueur.
# Fallback : si grep ne trouve rien, JSON vide valide (pas de crash via pipefail).
JSON=$(echo "$GDB_OUTPUT" | grep -o 'GDB_JSON_OUTPUT:.*' | sed 's/GDB_JSON_OUTPUT://' || true)
if [ -z "$JSON" ]; then
    echo "{\"module\":\"gdb_extract\",\"pid\":\"$PID\",\"regions_scanned\":0,\"regions_found\":0,\"regions\":[]}"
else
    echo "$JSON"
fi
