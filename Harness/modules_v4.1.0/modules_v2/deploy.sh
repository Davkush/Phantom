#!/usr/bin/env bash
# HARNESS-VALIDATION v2.2.0 — déploiement complet.
# Installe et lance le harness, produit le rapport signé.
# Corrige audit §6.3 : dépendances épinglées, vérification prérequis.
set -euo pipefail
DEST=${1:-/opt/harness}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[+] Installation dans $DEST"
mkdir -p "$DEST"
# v2.4 : cp -r avec dotfiles (shopt -s dotglob) — le glob * ignore les fichiers cachés
( cd "$SCRIPT_DIR" && shopt -s dotglob && cp -r * "$DEST/" )
cd "$DEST"

# ─── Vérification des prérequis ───────────────────────────────
echo "[+] Vérification des prérequis..."
for cmd in python3 php docker; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[!] $cmd non installé — certains modules seront ignorés"
    fi
done

# ─── Environnement Python ─────────────────────────────────────
echo "[+] Création environnement Python..."
python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt

# ─── PHP Composer (module 2) ──────────────────────────────────
if [ -f composer.json ]; then
    echo "[+] Installation dépendances PHP..."
    if command -v composer >/dev/null 2>&1; then
        # v2.4 : afficher les erreurs Composer (pas tout masquer)
        if ! composer install --no-dev --quiet 2>&1 | tail -5; then
            echo "[!] Composer install échoué — module php_chain ignoré"
        fi
    else
        echo "[!] Composer non installé — module php_chain ignoré"
    fi
fi

# ─── Build du module C (module 3) ─────────────────────────────
if [ -f c_heap_exploit.c ]; then
    echo "[+] Build c_heap_exploit..."
    # v2.3 : -ldl pour dlopen/dlsym. v2.4 : -g conditionnel via DEBUG env
    DEBUG_FLAGS="${DEBUG:+-g}"
    gcc $DEBUG_FLAGS -no-pie -fno-stack-protector -Wall -Wextra \
        -o c_heap_exploit c_heap_exploit.c -ldl 2>/dev/null || \
        echo "[!] Build c_heap_exploit échoué"
fi

# ─── Build images Docker sandbox (J6) ─────────────────────────
if [ -d docker ]; then
    echo "[+] Build images Docker sandbox..."
    for dockerfile in docker/Dockerfile.*; do
        [ -f "$dockerfile" ] || continue
        tag=$(basename "$dockerfile" | sed 's/Dockerfile.//')
        docker build -q -f "$dockerfile" -t "harness/$tag:latest" . 2>/dev/null || \
            echo "[!] Build $tag échoué — sandbox incomplet"
    done
fi

# ─── Lancement reproductible ──────────────────────────────────
echo "[+] Lancement du harness..."
SEED=${SEED:-1337}
export REPORT_KEY
if [ -z "$REPORT_KEY" ] || [ "$REPORT_KEY" = "harness-lab-key" ]; then
    echo "[+] Génération de REPORT_KEY..."
    REPORT_KEY="$(openssl rand -hex 32)"
    # v2.4 : masquer la clé dans la sortie terminal/logs CI
    MASKED=$(echo "$REPORT_KEY" | sed 's/./*/g')
    echo "[!] REPORT_KEY généré (masqué : $MASKED)"
    echo "[!] Sauvegarder dans un vault/HSM — ne pas commit"
fi
export OPERATOR="${OPERATOR:-$(whoami)}"

.venv/bin/python orchestrator.py

echo ""
echo "[+] Rapport signé : reports/report_${SEED}.json"
echo "[+] Vérification :"
echo "    .venv/bin/python -c \\"
echo "      \"import sys; sys.path.insert(0,'.'); \\"
echo "       from orchestrator import verify_report_file; \\"
echo "       print(verify_report_file('reports/report_${SEED}.json', b'\${REPORT_KEY}'))\""
