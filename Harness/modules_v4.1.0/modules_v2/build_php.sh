#!/usr/bin/env bash
# HARNESS-VALIDATION v2.4.0 — build PHP 7.4.33 debug + ASAN (prérequis module 1).
# v2.4 corrections :
#   - Vérification checksum SHA-256 (anti MITM/corruption)
#   - --prefix pour isolation (pas d'écrasement du PHP système)
#   - Cleanup du répertoire de build
# Prérequis : gcc, make, wget, autoconf, libtool, re2c, bison.
set -euo pipefail
V=7.4.33
PREFIX=/opt/php-asan-$V
BUILD_DIR=/tmp/php-build
mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"

echo "[+] Téléchargement PHP $V..."
if [ ! -f "php-$V.tar.gz" ]; then
    wget -q "https://www.php.net/distributions/php-$V.tar.gz"
fi

# v2.4 : vérification checksum SHA-256
echo "[+] Vérification checksum..."
wget -q "https://www.php.net/distributions/php-$V.tar.gz.sha256" -O "php-$V.tar.gz.sha256" || true
if [ -f "php-$V.tar.gz.sha256" ]; then
    # Le fichier .sha256 contient juste le hash, on construit le format check
    EXPECTED=$(cat "php-$V.tar.gz.sha256" | awk '{print $1}')
    ACTUAL=$(sha256sum "php-$V.tar.gz" | awk '{print $1}')
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "[FATAL] Checksum mismatch — fichier corrompu ou MITM"
        echo "  Expected: $EXPECTED"
        echo "  Actual:   $ACTUAL"
        exit 1
    fi
    echo "[+] Checksum OK"
else
    echo "[!] Fichier .sha256 indisponible — vérification ignorée (risque)"
fi

rm -rf "php-$V"
tar xzf "php-$V.tar.gz"
cd "php-$V"

# v2.4 : --prefix pour isolation (pas de sudo make install global)
echo "[+] Configuration avec --prefix=$PREFIX..."
./configure \
    --prefix="$PREFIX" \
    --enable-debug \
    --enable-address-sanitizer \
    --disable-all \
    --enable-cli \
    --enable-json \
    --enable-ctype \
    --enable-tokenizer \
    --enable-mbstring

# v2.4 : limiter les threads pour ne pas saturer le CPU host
JOBS=$(($(nproc) / 2))
[ "$JOBS" -lt 1 ] && JOBS=1
echo "[+] Compilation avec $JOBS threads..."
make -j"$JOBS"

# v2.4 : installation dans le prefix (pas de sudo, pas global)
make install

# Vérification
echo "[+] PHP installé dans $PREFIX :"
"$PREFIX/bin/php" -v
"$PREFIX/bin/php" -i | grep -i asan | head -3
echo "[+] Module php_uaf prêt à tester"
echo "[+] Lien : ln -sf $PREFIX/bin/php /usr/local/bin/php-asan"

# v2.4 : cleanup du répertoire de build
echo "[+] Cleanup..."
cd /
rm -rf "$BUILD_DIR"
echo "[+] Build terminé"
