#!/bin/bash
# Phantom Protocol: CLI Usage Example
# This script demonstrates how to route CLI traffic through the Phantom SOCKS5 proxy.
# The --socks5-hostname flag ensures that DNS resolution is also handled by the mixnet,
# preventing "DNS Leakage" to your local ISP.

PROXY_ADDR="127.0.0.1:9050"
TARGET_URL="https://check.phantom-protocol.net" # Simulated check endpoint

echo "=== Phantom SOCKS5 CLI Test ==="
echo "Target: $TARGET_URL"
echo "Proxy:  $PROXY_ADDR"
echo "--------------------------------"

# Execute curl through the Phantom proxy
# -s: Silent mode
# -L: Follow redirects
# --socks5-hostname: Use the proxy for both the connection and DNS resolution
curl -s -L --socks5-hostname "$PROXY_ADDR" "$TARGET_URL"

if [ $? -eq 0 ]; then
    echo -e "\n\n[SUCCESS] Traffic successfully routed through the Phantom Mixnet."
else
    echo -e "\n\n[ERROR] Failed to reach target. Is 'phantom start' running?"
    echo "Run 'phantom doctor' to check your local node health."
fi
