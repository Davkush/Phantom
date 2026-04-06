#!/bin/bash
set -e

# Phantom Protocol v1.0 Installer
# Verified on: Debian/Ubuntu, macOS (M1/Intel), WSL2

echo "PHANTOM PROTOCOL: The OS for Secure Communication"
echo "--- Installing v1.0 Binary ---"

# 1. Dependency Check
if ! command -v cargo &> /dev/null; then
    echo "ERROR: Rust/Cargo is required. Install via https://rustup.rs"
    exit 1
fi

# 2. Build the Node Binary
cd phantom-node
cargo build --release

# 3. Strategic Installation
echo "Moving binary to /usr/local/bin (requires sudo)..."
sudo cp target/release/phantom-node /usr/local/bin/phantom

# 4. Initialize Local Config
echo "Initializing local configuration (phantom.toml)..."
cat <<EOF > phantom.toml
port = 443
socks_port = 9050
config_dir = "."
adversarial_mode = false
EOF

echo "--- INSTALLATION COMPLETE ---"
echo "Run 'phantom doctor' to verify integrity."
echo "Run 'phantom start' to join the mixnet."
