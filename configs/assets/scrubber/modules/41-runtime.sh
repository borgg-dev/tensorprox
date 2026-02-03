#!/bin/bash
# Module: install dataplane helper scripts and attach base TC program
set -euo pipefail

echo "[module 41] Installing dataplane helper scripts..."
ROOT="${SCRUBBER_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOURCE_DIR="${ROOT}/assets/bin"
BIN_DIR="/opt/tensorprox/bin"

mkdir -p "$BIN_DIR"
cp -r "${SOURCE_DIR}/." "$BIN_DIR/"
find "$BIN_DIR" -type f \( -name "*.sh" -o -name "*.py" \) -exec chmod +x {} +

echo "[module 41] Attaching WAN ingress program..."
"$BIN_DIR/install-bpf.sh" ens5
