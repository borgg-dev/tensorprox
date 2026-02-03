#!/bin/bash
# Module: install WireGuard dataplane eBPF sources and build artifacts
set -euo pipefail

echo "[module 30] Deploying eBPF sources..."
ROOT="${SCRUBBER_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOURCE_DIR="${ROOT}/assets/ebpf"
TARGET_DIR="/opt/tensorprox/ebpf"

mkdir -p "$TARGET_DIR"
cp -r "${SOURCE_DIR}/." "$TARGET_DIR/"

echo "[module 30] Building eBPF objects..."
make -C "$TARGET_DIR" clean
make -C "$TARGET_DIR"
