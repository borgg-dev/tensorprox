#!/bin/bash
# Module 36: Populate blacklist from threat intelligence feeds (Spamhaus + EmergingThreats)
set -euo pipefail

echo "[module 36] Populating blacklist (LPM_TRIE with CIDR support)..."
ROOT="${SCRUBBER_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOURCE_HELPER="${ROOT}/assets/bin/populate-blacklist.py"

# IMPORTANT: blacklist_map and whitelist_map are defined in xdp_wan.c (XDP program)
# so they are pinned at /sys/fs/bpf/xdp/globals/ (NOT /sys/fs/bpf/tc/globals/)
XDP_MAP_DIR="/sys/fs/bpf/xdp/globals"

if [[ ! -f "$SOURCE_HELPER" ]]; then
    echo "[module 36] ERROR: populate-blacklist.py not found at $SOURCE_HELPER" >&2
    exit 1
fi

# Install requests if not present (needed for threat feed download)
if ! python3 -c "import requests" 2>/dev/null; then
    echo "[module 36] Installing python3-requests..."
    pip3 install --quiet requests
fi

# Run blacklist population (handles both CIDR blocks and individual IPs)
python3 "$SOURCE_HELPER"

# Verify blacklist map exists and has entries
if [[ -f "$XDP_MAP_DIR/blacklist_map" ]]; then
    MAP_COUNT=$(bpftool map dump pinned "$XDP_MAP_DIR/blacklist_map" 2>/dev/null | grep -c "key" || echo "0")
    echo "[module 36] ✓ Blacklist populated: $MAP_COUNT entries (CIDR + IPs)"

    if [[ "$MAP_COUNT" -eq 0 ]]; then
        echo "[module 36] WARNING: Blacklist empty (download failed) - can populate later via API" >&2
        echo "[module 36] Use: POST /api/v1/admin/refresh-blacklist" >&2
        # Don't exit - blacklist is optional, can be populated post-deployment
    elif [[ "$MAP_COUNT" -lt 100 ]]; then
        echo "[module 36] WARNING: Blacklist has fewer than 100 entries (partial download)" >&2
    fi
else
    echo "[module 36] ERROR: blacklist_map not found at $XDP_MAP_DIR" >&2
    echo "[module 36] Ensure module 35-xdp.sh has run successfully" >&2
    exit 1
fi

# Verify whitelist map exists (initially empty)
if [[ -f "$XDP_MAP_DIR/whitelist_map" ]]; then
    echo "[module 36] ✓ Whitelist map exists (empty initially)"
else
    echo "[module 36] WARNING: whitelist_map not found at $XDP_MAP_DIR" >&2
fi
