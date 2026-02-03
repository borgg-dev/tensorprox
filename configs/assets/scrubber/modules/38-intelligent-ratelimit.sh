#!/bin/bash
# 38-intelligent-ratelimit.sh
# Initialize BPF maps for intelligent rate limiting
# Runs AFTER 37-machine-limits.sh, BEFORE 39-synproxy.sh

set -euo pipefail

echo "[module 38] Initializing intelligent rate limiting maps..."

# Map paths (created by XDP load in 35-xdp.sh)
XDP_MAP_DIR="/sys/fs/bpf/xdp/globals"
TC_MAP_DIR="/sys/fs/bpf/tc/globals"

# Wait for XDP maps to be available
MAX_WAIT=30
WAITED=0
while [[ ! -d "$XDP_MAP_DIR" ]] && [[ $WAITED -lt $MAX_WAIT ]]; do
    echo "Waiting for XDP maps... ($WAITED/$MAX_WAIT)"
    sleep 1
    ((WAITED++))
done

if [[ ! -d "$XDP_MAP_DIR" ]]; then
    echo "ERROR: XDP maps not available after ${MAX_WAIT}s"
    exit 1
fi

# --- Initialize scrubber_load_map (key=0) with default values ---
echo "Initializing scrubber_load_map..."

# struct scrubber_load (16 bytes):
#   cpu_pct (u8): 0
#   bw_utilization_pct (u8): 0
#   active_origin_count (u16): 0
#   total_pps (u32): 0
#   last_update_ns (u64): 0
SCRUBBER_LOAD_INIT="00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"

if [[ -e "$XDP_MAP_DIR/scrubber_load_map" ]]; then
    bpftool map update pinned "$XDP_MAP_DIR/scrubber_load_map" \
        key hex 00 00 00 00 \
        value hex $SCRUBBER_LOAD_INIT
    echo "✓ scrubber_load_map initialized (will be populated by ecp-agent)"
else
    echo "⚠ scrubber_load_map not found (will be created on first XDP load)"
fi

# --- Verify source_reputation_map exists (no initialization needed, LRU) ---
if [[ -e "$XDP_MAP_DIR/source_reputation_map" ]]; then
    echo "✓ source_reputation_map exists (LRU, self-populating)"
else
    echo "⚠ source_reputation_map not found (will be created on first XDP load)"
fi

# --- Verify origin_rate_config_map exists (populated during origin creation) ---
if [[ -e "$XDP_MAP_DIR/origin_rate_config_map" ]]; then
    echo "✓ origin_rate_config_map exists (populated by miner on origin creation)"
else
    echo "⚠ origin_rate_config_map not found (will be created on first XDP load)"
fi

echo "[module 38] Intelligent rate limiting maps ready"
