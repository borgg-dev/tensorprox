#!/bin/bash
# Module 39: Initialize quarantine and bypass BPF maps
set -euo pipefail

echo "[module 40] Initializing quarantine and bypass maps..."

# Verify XDP program is loaded (maps should be pinned by XDP)
# Maps are created and pinned by the XDP program load in module 35
# This module just verifies they exist after XDP is loaded

# Wait a moment for XDP to fully initialize
sleep 2

# Expected maps (pinned by XDP program)
EXPECTED_MAPS=(
    "/sys/fs/bpf/xdp/globals/quarantine_map"
    "/sys/fs/bpf/xdp/globals/bypass_map"
    "/sys/fs/bpf/xdp/globals/vip_state_map"
)

MISSING=()
for map in "${EXPECTED_MAPS[@]}"; do
    if [[ ! -f "$map" ]]; then
        MISSING+=("$map")
    fi
done

if [[ "${#MISSING[@]}" -gt 0 ]]; then
    echo "[module 40] ERROR: Missing maps after XDP load:" >&2
    printf '  - %s\n' "${MISSING[@]}" >&2
    echo "[module 40] This likely means XDP program needs to be recompiled with new map definitions" >&2
    exit 1
fi

echo "[module 40] ✓ Quarantine and bypass maps verified"

# Log initial map statistics
echo "[module 40] Map statistics:"
bpftool map show pinned /sys/fs/bpf/xdp/globals/quarantine_map 2>/dev/null | head -3 || echo "  quarantine_map: details unavailable"
bpftool map show pinned /sys/fs/bpf/xdp/globals/bypass_map 2>/dev/null | head -3 || echo "  bypass_map: details unavailable"
bpftool map show pinned /sys/fs/bpf/xdp/globals/vip_state_map 2>/dev/null | head -3 || echo "  vip_state_map: details unavailable"

# Verify maps are initially empty
QUARANTINE_COUNT=$(bpftool map dump pinned /sys/fs/bpf/xdp/globals/quarantine_map 2>/dev/null | grep -c "key:" | tr -d '\n' || echo "0")
BYPASS_COUNT=$(bpftool map dump pinned /sys/fs/bpf/xdp/globals/bypass_map 2>/dev/null | grep -c "key:" | tr -d '\n' || echo "0")

echo "[module 40] Initial entry counts: quarantine=$QUARANTINE_COUNT, bypass=$BYPASS_COUNT"

if [[ "$QUARANTINE_COUNT" -eq 0 ]] && [[ "$BYPASS_COUNT" -eq 0 ]]; then
    echo "[module 40] ✓ Maps are initially empty (as expected)"
else
    echo "[module 40] WARNING: Maps contain entries at boot (unexpected)" >&2
fi

# Create log directory for quarantine events
mkdir -p /var/log/tensorprox
touch /var/log/tensorprox/quarantine.log
chmod 644 /var/log/tensorprox/quarantine.log

echo "[module 40] ✓ Quarantine initialization complete"
