#!/bin/bash
# Module 35: Load XDP on WAN interface
#
# Maps are pinned by libbpf to /sys/fs/bpf/<map_name> (LIBBPF_PIN_BY_NAME default).
# We create symlinks at /sys/fs/bpf/xdp/globals/ so all scripts use consistent paths.
set -euo pipefail

echo "[module 35] Loading XDP on WAN interface..."
WAN_IF="ens5"
XDP_OBJ="/opt/tensorprox/ebpf/build/xdp_wan.o"
XDP_MAP_DIR="/sys/fs/bpf/xdp/globals"

if [[ ! -f "$XDP_OBJ" ]]; then
    echo "[module 35] ERROR: XDP object not found: $XDP_OBJ" >&2
    exit 1
fi

# Check if already loaded (idempotent)
if bpftool net show dev "$WAN_IF" 2>/dev/null | grep "xdp:" -A 1 | grep -q "id [0-9]"; then
    echo "[module 35] XDP already attached to $WAN_IF"
    if [[ -L "$XDP_MAP_DIR/xdp_wan_stats" || -f "$XDP_MAP_DIR/xdp_wan_stats" ]]; then
        echo "[module 35] ✓ Maps already available at $XDP_MAP_DIR"
        exit 0
    fi
fi

# Load XDP using ip link set (libbpf pins maps to /sys/fs/bpf/<map_name>)
echo "[module 35] Loading XDP program..."
ip link set dev "$WAN_IF" xdpgeneric obj "$XDP_OBJ" sec xdp

# Verify XDP attached
if ! bpftool net show dev "$WAN_IF" | grep -q "xdp"; then
    echo "[module 35] ERROR: Failed to load XDP" >&2
    exit 1
fi
echo "[module 35] ✓ XDP loaded on $WAN_IF"

# Create symlink directory for consistent paths across all scripts
mkdir -p "$XDP_MAP_DIR"

# Create symlinks: /sys/fs/bpf/xdp/globals/<map> -> /sys/fs/bpf/<map>
XDP_MAPS=(
    xdp_wan_stats blacklist_map whitelist_map ratelimit_map machine_limits_map
    challenge_level_map source_ip_behavior_map temp_blacklist_map origin_challenge_map
    eip_map vip_state_map quarantine_map bypass_map
)

echo "[module 35] Creating symlinks to $XDP_MAP_DIR..."
for map in "${XDP_MAPS[@]}"; do
    if [[ -f "/sys/fs/bpf/$map" ]]; then
        ln -sf "/sys/fs/bpf/$map" "$XDP_MAP_DIR/$map"
    fi
done

# Verify critical maps exist
MISSING=()
for map in xdp_wan_stats blacklist_map whitelist_map machine_limits_map challenge_level_map; do
    if [[ ! -e "$XDP_MAP_DIR/$map" ]]; then
        MISSING+=("$map")
    fi
done

if [[ "${#MISSING[@]}" -gt 0 ]]; then
    echo "[module 35] ERROR: Missing maps:" >&2
    printf '  - %s\n' "${MISSING[@]}" >&2
    exit 1
fi

echo "[module 35] ✓ All XDP maps available at $XDP_MAP_DIR"
