#!/bin/bash
# Attach XDP to WAN interface with miner IP whitelist
# Called by miner AFTER bootstrap completes to ensure SSH access isn't blocked
set -euo pipefail

echo "[attach-xdp] Attaching XDP to WAN interface..."
# Use WAN_IF from bootstrap (auto-detected for multi-provider support)
WAN_IF="${WAN_IF:-$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1 || echo "eth0")}"
XDP_OBJ="/opt/tensorprox/ebpf/build/xdp_wan.o"
XDP_MAP_DIR="/sys/fs/bpf/xdp/globals"

# Get miner IP from argument or saved file
MINER_IP="${1:-}"
if [[ -z "$MINER_IP" ]] && [[ -f /opt/tensorprox/miner_ip ]]; then
    MINER_IP=$(cat /opt/tensorprox/miner_ip)
fi

if [[ -z "$MINER_IP" ]]; then
    echo "[attach-xdp] ERROR: Miner IP required as argument or in /opt/tensorprox/miner_ip" >&2
    exit 1
fi

echo "[attach-xdp] Miner IP for whitelist: $MINER_IP"

# Check if already attached (idempotent)
if bpftool net show dev "$WAN_IF" 2>/dev/null | grep "xdp:" -A 1 | grep -q "id [0-9]"; then
    echo "[attach-xdp] XDP already attached to $WAN_IF"

    # Verify whitelist entry exists
    IP_HEX=$(printf '%02x %02x %02x %02x' $(echo "$MINER_IP" | tr '.' ' '))
    if bpftool map dump pinned "$XDP_MAP_DIR/whitelist_map" 2>/dev/null | grep -q "$IP_HEX"; then
        echo "[attach-xdp] Miner IP already in whitelist"
        exit 0
    fi

    # Add to whitelist
    if bpftool map update pinned "$XDP_MAP_DIR/whitelist_map" key hex $IP_HEX value hex 01 2>/dev/null; then
        echo "[attach-xdp] Added miner IP to existing whitelist"
    fi
    exit 0
fi

if [[ ! -f "$XDP_OBJ" ]]; then
    echo "[attach-xdp] ERROR: XDP object not found: $XDP_OBJ" >&2
    exit 1
fi

# Load XDP - this creates maps
echo "[attach-xdp] Loading XDP program..."
ip link set dev "$WAN_IF" xdpgeneric obj "$XDP_OBJ" sec xdp

# Verify loaded with retry (race condition: kernel may need time to propagate)
MAX_RETRIES=10
RETRY_DELAY=0.5
for i in $(seq 1 $MAX_RETRIES); do
    if bpftool net show dev "$WAN_IF" 2>/dev/null | grep -q "xdp"; then
        echo "[attach-xdp] XDP loaded on $WAN_IF (verified on attempt $i)"
        break
    fi
    if [[ $i -eq $MAX_RETRIES ]]; then
        echo "[attach-xdp] ERROR: Failed to attach XDP after $MAX_RETRIES attempts" >&2
        exit 1
    fi
    echo "[attach-xdp] Waiting for XDP to register (attempt $i/$MAX_RETRIES)..."
    sleep $RETRY_DELAY
done

# Create symlink directory
mkdir -p "$XDP_MAP_DIR"

# Create symlinks to maps
XDP_MAPS=(
    xdp_wan_stats blacklist_map whitelist_map ratelimit_map machine_limits_map
    challenge_level_map source_ip_behavior_map temp_blacklist_map origin_challenge_map
    eip_map vip_state_map quarantine_map bypass_map
)

for map in "${XDP_MAPS[@]}"; do
    if [[ -f "/sys/fs/bpf/$map" ]]; then
        ln -sf "/sys/fs/bpf/$map" "$XDP_MAP_DIR/$map"
    fi
done

# CRITICAL: Whitelist miner IP immediately
echo "[attach-xdp] Whitelisting miner IP $MINER_IP..."
IP_HEX=$(printf '%02x %02x %02x %02x' $(echo "$MINER_IP" | tr '.' ' '))

if bpftool map update pinned "$XDP_MAP_DIR/whitelist_map" key hex $IP_HEX value hex 01 2>/dev/null; then
    echo "[attach-xdp] Miner IP whitelisted"
else
    echo "[attach-xdp] WARNING: Failed to whitelist miner IP!" >&2
fi

# Verify maps exist
echo "[attach-xdp] Verifying BPF maps..."
for map in xdp_wan_stats blacklist_map whitelist_map; do
    if [[ ! -e "$XDP_MAP_DIR/$map" ]]; then
        echo "[attach-xdp] WARNING: Map not found: $map" >&2
    fi
done

echo "[attach-xdp] XDP attached and configured successfully"
