#!/bin/bash
# Install XDP metrics program on exit hub interface
#
# Usage: install-xdp-metrics.sh <interface>
# Example: install-xdp-metrics.sh eth0
#
# This script:
# 1. Creates BPF pin directories
# 2. Attaches xdp_metrics program to the interface
# 3. Initializes the global metrics map
#
# The program monitors all traffic and tracks per-origin metrics
# in maps that can be read by the exit-hub-agent.

set -euo pipefail

IFACE="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XDP_OBJ="${SCRIPT_DIR}/ebpf/build/xdp_metrics.o"

if [ -z "$IFACE" ]; then
    echo "Usage: $0 <interface>"
    echo "Example: $0 eth0"
    exit 1
fi

if [ ! -f "$XDP_OBJ" ]; then
    echo "ERROR: XDP object not found: $XDP_OBJ"
    echo "Build it first with: make -C ${SCRIPT_DIR}/ebpf"
    exit 1
fi

echo "Installing XDP metrics on interface: $IFACE"

# Create BPF filesystem directories for pinned maps
echo "Creating BPF pin directories..."
mkdir -p /sys/fs/bpf/xdp/globals

# Detach any existing XDP program
echo "Detaching any existing XDP program..."
ip link set dev "$IFACE" xdp off 2>/dev/null || true

# Attach XDP program
echo "Attaching XDP metrics program..."
# Use xdpgeneric for compatibility (works on all interfaces including virtio)
ip link set dev "$IFACE" xdpgeneric obj "$XDP_OBJ" sec xdp

# Verify attachment
echo "Verifying XDP program attached..."
if ip link show dev "$IFACE" | grep -q "xdp"; then
    echo "SUCCESS: XDP metrics program attached to $IFACE"
else
    echo "WARNING: XDP attachment may have failed"
fi

# Initialize global metrics map with a zero entry
echo "Initializing global metrics map..."
# The map should be auto-pinned by the program, but let's verify
if [ -f /sys/fs/bpf/xdp/globals/global_metrics_map ]; then
    echo "Global metrics map pinned at /sys/fs/bpf/xdp/globals/global_metrics_map"
else
    echo "WARNING: Global metrics map not found - it may be created on first packet"
fi

echo ""
echo "=== XDP Metrics Installation Complete ==="
echo "Maps pinned at: /sys/fs/bpf/xdp/globals/"
echo ""
echo "Available maps:"
echo "  - origin_metrics_map    : Per-origin packet/byte counters"
echo "  - global_metrics_map    : Aggregate metrics"
echo "  - monitored_origins_map : Origins to track (populated by agent)"
echo ""
echo "Add origins to monitor with:"
echo "  bpftool map update pinned /sys/fs/bpf/xdp/globals/monitored_origins_map \\"
echo "    key hex <ip-bytes> value hex 01 00 00 00"
echo ""
echo "Read metrics with:"
echo "  bpftool map dump pinned /sys/fs/bpf/xdp/globals/origin_metrics_map"
