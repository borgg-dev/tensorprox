#!/bin/bash
# Bootstrap script for Exit Hubs
# Per dev-plan.md Section 1, 4, 7

set -eu
# Note: Removed -o pipefail for cloud-init compatibility (uses /bin/sh)

# Determine home directory (varies by provider)
if [ -d "/home/ubuntu" ]; then
  HOME_DIR="/home/ubuntu"
else
  HOME_DIR="/root"
fi

# Update and install packages (dev-plan.md Section 1)
# Exit Hubs don't need BPF toolchain - that's only for Scrubbers
apt-get update
apt-get install -y \
  iproute2 nftables conntrack ethtool \
  wireguard wireguard-tools \
  jq curl net-tools mtr-tiny iperf3 hping3 tcpdump socat \
  ca-certificates \
  python3 python3-pip redis-tools

# Ensure bpftool is available (package name varies per kernel)
if ! command -v bpftool >/dev/null 2>&1; then
  KERNEL_RELEASE="$(uname -r)"
  apt-get install -y "linux-tools-${KERNEL_RELEASE}" || true
fi
if ! command -v bpftool >/dev/null 2>&1; then
  apt-get install -y linux-tools-generic-hwe-22.04 linux-tools-common || true
fi
if ! command -v bpftool >/dev/null 2>&1; then
  echo "bpftool not available after package install" >&2
  exit 100
fi

# Configure sysctls (dev-plan.md Section 4)
cat > /etc/sysctl.d/99-edge.conf <<EOF
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=4096
net.core.netdev_max_backlog=50000
net.core.rmem_max=67108864
net.core.wmem_max=67108864
EOF
sysctl --system

# NIC tuning (dev-plan.md Section 4)
IF=$(ip route get 1.1.1.1 | grep -oP 'dev \K\S+' | head -1)
if [ -n "$IF" ]; then
  ethtool -G "$IF" rx 4096 tx 4096 2>/dev/null || true
  ethtool -L "$IF" combined 4 2>/dev/null || true
fi

# Create WireGuard directory
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# ============================================================================
# XDP Metrics Collection (TPM-owned ground truth for production audit)
# ============================================================================

# Create BPF pin directories
mkdir -p /sys/fs/bpf/xdp/globals

# Install XDP metrics program if available
XDP_OBJ="${HOME_DIR}/ebpf/build/xdp_metrics.o"
if [ -f "$XDP_OBJ" ]; then
  echo "Installing XDP metrics program on $IF..."

  # Detach any existing XDP program
  ip link set dev "$IF" xdp off 2>/dev/null || true

  # Attach XDP program (use xdpgeneric for compatibility)
  if ip link set dev "$IF" xdpgeneric obj "$XDP_OBJ" sec xdp; then
    echo "XDP metrics program attached to $IF"
    echo "XDP metrics installed on $IF" >> /root/bootstrap-complete.txt
  else
    echo "WARNING: Failed to attach XDP metrics program"
  fi
else
  echo "WARNING: XDP metrics object not found at $XDP_OBJ"
fi

# Initialize nftables for SNAT mode (dev-plan.md Section 7B)
# Filter table for forwarding between WireGuard and Origin
nft add table ip filter 2>/dev/null || true
nft add chain ip filter forward '{ type filter hook forward priority filter; policy drop; }' 2>/dev/null || true
nft add rule ip filter forward ct state related,established accept 2>/dev/null || true
# NOTE: Per-origin forward rules added via transparent_mode_commands during registration

# NAT table for SNAT (Exit Hub → Origin traffic)
nft add table ip nat 2>/dev/null || true
nft add chain ip nat postrouting '{ type nat hook postrouting priority 100; }' 2>/dev/null || true
nft add rule ip nat postrouting oifname "$IF" masquerade 2>/dev/null || true

# ============================================================================
# Volume Reporting Agent (reports traffic stats to TPM)
# ============================================================================

# Install Python redis package for volume reporting
pip3 install redis --break-system-packages 2>/dev/null || pip3 install redis

# Create agent directory
mkdir -p /opt/tensorprox

# Copy agent from assets (deployed by TPM)
AGENT_SRC="${HOME_DIR}/assets/exit-hub-agent.py"
AGENT_DST="/opt/tensorprox/exit-hub-agent.py"

if [ -f "$AGENT_SRC" ]; then
  cp "$AGENT_SRC" "$AGENT_DST"
  chmod +x "$AGENT_DST"
  echo "Volume agent installed from $AGENT_SRC"
else
  echo "WARNING: Volume agent not found at $AGENT_SRC"
fi

# Create environment file for the agent (TPM will update this after registration)
cat > /opt/tensorprox/agent.env <<'AGENT_ENV'
# TPM Redis connection - updated by TPM during exit hub registration
TPM_HOST=tpm.tensorprox.com
TPM_PORT=6379
REPORT_INTERVAL=60
EXIT_HUB_ID=
ORIGIN_ID=
AGENT_ENV

# Create systemd service for the volume agent
cat > /etc/systemd/system/exithub-agent.service <<'AGENT_SERVICE'
[Unit]
Description=Exit Hub Volume Reporting Agent
After=network.target

[Service]
Type=simple
EnvironmentFile=/opt/tensorprox/agent.env
ExecStart=/usr/bin/python3 /opt/tensorprox/exit-hub-agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
AGENT_SERVICE

# Reload systemd and enable the service
systemctl daemon-reload
systemctl enable exithub-agent.service

# Start the agent if it was installed
if [ -f "$AGENT_DST" ]; then
  systemctl start exithub-agent.service || echo "Agent start failed (may need config)"
fi

# Mark bootstrap complete
touch /var/lib/cloud/instance/boot-finished-marker
echo "Bootstrap complete at $(date)" > /root/bootstrap-complete.txt
echo "nftables initialized: filter + NAT SNAT mode" >> /root/bootstrap-complete.txt
echo "Volume agent service installed" >> /root/bootstrap-complete.txt
