#!/bin/bash
# Module: configure kernel and NIC tuning
set -euo pipefail

echo "[module 20] Applying sysctl and NIC tuning..."
cat > /etc/sysctl.d/99-edge.conf <<'EOSYSCTL'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=4096
net.core.netdev_max_backlog=50000
net.core.rmem_max=67108864
net.core.wmem_max=67108864
EOSYSCTL

sysctl --system >/dev/null 2>&1
ethtool -L ens5 combined 8 2>/dev/null || true
