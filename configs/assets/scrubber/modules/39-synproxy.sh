#!/bin/bash
# Module 38: Configure nftables SYNPROXY for SYN flood mitigation
set -euo pipefail

echo "[module 39] Configuring SYNPROXY via nftables..."

# Install nftables if not present (should already be installed in module 10)
if ! command -v nft &>/dev/null; then
    echo "[module 39] ERROR: nftables not installed" >&2
    exit 1
fi

# Flush existing SYNPROXY rules to avoid conflicts
nft flush table inet tcp_synproxy 2>/dev/null || true
nft delete table inet tcp_synproxy 2>/dev/null || true

# Create SYNPROXY table and chains (using tcp_synproxy as table name - 'synproxy' is reserved)
nft add table inet tcp_synproxy
nft add chain inet tcp_synproxy prerouting { type filter hook prerouting priority mangle \; }
nft add chain inet tcp_synproxy input { type filter hook input priority filter \; }

# Step 1: Mark SYN packets as untracked (bypass conntrack to enable SYNPROXY)
# Only for NEW connections (SYN without ACK)
nft add rule inet tcp_synproxy prerouting tcp flags syn tcp flags != syn,ack notrack

# Step 2: Apply SYNPROXY to SYN packets
# MSS, window scale, SACK, and timestamp options are learned from SYN
nft add rule inet tcp_synproxy input ct state untracked,invalid tcp flags syn synproxy mss 1460 wscale 7 timestamp sack-perm

echo "[module 39] ✓ SYNPROXY configured (global, triggered per-VIP by XDP)"

# Verify rules
RULE_COUNT=$(nft list table inet tcp_synproxy 2>/dev/null | grep -c "synproxy" || echo "0")
if [[ "$RULE_COUNT" -ge 1 ]]; then
    echo "[module 39] ✓ Verified: SYNPROXY rules active ($RULE_COUNT rules)"
else
    echo "[module 39] ERROR: SYNPROXY rules not found" >&2
    exit 1
fi

# Persist rules across reboot
mkdir -p /etc/nftables.d
nft list table inet tcp_synproxy > /etc/nftables.d/tcp_synproxy.nft

echo "[module 39] ✓ SYNPROXY rules persisted to /etc/nftables.d/tcp_synproxy.nft"
