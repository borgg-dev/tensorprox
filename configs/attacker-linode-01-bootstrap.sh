#!/bin/bash
# Bootstrap script for Attacker instance
# Installs tools for DDoS mitigation validation testing

set -euo pipefail

echo "[$(date)] Starting Attacker bootstrap..."

# Wait for network
while ! ping -c 1 8.8.8.8 >/dev/null 2>&1; do
    sleep 2
done

# Update and install attack tools
apt-get update
apt-get install -y \
    hping3 \
    nmap \
    tcpdump \
    curl \
    jq \
    iputils-ping \
    net-tools

# NOTE: Attack scripts auto-embedded by TensorProx Node class
# Scripts extracted from configs/assets/attacker/ to /root/ via base64
# See Node._embed_assets() for implementation

echo "[$(date)] Attacker bootstrap complete"
echo "Tools installed: hping3, nmap, tcpdump"
echo ""
echo "Attack scripts available in /root/:"
echo "  - syn-flood.sh <EIP> [port] [duration]"
echo "  - rst-flood.sh <EIP> [port] [count]"
echo "  - port-scan.sh <EIP> [range]"
echo "  - distributed-syn-flood.sh <EIP> [port] [duration]"
echo "  - cps-spike.sh, pps-spike.sh, slowloris.sh"
echo ""
echo "Usage example: /root/syn-flood.sh 203.0.113.10 7080 60"  # Use your target EIP
