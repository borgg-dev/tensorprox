#!/bin/bash
# PHASE 5 Test: Port Scan Attack
# Pattern: Many SYNs, low packets (score >= 25)

TARGET_IP=$1
PORT_RANGE=${2:-"7000-7200"}

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target_eip> [port_range]"
    exit 1
fi

echo "[PORT SCAN TEST] Launching port scan"
echo "Target: $TARGET_IP"
echo "Range: $PORT_RANGE"
echo "Expected: Ratelimit penalty applied (score 20-40)"
echo ""

# Port scan: SYN scan across port range
nmap -sS -p $PORT_RANGE $TARGET_IP --max-rate=100

echo ""
echo "[PORT SCAN TEST] Scan complete"
echo "Check ip_attack_signatures for type='scan'"
