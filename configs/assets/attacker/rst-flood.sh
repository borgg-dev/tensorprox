#!/bin/bash
# PHASE 5 Test: RST Flood Attack
# Expected: IP gets temp blacklisted (score >= 30 for RST pattern)

TARGET_IP=$1
TARGET_PORT=${2:-7080}
COUNT=${3:-1000}

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target_eip> [port] [packet_count]"
    exit 1
fi

echo "[RST FLOOD TEST] Launching RST flood attack"
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Packets: $COUNT"
echo "Expected: Source IP gets temp blacklisted (RST flood pattern)"
echo ""

# RST flood
hping3 -R -p $TARGET_PORT $TARGET_IP -c $COUNT --fast

echo ""
echo "[RST FLOOD TEST] Attack complete"
echo "Sent $COUNT RST packets"
echo "Check ip_attack_signatures for type='rst_flood'"
