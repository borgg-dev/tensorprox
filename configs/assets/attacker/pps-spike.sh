#!/bin/bash
# Layer 7 Test: PPS Spike Attack
# Generates 5× baseline PPS to trigger Z-score anomaly detection
# Expected: Challenge level escalates to 2 (ACTIVE) after 3 consecutive samples (90s)

TARGET_IP=$1
TARGET_PORT=${2:-7080}
DURATION=${3:-120}
PPS_RATE=${4:-5000}

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target_eip> [port] [duration_seconds] [pps_rate]"
    echo ""
    echo "Example: $0 203.0.113.10 7080 120 5000"  # Use your target EIP
    echo "  - Sends 5000 pps for 120 seconds"
    echo "  - Expected detection at T+90s (3 samples × 30s)"
    echo "  - Challenge level escalates to 2 (50% rate limit)"
    exit 1
fi

echo "[PPS SPIKE TEST] Launching PPS spike attack"
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Duration: ${DURATION}s"
echo "PPS Rate: ${PPS_RATE}"
echo "Expected: Challenge level escalates to 2 after 90s"
echo ""

# Calculate packets to send
TOTAL_PACKETS=$((PPS_RATE * DURATION))

# Use hping3 with controlled rate (-i u1000 = 1000 pps, adjust via -i)
# For 5000 pps: -i u200 (microseconds between packets: 1000000/5000 = 200)
INTERVAL_US=$((1000000 / PPS_RATE))

echo "Starting PPS flood at ${PPS_RATE} pps (interval: ${INTERVAL_US}us)..."
hping3 -S -p $TARGET_PORT --faster -i u${INTERVAL_US} $TARGET_IP -c $TOTAL_PACKETS &
FLOOD_PID=$!

echo "Attack PID: $FLOOD_PID"
echo "Flooding for ${DURATION}s at ${PPS_RATE} pps..."
echo ""
echo "Timeline:"
echo "  T+0s:  Attack starts"
echo "  T+30s: First sample (breach_count=1)"
echo "  T+60s: Second sample (breach_count=2)"
echo "  T+90s: Third sample (breach_count=3) → TRIGGER"
echo "  T+90s: Challenge level escalates 0→2"
echo "  T+${DURATION}s: Attack stops"
echo ""

sleep $DURATION

# Kill flood
kill -9 $FLOOD_PID 2>/dev/null
wait $FLOOD_PID 2>/dev/null

echo ""
echo "[PPS SPIKE TEST] Attack complete"
echo ""
echo "Verification steps:"
echo "  1. Check attack_events table:"
echo "     SELECT * FROM attack_events WHERE attack_type='PPS_SPIKE' ORDER BY detected_at DESC LIMIT 1;"
echo "  2. Check anomaly_detection_state:"
echo "     SELECT origin_id, pps_breach_count, current_challenge_level FROM anomaly_detection_state;"
echo "  3. Check challenge level in BPF map (XDP map at xdp/globals/):"
echo "     ssh edge-a 'sudo bpftool map dump pinned /sys/fs/bpf/xdp/globals/origin_challenge_map'"
echo "  4. Verify rate limiting (should be 50% capacity):"
echo "     curl http://localhost:8000/api/v1/origins/O1/metrics/latest | jq .metric.pps"
echo ""
