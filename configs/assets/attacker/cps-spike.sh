#!/bin/bash
# Layer 7 Test: CPS (Connections Per Second) Spike Attack
# Opens and closes TCP connections rapidly to spike CPS metric
# Expected: Challenge level escalates to 2 (ACTIVE) after 3 consecutive samples (90s)

TARGET_IP=$1
TARGET_PORT=${2:-7080}
DURATION=${3:-120}
CPS_RATE=${4:-100}

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target_eip> [port] [duration_seconds] [cps_rate]"
    echo ""
    echo "Example: $0 203.0.113.10 7080 120 100"  # Use your target EIP
    echo "  - Opens/closes 100 connections per second"
    echo "  - Runs for 120 seconds"
    echo "  - Expected: CPS spike detected, challenge level → 2"
    exit 1
fi

echo "[CPS SPIKE TEST] Launching high connection rate attack"
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Duration: ${DURATION}s"
echo "CPS Rate: ${CPS_RATE}"
echo "Expected: CPS spike detection after 90s, challenge level → 2"
echo ""

# Create Python script for rapid connect/disconnect
cat > /tmp/cps_spike_attack.py << 'PYEOF'
#!/usr/bin/env python3
import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

target_ip = sys.argv[1]
target_port = int(sys.argv[2])
duration = int(sys.argv[3])
cps_rate = int(sys.argv[4])

total_connections = 0
failed_connections = 0
lock = threading.Lock()

def rapid_connect():
    global total_connections, failed_connections
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target_ip, target_port))

        # Send minimal HTTP request and close immediately
        s.send(b"GET / HTTP/1.0\r\n\r\n")
        s.close()

        with lock:
            total_connections += 1
        return True
    except:
        with lock:
            failed_connections += 1
        return False

print(f"[CPS Spike] Starting rapid connection attack")
print(f"Target: {target_ip}:{target_port}")
print(f"Rate: {cps_rate} connections/sec")
print(f"Duration: {duration}s")
print("")

start_time = time.time()
end_time = start_time + duration

# Use thread pool for parallel connections
with ThreadPoolExecutor(max_workers=cps_rate) as executor:
    iteration = 0
    while time.time() < end_time:
        iter_start = time.time()

        # Submit CPS_RATE connections for this second
        futures = [executor.submit(rapid_connect) for _ in range(cps_rate)]

        # Wait for all connections to complete
        for future in as_completed(futures):
            future.result()

        iteration += 1

        # Status update every 10 iterations
        if iteration % 10 == 0:
            elapsed = int(time.time() - start_time)
            rate = total_connections / elapsed if elapsed > 0 else 0
            print(f"  T+{elapsed}s: {total_connections} total connections, {rate:.1f} cps avg, {failed_connections} failures")

        # Sleep to maintain rate
        elapsed_this_iter = time.time() - iter_start
        if elapsed_this_iter < 1.0:
            time.sleep(1.0 - elapsed_this_iter)

total_duration = time.time() - start_time
actual_cps = total_connections / total_duration if total_duration > 0 else 0

print(f"")
print(f"[CPS Spike] Attack complete")
print(f"Total connections: {total_connections}")
print(f"Failed connections: {failed_connections}")
print(f"Actual CPS: {actual_cps:.1f}")
print(f"Success rate: {100*total_connections/(total_connections+failed_connections):.1f}%")
PYEOF

chmod +x /tmp/cps_spike_attack.py

# Run the attack
python3 /tmp/cps_spike_attack.py $TARGET_IP $TARGET_PORT $DURATION $CPS_RATE

echo ""
echo "Verification steps:"
echo "  1. Check attack_events table:"
echo "     SELECT * FROM attack_events WHERE attack_type='CPS_SPIKE' ORDER BY detected_at DESC LIMIT 1;"
echo "  2. Check anomaly_detection_state:"
echo "     SELECT origin_id, cps_breach_count, current_challenge_level FROM anomaly_detection_state;"
echo "  3. Check CPS metric:"
echo "     curl http://localhost:8000/api/v1/origins/O1/metrics/latest | jq '.metric.cps'"
echo "  4. Verify challenge level escalation:"
echo "     curl http://localhost:8000/api/v1/challenge_levels | jq"
echo ""

# Cleanup
rm -f /tmp/cps_spike_attack.py
