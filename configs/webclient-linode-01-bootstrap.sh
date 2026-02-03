#!/bin/bash
# Web Client Bootstrap - Origin Test Client Setup
# Setup for automated Origin server testing and continuous traffic generation

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[$(date)] Starting Web Client bootstrap..." | tee /root/bootstrap.log

# Update and install minimal packages
apt-get update -qq | tee -a /root/bootstrap.log
apt-get install -y -qq \
  python3 \
  python3-pip \
  python3-venv \
  iputils-ping \
  curl \
  net-tools \
  jq 2>&1 | tee -a /root/bootstrap.log

echo "[$(date)] System packages installed" | tee -a /root/bootstrap.log

# Install Python dependencies for traffic_stream
pip3 install --quiet --break-system-packages \
  pyyaml \
  aiosqlite \
  pydantic 2>&1 | tee -a /root/bootstrap.log

echo "[$(date)] Python dependencies installed" | tee -a /root/bootstrap.log

# Create directories
mkdir -p /root/test_results
mkdir -p /var/log/traffic_stream
mkdir -p /var/lib/traffic_stream

# Create systemd service for traffic_stream (disabled by default)
cat > /etc/systemd/system/traffic-stream.service << 'EOF'
[Unit]
Description=Traffic Stream Client - Continuous Edge Platform Validation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /root/assets/traffic_stream.py \
    --config /root/assets/traffic_stream_config.yaml \
    --log-dir /var/log/traffic_stream \
    --db-path /var/lib/traffic_stream/metrics.db
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=traffic-stream

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/log/traffic_stream /var/lib/traffic_stream

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "[$(date)] traffic-stream service created (disabled by default)" | tee -a /root/bootstrap.log

# Mark bootstrap complete
echo "[$(date)] Web Client bootstrap complete" | tee -a /root/bootstrap.log
touch /var/lib/cloud/instance/boot-finished
