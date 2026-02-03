#!/bin/bash
# Module: install and configure the ecp-agent service
set -euo pipefail

echo "[module 50] Deploying ecp-agent..."
ROOT="${SCRUBBER_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOURCE_DIR="${ROOT}/assets/ecp-agent"
BIN_DIR="/opt/tensorprox/bin"

# Use INSTANCE_ID from environment (passed by miner), fallback to metadata/hostname
# This fixes the issue where metadata service is blocked and ec2-metadata command is missing
INSTANCE_ID="${INSTANCE_ID:-$(ec2-metadata --instance-id 2>/dev/null | awk '{print $2}' || hostname)}"
PRIVATE_IP=$(ip -4 addr show ens5 | awk '/inet / {print $2}' | cut -d'/' -f1 | head -1)

# Install ecp-agent to /opt/tensorprox/bin (consistent with other scripts)
cp "${SOURCE_DIR}/ecp-agent.py" "${BIN_DIR}/ecp-agent.py"
chmod +x "${BIN_DIR}/ecp-agent.py"

# Create systemd service
cat > /etc/systemd/system/ecp-agent.service <<EOSVC
[Unit]
Description=ECP Agent - Health Reporter for Scrubbers
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${BIN_DIR}
ExecStart=/usr/bin/python3 ${BIN_DIR}/ecp-agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Environment
Environment="EMN_URL=http://${EMN_IP}:${EMN_PORT}"
Environment="REPORT_INTERVAL=30"
Environment="NODE_ID=${INSTANCE_ID}"

[Install]
WantedBy=multi-user.target
EOSVC

systemctl daemon-reload
systemctl enable --now ecp-agent.service

cat > /root/bootstrap-status.txt <<EOSTATUS
Bootstrap completed: $(date)
Node ID: ${INSTANCE_ID}
Private IP: ${PRIVATE_IP}
WireGuard dataplane: ACTIVE
Scripts directory: /opt/tensorprox/bin
ecp-agent service: enabled
EOSTATUS

echo "[module 50] ecp-agent running."
