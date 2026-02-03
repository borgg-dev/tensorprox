#!/bin/bash
# Origin Server Setup Script - Two-Phase Deployment
# Deploys 6 test servers (3 TCP + 3 UDP) with systemd services
set -euo pipefail

echo "Starting Origin server setup at $(date)" | tee -a /root/setup-servers.log

# Environment variables with defaults
TCP_ECHO_PORT="${TCP_ECHO_PORT:-9001}"
TCP_HTTP_PORT="${TCP_HTTP_PORT:-8080}"
TCP_CUSTOM_PORT="${TCP_CUSTOM_PORT:-9003}"
UDP_ECHO_PORT="${UDP_ECHO_PORT:-9101}"
UDP_DGRAM_PORT="${UDP_DGRAM_PORT:-9102}"
UDP_CUSTOM_PORT="${UDP_CUSTOM_PORT:-9103}"

# ============================================================================
# INSTALL SERVER SCRIPTS
# ============================================================================

echo "Installing server scripts..." | tee -a /root/setup-servers.log
mkdir -p /opt/origin-servers

# Copy server scripts from assets directory
for script in tcp-echo.py tcp-http.py tcp-custom.py udp-echo.py udp-dgram.py udp-custom.py; do
    if [[ -f "/root/assets/origin/${script}" ]]; then
        cp "/root/assets/origin/${script}" "/opt/origin-servers/${script}"
        chmod +x "/opt/origin-servers/${script}"
        echo "Installed ${script}" | tee -a /root/setup-servers.log
    else
        echo "ERROR: Missing ${script}" | tee -a /root/setup-servers.log
        exit 1
    fi
done

# ============================================================================
# CREATE SYSTEMD SERVICE FILES
# ============================================================================

echo "Creating systemd services..." | tee -a /root/setup-servers.log

# TCP Echo Service
cat > /etc/systemd/system/tcp-echo.service << EOF
[Unit]
Description=TCP Echo Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/origin-servers/tcp-echo.py ${TCP_ECHO_PORT}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# TCP HTTP Service
cat > /etc/systemd/system/tcp-http.service << EOF
[Unit]
Description=TCP HTTP Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/origin-servers/tcp-http.py ${TCP_HTTP_PORT}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# TCP Custom Service
cat > /etc/systemd/system/tcp-custom.service << EOF
[Unit]
Description=TCP Custom Protocol Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/origin-servers/tcp-custom.py ${TCP_CUSTOM_PORT}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# UDP Echo Service
cat > /etc/systemd/system/udp-echo.service << EOF
[Unit]
Description=UDP Echo Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/origin-servers/udp-echo.py ${UDP_ECHO_PORT}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# UDP Datagram Service
cat > /etc/systemd/system/udp-dgram.service << EOF
[Unit]
Description=UDP Datagram Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/origin-servers/udp-dgram.py ${UDP_DGRAM_PORT}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# UDP Custom Service
cat > /etc/systemd/system/udp-custom.service << EOF
[Unit]
Description=UDP Custom Protocol Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/origin-servers/udp-custom.py ${UDP_CUSTOM_PORT}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# ============================================================================
# START ALL SERVICES
# ============================================================================

echo "Starting services..." | tee -a /root/setup-servers.log
systemctl daemon-reload

# Enable and start TCP services
for service in tcp-echo tcp-http tcp-custom; do
    systemctl enable ${service}.service
    systemctl start ${service}.service
    echo "Started ${service}" | tee -a /root/setup-servers.log
done

# Enable and start UDP services
for service in udp-echo udp-dgram udp-custom; do
    systemctl enable ${service}.service
    systemctl start ${service}.service
    echo "Started ${service}" | tee -a /root/setup-servers.log
done

# ============================================================================
# VERIFICATION
# ============================================================================

sleep 5

echo "=== Service Status ===" | tee -a /root/setup-servers.log
for service in tcp-echo tcp-http tcp-custom udp-echo udp-dgram udp-custom; do
    systemctl status ${service}.service --no-pager | tee -a /root/setup-servers.log
done

echo "=== Listening Ports ===" | tee -a /root/setup-servers.log
ss -tuln | grep -E "(${TCP_ECHO_PORT}|${TCP_HTTP_PORT}|${TCP_CUSTOM_PORT}|${UDP_ECHO_PORT}|${UDP_DGRAM_PORT}|${UDP_CUSTOM_PORT})" | tee -a /root/setup-servers.log

echo "Setup complete at $(date)" | tee -a /root/setup-servers.log
echo "TCP Echo Server: ${TCP_ECHO_PORT}" | tee -a /root/setup-servers.log
echo "TCP HTTP Server: ${TCP_HTTP_PORT}" | tee -a /root/setup-servers.log
echo "TCP Custom Server: ${TCP_CUSTOM_PORT}" | tee -a /root/setup-servers.log
echo "UDP Echo Server: ${UDP_ECHO_PORT}" | tee -a /root/setup-servers.log
echo "UDP Datagram Server: ${UDP_DGRAM_PORT}" | tee -a /root/setup-servers.log
echo "UDP Custom Server: ${UDP_CUSTOM_PORT}" | tee -a /root/setup-servers.log
