#!/bin/bash
# Module 12: Configure WireGuard Service Resilience
# Ensures WireGuard tunnels have proper systemd integration
#
# NOTE: wg-quick@.service is Type=oneshot (runs once to setup interface).
# Restart= directives don't work with oneshot. The interface stays up after
# wg-quick exits - this is by design. If the interface goes down, use
# health monitoring to detect and restart via miner failover.

set -euo pipefail

echo "Configuring WireGuard service dependencies..."

# Create systemd drop-in directory for wg-quick service template
mkdir -p /etc/systemd/system/wg-quick@.service.d

# Create dependency configuration (NO restart - incompatible with oneshot)
# This applies to ALL wg-quick@* services (template override)
cat > /etc/systemd/system/wg-quick@.service.d/deps.conf << 'DEPS_CONF'
[Unit]
# Ensure WireGuard starts after network is fully ready
After=network-online.target
Wants=network-online.target

# Rate limiting for manual restarts (prevent restart storm)
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
# Increase stop timeout for graceful shutdown
TimeoutStopSec=30
DEPS_CONF

# Reload systemd to apply changes
systemctl daemon-reload

echo "✓ WireGuard service dependencies configured"
echo "  - After=network-online.target (wait for network)"
echo "  - StartLimitBurst=5 (prevent restart storms)"
echo "  - NOTE: No auto-restart (wg-quick is oneshot - interface stays up)"
