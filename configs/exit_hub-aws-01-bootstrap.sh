#!/bin/bash
# Minimal bootstrap for AWS exit hubs (parity with Linode flow)

set -euo pipefail
exec > >(tee -a /var/log/exit-hub-bootstrap.log)
exec 2>&1

echo "========================================="
echo "Exit Hub Initialisation - $(date)"
echo "========================================="

# Ensure outbound connectivity before TensorProx post-provisioning runs
until ping -c 1 1.1.1.1 >/dev/null 2>&1; do
    echo "Waiting for network..."
    sleep 2
done

echo "Network ready. Awaiting TensorProx Manager bootstrap payload..."

# Cloud-init compatibility marker so future scripts know user-data finished
touch /var/lib/cloud/instance/boot-finished-marker || true
