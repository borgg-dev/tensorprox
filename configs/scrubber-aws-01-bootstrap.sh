#!/bin/bash
# Minimal bootstrap executed via Terraform user-data
# Leaves full WireGuard dataplane deployment to EMN post-provision orchestration

set -euo pipefail
exec > >(tee -a /var/log/scrubber-bootstrap.log)
exec 2>&1

echo "========================================="
echo "Scrubber Initialisation - $(date)"
echo "========================================="

while ! ping -c 1 8.8.8.8 >/dev/null 2>&1; do
    sleep 2
done

echo "Instance initialised. Awaiting EMN bootstrap payload..."
