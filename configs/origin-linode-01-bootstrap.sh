#!/bin/bash
# Minimal bootstrap for Origin Server - Phase 1 of two-phase deployment
# Installs basic dependencies and waits for SSH-based asset provisioning
set -euo pipefail

echo "Starting Origin bootstrap at $(date)" > /root/bootstrap.log

# Update and install packages (non-interactive)
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  python3 python3-pip \
  iproute2 net-tools \
  curl jq \
  ca-certificates 2>&1 | tee -a /root/bootstrap.log

echo "Bootstrap complete at $(date)" >> /root/bootstrap.log
echo "Waiting for SSH asset provisioning and setup-servers.sh execution" >> /root/bootstrap.log
