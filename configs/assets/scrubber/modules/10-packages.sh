#!/bin/bash
# Module: install system packages and python dependencies
set -euo pipefail

echo "[module 10] Waiting for cloud-init and APT locks to clear..."

# Wait for cloud-init to complete FIRST (prevents race conditions with sudoers)
cloud-init status --wait 2>/dev/null || true

# Now configure passwordless sudo AFTER cloud-init has finished
# This ensures cloud-init doesn't overwrite our config
echo "[module 10] Ensuring passwordless sudo for ubuntu user..."
# AWS Ubuntu AMIs have this via cloud-init, but ensure it exists
# This is CRITICAL for post-bootstrap SSH commands (XDP attach, BPF operations)
echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99-tensorprox-ubuntu
chmod 440 /etc/sudoers.d/99-tensorprox-ubuntu

# Verify sudo works for ubuntu user
echo "[module 10] Verifying passwordless sudo..."
if su - ubuntu -c "sudo -n true" 2>/dev/null; then
    echo "[module 10] ✓ Passwordless sudo configured and verified"
else
    echo "[module 10] ERROR: Passwordless sudo verification failed!" >&2
    cat /etc/sudoers.d/99-tensorprox-ubuntu >&2
    ls -la /etc/sudoers.d/ >&2
    exit 1
fi

# Wait for APT/dpkg locks to clear (max 5 minutes)
wait_for_apt() {
    local max_attempts=60
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && \
           ! fuser /var/lib/apt/lists/lock >/dev/null 2>&1 && \
           ! fuser /var/cache/apt/archives/lock >/dev/null 2>&1 && \
           ! pgrep -x apt-get >/dev/null 2>&1 && \
           ! pgrep -x dpkg >/dev/null 2>&1 && \
           ! pgrep -x unattended-upgrade >/dev/null 2>&1; then
            echo "[module 10] APT locks cleared after ${attempt} attempts"
            return 0
        fi

        echo "[module 10] Waiting for APT locks to clear... (attempt $((attempt + 1))/$max_attempts)"
        sleep 5
        attempt=$((attempt + 1))
    done

    echo "[module 10] WARNING: APT locks still present after 5 minutes, proceeding anyway"
    return 1
}

# Execute the wait
wait_for_apt

echo "[module 10] Testing DNS configuration..."

# Fix DNS: Disable systemd-resolved stub and use direct nameservers
# Why: systemd-resolved (127.0.0.53) causes slow/timeout issues for Python HTTPS requests
# even when VPC DNS (10.0.0.2) works for dig queries
echo "[module 10] Disabling systemd-resolved and configuring direct DNS..."

systemctl stop systemd-resolved 2>/dev/null || true
systemctl disable systemd-resolved 2>/dev/null || true
systemctl mask systemd-resolved 2>/dev/null || true

# Remove stub resolver symlink (remove immutable flag first if retrying)
chattr -i /etc/resolv.conf 2>/dev/null || true
rm -f /etc/resolv.conf

# Configure dual DNS: VPC primary + Google fallback
# VPC DNS can be unreliable during bootstrap, Google DNS provides fallback
echo "[module 10] Configuring dual DNS (VPC + Google fallback)..."

# Get AWS region dynamically from instance metadata
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
AWS_REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo "us-east-1")

cat > /etc/resolv.conf <<EOF
nameserver 10.0.0.2
nameserver 8.8.8.8
nameserver 8.8.4.4
search ${AWS_REGION}.compute.internal
EOF

# CRITICAL: Protect /etc/resolv.conf from DHCP overwrite
# Without this, DHCP lease renewal (~60 min) overwrites DNS config and breaks connectivity
chattr +i /etc/resolv.conf

echo "[module 10] ✓ DNS configured and protected (dual DNS, immutable, systemd-resolved disabled)"

# CRITICAL: Disable DHCP and configure static IP to prevent T+60 minute network failure
# DHCP lease renewal after ~60 minutes causes network TX path to break
echo "[module 10] Configuring static IP (disabling DHCP)..."

# Get current IP configuration from active interface
CURRENT_IP=$(ip -4 addr show ens5 | awk '/inet / {print $2}' | cut -d'/' -f1 | head -1)
CURRENT_GW="10.0.1.1"

if [[ -z "$CURRENT_IP" ]]; then
    echo "[module 10] ERROR: Could not determine current IP address" >&2
    exit 1
fi

# Disable cloud-init network management
mkdir -p /etc/cloud/cloud.cfg.d
cat > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg <<EOF
network: {config: disabled}
EOF

# Configure static IP via netplan
cat > /etc/netplan/99-static-aws.yaml <<EOF
network:
  version: 2
  ethernets:
    ens5:
      dhcp4: false
      addresses:
        - ${CURRENT_IP}/24
      routes:
        - to: default
          via: ${CURRENT_GW}
        - to: 10.0.0.2/32
          via: ${CURRENT_GW}
      nameservers:
        addresses: [10.0.0.2, 8.8.8.8, 8.8.4.4]
        search: [${AWS_REGION}.compute.internal]
EOF

# Apply netplan configuration (replaces DHCP with static)
netplan apply

echo "[module 10] ✓ Static IP configured: ${CURRENT_IP}/24 (DHCP disabled)"

# Ensure hostname resolves locally to silence sudo warnings.
HOSTNAME_FQDN="$(hostname)"
if ! grep -q "$HOSTNAME_FQDN" /etc/hosts; then
    echo "[module 10] Adding ${HOSTNAME_FQDN} to /etc/hosts (${CURRENT_IP})"
    echo "${CURRENT_IP} ${HOSTNAME_FQDN}" >> /etc/hosts
else
    echo "[module 10] /etc/hosts already contains ${HOSTNAME_FQDN}"
fi

echo "[module 10] Installing base packages..."
export DEBIAN_FRONTEND=noninteractive

# Retry apt-get update with exponential backoff
for i in 1 2 3; do
    if apt-get update -qq; then
        echo "[module 10] apt-get update successful"
        break
    fi
    echo "[module 10] apt-get update failed (attempt $i/3), waiting..."
    sleep $((i * 10))
done

# Install packages with retry logic
apt-get install -y -qq \
    iproute2 wireguard wireguard-tools \
    conntrack ethtool libbpf-dev libc6-dev-i386 \
    linux-tools-"$(uname -r)" linux-tools-generic \
    clang llvm make gcc pkg-config \
    jq curl python3-pip python3-yaml \
    ca-certificates socat tcpdump iperf3 hping3

if [[ -x "/usr/lib/linux-tools-$(uname -r)/bpftool" && ! -e /usr/bin/bpftool ]]; then
    ln -s "/usr/lib/linux-tools-$(uname -r)/bpftool" /usr/bin/bpftool
fi

pip3 install --quiet requests boto3 psycopg2-binary pyyaml psutil
