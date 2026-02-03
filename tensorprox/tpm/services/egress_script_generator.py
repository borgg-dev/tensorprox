"""Egress installer script generator.

Generates a POSIX-compliant shell script that:
1. Writes /etc/tensorprox/egress.conf with questionnaire values
2. Installs tp-reload script (creates GRE tunnel, applies firewall rules)
3. Installs tp-delete script (removes tunnel, rules, config, self-destructs)
4. Executes tp-reload to activate egress routing
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Default blacklist entries (immutable system defaults)
DEFAULT_BLACKLIST_PORTS = "22 53 68 123"
DEFAULT_BLACKLIST_CIDRS = (
    "127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16"
)

# Cloud provider metadata IPs (all use link-local 169.254.169.254)
CLOUD_METADATA_CIDRS = {
    "aws": "169.254.169.254/32",
    "linode": "169.254.169.254/32",
    "gcp": "169.254.169.254/32",
    "digitalocean": "169.254.169.254/32",
}

# OS package mirror CIDRs (for opt-out of routing updates)
# Note: Only includes resolvable CIDRs, not hostnames
OS_MIRROR_CIDRS = {
    "ubuntu": "91.189.88.0/24 91.189.91.0/24 91.189.92.0/24",
    "debian": "151.101.0.0/16 199.232.0.0/16",
    "centos": "23.128.0.0/16",  # Fastly CDN (CentOS mirrors)
    "rhel": "104.18.0.0/16",  # Cloudflare CDN (RHEL CDN)
}

# Backup provider CIDRs
# Note: S3 uses well-known ranges, others may need DNS resolution
BACKUP_PROVIDER_CIDRS = {
    "s3": "52.216.0.0/15 54.231.0.0/16",
    "gcs": "142.250.0.0/15",  # Google Cloud IP range
    "backblaze": "206.190.224.0/20",
}


def generate_egress_installer(
    *,
    origin_id: str,
    exit_hub_ip: str,
    callback_url: str,
    questionnaire: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a complete installer script for egress routing.

    Args:
        origin_id: Unique identifier for the origin
        exit_hub_ip: IP address of the exit hub
        callback_url: Base URL for TPM callbacks (e.g., https://app.tensorprox.com/api/v1)
        questionnaire: Optional questionnaire responses containing:
            - cloud_provider: aws, linode, gcp, digitalocean, other
            - route_system_updates: bool (True = route through TensorProx)
            - os_type: ubuntu, debian, centos, rhel, other
            - backup_providers: list of s3, gcs, backblaze
            - nic_name: specific interface or empty for auto-detect
            - custom_blacklist_ports: additional ports to bypass
            - custom_blacklist_cidrs: additional CIDRs to bypass
            - custom_blacklist_ips: additional IPs to bypass

    Returns:
        Complete shell script as string
    """
    q = questionnaire or {}

    # Build blacklist from questionnaire
    blacklist_ports = _build_blacklist_ports(q)
    blacklist_cidrs = _build_blacklist_cidrs(q)
    blacklist_ips = _build_blacklist_ips(q)
    nic_name = q.get("nic_name", "")

    # Generate config content
    config_content = _generate_config(
        origin_id=origin_id,
        exit_hub_ip=exit_hub_ip,
        callback_url=callback_url,
        nic_name=nic_name,
        blacklist_ports=blacklist_ports,
        blacklist_cidrs=blacklist_cidrs,
        blacklist_ips=blacklist_ips,
    )

    # Generate complete installer script
    return _generate_installer_script(config_content)


def _build_blacklist_ports(questionnaire: Dict[str, Any]) -> str:
    """Build port blacklist from defaults and questionnaire."""
    ports = set(DEFAULT_BLACKLIST_PORTS.split())

    # Add custom ports from questionnaire
    custom_ports = questionnaire.get("custom_blacklist_ports", [])
    if isinstance(custom_ports, str):
        custom_ports = custom_ports.split()
    ports.update(str(p) for p in custom_ports)

    return " ".join(sorted(ports, key=lambda x: int(x) if x.isdigit() else 0))


def _build_blacklist_cidrs(questionnaire: Dict[str, Any]) -> str:
    """Build CIDR blacklist from defaults and questionnaire."""
    cidrs = set(DEFAULT_BLACKLIST_CIDRS.split())

    # Add cloud metadata CIDR
    cloud_provider = questionnaire.get("cloud_provider", "").lower()
    if cloud_provider in CLOUD_METADATA_CIDRS:
        cidrs.add(CLOUD_METADATA_CIDRS[cloud_provider])

    # Add OS mirror CIDRs if not routing updates
    if not questionnaire.get("route_system_updates", True):
        os_type = questionnaire.get("os_type", "").lower()
        if os_type in OS_MIRROR_CIDRS:
            cidrs.update(OS_MIRROR_CIDRS[os_type].split())

    # Add backup provider CIDRs
    backup_providers = questionnaire.get("backup_providers", [])
    if isinstance(backup_providers, str):
        backup_providers = [backup_providers]
    for provider in backup_providers:
        provider_lower = provider.lower()
        if provider_lower in BACKUP_PROVIDER_CIDRS:
            cidrs.update(BACKUP_PROVIDER_CIDRS[provider_lower].split())

    # Add custom CIDRs
    custom_cidrs = questionnaire.get("custom_blacklist_cidrs", [])
    if isinstance(custom_cidrs, str):
        custom_cidrs = custom_cidrs.split()
    cidrs.update(custom_cidrs)

    return " ".join(sorted(cidrs))


def _build_blacklist_ips(questionnaire: Dict[str, Any]) -> str:
    """Build IP blacklist from questionnaire."""
    ips = set()

    custom_ips = questionnaire.get("custom_blacklist_ips", [])
    if isinstance(custom_ips, str):
        custom_ips = custom_ips.split()
    ips.update(custom_ips)

    return " ".join(sorted(ips))


def _generate_config(
    *,
    origin_id: str,
    exit_hub_ip: str,
    callback_url: str,
    nic_name: str,
    blacklist_ports: str,
    blacklist_cidrs: str,
    blacklist_ips: str,
) -> str:
    """Generate the egress.conf content."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return f'''# /etc/tensorprox/egress.conf
# TensorProx Egress Routing Configuration
# Origin: {origin_id}
# Generated: {generated_at}
#
# To reload after edits: sudo tp-reload
# To remove completely:  sudo tp-delete

# ============================================
# TUNNEL CONFIGURATION (managed by TensorProx)
# ============================================
TP_EXIT_HUB_IP="{exit_hub_ip}"
TP_TUNNEL_LOCAL_IP="10.99.0.2"
TP_TUNNEL_REMOTE_IP="10.99.0.1"
TP_TUNNEL_INTERFACE="gre-tpm"

# ============================================
# NETWORK INTERFACE
# ============================================
# Leave empty for auto-detection (recommended)
TP_NIC_NAME="{nic_name}"

# ============================================
# BLACKLIST - PORTS (bypass TensorProx)
# ============================================
TP_BLACKLIST_PORTS="{blacklist_ports}"

# ============================================
# BLACKLIST - CIDRS (bypass TensorProx)
# ============================================
TP_BLACKLIST_CIDRS="{blacklist_cidrs}"

# ============================================
# BLACKLIST - IPS (bypass TensorProx)
# ============================================
TP_BLACKLIST_IPS="{blacklist_ips}"

# ============================================
# TPM CALLBACK (for activation/deactivation)
# ============================================
TP_ORIGIN_ID="{origin_id}"
TP_CALLBACK_URL="{callback_url}"

# ============================================
# ADVANCED (do not modify unless instructed)
# ============================================
TP_ROUTING_TABLE="100"
TP_FWMARK="0x1"
TP_CONFIG_VERSION="1"
'''


def _generate_installer_script(config_content: str) -> str:
    """Generate the complete installer script with embedded tp-reload and tp-delete."""
    # Escape config content for embedding in heredoc
    config_escaped = config_content.replace("'", "'\\''")

    return f'''#!/bin/sh
# TensorProx Egress Routing Installer
# Generated by TensorProx Management
#
# This script:
#   1. Creates /etc/tensorprox/egress.conf
#   2. Installs /usr/local/bin/tp-reload
#   3. Installs /usr/local/bin/tp-delete
#   4. Executes tp-reload to activate egress routing
#
# POSIX-compliant (sh, dash, bash compatible)

set -e

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

echo "TensorProx Egress Routing Installer"
echo "===================================="
echo ""

# Create config directory
mkdir -p /etc/tensorprox
chmod 700 /etc/tensorprox

# Write config file
echo "Writing configuration to /etc/tensorprox/egress.conf..."
cat > /etc/tensorprox/egress.conf << 'EOFCONFIG'
{config_escaped}
EOFCONFIG
chmod 600 /etc/tensorprox/egress.conf
echo "  Done."

# Install tp-reload script
echo "Installing /usr/local/bin/tp-reload..."
cat > /usr/local/bin/tp-reload << 'EOFRELOAD'
{_generate_tp_reload_script()}
EOFRELOAD
chmod 755 /usr/local/bin/tp-reload
echo "  Done."

# Install tp-delete script
echo "Installing /usr/local/bin/tp-delete..."
cat > /usr/local/bin/tp-delete << 'EOFDELETE'
{_generate_tp_delete_script()}
EOFDELETE
chmod 755 /usr/local/bin/tp-delete
echo "  Done."

# Execute tp-reload to activate
echo ""
echo "Activating egress routing..."
/usr/local/bin/tp-reload

echo ""
echo "===================================="
echo "TensorProx Egress Routing is now ACTIVE"
echo ""
echo "Commands:"
echo "  tp-reload  - Reload configuration"
echo "  tp-delete  - Remove egress routing"
echo ""
'''


def _generate_tp_reload_script() -> str:
    """Generate the tp-reload script content."""
    return '''#!/bin/sh
# tp-reload - TensorProx Egress Routing Loader
# Applies/reloads egress routing configuration
# POSIX-compliant

set -e

CONFIG_FILE="/etc/tensorprox/egress.conf"

# Check config exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file not found: $CONFIG_FILE" >&2
    exit 1
fi

# Source config
. "$CONFIG_FILE"

# Detect primary NIC if not specified
if [ -z "$TP_NIC_NAME" ]; then
    TP_NIC_NAME=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    if [ -z "$TP_NIC_NAME" ]; then
        echo "ERROR: Could not detect network interface" >&2
        exit 1
    fi
fi

echo "Using interface: $TP_NIC_NAME"

# Load GRE kernel module
modprobe ip_gre 2>/dev/null || true

# Remove existing tunnel if present
ip tunnel del "$TP_TUNNEL_INTERFACE" 2>/dev/null || true

# Get local IP
LOCAL_IP=$(ip -4 addr show "$TP_NIC_NAME" | awk '/inet / {split($2,a,"/"); print a[1]}' | head -1)
if [ -z "$LOCAL_IP" ]; then
    echo "ERROR: Could not determine local IP for $TP_NIC_NAME" >&2
    exit 1
fi

echo "Local IP: $LOCAL_IP"
echo "Exit Hub: $TP_EXIT_HUB_IP"

# Create GRE tunnel with MTU 1400 (safe for internet paths, avoids TLS handshake timeouts)
ip tunnel add "$TP_TUNNEL_INTERFACE" mode gre remote "$TP_EXIT_HUB_IP" local "$LOCAL_IP" ttl 64
ip link set "$TP_TUNNEL_INTERFACE" up
ip link set "$TP_TUNNEL_INTERFACE" mtu 1400
ip addr add "$TP_TUNNEL_LOCAL_IP/30" dev "$TP_TUNNEL_INTERFACE"

echo "GRE tunnel $TP_TUNNEL_INTERFACE created (MTU 1400)"

# Detect firewall (prefer nftables)
if command -v nft >/dev/null 2>&1; then
    FW_TYPE="nftables"
else
    FW_TYPE="iptables"
fi

echo "Firewall type: $FW_TYPE"

# Apply firewall rules
if [ "$FW_TYPE" = "nftables" ]; then
    # Create table and chain if not exist
    nft add table ip tensorprox 2>/dev/null || true
    nft add chain ip tensorprox prerouting '{ type nat hook prerouting priority -100; }' 2>/dev/null || true
    nft add chain ip tensorprox output '{ type route hook output priority -100; }' 2>/dev/null || true

    # Flush existing rules
    nft flush chain ip tensorprox prerouting 2>/dev/null || true
    nft flush chain ip tensorprox output 2>/dev/null || true

    # CRITICAL: Bypass exit hub IP to prevent GRE tunnel routing loop
    # GRE encapsulated packets must reach exit hub directly, not via tunnel
    nft add rule ip tensorprox output ip daddr "$TP_EXIT_HUB_IP" accept

    # Add port bypasses (destination ports - outbound connections)
    for port in $TP_BLACKLIST_PORTS; do
        nft add rule ip tensorprox output tcp dport "$port" accept
        nft add rule ip tensorprox output udp dport "$port" accept
    done

    # Add port bypasses (source ports - server responses, e.g., SSH replies)
    for port in $TP_BLACKLIST_PORTS; do
        nft add rule ip tensorprox output tcp sport "$port" accept
        nft add rule ip tensorprox output udp sport "$port" accept
    done

    # Add CIDR bypasses
    for cidr in $TP_BLACKLIST_CIDRS; do
        nft add rule ip tensorprox output ip daddr "$cidr" accept
    done

    # Add IP bypasses
    for ip in $TP_BLACKLIST_IPS; do
        nft add rule ip tensorprox output ip daddr "$ip" accept
    done

    # Mark remaining traffic
    nft add rule ip tensorprox output mark set "$TP_FWMARK"

else
    # iptables fallback
    # Flush existing rules
    iptables -t mangle -F TENSORPROX_OUT 2>/dev/null || true
    iptables -t mangle -X TENSORPROX_OUT 2>/dev/null || true

    # Create chain
    iptables -t mangle -N TENSORPROX_OUT
    iptables -t mangle -A OUTPUT -j TENSORPROX_OUT

    # CRITICAL: Bypass exit hub IP to prevent GRE tunnel routing loop
    # GRE encapsulated packets must reach exit hub directly, not via tunnel
    iptables -t mangle -A TENSORPROX_OUT -d "$TP_EXIT_HUB_IP" -j RETURN

    # Add port bypasses (destination ports - outbound connections)
    for port in $TP_BLACKLIST_PORTS; do
        iptables -t mangle -A TENSORPROX_OUT -p tcp --dport "$port" -j RETURN
        iptables -t mangle -A TENSORPROX_OUT -p udp --dport "$port" -j RETURN
    done

    # Add port bypasses (source ports - server responses, e.g., SSH replies)
    for port in $TP_BLACKLIST_PORTS; do
        iptables -t mangle -A TENSORPROX_OUT -p tcp --sport "$port" -j RETURN
        iptables -t mangle -A TENSORPROX_OUT -p udp --sport "$port" -j RETURN
    done

    # Add CIDR bypasses
    for cidr in $TP_BLACKLIST_CIDRS; do
        iptables -t mangle -A TENSORPROX_OUT -d "$cidr" -j RETURN
    done

    # Add IP bypasses
    for ip in $TP_BLACKLIST_IPS; do
        iptables -t mangle -A TENSORPROX_OUT -d "$ip" -j RETURN
    done

    # Mark remaining traffic
    iptables -t mangle -A TENSORPROX_OUT -j MARK --set-mark "$TP_FWMARK"
fi

echo "Firewall rules applied"

# Call TPM activation endpoint BEFORE policy routing
# This allows TPM to configure the exit hub's GRE tunnel while traffic still routes directly
if [ -n "$TP_CALLBACK_URL" ] && [ -n "$TP_ORIGIN_ID" ]; then
    echo "Notifying TensorProx to configure exit hub..."
    if curl -sS -X POST "${TP_CALLBACK_URL}/origins/${TP_ORIGIN_ID}/egress/activate" \\
        -H "Content-Type: application/json" \\
        -d "{}" \\
        --connect-timeout 10 \\
        --max-time 60; then
        echo "Exit hub configured successfully"
    else
        echo "WARNING: Failed to configure exit hub. Egress routing may not work."
        echo "You can retry later with: tp-reload"
    fi
fi

# Policy routing - only apply after exit hub is configured
ip rule del fwmark "$TP_FWMARK" table "$TP_ROUTING_TABLE" 2>/dev/null || true
ip rule add fwmark "$TP_FWMARK" table "$TP_ROUTING_TABLE"
ip route replace default via "$TP_TUNNEL_REMOTE_IP" dev "$TP_TUNNEL_INTERFACE" table "$TP_ROUTING_TABLE"

echo "Policy routing configured"

echo ""
echo "Egress routing is ACTIVE"
echo "All outbound traffic (except blacklisted) now routes through TensorProx"
'''


def _generate_tp_delete_script() -> str:
    """Generate the tp-delete script content."""
    return '''#!/bin/sh
# tp-delete - TensorProx Egress Routing Remover
# Removes all egress routing configuration
# POSIX-compliant

set -e

CONFIG_FILE="/etc/tensorprox/egress.conf"

echo "TensorProx Egress Routing Removal"
echo "================================="

# Source config if exists (for cleanup values)
if [ -f "$CONFIG_FILE" ]; then
    . "$CONFIG_FILE"
else
    # Use defaults if config missing
    TP_TUNNEL_INTERFACE="gre-tpm"
    TP_ROUTING_TABLE="100"
    TP_FWMARK="0x1"
fi

# Remove policy routing
echo "Removing policy routing..."
ip rule del fwmark "$TP_FWMARK" table "$TP_ROUTING_TABLE" 2>/dev/null || true
ip route del default table "$TP_ROUTING_TABLE" 2>/dev/null || true

# Remove GRE tunnel
echo "Removing GRE tunnel..."
ip link set "$TP_TUNNEL_INTERFACE" down 2>/dev/null || true
ip tunnel del "$TP_TUNNEL_INTERFACE" 2>/dev/null || true

# Remove firewall rules
echo "Removing firewall rules..."
if command -v nft >/dev/null 2>&1; then
    nft delete table ip tensorprox 2>/dev/null || true
fi

# iptables cleanup
iptables -t mangle -D OUTPUT -j TENSORPROX_OUT 2>/dev/null || true
iptables -t mangle -F TENSORPROX_OUT 2>/dev/null || true
iptables -t mangle -X TENSORPROX_OUT 2>/dev/null || true

# Call TPM deactivation endpoint
if [ -n "$TP_CALLBACK_URL" ] && [ -n "$TP_ORIGIN_ID" ]; then
    echo "Notifying TensorProx..."
    curl -sS -X DELETE "${TP_CALLBACK_URL}/origins/${TP_ORIGIN_ID}/egress" \\
        -H "Content-Type: application/json" \\
        --connect-timeout 10 \\
        --max-time 30 \\
        || echo "Warning: Failed to notify TensorProx (non-fatal)"
fi

# Remove config directory
echo "Removing configuration..."
rm -rf /etc/tensorprox

# Remove scripts
echo "Removing scripts..."
rm -f /usr/local/bin/tp-reload
rm -f /usr/local/bin/tp-delete

echo ""
echo "================================="
echo "TensorProx Egress Routing has been REMOVED"
echo ""
'''
