"""
Rate Configuration Service for Intelligent Rate Limiting.

Manages per-origin rate limit configurations derived from bandwidth quotas.
Pushes configurations to scrubber BPF maps for XDP to read.

CRITICAL: Must be called during:
1. Origin creation (both active and standby)
2. Bandwidth quota changes
3. Standby pre-configuration for fast failover

AUDIT MODE:
For audit origins (shard_type='audit'), we use much stricter rate limits.
This is critical for the audit system to work correctly:
- Attack traffic is CONCENTRATED (few sources, many packets each)
- Benign traffic is DISTRIBUTED (unique source per packet)
- The per-source rate limit must be low enough that concentrated attack
  traffic exceeds it, while distributed benign traffic stays below it.
"""

import ipaddress
import struct
import logging
from typing import Dict, Optional

from shared.utils.ssh import ssh_exec

# Import audit-specific rate limit configuration
try:
    from tensorprox.config.audit_config import AUDIT_PER_SOURCE_BUDGET_PPS
except ImportError:
    AUDIT_PER_SOURCE_BUDGET_PPS = 50  # Fallback if config not available

logger = logging.getLogger(__name__)

# Default values if origin doesn't have bandwidth quota set
DEFAULT_BANDWIDTH_BPS = 1_000_000_000  # 1 Gbps default
DEFAULT_PER_SOURCE_BUDGET = 10000       # 10K PPS if no quota (production)
AUDIT_PER_SOURCE_BUDGET = AUDIT_PER_SOURCE_BUDGET_PPS  # 50 PPS for audit origins
AVG_PACKET_SIZE = 1500                  # Bytes
BITS_PER_BYTE = 8


def calculate_origin_rate_config(
    origin_ip: str,
    bandwidth_quota_bps: Optional[int] = None,
    challenge_level: int = 0,
    override_enabled: bool = False,
    override_pps: int = 0,
    is_audit: bool = False
) -> Dict:
    """
    Calculate rate limit configuration for an origin.

    Args:
        origin_ip: Origin's public IP address
        bandwidth_quota_bps: Origin's bandwidth quota in bits/second
        challenge_level: Current challenge level (0-4) from anomaly detector
        override_enabled: If True, use manual override values
        override_pps: Manual PPS override value
        is_audit: If True, use audit-specific rate limits (much stricter)

    Returns:
        Dict with rate config fields matching struct origin_rate_config

    AUDIT MODE:
        For audit origins, we use a very low per-source rate limit (50 PPS).
        This is critical for the audit system to work:
        - Attack traffic is concentrated (10 IPs sending 200 pkts each = 100 PPS/IP)
        - Benign traffic is distributed (unique IP per packet = 1 pkt/IP)
        - With 50 PPS limit: attack exceeds it (blocked), benign stays under (passes)
    """
    quota_bps = bandwidth_quota_bps or DEFAULT_BANDWIDTH_BPS

    # Convert bandwidth to packets per second
    # quota_bps / (avg_packet_size * bits_per_byte)
    derived_max_pps = quota_bps // (AVG_PACKET_SIZE * BITS_PER_BYTE)

    if is_audit:
        # AUDIT MODE: Use strict per-source rate limits
        # This enables pattern-based detection:
        # - Concentrated attack traffic (few IPs, many packets) → exceeds limit
        # - Distributed benign traffic (unique IPs, 1 packet) → stays under limit
        per_source_budget_pps = AUDIT_PER_SOURCE_BUDGET
        logger.debug(f"Audit origin {origin_ip}: per_source_budget={per_source_budget_pps} PPS (strict)")
    else:
        # PRODUCTION MODE: Each source gets 1% of origin's total allocation
        # This allows 100 concurrent sources at full capacity
        per_source_budget_pps = max(DEFAULT_PER_SOURCE_BUDGET, derived_max_pps // 100)

    return {
        'quota_bps': quota_bps,
        'derived_max_pps': derived_max_pps,
        'per_source_budget_pps': per_source_budget_pps,
        'current_pps': 0,  # Updated by metrics aggregation
        'challenge_level': challenge_level,
        'override_enabled': 1 if override_enabled else 0,
        'override_pps': override_pps if override_enabled else 0,
    }


def pack_origin_rate_config(config: Dict) -> bytes:
    """
    Pack origin_rate_config struct for BPF map update.

    struct origin_rate_config (24 bytes):
        u64 quota_bps
        u32 derived_max_pps
        u32 per_source_budget_pps
        u32 current_pps
        u8  challenge_level
        u8  override_enabled
        u16 override_pps

    Uses little-endian format ('<') to match x86 architecture.
    Format: Q=u64, I=u32, B=u8, H=u16
    """
    return struct.pack(
        '<QIIIBBH',
        config['quota_bps'],
        config['derived_max_pps'],
        config['per_source_budget_pps'],
        config['current_pps'],
        config['challenge_level'],
        config['override_enabled'],
        config['override_pps'],
    )


def ip_to_hex(ip_str: str) -> str:
    """Convert IP address to hex string for bpftool."""
    packed = ipaddress.IPv4Address(ip_str).packed
    return ' '.join(f'{b:02x}' for b in packed)


def push_origin_rate_config(
    host: str,
    origin_ip: str,
    config: Dict,
    ssh_key_path: str,
    nodes_db: dict = None
) -> bool:
    """
    Push rate config for a single origin to a scrubber.

    Args:
        host: Scrubber IP address
        origin_ip: Origin's public IP (BPF map key)
        config: Rate config dict from calculate_origin_rate_config()
        ssh_key_path: Path to SSH private key
        nodes_db: Node database for SSH user resolution

    Returns:
        True if successful, False otherwise
    """
    try:
        # Pack the struct
        value_bytes = pack_origin_rate_config(config)
        value_hex = ' '.join(f'{b:02x}' for b in value_bytes)
        key_hex = ip_to_hex(origin_ip)

        cmd = (
            f"sudo bpftool map update pinned "
            f"/sys/fs/bpf/xdp/globals/origin_rate_config_map "
            f"key hex {key_hex} "
            f"value hex {value_hex}"
        )

        rc, stdout, stderr = ssh_exec(host, cmd, ssh_key_path, nodes_db=nodes_db, timeout=30)

        if rc != 0:
            logger.error(f"Failed to push rate config to {host} for {origin_ip}: {stderr}")
            return False

        logger.debug(f"Pushed rate config for {origin_ip} to {host}: "
                    f"budget={config['per_source_budget_pps']} PPS")
        return True

    except Exception as e:
        logger.error(f"Error pushing rate config to {host}: {e}")
        return False


def push_rate_configs_to_scrubber(
    host: str,
    configs: Dict[str, Dict],
    ssh_key_path: str,
    nodes_db: dict = None
) -> int:
    """
    Push rate configs for multiple origins to a scrubber.

    Args:
        host: Scrubber IP address
        configs: Dict mapping origin_ip -> rate config
        ssh_key_path: Path to SSH private key
        nodes_db: Node database for SSH user resolution

    Returns:
        Number of successfully pushed configs
    """
    success_count = 0

    for origin_ip, config in configs.items():
        if push_origin_rate_config(host, origin_ip, config, ssh_key_path, nodes_db):
            success_count += 1

    logger.info(f"Pushed {success_count}/{len(configs)} rate configs to {host}")
    return success_count


def delete_origin_rate_config(
    host: str,
    origin_ip: str,
    ssh_key_path: str,
    nodes_db: dict = None
) -> bool:
    """
    Delete rate config for an origin from scrubber.
    Called during origin deletion.
    """
    try:
        key_hex = ip_to_hex(origin_ip)

        cmd = (
            f"sudo bpftool map delete pinned "
            f"/sys/fs/bpf/xdp/globals/origin_rate_config_map "
            f"key hex {key_hex}"
        )

        rc, stdout, stderr = ssh_exec(host, cmd, ssh_key_path, nodes_db=nodes_db, timeout=30)

        # Ignore "not found" errors - map entry might not exist
        if rc != 0 and "not found" not in stderr.lower():
            logger.warning(f"Failed to delete rate config from {host} for {origin_ip}: {stderr}")
            return False

        return True

    except Exception as e:
        logger.error(f"Error deleting rate config from {host}: {e}")
        return False
