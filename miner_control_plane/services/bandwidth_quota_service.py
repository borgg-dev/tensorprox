"""Bandwidth Quota Service - Calculates and pushes per-origin bandwidth quotas

Triggered when:
- Origin added/removed
- Origin enabled/disabled
- Scrubber capacity updated
- Manual API call

Calculates fair-share quotas and pushes to scrubber BPF maps via SSH.
"""
import logging
from typing import Dict, Optional
from shared.config import get_settings
from shared.utils.ssh import ssh_exec
from miner_control_plane.services.state_manager import state_manager

logger = logging.getLogger(__name__)

# Default bandwidth when capacity is unknown (1 Gbps)
DEFAULT_BANDWIDTH_BPS = 1_000_000_000


def calculate_quotas_for_shard(shard_id: str) -> Dict[str, dict]:
    """
    Calculate per-origin bandwidth quotas for all origins in a shard.

    Formula:
        usable_bps = node_bandwidth * (1 - buffer_percent/100)
        quota_per_origin = usable_bps / active_origin_count
        burst_bytes = quota_per_origin * 10  (10-second burst)

    Args:
        shard_id: Shard to calculate quotas for

    Returns:
        Dict mapping origin_ip to quota config:
        {
            "10.0.1.100": {"quota_bps": 200000000, "burst_bytes": 2000000000},
            ...
        }
    """
    settings = get_settings()
    buffer_percent = getattr(settings, 'qos_buffer_percent', 20)

    # Simple mode: fixed quota per origin (no fair-share calculation)
    quota_mode = getattr(settings, 'quota_mode', 'simple')
    if quota_mode == 'simple':
        simple_quota_mbps = getattr(settings, 'simple_quota_mbps', 100)
        quota_bps = simple_quota_mbps * 1_000_000  # Convert Mbps to bps
        burst_bytes = quota_bps * 10  # 10-second burst allowance

        # Get active origins for this shard
        origins = state_manager.get_origins_for_shard(shard_id)
        active_origins = [o for o in origins if o.get('state') == 'IN_SERVICE']

        if not active_origins:
            logger.info(f"No active origins in shard {shard_id}")
            return {}

        quotas = {}
        for origin in active_origins:
            origin_ip = origin.get('origin_ip')
            if origin_ip:
                quotas[origin_ip] = {
                    'quota_bps': quota_bps,
                    'burst_bytes': burst_bytes,
                }
                # Update state manager cache
                state_manager.update_bandwidth_quota(origin_ip, quotas[origin_ip])

        logger.info(
            f"Simple quota mode: shard {shard_id}, {len(quotas)} origins @ "
            f"{simple_quota_mbps} Mbps each"
        )
        return quotas

    # Dynamic mode: fair-share calculation based on node bandwidth
    # Get nodes for this shard (returns List[dict])
    nodes = state_manager.get_nodes_for_shard(shard_id)
    if not nodes:
        logger.warning(f"No nodes found for shard {shard_id}")
        return {}

    # Get active node's bandwidth capacity
    active_node = None
    for node_data in nodes:
        if node_data.get('role') == 'active':
            active_node = node_data
            break

    if not active_node:
        # Fallback to first node
        active_node = nodes[0] if nodes else None

    if not active_node:
        return {}

    node_id = active_node.get('node_id') or active_node.get('instance_id')

    # Get bandwidth capacity (returns dict with 'bandwidth_bps' key or None)
    capacity = state_manager.get_node_bandwidth(node_id)
    bandwidth_bps = capacity.get('bandwidth_bps', DEFAULT_BANDWIDTH_BPS) if capacity else DEFAULT_BANDWIDTH_BPS

    # Get active origins for this shard
    origins = state_manager.get_origins_for_shard(shard_id)
    active_origins = [o for o in origins if o.get('state') == 'IN_SERVICE']

    if not active_origins:
        logger.info(f"No active origins in shard {shard_id}")
        return {}

    # Calculate quotas
    usable_bps = int(bandwidth_bps * (100 - buffer_percent) / 100)
    quota_per_origin = usable_bps // len(active_origins)
    burst_bytes = quota_per_origin * 10  # 10-second burst allowance

    logger.info(
        f"Shard {shard_id}: {bandwidth_bps/1e9:.2f} Gbps total, "
        f"{usable_bps/1e9:.2f} Gbps usable, "
        f"{len(active_origins)} origins, "
        f"{quota_per_origin/1e6:.1f} Mbps each"
    )

    quotas = {}
    for origin in active_origins:
        origin_ip = origin.get('origin_ip')
        if origin_ip:
            quotas[origin_ip] = {
                'quota_bps': quota_per_origin,
                'burst_bytes': burst_bytes,
            }
            # Update state manager cache
            state_manager.update_bandwidth_quota(origin_ip, quotas[origin_ip])

    return quotas


def push_quotas_to_scrubber(node_id: str, host: str, quotas: Dict[str, dict],
                            provider: str = 'aws') -> bool:
    """
    Push calculated quotas to a scrubber's BPF maps.

    IMPORTANT: Preserves existing counters (bytes_exceeded, packets_dropped)
    when updating quota values. Only updates quota_bps, burst_bytes, and refills tokens.

    Args:
        node_id: Node identifier for logging
        host: Public IP of scrubber
        quotas: Dict of origin_ip → {quota_bps, burst_bytes}
        provider: Cloud provider (for SSH user resolution)

    Returns:
        True if all updates succeeded, False otherwise
    """
    import json
    import struct

    settings = get_settings()
    ssh_user = 'ubuntu' if provider == 'aws' else 'root'

    # Little-endian hex encoding
    def u64_to_hex(val):
        return ' '.join(f'{(val >> (i*8)) & 0xff:02x}' for i in range(8))

    # First, read existing entries to preserve counters
    read_cmd = "sudo bpftool map dump pinned /sys/fs/bpf/tc/globals/origin_bandwidth_map --json -p 2>/dev/null || echo '[]'"
    existing_entries = {}

    try:
        rc, stdout, stderr = ssh_exec(
            host=host, command=read_cmd, user=ssh_user,
            ssh_key_path=settings.ssh_key_path, timeout=30
        )
        if rc == 0 and stdout:
            map_data = json.loads(stdout)
            for entry in map_data:
                formatted = entry.get('formatted', {})
                if formatted:
                    key_int = formatted.get('key')
                    value = formatted.get('value', {})
                    if key_int is not None:
                        # Convert int to IP
                        ip_bytes = struct.pack('<I', key_int)
                        origin_ip = '.'.join(str(b) for b in ip_bytes)
                        existing_entries[origin_ip] = {
                            'bytes_exceeded': value.get('bytes_exceeded', 0),
                            'packets_dropped': value.get('packets_dropped', 0),
                            'last_refill_ns': value.get('last_refill_ns', 0),
                        }
    except Exception as e:
        logger.warning(f"Could not read existing bandwidth entries from {node_id}: {e}")

    success = True
    for origin_ip, quota in quotas.items():
        # Convert origin_ip to hex (network byte order)
        ip_parts = [int(p) for p in origin_ip.split('.')]
        ip_hex = ' '.join(f'{p:02x}' for p in ip_parts)

        # Get existing counters or use zeros for new entries
        existing = existing_entries.get(origin_ip, {})
        bytes_exceeded = existing.get('bytes_exceeded', 0)
        packets_dropped = existing.get('packets_dropped', 0)
        last_refill_ns = existing.get('last_refill_ns', 0)

        # Pack struct origin_bandwidth (64 bytes)
        quota_bps = quota['quota_bps']
        burst_bytes = quota['burst_bytes']
        tokens = burst_bytes  # Refill to full bucket on quota update

        value_hex = (
            f"{u64_to_hex(quota_bps)} "        # quota_bps (updated)
            f"{u64_to_hex(tokens)} "           # tokens (refilled)
            f"{u64_to_hex(burst_bytes)} "      # burst_bytes (updated)
            f"{u64_to_hex(last_refill_ns)} "   # last_refill_ns (preserved)
            f"{u64_to_hex(0)} "                # _reserved (unused)
            f"{u64_to_hex(bytes_exceeded)} "   # bytes_exceeded (PRESERVED)
            f"{u64_to_hex(packets_dropped)} "  # packets_dropped (PRESERVED)
            f"{u64_to_hex(0)}"                 # pad
        )

        cmd = (
            f"sudo bpftool map update pinned /sys/fs/bpf/tc/globals/origin_bandwidth_map "
            f"key hex {ip_hex} value hex {value_hex}"
        )

        try:
            rc, stdout, stderr = ssh_exec(
                host=host,
                command=cmd,
                user=ssh_user,
                ssh_key_path=settings.ssh_key_path,
                timeout=30
            )

            if rc != 0:
                logger.error(f"Failed to push quota for {origin_ip} to {node_id}: {stderr}")
                success = False
            else:
                logger.debug(f"Pushed quota {quota_bps/1e6:.1f} Mbps for {origin_ip} to {node_id}")

        except Exception as e:
            logger.error(f"SSH error pushing quota to {node_id}: {e}")
            success = False

    return success


def update_scrubber_capacity(node_id: str, host: str, origin_count: int,
                             enforce_mode: int = 0, provider: str = 'aws') -> bool:
    """
    Update scrubber_capacity_map with current origin count and enforce mode.

    Args:
        node_id: Node identifier
        host: Public IP of scrubber
        origin_count: Number of active origins
        enforce_mode: 0 = monitor, 1 = enforce
        provider: Cloud provider

    Returns:
        True on success
    """
    settings = get_settings()
    ssh_user = 'ubuntu' if provider == 'aws' else 'root'

    # Read current capacity values first (preserve bandwidth_bps, usable_bps)
    read_cmd = "cat /var/lib/tensorprox/bandwidth_capacity.json 2>/dev/null || echo '{}'"

    try:
        rc, stdout, stderr = ssh_exec(host=host, command=read_cmd, user=ssh_user,
                                      ssh_key_path=settings.ssh_key_path, timeout=10)

        import json
        capacity = json.loads(stdout or '{}')
        bandwidth_bps = capacity.get('bandwidth_bps', 1_000_000_000)
        usable_bps = capacity.get('usable_bps', 800_000_000)
        buffer_percent = capacity.get('buffer_percent', 20)

    except Exception as e:
        logger.warning(f"Could not read capacity from {node_id}, using defaults: {e}")
        bandwidth_bps = 1_000_000_000
        usable_bps = 800_000_000
        buffer_percent = 20

    # Pack struct scrubber_capacity (32 bytes)
    def u64_to_hex(val):
        return ' '.join(f'{(val >> (i*8)) & 0xff:02x}' for i in range(8))

    def u32_to_hex(val):
        return ' '.join(f'{(val >> (i*8)) & 0xff:02x}' for i in range(4))

    value_hex = (
        f"{u64_to_hex(bandwidth_bps)} "
        f"{u64_to_hex(usable_bps)} "
        f"{u32_to_hex(origin_count)} "
        f"{u32_to_hex(buffer_percent)} "
        f"{enforce_mode:02x} "
        f"00 00 00 00 00 00 00"  # pad[7]
    )

    cmd = (
        f"sudo bpftool map update pinned /sys/fs/bpf/tc/globals/scrubber_capacity_map "
        f"key hex 00 00 00 00 value hex {value_hex}"
    )

    try:
        rc, stdout, stderr = ssh_exec(host=host, command=cmd, user=ssh_user,
                                      ssh_key_path=settings.ssh_key_path, timeout=30)

        if rc != 0:
            logger.error(f"Failed to update scrubber_capacity on {node_id}: {stderr}")
            return False

        logger.info(f"Updated scrubber_capacity on {node_id}: {origin_count} origins, enforce={enforce_mode}")
        return True

    except Exception as e:
        logger.error(f"SSH error updating scrubber_capacity on {node_id}: {e}")
        return False


def recalculate_quotas(shard_id: str) -> bool:
    """
    Recalculate and push quotas for all origins in a shard.

    Called when:
    - Origin added/removed
    - Origin enabled/disabled
    - Manual trigger via API

    Args:
        shard_id: Shard to recalculate

    Returns:
        True if all operations succeeded
    """
    logger.info(f"Recalculating bandwidth quotas for shard {shard_id}")

    # Calculate new quotas
    quotas = calculate_quotas_for_shard(shard_id)

    if not quotas:
        logger.info(f"No quotas to push for shard {shard_id}")
        return True

    # Get all scrubber nodes for this shard (returns List[dict])
    nodes = state_manager.get_nodes_for_shard(shard_id)

    success = True
    for node_data in nodes:
        node_id = node_data.get('node_id') or node_data.get('instance_id')
        host = node_data.get('public_ip') or node_data.get('current_public_ip')
        provider = node_data.get('provider', 'aws')
        role = node_data.get('role', '')

        # Skip failed nodes (avoid SSH timeout to dead nodes during failover)
        if role == 'failed':
            logger.debug(f"Skipping failed node {node_id} for quota push")
            continue

        if not host:
            logger.warning(f"No public IP for node {node_id}, skipping")
            continue

        # Push quotas
        if not push_quotas_to_scrubber(node_id, host, quotas, provider):
            success = False

        # Update scrubber capacity map
        if not update_scrubber_capacity(node_id, host, len(quotas),
                                        enforce_mode=0, provider=provider):
            success = False

    return success
