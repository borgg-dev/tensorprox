"""
BPF Map Cleaner - Robust origin cleanup via direct bpftool commands.

Provides idempotent BPF map cleanup for origin deletion and orphan detection.
No dependency on scrubber-side scripts - all cleanup via SSH/bpftool from miner_control_plane.
"""
import json
import socket
import struct
import logging
from typing import Dict, List, Optional
from shared.utils.ssh import ssh_exec

logger = logging.getLogger(__name__)


def ip_to_hex(ip_str: str) -> str:
    """Convert IP address to hex string for bpftool.

    Args:
        ip_str: IP address as dotted decimal (e.g., "10.0.1.10")

    Returns:
        Hex string with spaces (e.g., "0a 00 01 0a")
    """
    ip_bytes = socket.inet_aton(ip_str)
    return ' '.join([f'{b:02x}' for b in ip_bytes])


def int_to_hex(value: int, bytes_len: int = 4) -> str:
    """Convert integer to hex string for bpftool.

    Args:
        value: Integer value
        bytes_len: Number of bytes (4 for 32-bit, 8 for 64-bit, etc.)

    Returns:
        Hex string with spaces (e.g., "05 00 00 00")
    """
    packed = struct.pack('<I', value) if bytes_len == 4 else struct.pack('<Q', value)
    return ' '.join([f'{b:02x}' for b in packed])


def bpf_delete_key(
    host: str,
    map_path: str,
    key_hex: str,
    ssh_key_path: str,
    nodes_db: dict,
    timeout: int = 30
) -> tuple[int, str]:
    """Delete a key from a BPF map.

    Args:
        host: Node IP address
        map_path: Full path to BPF map (e.g., "/sys/fs/bpf/tc/globals/eip_map")
        key_hex: Key in hex format with spaces (e.g., "0a 00 01 0a")
        ssh_key_path: Path to SSH private key
        nodes_db: Node database for SSH user resolution
        timeout: SSH timeout in seconds

    Returns:
        (return_code, stderr_message)
    """
    cmd = f"sudo bpftool map delete pinned {map_path} key hex {key_hex}"
    rc, stdout, stderr = ssh_exec(
        host,
        cmd,
        ssh_key_path,
        nodes_db=nodes_db,
        timeout=timeout
    )
    return rc, stderr


def bpf_lookup_key(
    host: str,
    map_path: str,
    key_hex: str,
    ssh_key_path: str,
    nodes_db: dict,
    timeout: int = 30
) -> tuple[int, str]:
    """Look up a key in a BPF map (verify if it exists).

    Args:
        host: Node IP address
        map_path: Full path to BPF map
        key_hex: Key in hex format with spaces
        ssh_key_path: Path to SSH private key
        nodes_db: Node database for SSH user resolution
        timeout: SSH timeout in seconds

    Returns:
        (return_code, stderr_message)
        rc=0: Key found
        rc!=0: Key not found (which is what we want after deletion)
    """
    cmd = f"sudo bpftool map lookup pinned {map_path} key hex {key_hex} 2>&1"
    rc, stdout, stderr = ssh_exec(
        host,
        cmd,
        ssh_key_path,
        nodes_db=nodes_db,
        timeout=timeout
    )
    return rc, stdout + stderr


def get_wg_interface_index(
    host: str,
    wg_interface: str,
    ssh_key_path: str,
    nodes_db: dict,
    timeout: int = 30
) -> Optional[int]:
    """Get the interface index (ifindex) for a WireGuard interface.

    Args:
        host: Node IP address
        wg_interface: WireGuard interface name (e.g., "wgO1")
        ssh_key_path: Path to SSH private key
        nodes_db: Node database
        timeout: SSH timeout in seconds

    Returns:
        Interface index as integer, or None if not found
    """
    cmd = f"cat /sys/class/net/{wg_interface}/ifindex 2>/dev/null"
    rc, stdout, stderr = ssh_exec(
        host,
        cmd,
        ssh_key_path,
        nodes_db=nodes_db,
        timeout=timeout
    )

    if rc == 0 and stdout.strip():
        try:
            return int(stdout.strip())
        except ValueError:
            logger.warning(f"Could not parse ifindex on {host} for {wg_interface}: {stdout}")
            return None
    else:
        logger.debug(f"Interface {wg_interface} not found on {host}")
        return None


def clean_origin_bpf_maps(
    origin_id: str,
    origin: dict,
    nodes_db: dict,
    ssh_key_path: str,
    settings,
    verify: bool = True
) -> Dict:
    """
    Clean all BPF maps related to an origin across all scrubbers.

    Cleans:
    - eip_map[private_ip] - Main origin IP mapping
    - eip_map[private_ip_standby] - Standby edge private IP (if exists)
    - eip_security_stats_map[private_ip] - Per-EIP security statistics (blacklist tracking)
    - eip_security_stats_map[private_ip_standby] - Standby EIP security stats (if exists)
    - wg2priv_map[wg_ifindex] - WireGuard interface → private IP mapping
    - wg_ifindex_to_origin_map[wg_ifindex] - WireGuard interface → origin IP (billing attribution)
    - origin_to_priv_map[origin_ip] - Reverse NAT mapping
    - egress_billing_map[origin_ip] - AWS billing tracking (to_origin_bytes, to_client_bytes)
    - origin_bandwidth_map[origin_ip] - QoS bandwidth tracking (quota, bytes_exceeded, etc.)
    - origin_challenge_map[origin_ip] - QoS pressure signaling to XDP

    Args:
        origin_id: Origin identifier (for logging)
        origin: Origin dict with keys: origin_ip, private_ip, private_ip_standby, wg_interface
        nodes_db: Dictionary of nodes {node_name: {public_ip, ...}}
        ssh_key_path: SSH key path for remote access
        settings: Settings object
        verify: Whether to verify deletions via bpftool lookup

    Returns:
        {
            'success': bool,  # True if ALL maps cleaned on ALL nodes
            'nodes': {
                'node-name': {
                    'eip_map': {'success': bool, 'verified': bool, 'error': str or None},
                    'eip_security_stats_map': {'success': bool, 'verified': bool, 'error': str or None},
                    'wg2priv_map': {'success': bool, 'verified': bool, 'error': str or None},
                    'wg_ifindex_to_origin_map': {'success': bool, 'verified': bool, 'error': str or None},
                    'origin_to_priv_map': {'success': bool, 'verified': bool, 'error': str or None},
                    'egress_billing_map': {'success': bool, 'verified': bool, 'error': str or None},
                },
                ...
            },
            'errors': [list of error messages]
        }
    """
    result = {
        'success': True,
        'nodes': {},
        'errors': []
    }

    if not origin:
        result['success'] = False
        result['errors'].append("Origin object is empty")
        return result

    origin_ip = origin.get('origin_ip')
    private_ip = origin.get('private_ip')
    private_ip_standby = origin.get('private_ip_standby')
    wg_interface = origin.get('wg_interface')

    if not origin_ip or not private_ip or not wg_interface:
        error_msg = f"Origin {origin_id} missing required fields: origin_ip={origin_ip}, private_ip={private_ip}, wg_interface={wg_interface}"
        logger.error(error_msg)
        result['success'] = False
        result['errors'].append(error_msg)
        return result

    # Process each scrubber node
    for node_name, node_data in nodes_db.items():
        node_ip = node_data.get('public_ip')
        if not node_ip:
            logger.warning(f"Node {node_name} has no public_ip")
            continue

        node_result = {
            'eip_map': {'success': False, 'verified': False, 'error': None},
            'eip_security_stats_map': {'success': False, 'verified': False, 'error': None},
            'wg2priv_map': {'success': False, 'verified': False, 'error': None},
            'wg_ifindex_to_origin_map': {'success': False, 'verified': False, 'error': None},
            'origin_to_priv_map': {'success': False, 'verified': False, 'error': None},
            'egress_billing_map': {'success': False, 'verified': False, 'error': None},
            'origin_bandwidth_map': {'success': False, 'verified': False, 'error': None},
            'origin_challenge_map': {'success': False, 'verified': False, 'error': None},
        }

        # --- Clean eip_map[private_ip] ---
        try:
            private_ip_hex = ip_to_hex(private_ip)
            rc, stderr = bpf_delete_key(
                node_ip,
                "/sys/fs/bpf/tc/globals/eip_map",
                private_ip_hex,
                ssh_key_path,
                nodes_db
            )

            if rc == 0:
                node_result['eip_map']['success'] = True

                # Verify deletion if requested
                if verify:
                    rc_verify, _ = bpf_lookup_key(
                        node_ip,
                        "/sys/fs/bpf/tc/globals/eip_map",
                        private_ip_hex,
                        ssh_key_path,
                        nodes_db
                    )
                    if rc_verify != 0:  # Should NOT find the key
                        node_result['eip_map']['verified'] = True
                        logger.debug(f"✓ Verified eip_map[{private_ip}] deleted on {node_name}")
                    else:
                        node_result['eip_map']['verified'] = False
                        error_msg = f"eip_map[{private_ip}] still exists on {node_name} after deletion"
                        logger.warning(error_msg)
                        node_result['eip_map']['error'] = error_msg
                        result['success'] = False
                else:
                    node_result['eip_map']['verified'] = True
            else:
                error_msg = f"Failed to delete eip_map[{private_ip}] on {node_name}: {stderr}"
                logger.warning(error_msg)
                node_result['eip_map']['error'] = error_msg
                result['success'] = False

        except Exception as e:
            error_msg = f"Exception cleaning eip_map[{private_ip}] on {node_name}: {e}"
            logger.error(error_msg)
            node_result['eip_map']['error'] = error_msg
            result['errors'].append(error_msg)
            result['success'] = False

        # --- Clean eip_map[private_ip_standby] if exists ---
        if private_ip_standby:
            try:
                standby_hex = ip_to_hex(private_ip_standby)
                rc, stderr = bpf_delete_key(
                    node_ip,
                    "/sys/fs/bpf/tc/globals/eip_map",
                    standby_hex,
                    ssh_key_path,
                    nodes_db
                )

                if rc == 0:
                    if verify:
                        rc_verify, _ = bpf_lookup_key(
                            node_ip,
                            "/sys/fs/bpf/tc/globals/eip_map",
                            standby_hex,
                            ssh_key_path,
                            nodes_db
                        )
                        if rc_verify != 0:
                            logger.debug(f"✓ Verified eip_map[{private_ip_standby}] deleted on {node_name}")
                        else:
                            error_msg = f"eip_map[{private_ip_standby}] still exists on {node_name} after deletion"
                            logger.warning(error_msg)
                            result['success'] = False
                    else:
                        logger.debug(f"Deleted eip_map[{private_ip_standby}] on {node_name}")
                else:
                    # Delete returned non-zero - verify if key actually exists
                    rc_verify, _ = bpf_lookup_key(
                        node_ip,
                        "/sys/fs/bpf/tc/globals/eip_map",
                        standby_hex,
                        ssh_key_path,
                        nodes_db
                    )
                    if rc_verify != 0:  # Key doesn't exist - OK
                        logger.debug(f"eip_map[{private_ip_standby}] not found on {node_name} (OK)")
                    else:  # Key still exists - deletion failed!
                        error_msg = f"Failed to delete eip_map[{private_ip_standby}] on {node_name}: key still exists"
                        logger.warning(error_msg)
                        result['success'] = False

            except Exception as e:
                error_msg = f"Exception cleaning eip_map[{private_ip_standby}] on {node_name}: {e}"
                logger.error(error_msg)
                result['errors'].append(error_msg)
                result['success'] = False

        # --- Clean eip_security_stats_map[private_ip] ---
        try:
            private_ip_hex = ip_to_hex(private_ip)
            rc, stderr = bpf_delete_key(
                node_ip,
                "/sys/fs/bpf/xdp/globals/eip_security_stats_map",
                private_ip_hex,
                ssh_key_path,
                nodes_db
            )

            if rc == 0:
                node_result['eip_security_stats_map']['success'] = True

                # Verify deletion if requested
                if verify:
                    rc_verify, _ = bpf_lookup_key(
                        node_ip,
                        "/sys/fs/bpf/xdp/globals/eip_security_stats_map",
                        private_ip_hex,
                        ssh_key_path,
                        nodes_db
                    )
                    if rc_verify != 0:  # Should NOT find the key
                        node_result['eip_security_stats_map']['verified'] = True
                        logger.debug(f"✓ Verified eip_security_stats_map[{private_ip}] deleted on {node_name}")
                    else:
                        node_result['eip_security_stats_map']['verified'] = False
                        error_msg = f"eip_security_stats_map[{private_ip}] still exists on {node_name} after deletion"
                        logger.warning(error_msg)
                        node_result['eip_security_stats_map']['error'] = error_msg
                        result['success'] = False
                else:
                    node_result['eip_security_stats_map']['verified'] = True
            else:
                # Delete returned non-zero - verify if key actually exists
                rc_verify, _ = bpf_lookup_key(
                    node_ip,
                    "/sys/fs/bpf/xdp/globals/eip_security_stats_map",
                    private_ip_hex,
                    ssh_key_path,
                    nodes_db
                )
                if rc_verify != 0:  # Key doesn't exist - OK
                    logger.debug(f"eip_security_stats_map[{private_ip}] not found on {node_name} (OK)")
                    node_result['eip_security_stats_map']['success'] = True
                    node_result['eip_security_stats_map']['verified'] = True
                else:  # Key still exists - deletion failed!
                    error_msg = f"Failed to delete eip_security_stats_map[{private_ip}] on {node_name}: key still exists after delete"
                    logger.warning(error_msg)
                    node_result['eip_security_stats_map']['error'] = error_msg
                    result['success'] = False

        except Exception as e:
            error_msg = f"Exception cleaning eip_security_stats_map[{private_ip}] on {node_name}: {e}"
            logger.error(error_msg)
            node_result['eip_security_stats_map']['error'] = error_msg
            result['errors'].append(error_msg)
            result['success'] = False

        # --- Clean eip_security_stats_map[private_ip_standby] if exists ---
        if private_ip_standby:
            try:
                standby_hex = ip_to_hex(private_ip_standby)
                rc, stderr = bpf_delete_key(
                    node_ip,
                    "/sys/fs/bpf/xdp/globals/eip_security_stats_map",
                    standby_hex,
                    ssh_key_path,
                    nodes_db
                )

                if rc == 0:
                    if verify:
                        rc_verify, _ = bpf_lookup_key(
                            node_ip,
                            "/sys/fs/bpf/xdp/globals/eip_security_stats_map",
                            standby_hex,
                            ssh_key_path,
                            nodes_db
                        )
                        if rc_verify != 0:
                            logger.debug(f"✓ Verified eip_security_stats_map[{private_ip_standby}] deleted on {node_name}")
                        else:
                            error_msg = f"eip_security_stats_map[{private_ip_standby}] still exists on {node_name} after deletion"
                            logger.warning(error_msg)
                            result['success'] = False
                    else:
                        logger.debug(f"Deleted eip_security_stats_map[{private_ip_standby}] on {node_name}")
                else:
                    # Delete returned non-zero - verify if key actually exists
                    rc_verify, _ = bpf_lookup_key(
                        node_ip,
                        "/sys/fs/bpf/xdp/globals/eip_security_stats_map",
                        standby_hex,
                        ssh_key_path,
                        nodes_db
                    )
                    if rc_verify != 0:  # Key doesn't exist - OK
                        logger.debug(f"eip_security_stats_map[{private_ip_standby}] not found on {node_name} (OK)")
                    else:  # Key still exists - deletion failed!
                        error_msg = f"Failed to delete eip_security_stats_map[{private_ip_standby}] on {node_name}: key still exists"
                        logger.warning(error_msg)
                        result['success'] = False

            except Exception as e:
                error_msg = f"Exception cleaning eip_security_stats_map[{private_ip_standby}] on {node_name}: {e}"
                logger.error(error_msg)
                result['errors'].append(error_msg)
                result['success'] = False

        # --- Clean wg2priv_map[wg_ifindex] ---
        try:
            wg_ifindex = get_wg_interface_index(
                node_ip,
                wg_interface,
                ssh_key_path,
                nodes_db
            )

            if wg_ifindex is not None:
                ifindex_hex = int_to_hex(wg_ifindex)
                rc, stderr = bpf_delete_key(
                    node_ip,
                    "/sys/fs/bpf/tc/globals/wg2priv_map",
                    ifindex_hex,
                    ssh_key_path,
                    nodes_db
                )

                if rc == 0:
                    node_result['wg2priv_map']['success'] = True

                    if verify:
                        rc_verify, _ = bpf_lookup_key(
                            node_ip,
                            "/sys/fs/bpf/tc/globals/wg2priv_map",
                            ifindex_hex,
                            ssh_key_path,
                            nodes_db
                        )
                        if rc_verify != 0:
                            node_result['wg2priv_map']['verified'] = True
                            logger.debug(f"✓ Verified wg2priv_map[{wg_ifindex}] deleted on {node_name}")
                        else:
                            node_result['wg2priv_map']['verified'] = False
                            error_msg = f"wg2priv_map[{wg_ifindex}] still exists on {node_name} after deletion"
                            logger.warning(error_msg)
                            node_result['wg2priv_map']['error'] = error_msg
                            result['success'] = False
                    else:
                        node_result['wg2priv_map']['verified'] = True
                else:
                    error_msg = f"Failed to delete wg2priv_map[{wg_ifindex}] on {node_name}: {stderr}"
                    logger.warning(error_msg)
                    node_result['wg2priv_map']['error'] = error_msg
                    result['success'] = False
            else:
                logger.debug(f"Interface {wg_interface} not found on {node_name} (already removed)")
                node_result['wg2priv_map']['success'] = True
                node_result['wg2priv_map']['verified'] = True

        except Exception as e:
            error_msg = f"Exception cleaning wg2priv_map for {wg_interface} on {node_name}: {e}"
            logger.error(error_msg)
            node_result['wg2priv_map']['error'] = error_msg
            result['errors'].append(error_msg)
            result['success'] = False

        # --- Clean wg_ifindex_to_origin_map[wg_ifindex] ---
        try:
            wg_ifindex = get_wg_interface_index(
                node_ip,
                wg_interface,
                ssh_key_path,
                nodes_db
            )

            if wg_ifindex is not None:
                ifindex_hex = int_to_hex(wg_ifindex)
                rc, stderr = bpf_delete_key(
                    node_ip,
                    "/sys/fs/bpf/tc/globals/wg_ifindex_to_origin_map",
                    ifindex_hex,
                    ssh_key_path,
                    nodes_db
                )

                if rc == 0:
                    node_result['wg_ifindex_to_origin_map']['success'] = True
                    node_result['wg_ifindex_to_origin_map']['verified'] = True
                    logger.debug(f"✓ Deleted wg_ifindex_to_origin_map[{wg_ifindex}] on {node_name}")
                else:
                    # Map may not exist on older deployments
                    logger.debug(f"wg_ifindex_to_origin_map[{wg_ifindex}] not found on {node_name} (may not exist)")
                    node_result['wg_ifindex_to_origin_map']['success'] = True
                    node_result['wg_ifindex_to_origin_map']['verified'] = True
            else:
                logger.debug(f"Interface {wg_interface} not found on {node_name} (already removed)")
                node_result['wg_ifindex_to_origin_map']['success'] = True
                node_result['wg_ifindex_to_origin_map']['verified'] = True

        except Exception as e:
            error_msg = f"Exception cleaning wg_ifindex_to_origin_map for {wg_interface} on {node_name}: {e}"
            logger.error(error_msg)
            node_result['wg_ifindex_to_origin_map']['error'] = error_msg
            result['errors'].append(error_msg)
            result['success'] = False

        # --- Clean origin_to_priv_map[origin_ip] ---
        try:
            origin_ip_hex = ip_to_hex(origin_ip)
            rc, stderr = bpf_delete_key(
                node_ip,
                "/sys/fs/bpf/tc/globals/origin_to_priv_map",
                origin_ip_hex,
                ssh_key_path,
                nodes_db
            )

            if rc == 0:
                node_result['origin_to_priv_map']['success'] = True

                if verify:
                    rc_verify, _ = bpf_lookup_key(
                        node_ip,
                        "/sys/fs/bpf/tc/globals/origin_to_priv_map",
                        origin_ip_hex,
                        ssh_key_path,
                        nodes_db
                    )
                    if rc_verify != 0:
                        node_result['origin_to_priv_map']['verified'] = True
                        logger.debug(f"✓ Verified origin_to_priv_map[{origin_ip}] deleted on {node_name}")
                    else:
                        node_result['origin_to_priv_map']['verified'] = False
                        error_msg = f"origin_to_priv_map[{origin_ip}] still exists on {node_name} after deletion"
                        logger.warning(error_msg)
                        node_result['origin_to_priv_map']['error'] = error_msg
                        result['success'] = False
                else:
                    node_result['origin_to_priv_map']['verified'] = True
            else:
                # Delete returned non-zero - verify if key actually exists
                rc_verify, _ = bpf_lookup_key(
                    node_ip,
                    "/sys/fs/bpf/tc/globals/origin_to_priv_map",
                    origin_ip_hex,
                    ssh_key_path,
                    nodes_db
                )
                if rc_verify != 0:  # Key doesn't exist - OK
                    logger.debug(f"origin_to_priv_map[{origin_ip}] not found on {node_name} (OK)")
                    node_result['origin_to_priv_map']['success'] = True
                    node_result['origin_to_priv_map']['verified'] = True
                else:  # Key still exists - deletion failed!
                    error_msg = f"Failed to delete origin_to_priv_map[{origin_ip}] on {node_name}: key still exists"
                    logger.warning(error_msg)
                    node_result['origin_to_priv_map']['error'] = error_msg
                    result['success'] = False

        except Exception as e:
            error_msg = f"Exception cleaning origin_to_priv_map[{origin_ip}] on {node_name}: {e}"
            logger.error(error_msg)
            node_result['origin_to_priv_map']['error'] = error_msg
            result['errors'].append(error_msg)
            result['success'] = False

        # --- Clean egress_billing_map[origin_ip] ---
        try:
            origin_ip_hex = ip_to_hex(origin_ip)
            rc, stderr = bpf_delete_key(
                node_ip,
                "/sys/fs/bpf/tc/globals/egress_billing_map",
                origin_ip_hex,
                ssh_key_path,
                nodes_db
            )

            if rc == 0:
                node_result['egress_billing_map']['success'] = True
                node_result['egress_billing_map']['verified'] = True
                logger.debug(f"✓ Deleted egress_billing_map[{origin_ip}] on {node_name}")
            else:
                # Delete returned non-zero - verify if key actually exists
                rc_verify, _ = bpf_lookup_key(
                    node_ip,
                    "/sys/fs/bpf/tc/globals/egress_billing_map",
                    origin_ip_hex,
                    ssh_key_path,
                    nodes_db
                )
                if rc_verify != 0:  # Key doesn't exist - OK
                    logger.debug(f"egress_billing_map[{origin_ip}] not found on {node_name} (OK)")
                    node_result['egress_billing_map']['success'] = True
                    node_result['egress_billing_map']['verified'] = True
                else:  # Key still exists - deletion failed!
                    error_msg = f"Failed to delete egress_billing_map[{origin_ip}] on {node_name}: key still exists"
                    logger.warning(error_msg)
                    node_result['egress_billing_map']['error'] = error_msg
                    result['success'] = False

        except Exception as e:
            error_msg = f"Exception cleaning egress_billing_map[{origin_ip}] on {node_name}: {e}"
            logger.error(error_msg)
            node_result['egress_billing_map']['error'] = error_msg
            result['errors'].append(error_msg)
            result['success'] = False

        # --- Clean origin_bandwidth_map[origin_ip] (QoS bandwidth tracking) ---
        try:
            rc, stderr = bpf_delete_key(
                node_ip,
                "/sys/fs/bpf/tc/globals/origin_bandwidth_map",
                origin_ip_hex,
                ssh_key_path,
                nodes_db
            )

            if rc == 0:
                node_result['origin_bandwidth_map']['success'] = True
                node_result['origin_bandwidth_map']['verified'] = True
                logger.debug(f"✓ Deleted origin_bandwidth_map[{origin_ip}] on {node_name}")
            else:
                # Delete returned non-zero - verify if key actually exists
                rc_verify, _ = bpf_lookup_key(
                    node_ip,
                    "/sys/fs/bpf/tc/globals/origin_bandwidth_map",
                    origin_ip_hex,
                    ssh_key_path,
                    nodes_db
                )
                if rc_verify != 0:  # Key doesn't exist - OK
                    logger.debug(f"origin_bandwidth_map[{origin_ip}] not found on {node_name} (OK)")
                    node_result['origin_bandwidth_map']['success'] = True
                    node_result['origin_bandwidth_map']['verified'] = True
                else:  # Key still exists - deletion failed!
                    error_msg = f"Failed to delete origin_bandwidth_map[{origin_ip}] on {node_name}: key still exists"
                    logger.warning(error_msg)
                    node_result['origin_bandwidth_map']['error'] = error_msg
                    result['success'] = False

        except Exception as e:
            error_msg = f"Exception cleaning origin_bandwidth_map[{origin_ip}] on {node_name}: {e}"
            logger.error(error_msg)
            node_result['origin_bandwidth_map']['error'] = error_msg
            result['errors'].append(error_msg)
            result['success'] = False

        # --- Clean origin_challenge_map[origin_ip] (QoS pressure signaling) ---
        try:
            rc, stderr = bpf_delete_key(
                node_ip,
                "/sys/fs/bpf/tc/globals/origin_challenge_map",
                origin_ip_hex,
                ssh_key_path,
                nodes_db
            )

            if rc == 0:
                node_result['origin_challenge_map']['success'] = True
                node_result['origin_challenge_map']['verified'] = True
                logger.debug(f"✓ Deleted origin_challenge_map[{origin_ip}] on {node_name}")
            else:
                # Delete returned non-zero - verify if key actually exists
                rc_verify, _ = bpf_lookup_key(
                    node_ip,
                    "/sys/fs/bpf/tc/globals/origin_challenge_map",
                    origin_ip_hex,
                    ssh_key_path,
                    nodes_db
                )
                if rc_verify != 0:  # Key doesn't exist - OK
                    logger.debug(f"origin_challenge_map[{origin_ip}] not found on {node_name} (OK)")
                    node_result['origin_challenge_map']['success'] = True
                    node_result['origin_challenge_map']['verified'] = True
                else:  # Key still exists - deletion failed!
                    error_msg = f"Failed to delete origin_challenge_map[{origin_ip}] on {node_name}: key still exists"
                    logger.warning(error_msg)
                    node_result['origin_challenge_map']['error'] = error_msg
                    result['success'] = False

        except Exception as e:
            error_msg = f"Exception cleaning origin_challenge_map[{origin_ip}] on {node_name}: {e}"
            logger.error(error_msg)
            node_result['origin_challenge_map']['error'] = error_msg
            result['errors'].append(error_msg)
            result['success'] = False

        # --- Clean per-origin reputation maps ---
        # These use compound keys {src_ip, dst_eip} and need to be iterated
        eip = origin.get('eip')
        if eip:
            eip_hex = ip_to_hex(eip)

            # Maps to clean: origin_whitelist, origin_blacklist, origin_override, temp_blacklist
            per_origin_maps = [
                '/sys/fs/bpf/xdp/globals/origin_whitelist_map',
                '/sys/fs/bpf/xdp/globals/origin_blacklist_map',
                '/sys/fs/bpf/xdp/globals/origin_override_map',
                '/sys/fs/bpf/xdp/globals/temp_blacklist_map',
            ]

            for map_path in per_origin_maps:
                try:
                    # Dump all keys from map, filter by dst_eip matching our origin
                    dump_cmd = f"sudo bpftool -j map dump pinned {map_path} 2>/dev/null || echo '[]'"
                    rc, stdout, stderr = ssh_exec(
                        node_ip,
                        dump_cmd,
                        ssh_key_path,
                        nodes_db=nodes_db,
                        timeout=30
                    )

                    if rc == 0 and stdout.strip():
                        try:
                            entries = json.loads(stdout)
                            for entry in entries:
                                # Key is 8 bytes: first 4 = src_ip, last 4 = dst_eip
                                key_bytes = entry.get('key', [])
                                if len(key_bytes) >= 8:
                                    # Extract dst_eip (bytes 4-7)
                                    entry_eip_hex = ' '.join([f'{b:02x}' for b in key_bytes[4:8]])
                                    if entry_eip_hex == eip_hex:
                                        # This entry belongs to our origin - delete it
                                        full_key_hex = ' '.join([f'{b:02x}' for b in key_bytes])
                                        bpf_delete_key(
                                            node_ip,
                                            map_path,
                                            full_key_hex,
                                            ssh_key_path,
                                            nodes_db
                                        )
                                        logger.debug(f"Deleted entry from {map_path} for origin {origin_id}")
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse map dump from {map_path}")
                except Exception as e:
                    logger.warning(f"Failed to clean {map_path} for origin {origin_id}: {e}")

        result['nodes'][node_name] = node_result

    # Summary logging
    if result['success']:
        logger.info(f"✓ BPF map cleanup completed for origin {origin_id}")
    else:
        failed_items = []
        for node_name, node_result in result['nodes'].items():
            for map_name, map_result in node_result.items():
                if not map_result['success']:
                    failed_items.append(f"{node_name}/{map_name}")

        if failed_items:
            logger.warning(
                f"⚠ BPF map cleanup partially failed for origin {origin_id}: "
                f"{', '.join(failed_items)}"
            )

    return result
