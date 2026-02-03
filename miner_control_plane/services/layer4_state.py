"""
Shared helpers for updating vip_state_map across all scrubbers.

Used by the Layer4 API blueprint as well as background controllers so we do not
duplicate bpftool/DB logging logic in multiple places.
"""
import ipaddress
import struct
import time
import re
import logging
from typing import Dict, Tuple

from shared.database import get_db_connection
from shared.config import get_settings
from shared.utils.ssh import ssh_exec
from shared.utils.bpf_helpers import apply_bpf_map_all
from miner_control_plane.services.state_manager import state_manager

logger = logging.getLogger(__name__)
settings = get_settings()

VIP_STATE_MAP = "/sys/fs/bpf/xdp/globals/vip_state_map"


def _origin_hex(origin_ip: str) -> str:
    packed = ipaddress.IPv4Address(origin_ip).packed
    return ' '.join(f"{b:02x}" for b in packed)


def _state_to_hex(flags: int, challenge_level: int) -> str:
    state_value = struct.pack('<BBHI', flags & 0xFF, challenge_level & 0xFF, 0, int(time.time()))
    return ' '.join(f"{b:02x}" for b in state_value)


def _push_state_to_edges(origin_ip: str, state_hex: str) -> Tuple[int, list]:
    """Update vip_state_map on every registered scrubber."""
    if not state_manager.nodes_db:
        return 0, ['No scrubbers registered']

    key_hex = _origin_hex(origin_ip)
    results = apply_bpf_map_all(
        nodes=state_manager.nodes_db,
        map_path=VIP_STATE_MAP,
        key_hex=key_hex,
        value_hex=state_hex,
        ssh_key_path=settings.ssh_key_path,
        verify=True
    )
    success = sum(1 for res in results.values() if res.success)
    errors = [
        f"{edge_name}: {(res.stderr or res.verification_error or 'unknown error')}"
        for edge_name, res in results.items()
        if not res.success
    ]
    return success, errors


def _log_vip_state(origin_ip: str, flags: int, challenge_level: int, reason: str):
    db = get_db_connection()
    conn = db.conn
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO vip_state_history (origin_ip, flags, challenge_level, changed_at, reason)
            VALUES (%s, %s, %s, %s, %s)
        """, (origin_ip, flags, challenge_level, int(time.time()), reason))
        conn.commit()
    finally:
        cur.close()


def apply_vip_state(origin_ip: str, cookie_mode: int, under_attack: int,
                    escalated: int, challenge_level: int, reason: str) -> Dict:
    """
    Set the complete VIP state (flags + challenge level) on all scrubbers.
    """
    flags = (cookie_mode & 0x1) | ((under_attack & 0x1) << 1) | ((escalated & 0x1) << 2)
    state_hex = _state_to_hex(flags, challenge_level)

    success, errors = _push_state_to_edges(origin_ip, state_hex)
    if success:
        _log_vip_state(origin_ip, flags, challenge_level, reason)

    return {
        'vip': origin_ip,
        'flags': flags,
        'challenge_level': challenge_level,
        'updated_scrubbers': success,
        'errors': errors or None
    }


def _read_current_state(origin_ip: str) -> Tuple[int, int]:
    """
    Read the current vip_state entry from the first reachable scrubber.
    Returns (flags, challenge_level); defaults to (0,0) if not available.
    """
    if not state_manager.nodes_db:
        return 0, 0

    key_hex = _origin_hex(origin_ip)
    for node in state_manager.nodes_db.values():
        host_ip = node['public_ip']
        cmd = f"sudo bpftool map lookup pinned {VIP_STATE_MAP} key hex {key_hex}"
        rc, stdout, stderr = ssh_exec(
            host_ip,
            cmd,
            settings.ssh_key_path,
            nodes_db=state_manager.nodes_db
        )
        if rc == 0 and 'value:' in stdout:
            match = re.search(r'value:\s*([0-9a-f\s]+)', stdout)
            if match:
                hex_bytes = match.group(1).strip().split()
                if len(hex_bytes) >= 2:
                    flags = int(hex_bytes[0], 16)
                    challenge_level = int(hex_bytes[1], 16)
                    return flags, challenge_level
    return 0, 0


def set_cookie_flag(origin_ip: str, enable: bool, reason: str) -> Dict:
    """
    Toggle only the COOKIE_ON bit while preserving the rest of the VIP state.
    """
    flags, challenge_level = _read_current_state(origin_ip)
    if enable:
        flags |= 0x1
    else:
        flags &= ~0x1

    state_hex = _state_to_hex(flags, challenge_level)
    success, errors = _push_state_to_edges(origin_ip, state_hex)
    if success:
        _log_vip_state(origin_ip, flags, challenge_level, reason)

    return {
        'vip': origin_ip,
        'flags': flags,
        'challenge_level': challenge_level,
        'updated_scrubbers': success,
        'errors': errors or None
    }
