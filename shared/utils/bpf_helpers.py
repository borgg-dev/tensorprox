"""BPF map operation helpers - Centralized sudo + SSH handling

Provides high-level functions for common BPF map operations that handle:
- Provider-aware SSH user resolution (no hardcoded users)
- Proper timeout values (30s for map ops)
- Return code checking and error logging
- Hex key/value formatting

Usage:
    from shared.utils.bpf_helpers import update_bpf_map, delete_bpf_map
    from shared.config import get_settings

    settings = get_settings()

    # Update map on scrubber (user auto-detected from provider)
    success = update_bpf_map(
        host="203.0.113.10",  # RFC 5737 documentation IP - replace with actual scrubber IP
        map_path="/sys/fs/bpf/xdp/globals/whitelist_map",  # XDP maps are at xdp/globals/
        key_hex="cb 00 71 64",
        value_hex="01",
        ssh_key_path=settings.ssh_key_path,  # From tp.env
        provider="aws"  # Resolves to user='ubuntu' automatically
    )
"""
import ipaddress
import json
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from shared.utils.logging import get_logger
from shared.utils.ssh import get_ssh_user_for_provider, ssh_exec

logger = get_logger(__name__)


class BpfStatsReadError(Exception):
    """Exception raised when BPF stats cannot be read.

    This allows callers to distinguish between:
    - Stats read successfully with zero values (returns dict with zeros)
    - Stats read failed entirely (raises this exception)
    """

    def __init__(self, message: str, host: str, reason: str, details: Optional[str] = None):
        self.host = host
        self.reason = reason
        self.details = details
        super().__init__(message)


class BpfReadStatus(Enum):
    """Status of a BPF map read operation."""
    SUCCESS = "success"                    # Map read successfully
    SSH_FAILED = "ssh_failed"              # SSH command failed to execute
    MAP_NOT_FOUND = "map_not_found"        # Map does not exist
    PARSE_ERROR = "parse_error"            # JSON parsing failed
    EMPTY_RESULT = "empty_result"          # Command succeeded but no data returned


@dataclass
class BpfMapReadResult:
    """Structured result for BPF map read operations.

    Allows callers to distinguish between:
    - Successful read with data
    - Successful read with empty map (no entries)
    - Failed read (SSH error, map not found, parse error)
    """
    status: BpfReadStatus
    entries: List[Dict[str, Any]] = field(default_factory=list)
    error_message: str = ""
    exit_code: int = 0
    raw_output: str = ""

    @property
    def success(self) -> bool:
        """True if the read operation succeeded (even if map was empty)."""
        return self.status == BpfReadStatus.SUCCESS

    @property
    def available(self) -> bool:
        """True if stats are available and can be trusted."""
        return self.status == BpfReadStatus.SUCCESS


@dataclass
class XdpStatsResult:
    """Structured result for XDP stats read operations.

    Allows callers to distinguish between:
    - Stats read successfully, miner blocked N packets (available=True, stats has values)
    - Stats read successfully, miner blocked 0 packets (available=True, stats all zeros)
    - Stats read failed, result unknown (available=False, error_message explains why)
    """
    available: bool
    stats: Dict[str, int] = field(default_factory=dict)
    status: BpfReadStatus = BpfReadStatus.SUCCESS
    error_message: str = ""
    host: str = ""

    @property
    def total_drops(self) -> int:
        """Total number of dropped packets across all drop counters."""
        if not self.available:
            return 0
        return sum(v for k, v in self.stats.items() if k.startswith("xdp_drop_"))

    @property
    def total_passed(self) -> int:
        """Total number of passed packets."""
        if not self.available:
            return 0
        return self.stats.get("xdp_pass", 0)


# Counter names must match enum xdp_stats in common.h exactly
XDP_COUNTER_NAMES = [
    "xdp_pass",                    # 0: XDP_STAT_PASS
    "whitelist_bypass",            # 1: XDP_STAT_WHITELIST_BYPASS
    "xdp_drop_blacklist",          # 2: XDP_STAT_DROP_BLACKLIST
    "xdp_drop_invalid_ip",         # 3: XDP_STAT_DROP_INVALID_IP
    "xdp_drop_invalid_tcp",        # 4: XDP_STAT_DROP_INVALID_TCP
    "xdp_drop_ratelimit",          # 5: XDP_STAT_DROP_RATELIMIT
    "xdp_drop_temp_blacklist",     # 6: XDP_STAT_DROP_TEMP_BLACKLIST
    "xdp_syncookie_challenge",     # 7: XDP_STAT_SYNCOOKIE_CHALLENGE
    "xdp_syncookie_validated",     # 8: XDP_STAT_SYNCOOKIE_VALIDATED
    "xdp_syncookie_allow",         # 9: XDP_STAT_SYNCOOKIE_ALLOW
    "xdp_syncookie_reject",        # 10: XDP_STAT_SYNCOOKIE_REJECT
    "xdp_drop_quarantine",         # 11: XDP_STAT_DROP_QUARANTINE
    "xdp_bypass_allowed",          # 12: XDP_STAT_BYPASS_ALLOWED
    "xdp_drop_bogon",              # 13: XDP_STAT_DROP_BOGON
    "xdp_drop_tcp_xmas",           # 14: XDP_STAT_DROP_TCP_XMAS
    "xdp_drop_tcp_null",           # 15: XDP_STAT_DROP_TCP_NULL
    "xdp_drop_tcp_synfin",         # 16: XDP_STAT_DROP_TCP_SYNFIN
    "xdp_drop_tcp_synrst",         # 17: XDP_STAT_DROP_TCP_SYNRST
    "xdp_drop_syn_flood",          # 18: XDP_STAT_DROP_SYN_FLOOD
    "xdp_drop_udp_amp",            # 19: XDP_STAT_DROP_UDP_AMP
    "xdp_drop_icmp_flood",         # 20: XDP_STAT_DROP_ICMP_FLOOD
    "xdp_drop_frag",               # 21: XDP_STAT_DROP_FRAG
    "xdp_drop_tcp_fin",            # 22: XDP_STAT_DROP_TCP_FIN
    "xdp_drop_tcp_rst",            # 23: XDP_STAT_DROP_TCP_RST
    "xdp_drop_tcp_ack",            # 24: XDP_STAT_DROP_TCP_ACK
    "xdp_drop_udp_flood",          # 25: XDP_STAT_DROP_UDP_FLOOD
    "xdp_drop_malformed",          # 26: XDP_STAT_DROP_MALFORMED
    "xdp_drop_http_flood",         # 27: XDP_STAT_DROP_HTTP_FLOOD (L7 HTTP flood - PSH+ACK)
    "xdp_drop_slowloris",          # 28: XDP_STAT_DROP_SLOWLORIS (L7 Slowloris - SYN to HTTP)
    "xdp_drop_land",               # 29: XDP_STAT_DROP_LAND (Land attack - src == dst)
]


@dataclass
class BpfOpResult:
    """Structured result for every bpftool operation."""

    host: str
    map_path: str
    action: str
    key_hex: str
    value_hex: Optional[str]
    rc: int
    stderr: str = ""
    stdout: str = ""
    elapsed: float = 0.0
    verify_elapsed: float = 0.0
    verified: Optional[bool] = None
    verification_error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.rc == 0 and (self.verified is not False)

    def status_label(self) -> str:
        if self.rc != 0:
            return "FAILED"
        if self.verified is False:
            return "UNVERIFIED"
        return "SUCCESS"


def ip_to_hex(ip_str: str) -> str:
    """
    Convert IPv4 address to hex format for BPF map keys.

    Args:
        ip_str: IPv4 address (e.g., "192.168.1.1")

    Returns:
        Space-separated hex bytes (e.g., "c0 a8 01 01")

    Example:
        >>> ip_to_hex("192.168.1.1")
        'c0 a8 01 01'
    """
    ip_bytes = ipaddress.IPv4Address(ip_str).packed
    return ' '.join([f'{b:02x}' for b in ip_bytes])


def cidr_to_lpm_key(cidr_str: str) -> str:
    """
    Convert CIDR to LPM_TRIE key format (prefixlen + IP).

    Args:
        cidr_str: CIDR notation (e.g., "192.168.0.0/24") or IP (e.g., "192.168.1.1")

    Returns:
        Space-separated hex: prefixlen (4 bytes LE) + IP (4 bytes BE)

    Example:
        >>> cidr_to_lpm_key("192.168.1.1")
        '20 00 00 00 c0 a8 01 01'  # /32 + IP

        >>> cidr_to_lpm_key("192.168.0.0/24")
        '18 00 00 00 c0 a8 00 00'  # /24 + IP
    """
    if '/' in cidr_str:
        network = ipaddress.IPv4Network(cidr_str, strict=False)
        ip_str = str(network.network_address)
        prefixlen = network.prefixlen
    else:
        ip_str = cidr_str
        prefixlen = 32

    prefixlen_hex = struct.pack('<I', prefixlen).hex()
    ip_hex = ipaddress.IPv4Address(ip_str).packed.hex()
    key_hex = prefixlen_hex + ip_hex

    return ' '.join([key_hex[i:i+2] for i in range(0, len(key_hex), 2)])


def _resolve_user(provider: str, user: Optional[str]) -> str:
    return user or get_ssh_user_for_provider(provider)


def _run_ssh_command(host: str, cmd: str, ssh_key_path: str, user: str, timeout: int) -> Tuple[int, str, str, float]:
    start = time.time()
    rc, stdout, stderr = ssh_exec(host, cmd, ssh_key_path, user=user, timeout=timeout)
    elapsed = time.time() - start
    return rc, stdout or "", stderr or "", elapsed


def _log_op_result(result: BpfOpResult, prefix: str = "") -> None:
    prefix_str = f"{prefix} " if prefix else ""
    message = (
        f"{prefix_str}[{result.host}] {result.action.upper()} {result.map_path} "
        f"key={result.key_hex} status={result.status_label()} rc={result.rc} "
        f"elapsed={result.elapsed:.2f}s"
    )
    if result.verified is not None:
        message += f" verify={result.verified} verify_elapsed={result.verify_elapsed:.2f}s"
        if result.verification_error:
            message += f" verify_error='{result.verification_error}'"
    if result.stderr:
        message += f" stderr='{result.stderr.strip()[:200]}'"
    if result.success:
        logger.info(message)
    else:
        logger.warning(message)


def _verify_bpf_entry(host: str, map_path: str, key_hex: str, ssh_key_path: str, user: str, timeout: int) -> Tuple[bool, str, float]:
    lookup_cmd = f"sudo bpftool -j map lookup pinned {map_path} key hex {key_hex}"
    rc, stdout, stderr, elapsed = _run_ssh_command(host, lookup_cmd, ssh_key_path, user, timeout)
    return rc == 0, stderr.strip(), elapsed


def _update_bpf_map_verbose(
    host: str,
    map_path: str,
    key_hex: str,
    value_hex: str,
    ssh_key_path: str,
    provider: str,
    user: Optional[str],
    timeout: int,
    verify: bool = True
) -> BpfOpResult:
    resolved_user = _resolve_user(provider, user)
    cmd = f"sudo bpftool map update pinned {map_path} key hex {key_hex} value hex {value_hex}"
    rc, stdout, stderr, elapsed = _run_ssh_command(host, cmd, ssh_key_path, resolved_user, timeout)

    result = BpfOpResult(
        host=host,
        map_path=map_path,
        action="update",
        key_hex=key_hex,
        value_hex=value_hex,
        rc=rc,
        stdout=stdout,
        stderr=stderr,
        elapsed=elapsed
    )

    if rc == 0 and verify:
        verified, verify_error, verify_elapsed = _verify_bpf_entry(host, map_path, key_hex, ssh_key_path, resolved_user, timeout)
        result.verified = verified
        result.verify_elapsed = verify_elapsed
        result.verification_error = verify_error or None
    elif not verify:
        result.verified = None

    _log_op_result(result)
    return result


def _delete_bpf_map_verbose(
    host: str,
    map_path: str,
    key_hex: str,
    ssh_key_path: str,
    provider: str,
    user: Optional[str],
    timeout: int
) -> BpfOpResult:
    resolved_user = _resolve_user(provider, user)
    cmd = f"sudo bpftool map delete pinned {map_path} key hex {key_hex}"
    rc, stdout, stderr, elapsed = _run_ssh_command(host, cmd, ssh_key_path, resolved_user, timeout)

    # Treat "key not found" as success for delete
    if rc != 0 and ("key not found" in stderr.lower() or "no such file" in stderr.lower()):
        rc = 0
        stderr = ""

    result = BpfOpResult(
        host=host,
        map_path=map_path,
        action="delete",
        key_hex=key_hex,
        value_hex=None,
        rc=rc,
        stdout=stdout,
        stderr=stderr,
        elapsed=elapsed,
        verified=None
    )

    _log_op_result(result)
    return result


def update_bpf_map(
    host: str,
    map_path: str,
    key_hex: str,
    value_hex: str,
    ssh_key_path: str,
    provider: str = 'aws',
    user: Optional[str] = None,
    timeout: int = 30,
    verify: bool = True
) -> Tuple[bool, str]:
    """
    Update BPF map entry via bpftool over SSH with provider-aware user resolution.
    Returns (success, error_message). When verification is enabled, the helper logs
    a follow-up lookup result so operators can confirm the write persisted.
    """
    result = _update_bpf_map_verbose(
        host=host,
        map_path=map_path,
        key_hex=key_hex,
        value_hex=value_hex,
        ssh_key_path=ssh_key_path,
        provider=provider,
        user=user,
        timeout=timeout,
        verify=verify
    )
    return result.success, result.stderr if not result.success else ""


def delete_bpf_map(
    host: str,
    map_path: str,
    key_hex: str,
    ssh_key_path: str,
    provider: str = 'aws',
    user: Optional[str] = None,
    timeout: int = 30
) -> Tuple[bool, str]:
    """
    Delete BPF map entry via bpftool over SSH with provider-aware user resolution.
    """
    result = _delete_bpf_map_verbose(
        host=host,
        map_path=map_path,
        key_hex=key_hex,
        ssh_key_path=ssh_key_path,
        provider=provider,
        user=user,
        timeout=timeout
    )
    return result.success, result.stderr if not result.success else ""


def lookup_bpf_map(
    host: str,
    map_path: str,
    key_hex: str,
    ssh_key_path: str,
    provider: str = 'aws',
    user: Optional[str] = None,
    timeout: int = 30
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Lookup a BPF map entry and return parsed JSON if available.
    """
    resolved_user = _resolve_user(provider, user)
    cmd = f"sudo bpftool -j map lookup pinned {map_path} key hex {key_hex}"
    rc, stdout, stderr, elapsed = _run_ssh_command(host, cmd, ssh_key_path, resolved_user, timeout)
    result = BpfOpResult(
        host=host,
        map_path=map_path,
        action="lookup",
        key_hex=key_hex,
        value_hex=None,
        rc=rc,
        stdout=stdout,
        stderr=stderr,
        elapsed=elapsed
    )
    _log_op_result(result)
    if rc != 0:
        return False, None, stderr.strip()

    try:
        return True, json.loads(stdout or "{}"), ""
    except json.JSONDecodeError as exc:
        logger.warning(f"Failed to decode bpftool lookup output: {exc}")
        return False, None, f"json_decode_error: {exc}"


def apply_bpf_map_all(
    nodes: Dict[str, Dict[str, Any]],
    map_path: str,
    key_hex: str,
    ssh_key_path: str,
    value_hex: Optional[str] = None,
    action: str = "update",
    verify: bool = True,
    timeout: int = 30
) -> Dict[str, BpfOpResult]:
    """
    Fan out a BPF map update/delete across all nodes, returning per-node results.
    """
    results: Dict[str, BpfOpResult] = {}
    for node_name, node in nodes.items():
        host = node['public_ip']
        provider = node.get('provider', 'aws')

        if action == "update":
            if value_hex is None:
                raise ValueError("value_hex is required for update operations")
            result = _update_bpf_map_verbose(
                host=host,
                map_path=map_path,
                key_hex=key_hex,
                value_hex=value_hex,
                ssh_key_path=ssh_key_path,
                provider=provider,
                user=node.get('ssh_user'),
                timeout=timeout,
                verify=verify
            )
        elif action == "delete":
            result = _delete_bpf_map_verbose(
                host=host,
                map_path=map_path,
                key_hex=key_hex,
                ssh_key_path=ssh_key_path,
                provider=provider,
                user=node.get('ssh_user'),
                timeout=timeout
            )
        else:
            raise ValueError(f"Unsupported action '{action}'")

        results[node_name] = result

    return results


# Default map paths (centralized configuration)
# NOTE: Map locations are determined by which BPF program defines them:
#   - XDP maps (xdp_wan.c): /sys/fs/bpf/xdp/globals/<map_name>
#   - TC maps (tc_ingress_wan.c): /sys/fs/bpf/tc/globals/<map_name>
MAP_PATHS = {
    # XDP maps (defined in xdp_wan.c)
    'whitelist': '/sys/fs/bpf/xdp/globals/whitelist_map',
    'blacklist': '/sys/fs/bpf/xdp/globals/blacklist_map',
    'temp_blacklist': '/sys/fs/bpf/xdp/globals/temp_blacklist_map',
    'machine_limits': '/sys/fs/bpf/xdp/globals/machine_limits_map',
    'challenge_level': '/sys/fs/bpf/xdp/globals/challenge_level_map',
    'origin_challenge': '/sys/fs/bpf/xdp/globals/origin_challenge_map',
    'quarantine': '/sys/fs/bpf/xdp/globals/quarantine_map',
    'bypass': '/sys/fs/bpf/xdp/globals/bypass_map',
    'ratelimit': '/sys/fs/bpf/xdp/globals/ratelimit_map',
    'vip_state': '/sys/fs/bpf/xdp/globals/vip_state_map',
    'source_ip_behavior': '/sys/fs/bpf/xdp/globals/source_ip_behavior_map',
    # Per-origin reputation maps (XDP) - use compound key {src_ip, dst_eip}
    'origin_whitelist': '/sys/fs/bpf/xdp/globals/origin_whitelist_map',
    'origin_blacklist': '/sys/fs/bpf/xdp/globals/origin_blacklist_map',
    'origin_override': '/sys/fs/bpf/xdp/globals/origin_override_map',
    # NOTE: temp_blacklist path unchanged, but key format changed to compound
    # TC maps (defined in tc_ingress_wan.c)
    'syncookie_mode': '/sys/fs/bpf/tc/globals/syncookie_mode_map',
    'eip': '/sys/fs/bpf/tc/globals/eip_map',
    'origin_stats': '/sys/fs/bpf/tc/globals/origin_stats_map',
    'syncookie_metrics': '/sys/fs/bpf/tc/globals/syncookie_metrics_map',
}


def get_map_path(map_name: str) -> str:
    """
    Get standard map path by name.

    Args:
        map_name: Map identifier (whitelist, blacklist, etc.)

    Returns:
        Full path to map

    Raises:
        KeyError: If map_name not recognized
    """
    return MAP_PATHS[map_name]


# ============================================================
# Subnet-compatible functions (for tensorprox_subnet miner)
# ============================================================

# Default BPF map pin path
BPF_PIN_PATH = "/sys/fs/bpf/tc/globals"


def bpf_read_map(
    host: str,
    map_name: str,
    ssh_key_path: str,
    user: str = "ubuntu",
    pin_path: str = BPF_PIN_PATH
) -> list:
    """
    Read all entries from a BPF map by name.

    Args:
        host: Remote host IP.
        map_name: Name of the BPF map.
        ssh_key_path: Path to SSH private key.
        user: SSH username.
        pin_path: BPF map pin path.

    Returns:
        List of map entries as dictionaries.

    Note:
        This function returns an empty list on failure for backward compatibility.
        Use bpf_read_map_validated() for explicit error handling.
    """
    command = f"sudo bpftool map dump name {map_name} -j 2>/dev/null || echo '[]'"

    exit_code, stdout, stderr = ssh_exec(host, command, ssh_key_path, user=user, timeout=30)

    if exit_code != 0:
        logger.warning(f"Failed to read BPF map {map_name}: {stderr}")
        return []

    try:
        entries = json.loads((stdout or "").strip())
        return entries if isinstance(entries, list) else []
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse BPF map output for {map_name}")
        return []


def bpf_read_map_validated(
    host: str,
    map_name: str,
    ssh_key_path: str,
    user: str = "ubuntu",
    pin_path: str = BPF_PIN_PATH
) -> BpfMapReadResult:
    """
    Read all entries from a BPF map by name with explicit validation.

    Unlike bpf_read_map(), this function returns a structured result that
    allows callers to distinguish between:
    - Map read successfully with entries
    - Map read successfully but is empty
    - SSH command failed
    - Map does not exist
    - JSON parsing failed

    Args:
        host: Remote host IP.
        map_name: Name of the BPF map.
        ssh_key_path: Path to SSH private key.
        user: SSH username.
        pin_path: BPF map pin path.

    Returns:
        BpfMapReadResult with status, entries, and error details.
    """
    # Use a command that doesn't mask errors - we want to see if map doesn't exist
    command = f"sudo bpftool map dump name {map_name} -j"

    exit_code, stdout, stderr = ssh_exec(host, command, ssh_key_path, user=user, timeout=30)
    raw_output = stdout or ""
    stderr_str = stderr or ""

    # Check for SSH/command execution failure
    if exit_code != 0:
        # Check for specific error conditions
        if "No such file or directory" in stderr_str or "can't get info" in stderr_str.lower():
            logger.warning(
                f"[{host}] BPF map '{map_name}' not found: {stderr_str.strip()}"
            )
            return BpfMapReadResult(
                status=BpfReadStatus.MAP_NOT_FOUND,
                error_message=f"Map '{map_name}' does not exist on {host}",
                exit_code=exit_code,
                raw_output=stderr_str
            )
        elif "error fetching map by name" in stderr_str.lower():
            logger.warning(
                f"[{host}] BPF map '{map_name}' not found (error fetching): {stderr_str.strip()}"
            )
            return BpfMapReadResult(
                status=BpfReadStatus.MAP_NOT_FOUND,
                error_message=f"Map '{map_name}' not found on {host}",
                exit_code=exit_code,
                raw_output=stderr_str
            )
        else:
            logger.warning(
                f"[{host}] SSH command failed for BPF map '{map_name}': "
                f"exit_code={exit_code}, stderr={stderr_str.strip()}"
            )
            return BpfMapReadResult(
                status=BpfReadStatus.SSH_FAILED,
                error_message=f"SSH command failed: {stderr_str.strip()}",
                exit_code=exit_code,
                raw_output=stderr_str
            )

    # Check for empty output
    if not raw_output.strip():
        logger.warning(
            f"[{host}] BPF map '{map_name}' returned empty output"
        )
        return BpfMapReadResult(
            status=BpfReadStatus.EMPTY_RESULT,
            error_message="Command succeeded but returned empty output",
            exit_code=exit_code,
            raw_output=raw_output
        )

    # Try to parse JSON
    try:
        entries = json.loads(raw_output.strip())
        if not isinstance(entries, list):
            logger.warning(
                f"[{host}] BPF map '{map_name}' returned non-list JSON: {type(entries)}"
            )
            return BpfMapReadResult(
                status=BpfReadStatus.PARSE_ERROR,
                error_message=f"Expected list, got {type(entries).__name__}",
                exit_code=exit_code,
                raw_output=raw_output
            )

        # Success - entries may be empty list (valid empty map)
        logger.debug(
            f"[{host}] BPF map '{map_name}' read successfully: {len(entries)} entries"
        )
        return BpfMapReadResult(
            status=BpfReadStatus.SUCCESS,
            entries=entries,
            exit_code=exit_code,
            raw_output=raw_output
        )

    except json.JSONDecodeError as e:
        logger.warning(
            f"[{host}] Failed to parse BPF map '{map_name}' output as JSON: {e}"
        )
        return BpfMapReadResult(
            status=BpfReadStatus.PARSE_ERROR,
            error_message=f"JSON decode error: {e}",
            exit_code=exit_code,
            raw_output=raw_output
        )


def bpf_update_map(
    host: str,
    map_name: str,
    key: Dict[str, Any],
    value: Dict[str, Any],
    ssh_key_path: str,
    user: str = "ubuntu",
    pin_path: str = BPF_PIN_PATH
) -> bool:
    """
    Update an entry in a BPF map by name.

    Args:
        host: Remote host IP.
        map_name: Name of the BPF map.
        key: Key dictionary (will be converted to hex bytes).
        value: Value dictionary (will be converted to hex bytes).
        ssh_key_path: Path to SSH private key.
        user: SSH username.
        pin_path: BPF map pin path.

    Returns:
        True if successful.
    """
    key_hex = _dict_to_bpf_hex(key)
    value_hex = _dict_to_bpf_hex(value)

    command = (
        f"sudo bpftool map update name {map_name} "
        f"key hex {key_hex} value hex {value_hex}"
    )

    exit_code, stdout, stderr = ssh_exec(host, command, ssh_key_path, user=user, timeout=30)

    if exit_code != 0:
        logger.error(f"Failed to update BPF map {map_name}: {stderr}")
        return False

    return True


def bpf_delete_map(
    host: str,
    map_name: str,
    key: Dict[str, Any],
    ssh_key_path: str,
    user: str = "ubuntu",
    pin_path: str = BPF_PIN_PATH
) -> bool:
    """
    Delete an entry from a BPF map by name.

    Args:
        host: Remote host IP.
        map_name: Name of the BPF map.
        key: Key dictionary.
        ssh_key_path: Path to SSH private key.
        user: SSH username.
        pin_path: BPF map pin path.

    Returns:
        True if successful.
    """
    key_hex = _dict_to_bpf_hex(key)

    command = f"sudo bpftool map delete name {map_name} key hex {key_hex}"

    exit_code, stdout, stderr = ssh_exec(host, command, ssh_key_path, user=user, timeout=30)

    if exit_code != 0:
        logger.warning(f"Failed to delete from BPF map {map_name}: {stderr}")
        return False

    return True


def _dict_to_bpf_hex(data: Dict[str, Any]) -> str:
    """
    Convert a dictionary to hex bytes for bpftool.

    Handles common key/value types:
    - ip: IPv4 address string -> 4 bytes
    - prefix_len: Integer -> 4 bytes (for LPM trie)
    - uint32/uint64: Integer -> 4/8 bytes

    Args:
        data: Dictionary with field values.

    Returns:
        Hex string for bpftool.
    """
    hex_bytes = []

    for key, value in data.items():
        if key in ("ip", "src_ip", "dst_ip", "private_ip", "origin_ip"):
            # IPv4 address
            parts = str(value).split(".")
            hex_bytes.extend([int(p) for p in parts])
        elif key == "prefix_len":
            # LPM prefix length (4 bytes, little endian)
            hex_bytes.extend(int(value).to_bytes(4, "little"))
        elif key in ("wg_ifindex", "flags"):
            # 4-byte integer
            hex_bytes.extend(int(value).to_bytes(4, "little"))
        elif isinstance(value, int):
            # Default to 4-byte integer
            hex_bytes.extend(int(value).to_bytes(4, "little"))
        elif isinstance(value, bytes):
            hex_bytes.extend(value)

    return " ".join(f"{b:02x}" for b in hex_bytes)


def _parse_xdp_stats_entries(raw_entries: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Parse raw BPF map entries into XDP stats dictionary.

    Internal helper that handles both single-map and multi-map output formats.

    Args:
        raw_entries: List of entries from bpftool map dump.

    Returns:
        Dictionary of counter names to values.
    """
    stats: Dict[str, int] = {}

    # Handle both single-map and multi-map formats:
    # Single map: [{"key": [...], "value": [...]}, ...]
    # Multi map:  [{"id": 70, "elements": [...]}, {"id": 73, "elements": [...]}]
    entries = []
    for item in raw_entries:
        if "elements" in item:
            # Multi-map format: extract elements from each map object
            entries.extend(item.get("elements", []))
        else:
            # Single-map format: item is already an entry
            entries.append(item)

    for entry in entries:
        try:
            formatted = entry.get("formatted", {})
            if formatted:
                idx = formatted.get("key", -1)
                values = formatted.get("values", [])
                if isinstance(idx, int) and 0 <= idx < len(XDP_COUNTER_NAMES):
                    total = sum(v.get("value", 0) for v in values)
                    # Aggregate across multiple maps
                    stats[XDP_COUNTER_NAMES[idx]] = stats.get(XDP_COUNTER_NAMES[idx], 0) + total
                continue

            key_bytes = entry.get("key", [])
            value_data = entry.get("values", entry.get("value", []))

            if key_bytes is not None and value_data:
                # Handle key - can be int directly or byte array
                if isinstance(key_bytes, int):
                    idx = key_bytes
                else:
                    idx = int.from_bytes(bytes(key_bytes), "little")

                if value_data and isinstance(value_data[0], dict):
                    total = 0
                    for cpu_entry in value_data:
                        cpu_val = cpu_entry.get("value", 0)
                        # Handle value - can be int directly or byte array
                        if isinstance(cpu_val, int):
                            total += cpu_val
                        elif cpu_val:
                            total += int.from_bytes(bytes(cpu_val), "little")
                elif value_data and isinstance(value_data[0], list):
                    total = sum(
                        int.from_bytes(bytes(cpu_val), "little")
                        for cpu_val in value_data
                    )
                else:
                    if isinstance(value_data, int):
                        total = value_data
                    else:
                        total = int.from_bytes(bytes(value_data), "little")

                if idx < len(XDP_COUNTER_NAMES):
                    # Aggregate across multiple maps
                    stats[XDP_COUNTER_NAMES[idx]] = stats.get(XDP_COUNTER_NAMES[idx], 0) + total

        except (ValueError, TypeError) as e:
            logger.debug(f"Failed to parse stats entry: {e}")

    return stats


def bpf_read_xdp_stats(
    host: str,
    ssh_key_path: str,
    user: str = "ubuntu",
    map_name: str = "xdp_wan_stats"
) -> Dict[str, int]:
    """
    Read XDP statistics from the stats map.

    Handles both single-map and multi-map output formats from bpftool.
    When multiple maps with the same name exist (e.g., per-interface audit maps),
    stats are aggregated across all maps.

    Args:
        host: Remote host IP.
        ssh_key_path: Path to SSH private key.
        user: SSH username.
        map_name: Name of the stats map.

    Returns:
        Dictionary of counter names to values.

    Note:
        This function returns an empty dict on failure for backward compatibility.
        Use bpf_read_xdp_stats_validated() to distinguish between:
        - Stats read successfully with zeros (available=True)
        - Stats read failed (available=False)
    """
    raw_entries = bpf_read_map(host, map_name, ssh_key_path, user)
    return _parse_xdp_stats_entries(raw_entries)


def bpf_read_xdp_stats_validated(
    host: str,
    ssh_key_path: str,
    user: str = "ubuntu",
    map_name: str = "xdp_wan_stats"
) -> XdpStatsResult:
    """
    Read XDP statistics from the stats map with explicit validation.

    Unlike bpf_read_xdp_stats(), this function returns a structured result
    that allows callers to distinguish between:
    - Stats read successfully, miner blocked N packets (available=True, stats has values)
    - Stats read successfully, miner blocked 0 packets (available=True, stats all zeros)
    - Stats read failed, result unknown (available=False, error_message explains why)

    This is critical for scoring: a miner with unavailable stats should NOT be
    scored as if they blocked 0 packets.

    Args:
        host: Remote host IP.
        ssh_key_path: Path to SSH private key.
        user: SSH username.
        map_name: Name of the stats map.

    Returns:
        XdpStatsResult with available flag, stats dict, and error details.

    Example:
        result = bpf_read_xdp_stats_validated(host, ssh_key_path, user)
        if not result.available:
            logger.warning(f"Stats unavailable for {host}: {result.error_message}")
            # Don't score this miner - stats are unknown
            return None
        # Safe to use result.stats - zeros mean miner genuinely blocked nothing
        drops = result.total_drops
    """
    # Use validated map read
    read_result = bpf_read_map_validated(host, map_name, ssh_key_path, user)

    if not read_result.success:
        logger.warning(
            f"[{host}] XDP stats read failed: status={read_result.status.value}, "
            f"error={read_result.error_message}"
        )
        return XdpStatsResult(
            available=False,
            stats={},
            status=read_result.status,
            error_message=read_result.error_message,
            host=host
        )

    # Parse the entries
    stats = _parse_xdp_stats_entries(read_result.entries)

    # Validate that we got at least some expected counter indices
    # An empty map with 0 entries is valid (no packets processed yet)
    # but if bpftool returned success with entries that couldn't be parsed,
    # that's suspicious
    if read_result.entries and not stats:
        logger.warning(
            f"[{host}] XDP stats: bpftool returned {len(read_result.entries)} entries "
            f"but none could be parsed into valid counters"
        )
        return XdpStatsResult(
            available=False,
            stats={},
            status=BpfReadStatus.PARSE_ERROR,
            error_message=f"Parsed 0 valid counters from {len(read_result.entries)} entries",
            host=host
        )

    logger.debug(
        f"[{host}] XDP stats read successfully: {len(stats)} counters, "
        f"total_drops={sum(v for k, v in stats.items() if k.startswith('xdp_drop_'))}"
    )

    return XdpStatsResult(
        available=True,
        stats=stats,
        status=BpfReadStatus.SUCCESS,
        error_message="",
        host=host
    )


def bpf_read_xdp_stats_by_id(
    host: str,
    ssh_key_path: str,
    map_id: str,
    user: str = "ubuntu"
) -> Dict[str, int]:
    """
    Read XDP statistics from a stats map by its ID.

    Args:
        host: Remote host IP.
        ssh_key_path: Path to SSH private key.
        map_id: BPF map ID.
        user: SSH username.

    Returns:
        Dictionary of counter names to values.

    Note:
        This function returns an empty dict on failure for backward compatibility.
        Use bpf_read_xdp_stats_by_id_validated() to distinguish between:
        - Stats read successfully with zeros (available=True)
        - Stats read failed (available=False)
    """
    command = f"sudo bpftool map dump id {map_id} -j 2>/dev/null || echo '[]'"

    exit_code, stdout, stderr = ssh_exec(host, command, ssh_key_path, user=user, timeout=30)

    if exit_code != 0:
        return {}

    try:
        entries = json.loads((stdout or "").strip())
        if not isinstance(entries, list):
            return {}
    except json.JSONDecodeError:
        return {}

    return _parse_xdp_stats_entries(entries)


def bpf_read_xdp_stats_by_id_validated(
    host: str,
    ssh_key_path: str,
    map_id: str,
    user: str = "ubuntu"
) -> XdpStatsResult:
    """
    Read XDP statistics from a stats map by its ID with explicit validation.

    Unlike bpf_read_xdp_stats_by_id(), this function returns a structured result
    that allows callers to distinguish between:
    - Stats read successfully, miner blocked N packets (available=True)
    - Stats read successfully, miner blocked 0 packets (available=True, stats all zeros)
    - Stats read failed, result unknown (available=False)

    Args:
        host: Remote host IP.
        ssh_key_path: Path to SSH private key.
        map_id: BPF map ID.
        user: SSH username.

    Returns:
        XdpStatsResult with available flag, stats dict, and error details.
    """
    # Don't mask errors - we want to see the actual failure reason
    command = f"sudo bpftool map dump id {map_id} -j"

    exit_code, stdout, stderr = ssh_exec(host, command, ssh_key_path, user=user, timeout=30)
    raw_output = stdout or ""
    stderr_str = stderr or ""

    if exit_code != 0:
        # Check for specific error conditions
        if "No such file or directory" in stderr_str or "can't get info" in stderr_str.lower():
            logger.warning(
                f"[{host}] BPF map id={map_id} not found: {stderr_str.strip()}"
            )
            return XdpStatsResult(
                available=False,
                stats={},
                status=BpfReadStatus.MAP_NOT_FOUND,
                error_message=f"Map id={map_id} does not exist on {host}",
                host=host
            )
        else:
            logger.warning(
                f"[{host}] SSH command failed for BPF map id={map_id}: "
                f"exit_code={exit_code}, stderr={stderr_str.strip()}"
            )
            return XdpStatsResult(
                available=False,
                stats={},
                status=BpfReadStatus.SSH_FAILED,
                error_message=f"SSH command failed: {stderr_str.strip()}",
                host=host
            )

    # Check for empty output
    if not raw_output.strip():
        logger.warning(
            f"[{host}] BPF map id={map_id} returned empty output"
        )
        return XdpStatsResult(
            available=False,
            stats={},
            status=BpfReadStatus.EMPTY_RESULT,
            error_message="Command succeeded but returned empty output",
            host=host
        )

    # Try to parse JSON
    try:
        entries = json.loads(raw_output.strip())
        if not isinstance(entries, list):
            logger.warning(
                f"[{host}] BPF map id={map_id} returned non-list JSON: {type(entries)}"
            )
            return XdpStatsResult(
                available=False,
                stats={},
                status=BpfReadStatus.PARSE_ERROR,
                error_message=f"Expected list, got {type(entries).__name__}",
                host=host
            )
    except json.JSONDecodeError as e:
        logger.warning(
            f"[{host}] Failed to parse BPF map id={map_id} output as JSON: {e}"
        )
        return XdpStatsResult(
            available=False,
            stats={},
            status=BpfReadStatus.PARSE_ERROR,
            error_message=f"JSON decode error: {e}",
            host=host
        )

    # Parse entries
    stats = _parse_xdp_stats_entries(entries)

    # Validate parsed results
    if entries and not stats:
        logger.warning(
            f"[{host}] XDP stats id={map_id}: bpftool returned {len(entries)} entries "
            f"but none could be parsed into valid counters"
        )
        return XdpStatsResult(
            available=False,
            stats={},
            status=BpfReadStatus.PARSE_ERROR,
            error_message=f"Parsed 0 valid counters from {len(entries)} entries",
            host=host
        )

    logger.debug(
        f"[{host}] XDP stats id={map_id} read successfully: {len(stats)} counters"
    )

    return XdpStatsResult(
        available=True,
        stats=stats,
        status=BpfReadStatus.SUCCESS,
        error_message="",
        host=host
    )
