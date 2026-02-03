"""
WireGuard Tunnel Manager for Validator-Scrubber Audit Traffic.

Creates WireGuard tunnels to allow validators to send test packets with
spoofed source IPs that would otherwise be dropped by cloud anti-spoofing.

WireGuard uses UDP encapsulation which passes through cloud firewalls.

MULTI-VALIDATOR SUPPORT:
Each (validator, miner) pair gets a unique tunnel, allowing multiple validators
to audit the same miner simultaneously without interference.

The tunnel encapsulates packets so:
- Outer packet: Real validator IP → Scrubber IP (UDP, passes cloud filters)
- Inner packet: Spoofed source IP → Test destination (processed by XDP)

IP Addressing Scheme (per validator_uid + miner_uid):
- Tunnel name: wga{validator_uid}_{miner_uid} (max 10 chars, fits Linux 15 char limit)
- WireGuard port: 10000 + (validator_uid * 216 + miner_uid) (max port ~65000)
- Tunnel subnet: 10.{100 + validator_uid % 156}.{miner_uid}.0/30
- Scrubber tunnel IP: 10.{100 + validator_uid % 156}.{miner_uid}.1
- Validator tunnel IP: 10.{100 + validator_uid % 156}.{miner_uid}.2

This supports up to 256 validators × 256 miners = 65,536 simultaneous tunnels.
Port allocation uses V*216+M to fit within port range 10000-65000 without modulo collisions.
"""

import subprocess
import os
import re
from typing import Optional, Tuple, Dict
from dataclasses import dataclass, field

from loguru import logger

from shared.utils.ssh import ssh_exec, ssh_exec_pooled, SSHConnectionPool

# Scrubber filesystem paths - these are paths ON THE SCRUBBER (remote)
# The assets are uploaded to /home/ubuntu/assets during scrubber bootstrap
# Module 30 copies some files to /opt/tensorprox but NOT the audit eBPF programs
SCRUBBER_EBPF_BUILD_PATH = "/home/ubuntu/assets/ebpf/build"


def generate_wireguard_keypair() -> Tuple[str, str]:
    """Generate a WireGuard key pair."""
    result = subprocess.run(
        ["wg", "genkey"],
        capture_output=True,
        text=True,
        timeout=10
    )
    private_key = result.stdout.strip()

    result = subprocess.run(
        ["wg", "pubkey"],
        input=private_key,
        capture_output=True,
        text=True,
        timeout=10
    )
    public_key = result.stdout.strip()

    return private_key, public_key


@dataclass
class TunnelConfig:
    """
    Configuration for a multi-validator audit tunnel.

    Each (validator_uid, miner_uid) pair gets a unique tunnel configuration.
    This allows multiple validators to audit the same miner simultaneously
    without interference.
    """
    miner_uid: int
    validator_uid: int = 0  # Validator's UID for multi-validator support
    tunnel_name: str = field(init=False)
    wg_port: int = field(init=False)
    scrubber_tunnel_ip: str = field(init=False)
    validator_tunnel_ip: str = field(init=False)
    tunnel_subnet: str = field(init=False)

    def __post_init__(self):
        """Generate all values based on validator_uid and miner_uid."""
        # Tunnel name: shortened to fit Linux 15-char interface name limit
        # "wga" prefix + validator_uid + "_" + miner_uid = max 10 chars (wga255_255)
        self.tunnel_name = f"wga{self.validator_uid}_{self.miner_uid}"

        # WireGuard port: unique for each (validator, miner) pair
        # Formula: 10000 + (V * 216 + M) gives range 10000-65335 without collisions
        # V * 216 + M for V=255, M=255 = 55335, + 10000 = 65335 (within 65535 limit)
        self.wg_port = 10000 + (self.validator_uid * 216 + self.miner_uid)

        # IP addressing: 10.{100 + validator_uid % 156}.{miner_uid}.{1|2}/30
        # Each validator gets its own /24 subnet (100-255), each miner gets a /30
        # This supports 256 validators × 256 miners = 65,536 unique tunnels
        octet2 = 100 + (self.validator_uid % 156)
        octet3 = self.miner_uid % 256

        self.tunnel_subnet = f"10.{octet2}.{octet3}"
        self.scrubber_tunnel_ip = f"10.{octet2}.{octet3}.1"
        self.validator_tunnel_ip = f"10.{octet2}.{octet3}.2"


class TunnelManager:
    """
    Manages WireGuard tunnels between validators and scrubbers for audit traffic.

    Supports multiple concurrent tunnels with MULTI-VALIDATOR support.
    Each (validator_uid, miner_uid) pair gets a unique tunnel, allowing
    multiple validators to audit the same miner simultaneously.

    Usage:
        # Create tunnel for validator UID 58 auditing miner UID 57
        manager = TunnelManager(
            scrubber_ip="1.2.3.4",
            ssh_key_path="/path/to/key",
            miner_uid=57,
            validator_uid=58  # Your validator's UID
        )

        # Setup tunnel (does both local and remote)
        success = manager.setup_tunnel()

        # Send packets to manager.config.scrubber_tunnel_ip
        # They will be decapsulated at scrubber and processed by XDP

        # Teardown when done
        manager.teardown_tunnel()
    """

    # Class-level storage of active tunnels keyed by (validator_uid, miner_uid)
    _active_tunnels: Dict[Tuple[int, int], "TunnelManager"] = {}

    def __init__(
        self,
        scrubber_ip: str,
        ssh_key_path: str,
        miner_uid: int,
        validator_uid: int = 0,  # Validator's UID for multi-validator support
        ssh_user: str = "ubuntu",
        use_connection_pool: bool = True,  # Use pooled SSH connections for scalability
    ):
        self.scrubber_ip = scrubber_ip
        self.ssh_key_path = ssh_key_path
        self.ssh_user = ssh_user
        self.miner_uid = miner_uid
        self.validator_uid = validator_uid
        self.use_connection_pool = use_connection_pool
        self.config = TunnelConfig(miner_uid=miner_uid, validator_uid=validator_uid)
        self.local_ip: Optional[str] = None
        self.tunnel_established = False
        self.tunnel_rtt_ms: float = 0.0  # RTT from tunnel verification (for latency scoring)

        # WireGuard keys (generated on setup)
        self.validator_private_key: Optional[str] = None
        self.validator_public_key: Optional[str] = None
        self.scrubber_private_key: Optional[str] = None
        self.scrubber_public_key: Optional[str] = None

        # Audit XDP tracking (for reading correct stats map)
        self.audit_xdp_prog_id: Optional[str] = None
        self.audit_stats_map_id: Optional[str] = None

    def _get_local_ip(self) -> Optional[str]:
        """Get local IP address used to reach scrubber."""
        try:
            result = subprocess.run(
                ["ip", "route", "get", self.scrubber_ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                parts = result.stdout.split()
                for i, part in enumerate(parts):
                    if part == "src" and i + 1 < len(parts):
                        return parts[i + 1]
        except Exception as e:
            logger.warning(f"Failed to get local IP: {e}")
        return None

    def _run_local_cmd(self, cmd: str) -> Tuple[bool, str]:
        """Run a command locally, using sudo only if not root."""
        try:
            # Root doesn't need sudo
            if os.geteuid() == 0:
                shell_cmd = ["bash", "-c", cmd]
            else:
                shell_cmd = ["sudo", "-n", "bash", "-c", cmd]

            result = subprocess.run(
                shell_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                return False, result.stderr
            return True, result.stdout
        except Exception as e:
            return False, str(e)

    def _run_remote_cmd(self, cmd: str, timeout: int = 30) -> Tuple[bool, str]:
        """
        Run a command on the scrubber via SSH.

        Uses connection pooling by default for 256-miner scalability.
        Each audit would otherwise spawn ~17 SSH processes; pooling
        reduces this to reusing ~4 persistent connections per scrubber.
        """
        # Use pooled connection for better scalability (critical for 256 miners)
        if self.use_connection_pool:
            exit_code, stdout, stderr = ssh_exec_pooled(
                host=self.scrubber_ip,
                command=f"sudo bash -c '{cmd}'",
                ssh_key_path=self.ssh_key_path,
                user=self.ssh_user,
                timeout=timeout
            )
        else:
            # Fallback to subprocess-based SSH (spawns new process per command)
            exit_code, stdout, stderr = ssh_exec(
                host=self.scrubber_ip,
                command=f"sudo bash -c '{cmd}'",
                ssh_key_path=self.ssh_key_path,
                user=self.ssh_user,
                timeout=timeout
            )

        if exit_code != 0:
            return False, stderr
        return True, stdout

    def _generate_keys(self) -> bool:
        """Generate WireGuard key pairs for both ends."""
        try:
            self.validator_private_key, self.validator_public_key = generate_wireguard_keypair()
            self.scrubber_private_key, self.scrubber_public_key = generate_wireguard_keypair()
            return True
        except Exception as e:
            logger.error(f"Failed to generate WireGuard keys: {e}")
            return False

    def setup_scrubber_tunnel(self) -> bool:
        """
        Set up WireGuard tunnel endpoint on the scrubber.

        Creates a WireGuard interface that accepts tunneled traffic from validator.
        """
        # MULTI-MINER: Per-miner tunnel setup at TRACE level
        logger.trace(f"WG tunnel setup for miner={self.miner_uid}")

        cfg = self.config

        # Remove existing interface if present
        self._run_remote_cmd(f"ip link del {cfg.tunnel_name} 2>/dev/null || true")

        # Create WireGuard interface
        success, err = self._run_remote_cmd(f"ip link add {cfg.tunnel_name} type wireguard")
        if not success:
            logger.error(f"Failed to create scrubber WireGuard interface: {err}")
            return False

        # Write scrubber private key to temp file and configure
        key_file = f"/tmp/wg_key_{cfg.tunnel_name}"
        self._run_remote_cmd(f"echo '{self.scrubber_private_key}' > {key_file} && chmod 600 {key_file}")

        # Configure WireGuard
        # IMPORTANT: Use 0.0.0.0/0 for allowed-ips to accept packets with ANY source IP
        # from the validator peer. This is required because audit traffic uses spoofed
        # source IPs (bogon, blacklist, random) that would otherwise be dropped by WireGuard.
        success, err = self._run_remote_cmd(
            f"wg set {cfg.tunnel_name} listen-port {cfg.wg_port} private-key {key_file} "
            f"peer {self.validator_public_key} allowed-ips 0.0.0.0/0"
        )
        if not success:
            logger.error(f"Failed to configure scrubber WireGuard: {err}")
            return False

        # Clean up key file
        self._run_remote_cmd(f"rm -f {key_file}")

        # Assign IP (ignore if already exists from a previous run)
        success, err = self._run_remote_cmd(
            f"ip addr add {cfg.scrubber_tunnel_ip}/30 dev {cfg.tunnel_name} 2>&1 || true"
        )

        # ALWAYS bring the interface up (critical - was skipped if ip addr failed)
        success, err = self._run_remote_cmd(f"ip link set {cfg.tunnel_name} up")
        if not success:
            logger.error(f"Failed to bring up scrubber WireGuard interface: {err}")
            return False

        # Set MTU to account for WireGuard overhead (~60 bytes)
        # This prevents "Message too long" errors when sending through the tunnel
        self._run_remote_cmd(f"ip link set {cfg.tunnel_name} mtu 1380")

        # Verify interface is UP immediately after bringing it up
        # Note: WireGuard shows "state UNKNOWN" when up but no active peers, check flags instead
        _, link_state = self._run_remote_cmd(f"ip link show {cfg.tunnel_name}")
        if ",UP," in link_state or "UP>" in link_state:
            logger.trace(f"WG interface {cfg.tunnel_name} UP")
        else:
            logger.debug(f"WG interface {cfg.tunnel_name} status unclear: {link_state}")

        # Disable reverse path filtering (crucial for spoofed packets)
        # Must disable on ALL interfaces for forwarding to work with spoofed sources
        self._run_remote_cmd(f"sysctl -w net.ipv4.conf.{cfg.tunnel_name}.rp_filter=0")
        self._run_remote_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
        self._run_remote_cmd("sysctl -w net.ipv4.conf.default.rp_filter=0")
        self._run_remote_cmd("sysctl -w net.ipv4.conf.ens5.rp_filter=0")
        # Enable forwarding and accept_local for proper packet forwarding
        self._run_remote_cmd("sysctl -w net.ipv4.ip_forward=1")
        self._run_remote_cmd("sysctl -w net.ipv4.conf.all.accept_local=1")
        self._run_remote_cmd("sysctl -w net.ipv4.conf.default.accept_local=1")

        # CRITICAL: Whitelist the validator IP in XDP so WireGuard UDP packets aren't blocked
        # XDP on ens5 processes packets BEFORE WireGuard decapsulation, so the validator's
        # outer IP must be whitelisted or the tunnel traffic will be dropped.
        validator_ip = self._get_local_ip()
        if validator_ip:
            # Find the whitelist_map ID (maps aren't pinned, need to find by name)
            _, map_output = self._run_remote_cmd('bpftool map show 2>/dev/null | grep -E "whitelist_map" | head -1 | cut -d: -f1')
            map_id = map_output.strip() if map_output else ""

            if map_id:
                # Convert IP to hex bytes for bpftool (network byte order)
                octets = validator_ip.split(".")
                ip_hex = " ".join(f"{int(o):02x}" for o in octets)
                whitelist_cmd = f"bpftool map update id {map_id} key hex {ip_hex} value hex 01"
                success, output = self._run_remote_cmd(whitelist_cmd)
                if success:
                    logger.trace("Whitelisted validator IP in XDP")
                else:
                    logger.debug("Failed to whitelist validator IP in XDP")
            else:
                logger.warning("Could not find whitelist_map ID")

        # Verify WG is up (XDP attachment happens later, after tunnel verification)
        _, state_out = self._run_remote_cmd(f"ip link show {cfg.tunnel_name}")
        wg_state = "UP" if (",UP," in state_out or "UP>" in state_out) else "DOWN"
        logger.info(f"WG verify: state={wg_state}")

        logger.info(f"Scrubber WireGuard tunnel ready: {cfg.tunnel_name}")
        return True

    def attach_audit_xdp(self) -> bool:
        """
        Attach XDP program to the WireGuard interface on the scrubber.

        This is called AFTER tunnel verification to avoid XDP dropping ping packets.
        """
        cfg = self.config

        # Attach XDP directly to the WireGuard interface for audit traffic processing.
        # WireGuard delivers raw IP packets (no Ethernet header), so we use a special
        # XDP program designed for WireGuard's link/none interface type.
        xdp_attached = False
        xdp_path = f"{SCRUBBER_EBPF_BUILD_PATH}/xdp_wg_audit.o"

        success, output = self._run_remote_cmd(
            f"sudo ip link set {cfg.tunnel_name} xdpgeneric obj {xdp_path} sec xdp 2>&1"
        )
        logger.debug(f"XDP attach cmd: success={success}, output=[{output}]")

        # Verify XDP actually attached (not just exit code)
        _, verify_output = self._run_remote_cmd(
            f"sudo bpftool net show dev {cfg.tunnel_name} 2>&1"
        )
        logger.debug(f"XDP verify after attach: {verify_output}")

        if "xdp" in str(verify_output).lower() and "id" in str(verify_output):
            logger.debug(f"XDP CONFIRMED attached to {cfg.tunnel_name}")
            xdp_attached = True

            # Extract prog ID directly from verify_output (format: "wga57_87(87) generic id 1234")
            prog_match = re.search(r'id\s+(\d+)', verify_output)
            if prog_match:
                self.audit_xdp_prog_id = prog_match.group(1)
                # Get the stats map ID - use double quotes in sed to avoid nested single quotes
                _, map_ids_out = self._run_remote_cmd(
                    f'bpftool prog show id {self.audit_xdp_prog_id} 2>/dev/null | sed -n "s/.*map_ids //p" | tr , " "'
                )
                if map_ids_out and map_ids_out.strip():
                    map_ids = map_ids_out.strip().split()
                    for map_id in map_ids:
                        _, map_info = self._run_remote_cmd(f"bpftool map show id {map_id} 2>/dev/null")
                        if "audit_xdp_stats" in str(map_info):
                            self.audit_stats_map_id = map_id
                            logger.debug(f"Audit XDP prog ID={self.audit_xdp_prog_id}, stats map ID={self.audit_stats_map_id}")
                            break
                    if not self.audit_stats_map_id:
                        logger.warning(f"Could not find audit_xdp_stats among maps: {map_ids}")
                else:
                    logger.warning(f"Failed to get map IDs for XDP prog {self.audit_xdp_prog_id}: {map_ids_out}")
            else:
                logger.warning(f"Could not extract prog ID from verify output: {verify_output}")
        elif success or "already" in str(output):
            logger.warning(f"XDP cmd exit=0 but NOT verified: bpftool=[{verify_output}], trying manual attach")
            # Try manual attach without the _run_remote_cmd wrapper
            _, manual_output = self._run_remote_cmd(
                f"ip link set {cfg.tunnel_name} xdpgeneric obj {xdp_path} sec xdp 2>&1; bpftool net show dev {cfg.tunnel_name} 2>&1"
            )
            logger.debug(f"Manual attach result: {manual_output}")
            if "id" in str(manual_output):
                xdp_attached = True
        else:
            logger.warning(f"XDP attach to {cfg.tunnel_name} failed: {output}")

        if not xdp_attached:
            # Fallback: simple counting without full XDP processing
            logger.warning("Using fallback TC counting (no full XDP filtering)")
            _, stats_map_output = self._run_remote_cmd(
                'bpftool map show 2>/dev/null | grep -E "xdp_wan_stats" | head -1 | cut -d: -f1'
            )
            stats_map_id = stats_map_output.strip() if stats_map_output else ""
            if stats_map_id:
                self._run_remote_cmd("mkdir -p /sys/fs/bpf")
                self._run_remote_cmd(f"bpftool map pin id {stats_map_id} /sys/fs/bpf/xdp_wan_stats 2>/dev/null || true")

            # Use tc_audit_redirect which has audit_stats map for counting
            tc_redirect_path = f"{SCRUBBER_EBPF_BUILD_PATH}/tc_audit_redirect.o"
            self._run_remote_cmd(
                f"tc qdisc add dev {cfg.tunnel_name} clsact 2>/dev/null || true; "
                f"tc filter add dev {cfg.tunnel_name} ingress bpf da obj {tc_redirect_path} sec tc/ingress"
            )

        # Verify TC was attached
        _, tc_out = self._run_remote_cmd(f"tc filter show dev {cfg.tunnel_name} ingress")
        tc_attached = "1" if "bpf" in tc_out else "0"
        logger.debug(f"XDP/TC verify: xdp={xdp_attached}, tc_filters={tc_attached}")

        # Populate the audit_blacklist_map with known malicious prefixes
        # This is required for blacklist detection to work in audit mode
        if xdp_attached and self.audit_xdp_prog_id:
            self._populate_audit_blacklist()

        return xdp_attached

    def _populate_audit_blacklist(self) -> None:
        """
        Populate the audit_blacklist_map with known malicious IP prefixes.

        This is required for blacklist detection to work during audits, since the
        audit XDP program has its own blacklist map (not the production one).

        The prefixes match those in real_packet_sender.MALICIOUS_PREFIXES.
        """
        # Known malicious prefixes (must match real_packet_sender.MALICIOUS_PREFIXES)
        MALICIOUS_PREFIXES = [
            ("45.142.212.0", 22),
            ("185.220.100.0", 22),
            ("89.248.160.0", 21),
            ("194.165.16.0", 24),
            ("45.155.204.0", 22),
            ("193.32.160.0", 21),
            ("91.241.19.0", 24),
            ("5.188.86.0", 23),
            ("167.94.138.0", 23),
            ("80.82.77.0", 24),
        ]

        if not self.audit_xdp_prog_id:
            logger.warning("Cannot populate blacklist: XDP prog ID not found")
            return

        # Find the audit_blacklist_map ID from the XDP program
        _, map_ids_out = self._run_remote_cmd(
            f'bpftool prog show id {self.audit_xdp_prog_id} 2>/dev/null | sed -n "s/.*map_ids //p" | tr , " "'
        )
        if not map_ids_out or not map_ids_out.strip():
            logger.warning("Cannot populate blacklist: failed to get map IDs")
            return

        blacklist_map_id = None
        for map_id in map_ids_out.strip().split():
            _, map_info = self._run_remote_cmd(f"bpftool map show id {map_id} 2>/dev/null")
            if "audit_blacklist_map" in str(map_info):
                blacklist_map_id = map_id
                break

        if not blacklist_map_id:
            logger.warning("Cannot populate blacklist: audit_blacklist_map not found")
            return

        # Add each malicious prefix to the blacklist map
        # LPM key format: prefixlen (4 bytes LE) + IP (4 bytes network order)
        added = 0
        for ip_str, prefix_len in MALICIOUS_PREFIXES:
            # Convert IP to bytes
            ip_parts = [int(x) for x in ip_str.split('.')]
            ip_hex = ' '.join(f'{b:02x}' for b in ip_parts)
            # Prefix length in little-endian
            prefix_hex = ' '.join(f'{b:02x}' for b in prefix_len.to_bytes(4, 'little'))
            key_hex = f"{prefix_hex} {ip_hex}"

            success, _ = self._run_remote_cmd(
                f"bpftool map update id {blacklist_map_id} key hex {key_hex} value hex 01 2>/dev/null"
            )
            if success:
                added += 1

        logger.debug(f"Audit blacklist populated: {added}/{len(MALICIOUS_PREFIXES)} prefixes added")

    def setup_validator_tunnel(self) -> bool:
        """
        Set up WireGuard tunnel endpoint on the validator (local).

        Creates a WireGuard interface to send tunneled traffic to scrubber.
        """
        self.local_ip = self._get_local_ip()
        if not self.local_ip:
            logger.error("Failed to determine local IP")
            return False

        # MULTI-MINER: Per-miner tunnel setup at TRACE level
        logger.trace(f"WG local tunnel setup for miner={self.miner_uid}")

        cfg = self.config

        # Remove existing interface if present
        self._run_local_cmd(f"ip link del {cfg.tunnel_name} 2>/dev/null || true")

        # Create WireGuard interface
        success, err = self._run_local_cmd(f"ip link add {cfg.tunnel_name} type wireguard")
        if not success:
            logger.error(f"Failed to create local WireGuard interface: {err}")
            return False

        # Write validator private key to temp file and configure
        key_file = f"/tmp/wg_key_{cfg.tunnel_name}"
        self._run_local_cmd(f"echo '{self.validator_private_key}' > {key_file} && chmod 600 {key_file}")

        # Configure WireGuard with scrubber as peer
        success, err = self._run_local_cmd(
            f"wg set {cfg.tunnel_name} private-key {key_file} "
            f"peer {self.scrubber_public_key} "
            f"endpoint {self.scrubber_ip}:{cfg.wg_port} "
            f"allowed-ips {cfg.scrubber_tunnel_ip}/32 "
            f"persistent-keepalive 25"
        )
        if not success:
            logger.error(f"Failed to configure local WireGuard: {err}")
            return False

        # Clean up key file
        self._run_local_cmd(f"rm -f {key_file}")

        # Assign IP and bring up
        success, err = self._run_local_cmd(
            f"ip addr add {cfg.validator_tunnel_ip}/30 dev {cfg.tunnel_name} && "
            f"ip link set {cfg.tunnel_name} up"
        )
        if not success and "RTNETLINK answers: File exists" not in err:
            logger.error(f"Failed to configure local tunnel IP: {err}")
            return False

        # Set MTU to account for WireGuard overhead (~60 bytes)
        # Must match scrubber side to prevent fragmentation issues
        self._run_local_cmd(f"ip link set {cfg.tunnel_name} mtu 1380")

        # Add route to scrubber's tunnel IP through the tunnel
        self._run_local_cmd(
            f"ip route add {cfg.scrubber_tunnel_ip}/32 dev {cfg.tunnel_name} 2>/dev/null || true"
        )

        logger.trace(f"WG tunnel ready: {cfg.tunnel_name} for miner={self.miner_uid}")
        return True

    def setup_tunnel(self) -> bool:
        """
        Set up WireGuard tunnel on both ends.

        Returns:
            True if tunnel established successfully.
        """
        # Generate keys first
        if not self._generate_keys():
            return False

        # First set up scrubber side
        if not self.setup_scrubber_tunnel():
            return False

        # Then set up local side
        if not self.setup_validator_tunnel():
            self.teardown_scrubber_tunnel()
            return False

        # Verify tunnel is working (before XDP attachment, since XDP drops bogon IPs)
        tunnel_ok, self.tunnel_rtt_ms = self.verify_tunnel()
        if not tunnel_ok:
            logger.warning("Tunnel verification failed, proceeding but audit may not work")
            self.tunnel_rtt_ms = 0.0

        # Now attach XDP to the scrubber's WireGuard interface for audit traffic filtering
        self.attach_audit_xdp()

        self.tunnel_established = True

        # Track active tunnel by (validator_uid, miner_uid) tuple
        tunnel_key = (self.validator_uid, self.miner_uid)
        TunnelManager._active_tunnels[tunnel_key] = self

        return True

    def verify_tunnel(self) -> tuple[bool, float]:
        """
        Verify the tunnel is working by pinging through it.

        Returns:
            Tuple of (success: bool, rtt_ms: float)
            RTT is the average ping time if successful, 0.0 otherwise.
        """
        cfg = self.config

        try:
            result = subprocess.run(
                ["ping", "-c", "3", "-W", "3", "-I", cfg.tunnel_name, cfg.scrubber_tunnel_ip],
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                # Parse RTT from ping output (e.g., "rtt min/avg/max/mdev = 10.5/15.2/20.1/3.5 ms")
                rtt_ms = 0.0
                for line in result.stdout.split('\n'):
                    if 'rtt' in line or 'round-trip' in line:
                        # Extract avg RTT from "min/avg/max/mdev" format
                        import re
                        match = re.search(r'[\d.]+/([\d.]+)/[\d.]+/[\d.]+', line)
                        if match:
                            rtt_ms = float(match.group(1))
                            break

                logger.trace(f"WG tunnel verified miner={self.miner_uid} rtt={rtt_ms:.1f}ms")
                return True, rtt_ms
            else:
                logger.warning(f"Tunnel ping failed: {result.stderr}")
        except Exception as e:
            logger.warning(f"Tunnel verification error: {e}")

        return False, 0.0

    def teardown_validator_tunnel(self) -> bool:
        """Remove local WireGuard tunnel."""
        cfg = self.config
        self._run_local_cmd(f"ip link del {cfg.tunnel_name} 2>/dev/null || true")
        logger.trace(f"WG local tunnel removed miner={self.miner_uid}")
        return True

    def teardown_scrubber_tunnel(self) -> bool:
        """Remove WireGuard tunnel and XDP program on scrubber."""
        cfg = self.config

        # Detach XDP from WireGuard interface before deleting
        self._run_remote_cmd(f"ip link set {cfg.tunnel_name} xdp off 2>/dev/null || true")

        # Remove TC filter if any (fallback mode)
        self._run_remote_cmd(f"tc filter del dev {cfg.tunnel_name} ingress 2>/dev/null || true")
        self._run_remote_cmd(f"tc qdisc del dev {cfg.tunnel_name} clsact 2>/dev/null || true")

        # Remove WireGuard interface
        self._run_remote_cmd(f"ip link del {cfg.tunnel_name} 2>/dev/null || true")

        logger.trace(f"WG scrubber tunnel removed miner={self.miner_uid}")
        return True

    def teardown_tunnel(self) -> bool:
        """Tear down the WireGuard tunnel on both ends."""
        self.teardown_validator_tunnel()
        self.teardown_scrubber_tunnel()
        self.tunnel_established = False

        # Remove from active tunnels
        tunnel_key = (self.validator_uid, self.miner_uid)
        if tunnel_key in TunnelManager._active_tunnels:
            del TunnelManager._active_tunnels[tunnel_key]

        return True

    def get_tunnel_destination(self) -> str:
        """Get the IP to send test packets to (through the tunnel)."""
        return self.config.scrubber_tunnel_ip

    def get_tunnel_interface(self) -> str:
        """Get the tunnel interface name for packet sending."""
        return self.config.tunnel_name

    @classmethod
    def get_active_tunnel(cls, validator_uid: int, miner_uid: int) -> Optional["TunnelManager"]:
        """Get an active tunnel by (validator_uid, miner_uid) pair."""
        return cls._active_tunnels.get((validator_uid, miner_uid))

    @classmethod
    def get_all_active_tunnels(cls) -> Dict[Tuple[int, int], "TunnelManager"]:
        """Get all active tunnels keyed by (validator_uid, miner_uid)."""
        return cls._active_tunnels.copy()

    @classmethod
    def teardown_all_tunnels(cls):
        """Tear down all active tunnels."""
        for key, manager in list(cls._active_tunnels.items()):
            manager.teardown_tunnel()


# Aliases for clarity and backward compatibility
AuditTunnelManager = TunnelManager
AuditTunnelConfig = TunnelConfig
# Legacy aliases (deprecated)
GRETunnelConfig = TunnelConfig
GRETunnelManager = TunnelManager


# Convenience function for quick tunnel setup
def setup_audit_tunnel(
    scrubber_ip: str,
    ssh_key_path: str,
    miner_uid: int,
    validator_uid: int = 0,
    ssh_user: str = "ubuntu"
) -> Optional[TunnelManager]:
    """
    Quick setup of WireGuard audit tunnel for a specific (validator, miner) pair.

    Args:
        scrubber_ip: Scrubber's public IP address.
        ssh_key_path: Path to SSH private key for scrubber access.
        miner_uid: Miner's UID for unique tunnel addressing.
        validator_uid: Validator's UID for multi-validator support.
        ssh_user: SSH username for scrubber (default: ubuntu).

    Returns:
        TunnelManager if successful, None otherwise.
    """
    manager = TunnelManager(
        scrubber_ip=scrubber_ip,
        ssh_key_path=ssh_key_path,
        miner_uid=miner_uid,
        validator_uid=validator_uid,
        ssh_user=ssh_user
    )
    if manager.setup_tunnel():
        return manager
    return None


class SynapseBasedTunnelManager:
    """
    WireGuard tunnel manager that uses bittensor synapses for scrubber setup.

    Unlike TunnelManager which SSH's to the scrubber, this class requests
    the miner to set up the scrubber-side tunnel via SetupTunnelSynapse.
    The validator only configures its local WireGuard interface.

    This ensures clear security boundaries - validators never SSH to
    miner infrastructure. Each party controls only their own machines.

    Usage:
        manager = SynapseBasedTunnelManager(
            scrubber_ip="1.2.3.4",
            miner_uid=57,
            validator_uid=58
        )

        # Request miner to set up tunnel and configure local interface
        success = await manager.setup_tunnel(dendrite, axon)

        # Send traffic through manager.tunnel_destination_ip
        # ...

        # Request teardown
        await manager.teardown_tunnel(dendrite, axon)
    """

    def __init__(
        self,
        scrubber_ip: str,
        miner_uid: int,
        validator_uid: int,
    ):
        self.scrubber_ip = scrubber_ip
        self.miner_uid = miner_uid
        self.validator_uid = validator_uid
        self.tunnel_established = False
        self.tunnel_rtt_ms: float = 0.0

        # Calculate tunnel config (scalable for 256 miners per validator)
        # Port formula: 10000 + V*216 + M (max port = 10000 + 255*216 + 255 = 65335)
        wg_port = 10000 + (validator_uid * 216 + miner_uid)
        # Subnet: 10.{100+V%156}.{M}.{1,2}/30 - supports up to 156 validators
        subnet_second = 100 + (validator_uid % 156)
        # Interface name: wga{V}_{M} - max 10 chars, fits Linux 15-char limit
        self.tunnel_name = f"wga{validator_uid}_{miner_uid}"
        self.validator_port = wg_port
        self.tunnel_ip_validator = f"10.{subnet_second}.{miner_uid}.2"
        self.tunnel_ip_scrubber = f"10.{subnet_second}.{miner_uid}.1"

        # Keys (generated on setup)
        self.validator_private_key: Optional[str] = None
        self.validator_public_key: Optional[str] = None
        self.scrubber_public_key: Optional[str] = None
        self.scrubber_port: Optional[int] = None

    def _get_local_ip(self) -> Optional[str]:
        """Get local IP address used to reach scrubber."""
        try:
            result = subprocess.run(
                ["ip", "route", "get", self.scrubber_ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                parts = result.stdout.split()
                for i, part in enumerate(parts):
                    if part == "src" and i + 1 < len(parts):
                        return parts[i + 1]
        except Exception as e:
            logger.warning(f"Failed to get local IP: {e}")
        return None

    def _run_local_cmd(self, cmd: str) -> Tuple[bool, str]:
        """Run a command locally."""
        try:
            if os.geteuid() == 0:
                shell_cmd = ["bash", "-c", cmd]
            else:
                shell_cmd = ["sudo", "-n", "bash", "-c", cmd]

            result = subprocess.run(
                shell_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                return False, result.stderr
            return True, result.stdout
        except Exception as e:
            return False, str(e)

    async def setup_tunnel(self, dendrite, axon) -> bool:
        """
        Set up WireGuard tunnel using synapse to request scrubber config.

        Args:
            dendrite: Bittensor dendrite for sending synapse.
            axon: Miner's axon to send the request to.

        Returns:
            True if tunnel established successfully.
        """
        from tensorprox.base.protocol import SetupTunnelSynapse

        # Generate local keys
        self.validator_private_key, self.validator_public_key = generate_wireguard_keypair()

        # Get local IP
        local_ip = self._get_local_ip()
        if not local_ip:
            logger.error("Failed to determine local IP for tunnel setup")
            return False

        # Create synapse request
        synapse = SetupTunnelSynapse(
            validator_pubkey=self.validator_public_key,
            validator_ip=local_ip,
            validator_port=self.validator_port,
            validator_uid=self.validator_uid,
            scrubber_ip=self.scrubber_ip,
            action="setup",
        )

        # Send to miner
        logger.debug(f"Requesting tunnel setup from miner {self.miner_uid}")
        responses = await dendrite.forward(
            axons=[axon],
            synapse=synapse,
            timeout=60.0,  # Tunnel setup involves SSH, give it time
        )

        if not responses or not responses[0].success:
            error = responses[0].error_message if responses else "No response"
            logger.error(f"Miner failed to set up tunnel: {error}")
            return False

        response = responses[0]
        self.scrubber_public_key = response.scrubber_pubkey
        self.scrubber_port = response.scrubber_port
        self.tunnel_ip_scrubber = response.tunnel_ip_scrubber
        self.tunnel_ip_validator = response.tunnel_ip_validator

        logger.debug(
            f"Miner set up tunnel: scrubber_port={self.scrubber_port}, "
            f"scrubber_ip={self.tunnel_ip_scrubber}, validator_ip={self.tunnel_ip_validator}"
        )

        # Set up local WireGuard interface
        if not self._setup_local_interface():
            logger.error("Failed to set up local WireGuard interface")
            return False

        # Verify tunnel works
        tunnel_ok, self.tunnel_rtt_ms = self._verify_tunnel()
        if not tunnel_ok:
            logger.warning("Tunnel verification failed, proceeding but audit may not work")

        self.tunnel_established = True
        logger.info(
            f"Synapse-based tunnel ready: {self.tunnel_name} -> {self.scrubber_ip}:{self.scrubber_port}"
        )

        return True

    def _setup_local_interface(self) -> bool:
        """Set up local WireGuard interface."""
        # Remove existing interface
        self._run_local_cmd(f"ip link del {self.tunnel_name} 2>/dev/null || true")

        # Create interface
        success, err = self._run_local_cmd(f"ip link add {self.tunnel_name} type wireguard")
        if not success:
            logger.error(f"Failed to create local WG interface: {err}")
            return False

        # Write private key and configure
        key_file = f"/tmp/wg_val_key_{self.tunnel_name}"
        self._run_local_cmd(f"echo '{self.validator_private_key}' > {key_file} && chmod 600 {key_file}")

        # Configure WireGuard with scrubber as peer
        wg_cmd = (
            f"wg set {self.tunnel_name} listen-port {self.validator_port} private-key {key_file} "
            f"peer {self.scrubber_public_key} allowed-ips 0.0.0.0/0 "
            f"endpoint {self.scrubber_ip}:{self.scrubber_port}"
        )
        success, err = self._run_local_cmd(wg_cmd)
        if not success:
            logger.error(f"Failed to configure local WG: {err}")
            return False

        # Clean up key file
        self._run_local_cmd(f"rm -f {key_file}")

        # Assign IP and bring up
        self._run_local_cmd(f"ip addr add {self.tunnel_ip_validator}/30 dev {self.tunnel_name} 2>/dev/null || true")

        success, err = self._run_local_cmd(f"ip link set {self.tunnel_name} up")
        if not success:
            logger.error(f"Failed to bring up local WG: {err}")
            return False

        # Set MTU
        self._run_local_cmd(f"ip link set {self.tunnel_name} mtu 1380")

        return True

    def _verify_tunnel(self) -> Tuple[bool, float]:
        """Verify tunnel by pinging through it."""
        try:
            cmd = ["ping", "-c", "3", "-W", "3", "-I", self.tunnel_name, self.tunnel_ip_scrubber]
            logger.debug(f"Tunnel verify: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                rtt_ms = 0.0
                for line in result.stdout.split('\n'):
                    if 'rtt' in line or 'round-trip' in line:
                        match = re.search(r'[\d.]+/([\d.]+)/[\d.]+/[\d.]+', line)
                        if match:
                            rtt_ms = float(match.group(1))
                            break
                logger.debug(f"Tunnel verify success: RTT={rtt_ms}ms")
                return True, rtt_ms
            else:
                logger.warning("Tunnel ping failed")
                return False, 0.0
        except Exception as e:
            logger.warning(f"Tunnel verification error: {e}")
            return False, 0.0

    async def teardown_tunnel(self, dendrite, axon) -> None:
        """Tear down the tunnel (both local and remote)."""
        from tensorprox.base.protocol import SetupTunnelSynapse

        # Remove local interface
        self._run_local_cmd(f"ip link del {self.tunnel_name} 2>/dev/null || true")

        # Request miner to tear down scrubber-side
        synapse = SetupTunnelSynapse(
            validator_uid=self.validator_uid,
            scrubber_ip=self.scrubber_ip,
            action="teardown",
        )

        try:
            await dendrite.forward(
                axons=[axon],
                synapse=synapse,
                timeout=30.0,
            )
        except Exception as e:
            logger.warning(f"Failed to request tunnel teardown: {e}")

        self.tunnel_established = False

    def teardown_local(self) -> None:
        """Tear down only the local interface (synchronous)."""
        self._run_local_cmd(f"ip link del {self.tunnel_name} 2>/dev/null || true")
        self.tunnel_established = False

    def get_tunnel_interface(self) -> str:
        """Get the tunnel interface name."""
        return self.tunnel_name

    def get_tunnel_destination(self) -> str:
        """Get the scrubber's tunnel IP (where to send traffic)."""
        return self.tunnel_ip_scrubber
