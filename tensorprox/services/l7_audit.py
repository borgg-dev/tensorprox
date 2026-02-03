"""
Layer 7 Attack Audit Module.

Audits miner capability to detect and block application-layer attacks:
- Slowloris (slow HTTP headers / connection exhaustion)
- HTTP Flood (high request rate per IP)
- State Exhaustion (many half-open connections)

ARCHITECTURE:
Layer 7 attacks are characterized by their TCP CONNECTION PATTERNS, not packet content.
Since XDP can't do deep packet inspection for HTTPS, we detect L7 attacks via:

1. Connection rate per source IP (HTTP flood signature)
2. SYN rate vs completion rate (state exhaustion signature)
3. Connection duration patterns (Slowloris signature)

This module sends TCP SYN patterns that simulate L7 attack behaviors,
and scores miners based on their rate limiting and blocking decisions.

The traffic flows through WireGuard tunnel just like L3/L4 audits, so
cloud provider DDoS protection is bypassed.

INTEGRATION:
Works alongside existing L3/L4 crypto audits - does NOT replace them.
L7 audit results are combined with L3/L4 results for final scoring.
"""

import asyncio
import hashlib
import secrets
import time
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

from loguru import logger

# Try to import scapy
try:
    from scapy.all import IP, TCP, Raw, send, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - L7 audit disabled")


class L7AttackType(Enum):
    """Layer 7 attack types that can be detected via connection patterns."""

    # Slowloris: Many connections from same IP, held open with slow data
    # Detection: High SYN count per IP, low completion rate, long duration
    SLOWLORIS = "slowloris"

    # HTTP Flood: Rapid valid requests from single/few IPs
    # Detection: High connection rate per IP, high completion rate
    HTTP_FLOOD = "http_flood"

    # Connection State Exhaustion: Many half-open connections
    # Detection: High SYN count, very low SYN-ACK ratio, many RST responses
    STATE_EXHAUSTION = "state_exhaustion"

    # Slow POST: Send body very slowly to hold connections
    # Detection: Similar to Slowloris - long connection times
    SLOW_POST = "slow_post"

    # Benign connection pattern for false positive testing
    BENIGN_CONNECTIONS = "benign_connections"


class L7ExpectedAction(Enum):
    """Expected miner action for L7 attack patterns."""

    # Miner should rate-limit or block this pattern
    SHOULD_BLOCK = "should_block"

    # Miner must allow this pattern (benign)
    MUST_PASS = "must_pass"

    # Either action is acceptable (edge case)
    MAY_BLOCK = "may_block"


@dataclass
class L7AttackPattern:
    """
    Defines an L7 attack pattern to simulate.

    Each pattern specifies:
    - Source IP(s) to use
    - Connection rate (SYNs per second)
    - Whether connections should complete (SYN-ACK expected)
    - Duration of the attack simulation
    """
    attack_type: L7AttackType
    expected_action: L7ExpectedAction

    # Source IP configuration
    source_ips: List[str] = field(default_factory=list)
    single_source: bool = True  # True = all from one IP (concentrated attack)

    # Connection pattern
    syn_count: int = 100  # Total SYN packets to send
    syn_rate_pps: int = 50  # SYNs per second

    # Target ports (HTTP/HTTPS)
    target_ports: List[int] = field(default_factory=lambda: [80, 443, 8080])

    # Pattern identifier for scoring
    pattern_id: str = ""

    def __post_init__(self):
        if not self.pattern_id:
            self.pattern_id = f"{self.attack_type.value}_{secrets.token_hex(4)}"


@dataclass
class L7AuditChallenge:
    """Complete L7 audit challenge with multiple attack patterns."""

    challenge_id: str

    # Attack patterns to simulate
    patterns: List[L7AttackPattern] = field(default_factory=list)

    # Timing
    start_time: float = 0.0
    end_time: float = 0.0

    # Target scrubber
    dest_ip: str = ""

    # Results tracking
    total_syns_sent: int = 0
    patterns_completed: int = 0


@dataclass
class L7AuditResult:
    """Results of L7 audit verification."""

    challenge_id: str

    # Overall metrics
    total_attack_patterns: int = 0
    patterns_detected: int = 0
    patterns_blocked: int = 0

    # Per-attack-type results
    type_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # Format: {attack_type: {sent: N, detected: N, blocked: N, score: float}}

    # False positive (benign blocked)
    benign_patterns_sent: int = 0
    benign_patterns_blocked: int = 0
    false_positive_rate: float = 0.0

    # Scoring
    detection_score: float = 0.0  # How many attacks were detected
    blocking_score: float = 0.0   # How many detected attacks were blocked
    overall_score: float = 0.0    # Combined L7 protection score

    # Connection metrics from miner (for verification)
    miner_metrics: Dict[str, Any] = field(default_factory=dict)

    def compute_scores(self):
        """Compute final L7 protection scores."""
        # Detection score: % of attack patterns where miner showed awareness
        if self.total_attack_patterns > 0:
            self.detection_score = self.patterns_detected / self.total_attack_patterns

        # Blocking score: % of detected attacks that were blocked/rate-limited
        if self.patterns_detected > 0:
            self.blocking_score = self.patterns_blocked / self.patterns_detected

        # False positive rate
        if self.benign_patterns_sent > 0:
            self.false_positive_rate = self.benign_patterns_blocked / self.benign_patterns_sent

        # Overall L7 score:
        # 60% detection + 30% blocking + 10% (1 - false_positive_rate)
        fp_score = 1.0 - self.false_positive_rate
        self.overall_score = (
            0.60 * self.detection_score +
            0.30 * self.blocking_score +
            0.10 * fp_score
        )


class L7AuditSender:
    """
    Sends L7 attack pattern traffic through WireGuard tunnel.

    Unlike L3/L4 audits that check packet-level filtering, L7 audits
    check the miner's ability to detect PATTERNS of connections that
    indicate application-layer attacks.
    """

    # L7-specific port targets
    HTTP_PORTS = [80, 8080, 8000, 3000]
    HTTPS_PORTS = [443, 8443]
    ALL_HTTP_PORTS = HTTP_PORTS + HTTPS_PORTS

    def __init__(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy required for L7 audit")
        conf.verb = 0

    def _generate_attack_source_ip(self) -> str:
        """Generate a random public IP for attack simulation."""
        # Use public IP ranges that aren't bogons
        first_octet = random.choice([1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15])
        return f"{first_octet}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def _generate_benign_source_ip(self) -> str:
        """Generate a legitimate-looking source IP."""
        # Well-known cloud provider ranges (Google, AWS, etc.)
        prefixes = [
            (35, 190),  # Google Cloud
            (52, 0),    # AWS
            (13, 100),  # AWS
            (104, 16),  # Cloudflare
        ]
        prefix = random.choice(prefixes)
        return f"{prefix[0]}.{prefix[1]}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def _create_slowloris_pattern(self, dest_ip: str) -> L7AttackPattern:
        """
        Create Slowloris attack pattern.

        Slowloris signature:
        - Single source IP sends many SYNs
        - Low rate (to stay under per-second limits)
        - But sustained over time
        - Targets HTTP ports
        """
        source_ip = self._generate_attack_source_ip()

        return L7AttackPattern(
            attack_type=L7AttackType.SLOWLORIS,
            expected_action=L7ExpectedAction.SHOULD_BLOCK,
            source_ips=[source_ip],
            single_source=True,
            syn_count=50,  # Many connections from one IP
            syn_rate_pps=10,  # Slow rate (Slowloris is slow)
            target_ports=self.HTTP_PORTS,
        )

    def _create_http_flood_pattern(self, dest_ip: str) -> L7AttackPattern:
        """
        Create HTTP Flood attack pattern.

        HTTP Flood signature:
        - Single or few sources
        - Very high SYN rate
        - Targets HTTP/HTTPS ports
        - Rapid-fire connections
        """
        source_ip = self._generate_attack_source_ip()

        return L7AttackPattern(
            attack_type=L7AttackType.HTTP_FLOOD,
            expected_action=L7ExpectedAction.SHOULD_BLOCK,
            source_ips=[source_ip],
            single_source=True,
            syn_count=200,  # High volume
            syn_rate_pps=100,  # Fast rate
            target_ports=self.ALL_HTTP_PORTS,
        )

    def _create_state_exhaustion_pattern(self, dest_ip: str) -> L7AttackPattern:
        """
        Create State Exhaustion attack pattern.

        State Exhaustion signature:
        - Many source IPs (distributed)
        - High SYN rate
        - No completion (just SYN, no ACK after SYN-ACK)
        - Fills up connection table
        """
        # Multiple source IPs for distributed attack
        source_ips = [self._generate_attack_source_ip() for _ in range(5)]

        return L7AttackPattern(
            attack_type=L7AttackType.STATE_EXHAUSTION,
            expected_action=L7ExpectedAction.SHOULD_BLOCK,
            source_ips=source_ips,
            single_source=False,
            syn_count=150,  # Moderate per-IP, high total
            syn_rate_pps=50,
            target_ports=self.ALL_HTTP_PORTS,
        )

    def _create_benign_pattern(self, dest_ip: str) -> L7AttackPattern:
        """
        Create benign connection pattern for false positive testing.

        Benign signature:
        - Single source
        - Low rate
        - Normal HTTP ports
        - Should NOT be blocked
        """
        source_ip = self._generate_benign_source_ip()

        return L7AttackPattern(
            attack_type=L7AttackType.BENIGN_CONNECTIONS,
            expected_action=L7ExpectedAction.MUST_PASS,
            source_ips=[source_ip],
            single_source=True,
            syn_count=10,  # Low count
            syn_rate_pps=2,  # Low rate (normal browsing)
            target_ports=[80, 443],
        )

    async def generate_challenge(
        self,
        dest_ip: str,
        include_slowloris: bool = True,
        include_http_flood: bool = True,
        include_state_exhaustion: bool = True,
        benign_patterns: int = 3,
    ) -> L7AuditChallenge:
        """
        Generate an L7 audit challenge with multiple attack patterns.

        Args:
            dest_ip: Target scrubber IP
            include_slowloris: Include Slowloris pattern
            include_http_flood: Include HTTP Flood pattern
            include_state_exhaustion: Include State Exhaustion pattern
            benign_patterns: Number of benign patterns for FP testing

        Returns:
            L7AuditChallenge ready for sending
        """
        challenge_id = f"l7-{secrets.token_hex(6)}-{int(time.time())}"

        patterns = []

        # Add attack patterns
        if include_slowloris:
            patterns.append(self._create_slowloris_pattern(dest_ip))

        if include_http_flood:
            patterns.append(self._create_http_flood_pattern(dest_ip))

        if include_state_exhaustion:
            patterns.append(self._create_state_exhaustion_pattern(dest_ip))

        # Add benign patterns for false positive testing
        for _ in range(benign_patterns):
            patterns.append(self._create_benign_pattern(dest_ip))

        # Shuffle patterns to prevent prediction
        random.shuffle(patterns)

        challenge = L7AuditChallenge(
            challenge_id=challenge_id,
            patterns=patterns,
            dest_ip=dest_ip,
        )

        logger.info(
            f"Generated L7 audit challenge {challenge_id}: "
            f"{len(patterns)} patterns"
        )

        return challenge

    def _build_syn_packet(
        self,
        source_ip: str,
        dest_ip: str,
        dest_port: int,
        seq_num: int,
    ) -> Any:
        """Build a TCP SYN packet for L7 pattern testing."""
        source_port = random.randint(1024, 65535)

        # Build SYN packet
        ip = IP(src=source_ip, dst=dest_ip)
        tcp = TCP(
            sport=source_port,
            dport=dest_port,
            flags="S",
            seq=random.randint(1000000, 4000000000),
        )

        # Add audit marker in payload for debugging
        marker = f"L7AUDIT:SEQ{seq_num}".encode()
        payload = Raw(load=marker)

        return ip / tcp / payload

    async def send_pattern(
        self,
        pattern: L7AttackPattern,
        dest_ip: str,
        tunnel_interface: Optional[str] = None,
    ) -> Tuple[int, float]:
        """
        Send a single attack pattern through the tunnel.

        Args:
            pattern: Attack pattern to send
            dest_ip: Target scrubber IP
            tunnel_interface: WireGuard tunnel interface

        Returns:
            Tuple of (packets_sent, duration_seconds)
        """
        packets = []
        seq_num = int(time.time() * 1000) % 1000000

        # Generate packets for this pattern
        for i in range(pattern.syn_count):
            # Select source IP
            if pattern.single_source:
                source_ip = pattern.source_ips[0]
            else:
                source_ip = random.choice(pattern.source_ips)

            # Select target port
            dest_port = random.choice(pattern.target_ports)

            # Build packet
            pkt = self._build_syn_packet(
                source_ip=source_ip,
                dest_ip=dest_ip,
                dest_port=dest_port,
                seq_num=seq_num + i,
            )
            packets.append(pkt)

        # Send at specified rate
        start_time = time.time()
        batch_size = max(1, pattern.syn_rate_pps // 10)  # 10 batches per second
        delay = 0.1  # 100ms between batches

        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=2) as executor:
            for i in range(0, len(packets), batch_size):
                batch = packets[i:i + batch_size]

                if tunnel_interface:
                    await loop.run_in_executor(
                        executor,
                        self._send_via_interface,
                        batch,
                        tunnel_interface,
                    )
                else:
                    await loop.run_in_executor(
                        executor,
                        self._send_packets,
                        batch,
                    )

                # Rate limiting
                if i + batch_size < len(packets):
                    await asyncio.sleep(delay)

        duration = time.time() - start_time

        logger.debug(
            f"Sent {len(packets)} SYNs for {pattern.attack_type.value} "
            f"in {duration:.2f}s ({len(packets)/duration:.1f} pps)"
        )

        return len(packets), duration

    def _send_packets(self, packets: List, batch_size: int = 50):
        """Send packets via scapy."""
        try:
            send(packets, verbose=0)
        except Exception as e:
            logger.warning(f"Packet send error: {e}")

    def _send_via_interface(self, packets: List, interface: str):
        """Send packets via specific interface."""
        import socket as stdlib_socket

        try:
            sock = stdlib_socket.socket(
                stdlib_socket.AF_INET,
                stdlib_socket.SOCK_RAW,
                stdlib_socket.IPPROTO_RAW
            )
            sock.setsockopt(stdlib_socket.IPPROTO_IP, stdlib_socket.IP_HDRINCL, 1)
            sock.setsockopt(
                stdlib_socket.SOL_SOCKET,
                stdlib_socket.SO_BINDTODEVICE,
                interface.encode() + b'\0'
            )

            for pkt in packets:
                try:
                    raw_bytes = bytes(pkt)
                    dest_ip = f"{raw_bytes[16]}.{raw_bytes[17]}.{raw_bytes[18]}.{raw_bytes[19]}"
                    sock.sendto(raw_bytes, (dest_ip, 0))
                except Exception:
                    pass  # Best effort

            sock.close()
        except Exception as e:
            logger.error(f"Interface send error: {e}")

    async def send_challenge(
        self,
        challenge: L7AuditChallenge,
        tunnel_interface: Optional[str] = None,
    ) -> L7AuditChallenge:
        """
        Send all patterns in an L7 audit challenge.

        Args:
            challenge: The challenge to send
            tunnel_interface: WireGuard tunnel interface

        Returns:
            Updated challenge with timing info
        """
        challenge.start_time = time.time()
        total_sent = 0

        for pattern in challenge.patterns:
            sent, _ = await self.send_pattern(
                pattern=pattern,
                dest_ip=challenge.dest_ip,
                tunnel_interface=tunnel_interface,
            )
            total_sent += sent
            challenge.patterns_completed += 1

            # Brief pause between patterns to allow miner detection
            await asyncio.sleep(0.5)

        challenge.end_time = time.time()
        challenge.total_syns_sent = total_sent

        duration = challenge.end_time - challenge.start_time
        logger.info(
            f"L7 challenge {challenge.challenge_id} complete: "
            f"{total_sent} SYNs in {duration:.2f}s, "
            f"{len(challenge.patterns)} patterns"
        )

        return challenge

    def verify_results(
        self,
        challenge: L7AuditChallenge,
        miner_metrics: Dict[str, Any],
    ) -> L7AuditResult:
        """
        Verify L7 audit results based on miner's reported metrics.

        The miner reports connection-level metrics that indicate
        whether L7 attacks were detected and blocked:
        - rate_limited_ips: IPs that hit rate limits
        - blocked_connection_ips: IPs blocked for connection patterns
        - high_syn_rate_ips: IPs with suspicious SYN rates
        - connection_completion_rate: Overall connection completion

        Args:
            challenge: The sent challenge
            miner_metrics: Connection metrics from miner

        Returns:
            L7AuditResult with verification data
        """
        result = L7AuditResult(
            challenge_id=challenge.challenge_id,
            miner_metrics=miner_metrics,
        )

        # Extract metrics
        rate_limited = set(miner_metrics.get("rate_limited_ips", []))
        blocked_ips = set(miner_metrics.get("blocked_connection_ips", []))
        high_syn_ips = set(miner_metrics.get("high_syn_rate_ips", []))

        # Combine all detection signals
        detected_ips = rate_limited | blocked_ips | high_syn_ips
        blocked_or_limited = rate_limited | blocked_ips

        # Verify each pattern
        for pattern in challenge.patterns:
            attack_type = pattern.attack_type.value
            pattern_ips = set(pattern.source_ips)

            # Initialize type result
            if attack_type not in result.type_results:
                result.type_results[attack_type] = {
                    "sent": 0,
                    "detected": 0,
                    "blocked": 0,
                    "score": 0.0,
                }

            result.type_results[attack_type]["sent"] += 1

            # Check if pattern was detected
            detected = bool(pattern_ips & detected_ips)
            blocked = bool(pattern_ips & blocked_or_limited)

            if pattern.expected_action == L7ExpectedAction.SHOULD_BLOCK:
                # Attack pattern
                result.total_attack_patterns += 1

                if detected:
                    result.patterns_detected += 1
                    result.type_results[attack_type]["detected"] += 1

                if blocked:
                    result.patterns_blocked += 1
                    result.type_results[attack_type]["blocked"] += 1

            elif pattern.expected_action == L7ExpectedAction.MUST_PASS:
                # Benign pattern
                result.benign_patterns_sent += 1

                if blocked:
                    result.benign_patterns_blocked += 1

        # Compute per-type scores
        for attack_type, data in result.type_results.items():
            if data["sent"] > 0:
                data["score"] = data["blocked"] / data["sent"]

        # Compute overall scores
        result.compute_scores()

        logger.info(
            f"L7 verification complete: "
            f"detection={result.detection_score:.1%}, "
            f"blocking={result.blocking_score:.1%}, "
            f"FP_rate={result.false_positive_rate:.1%}, "
            f"overall={result.overall_score:.3f}"
        )

        return result


# Type alias for clarity
L7AuditSenderType = L7AuditSender


__all__ = [
    "L7AuditSender",
    "L7AuditChallenge",
    "L7AuditResult",
    "L7AttackPattern",
    "L7AttackType",
    "L7ExpectedAction",
]
