"""
Synthetic traffic generator for miner auditing.

Generates various types of attack and benign traffic to test
scrubber filtering capabilities during validator audits.

ANTI-GAMING DESIGN:
- Randomized attack/benign counts per round (±30-50% variance)
- Randomized attack type distribution (not fixed percentages)
- Dynamic blacklist IPs (generated per round, not hardcoded)
- All bogon ranges used (not just 3)
- Port diversity (80, 443, 8080, random high ports)
- Protocol diversity (TCP, UDP)
- Unique round identifiers for each test
"""

import hashlib
import random
import secrets
import socket
import struct
import time
import uuid
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from loguru import logger


class TrafficType(Enum):
    """Types of synthetic traffic."""
    BENIGN = "benign"
    SPOOFED_IP = "spoofed_ip"
    MALFORMED_PACKET = "malformed"
    BOGON_ADDRESS = "bogon"
    BLACKLIST_IP = "blacklist"
    SYN_FLOOD = "syn_flood"
    UDP_AMPLIFICATION = "udp_amp"


@dataclass
class SyntheticPacket:
    """Represents a synthetic packet for testing."""

    packet_type: TrafficType
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str  # TCP, UDP, ICMP
    payload: bytes = b""
    should_be_blocked: bool = True
    timestamp: float = field(default_factory=time.time)
    round_id: str = ""  # Unique identifier for this test round


@dataclass
class TrafficTestResult:
    """Results from a synthetic traffic test."""

    # Round identifier for this test
    round_id: str = ""

    total_sent: int = 0
    total_received: int = 0

    # Attack traffic
    attack_sent: int = 0
    attack_blocked: int = 0  # Expected to be blocked
    attack_passed: int = 0   # False negatives

    # Benign traffic
    benign_sent: int = 0
    benign_passed: int = 0  # Expected to pass
    benign_blocked: int = 0  # False positives

    # By attack type
    spoofed_sent: int = 0
    spoofed_blocked: int = 0

    malformed_sent: int = 0
    malformed_blocked: int = 0

    bogon_sent: int = 0
    bogon_blocked: int = 0

    blacklist_sent: int = 0
    blacklist_blocked: int = 0

    # Latency measurements
    rtt_samples: List[float] = field(default_factory=list)

    # Round configuration (for transparency)
    config: Dict[str, Any] = field(default_factory=dict)

    @property
    def avg_rtt_ms(self) -> float:
        """Average RTT in milliseconds."""
        if not self.rtt_samples:
            return 0.0
        return sum(self.rtt_samples) / len(self.rtt_samples)

    @property
    def min_rtt_ms(self) -> float:
        """Minimum RTT in milliseconds (baseline for distance normalization)."""
        if not self.rtt_samples:
            return 0.0
        return min(self.rtt_samples)

    @property
    def p95_rtt_ms(self) -> float:
        """P95 RTT in milliseconds."""
        if not self.rtt_samples:
            return 0.0
        sorted_samples = sorted(self.rtt_samples)
        idx = int(len(sorted_samples) * 0.95)
        return sorted_samples[idx]

    @property
    def p99_rtt_ms(self) -> float:
        """P99 RTT in milliseconds."""
        if not self.rtt_samples:
            return 0.0
        sorted_samples = sorted(self.rtt_samples)
        idx = int(len(sorted_samples) * 0.99)
        return sorted_samples[idx]

    @property
    def false_positive_rate(self) -> float:
        """Rate of benign traffic incorrectly blocked."""
        if self.benign_sent == 0:
            return 0.0
        return self.benign_blocked / self.benign_sent

    @property
    def false_negative_rate(self) -> float:
        """Rate of attack traffic incorrectly passed."""
        if self.attack_sent == 0:
            return 0.0
        return self.attack_passed / self.attack_sent

    @property
    def accuracy(self) -> float:
        """Overall accuracy (correct decisions / total)."""
        if self.total_sent == 0:
            return 0.0
        correct = self.attack_blocked + self.benign_passed
        return correct / self.total_sent


class SyntheticTrafficGenerator:
    """
    Generates synthetic traffic for scrubber auditing.

    Creates various types of legitimate and attack traffic to test
    whether miners correctly filter attacks while passing benign traffic.

    ANTI-GAMING FEATURES:
    - All counts and distributions randomized per round
    - Dynamic IP generation (no hardcoded lists)
    - Protocol and port diversity
    - Unique round identifiers
    """

    # All RFC bogon ranges (expanded from just 3)
    BOGON_RANGES = [
        ("0.0.0.0", 8),        # RFC5735 This Host
        ("10.0.0.0", 8),       # RFC1918 Private
        ("100.64.0.0", 10),    # RFC6598 Shared Address Space (CGNAT)
        ("127.0.0.0", 8),      # RFC5735 Loopback
        ("169.254.0.0", 16),   # RFC5735 Link Local
        ("172.16.0.0", 12),    # RFC1918 Private
        ("192.0.0.0", 24),     # RFC5735 IETF Protocol Assignments
        ("192.0.2.0", 24),     # RFC5737 Documentation (TEST-NET-1)
        ("192.168.0.0", 16),   # RFC1918 Private
        ("198.18.0.0", 15),    # RFC2544 Network Interconnect Device Benchmark
        ("198.51.100.0", 24),  # RFC5737 Documentation (TEST-NET-2)
        ("203.0.113.0", 24),   # RFC5737 Documentation (TEST-NET-3)
        ("224.0.0.0", 4),      # RFC5735 Multicast
        ("240.0.0.0", 4),      # RFC5735 Reserved
    ]

    # Known malicious AS/IP prefix ranges (for dynamic blacklist generation)
    # These are ranges known to host bulletproof hosting, botnets, etc.
    MALICIOUS_PREFIXES = [
        ("45.142.212.0", 22),   # Known botnet hosting
        ("185.220.100.0", 22),  # Tor exit nodes (often abused)
        ("89.248.160.0", 21),   # Aggressive scanning source
        ("194.165.16.0", 24),   # Known attack source
        ("45.155.204.0", 22),   # Bulletproof hosting
        ("193.32.160.0", 21),   # VPN/proxy abuse
        ("91.241.19.0", 24),    # Known spam source
        ("5.188.86.0", 23),     # Brute force attacks
        ("167.94.138.0", 23),   # Scanning activity
        ("80.82.77.0", 24),     # Known bad actor
    ]

    # Common target ports for diversity
    TARGET_PORTS = [80, 443, 8080, 8443, 3000, 3001, 8000, 8888]

    # Protocols to test
    PROTOCOLS = ["TCP", "UDP"]

    # Legitimate public IP ranges (diverse ASNs)
    LEGITIMATE_PREFIXES = [
        (1, "Level3/Lumen"),
        (8, "Verizon"),
        (13, "Xerox"),
        (15, "HP"),
        (16, "DEC"),
        (17, "Apple"),
        (18, "MIT"),
        (19, "Ford"),
        (20, "CSC"),
        (23, "DoD"),
        (32, "ATT"),
        (33, "DLA"),
        (34, "Halliburton"),
        (35, "MERIT"),
        (38, "PSINet"),
        (40, "Eli Lilly"),
        (44, "Amateur Radio"),
        (45, "Interop"),
        (47, "Bell Northern"),
        (48, "Prudential"),
        (52, "DuPont"),
        (54, "Merck"),
        (56, "USPS"),
        (57, "SITA"),
        (104, "Cloudflare"),
        (142, "UVA"),
        (143, "CMU"),
        (144, "DOE"),
        (146, "Xerox PARC"),
        (147, "Stanford"),
        (204, "Various ISPs"),
        (205, "Various ISPs"),
        (206, "Various ISPs"),
        (207, "Various ISPs"),
        (208, "Various ISPs"),
        (209, "Various ISPs"),
    ]

    def __init__(
        self,
        attack_count: int = 1000,
        benign_count: int = 200,
    ):
        """
        Initialize the traffic generator.

        Args:
            attack_count: BASE number of attack packets (actual will vary ±30-50%).
            benign_count: BASE number of benign packets (5:1 ratio, actual will vary).
        """
        self.base_attack_count = attack_count
        self.base_benign_count = benign_count

    def _generate_round_id(self) -> str:
        """Generate a unique round identifier."""
        return f"round-{uuid.uuid4().hex[:12]}-{int(time.time())}"

    def _randomize_counts(self) -> Tuple[int, int]:
        """
        Randomize attack and benign counts for this round.

        Returns:
            Tuple of (attack_count, benign_count) with ±30-50% variance.
        """
        # Random variance between 0.5 and 1.5 (±50%)
        attack_variance = random.uniform(0.5, 1.5)
        benign_variance = random.uniform(0.5, 1.5)

        attack_count = int(self.base_attack_count * attack_variance)
        benign_count = int(self.base_benign_count * benign_variance)

        # Ensure minimum counts
        attack_count = max(100, attack_count)
        benign_count = max(50, benign_count)

        return attack_count, benign_count

    def _randomize_attack_distribution(self, total_attacks: int) -> Dict[str, int]:
        """
        Randomize distribution of attack types.

        Instead of fixed 25% each, use random weights.

        Returns:
            Dict mapping attack type to count.
        """
        # Generate random weights for each attack type
        weights = {
            "spoofed": random.uniform(0.1, 0.4),
            "malformed": random.uniform(0.1, 0.4),
            "bogon": random.uniform(0.1, 0.4),
            "blacklist": random.uniform(0.1, 0.4),
        }

        # Normalize weights to sum to 1.0
        total_weight = sum(weights.values())
        for key in weights:
            weights[key] /= total_weight

        # Calculate counts
        distribution = {}
        remaining = total_attacks

        for i, (attack_type, weight) in enumerate(weights.items()):
            if i == len(weights) - 1:
                # Last type gets remaining to avoid rounding issues
                distribution[attack_type] = remaining
            else:
                count = int(total_attacks * weight)
                distribution[attack_type] = count
                remaining -= count

        return distribution

    def _generate_dynamic_blacklist_ip(self) -> str:
        """
        Generate a random IP from known malicious ranges.

        Creates unique IPs each round instead of reusing hardcoded list.
        """
        prefix, mask = random.choice(self.MALICIOUS_PREFIXES)

        # Parse prefix
        octets = [int(x) for x in prefix.split('.')]

        # Calculate how many bits we can randomize
        host_bits = 32 - mask

        # Generate random host portion
        if host_bits > 0:
            max_host = (1 << host_bits) - 1
            random_host = random.randint(1, max(1, max_host - 1))

            # Apply to octets
            base_ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
            network_mask = (0xFFFFFFFF << host_bits) & 0xFFFFFFFF
            final_ip = (base_ip & network_mask) | random_host

            return f"{(final_ip >> 24) & 0xFF}.{(final_ip >> 16) & 0xFF}.{(final_ip >> 8) & 0xFF}.{final_ip & 0xFF}"

        return prefix

    def _generate_bogon_ip(self) -> str:
        """
        Generate a random IP from ANY bogon range (not just 3).
        """
        prefix, mask = random.choice(self.BOGON_RANGES)

        # Parse prefix
        octets = [int(x) for x in prefix.split('.')]

        # Calculate how many bits we can randomize
        host_bits = 32 - mask

        # Generate random host portion
        if host_bits > 0:
            max_host = (1 << host_bits) - 1
            random_host = random.randint(1, max(1, max_host - 1))

            base_ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
            network_mask = (0xFFFFFFFF << host_bits) & 0xFFFFFFFF
            final_ip = (base_ip & network_mask) | random_host

            return f"{(final_ip >> 24) & 0xFF}.{(final_ip >> 16) & 0xFF}.{(final_ip >> 8) & 0xFF}.{final_ip & 0xFF}"

        return prefix

    def _generate_legitimate_ip(self) -> str:
        """
        Generate a random IP from legitimate public ranges.

        Uses diverse ASN prefixes for realism.
        """
        first_octet, _ = random.choice(self.LEGITIMATE_PREFIXES)
        return f"{first_octet}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def _select_random_port(self) -> int:
        """Select a random target port from common ports or high range."""
        if random.random() < 0.7:
            # 70% chance: common ports
            return random.choice(self.TARGET_PORTS)
        else:
            # 30% chance: random high port
            return random.randint(1024, 65535)

    def _select_random_protocol(self) -> str:
        """Select a random protocol (weighted towards TCP)."""
        if random.random() < 0.8:
            return "TCP"
        else:
            return "UDP"

    def generate_test_traffic(
        self,
        scrubber_ip: str,
        target_port: int = None,  # Now optional - will be randomized if not specified
    ) -> List[SyntheticPacket]:
        """
        Generate a full suite of test traffic with randomization.

        Args:
            scrubber_ip: Destination IP (scrubber to test).
            target_port: Destination port (optional, randomized if not specified).

        Returns:
            List of SyntheticPacket objects to send.
        """
        round_id = self._generate_round_id()

        # Randomize counts for this round
        attack_count, benign_count = self._randomize_counts()

        # Randomize attack distribution
        attack_distribution = self._randomize_attack_distribution(attack_count)

        packets = []

        # Generate spoofed IP attacks
        packets.extend(
            self._generate_spoofed_traffic(
                scrubber_ip,
                attack_distribution["spoofed"],
                round_id,
            )
        )

        # Generate malformed packets
        packets.extend(
            self._generate_malformed_traffic(
                scrubber_ip,
                attack_distribution["malformed"],
                round_id,
            )
        )

        # Generate bogon source addresses
        packets.extend(
            self._generate_bogon_traffic(
                scrubber_ip,
                attack_distribution["bogon"],
                round_id,
            )
        )

        # Generate blacklist IPs
        packets.extend(
            self._generate_blacklist_traffic(
                scrubber_ip,
                attack_distribution["blacklist"],
                round_id,
            )
        )

        # Generate benign traffic (should pass)
        packets.extend(
            self._generate_benign_traffic(
                scrubber_ip,
                benign_count,
                round_id,
            )
        )

        # Shuffle to randomize order
        random.shuffle(packets)

        logger.info(
            f"Generated {len(packets)} synthetic packets for round {round_id}: "
            f"{attack_count} attack (spoofed={attack_distribution['spoofed']}, "
            f"malformed={attack_distribution['malformed']}, "
            f"bogon={attack_distribution['bogon']}, "
            f"blacklist={attack_distribution['blacklist']}), "
            f"{benign_count} benign"
        )

        return packets

    def _generate_spoofed_traffic(
        self,
        dest_ip: str,
        count: int,
        round_id: str,
    ) -> List[SyntheticPacket]:
        """Generate traffic with spoofed source IPs."""
        packets = []

        for _ in range(count):
            # Random spoofed IP (non-routable or mismatched)
            source_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

            packet = SyntheticPacket(
                packet_type=TrafficType.SPOOFED_IP,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=self._select_random_port(),
                protocol=self._select_random_protocol(),
                should_be_blocked=True,
                round_id=round_id,
            )
            packets.append(packet)

        return packets

    def _generate_malformed_traffic(
        self,
        dest_ip: str,
        count: int,
        round_id: str,
    ) -> List[SyntheticPacket]:
        """Generate malformed packets with various corruptions."""
        packets = []

        malformation_types = [
            b"\xff\xff",                    # Invalid header
            b"\x00\x00\x00\x00",             # All zeros
            b"\xde\xad\xbe\xef",             # Classic bad data
            bytes([random.randint(0, 255) for _ in range(4)]),  # Random header
        ]

        for _ in range(count):
            # Use legitimate source but malformed payload
            source_ip = self._generate_legitimate_ip()

            # Create malformed payload (invalid TCP options, bad checksums, etc)
            malform_prefix = random.choice(malformation_types)
            malformed_payload = malform_prefix + bytes([random.randint(0, 255) for _ in range(random.randint(10, 50))])

            packet = SyntheticPacket(
                packet_type=TrafficType.MALFORMED_PACKET,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=self._select_random_port(),
                protocol=self._select_random_protocol(),
                payload=malformed_payload,
                should_be_blocked=True,
                round_id=round_id,
            )
            packets.append(packet)

        return packets

    def _generate_bogon_traffic(
        self,
        dest_ip: str,
        count: int,
        round_id: str,
    ) -> List[SyntheticPacket]:
        """Generate traffic from ALL bogon source addresses (not just 3)."""
        packets = []

        for _ in range(count):
            # Use dynamic bogon IP generation from all ranges
            source_ip = self._generate_bogon_ip()

            packet = SyntheticPacket(
                packet_type=TrafficType.BOGON_ADDRESS,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=self._select_random_port(),
                protocol=self._select_random_protocol(),
                should_be_blocked=True,
                round_id=round_id,
            )
            packets.append(packet)

        return packets

    def _generate_blacklist_traffic(
        self,
        dest_ip: str,
        count: int,
        round_id: str,
    ) -> List[SyntheticPacket]:
        """Generate traffic from dynamically generated blacklist IPs."""
        packets = []

        for _ in range(count):
            # Generate unique blacklist IP each time (not from hardcoded list!)
            source_ip = self._generate_dynamic_blacklist_ip()

            packet = SyntheticPacket(
                packet_type=TrafficType.BLACKLIST_IP,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=self._select_random_port(),
                protocol=self._select_random_protocol(),
                should_be_blocked=True,
                round_id=round_id,
            )
            packets.append(packet)

        return packets

    def _generate_benign_traffic(
        self,
        dest_ip: str,
        count: int,
        round_id: str,
    ) -> List[SyntheticPacket]:
        """Generate legitimate traffic (should pass)."""
        packets = []

        for _ in range(count):
            # Legitimate public IPs from diverse ASNs
            source_ip = self._generate_legitimate_ip()

            packet = SyntheticPacket(
                packet_type=TrafficType.BENIGN,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=self._select_random_port(),
                protocol=self._select_random_protocol(),
                should_be_blocked=False,  # Should pass
                round_id=round_id,
            )
            packets.append(packet)

        return packets

    async def run_test(
        self,
        scrubber_ip: str,
        target_port: int = 80,
        timeout: float = 60.0,
    ) -> TrafficTestResult:
        """
        Run a complete synthetic traffic test.

        Args:
            scrubber_ip: IP of scrubber to test.
            target_port: Port to target.
            timeout: Test timeout in seconds.

        Returns:
            TrafficTestResult with all metrics.
        """
        logger.info(f"Starting synthetic traffic test on port {target_port}")

        # Generate test packets (now with randomization)
        packets = self.generate_test_traffic(scrubber_ip, target_port)

        # Get round ID from first packet
        round_id = packets[0].round_id if packets else self._generate_round_id()

        result = TrafficTestResult()
        result.round_id = round_id
        result.total_sent = len(packets)

        # Store configuration for this round (transparency)
        attack_count = sum(1 for p in packets if p.should_be_blocked)
        benign_count = sum(1 for p in packets if not p.should_be_blocked)
        result.config = {
            "round_id": round_id,
            "attack_count": attack_count,
            "benign_count": benign_count,
            "timestamp": time.time(),
        }

        # Send packets and measure responses
        # NOTE: In production, this would use raw sockets or scapy
        # For now, we simulate the test with realistic metrics

        for packet in packets:
            # Simulate sending packet and checking response
            # In real implementation:
            # 1. Send packet via raw socket
            # 2. Listen for response or timeout
            # 3. Measure RTT
            # 4. Determine if blocked or passed

            # Simulated behavior (replace with actual implementation)
            was_blocked = self._simulate_packet_send(packet, scrubber_ip, target_port)
            rtt = random.uniform(10.0, 50.0)  # Simulated RTT

            result.rtt_samples.append(rtt)

            if packet.should_be_blocked:
                # Attack traffic
                result.attack_sent += 1

                if was_blocked:
                    result.attack_blocked += 1
                else:
                    result.attack_passed += 1  # False negative

                # Track by type
                if packet.packet_type == TrafficType.SPOOFED_IP:
                    result.spoofed_sent += 1
                    if was_blocked:
                        result.spoofed_blocked += 1

                elif packet.packet_type == TrafficType.MALFORMED_PACKET:
                    result.malformed_sent += 1
                    if was_blocked:
                        result.malformed_blocked += 1

                elif packet.packet_type == TrafficType.BOGON_ADDRESS:
                    result.bogon_sent += 1
                    if was_blocked:
                        result.bogon_blocked += 1

                elif packet.packet_type == TrafficType.BLACKLIST_IP:
                    result.blacklist_sent += 1
                    if was_blocked:
                        result.blacklist_blocked += 1

            else:
                # Benign traffic
                result.benign_sent += 1

                if not was_blocked:
                    result.benign_passed += 1
                    result.total_received += 1
                else:
                    result.benign_blocked += 1  # False positive

        logger.info(
            f"Synthetic test complete (round={round_id[:20]}...): accuracy={result.accuracy:.2%}, "
            f"FP={result.false_positive_rate:.2%}, FN={result.false_negative_rate:.2%}, "
            f"avg_rtt={result.avg_rtt_ms:.1f}ms"
        )

        return result

    def _simulate_packet_send(
        self,
        packet: SyntheticPacket,
        scrubber_ip: str,
        target_port: int
    ) -> bool:
        """
        Simulate sending a packet and determine if blocked.

        In production, this would:
        1. Craft raw packet with scapy
        2. Send via raw socket
        3. Wait for response or timeout
        4. Return True if blocked (timeout/RST), False if passed

        For now, we simulate realistic scrubber behavior.
        """
        # Simulate realistic scrubber filtering (95% accurate)
        if packet.should_be_blocked:
            # Attack traffic - should be blocked
            return random.random() < 0.95  # 95% block rate
        else:
            # Benign traffic - should pass (inverse check)
            return random.random() < 0.02  # 2% false positive rate
