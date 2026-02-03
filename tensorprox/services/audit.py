"""
Traffic-Based Audit System.

Generates and sends test traffic to scrubbers via WireGuard tunnel.
Miners report XDP stats which are used to compute accuracy scores.

Features:
- Randomized attack profiles - prevents optimization for known distributions
- Multiple attack categories for comprehensive coverage testing
- Graduated throughput testing for capacity measurement

NON-GAMEABILITY PRINCIPLES:
==========================
This audit system is designed to be impossible to game. Key principles:

1. NO PREDICTABLE MARKERS: Payloads contain random data, not identifiable headers.
   A scrubber cannot distinguish audit traffic from real traffic by content.

2. RANDOMIZED DISTRIBUTIONS: Pool sizes, packet counts, timing - all have entropy.
   Each audit is statistically unique.

3. PATTERN-BASED DETECTION ONLY: The scrubber must detect attacks by BEHAVIOR
   (rate, protocol violations, source patterns) not by recognizing test traffic.

4. COMPETITIVE DIFFERENTIATION: Scoring rewards accuracy, speed, and edge-case
   handling. Different miners can excel in different areas.

5. PER-AUDIT ENTROPY: Each audit uses fresh random seeds, IPs, and distributions.
   Historical patterns don't help predict future audits.
"""

import asyncio
import hashlib
import secrets
import time
import random
import string
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import List, Dict, Any, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor

from loguru import logger

# Import audit configuration for realistic traffic patterns and non-gameability
from tensorprox.config.audit_config import (
    ATTACK_SOURCE_POOL_SIZE,
    ATTACK_MIN_PACKETS_PER_SOURCE,
    RATE_LIMITED_CATEGORIES,
    BENIGN_DISTRIBUTED_SOURCES,
    # Randomization ranges for non-gameability
    ATTACK_POOL_SIZE_MIN,
    ATTACK_POOL_SIZE_MAX,
    PACKET_COUNT_JITTER_MIN,
    PACKET_COUNT_JITTER_MAX,
    PROFILE_PERTURBATION_MIN,
    PROFILE_PERTURBATION_MAX,
)

# Try to import scapy
try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, send, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - crypto audit disabled")


class AttackCategory(Enum):
    """Attack categories for audit scoring."""
    # Deterministically detectable by XDP (guaranteed block)
    BOGON = "bogon"
    BLACKLIST = "blacklist"
    TCP_FLAG_ANOMALY = "tcp_flag_anomaly"  # XMAS, NULL, SYN+FIN, SYN+RST
    UDP_AMPLIFICATION = "udp_amplification"
    FRAGMENTATION = "fragmentation"
    MALFORMED = "malformed"
    LAND_ATTACK = "land_attack"  # Source IP == Destination IP

    # Rate-limited (probabilistic block)
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    ICMP_FLOOD = "icmp_flood"

    # Previously undetectable, now detected via connection patterns to HTTP ports
    SPOOFED_PUBLIC = "spoofed_public"  # Valid public IPs - still undetectable
    L7_APPLICATION = "l7_application"  # Slowloris (SYN flood to HTTP), HTTP flood (PSH+ACK to HTTP)

    # Benign traffic (must pass)
    BENIGN = "benign"


class ExpectedAction(IntEnum):
    """Expected XDP action for a packet."""
    MUST_BLOCK = 0      # Deterministic block (bogon, blacklist, etc.)
    SHOULD_BLOCK = 1    # Probabilistic block (rate-limited)
    MUST_PASS = 2       # Must pass (benign)
    MAY_PASS = 3        # Acceptable to pass (undetectable attacks)


@dataclass
class AttackProfile:
    """
    Randomized attack distribution profile.

    Each audit uses a randomly selected and perturbed profile
    to prevent miners from optimizing for known distributions.
    """
    name: str
    weights: Dict[AttackCategory, float]
    description: str

    def perturb(self, noise_factor: float = 0.3) -> 'AttackProfile':
        """Add random noise to weights."""
        perturbed = {}
        for cat, weight in self.weights.items():
            noise = random.uniform(1 - noise_factor, 1 + noise_factor)
            perturbed[cat] = weight * noise

        # Normalize
        total = sum(perturbed.values())
        perturbed = {k: v / total for k, v in perturbed.items()}

        return AttackProfile(
            name=f"{self.name}_perturbed",
            weights=perturbed,
            description=f"Perturbed {self.name}"
        )


# Pre-defined attack profiles (randomly selected per audit)
ATTACK_PROFILES = [
    AttackProfile(
        name="balanced",
        weights={
            AttackCategory.BOGON: 0.08,
            AttackCategory.BLACKLIST: 0.08,
            AttackCategory.TCP_FLAG_ANOMALY: 0.14,
            AttackCategory.UDP_AMPLIFICATION: 0.12,
            AttackCategory.FRAGMENTATION: 0.05,
            AttackCategory.MALFORMED: 0.05,
            AttackCategory.LAND_ATTACK: 0.02,
            AttackCategory.SYN_FLOOD: 0.14,
            AttackCategory.UDP_FLOOD: 0.10,
            AttackCategory.ICMP_FLOOD: 0.07,
            AttackCategory.SPOOFED_PUBLIC: 0.05,
            AttackCategory.L7_APPLICATION: 0.05,
            AttackCategory.BENIGN: 0.05,
        },
        description="Balanced attack distribution"
    ),
    AttackProfile(
        name="syn_flood_heavy",
        weights={
            AttackCategory.BOGON: 0.03,
            AttackCategory.BLACKLIST: 0.03,
            AttackCategory.TCP_FLAG_ANOMALY: 0.10,
            AttackCategory.UDP_AMPLIFICATION: 0.05,
            AttackCategory.FRAGMENTATION: 0.02,
            AttackCategory.MALFORMED: 0.02,
            AttackCategory.LAND_ATTACK: 0.02,
            AttackCategory.SYN_FLOOD: 0.43,
            AttackCategory.UDP_FLOOD: 0.05,
            AttackCategory.ICMP_FLOOD: 0.05,
            AttackCategory.SPOOFED_PUBLIC: 0.10,
            AttackCategory.L7_APPLICATION: 0.05,
            AttackCategory.BENIGN: 0.05,
        },
        description="Heavy SYN flood focus"
    ),
    AttackProfile(
        name="amplification_heavy",
        weights={
            AttackCategory.BOGON: 0.03,
            AttackCategory.BLACKLIST: 0.03,
            AttackCategory.TCP_FLAG_ANOMALY: 0.05,
            AttackCategory.UDP_AMPLIFICATION: 0.38,
            AttackCategory.FRAGMENTATION: 0.05,
            AttackCategory.MALFORMED: 0.02,
            AttackCategory.LAND_ATTACK: 0.02,
            AttackCategory.SYN_FLOOD: 0.10,
            AttackCategory.UDP_FLOOD: 0.15,
            AttackCategory.ICMP_FLOOD: 0.02,
            AttackCategory.SPOOFED_PUBLIC: 0.05,
            AttackCategory.L7_APPLICATION: 0.05,
            AttackCategory.BENIGN: 0.05,
        },
        description="Heavy amplification attack focus"
    ),
    AttackProfile(
        name="flag_anomaly_heavy",
        weights={
            AttackCategory.BOGON: 0.05,
            AttackCategory.BLACKLIST: 0.05,
            AttackCategory.TCP_FLAG_ANOMALY: 0.38,
            AttackCategory.UDP_AMPLIFICATION: 0.08,
            AttackCategory.FRAGMENTATION: 0.08,
            AttackCategory.MALFORMED: 0.08,
            AttackCategory.LAND_ATTACK: 0.02,
            AttackCategory.SYN_FLOOD: 0.08,
            AttackCategory.UDP_FLOOD: 0.03,
            AttackCategory.ICMP_FLOOD: 0.03,
            AttackCategory.SPOOFED_PUBLIC: 0.05,
            AttackCategory.L7_APPLICATION: 0.02,
            AttackCategory.BENIGN: 0.05,
        },
        description="Heavy TCP flag anomaly focus"
    ),
    AttackProfile(
        name="edge_case_heavy",
        weights={
            AttackCategory.BOGON: 0.10,
            AttackCategory.BLACKLIST: 0.10,
            AttackCategory.TCP_FLAG_ANOMALY: 0.10,
            AttackCategory.UDP_AMPLIFICATION: 0.05,
            AttackCategory.FRAGMENTATION: 0.18,
            AttackCategory.MALFORMED: 0.18,
            AttackCategory.LAND_ATTACK: 0.04,
            AttackCategory.SYN_FLOOD: 0.05,
            AttackCategory.UDP_FLOOD: 0.03,
            AttackCategory.ICMP_FLOOD: 0.02,
            AttackCategory.SPOOFED_PUBLIC: 0.05,
            AttackCategory.L7_APPLICATION: 0.05,
            AttackCategory.BENIGN: 0.05,
        },
        description="Heavy edge case focus (fragmentation, malformed, land attack)"
    ),
    AttackProfile(
        name="benign_heavy",
        weights={
            AttackCategory.BOGON: 0.05,
            AttackCategory.BLACKLIST: 0.05,
            AttackCategory.TCP_FLAG_ANOMALY: 0.07,
            AttackCategory.UDP_AMPLIFICATION: 0.07,
            AttackCategory.FRAGMENTATION: 0.03,
            AttackCategory.MALFORMED: 0.03,
            AttackCategory.LAND_ATTACK: 0.02,
            AttackCategory.SYN_FLOOD: 0.08,
            AttackCategory.UDP_FLOOD: 0.05,
            AttackCategory.ICMP_FLOOD: 0.03,
            AttackCategory.SPOOFED_PUBLIC: 0.07,
            AttackCategory.L7_APPLICATION: 0.05,
            AttackCategory.BENIGN: 0.40,  # Heavy benign for FP testing
        },
        description="Heavy benign traffic for false positive testing"
    ),
]


@dataclass
class AuditPacket:
    """
    Single packet in an audit.

    Each packet contains:
    - Unique sequence number for tracking
    - Expected XDP action
    - Attack category for scoring
    """
    seq_num: int
    category: AttackCategory
    expected_action: ExpectedAction

    # Packet specification
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str  # TCP, UDP, ICMP
    tcp_flags: str = ""
    payload: bytes = b""

    # For fragmented packets
    ip_flags: str = ""
    ip_frag_offset: int = 0
    is_malformed: bool = False


@dataclass
class AuditChallenge:
    """
    Audit challenge containing packets and ground truth.
    """
    # Challenge identification
    challenge_id: str
    challenge_nonce: str

    # Attack profile used
    profile_name: str

    # Packets sent (ground truth for scoring)
    packets: List[AuditPacket] = field(default_factory=list)

    # Throughput level
    throughput_level: int = 0  # 0=light, 1=normal, 2=heavy, 3=stress

    # Timing
    start_time: float = 0.0
    end_time: float = 0.0

    def get_packet_by_seq(self, seq_num: int) -> Optional[AuditPacket]:
        """Find packet by sequence number."""
        for p in self.packets:
            if p.seq_num == seq_num:
                return p
        return None


@dataclass
class AuditResult:
    """
    Verified audit result with cryptographic proofs.

    This replaces self-reported stats with verified data.
    """
    challenge_id: str

    # Verification results
    total_packets_sent: int = 0
    packets_verified: int = 0  # Miner proved they saw these
    packets_unverified: int = 0  # Miner didn't prove

    # Correctness by category
    category_results: Dict[str, Dict[str, int]] = field(default_factory=dict)
    # Format: {category: {sent: N, correct: N, incorrect: N}}

    # Expected vs actual actions
    correct_blocks: int = 0  # Correctly blocked attacks
    correct_passes: int = 0  # Correctly passed benign
    false_positives: int = 0  # Incorrectly blocked benign
    false_negatives: int = 0  # Incorrectly passed attacks
    missed_rate_limited: int = 0  # Rate-limited attacks that passed (acceptable)

    # Throughput metrics
    throughput_level: int = 0
    packets_per_second: float = 0.0

    # Computed scores
    accuracy_score: float = 0.0  # Weighted correctness
    false_positive_rate: float = 0.0

    # Per-category coverage
    category_coverage: Dict[str, float] = field(default_factory=dict)

    def compute_scores(self):
        """Compute final scores from verification results."""
        # Accuracy = correct actions / verified packets
        total_verified_actions = (
            self.correct_blocks + self.correct_passes +
            self.false_positives + self.false_negatives +
            self.missed_rate_limited
        )

        if total_verified_actions > 0:
            # Correct = blocks + passes + acceptable misses (rate-limited)
            correct = self.correct_blocks + self.correct_passes + self.missed_rate_limited
            self.accuracy_score = correct / total_verified_actions

        # FP rate
        total_benign = self.correct_passes + self.false_positives
        if total_benign > 0:
            self.false_positive_rate = self.false_positives / total_benign

        # Per-category coverage
        for cat_name, results in self.category_results.items():
            sent = results.get("sent", 0)
            correct = results.get("correct", 0)
            if sent > 0:
                self.category_coverage[cat_name] = correct / sent


class AuditSender:
    """
    Cryptographic audit traffic sender.

    Generates and sends audit traffic with HMAC-based verification.
    """

    # Throughput levels: (attack_count, benign_count) - 5:1 ratio
    THROUGHPUT_LEVELS = [
        (100, 20),      # Level 0: Light
        (500, 100),     # Level 1: Normal
        (2000, 400),    # Level 2: Heavy
        (5000, 1000),   # Level 3: Stress
    ]

    # Bogon ranges (RFC 1918 + reserved)
    BOGON_RANGES = [
        ("0.0.0.0", 8),
        ("10.0.0.0", 8),
        ("100.64.0.0", 10),
        ("127.0.0.0", 8),
        ("169.254.0.0", 16),
        ("172.16.0.0", 12),
        ("192.0.0.0", 24),
        ("192.0.2.0", 24),
        ("192.168.0.0", 16),
        ("198.18.0.0", 15),
        ("198.51.100.0", 24),
        ("203.0.113.0", 24),
        ("224.0.0.0", 4),
        ("240.0.0.0", 4),
    ]

    # Known malicious prefixes (for blacklist testing)
    MALICIOUS_PREFIXES = [
        ("45.142.212.0", 22),
        ("185.220.100.0", 22),
        ("89.248.160.0", 21),
        ("194.165.16.0", 24),
        ("45.155.204.0", 22),
    ]

    # Legitimate prefixes for benign/spoofed traffic
    LEGITIMATE_PREFIXES = [
        1, 8, 13, 15, 16, 17, 18, 19, 20, 23,
        32, 33, 34, 35, 38, 40, 44, 45, 47, 48,
    ]

    # Target ports - HTTP ports for L7 detection (Slowloris, HTTP flood)
    TARGET_PORTS = [80, 443, 8080, 8443, 3000, 8000]
    HTTP_PORTS = TARGET_PORTS  # Alias for clarity

    # Non-HTTP ports for general SYN flood detection (not L7)
    # These are common service ports that are NOT HTTP
    NON_HTTP_PORTS = [22, 25, 110, 143, 993, 995, 3306, 5432, 6379, 27017, 11211]

    # UDP amplification ports (must match xdp_wan.c and xdp_wg_audit.c)
    AMP_PORTS = {
        "dns": 53,
        "ntp": 123,
        "memcached": 11211,
        "ssdp": 1900,
        "snmp": 161,
        "chargen": 19,
        "mdns": 5353,  # mDNS - blocked by both production and audit XDP
    }

    # Randomization ranges loaded from config for non-gameability
    # These can be tuned via environment variables

    # Realistic user agents for HTTP traffic (randomized)
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/109.0",
        "curl/7.88.1", "python-requests/2.28.1", "Go-http-client/1.1",
        "axios/1.3.4", "okhttp/4.10.0", "Apache-HttpClient/4.5.13",
    ]

    # Realistic HTTP paths (randomized)
    HTTP_PATHS = [
        "/", "/api/v1/users", "/login", "/search", "/api/data", "/health",
        "/static/js/main.js", "/assets/logo.png", "/favicon.ico",
        "/api/v2/products", "/checkout", "/cart", "/profile", "/settings",
        "/api/auth/token", "/graphql", "/.well-known/security.txt",
    ]

    # Realistic hostnames (randomized)
    HTTP_HOSTS = [
        "api.example.com", "www.example.org", "cdn.example.net",
        "app.service.io", "portal.company.com", "store.shop.com",
    ]

    def __init__(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy required for audit")
        conf.verb = 0

        # Per-audit random state for reproducibility within audit but unpredictability between audits
        self._audit_seed: int = 0
        self._audit_rng: random.Random = random.Random()

        # Attack IP pool for concentrated rate-limited traffic
        # This simulates real DDoS patterns where few sources send many packets
        self._attack_ip_pool: List[str] = []
        self._attack_ip_weights: List[float] = []  # Non-uniform distribution

    def _initialize_audit_entropy(self) -> None:
        """
        Initialize per-audit random state.

        Each audit gets a fresh cryptographic seed, making patterns
        unpredictable between audits while reproducible within one audit.
        """
        self._audit_seed = secrets.randbits(64)
        self._audit_rng = random.Random(self._audit_seed)
        logger.debug(f"Audit entropy initialized: seed={self._audit_seed:016x}")

    def _initialize_attack_ip_pool(self, total_rate_limited_packets: int) -> None:
        """
        Initialize the attack IP pool for concentrated traffic patterns.

        NON-GAMEABILITY:
        - Pool size is randomized (not fixed)
        - IP distribution is non-uniform (some IPs get more traffic)
        - Simulates real botnet behavior where some bots are more active

        Args:
            total_rate_limited_packets: Total packets for rate-limited categories
        """
        # RANDOMIZED pool size - prevents detection by counting unique sources
        base_pool_size = self._audit_rng.randint(
            ATTACK_POOL_SIZE_MIN,
            ATTACK_POOL_SIZE_MAX
        )

        # Adjust pool size if needed to ensure minimum packets per source
        pool_size = base_pool_size
        if total_rate_limited_packets > 0:
            packets_per_source = total_rate_limited_packets / pool_size
            if packets_per_source < ATTACK_MIN_PACKETS_PER_SOURCE:
                # Reduce pool size to concentrate traffic more
                pool_size = max(3, total_rate_limited_packets // ATTACK_MIN_PACKETS_PER_SOURCE)

        # Generate the attack IP pool with RANDOM public IPs
        self._attack_ip_pool = [
            self._generate_spoofed_public_ip() for _ in range(pool_size)
        ]

        # NON-UNIFORM distribution - some IPs are "hotter" than others
        # This mimics real botnets where some bots have more bandwidth
        raw_weights = [self._audit_rng.paretovariate(1.5) for _ in range(pool_size)]
        total_weight = sum(raw_weights)
        self._attack_ip_weights = [w / total_weight for w in raw_weights]

        logger.debug(
            f"Attack IP pool: {pool_size} IPs (range {ATTACK_POOL_SIZE_MIN}-{ATTACK_POOL_SIZE_MAX}), "
            f"{total_rate_limited_packets} packets, non-uniform distribution"
        )

    def _get_attack_source_ip(self) -> str:
        """
        Get a source IP from the attack pool using WEIGHTED random selection.

        NON-GAMEABILITY:
        - Not round-robin (would be detectable)
        - Weighted selection mimics real botnet traffic patterns
        - Some IPs appear much more frequently than others
        """
        if not self._attack_ip_pool:
            return self._generate_spoofed_public_ip()

        # Weighted random choice - some IPs are "hotter"
        return self._audit_rng.choices(
            self._attack_ip_pool,
            weights=self._attack_ip_weights,
            k=1
        )[0]

    def _generate_random_payload(self, min_size: int = 16, max_size: int = 256) -> bytes:
        """
        Generate random payload data that looks like real traffic.

        NON-GAMEABILITY:
        - No identifiable markers or patterns
        - Variable length with realistic distribution
        - Mix of printable and binary data
        """
        size = self._audit_rng.randint(min_size, max_size)

        # Mix of patterns that look like real data
        pattern_type = self._audit_rng.randint(0, 3)

        if pattern_type == 0:
            # Random binary
            return bytes(self._audit_rng.randint(0, 255) for _ in range(size))
        elif pattern_type == 1:
            # Random printable ASCII
            return ''.join(self._audit_rng.choices(string.printable[:62], k=size)).encode()
        elif pattern_type == 2:
            # JSON-like structure
            keys = ['id', 'name', 'value', 'data', 'token', 'ts']
            data = {self._audit_rng.choice(keys): self._audit_rng.randint(1, 99999) for _ in range(3)}
            return str(data).encode()[:size]
        else:
            # URL-encoded params
            params = [f"p{i}={self._audit_rng.randint(1,999)}" for i in range(self._audit_rng.randint(2,5))]
            return '&'.join(params).encode()[:size]

    def _select_profile(self) -> AttackProfile:
        """Randomly select and perturb an attack profile."""
        base_profile = secrets.choice(ATTACK_PROFILES)
        return base_profile.perturb(noise_factor=0.3)

    def _ip_from_prefix(self, prefix: str, mask: int) -> str:
        """Generate random IP from CIDR prefix."""
        octets = [int(x) for x in prefix.split('.')]
        host_bits = 32 - mask

        if host_bits > 0:
            max_host = (1 << host_bits) - 1
            random_host = random.randint(1, max(1, max_host - 1))

            base = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
            net_mask = (0xFFFFFFFF << host_bits) & 0xFFFFFFFF
            final = (base & net_mask) | random_host

            return f"{(final >> 24) & 0xFF}.{(final >> 16) & 0xFF}.{(final >> 8) & 0xFF}.{final & 0xFF}"

        return prefix

    def _generate_bogon_ip(self) -> str:
        prefix, mask = random.choice(self.BOGON_RANGES)
        return self._ip_from_prefix(prefix, mask)

    def _generate_blacklist_ip(self) -> str:
        prefix, mask = random.choice(self.MALICIOUS_PREFIXES)
        return self._ip_from_prefix(prefix, mask)

    def _generate_legitimate_ip(self) -> str:
        first = random.choice(self.LEGITIMATE_PREFIXES)
        return f"{first}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def _generate_spoofed_public_ip(self) -> str:
        """Generate random public IP (not bogon, not blacklisted)."""
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _generate_packets_for_category(
        self,
        category: AttackCategory,
        count: int,
        dest_ip: str,
        start_seq: int,
    ) -> List[AuditPacket]:
        """Generate packets for a specific attack category."""
        packets = []

        for i in range(count):
            seq_num = start_seq + i

            if category == AttackCategory.BOGON:
                pkt = AuditPacket(
                    seq_num=seq_num,
                    category=category,
                    expected_action=ExpectedAction.MUST_BLOCK,
                    source_ip=self._generate_bogon_ip(),
                    dest_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    dest_port=random.choice(self.TARGET_PORTS),
                    protocol=random.choice(["TCP", "UDP"]),
                    tcp_flags="S" if random.random() > 0.5 else "",
                )

            elif category == AttackCategory.BLACKLIST:
                pkt = AuditPacket(
                    seq_num=seq_num,
                    category=category,
                    expected_action=ExpectedAction.MUST_BLOCK,
                    source_ip=self._generate_blacklist_ip(),
                    dest_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    dest_port=random.choice(self.TARGET_PORTS),
                    protocol=random.choice(["TCP", "UDP"]),
                    tcp_flags="S" if random.random() > 0.5 else "",
                )

            elif category == AttackCategory.TCP_FLAG_ANOMALY:
                # Randomly pick an anomaly type
                anomaly_type = random.choice(["xmas", "null", "synfin", "synrst", "fin", "rst", "ack"])
                flag_map = {
                    "xmas": "FSRPAUEC",
                    "null": "",
                    "synfin": "SF",
                    "synrst": "SR",
                    "fin": "F",
                    "rst": "R",
                    "ack": "A",
                }
                pkt = AuditPacket(
                    seq_num=seq_num,
                    category=category,
                    expected_action=ExpectedAction.MUST_BLOCK,
                    source_ip=self._generate_spoofed_public_ip(),
                    dest_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    dest_port=random.choice(self.TARGET_PORTS),
                    protocol="TCP",
                    tcp_flags=flag_map[anomaly_type],
                )

            elif category == AttackCategory.UDP_AMPLIFICATION:
                amp_type = random.choice(list(self.AMP_PORTS.keys()))
                pkt = AuditPacket(
                    seq_num=seq_num,
                    category=category,
                    expected_action=ExpectedAction.MUST_BLOCK,
                    source_ip=self._generate_spoofed_public_ip(),
                    dest_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    dest_port=self.AMP_PORTS[amp_type],
                    protocol="UDP",
                    payload=self._generate_amp_payload(amp_type),
                )

            elif category == AttackCategory.FRAGMENTATION:
                frag_type = random.choice(["overlap", "tiny"])
                if frag_type == "overlap":
                    pkt = AuditPacket(
                        seq_num=seq_num,
                            category=category,
                        expected_action=ExpectedAction.MUST_BLOCK,
                        source_ip=self._generate_spoofed_public_ip(),
                        dest_ip=dest_ip,
                        source_port=0,
                        dest_port=0,
                        protocol="UDP",
                        ip_frag_offset=10,
                        payload=bytes([random.randint(0, 255) for _ in range(100)]),
                    )
                else:  # tiny
                    pkt = AuditPacket(
                        seq_num=seq_num,
                            category=category,
                        expected_action=ExpectedAction.MUST_BLOCK,
                        source_ip=self._generate_spoofed_public_ip(),
                        dest_ip=dest_ip,
                        source_port=random.randint(1024, 65535),
                        dest_port=random.choice(self.TARGET_PORTS),
                        protocol="UDP",
                        ip_flags="MF",
                        payload=bytes([0x41] * 8),
                    )

            elif category == AttackCategory.MALFORMED:
                pkt = AuditPacket(
                    seq_num=seq_num,
                    category=category,
                    expected_action=ExpectedAction.MUST_BLOCK,
                    source_ip=self._generate_legitimate_ip(),
                    dest_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    dest_port=random.choice(self.TARGET_PORTS),
                    protocol=random.choice(["TCP", "UDP"]),
                    is_malformed=True,
                    payload=bytes([random.randint(0, 255) for _ in range(50)]),
                )

            elif category == AttackCategory.LAND_ATTACK:
                # Land attack: source IP == destination IP
                # This is an invalid packet that XDP should always block
                pkt = AuditPacket(
                    seq_num=seq_num,
                    category=category,
                    expected_action=ExpectedAction.MUST_BLOCK,
                    source_ip=dest_ip,  # Source IP == Destination IP (Land attack)
                    dest_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    dest_port=random.choice(self.TARGET_PORTS),
                    protocol=random.choice(["TCP", "UDP"]),
                    tcp_flags="S" if random.random() > 0.5 else "PA",
                    payload=bytes([random.randint(0, 255) for _ in range(random.randint(32, 128))]),
                )

            elif category == AttackCategory.SYN_FLOOD:
                # Use NON-HTTP ports for general SYN flood detection
                # HTTP port SYNs are detected as Slowloris (L7_APPLICATION)
                # Use CONCENTRATED source IPs from attack pool to trigger rate limiting
                pkt = AuditPacket(
                    seq_num=seq_num,
                    category=category,
                    expected_action=ExpectedAction.SHOULD_BLOCK,  # Rate-limited
                    source_ip=self._get_attack_source_ip(),  # Concentrated pattern
                    dest_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    dest_port=random.choice(self.NON_HTTP_PORTS),
                    protocol="TCP",
                    tcp_flags="S",
                )

            elif category == AttackCategory.UDP_FLOOD:
                # Use CONCENTRATED source IPs from attack pool to trigger rate limiting
                pkt = AuditPacket(
                    seq_num=seq_num,
                    category=category,
                    expected_action=ExpectedAction.SHOULD_BLOCK,
                    source_ip=self._get_attack_source_ip(),  # Concentrated pattern
                    dest_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    dest_port=random.randint(10000, 60000),  # Non-amp ports
                    protocol="UDP",
                    payload=bytes([random.randint(0, 255) for _ in range(random.randint(64, 512))]),
                )

            elif category == AttackCategory.ICMP_FLOOD:
                # Use CONCENTRATED source IPs from attack pool to trigger rate limiting
                pkt = AuditPacket(
                    seq_num=seq_num,
                    category=category,
                    expected_action=ExpectedAction.SHOULD_BLOCK,
                    source_ip=self._get_attack_source_ip(),  # Concentrated pattern
                    dest_ip=dest_ip,
                    source_port=0,
                    dest_port=0,
                    protocol="ICMP",
                    payload=bytes([random.randint(0, 255) for _ in range(random.randint(64, 1200))]),
                )

            elif category == AttackCategory.SPOOFED_PUBLIC:
                # Valid public IPs that pass bogon/blacklist - XDP cannot detect
                pkt = AuditPacket(
                    seq_num=seq_num,
                    category=category,
                    expected_action=ExpectedAction.MAY_PASS,  # XDP can't detect
                    source_ip=self._generate_spoofed_public_ip(),
                    dest_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    dest_port=random.choice(self.TARGET_PORTS),
                    protocol=random.choice(["TCP", "UDP"]),
                    tcp_flags="S" if random.random() > 0.5 else "",
                )

            elif category == AttackCategory.L7_APPLICATION:
                # L7 attacks: XDP can now detect these by connection patterns to HTTP ports:
                # - HTTP Flood: High rate of PSH+ACK packets (data requests)
                # - Slowloris: High rate of SYN packets (connection attempts)
                # Use CONCENTRATED source IPs from attack pool to trigger rate limiting
                # Randomly choose between HTTP flood (PSH+ACK) and Slowloris (SYN) patterns
                if random.random() < 0.5:
                    # HTTP Flood pattern: PSH+ACK to HTTP ports
                    pkt = AuditPacket(
                        seq_num=seq_num,
                        category=category,
                        expected_action=ExpectedAction.SHOULD_BLOCK,  # XDP detects via rate limiting
                        source_ip=self._get_attack_source_ip(),  # Concentrated pattern
                        dest_ip=dest_ip,
                        source_port=random.randint(1024, 65535),
                        dest_port=random.choice([80, 443, 8080, 8000, 3000, 8443]),
                        protocol="TCP",
                        tcp_flags="PA",  # PSH+ACK = data packet (HTTP request)
                        payload=self._generate_http_payload(),
                    )
                else:
                    # Slowloris pattern: SYN to HTTP ports (connection exhaustion)
                    pkt = AuditPacket(
                        seq_num=seq_num,
                        category=category,
                        expected_action=ExpectedAction.SHOULD_BLOCK,  # XDP detects via rate limiting
                        source_ip=self._get_attack_source_ip(),  # Concentrated pattern
                        dest_ip=dest_ip,
                        source_port=random.randint(1024, 65535),
                        dest_port=random.choice([80, 443, 8080, 8000, 3000, 8443]),
                        protocol="TCP",
                        tcp_flags="S",  # SYN = connection attempt
                        payload=b"",  # No payload for SYN
                    )

            elif category == AttackCategory.BENIGN:
                # Legitimate traffic that MUST pass
                # CRITICAL: Use DISTRIBUTED source IPs (unique per packet)
                # This simulates real user traffic: many sources, few packets each
                # Each benign packet uses a unique IP → stays below per-source rate limits
                if random.random() < 0.2:
                    # Benign ICMP
                    pkt = AuditPacket(
                        seq_num=seq_num,
                        category=category,
                        expected_action=ExpectedAction.MUST_PASS,
                        source_ip=self._generate_legitimate_ip(),  # Unique IP per packet
                        dest_ip=dest_ip,
                        source_port=0,
                        dest_port=0,
                        protocol="ICMP",
                        payload=bytes([random.randint(0, 255) for _ in range(random.randint(64, 128))]),
                    )
                else:
                    # Benign TCP/UDP
                    pkt = AuditPacket(
                        seq_num=seq_num,
                        category=category,
                        expected_action=ExpectedAction.MUST_PASS,
                        source_ip=self._generate_legitimate_ip(),  # Unique IP per packet
                        dest_ip=dest_ip,
                        source_port=random.randint(1024, 65535),
                        dest_port=random.choice(self.TARGET_PORTS),
                        protocol=random.choice(["TCP", "UDP"]),
                        tcp_flags="S" if random.random() > 0.5 else "PA",
                    )
            else:
                continue

            packets.append(pkt)

        return packets

    def _generate_amp_payload(self, amp_type: str) -> bytes:
        """
        Generate amplification attack payload with variability.

        These payloads must contain the protocol signatures that XDP detects,
        but we add randomization in non-critical fields to prevent fingerprinting.
        """
        if amp_type == "dns":
            # DNS query - vary the query ID and domain
            query_id = self._audit_rng.randint(0, 65535).to_bytes(2, 'big')
            domains = [b'\x07example\x03com', b'\x06google\x03com', b'\x05yahoo\x03com',
                      b'\x09microsoft\x03com', b'\x06amazon\x03com']
            domain = self._audit_rng.choice(domains)
            # Query types that trigger amp detection: ANY(255), TXT(16), AXFR(252)
            qtype = self._audit_rng.choice([b'\x00\xff', b'\x00\x10', b'\x00\xfc'])
            return query_id + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + domain + b'\x00' + qtype + b'\x00\x01'
        elif amp_type == "ntp":
            # NTP monlist - header identifies the attack
            padding = bytes(self._audit_rng.randint(0, 255) for _ in range(self._audit_rng.randint(4, 12)))
            return b'\x17\x00\x03\x2a' + padding
        elif amp_type == "memcached":
            # Memcached - vary the command
            cmds = [b'stats\r\n', b'stats items\r\n', b'get *\r\n', b'version\r\n']
            cmd = self._audit_rng.choice(cmds)
            return b'\x00\x01\x00\x00\x00\x01\x00\x00' + cmd
        elif amp_type == "ssdp":
            # SSDP - vary the search target
            targets = ['ssdp:all', 'upnp:rootdevice', 'urn:schemas-upnp-org:device:MediaServer:1']
            st = self._audit_rng.choice(targets)
            mx = self._audit_rng.randint(1, 5)
            return f'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: {mx}\r\nST: {st}\r\n\r\n'.encode()
        elif amp_type == "snmp":
            # SNMP - vary community string length slightly
            community = self._audit_rng.choice([b'public', b'private', b'admin'])
            comm_len = len(community)
            return bytes([0x30, 0x20 + comm_len, 0x02, 0x01, 0x01, 0x04, comm_len]) + community
        elif amp_type == "chargen":
            # Chargen - vary the trigger data
            size = self._audit_rng.randint(32, 128)
            return bytes(self._audit_rng.randint(32, 126) for _ in range(size))
        elif amp_type == "mdns":
            # mDNS query
            services = [b'\x09_services\x07_dns-sd', b'\x04_tcp', b'\x04_udp']
            service = self._audit_rng.choice(services)
            return b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + service + b'\x04_udp\x05local\x00\x00\x0c\x00\x01'
        return self._generate_random_payload(32, 64)

    def _generate_http_payload(self) -> bytes:
        """
        Generate realistic HTTP request payload.

        NON-GAMEABILITY:
        - Randomized method, path, host, user-agent
        - Variable headers that look like real requests
        - No identifiable audit markers
        """
        methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH"]
        method = self._audit_rng.choice(methods)
        path = self._audit_rng.choice(self.HTTP_PATHS)
        host = self._audit_rng.choice(self.HTTP_HOSTS)
        ua = self._audit_rng.choice(self.USER_AGENTS)

        # Build request with variable headers
        request = f"{method} {path} HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"
        request += f"User-Agent: {ua}\r\n"

        # Random additional headers (makes fingerprinting harder)
        if self._audit_rng.random() > 0.3:
            request += f"Accept: text/html,application/json\r\n"
        if self._audit_rng.random() > 0.5:
            request += f"Accept-Language: en-US,en;q=0.9\r\n"
        if self._audit_rng.random() > 0.4:
            request += f"Connection: keep-alive\r\n"
        if self._audit_rng.random() > 0.6:
            request += f"Cache-Control: no-cache\r\n"
        if self._audit_rng.random() > 0.7:
            request += f"X-Request-ID: {secrets.token_hex(8)}\r\n"

        # POST/PUT body
        if method in ["POST", "PUT", "PATCH"] and self._audit_rng.random() > 0.3:
            body = self._generate_random_payload(32, 128)
            request += f"Content-Length: {len(body)}\r\n"
            request += f"Content-Type: application/json\r\n"
            request += f"\r\n"
            return request.encode() + body
        else:
            request += f"\r\n"
            return request.encode()

    def _build_scapy_packet(self, pkt: AuditPacket, nonce: str):
        """
        Build scapy packet from AuditPacket.

        NON-GAMEABILITY:
        - NO identifiable audit markers in payload
        - Packet looks indistinguishable from real traffic
        - The nonce is kept for internal tracking only, not sent in packet
        """
        # Use the packet's payload directly - NO AUDIT MARKERS
        # The payload was already generated with realistic random data
        payload = pkt.payload if pkt.payload else self._generate_random_payload(8, 64)

        # Build IP layer
        ip_kwargs = {"src": pkt.source_ip, "dst": pkt.dest_ip}
        if pkt.ip_flags:
            ip_kwargs["flags"] = pkt.ip_flags
        if pkt.ip_frag_offset > 0:
            ip_kwargs["frag"] = pkt.ip_frag_offset

        if pkt.is_malformed:
            ip_kwargs["ihl"] = 2  # Invalid header length

        # Handle fragment packets
        if pkt.ip_frag_offset > 0:
            if pkt.protocol == "TCP":
                ip_kwargs["proto"] = 6
            elif pkt.protocol == "UDP":
                ip_kwargs["proto"] = 17
            elif pkt.protocol == "ICMP":
                ip_kwargs["proto"] = 1
            return IP(**ip_kwargs) / Raw(load=payload)

        ip = IP(**ip_kwargs)

        if pkt.protocol == "TCP":
            transport = TCP(
                sport=pkt.source_port,
                dport=pkt.dest_port,
                flags=pkt.tcp_flags if pkt.tcp_flags else "S",
            )
        elif pkt.protocol == "UDP":
            transport = UDP(
                sport=pkt.source_port,
                dport=pkt.dest_port,
            )
        elif pkt.protocol == "ICMP":
            transport = ICMP()
        else:
            transport = TCP(sport=pkt.source_port, dport=pkt.dest_port, flags="S")

        return ip / transport / Raw(load=payload)

    async def generate_challenge(
        self,
        dest_ip: str,
        throughput_level: int = 1,
        profile: Optional[AttackProfile] = None,
    ) -> AuditChallenge:
        """
        Generate an audit challenge with test packets.

        NON-GAMEABILITY FEATURES:
        - Fresh cryptographic entropy per audit
        - Randomized packet counts (not fixed)
        - Randomized pool sizes and distributions
        - No identifiable markers in traffic

        Args:
            dest_ip: Target scrubber IP
            throughput_level: 0=light, 1=normal, 2=heavy, 3=stress
            profile: Optional attack profile (randomly selected if None)

        Returns:
            AuditChallenge ready for sending
        """
        # CRITICAL: Initialize fresh entropy for this audit
        # This ensures each audit is unpredictable
        self._initialize_audit_entropy()

        challenge_nonce = secrets.token_hex(8)
        challenge_id = f"audit-{secrets.token_hex(6)}-{int(time.time())}"

        # Select attack profile with higher perturbation for unpredictability
        if profile is None:
            profile = self._select_profile()
            # Apply additional per-audit perturbation (configurable range)
            noise_factor = self._audit_rng.uniform(
                PROFILE_PERTURBATION_MIN,
                PROFILE_PERTURBATION_MAX
            )
            profile = profile.perturb(noise_factor=noise_factor)

        # Get packet counts for throughput level
        level = min(throughput_level, len(self.THROUGHPUT_LEVELS) - 1)
        attack_count, benign_count = self.THROUGHPUT_LEVELS[level]

        # ENHANCED randomization to counts - configurable range, per-audit RNG
        # This prevents miners from detecting audit by packet count patterns
        attack_multiplier = self._audit_rng.uniform(
            PACKET_COUNT_JITTER_MIN,
            PACKET_COUNT_JITTER_MAX
        )
        benign_multiplier = self._audit_rng.uniform(
            PACKET_COUNT_JITTER_MIN + 0.05,  # Slightly higher floor for benign
            PACKET_COUNT_JITTER_MAX + 0.05
        )
        attack_count = int(attack_count * attack_multiplier)
        benign_count = int(benign_count * benign_multiplier)

        # Compute attack counts per category with additional jitter
        total_attack = attack_count
        category_counts = {}

        for cat, weight in profile.weights.items():
            if cat == AttackCategory.BENIGN:
                category_counts[cat] = benign_count
            else:
                # Add per-category jitter (±20%)
                jitter = self._audit_rng.uniform(0.8, 1.2)
                category_counts[cat] = max(1, int(total_attack * weight * jitter))

        # Calculate total rate-limited packets for attack IP pool sizing
        # Rate-limited categories use concentrated source IPs to trigger per-source limits
        rate_limited_categories = {
            AttackCategory.SYN_FLOOD,
            AttackCategory.UDP_FLOOD,
            AttackCategory.ICMP_FLOOD,
            AttackCategory.L7_APPLICATION,
        }
        total_rate_limited = sum(
            count for cat, count in category_counts.items()
            if cat in rate_limited_categories
        )

        # Initialize attack IP pool with randomized size and non-uniform distribution
        self._initialize_attack_ip_pool(total_rate_limited)

        # DON'T log exact breakdown - keeps patterns hidden even from log analysis
        logger.info(
            f"Challenge {challenge_id[:12]}...: ~{len(category_counts)} categories, "
            f"entropy={self._audit_seed & 0xFFFF:04x}"
        )

        # Generate packets with randomized starting sequence
        all_packets = []
        seq_num = self._audit_rng.randint(100000, 999999)

        for cat, count in category_counts.items():
            packets = self._generate_packets_for_category(
                cat, count, dest_ip, seq_num
            )
            all_packets.extend(packets)
            seq_num += count + self._audit_rng.randint(0, 100)  # Random gaps

        # Shuffle packets using audit RNG for reproducibility
        self._audit_rng.shuffle(all_packets)

        challenge = AuditChallenge(
            challenge_id=challenge_id,
            challenge_nonce=challenge_nonce,
            profile_name=profile.name,
            packets=all_packets,
            throughput_level=throughput_level,
        )

        return challenge

    async def send_challenge(
        self,
        challenge: AuditChallenge,
        tunnel_interface: Optional[str] = None,
    ) -> AuditChallenge:
        """
        Send the challenge traffic.

        Args:
            challenge: The challenge to send
            tunnel_interface: Optional interface for packet sending

        Returns:
            Updated challenge with timing info
        """
        import socket as stdlib_socket

        challenge.start_time = time.time()

        # Build scapy packets
        scapy_packets = []
        for pkt in challenge.packets:
            try:
                scapy_pkt = self._build_scapy_packet(pkt, challenge.challenge_nonce)
                scapy_packets.append(scapy_pkt)
            except Exception as e:
                logger.warning(f"Failed to build packet seq={pkt.seq_num}: {e}")

        # Send packets
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=4) as executor:
            if tunnel_interface:
                await loop.run_in_executor(
                    executor,
                    self._send_via_interface,
                    scapy_packets,
                    tunnel_interface,
                )
            else:
                await loop.run_in_executor(
                    executor,
                    self._send_packets,
                    scapy_packets,
                )

        challenge.end_time = time.time()

        duration = challenge.end_time - challenge.start_time
        pps = len(scapy_packets) / duration if duration > 0 else 0

        logger.info(
            f"Sent {len(scapy_packets)} packets in {duration:.2f}s ({pps:.0f} pps)"
        )

        return challenge

    def _send_packets(self, packets: List, batch_size: int = 50):
        """
        Send packets via scapy with randomized timing.

        NON-GAMEABILITY:
        - Randomized batch sizes (not fixed 50)
        - Micro-delays between batches to simulate real traffic bursts
        - Prevents detection by timing analysis
        """
        # Randomize batch size per audit (30-70 packets)
        actual_batch_size = self._audit_rng.randint(30, 70)

        for i in range(0, len(packets), actual_batch_size):
            batch = packets[i:i + actual_batch_size]
            try:
                send(batch, verbose=0)
                # Random micro-delay between batches (0-5ms)
                # Simulates realistic network jitter
                if i + actual_batch_size < len(packets):
                    time.sleep(self._audit_rng.uniform(0, 0.005))
            except Exception as e:
                logger.warning(f"Batch send error: {e}")

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
                except Exception as e:
                    pass  # Best effort

            sock.close()
        except Exception as e:
            logger.error(f"Interface send error: {e}")

    def compute_expected_results(
        self,
        challenge: AuditChallenge,
    ) -> AuditResult:
        """
        Compute expected results based on packets sent.

        Args:
            challenge: The challenge with packets

        Returns:
            AuditResult with expected packet counts by category
        """
        result = AuditResult(
            challenge_id=challenge.challenge_id,
            total_packets_sent=len(challenge.packets),
            throughput_level=challenge.throughput_level,
        )

        # Count packets by category and expected action
        for cat in AttackCategory:
            result.category_results[cat.value] = {"sent": 0, "expected_block": 0, "expected_pass": 0}

        for pkt in challenge.packets:
            cat_name = pkt.category.value
            result.category_results[cat_name]["sent"] += 1

            if pkt.expected_action in (ExpectedAction.MUST_BLOCK, ExpectedAction.SHOULD_BLOCK):
                result.category_results[cat_name]["expected_block"] += 1
            elif pkt.expected_action == ExpectedAction.MUST_PASS:
                result.category_results[cat_name]["expected_pass"] += 1

        # Compute timing
        duration = challenge.end_time - challenge.start_time
        if duration > 0:
            result.packets_per_second = len(challenge.packets) / duration

        return result


class GraduatedThroughputAuditor:
    """
    Tests scrubber performance under increasing load.

    Runs audits at progressively higher throughput levels
    to measure capacity and degradation.
    """

    def __init__(self):
        self.sender = AuditSender()

    async def run_graduated_audit(
        self,
        dest_ip: str,
        tunnel_interface: Optional[str] = None,
        max_level: int = 3,
        get_stats_callback=None,
    ) -> List[AuditResult]:
        """
        Run graduated throughput audit.

        Args:
            dest_ip: Target scrubber IP
            tunnel_interface: Optional tunnel interface
            max_level: Maximum throughput level (0-3)
            get_stats_callback: Async function to get XDP stats from miner

        Returns:
            List of results at each throughput level
        """
        results = []

        for level in range(max_level + 1):
            logger.info(f"Running throughput level {level}")

            # Generate challenge
            challenge = await self.sender.generate_challenge(
                dest_ip,
                throughput_level=level
            )

            # Send traffic
            challenge = await self.sender.send_challenge(
                challenge,
                tunnel_interface=tunnel_interface,
            )

            # Compute expected results based on what we sent
            result = self.sender.compute_expected_results(challenge)
            results.append(result)

            # Brief pause between levels
            await asyncio.sleep(1.0)

        return results

    def compute_throughput_score(self, results: List[AuditResult]) -> float:
        """
        Compute overall throughput score from graduated results.

        Rewards:
        - Maintaining high accuracy at higher levels
        - Processing more packets per second

        Returns:
            Score from 0 to 1
        """
        if not results:
            return 0.0

        # Weight by level (higher levels worth more)
        level_weights = [0.1, 0.2, 0.3, 0.4]

        total_weight = 0.0
        weighted_score = 0.0

        for i, result in enumerate(results):
            weight = level_weights[min(i, len(level_weights) - 1)]
            total_weight += weight

            # Score = accuracy
            level_score = result.accuracy_score
            weighted_score += weight * level_score

        if total_weight > 0:
            return weighted_score / total_weight

        return 0.0


# Export main classes
__all__ = [
    "AuditSender",
    "AuditChallenge",
    "AuditResult",
    "AuditPacket",
    "AttackCategory",
    "ExpectedAction",
    "AttackProfile",
    "GraduatedThroughputAuditor",
    "ATTACK_PROFILES",
]
