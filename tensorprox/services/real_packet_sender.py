"""
Real packet sender for miner auditing.

Sends ACTUAL network packets to test scrubber XDP filtering.
This is NOT a simulation - it crafts and sends real packets
that the scrubber's XDP program must process.

CRITICAL: This replaces the fake simulation that was using
random numbers instead of real traffic.

NON-GAMEABILITY PRINCIPLES:
==========================
1. NO PREDICTABLE MARKERS: Payloads contain random data, not identifiable headers.
   A scrubber cannot distinguish audit traffic from real traffic by content.

2. PER-AUDIT ENTROPY: Each audit uses fresh cryptographic seeds for all random
   decisions. Historical patterns don't help predict future audits.

3. RANDOMIZED DISTRIBUTIONS: Pool sizes, packet counts, timing - all have entropy.

4. PATTERN-BASED DETECTION: The scrubber must detect attacks by BEHAVIOR
   (rate, protocol violations, source patterns) not by recognizing test traffic.

5. CONCENTRATED ATTACK SOURCES: Rate-limited attacks come from few IPs with
   many packets each (mimics real botnets), while benign is distributed.
"""

import asyncio
import multiprocessing
import random
import secrets
import socket
import string
import struct
import time
import uuid
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ProcessPoolExecutor

from loguru import logger

# Module-level process pool for true parallelism (bypasses GIL)
# Lazily initialized on first use
_PROCESS_POOL: Optional[ProcessPoolExecutor] = None
_PROCESS_POOL_SIZE = 8  # Fixed at 8 workers for parallel traffic generation


def _warmup_worker(worker_id):
    """Warmup function to pre-import scapy in worker processes."""
    import warnings
    warnings.filterwarnings("ignore")
    import os
    pid = os.getpid()
    from scapy.all import IP, TCP, UDP, ICMP, Raw, conf
    conf.verb = 0
    return (worker_id, pid)


def _get_process_pool() -> ProcessPoolExecutor:
    """Get or create the module-level process pool."""
    global _PROCESS_POOL
    if _PROCESS_POOL is None:
        import os
        # Suppress all Python warnings in subprocesses via environment
        os.environ['PYTHONWARNINGS'] = 'ignore'

        _PROCESS_POOL = ProcessPoolExecutor(
            max_workers=_PROCESS_POOL_SIZE,
            mp_context=multiprocessing.get_context('spawn'),
        )
        logger.info(f"Initialized process pool with {_PROCESS_POOL_SIZE} workers, warming up...")

        # Pre-warm ALL workers by submitting dummy tasks
        # This forces each worker to start and import scapy NOW
        warmup_futures = [_PROCESS_POOL.submit(_warmup_worker, i) for i in range(_PROCESS_POOL_SIZE)]
        for f in warmup_futures:
            f.result()  # Wait for all workers to be ready
        logger.info(f"Process pool ready with {_PROCESS_POOL_SIZE} warmed workers")
    return _PROCESS_POOL

# Import audit configuration for non-gameability settings
try:
    from tensorprox.config.audit_config import (
        ATTACK_POOL_SIZE_MIN,
        ATTACK_POOL_SIZE_MAX,
        PACKET_COUNT_JITTER_MIN,
        PACKET_COUNT_JITTER_MAX,
    )
    _HAS_AUDIT_CONFIG = True
except ImportError:
    _HAS_AUDIT_CONFIG = False
    ATTACK_POOL_SIZE_MIN = 5
    ATTACK_POOL_SIZE_MAX = 25
    PACKET_COUNT_JITTER_MIN = 0.65
    PACKET_COUNT_JITTER_MAX = 1.35

# Try to import scapy - required for real packet sending
try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Raw, Ether,
        send, sendp, sr1, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - real packet sending disabled")


class AttackType(Enum):
    """
    Types of attack traffic to test - comprehensive coverage matching product protection.

    Tests the FULL protection layer provided to customers:
    - Layer 3/4: IP spoofing, bogons, blacklists, rate limiting
    - Layer 4: TCP/UDP floods, amplification attacks
    - Layer 7: HTTP floods, slowloris, application attacks
    """
    # Layer 3/4 - IP-based attacks
    BOGON = "bogon"                     # RFC bogon source addresses
    BLACKLIST = "blacklist"             # Known malicious IPs

    # Layer 4 - TCP attacks
    SYN_FLOOD = "syn_flood"             # Rapid SYN packets (tests SYN cookies)
    TCP_XMAS = "tcp_xmas"               # Christmas tree packets (all flags)
    TCP_NULL = "tcp_null"               # NULL packets (no flags)
    TCP_FIN_SCAN = "tcp_fin_scan"       # FIN scan (only FIN flag)
    TCP_RST_FLOOD = "tcp_rst_flood"     # RST flood
    TCP_ACK_FLOOD = "tcp_ack_flood"     # ACK flood (state exhaustion)
    TCP_SYNFIN = "tcp_synfin"           # SYN+FIN invalid combo
    TCP_SYNRST = "tcp_synrst"           # SYN+RST invalid combo

    # Layer 4 - UDP attacks
    UDP_FLOOD = "udp_flood"             # Basic UDP flood
    UDP_AMP_DNS = "udp_amp_dns"         # DNS amplification
    UDP_AMP_NTP = "udp_amp_ntp"         # NTP amplification
    UDP_AMP_MEMCACHED = "udp_amp_memcached"  # Memcached amplification
    UDP_AMP_SSDP = "udp_amp_ssdp"       # SSDP/UPnP amplification
    UDP_AMP_SNMP = "udp_amp_snmp"       # SNMP amplification
    UDP_AMP_CHARGEN = "udp_amp_chargen" # Chargen amplification

    # Layer 3 - ICMP attacks
    ICMP_FLOOD = "icmp_flood"           # ICMP echo flood (ping flood)
    ICMP_FRAG = "icmp_frag"             # ICMP fragmentation attack

    # Fragmentation attacks
    FRAG_OVERLAP = "frag_overlap"       # Overlapping IP fragments
    FRAG_TINY = "frag_tiny"             # Tiny fragments

    # Layer 7 - Application attacks
    SLOWLORIS = "slowloris"             # Partial HTTP requests
    HTTP_FLOOD = "http_flood"           # HTTP GET/POST flood

    # Malformed packets
    MALFORMED = "malformed"             # Invalid packet structure

    # Land attack
    LAND_ATTACK = "land_attack"         # Source IP == Destination IP


@dataclass
class AuditProfile:
    """
    Shared audit profile for a single audit round.

    FAIRNESS: All miners in the same round receive IDENTICAL traffic patterns.
    This ensures fair comparison - miners are scored on the same test.

    Generated once per round by the validator, then passed to all miners.
    """
    seed: int  # Cryptographic seed for reproducible randomness
    attack_count: int  # Total attack packets
    benign_count: int  # Total benign packets
    distribution: Dict[str, int]  # Per-category packet counts

    # Base attack count — randomized ±50% each round (5,000–15,000 actual)
    BASE_ATTACK_COUNT = 10000

    @classmethod
    def generate(cls) -> 'AuditProfile':
        """
        Generate a new audit profile with randomized distribution.

        Called ONCE per audit round to ensure all miners get identical traffic.
        Attack count is randomized ±50% around BASE_ATTACK_COUNT.
        Benign:attack ratio is randomized each round between 1:3 and 1:10
        to prevent miners from predicting traffic patterns.
        """
        seed = secrets.randbits(64)
        rng = random.Random(seed)

        # Randomize attack count with ±50% jitter around base
        attack_var = rng.uniform(0.5, 1.5)
        final_attack = max(50, int(cls.BASE_ATTACK_COUNT * attack_var))

        # Dynamic benign:attack ratio (1:3 to 1:10) — unpredictable per round
        # 0.333 = 1 benign per 3 attacks, 0.1 = 1 benign per 10 attacks
        benign_ratio = rng.uniform(0.1, 0.333)
        final_benign = max(50, int(final_attack * benign_ratio))
        effective_ratio = final_attack / final_benign if final_benign > 0 else 0

        # Generate distribution using the seeded RNG
        distribution = cls._generate_distribution(rng, final_attack)

        logger.info(
            f"Audit profile generated: seed={seed & 0xFFFF:04x}, "
            f"attacks={final_attack}, benign={final_benign}, "
            f"ratio={effective_ratio:.1f}:1, total={final_attack + final_benign}"
        )

        return cls(
            seed=seed,
            attack_count=final_attack,
            benign_count=final_benign,
            distribution=distribution,
        )

    @staticmethod
    def _generate_distribution(rng: random.Random, total: int) -> Dict[str, int]:
        """Generate attack distribution using seeded RNG for reproducibility."""
        # Category weights (sum to 1.0)
        category_weights = {
            "layer3_ip": 0.18,
            "layer4_tcp": 0.30,
            "layer4_udp": 0.20,
            "layer3_icmp": 0.10,
            "fragmentation": 0.05,
            "layer7": 0.10,
            "malformed": 0.05,
            "land_attack": 0.02,
        }

        # Add randomness with seeded RNG (±30%)
        for k in category_weights:
            category_weights[k] *= rng.uniform(0.7, 1.3)

        # Normalize
        total_weight = sum(category_weights.values())
        for k in category_weights:
            category_weights[k] /= total_weight

        dist = {}

        # Layer 3/4 IP attacks (bogon + blacklist only — XDP can reliably detect these)
        ip_count = int(total * category_weights["layer3_ip"])
        dist["bogon"] = ip_count // 2
        dist["blacklist"] = ip_count - dist["bogon"]

        # TCP attacks
        tcp_count = int(total * category_weights["layer4_tcp"])
        dist["syn_flood"] = int(tcp_count * 0.35)
        dist["tcp_xmas"] = int(tcp_count * 0.12)
        dist["tcp_null"] = int(tcp_count * 0.12)
        dist["tcp_fin"] = int(tcp_count * 0.10)
        dist["tcp_rst"] = int(tcp_count * 0.08)
        dist["tcp_ack"] = int(tcp_count * 0.08)
        dist["tcp_synfin"] = int(tcp_count * 0.08)
        dist["tcp_synrst"] = tcp_count - sum([
            dist["syn_flood"], dist["tcp_xmas"], dist["tcp_null"],
            dist["tcp_fin"], dist["tcp_rst"], dist["tcp_ack"], dist["tcp_synfin"]
        ])

        # UDP attacks
        udp_count = int(total * category_weights["layer4_udp"])
        dist["udp_flood"] = int(udp_count * 0.40)
        dist["udp_amp_dns"] = int(udp_count * 0.15)
        dist["udp_amp_ntp"] = int(udp_count * 0.15)
        dist["udp_amp_memcached"] = int(udp_count * 0.10)
        dist["udp_amp_ssdp"] = int(udp_count * 0.08)
        dist["udp_amp_snmp"] = int(udp_count * 0.07)
        dist["udp_amp_chargen"] = udp_count - sum([
            dist["udp_flood"], dist["udp_amp_dns"], dist["udp_amp_ntp"],
            dist["udp_amp_memcached"], dist["udp_amp_ssdp"], dist["udp_amp_snmp"]
        ])

        # ICMP attacks
        icmp_count = int(total * category_weights["layer3_icmp"])
        dist["icmp_flood"] = int(icmp_count * 0.7)
        dist["icmp_frag"] = icmp_count - dist["icmp_flood"]

        # Fragmentation
        frag_count = int(total * category_weights["fragmentation"])
        dist["frag_small"] = frag_count // 2
        dist["frag_overlap"] = frag_count - dist["frag_small"]

        # Layer 7
        l7_count = int(total * category_weights["layer7"])
        dist["slowloris"] = l7_count // 2
        dist["http_flood"] = l7_count - dist["slowloris"]

        # Malformed
        dist["malformed"] = int(total * category_weights["malformed"])

        # Land attack
        dist["land_attack"] = int(total * category_weights["land_attack"])

        return dist


@dataclass
class PacketSpec:
    """Specification for a packet to send."""
    attack_type: Optional[AttackType]  # None for benign
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str  # TCP, UDP, ICMP
    payload: bytes = b""
    should_be_blocked: bool = True
    tcp_flags: str = "S"  # For TCP packets
    ip_flags: str = ""  # IP flags: "MF" for More Fragments, "DF" for Don't Fragment
    ip_frag_offset: int = 0  # Fragment offset in 8-byte units
    is_malformed: bool = False  # If True, create invalid IP header


@dataclass
class RealTrafficResult:
    """
    Results from real traffic test - comprehensive attack coverage.

    Packet uniqueness is ensured via:
    1. Per-packet sequence numbers in payload (seq_start to seq_end)
    2. Challenge nonce for round identification
    3. Hash of packet spec for deduplication
    """

    challenge_id: str = ""
    challenge_nonce: str = ""

    # What we sent (ground truth)
    total_sent: int = 0
    attack_sent: int = 0
    benign_sent: int = 0

    # Packet sequence tracking for uniqueness verification
    # Each packet gets a unique sequence number: AUDIT:{nonce}:SEQ{seq_num}:
    seq_start: int = 0  # First sequence number in this round
    seq_end: int = 0    # Last sequence number in this round
    packet_hashes: List[str] = field(default_factory=list)  # SHA256 of each packet spec

    # Layer 3/4 - IP-based attacks
    bogon_sent: int = 0
    blacklist_sent: int = 0

    # Layer 4 - TCP attacks
    syn_flood_sent: int = 0
    tcp_xmas_sent: int = 0
    tcp_null_sent: int = 0
    tcp_fin_sent: int = 0
    tcp_rst_sent: int = 0
    tcp_ack_sent: int = 0
    tcp_synfin_sent: int = 0
    tcp_synrst_sent: int = 0

    # Layer 4 - UDP attacks
    udp_flood_sent: int = 0
    udp_amp_dns_sent: int = 0
    udp_amp_ntp_sent: int = 0
    udp_amp_memcached_sent: int = 0
    udp_amp_ssdp_sent: int = 0
    udp_amp_snmp_sent: int = 0
    udp_amp_chargen_sent: int = 0

    # Layer 3 - ICMP attacks
    icmp_flood_sent: int = 0
    icmp_frag_sent: int = 0

    # Fragmentation attacks
    frag_overlap_sent: int = 0
    frag_tiny_sent: int = 0

    # Layer 7 - Application attacks
    slowloris_sent: int = 0
    http_flood_sent: int = 0

    # Malformed
    malformed_sent: int = 0

    # Land attack
    land_attack_sent: int = 0

    # Send errors (packets that failed to send)
    send_errors: int = 0

    # Timing
    start_time: float = 0.0
    end_time: float = 0.0
    duration_seconds: float = 0.0
    packets_per_second: float = 0.0

    def get_attack_breakdown(self) -> Dict[str, int]:
        """Get breakdown of attacks by category."""
        return {
            "layer3_ip": self.bogon_sent + self.blacklist_sent,
            "layer4_tcp": (self.syn_flood_sent + self.tcp_xmas_sent + self.tcp_null_sent +
                         self.tcp_fin_sent + self.tcp_rst_sent + self.tcp_ack_sent +
                         self.tcp_synfin_sent + self.tcp_synrst_sent),
            "layer4_udp": (self.udp_flood_sent + self.udp_amp_dns_sent +
                         self.udp_amp_ntp_sent + self.udp_amp_memcached_sent +
                         self.udp_amp_ssdp_sent + self.udp_amp_snmp_sent +
                         self.udp_amp_chargen_sent),
            "layer3_icmp": self.icmp_flood_sent + self.icmp_frag_sent,
            "fragmentation": self.frag_overlap_sent + self.frag_tiny_sent,
            "layer7": self.slowloris_sent + self.http_flood_sent,
            "malformed": self.malformed_sent,
            "land_attack": self.land_attack_sent,
        }

    def get_expected_blocked(self) -> int:
        """
        Get expected number of packets that XDP should block.

        ONLY counts attacks that XDP has deterministic rules for:
        - Bogon source IPs: Always blocked
        - Blacklist IPs: Always blocked
        - TCP flag anomalies (XMAS, NULL, FIN-only, RST-only, ACK-only): Always blocked
        - UDP amplification ports: Always blocked
        - Fragmentation attacks: Always blocked

        NOT counted (XDP can't reliably detect):
        - Spoofed IPs: Random public IPs pass bogon/blacklist checks
        - SYN flood: Only rate-limited, timing-dependent
        - UDP flood: Only rate-limited, timing-dependent
        - ICMP flood: Only rate/size-limited, variable
        - L7 attacks (slowloris, HTTP flood): TCP PSH+ACK is valid
        - Malformed: No specific payload detection
        """
        # Attacks XDP guarantees to block
        guaranteed_blocked = (
            self.bogon_sent +
            self.blacklist_sent +
            # TCP flag anomalies (always blocked)
            self.tcp_xmas_sent +
            self.tcp_null_sent +
            self.tcp_fin_sent +
            self.tcp_rst_sent +
            self.tcp_ack_sent +
            self.tcp_synfin_sent +
            self.tcp_synrst_sent +
            # UDP amplification ports (always blocked)
            self.udp_amp_dns_sent +
            self.udp_amp_ntp_sent +
            self.udp_amp_memcached_sent +
            self.udp_amp_ssdp_sent +
            self.udp_amp_snmp_sent +
            self.udp_amp_chargen_sent +
            # Fragmentation (always blocked in audit mode)
            self.frag_overlap_sent +
            self.frag_tiny_sent +
            # Malformed packets (invalid IP headers)
            self.malformed_sent +
            # Land attack (src == dst, always blocked)
            self.land_attack_sent
        )

        # Rate-limited attacks: estimate ~70% will be blocked
        # (depends on packet timing and rate counter windows)
        rate_limited_blocked = int(0.7 * (
            self.syn_flood_sent +
            self.udp_flood_sent +
            self.icmp_flood_sent +
            self.icmp_frag_sent
        ))

        return guaranteed_blocked + rate_limited_blocked

    def get_expected_passed(self) -> int:
        """
        Get expected number of packets that should pass.

        Includes:
        - All benign traffic
        - Attack traffic that XDP can't detect:
          - Spoofed IPs (random public IPs)
          - L7 attacks (valid TCP structure)
          - ~30% of rate-limited attacks that slip through
        """
        # Attacks that XDP cannot detect (L7 uses valid TCP structure)
        undetectable_attacks = (
            self.slowloris_sent +        # TCP PSH+ACK is valid
            self.http_flood_sent         # TCP PSH+ACK is valid
        )

        # ~30% of rate-limited attacks slip through
        rate_limited_passed = int(0.3 * (
            self.syn_flood_sent +
            self.udp_flood_sent +
            self.icmp_flood_sent +
            self.icmp_frag_sent
        ))

        return self.benign_sent + undetectable_attacks + rate_limited_passed


def _build_and_send_in_process(
    dest_ip: str,
    tunnel_interface: Optional[str],
    attack_count: int,
    benign_count: int,
    distribution: Dict[str, int],
    challenge_nonce: str,
    audit_seed: int,
    target_pps: int,
) -> Tuple[int, int, int, int]:
    """
    Standalone function for packet building and sending in a subprocess.

    This runs in a separate process via ProcessPoolExecutor to bypass Python's GIL,
    enabling true parallelism for CPU-bound packet serialization.

    Returns: (total_sent, seq_start, seq_end, send_errors)
    """
    # Suppress ALL warnings BEFORE any imports (pydantic warnings from scapy)
    import warnings
    warnings.filterwarnings("ignore")

    import time
    import random
    import socket as stdlib_socket

    # Import scapy in subprocess (each process needs its own import)
    from scapy.all import IP, TCP, UDP, ICMP, Raw, conf
    conf.verb = 0  # Disable verbose output

    # Initialize random state with the provided seed for reproducibility
    rng = random.Random(audit_seed)

    # Constants (duplicated here to avoid pickling issues)
    BOGON_RANGES = [
        ("0.0.0.0", 8), ("10.0.0.0", 8), ("100.64.0.0", 10), ("127.0.0.0", 8),
        ("169.254.0.0", 16), ("172.16.0.0", 12), ("192.0.0.0", 24), ("192.0.2.0", 24),
        ("192.168.0.0", 16), ("198.18.0.0", 15), ("198.51.100.0", 24), ("203.0.113.0", 24),
        ("224.0.0.0", 4), ("240.0.0.0", 4),
    ]
    MALICIOUS_PREFIXES = [
        ("45.142.212.0", 22), ("185.220.100.0", 22), ("89.248.160.0", 21),
        ("194.165.16.0", 24), ("45.155.204.0", 22), ("193.32.160.0", 21),
        ("91.241.19.0", 24), ("5.188.86.0", 23), ("167.94.138.0", 23), ("80.82.77.0", 24),
    ]
    LEGITIMATE_PREFIXES = [
        1, 8, 13, 15, 16, 17, 18, 19, 20, 23, 32, 33, 34, 35, 38, 40, 44, 45, 47, 48,
        52, 54, 56, 57, 104, 142, 143, 144, 146, 147, 204, 205, 206, 207, 208, 209,
    ]
    TARGET_PORTS = [80, 443, 8080, 8443, 3000, 8000]
    NON_HTTP_PORTS = [22, 25, 110, 143, 993, 995, 3306, 5432, 6379, 27017]

    def ip_from_prefix(prefix: str, mask: int) -> str:
        octets = [int(x) for x in prefix.split('.')]
        host_bits = 32 - mask
        if host_bits > 0:
            max_host = (1 << host_bits) - 1
            random_host = rng.randint(1, max(1, max_host - 1))
            base = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
            net_mask = (0xFFFFFFFF << host_bits) & 0xFFFFFFFF
            final = (base & net_mask) | random_host
            return f"{(final >> 24) & 0xFF}.{(final >> 16) & 0xFF}.{(final >> 8) & 0xFF}.{final & 0xFF}"
        return prefix

    def gen_bogon_ip() -> str:
        prefix, mask = rng.choice(BOGON_RANGES)
        return ip_from_prefix(prefix, mask)

    def gen_blacklist_ip() -> str:
        prefix, mask = rng.choice(MALICIOUS_PREFIXES)
        return ip_from_prefix(prefix, mask)

    def gen_legitimate_ip() -> str:
        first = rng.choice(LEGITIMATE_PREFIXES)
        return f"{first}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"

    def gen_spoofed_ip() -> str:
        return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"

    def gen_random_payload(min_size: int = 16, max_size: int = 64) -> bytes:
        size = rng.randint(min_size, max_size)
        return bytes(rng.randint(0, 255) for _ in range(size))

    # Build attack IP pool for concentrated traffic
    rate_limited_count = (
        distribution.get('syn_flood', 0) + distribution.get('udp_flood', 0) +
        distribution.get('icmp_flood', 0) + distribution.get('tcp_ack', 0) + distribution.get('tcp_rst', 0)
    )
    pool_size = rng.randint(5, 25)
    if rate_limited_count > 0 and rate_limited_count / pool_size < 30:
        pool_size = max(3, rate_limited_count // 30)
    attack_ip_pool = [gen_spoofed_ip() for _ in range(pool_size)]
    raw_weights = [rng.paretovariate(1.5) for _ in range(pool_size)]
    total_weight = sum(raw_weights)
    attack_ip_weights = [w / total_weight for w in raw_weights]

    def get_attack_ip() -> str:
        return rng.choices(attack_ip_pool, weights=attack_ip_weights, k=1)[0]

    # ==========================================================================
    # BURST MODE: Separate rate-limited attacks from signature-based attacks
    # Rate-limited attacks need concentrated bursts to reliably trigger XDP
    # per-window rate limits. Signature-based attacks are detected by packet
    # content, not rate.
    #
    # XDP Rate Limits (per 2-second window):
    # - SYN flood: 25 packets (COUNTER_SYN)
    # - UDP flood: 35 packets (COUNTER_UDP)
    # - ICMP flood: 20 packets (COUNTER_ICMP) + payload size check
    # - Slowloris: 25 packets (COUNTER_SLOWLORIS) - HTTP port SYNs
    # - HTTP flood: 30 packets (COUNTER_HTTP) - HTTP port PSH+ACK
    # - TCP RST/ACK: per-source rate limit (50 PPS per IP)
    # ==========================================================================

    # Rate-limited attack packets (sent in concentrated bursts)
    burst_packets = []

    # SYN flood - needs >25 packets per 2s window to trigger rate limit
    for _ in range(distribution.get("syn_flood", 0)):
        burst_packets.append(IP(src=get_attack_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice(NON_HTTP_PORTS), flags="S"))

    # UDP flood - needs >30 packets per 2s window to trigger rate limit
    for _ in range(distribution.get("udp_flood", 0)):
        burst_packets.append(IP(src=get_attack_ip(), dst=dest_ip) /
                      UDP(sport=rng.randint(1024, 65535), dport=rng.randint(10000, 60000)) /
                      Raw(load=gen_random_payload(64, 512)))

    # ICMP flood - rate-limited + payload size check
    for _ in range(distribution.get("icmp_flood", 0)):
        burst_packets.append(IP(src=get_attack_ip(), dst=dest_ip) / ICMP() / Raw(load=gen_random_payload(64, 1200)))

    # TCP RST flood - uses per-source rate limiting (concentrated IPs trigger it)
    for _ in range(distribution.get("tcp_rst", 0)):
        burst_packets.append(IP(src=get_attack_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice(TARGET_PORTS), flags="R"))

    # TCP ACK flood - uses per-source rate limiting (also signature-blocked)
    for _ in range(distribution.get("tcp_ack", 0)):
        burst_packets.append(IP(src=get_attack_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice(TARGET_PORTS), flags="A"))

    # Slowloris - rate-limited on HTTP ports (25/window)
    for _ in range(distribution.get("slowloris", 0)):
        burst_packets.append(IP(src=get_attack_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=80, flags="PA") /
                      Raw(load=b'GET / HTTP/1.1\r\nHost: x\r\n'))

    # HTTP flood - rate-limited on HTTP ports (400/window for PSH+ACK)
    for _ in range(distribution.get("http_flood", 0)):
        burst_packets.append(IP(src=get_attack_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice([80, 443, 8080]), flags="PA") /
                      Raw(load=b'GET / HTTP/1.1\r\nHost: x\r\n\r\n'))

    # Signature-based attack packets (detected by content, can be spread out)
    regular_packets = []

    # IP-based attacks (blocked by source IP classification)
    for _ in range(distribution.get("bogon", 0)):
        regular_packets.append(IP(src=gen_bogon_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice(TARGET_PORTS), flags="S") /
                      Raw(load=gen_random_payload()))

    for _ in range(distribution.get("blacklist", 0)):
        regular_packets.append(IP(src=gen_blacklist_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice(TARGET_PORTS), flags="S") /
                      Raw(load=gen_random_payload()))

    # TCP flag attacks (blocked by invalid flag combinations)
    for _ in range(distribution.get("tcp_xmas", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice(TARGET_PORTS), flags="FSRPAUEC"))

    for _ in range(distribution.get("tcp_null", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice(TARGET_PORTS), flags=""))

    for _ in range(distribution.get("tcp_fin", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice(TARGET_PORTS), flags="F"))

    for _ in range(distribution.get("tcp_synfin", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice(TARGET_PORTS), flags="SF"))

    for _ in range(distribution.get("tcp_synrst", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice(TARGET_PORTS), flags="SR"))

    # UDP amplification attacks (blocked by destination port detection)
    for _ in range(distribution.get("udp_amp_dns", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) /
                      UDP(sport=rng.randint(1024, 65535), dport=53) / Raw(load=b'\x00\x01\x01\x00\x00\x01'))

    for _ in range(distribution.get("udp_amp_ntp", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) /
                      UDP(sport=rng.randint(1024, 65535), dport=123) / Raw(load=b'\x17\x00\x03\x2a'))

    for _ in range(distribution.get("udp_amp_memcached", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) /
                      UDP(sport=rng.randint(1024, 65535), dport=11211) / Raw(load=b'\x00\x01\x00\x00stats\r\n'))

    for _ in range(distribution.get("udp_amp_ssdp", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) /
                      UDP(sport=rng.randint(1024, 65535), dport=1900) / Raw(load=b'M-SEARCH * HTTP/1.1\r\n'))

    for _ in range(distribution.get("udp_amp_snmp", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) /
                      UDP(sport=rng.randint(1024, 65535), dport=161) / Raw(load=b'\x30\x26\x02\x01\x01'))

    for _ in range(distribution.get("udp_amp_chargen", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) /
                      UDP(sport=rng.randint(1024, 65535), dport=19) / Raw(load=b'x' * 64))

    # ICMP frag (blocked by payload size - signature-based)
    for _ in range(distribution.get("icmp_frag", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip) / ICMP() / Raw(load=gen_random_payload(800, 1200)))

    # Fragmentation attacks (blocked by fragment flags/offset)
    for _ in range(distribution.get("frag_overlap", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip, proto=17, frag=10) / Raw(load=gen_random_payload(50, 100)))

    for _ in range(distribution.get("frag_tiny", 0)):
        regular_packets.append(IP(src=gen_spoofed_ip(), dst=dest_ip, flags="MF") /
                      UDP(sport=rng.randint(1024, 65535), dport=rng.choice(TARGET_PORTS)) / Raw(load=b'\x41' * 8))

    # Malformed packets (blocked by invalid IP header)
    for _ in range(distribution.get("malformed", 0)):
        regular_packets.append(IP(src=gen_legitimate_ip(), dst=dest_ip, ihl=2) / Raw(load=gen_random_payload(20, 60)))

    # Land attack (blocked by src==dst)
    for _ in range(distribution.get("land_attack", 0)):
        regular_packets.append(IP(src=dest_ip, dst=dest_ip) /
                      TCP(sport=rng.randint(1024, 65535), dport=rng.choice(TARGET_PORTS), flags="S"))

    # Benign traffic (spread out with regular traffic)
    # NOTE: No ICMP in benign traffic - ICMP rate limiting during attack bursts
    # would cause benign ICMP to be blocked (false positives)
    for _ in range(benign_count):
        proto_roll = rng.random()
        if proto_roll < 0.3:
            # 30% UDP on non-attack ports
            regular_packets.append(IP(src=gen_legitimate_ip(), dst=dest_ip) /
                          UDP(sport=rng.randint(1024, 65535), dport=rng.randint(8000, 65535)) /
                          Raw(load=gen_random_payload(32, 128)))
        else:
            # 70% TCP with PSH+ACK on non-attack ports
            regular_packets.append(IP(src=gen_legitimate_ip(), dst=dest_ip) /
                          TCP(sport=rng.randint(1024, 65535), dport=rng.randint(8001, 65535), flags="PA") /
                          Raw(load=gen_random_payload(32, 128)))

    # Shuffle within each category (but keep bursts separate from regular)
    rng.shuffle(burst_packets)
    rng.shuffle(regular_packets)

    logger.debug(f"BURST MODE: {len(burst_packets)} rate-limited + {len(regular_packets)} signature-based packets")

    # ==========================================================================
    # MULTI-WAVE SENDING STRATEGY
    # ==========================================================================
    # Audit traffic is spread over ~60 seconds with multiple burst waves
    # interleaved with paced regular traffic. This tests:
    #
    # 1. Rate limiter ACTIVATION — burst waves exceed per-window thresholds
    # 2. Rate limiter RECOVERY — gaps between waves test if limits reset properly
    # 3. Sustained filtering — regular traffic tests consistent blocking over time
    # 4. Anti-gaming — unpredictable wave timing prevents pattern matching
    #
    # XDP Rate Limits (per 2-second window):
    # - SYN: 25 packets → need to send 100+ in <2s to trigger
    # - UDP: 250 packets → need to send 500+ in <2s to trigger
    # - ICMP: 400 packets → blocked by payload size first, rate limit secondary
    #
    # Strategy: Split burst packets into N waves, interleave with regular
    # traffic between waves. Dynamic PPS targets ~60s total duration.
    # ==========================================================================

    MIN_AUDIT_DURATION_SECONDS = 60

    # Total packets for tracking
    total_packets = len(burst_packets) + len(regular_packets)
    seq_start = int(time.time() * 1000) % 1000000
    seq_end = seq_start + total_packets - 1
    errors = 0

    # Dynamic PPS: target ~60s for regular packets (bursts are max-speed)
    if len(regular_packets) > 0:
        regular_pps = max(50, int(len(regular_packets) / MIN_AUDIT_DURATION_SECONDS))
    else:
        regular_pps = target_pps
    packet_delay = 1.0 / regular_pps if regular_pps > 0 else 0

    # Split burst packets into 3-5 waves (randomized)
    num_waves = rng.randint(3, 5) if len(burst_packets) >= 30 else 1
    burst_waves = []
    if burst_packets:
        wave_size = len(burst_packets) // num_waves
        for i in range(num_waves):
            start = i * wave_size
            end = start + wave_size if i < num_waves - 1 else len(burst_packets)
            burst_waves.append(burst_packets[start:end])

    # Distribute regular packets between waves (N waves = N+1 gaps)
    regular_chunks = []
    if regular_packets and num_waves > 0:
        chunk_size = len(regular_packets) // (num_waves + 1)
        for i in range(num_waves + 1):
            start = i * chunk_size
            end = start + chunk_size if i < num_waves else len(regular_packets)
            regular_chunks.append(regular_packets[start:end])
    elif regular_packets:
        regular_chunks.append(regular_packets)

    logger.debug(
        f"MULTI-WAVE: {num_waves} burst waves ({len(burst_packets)} pkts), "
        f"{len(regular_chunks)} regular chunks ({len(regular_packets)} pkts), "
        f"regular_pps={regular_pps}, target={MIN_AUDIT_DURATION_SECONDS}s"
    )

    send_start = time.time()

    if tunnel_interface and tunnel_interface.startswith('wg'):
        ETH_P_IP = 0x0800
        try:
            af_sock = stdlib_socket.socket(stdlib_socket.AF_PACKET, stdlib_socket.SOCK_DGRAM, stdlib_socket.htons(ETH_P_IP))
            af_sock.bind((tunnel_interface, ETH_P_IP))

            def _send_burst_wave(wave_packets, wave_num):
                """Send a burst wave at max speed to trigger rate limiters."""
                nonlocal errors
                wave_start = time.time()
                for pkt in wave_packets:
                    try:
                        af_sock.send(bytes(pkt))
                    except OSError:
                        errors += 1
                wave_elapsed = time.time() - wave_start
                wave_pps = len(wave_packets) / wave_elapsed if wave_elapsed > 0 else 0
                logger.debug(f"  BURST WAVE {wave_num}/{num_waves}: {len(wave_packets)} pkts in {wave_elapsed:.3f}s ({wave_pps:.0f} pps)")

            def _send_regular_chunk(chunk_packets):
                """Send regular packets with timing jitter."""
                nonlocal errors
                last_t = time.time()
                for pkt in chunk_packets:
                    try:
                        af_sock.send(bytes(pkt))
                        if packet_delay > 0:
                            jitter_factor = rng.uniform(0.5, 2.0)
                            jittered_delay = packet_delay * jitter_factor
                            # 5% chance micro-burst
                            if rng.random() < 0.05:
                                jittered_delay = packet_delay * 0.1
                            elapsed = time.time() - last_t
                            if elapsed < jittered_delay:
                                time.sleep(jittered_delay - elapsed)
                            last_t = time.time()
                    except OSError:
                        errors += 1

            # Interleave: regular → burst → regular → burst → ... → regular
            # First chunk of regular traffic (baseline before first burst)
            if regular_chunks:
                _send_regular_chunk(regular_chunks[0])

            for wave_idx in range(num_waves):
                # Send burst wave at max speed
                _send_burst_wave(burst_waves[wave_idx], wave_idx + 1)

                # Send regular traffic after this wave (if available)
                chunk_idx = wave_idx + 1
                if chunk_idx < len(regular_chunks):
                    _send_regular_chunk(regular_chunks[chunk_idx])

            af_sock.close()
        except Exception as e:
            logger.error(f"AF_PACKET error: {e}")
            errors = total_packets
    else:
        # Fallback for non-WireGuard (simplified, no wave mode)
        from scapy.all import send as scapy_send
        all_packets = burst_packets + regular_packets
        rng.shuffle(all_packets)
        for i in range(0, len(all_packets), 50):
            batch = all_packets[i:i + 50]
            try:
                scapy_send(batch, verbose=0)
            except Exception:
                errors += len(batch)

    total_elapsed = time.time() - send_start
    pps = total_packets / total_elapsed if total_elapsed > 0 else 0

    logger.debug(f"TRAFFIC[{tunnel_interface}]: {total_packets} pkts in {total_elapsed:.1f}s ({pps:.0f} pps, {num_waves} waves)")

    return (total_packets, seq_start, seq_end, errors)


class RealPacketSender:
    """
    Sends REAL network packets to test scrubber filtering.

    This is the ground truth - we know exactly what we sent,
    and the miner must prove their XDP actually processed it.
    """

    # All RFC bogon ranges
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

    # Known malicious prefixes
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

    # Legitimate prefixes for benign traffic
    LEGITIMATE_PREFIXES = [
        1, 8, 13, 15, 16, 17, 18, 19, 20, 23,
        32, 33, 34, 35, 38, 40, 44, 45, 47, 48,
        52, 54, 56, 57, 104, 142, 143, 144, 146, 147,
        204, 205, 206, 207, 208, 209,
    ]

    # Common target ports - HTTP ports for L7 detection (Slowloris, HTTP flood)
    TARGET_PORTS = [80, 443, 8080, 8443, 3000, 8000]
    HTTP_PORTS = TARGET_PORTS  # Alias for clarity

    # Non-HTTP ports for general SYN flood detection (not L7)
    # SYN packets to HTTP ports are detected as Slowloris, not SYN flood
    NON_HTTP_PORTS = [22, 25, 110, 143, 993, 995, 3306, 5432, 6379, 27017]

    def __init__(
        self,
        base_attack_count: int = 500,
        base_benign_count: int = 100,
    ):
        """
        Initialize the real packet sender.

        Args:
            base_attack_count: Base number of attack packets (randomized ±50%)
            base_benign_count: Base number of benign packets (5:1 ratio)
        """
        self.base_attack_count = base_attack_count
        self.base_benign_count = base_benign_count

        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is required for real packet sending. "
                "Install with: pip install scapy"
            )

        # Configure scapy for performance
        conf.verb = 0  # Disable verbose output

        # Per-audit entropy for non-gameability
        self._audit_seed: int = 0
        self._audit_rng: random.Random = random.Random()

        # Attack IP pool for concentrated rate-limited traffic
        self._attack_ip_pool: List[str] = []
        self._attack_ip_weights: List[float] = []

    def _initialize_audit_entropy(self) -> None:
        """
        Initialize per-audit random state for non-gameability.

        Each audit gets fresh cryptographic seed, making patterns
        unpredictable between audits.
        """
        self._audit_seed = secrets.randbits(64)
        self._audit_rng = random.Random(self._audit_seed)
        logger.debug(f"Audit entropy initialized: seed={self._audit_seed & 0xFFFF:04x}")

    def _initialize_attack_ip_pool(self, rate_limited_count: int) -> None:
        """
        Initialize attack IP pool for concentrated traffic patterns.

        NON-GAMEABILITY:
        - Pool size is randomized (not fixed)
        - IP distribution is non-uniform (some IPs get more traffic)
        - Simulates real botnet behavior
        """
        # Randomized pool size
        pool_size = self._audit_rng.randint(ATTACK_POOL_SIZE_MIN, ATTACK_POOL_SIZE_MAX)

        # Adjust if needed to ensure concentrated traffic
        min_per_source = 30  # Minimum packets per source to trigger rate limiting
        if rate_limited_count > 0 and rate_limited_count / pool_size < min_per_source:
            pool_size = max(3, rate_limited_count // min_per_source)

        # Generate IPs
        self._attack_ip_pool = [
            self._generate_spoofed_ip() for _ in range(pool_size)
        ]

        # Non-uniform weights (Pareto distribution - some IPs are "hotter")
        raw_weights = [self._audit_rng.paretovariate(1.5) for _ in range(pool_size)]
        total_weight = sum(raw_weights)
        self._attack_ip_weights = [w / total_weight for w in raw_weights]

        logger.debug(
            f"Attack IP pool: {pool_size} IPs for {rate_limited_count} rate-limited packets"
        )

    def _get_attack_source_ip(self) -> str:
        """Get source IP from attack pool using weighted random selection."""
        if not self._attack_ip_pool:
            return self._generate_spoofed_ip()

        return self._audit_rng.choices(
            self._attack_ip_pool,
            weights=self._attack_ip_weights,
            k=1
        )[0]

    def _generate_random_payload(self, min_size: int = 16, max_size: int = 128) -> bytes:
        """
        Generate random payload that looks like real traffic.

        NON-GAMEABILITY: No identifiable markers.
        """
        size = self._audit_rng.randint(min_size, max_size)
        pattern = self._audit_rng.randint(0, 3)

        if pattern == 0:
            return bytes(self._audit_rng.randint(0, 255) for _ in range(size))
        elif pattern == 1:
            return ''.join(self._audit_rng.choices(string.printable[:62], k=size)).encode()
        elif pattern == 2:
            return str({f'k{i}': self._audit_rng.randint(1, 9999) for i in range(3)}).encode()[:size]
        else:
            return '&'.join(f'p{i}={self._audit_rng.randint(1,999)}' for i in range(3)).encode()[:size]

    def _generate_challenge_id(self) -> str:
        """Generate unique challenge ID."""
        return f"audit-{uuid.uuid4().hex[:12]}-{int(time.time())}"

    def _generate_nonce(self) -> str:
        """Generate challenge nonce to embed in packets."""
        return secrets.token_hex(8)

    def _randomize_counts(
        self,
        attack_override: Optional[int] = None,
        benign_override: Optional[int] = None,
    ) -> Tuple[int, int]:
        """
        Randomize attack/benign counts with dynamic ratio.

        Benign:attack ratio randomized between 1:3 and 1:10 per round
        to prevent miners from predicting traffic patterns.

        Args:
            attack_override: If provided, use this as base instead of self.base_attack_count
            benign_override: If provided, use this as base instead of self.base_benign_count
        """
        base_attack = attack_override if attack_override is not None else self.base_attack_count
        base_benign = benign_override if benign_override is not None else self.base_benign_count

        # Attack variation: ±50%
        attack_var = random.uniform(0.5, 1.5)
        attack = max(50, int(base_attack * attack_var))

        # Dynamic benign:attack ratio (1:3 to 1:10)
        if benign_override is not None:
            benign_var = random.uniform(0.5, 1.5)
            benign = max(25, int(base_benign * benign_var))
        else:
            benign_ratio = random.uniform(0.1, 0.333)
            benign = max(50, int(attack * benign_ratio))

        return attack, benign

    def _randomize_distribution(self, total: int) -> Dict[str, int]:
        """
        Randomize distribution across all attack types.

        Categories and their weights (representative of real-world attacks):
        - Layer 3/4 IP attacks (bogon, blacklist): ~20%
        - TCP attacks (SYN, XMAS, NULL, FIN, RST, ACK): ~30%
        - UDP attacks (flood, DNS amp, NTP amp, memcached): ~20%
        - ICMP attacks (flood, frag): ~10%
        - Fragmentation attacks: ~5%
        - Layer 7 attacks (slowloris, HTTP flood): ~10%
        - Malformed: ~5%
        """
        # Define category weights (sum to 1.0)
        category_weights = {
            "layer3_ip": 0.18,      # IP-based attacks
            "layer4_tcp": 0.30,     # TCP attacks (most common)
            "layer4_udp": 0.20,     # UDP attacks
            "layer3_icmp": 0.10,    # ICMP attacks
            "fragmentation": 0.05,  # Fragment attacks
            "layer7": 0.10,         # Application layer
            "malformed": 0.05,      # Malformed packets
            "land_attack": 0.02,    # Land attack (src == dst)
        }

        # Add randomness to weights (±30%)
        for k in category_weights:
            category_weights[k] *= random.uniform(0.7, 1.3)

        # Normalize
        total_weight = sum(category_weights.values())
        for k in category_weights:
            category_weights[k] /= total_weight

        dist = {}

        # Layer 3/4 IP attacks (bogon + blacklist only — XDP can reliably detect these)
        ip_count = int(total * category_weights["layer3_ip"])
        dist["bogon"] = ip_count // 2
        dist["blacklist"] = ip_count - dist["bogon"]

        # TCP attacks (8 types - includes synfin and synrst)
        tcp_count = int(total * category_weights["layer4_tcp"])
        tcp_per_type = tcp_count // 8
        dist["syn_flood"] = tcp_per_type + tcp_count % 8  # SYN flood gets extra
        dist["tcp_xmas"] = tcp_per_type
        dist["tcp_null"] = tcp_per_type
        dist["tcp_fin"] = tcp_per_type
        dist["tcp_rst"] = tcp_per_type
        dist["tcp_ack"] = tcp_per_type
        dist["tcp_synfin"] = tcp_per_type
        dist["tcp_synrst"] = tcp_per_type

        # UDP attacks (7 types including new amplification variants)
        udp_count = int(total * category_weights["layer4_udp"])
        udp_per_type = udp_count // 7
        dist["udp_flood"] = udp_per_type + udp_count % 7
        dist["udp_amp_dns"] = udp_per_type
        dist["udp_amp_ntp"] = udp_per_type
        dist["udp_amp_memcached"] = udp_per_type
        dist["udp_amp_ssdp"] = udp_per_type
        dist["udp_amp_snmp"] = udp_per_type
        dist["udp_amp_chargen"] = udp_per_type

        # ICMP attacks (2 types)
        icmp_count = int(total * category_weights["layer3_icmp"])
        dist["icmp_flood"] = icmp_count // 2 + icmp_count % 2
        dist["icmp_frag"] = icmp_count // 2

        # Fragmentation attacks (2 types)
        frag_count = int(total * category_weights["fragmentation"])
        dist["frag_overlap"] = frag_count // 2 + frag_count % 2
        dist["frag_tiny"] = frag_count // 2

        # Layer 7 attacks (2 types)
        l7_count = int(total * category_weights["layer7"])
        dist["slowloris"] = l7_count // 2 + l7_count % 2
        dist["http_flood"] = l7_count // 2

        # Malformed
        dist["malformed"] = int(total * category_weights["malformed"])

        # Land attack
        dist["land_attack"] = int(total * category_weights["land_attack"])

        # Ensure we hit the target total
        current_total = sum(dist.values())
        if current_total < total:
            dist["syn_flood"] += total - current_total
        elif current_total > total:
            dist["malformed"] = max(0, dist["malformed"] - (current_total - total))

        return dist

    def _ip_from_prefix(self, prefix: str, mask: int) -> str:
        """Generate random IP from prefix/mask."""
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
        """Generate random bogon IP."""
        prefix, mask = random.choice(self.BOGON_RANGES)
        return self._ip_from_prefix(prefix, mask)

    def _generate_blacklist_ip(self) -> str:
        """Generate random IP from malicious prefixes."""
        prefix, mask = random.choice(self.MALICIOUS_PREFIXES)
        return self._ip_from_prefix(prefix, mask)

    def _generate_legitimate_ip(self) -> str:
        """Generate random legitimate IP."""
        first = random.choice(self.LEGITIMATE_PREFIXES)
        return f"{first}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def _generate_spoofed_ip(self) -> str:
        """Generate random spoofed IP (any public range)."""
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _build_packet(
        self,
        spec: PacketSpec,
        nonce: str,
        seq_num: int,
    ):
        """
        Build a real scapy packet from spec.

        NON-GAMEABILITY:
        - NO identifiable audit markers in payload
        - Packets are indistinguishable from real traffic
        - The nonce/seq_num are tracked internally, not embedded in payload

        NOTE: For FRAG_TINY and MALFORMED attacks, we use minimal payloads
        to ensure packets meet size requirements for XDP detection.
        """
        # For FRAG_TINY, use minimal payload to keep packet small
        # XDP check: MF && tot_len < 68 - must be under 68 bytes total
        if spec.attack_type == AttackType.FRAG_TINY:
            # IP(20) + UDP(8) + payload(8) = 36 bytes < 68 bytes
            payload = spec.payload  # Use raw payload without any header
        elif spec.is_malformed:
            # Malformed packets may not reach scrubber due to kernel validation
            # Use minimal random payload
            payload = self._generate_random_payload(8, 20)
        else:
            # Normal packets: Use random payload (NO audit markers)
            # This makes packets indistinguishable from real traffic
            if spec.payload:
                payload = spec.payload
            else:
                payload = self._generate_random_payload(16, 64)

        # Build IP layer with optional fragmentation flags
        ip_kwargs = {"src": spec.source_ip, "dst": spec.dest_ip}
        if spec.ip_flags:
            ip_kwargs["flags"] = spec.ip_flags
        if spec.ip_frag_offset > 0:
            ip_kwargs["frag"] = spec.ip_frag_offset

        # Handle malformed packets - create invalid IP header length
        if spec.is_malformed:
            # Create packet with invalid IHL (header length)
            # IHL=2 means 8 bytes, but minimum valid is 20 bytes (IHL=5)
            ip_kwargs["ihl"] = 2  # Invalid: claims 8 bytes but needs 20
            ip = IP(**ip_kwargs)
            # For malformed, just return raw IP with garbage
            return ip / Raw(load=payload)

        # Handle fragment packets with offset > 0 (no transport header)
        if spec.ip_frag_offset > 0:
            # Set protocol explicitly since we're not adding transport layer
            # Scapy defaults to proto=0 when only Raw is attached
            if spec.protocol == "TCP":
                ip_kwargs["proto"] = 6  # IPPROTO_TCP
            elif spec.protocol == "UDP":
                ip_kwargs["proto"] = 17  # IPPROTO_UDP
            elif spec.protocol == "ICMP":
                ip_kwargs["proto"] = 1  # IPPROTO_ICMP
            ip = IP(**ip_kwargs)
            return ip / Raw(load=payload)

        ip = IP(**ip_kwargs)

        if spec.protocol == "TCP":
            transport = TCP(
                sport=spec.source_port,
                dport=spec.dest_port,
                flags=spec.tcp_flags,
            )
        elif spec.protocol == "UDP":
            transport = UDP(
                sport=spec.source_port,
                dport=spec.dest_port,
            )
        elif spec.protocol == "ICMP":
            transport = ICMP()
        else:
            transport = TCP(
                sport=spec.source_port,
                dport=spec.dest_port,
                flags="S",
            )

        return ip / transport / Raw(load=payload)

    def _generate_dns_query_payload(self) -> bytes:
        """Generate a DNS query payload for amplification attack."""
        # DNS query for ANY record (amplification)
        # Transaction ID + flags + questions + answers + authority + additional
        dns_header = b'\x00\x01'  # Transaction ID
        dns_header += b'\x01\x00'  # Flags: standard query
        dns_header += b'\x00\x01'  # Questions: 1
        dns_header += b'\x00\x00'  # Answer RRs: 0
        dns_header += b'\x00\x00'  # Authority RRs: 0
        dns_header += b'\x00\x00'  # Additional RRs: 0
        # Query: random domain, type ANY, class IN
        domain = f"test{random.randint(1000, 9999)}.example.com"
        query = b''
        for part in domain.split('.'):
            query += bytes([len(part)]) + part.encode()
        query += b'\x00'  # Null terminator
        query += b'\x00\xff'  # Type: ANY (255)
        query += b'\x00\x01'  # Class: IN
        return dns_header + query

    def _generate_ntp_monlist_payload(self) -> bytes:
        """Generate NTP monlist payload for amplification attack."""
        # NTP mode 7, private, REQ_MON_GETLIST
        return b'\x17\x00\x03\x2a' + b'\x00' * 4

    def _generate_memcached_payload(self) -> bytes:
        """Generate memcached stats payload for amplification attack."""
        return b'\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n'

    def _generate_ssdp_payload(self) -> bytes:
        """Generate SSDP M-SEARCH payload for amplification attack."""
        # SSDP M-SEARCH request that triggers large responses
        ssdp = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        )
        return ssdp.encode()

    def _generate_snmp_payload(self) -> bytes:
        """Generate SNMP GetBulk request for amplification attack."""
        # SNMPv2c GetBulk request - community string "public"
        # This is a simplified payload that triggers large responses
        return bytes([
            0x30, 0x26,  # SEQUENCE
            0x02, 0x01, 0x01,  # version: v2c (1)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # community: "public"
            0xa5, 0x19,  # GetBulkRequest
            0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # request-id
            0x02, 0x01, 0x00,  # non-repeaters
            0x02, 0x02, 0x00, 0x64,  # max-repetitions: 100
            0x30, 0x0a,  # variable-bindings
            0x30, 0x08,
            0x06, 0x04, 0x2b, 0x06, 0x01, 0x02,  # OID: 1.3.6.1.2 (system tree)
            0x05, 0x00  # NULL value
        ])

    def _generate_chargen_payload(self) -> bytes:
        """Generate chargen payload for amplification attack."""
        # Simple payload - chargen responds with 72 bytes per byte received
        return b'x' * 64

    def _generate_slowloris_payload(self) -> bytes:
        """Generate partial HTTP request (slowloris attack)."""
        headers = [
            f"GET /?{random.randint(1, 99999)} HTTP/1.1\r\n",
            f"Host: target.example.com\r\n",
            f"User-Agent: Mozilla/5.0 (compatible; audit-{random.randint(1, 9999)})\r\n",
            f"Accept: text/html,application/xhtml+xml\r\n",
            f"X-a: {random.randint(1, 99999)}\r\n",
            # Note: NO final \r\n - this keeps connection open (slowloris)
        ]
        return ''.join(headers).encode()

    def _generate_http_flood_payload(self) -> bytes:
        """Generate HTTP flood request."""
        methods = ["GET", "POST", "HEAD"]
        paths = ["/", "/api/", "/login", "/search", f"/page/{random.randint(1, 9999)}"]
        request = f"{random.choice(methods)} {random.choice(paths)} HTTP/1.1\r\n"
        request += f"Host: target.example.com\r\n"
        request += f"User-Agent: Mozilla/5.0 (audit-{random.randint(1, 9999)})\r\n"
        request += f"Accept: */*\r\n"
        request += f"Connection: keep-alive\r\n"
        request += f"\r\n"
        return request.encode()

    def _generate_packet_specs(
        self,
        dest_ip: str,
        attack_count: int,
        benign_count: int,
        distribution: Dict[str, int],
    ) -> List[PacketSpec]:
        """
        Generate comprehensive packet specifications for all attack types.

        This creates packets representing ALL attack vectors that a DDoS
        scrubber should handle in production.
        """
        specs = []

        # ===== Layer 3/4 IP-based attacks =====

        # Bogon source addresses
        for _ in range(distribution.get("bogon", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.BOGON,
                source_ip=self._generate_bogon_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.choice(self.TARGET_PORTS),
                protocol=random.choice(["TCP", "UDP"]),
                should_be_blocked=True,
            ))

        # Blacklist IPs
        for _ in range(distribution.get("blacklist", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.BLACKLIST,
                source_ip=self._generate_blacklist_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.choice(self.TARGET_PORTS),
                protocol=random.choice(["TCP", "UDP"]),
                should_be_blocked=True,
            ))

        # ===== Layer 4 TCP attacks =====

        # SYN flood - rapid SYN packets (tests SYN cookies)
        # Use NON-HTTP ports so SYN flood is detected separately from Slowloris
        # (SYN packets to HTTP ports are classified as Slowloris L7 attacks)
        # NON-GAMEABILITY: Use concentrated IPs from attack pool to trigger rate limiting
        for _ in range(distribution.get("syn_flood", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.SYN_FLOOD,
                source_ip=self._get_attack_source_ip(),  # Concentrated sources
                dest_ip=dest_ip,
                source_port=self._audit_rng.randint(1024, 65535),
                dest_port=self._audit_rng.choice(self.NON_HTTP_PORTS),
                protocol="TCP",
                tcp_flags="S",  # SYN only
                should_be_blocked=True,
            ))

        # Christmas tree packets (all flags set)
        for _ in range(distribution.get("tcp_xmas", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.TCP_XMAS,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.choice(self.TARGET_PORTS),
                protocol="TCP",
                tcp_flags="FSRPAUEC",  # All flags - Christmas tree
                should_be_blocked=True,
            ))

        # NULL packets (no flags)
        for _ in range(distribution.get("tcp_null", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.TCP_NULL,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.choice(self.TARGET_PORTS),
                protocol="TCP",
                tcp_flags="",  # No flags
                should_be_blocked=True,
            ))

        # FIN scan packets
        for _ in range(distribution.get("tcp_fin", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.TCP_FIN_SCAN,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.choice(self.TARGET_PORTS),
                protocol="TCP",
                tcp_flags="F",  # FIN only
                should_be_blocked=True,
            ))

        # RST flood - use concentrated IPs for rate limiting
        for _ in range(distribution.get("tcp_rst", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.TCP_RST_FLOOD,
                source_ip=self._get_attack_source_ip(),  # Concentrated sources
                dest_ip=dest_ip,
                source_port=self._audit_rng.randint(1024, 65535),
                dest_port=self._audit_rng.choice(self.TARGET_PORTS),
                protocol="TCP",
                tcp_flags="R",  # RST only
                should_be_blocked=True,
            ))

        # ACK flood (state exhaustion) - use concentrated IPs for rate limiting
        for _ in range(distribution.get("tcp_ack", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.TCP_ACK_FLOOD,
                source_ip=self._get_attack_source_ip(),  # Concentrated sources
                dest_ip=dest_ip,
                source_port=self._audit_rng.randint(1024, 65535),
                dest_port=self._audit_rng.choice(self.TARGET_PORTS),
                protocol="TCP",
                tcp_flags="A",  # ACK only (no state)
                should_be_blocked=True,
            ))

        # SYN+FIN invalid combination
        for _ in range(distribution.get("tcp_synfin", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.TCP_SYNFIN,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.choice(self.TARGET_PORTS),
                protocol="TCP",
                tcp_flags="SF",  # SYN+FIN (invalid)
                should_be_blocked=True,
            ))

        # SYN+RST invalid combination
        for _ in range(distribution.get("tcp_synrst", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.TCP_SYNRST,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.choice(self.TARGET_PORTS),
                protocol="TCP",
                tcp_flags="SR",  # SYN+RST (invalid)
                should_be_blocked=True,
            ))

        # ===== Layer 4 UDP attacks =====

        # Basic UDP flood - use concentrated IPs for rate limiting
        for _ in range(distribution.get("udp_flood", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.UDP_FLOOD,
                source_ip=self._get_attack_source_ip(),  # Concentrated sources
                dest_ip=dest_ip,
                source_port=self._audit_rng.randint(1024, 65535),
                dest_port=self._audit_rng.randint(10000, 60000),  # Non-amp ports for rate-limit testing
                protocol="UDP",
                payload=self._generate_random_payload(64, 512),
                should_be_blocked=True,
            ))

        # DNS amplification - XDP checks BOTH source AND dest ports
        # Use DEST port for audit (kernel blocks low source ports in userspace raw sockets)
        for _ in range(distribution.get("udp_amp_dns", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.UDP_AMP_DNS,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=53,  # Amp port as DEST (kernel blocks low source ports)
                protocol="UDP",
                payload=self._generate_dns_query_payload(),
                should_be_blocked=True,
            ))

        # NTP amplification
        for _ in range(distribution.get("udp_amp_ntp", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.UDP_AMP_NTP,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=123,  # Amp port as DEST
                protocol="UDP",
                payload=self._generate_ntp_monlist_payload(),
                should_be_blocked=True,
            ))

        # Memcached amplification
        for _ in range(distribution.get("udp_amp_memcached", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.UDP_AMP_MEMCACHED,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=11211,  # Amp port as DEST
                protocol="UDP",
                payload=self._generate_memcached_payload(),
                should_be_blocked=True,
            ))

        # SSDP amplification (UPnP)
        for _ in range(distribution.get("udp_amp_ssdp", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.UDP_AMP_SSDP,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=1900,  # Amp port as DEST
                protocol="UDP",
                payload=self._generate_ssdp_payload(),
                should_be_blocked=True,
            ))

        # SNMP amplification
        for _ in range(distribution.get("udp_amp_snmp", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.UDP_AMP_SNMP,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=161,  # Amp port as DEST
                protocol="UDP",
                payload=self._generate_snmp_payload(),
                should_be_blocked=True,
            ))

        # Chargen amplification
        for _ in range(distribution.get("udp_amp_chargen", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.UDP_AMP_CHARGEN,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=19,  # Amp port as DEST
                protocol="UDP",
                payload=self._generate_chargen_payload(),
                should_be_blocked=True,
            ))

        # ===== Layer 3 ICMP attacks =====

        # ICMP flood (ping flood) - use concentrated IPs for rate limiting
        for _ in range(distribution.get("icmp_flood", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.ICMP_FLOOD,
                source_ip=self._get_attack_source_ip(),  # Concentrated sources
                dest_ip=dest_ip,
                source_port=0,
                dest_port=0,
                protocol="ICMP",
                # Limit to 1200 bytes to fit within WireGuard MTU (1380 - headers)
                payload=self._generate_random_payload(64, 1200),
                should_be_blocked=True,
            ))

        # ICMP fragmentation attack
        for _ in range(distribution.get("icmp_frag", 0)):
            # ICMP packet near MTU limit to test fragmentation handling
            # Reduced from 2000 to 1200 to fit within WireGuard MTU
            specs.append(PacketSpec(
                attack_type=AttackType.ICMP_FRAG,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=0,
                dest_port=0,
                protocol="ICMP",
                payload=bytes([random.randint(0, 255) for _ in range(1200)]),
                should_be_blocked=True,
            ))

        # ===== Fragmentation attacks =====
        # These set IP fragmentation flags that XDP will detect

        for _ in range(distribution.get("frag_overlap", 0)):
            # Simulate middle/last fragment with non-zero offset
            # XDP blocks any fragmented packet (MF set or offset > 0)
            specs.append(PacketSpec(
                attack_type=AttackType.FRAG_OVERLAP,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=0,  # No valid port for fragment
                dest_port=0,
                protocol="UDP",  # Still need protocol for packet building
                payload=bytes([random.randint(0, 255) for _ in range(100)]),
                should_be_blocked=True,
                ip_frag_offset=10,  # Non-zero offset indicates middle/last fragment
            ))

        for _ in range(distribution.get("frag_tiny", 0)):
            # Tiny fragment attack: very small fragment with MF set
            # XDP blocks: first fragment with MF and tot_len < 68
            specs.append(PacketSpec(
                attack_type=AttackType.FRAG_TINY,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.choice(self.TARGET_PORTS),
                protocol="UDP",
                payload=bytes([0x41] * 8),  # Very small payload
                should_be_blocked=True,
                ip_flags="MF",  # More Fragments flag
            ))

        # ===== Layer 7 Application attacks =====

        # Slowloris (partial HTTP requests)
        for _ in range(distribution.get("slowloris", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.SLOWLORIS,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=80,
                protocol="TCP",
                tcp_flags="PA",  # PSH+ACK (data packet)
                payload=self._generate_slowloris_payload(),
                should_be_blocked=True,
            ))

        # HTTP flood
        for _ in range(distribution.get("http_flood", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.HTTP_FLOOD,
                source_ip=self._generate_spoofed_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.choice([80, 443, 8080]),
                protocol="TCP",
                tcp_flags="PA",  # PSH+ACK
                payload=self._generate_http_flood_payload(),
                should_be_blocked=True,
            ))

        # ===== Malformed packets =====
        # Create packets with invalid IP header length (IHL=2 instead of 5+)
        # XDP's validate_ip_header() checks iph->ihl < 5 and drops

        for _ in range(distribution.get("malformed", 0)):
            malformed_payload = bytes([random.randint(0, 255) for _ in range(random.randint(20, 100))])
            specs.append(PacketSpec(
                attack_type=AttackType.MALFORMED,
                source_ip=self._generate_legitimate_ip(),
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.choice(self.TARGET_PORTS),
                protocol=random.choice(["TCP", "UDP"]),
                payload=malformed_payload,
                should_be_blocked=True,
                is_malformed=True,  # Creates invalid IP header (IHL < 5)
            ))

        # ===== Land attack (source IP == destination IP) =====
        # This is an invalid packet where src == dst, which XDP should block

        for _ in range(distribution.get("land_attack", 0)):
            specs.append(PacketSpec(
                attack_type=AttackType.LAND_ATTACK,
                source_ip=dest_ip,  # Source IP == Destination IP (Land attack)
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.choice(self.TARGET_PORTS),
                protocol=random.choice(["TCP", "UDP"]),
                tcp_flags="S" if random.random() > 0.5 else "PA",
                payload=bytes([random.randint(0, 255) for _ in range(random.randint(32, 128))]),
                should_be_blocked=True,
            ))

        # ===== Benign traffic (should pass) =====
        # IMPORTANT: Benign traffic represents ESTABLISHED connections, NOT new SYNs.
        # - Real benign traffic is mostly established connections (ACK, PSH+ACK)
        # - SYN packets are for NEW connections and hit GLOBAL_SYN_LIMIT (12.5/sec)
        # - Using SYN for benign would cause false positives when rate is high
        # - UDP benign uses high ports (not amplification ports) to avoid amp detection

        for _ in range(benign_count):
            # 70% TCP (established), 30% UDP (high ports)
            # NOTE: No ICMP - rate limiting during attack bursts causes false positives
            proto_roll = random.random()
            if proto_roll < 0.3:
                # Benign UDP (high ports, NOT amplification ports) - 30% of benign
                specs.append(PacketSpec(
                    attack_type=None,  # Benign
                    source_ip=self._generate_legitimate_ip(),
                    dest_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    # Use high destination ports (not amp ports like 53, 123, 1900, etc.)
                    dest_port=random.randint(8000, 65535),
                    protocol="UDP",
                    payload=bytes([random.randint(0, 255) for _ in range(random.randint(32, 128))]),
                    should_be_blocked=False,
                ))
            else:
                # Benign TCP (ESTABLISHED connection data transfer) - 70% of benign
                # CRITICAL FLAGS:
                # - Must use PSH+ACK only - represents data packets in established connections
                # - Pure ACK (no PSH) is BLOCKED by XDP as "ACK flood" (no connection state)
                # - SYN is blocked by GLOBAL_SYN_LIMIT (12.5/sec)
                # CRITICAL PORTS:
                # - Must use non-HTTP high ports (>8000)
                # - HTTP ports (80, 443, 8080) trigger L7 HTTP flood detection for PSH+ACK
                specs.append(PacketSpec(
                    attack_type=None,  # Benign
                    source_ip=self._generate_legitimate_ip(),
                    dest_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    # Non-HTTP high ports only (8001-65535, excluding common HTTP ports)
                    dest_port=random.choice([p for p in range(8001, 65536) if p not in (8080, 8443, 8888)]),
                    protocol="TCP",
                    # PSH+ACK only - pure ACK is blocked as ACK flood!
                    tcp_flags="PA",
                    should_be_blocked=False,
                ))

        # Shuffle all packets
        random.shuffle(specs)
        return specs

    # Fallback PPS (used when dynamic calculation isn't available)
    # In practice, PPS is calculated dynamically to spread traffic over ~60 seconds
    TARGET_AUDIT_PPS: int = 500

    def _send_packet_batch(
        self,
        packets: List,
        batch_size: int = 50,
        interface: Optional[str] = None,
        target_pps: Optional[int] = None,
    ) -> int:
        """
        Send a batch of packets with rate control.

        For WireGuard (TUN) interfaces, ALL packets are sent via AF_PACKET to
        bypass kernel validation that would drop:
        - Packets with spoofed/bogon source IPs (egress filtering)
        - Packets with invalid IP headers (malformed with ihl < 5)
        - Fragmented packets (reassembly issues)

        Rate control ensures consistent audit results across validators by
        preventing high-rate bursts that trigger global rate limits.

        Args:
            packets: List of scapy packets to send.
            batch_size: Number of packets per batch.
            interface: Optional interface name to bind socket to.
            target_pps: Target packets per second (None = max speed).

        Returns number of send errors.
        """
        errors = 0
        target_pps = target_pps or self.TARGET_AUDIT_PPS

        # Calculate delay between packets for rate limiting
        # Add small buffer to account for processing overhead
        packet_delay = 1.0 / target_pps if target_pps > 0 else 0
        last_send_time = time.time()

        if interface:
            try:
                import socket as stdlib_socket

                # Check if this is a TUN interface (WireGuard)
                is_wg = interface.startswith('wg')

                if is_wg:
                    # For WireGuard TUN interfaces, use AF_PACKET with SOCK_DGRAM to send
                    # raw IP packets directly to the interface, BYPASSING kernel IP validation.
                    # This is critical for:
                    # - Malformed packets (IHL < 5): Kernel would reject invalid IP headers
                    # - Fragmented packets: Kernel would reassemble/drop fragments
                    # - Spoofed source IPs: Kernel egress filtering would block
                    #
                    # AF_PACKET SOCK_DGRAM on a TUN interface sends raw IP packets without
                    # any kernel IP stack processing - the bytes go directly to WireGuard.
                    ETH_P_IP = 0x0800
                    use_afpacket = True

                    try:
                        # Create AF_PACKET socket for raw IP packets on the TUN interface
                        af_sock = stdlib_socket.socket(
                            stdlib_socket.AF_PACKET,
                            stdlib_socket.SOCK_DGRAM,
                            stdlib_socket.htons(ETH_P_IP)
                        )
                        af_sock.bind((interface, ETH_P_IP))

                        send_start = time.time()
                        for pkt in packets:
                            try:
                                raw_bytes = bytes(pkt)
                                af_sock.send(raw_bytes)

                                # Rate control: ensure consistent PPS across validators
                                if packet_delay > 0:
                                    elapsed = time.time() - last_send_time
                                    if elapsed < packet_delay:
                                        time.sleep(packet_delay - elapsed)
                                    last_send_time = time.time()

                            except OSError as e:
                                errors += 1
                                if errors <= 10:
                                    logger.debug(f"AF_PACKET send failed: {e}")

                        total_elapsed = time.time() - send_start
                        pps = len(packets) / total_elapsed if total_elapsed > 0 else 0
                        logger.info(f"TRAFFIC: {len(packets)} pkts in {total_elapsed:.1f}s ({pps:.0f} pps)")

                        af_sock.close()
                    except PermissionError as e:
                        logger.error(f"AF_PACKET requires CAP_NET_RAW: {e}")
                        use_afpacket = False
                    except OSError as e:
                        if "No such device" in str(e) or "network is down" in str(e).lower():
                            logger.warning(f"AF_PACKET failed on TUN interface, falling back to L3RawSocket: {e}")
                            use_afpacket = False
                        else:
                            logger.error(f"AF_PACKET error: {e}")
                            use_afpacket = False
                    except Exception as e:
                        logger.error(f"AF_PACKET setup/send error: {e}")
                        use_afpacket = False

                    # Fallback to L3RawSocket if AF_PACKET failed
                    # Note: L3RawSocket may not send malformed/fragmented packets correctly
                    # due to kernel validation, but it's better than nothing
                    if not use_afpacket:
                        logger.warning("Falling back to L3RawSocket (malformed/frag packets may be blocked by kernel)")
                        from scapy.supersocket import L3RawSocket
                        try:
                            l3sock = L3RawSocket(iface=interface)
                            for pkt in packets:
                                try:
                                    l3sock.send(pkt)
                                except OSError as e:
                                    errors += 1
                                    if errors <= 10:
                                        logger.debug(f"L3RawSocket fallback send failed: {e}")
                            l3sock.close()
                        except Exception as e:
                            logger.error(f"L3RawSocket fallback failed: {e}")
                            errors = len(packets)
                else:
                    # For non-WireGuard interfaces, use raw socket with SO_BINDTODEVICE
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

                            # Rate control: ensure consistent PPS across validators
                            if packet_delay > 0:
                                elapsed = time.time() - last_send_time
                                if elapsed < packet_delay:
                                    time.sleep(packet_delay - elapsed)
                                last_send_time = time.time()
                        except Exception as e:
                            errors += 1
                            if errors <= 5:
                                logger.warning(f"Packet send error: {e}")
                    sock.close()

            except Exception as e:
                logger.error(f"Socket setup error: {e}")
                errors = len(packets)
        else:
            # Standard scapy send() with routing table
            for i in range(0, len(packets), batch_size):
                batch = packets[i:i + batch_size]
                try:
                    send(batch, verbose=0)
                except Exception as e:
                    errors += len(batch)
                    logger.warning(f"Batch send error: {e}")

        return errors

    def _build_and_send_sync(
        self,
        dest_ip: str,
        tunnel_interface: Optional[str],
        attack_count: int,
        benign_count: int,
        distribution: Dict[str, int],
        challenge_nonce: str,
    ) -> Tuple[int, int, int, int, List[str]]:
        """
        Synchronous method that builds and sends all packets.

        This runs in a thread pool to avoid blocking the async event loop.
        Returns: (total_sent, seq_start, seq_end, send_errors, packet_hashes)
        """
        # Generate packet specs
        specs = self._generate_packet_specs(
            dest_ip,
            attack_count,
            benign_count,
            distribution,
        )

        # Build actual packets with unique sequence numbers
        packets = []
        seq_start = int(time.time() * 1000) % 1000000
        seq_num = seq_start
        build_errors = 0

        for spec in specs:
            try:
                pkt = self._build_packet(spec, challenge_nonce, seq_num)
                packets.append(pkt)
                seq_num += 1
            except Exception as e:
                logger.warning(f"Failed to build packet: {e}")
                build_errors += 1

        seq_end = seq_num - 1

        # Send packets
        send_errors = self._send_packet_batch(packets, 50, tunnel_interface)

        # Skip packet hash generation - not used for verification, saves ~30% CPU time
        return (len(specs), seq_start, seq_end, build_errors + send_errors, [])

    async def send_real_traffic(
        self,
        scrubber_ip: str,
        challenge_id: Optional[str] = None,
        tunnel_interface: Optional[str] = None,
        tunnel_dest_ip: Optional[str] = None,
        attack_count_override: Optional[int] = None,
        benign_count_override: Optional[int] = None,
        audit_profile: Optional[AuditProfile] = None,
    ) -> RealTrafficResult:
        """
        Send REAL traffic to test scrubber filtering.

        This is NOT a simulation - actual packets are sent to the scrubber IP.
        Each packet has a unique sequence number for duplicate detection.

        IMPORTANT: All heavy work (packet building, sending) runs in a PROCESS POOL
        (not thread pool) to bypass Python's GIL and enable true parallelism.
        This is critical for scaling to 200+ miners - each subprocess has its own
        Python interpreter and can do CPU-bound packet serialization in parallel.

        FAIRNESS: When audit_profile is provided, all miners receive IDENTICAL
        traffic patterns. The profile contains pre-computed seed, counts, and
        distribution that are shared across all miners in a round.

        Args:
            scrubber_ip: IP of the scrubber to test (used for packet destination)
            challenge_id: Optional challenge ID (generated if not provided)
            tunnel_interface: Optional GRE tunnel interface to send through.
                             When specified, packets are sent via the tunnel,
                             allowing spoofed source IPs to reach the scrubber.
            tunnel_dest_ip: Destination IP when using tunnel (scrubber's tunnel IP).
                           If not specified, uses scrubber_ip.
            attack_count_override: Override base attack count (for differentiated audits).
            benign_count_override: Override base benign count (for differentiated audits).
            audit_profile: Optional shared audit profile for fair comparison.
                          When provided, uses the profile's seed, counts, and distribution
                          instead of generating new randomness. This ensures all miners
                          in the same round receive identical traffic.

        Returns:
            RealTrafficResult with ground truth of what was sent
        """
        # Use shared audit profile if provided (fair comparison across miners)
        # Otherwise generate new randomness (backwards compatibility / single-miner audits)
        if audit_profile:
            # FAIRNESS MODE: Use shared profile
            self._audit_seed = audit_profile.seed
            self._audit_rng = random.Random(audit_profile.seed)
            attack_count = audit_profile.attack_count
            benign_count = audit_profile.benign_count
            distribution = audit_profile.distribution.copy()
            logger.debug(f"Using shared audit profile: seed={audit_profile.seed & 0xFFFF:04x}")
        else:
            # LEGACY MODE: Generate per-miner randomness
            self._initialize_audit_entropy()
            attack_count, benign_count = self._randomize_counts(
                attack_override=attack_count_override,
                benign_override=benign_count_override,
            )
            distribution = self._randomize_distribution(attack_count)

        result = RealTrafficResult()
        result.challenge_id = challenge_id or self._generate_challenge_id()
        result.challenge_nonce = self._generate_nonce()
        result.start_time = time.time()

        # Determine actual destination IP for packets
        dest_ip = tunnel_dest_ip if tunnel_dest_ip else scrubber_ip
        via_tunnel = f" via tunnel {tunnel_interface}" if tunnel_interface else ""

        # Run ALL heavy work (packet building + sending) in PROCESS POOL
        # Using ProcessPoolExecutor bypasses Python's GIL, enabling true parallelism
        # for CPU-bound packet serialization (scapy bytes() calls)
        loop = asyncio.get_event_loop()
        process_pool = _get_process_pool()

        # Log timing to debug parallelism
        submit_time = time.time()

        # Call module-level function that can be pickled for subprocess
        total_sent, seq_start, seq_end, send_errors = await loop.run_in_executor(
            process_pool,
            _build_and_send_in_process,
            dest_ip,
            tunnel_interface,
            attack_count,
            benign_count,
            distribution,
            result.challenge_nonce,
            self._audit_seed,  # Pass seed for reproducible randomness in subprocess
            self.TARGET_AUDIT_PPS,
        )

        done_time = time.time()

        result.seq_start = seq_start
        result.seq_end = seq_end
        result.send_errors = send_errors
        result.packet_hashes = []  # Not used, skip for performance
        result.end_time = time.time()
        result.duration_seconds = result.end_time - result.start_time

        # Record what we sent (ground truth) - comprehensive tracking
        result.total_sent = total_sent
        result.attack_sent = attack_count
        result.benign_sent = benign_count

        # Layer 3/4 IP attacks
        result.bogon_sent = distribution.get("bogon", 0)
        result.blacklist_sent = distribution.get("blacklist", 0)

        # Layer 4 TCP attacks
        result.syn_flood_sent = distribution.get("syn_flood", 0)
        result.tcp_xmas_sent = distribution.get("tcp_xmas", 0)
        result.tcp_null_sent = distribution.get("tcp_null", 0)
        result.tcp_fin_sent = distribution.get("tcp_fin", 0)
        result.tcp_rst_sent = distribution.get("tcp_rst", 0)
        result.tcp_ack_sent = distribution.get("tcp_ack", 0)
        result.tcp_synfin_sent = distribution.get("tcp_synfin", 0)
        result.tcp_synrst_sent = distribution.get("tcp_synrst", 0)

        # Layer 4 UDP attacks
        result.udp_flood_sent = distribution.get("udp_flood", 0)
        result.udp_amp_dns_sent = distribution.get("udp_amp_dns", 0)
        result.udp_amp_ntp_sent = distribution.get("udp_amp_ntp", 0)
        result.udp_amp_memcached_sent = distribution.get("udp_amp_memcached", 0)
        result.udp_amp_ssdp_sent = distribution.get("udp_amp_ssdp", 0)
        result.udp_amp_snmp_sent = distribution.get("udp_amp_snmp", 0)
        result.udp_amp_chargen_sent = distribution.get("udp_amp_chargen", 0)

        # Layer 3 ICMP attacks
        result.icmp_flood_sent = distribution.get("icmp_flood", 0)
        result.icmp_frag_sent = distribution.get("icmp_frag", 0)

        # Fragmentation attacks
        result.frag_overlap_sent = distribution.get("frag_overlap", 0)
        result.frag_tiny_sent = distribution.get("frag_tiny", 0)

        # Layer 7 attacks
        result.slowloris_sent = distribution.get("slowloris", 0)
        result.http_flood_sent = distribution.get("http_flood", 0)

        # Malformed
        result.malformed_sent = distribution.get("malformed", 0)

        # Land attack
        result.land_attack_sent = distribution.get("land_attack", 0)

        if result.duration_seconds > 0:
            result.packets_per_second = result.total_sent / result.duration_seconds

        # Log concise summary
        logger.debug(
            f"Traffic sent: {result.total_sent} packets ({result.attack_sent} attack, {result.benign_sent} benign) "
            f"in {result.duration_seconds:.2f}s, {result.packets_per_second:.0f} pps"
        )

        return result


# Module-level function for easy import
async def send_real_audit_traffic(
    scrubber_ip: str,
    challenge_id: Optional[str] = None,
    attack_count: int = 500,
    benign_count: int = 100,
    tunnel_interface: Optional[str] = None,
    tunnel_dest_ip: Optional[str] = None,
) -> RealTrafficResult:
    """
    Send real audit traffic to a scrubber.

    This is the main entry point for validators to send REAL
    test traffic instead of simulated results.

    Args:
        scrubber_ip: IP of scrubber to test
        challenge_id: Optional challenge ID
        attack_count: Base attack count (randomized)
        benign_count: Base benign count (5:1 ratio)
        tunnel_interface: Optional GRE tunnel interface for sending packets.
                         Use this in cloud environments to bypass anti-spoofing.
        tunnel_dest_ip: Destination IP when using tunnel (scrubber's tunnel IP).

    Returns:
        RealTrafficResult with ground truth
    """
    sender = RealPacketSender(
        base_attack_count=attack_count,
        base_benign_count=benign_count,
    )
    return await sender.send_real_traffic(
        scrubber_ip,
        challenge_id,
        tunnel_interface=tunnel_interface,
        tunnel_dest_ip=tunnel_dest_ip,
    )
