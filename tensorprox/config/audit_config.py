"""
Audit System Configuration and Constants.

Centralizes all audit-related settings for easy tuning and deployment.
Environment variables can override defaults for production flexibility.

Usage:
    from tensorprox.config.audit_config import AUDIT_CONFIG, get_audit_config

    # Access constants
    threshold = AUDIT_CONFIG.ELIGIBILITY_THRESHOLD

    # Get config with env overrides
    config = get_audit_config()
"""

import os
from dataclasses import dataclass
from typing import Dict, List, Tuple
from enum import IntEnum


# =============================================================================
# THROUGHPUT LEVELS
# =============================================================================

class ThroughputLevel(IntEnum):
    """
    Traffic intensity levels for audits.

    Higher levels test scrubber capacity under increasing load.
    """
    LIGHT = 0       # Light traffic - baseline test
    NORMAL = 1      # Normal traffic - standard audit
    HEAVY = 2       # Heavy traffic - stress test
    STRESS = 3      # Maximum stress - capacity limit


# Packets per level for graduated testing
THROUGHPUT_PACKETS: Dict[ThroughputLevel, int] = {
    ThroughputLevel.LIGHT: 150,
    ThroughputLevel.NORMAL: 750,
    ThroughputLevel.HEAVY: 3000,
    ThroughputLevel.STRESS: 7500,
}

# Packets per second target per level
THROUGHPUT_PPS: Dict[ThroughputLevel, int] = {
    ThroughputLevel.LIGHT: 50,
    ThroughputLevel.NORMAL: 250,
    ThroughputLevel.HEAVY: 1000,
    ThroughputLevel.STRESS: 2500,
}


# =============================================================================
# SCORING CONSTANTS
# =============================================================================

# EMA smoothing factor (higher = more weight on recent scores)
EMA_ALPHA: float = float(os.getenv("AUDIT_EMA_ALPHA", "0.3"))

# Variance tracking smoothing factor
VARIANCE_ALPHA: float = float(os.getenv("AUDIT_VARIANCE_ALPHA", "0.2"))

# Variance threshold - above this triggers stability penalty
VARIANCE_THRESHOLD: float = float(os.getenv("AUDIT_VARIANCE_THRESHOLD", "0.15"))

# Stability scoring components
STABILITY_BASE: float = float(os.getenv("AUDIT_STABILITY_BASE", "0.80"))
STABILITY_BONUS: float = float(os.getenv("AUDIT_STABILITY_BONUS", "0.20"))

# Minimum audits before eligibility for rankings
MINIMUM_AUDITS_FOR_ELIGIBILITY: int = int(
    os.getenv("AUDIT_MIN_AUDITS_ELIGIBILITY", "3")
)

# Eligibility threshold - minimum score to be considered for rewards
ELIGIBILITY_THRESHOLD: float = float(
    os.getenv("AUDIT_ELIGIBILITY_THRESHOLD", "0.3")
)


# =============================================================================
# WEIGHT COMPUTATION
# =============================================================================

# Weight formula: VOLUME_WEIGHT * volume_score + AUDIT_WEIGHT * audit_score
VOLUME_WEIGHT: float = float(os.getenv("AUDIT_VOLUME_WEIGHT", "0.7"))
AUDIT_WEIGHT: float = float(os.getenv("AUDIT_AUDIT_WEIGHT", "0.3"))

# Throughput bonus multipliers by level achieved
# Level 0 = 0%, Level 1 = 5%, Level 2 = 10%, Level 3 = 20%
THROUGHPUT_BONUS: Dict[int, float] = {
    0: 0.00,
    1: 0.05,
    2: 0.10,
    3: 0.20,
}


# =============================================================================
# AUDIT TIMING
# =============================================================================

# Default audit round interval (seconds)
AUDIT_INTERVAL_SECONDS: int = int(os.getenv("AUDIT_INTERVAL_SECONDS", "300"))

# Synapse timeout for commit/reveal phases
SYNAPSE_TIMEOUT_SECONDS: float = float(os.getenv("AUDIT_SYNAPSE_TIMEOUT", "30.0"))

# Total timeout for graduated audit (all levels)
GRADUATED_TIMEOUT_SECONDS: float = float(
    os.getenv("AUDIT_GRADUATED_TIMEOUT", "120.0")
)

# Delay between sending commitment and starting traffic
COMMIT_TO_TRAFFIC_DELAY_MS: int = int(
    os.getenv("AUDIT_COMMIT_TRAFFIC_DELAY_MS", "100")
)

# Wait time for XDP processing after traffic sent
XDP_PROCESSING_WAIT_SECONDS: float = float(
    os.getenv("AUDIT_XDP_PROCESSING_WAIT", "0.5")
)

# Pause between graduated audit levels
GRADUATED_LEVEL_PAUSE_SECONDS: float = float(
    os.getenv("AUDIT_GRADUATED_LEVEL_PAUSE", "1.0")
)


# =============================================================================
# XDP RATE LIMIT THRESHOLDS (for scoring)
# =============================================================================
#
# These match the default thresholds in the scrubber's XDP program (xdp_wg_audit.c).
# Used by the reward model to calculate expected blocked packets.
#
# Rate limiting behavior:
# - Packets 1 to threshold: ALLOWED (below limit)
# - Packets threshold+1 to end: BLOCKED (limit exceeded)
#
# Scoring: actual_blocked / expected_blocked
# This rewards scrubbers that correctly block AFTER threshold is reached.

# Global rate limits (packets per rate-limit window)
XDP_RATELIMIT_SYN: int = int(os.getenv("XDP_RATELIMIT_SYN", "25"))
XDP_RATELIMIT_UDP: int = int(os.getenv("XDP_RATELIMIT_UDP", "35"))
XDP_RATELIMIT_ICMP: int = int(os.getenv("XDP_RATELIMIT_ICMP", "20"))
XDP_RATELIMIT_APP: int = int(os.getenv("XDP_RATELIMIT_APP", "25"))  # Slowloris

# Rate limit window in seconds (GLOBAL_RATE_WINDOW_NS = 2000ms in XDP)
XDP_RATELIMIT_WINDOW_SECONDS: float = float(os.getenv("XDP_RATELIMIT_WINDOW", "2.0"))


# =============================================================================
# MINER SELECTION
# =============================================================================

# Miners to audit per round
MINERS_PER_ROUND: int = int(os.getenv("AUDIT_MINERS_PER_ROUND", "10"))

# Minimum eligible miners to proceed with round
MIN_ELIGIBLE_MINERS: int = int(os.getenv("AUDIT_MIN_ELIGIBLE_MINERS", "3"))

# Probability of graduated (vs standard) audit
GRADUATED_AUDIT_PROBABILITY: float = float(
    os.getenv("AUDIT_GRADUATED_PROBABILITY", "0.2")
)

# Maximum concurrent challenges per miner
MAX_ACTIVE_CHALLENGES: int = int(os.getenv("AUDIT_MAX_ACTIVE_CHALLENGES", "5"))


# =============================================================================
# ATTACK PROFILES
# =============================================================================

# Profile noise factor (randomization)
PROFILE_NOISE_FACTOR: float = float(os.getenv("AUDIT_PROFILE_NOISE", "0.3"))

# Attack category names (for consistency)
class AttackCategory:
    """Standard attack category identifiers."""
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    ICMP_FLOOD = "icmp_flood"
    DNS_AMPLIFICATION = "dns_amplification"
    NTP_AMPLIFICATION = "ntp_amplification"
    SSDP_AMPLIFICATION = "ssdp_amplification"
    MEMCACHED_AMPLIFICATION = "memcached_amplification"
    TCP_FLAG_ANOMALY = "tcp_flag_anomaly"
    LAND_ATTACK = "land_attack"
    TEARDROP = "teardrop"
    SLOWLORIS = "slowloris"
    HTTP_FLOOD = "http_flood"
    BENIGN = "benign"


# Base attack profile weights
# Format: {category: (weight, min_per_round)}
DEFAULT_ATTACK_PROFILE: Dict[str, Tuple[float, int]] = {
    AttackCategory.SYN_FLOOD: (0.20, 10),
    AttackCategory.UDP_FLOOD: (0.15, 5),
    AttackCategory.ICMP_FLOOD: (0.05, 3),
    AttackCategory.DNS_AMPLIFICATION: (0.10, 5),
    AttackCategory.NTP_AMPLIFICATION: (0.08, 3),
    AttackCategory.TCP_FLAG_ANOMALY: (0.07, 3),
    AttackCategory.SLOWLORIS: (0.05, 2),
    AttackCategory.HTTP_FLOOD: (0.05, 2),
    AttackCategory.BENIGN: (0.25, 15),
}


# =============================================================================
# VERIFICATION THRESHOLDS
# =============================================================================

# Accuracy threshold for passing graduated level
GRADUATED_PASS_THRESHOLD: float = float(
    os.getenv("AUDIT_GRADUATED_PASS_THRESHOLD", "0.5")
)

# Maximum acceptable false positive rate
MAX_FALSE_POSITIVE_RATE: float = float(
    os.getenv("AUDIT_MAX_FALSE_POSITIVE_RATE", "0.10")
)


# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

# Default ports for test traffic
DEFAULT_DEST_PORT: int = 80
DNS_PORT: int = 53
NTP_PORT: int = 123
SSDP_PORT: int = 1900
MEMCACHED_PORT: int = 11211

# Source port range for generated traffic
SOURCE_PORT_MIN: int = 1024
SOURCE_PORT_MAX: int = 65535


# =============================================================================
# REALISTIC TRAFFIC PATTERN CONFIGURATION
# =============================================================================
#
# The key to accurate audit scoring is simulating REALISTIC traffic patterns:
#
# ATTACK TRAFFIC (rate-limited categories: SYN_FLOOD, UDP_FLOOD, ICMP_FLOOD, L7):
#   - Real DDoS attacks come from CONCENTRATED sources (botnets, amplifiers)
#   - Few source IPs, each sending MANY packets → high per-source rate
#   - This triggers per-source rate limiting in XDP
#
# BENIGN TRAFFIC:
#   - Real legitimate traffic comes from DISTRIBUTED sources (unique users)
#   - Many source IPs, each sending FEW packets → low per-source rate
#   - This stays BELOW per-source rate limits → passes through
#
# The XDP applies the SAME rules to ALL traffic. The difference in PATTERN
# (concentrated vs distributed) determines whether traffic is blocked.
# The scrubber does NOT know which traffic is attack vs benign.

# Number of unique source IPs for rate-limited attack traffic
# Lower = more concentrated = higher per-source rate = more likely to trigger rate limiting
# Formula: attack_packets / ATTACK_SOURCE_POOL_SIZE = packets per source
# Example: 2000 attack packets / 10 IPs = 200 packets/IP over audit duration
ATTACK_SOURCE_POOL_SIZE: int = int(os.getenv("AUDIT_ATTACK_SOURCE_POOL_SIZE", "10"))

# Minimum packets per attack source to guarantee rate limit trigger
# If calculated rate is below this, reduce pool size
ATTACK_MIN_PACKETS_PER_SOURCE: int = int(os.getenv("AUDIT_ATTACK_MIN_PPS", "50"))

# Per-source PPS budget for audit origins
# This sets the rate limit threshold - attack sources exceed it, benign sources don't
# Must be calibrated: ATTACK_PPS > threshold > BENIGN_PPS
# With pool size 10 and 2000 rate-limited packets over 2 seconds:
#   Attack per-source: 200 packets / 2 sec = 100 PPS
#   With SYN multiplier 0.1x: effective limit needs to be < 100 PPS for SYN
#   So base limit of 50 PPS → SYN effective = 5 PPS → attack at 100 PPS triggers
# Benign traffic (1 packet per source) easily stays below any threshold
AUDIT_PER_SOURCE_BUDGET_PPS: int = int(os.getenv("AUDIT_PER_SOURCE_BUDGET_PPS", "50"))

# Whether to use distributed sources for benign traffic (always True for accuracy)
# When True, each benign packet uses a unique source IP
# This ensures benign traffic never exceeds per-source rate limits
BENIGN_DISTRIBUTED_SOURCES: bool = os.getenv("AUDIT_BENIGN_DISTRIBUTED", "true").lower() == "true"

# Rate-limited attack categories that use concentrated source patterns
# These categories are detected by per-source rate limiting, not signatures
RATE_LIMITED_CATEGORIES: List[str] = [
    "syn_flood",
    "udp_flood",
    "icmp_flood",
    "l7_application",
]

# Signature-based categories that can use any source pattern
# These are detected by packet content (bogon IPs, blacklist, flags, etc.)
SIGNATURE_BASED_CATEGORIES: List[str] = [
    "bogon",
    "blacklist",
    "tcp_flag_anomaly",
    "udp_amplification",
    "fragmentation",
    "malformed",
    "land_attack",
]


# =============================================================================
# COMPETITIVE SCORING CONFIGURATION
# =============================================================================
#
# The audit system is designed to be COMPETITIVE - different miners can excel
# in different areas. This prevents a single "optimal" configuration and
# rewards genuine defense capability across multiple dimensions.
#
# NOTE: These weights are also defined in tensorprox/rewards/reward.py
# (ProductionRewardModel). The reward.py values are used for actual scoring.
# These values are for reference and can be used to configure the audit
# traffic generation distribution.
#
# AUDIT SCORE = weighted sum of 3 factors (no volume - that's in Bittensor weight):
# 1. ATTACK COVERAGE (55%): Per-category mitigation effectiveness - PRIMARY
# 2. FALSE POSITIVE (25%): Protecting legitimate traffic - CRITICAL
# 3. LATENCY (20%): RTT measurements, responsiveness

# Main scoring factor weights (must sum to 1.0)
# These align with ProductionRewardModel in reward.py
SCORING_FACTOR_WEIGHTS: Dict[str, float] = {
    "attack_coverage": float(os.getenv("AUDIT_WEIGHT_ATTACK", "0.55")),
    "false_positive": float(os.getenv("AUDIT_WEIGHT_FP", "0.25")),
    "latency": float(os.getenv("AUDIT_WEIGHT_LATENCY", "0.20")),
}

# Per-category attack weights (for attack coverage scoring)
# These align with CATEGORY_WEIGHTS in ProductionRewardModel
# Signature-based (60% total) - scored by attacks_blocked / attacks_sent
# Rate-limit (40% total) - scored binary (triggered or not)
CATEGORY_SCORING_WEIGHTS: Dict[str, float] = {
    # Signature-based categories (percentage scoring)
    "layer3_ip": float(os.getenv("AUDIT_CAT_LAYER3_IP", "0.15")),
    "layer4_tcp_flag": float(os.getenv("AUDIT_CAT_TCP_FLAG", "0.15")),
    "layer4_udp_amp": float(os.getenv("AUDIT_CAT_UDP_AMP", "0.12")),
    "fragmentation": float(os.getenv("AUDIT_CAT_FRAG", "0.10")),
    "malformed": float(os.getenv("AUDIT_CAT_MALFORMED", "0.08")),
    # Rate-limit categories (binary scoring: triggered or not)
    "ratelimit_syn": float(os.getenv("AUDIT_CAT_SYN", "0.17")),
    "ratelimit_udp": float(os.getenv("AUDIT_CAT_UDP", "0.14")),
    "ratelimit_icmp": float(os.getenv("AUDIT_CAT_ICMP", "0.05")),
    "ratelimit_app": float(os.getenv("AUDIT_CAT_APP", "0.04")),
}

# Difficulty multipliers for competitive differentiation
# Higher = more points for correctly handling (applied in traffic generation)
# Miners who excel at harder categories get differentiated
CATEGORY_DIFFICULTY_MULTIPLIERS: Dict[str, float] = {
    # Easy (signature-based, deterministic detection)
    "bogon": 1.0,
    "blacklist": 1.0,
    "land_attack": 1.0,

    # Medium (clear signatures but require proper implementation)
    "tcp_flag_anomaly": 1.2,
    "udp_amplification": 1.2,
    "fragmentation": 1.5,  # Requires fragment tracking
    "malformed": 1.3,

    # Hard (rate-limited, requires good threshold tuning)
    "syn_flood": 1.5,
    "udp_flood": 1.4,
    "icmp_flood": 1.3,
    "l7_application": 1.8,  # L7 patterns at L4 - hardest

    # Benign (critical - false positives are costly)
    "benign": 2.0,  # Double weight - FP destroys user trust
}

# Randomization ranges for non-gameability
# Pool size varies each audit
ATTACK_POOL_SIZE_MIN: int = int(os.getenv("AUDIT_POOL_SIZE_MIN", "5"))
ATTACK_POOL_SIZE_MAX: int = int(os.getenv("AUDIT_POOL_SIZE_MAX", "25"))

# Packet count jitter range (multiplicative)
PACKET_COUNT_JITTER_MIN: float = float(os.getenv("AUDIT_JITTER_MIN", "0.65"))
PACKET_COUNT_JITTER_MAX: float = float(os.getenv("AUDIT_JITTER_MAX", "1.35"))

# Profile perturbation range
PROFILE_PERTURBATION_MIN: float = float(os.getenv("AUDIT_PERTURB_MIN", "0.35"))
PROFILE_PERTURBATION_MAX: float = float(os.getenv("AUDIT_PERTURB_MAX", "0.55"))


# =============================================================================
# CONSOLIDATED CONFIG CLASS
# =============================================================================

@dataclass
class AuditSystemConfig:
    """
    Complete audit system configuration.

    Consolidates all settings for easy passing between components.
    """
    # Timing
    audit_interval_seconds: int = AUDIT_INTERVAL_SECONDS
    synapse_timeout: float = SYNAPSE_TIMEOUT_SECONDS
    graduated_timeout: float = GRADUATED_TIMEOUT_SECONDS

    # Selection
    miners_per_round: int = MINERS_PER_ROUND
    min_eligible_miners: int = MIN_ELIGIBLE_MINERS
    graduated_probability: float = GRADUATED_AUDIT_PROBABILITY

    # Scoring
    ema_alpha: float = EMA_ALPHA
    variance_alpha: float = VARIANCE_ALPHA
    variance_threshold: float = VARIANCE_THRESHOLD
    eligibility_threshold: float = ELIGIBILITY_THRESHOLD

    # Weights
    volume_weight: float = VOLUME_WEIGHT
    audit_weight: float = AUDIT_WEIGHT

    # Throughput
    default_throughput_level: int = ThroughputLevel.NORMAL

    # Verification
    graduated_pass_threshold: float = GRADUATED_PASS_THRESHOLD
    max_false_positive_rate: float = MAX_FALSE_POSITIVE_RATE

    # Profile
    profile_noise_factor: float = PROFILE_NOISE_FACTOR

    def __post_init__(self):
        """Validate configuration values."""
        assert 0 < self.ema_alpha <= 1, "EMA alpha must be in (0, 1]"
        assert 0 < self.variance_alpha <= 1, "Variance alpha must be in (0, 1]"
        assert 0 <= self.volume_weight <= 1, "Volume weight must be in [0, 1]"
        assert 0 <= self.audit_weight <= 1, "Audit weight must be in [0, 1]"
        assert abs(self.volume_weight + self.audit_weight - 1.0) < 0.01, \
            "Weights must sum to 1.0"


# Default configuration instance
AUDIT_CONFIG = AuditSystemConfig()


def get_audit_config(**overrides) -> AuditSystemConfig:
    """
    Get audit configuration with optional overrides.

    Args:
        **overrides: Field values to override

    Returns:
        AuditSystemConfig instance
    """
    return AuditSystemConfig(**overrides)


# =============================================================================
# DROP REASON CODES (must match XDP)
# =============================================================================

class DropReason(IntEnum):
    """
    XDP drop reason codes.

    Must match values in common.h
    """
    NONE = 0                    # Not dropped (passed)
    BLACKLIST = 1               # Source IP in blacklist
    BOGON = 2                   # Bogon/reserved IP
    RATE_LIMIT = 3              # Rate limit exceeded
    SYN_FLOOD = 4               # SYN flood detection
    UDP_FLOOD = 5               # UDP flood detection
    ICMP_FLOOD = 6              # ICMP flood detection
    TCP_FLAG_INVALID = 7        # Invalid TCP flag combination
    QUARANTINE = 8              # IP in quarantine
    AMPLIFICATION = 9           # Amplification attack
    FRAGMENT = 10               # Fragmented packet
    LAND_ATTACK = 11            # LAND attack (src==dst)
    L7_PATTERN = 12             # L7 pattern match (rare in XDP)


# Map drop reasons to categories
DROP_REASON_CATEGORY: Dict[DropReason, str] = {
    DropReason.BLACKLIST: AttackCategory.SYN_FLOOD,  # Often blacklisted for SYN
    DropReason.BOGON: "bogon",
    DropReason.RATE_LIMIT: "rate_limit",
    DropReason.SYN_FLOOD: AttackCategory.SYN_FLOOD,
    DropReason.UDP_FLOOD: AttackCategory.UDP_FLOOD,
    DropReason.ICMP_FLOOD: AttackCategory.ICMP_FLOOD,
    DropReason.TCP_FLAG_INVALID: AttackCategory.TCP_FLAG_ANOMALY,
    DropReason.QUARANTINE: "quarantine",
    DropReason.AMPLIFICATION: AttackCategory.DNS_AMPLIFICATION,
    DropReason.FRAGMENT: "fragment",
    DropReason.LAND_ATTACK: AttackCategory.LAND_ATTACK,
    DropReason.L7_PATTERN: AttackCategory.HTTP_FLOOD,
}


# =============================================================================
# EXPECTED ACTIONS
# =============================================================================

class ExpectedAction(IntEnum):
    """
    Expected XDP action for packet type.

    Used in scoring to handle different packet categories appropriately.
    """
    MUST_BLOCK = 0      # Deterministic block (bogon, blacklist, clear attacks)
    SHOULD_BLOCK = 1    # Probabilistic block (rate-limited traffic)
    MUST_PASS = 2       # Must pass (legitimate traffic)
    MAY_PASS = 3        # Acceptable to pass (undetectable at L3/L4)


# Scoring weights by expected action
ACTION_WEIGHTS: Dict[ExpectedAction, Dict[str, float]] = {
    # MUST_BLOCK: Full penalty for passing, full reward for blocking
    ExpectedAction.MUST_BLOCK: {
        "correct_block": 1.0,
        "incorrect_pass": -1.0,
    },
    # SHOULD_BLOCK: Partial credit for blocking, smaller penalty for passing
    ExpectedAction.SHOULD_BLOCK: {
        "correct_block": 0.8,
        "incorrect_pass": -0.5,
    },
    # MUST_PASS: Full penalty for blocking, full reward for passing
    ExpectedAction.MUST_PASS: {
        "correct_pass": 1.0,
        "incorrect_block": -1.0,  # False positive
    },
    # MAY_PASS: No penalty for passing (L7 attacks undetectable at XDP)
    ExpectedAction.MAY_PASS: {
        "correct_block": 0.5,  # Bonus if somehow detected
        "correct_pass": 0.0,  # No penalty for passing
    },
}


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    "ThroughputLevel",
    "DropReason",
    "ExpectedAction",
    "AttackCategory",

    # Throughput mappings
    "THROUGHPUT_PACKETS",
    "THROUGHPUT_PPS",

    # Scoring constants
    "EMA_ALPHA",
    "VARIANCE_ALPHA",
    "VARIANCE_THRESHOLD",
    "STABILITY_BASE",
    "STABILITY_BONUS",
    "MINIMUM_AUDITS_FOR_ELIGIBILITY",
    "ELIGIBILITY_THRESHOLD",

    # Weight constants
    "VOLUME_WEIGHT",
    "AUDIT_WEIGHT",
    "THROUGHPUT_BONUS",

    # Timing constants
    "AUDIT_INTERVAL_SECONDS",
    "SYNAPSE_TIMEOUT_SECONDS",
    "GRADUATED_TIMEOUT_SECONDS",

    # XDP rate limit thresholds (for scoring)
    "XDP_RATELIMIT_SYN",
    "XDP_RATELIMIT_UDP",
    "XDP_RATELIMIT_ICMP",
    "XDP_RATELIMIT_APP",
    "XDP_RATELIMIT_WINDOW_SECONDS",

    # Selection constants
    "MINERS_PER_ROUND",
    "MIN_ELIGIBLE_MINERS",
    "GRADUATED_AUDIT_PROBABILITY",

    # Verification thresholds
    "GRADUATED_PASS_THRESHOLD",
    "MAX_FALSE_POSITIVE_RATE",

    # Attack profiles
    "DEFAULT_ATTACK_PROFILE",
    "PROFILE_NOISE_FACTOR",

    # Drop reason mappings
    "DROP_REASON_CATEGORY",
    "ACTION_WEIGHTS",

    # Realistic traffic patterns
    "ATTACK_SOURCE_POOL_SIZE",
    "ATTACK_MIN_PACKETS_PER_SOURCE",
    "AUDIT_PER_SOURCE_BUDGET_PPS",
    "RATE_LIMITED_CATEGORIES",
    "SIGNATURE_BASED_CATEGORIES",

    # Competitive scoring (aligned with reward.py)
    "SCORING_FACTOR_WEIGHTS",
    "CATEGORY_SCORING_WEIGHTS",
    "CATEGORY_DIFFICULTY_MULTIPLIERS",

    # Randomization ranges (non-gameability)
    "ATTACK_POOL_SIZE_MIN",
    "ATTACK_POOL_SIZE_MAX",
    "PACKET_COUNT_JITTER_MIN",
    "PACKET_COUNT_JITTER_MAX",
    "PROFILE_PERTURBATION_MIN",
    "PROFILE_PERTURBATION_MAX",

    # Config class
    "AuditSystemConfig",
    "AUDIT_CONFIG",
    "get_audit_config",
]
