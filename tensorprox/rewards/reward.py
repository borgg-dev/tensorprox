"""
Production reward computation for TensorProx subnet.

Implements a comprehensive 4-factor weighted AUDIT SCORE model with full attack
category coverage scoring, optimized for real DDoS protection workloads.

AUDIT SCORE Weights (total = 100%):
1. Attack Coverage (45%): Per-category mitigation effectiveness - PRIMARY
2. False Positive Prevention (25%): Protecting legitimate traffic - CRITICAL
3. Latency (15%): RTT measurements, responsiveness
4. Availability (15%): Uptime, failover resilience - COMPETITIVE DIFFERENTIATION

NOTE: Volume is NOT in the audit score. Volume is handled in the Bittensor
weight formula: weight = 0.70 × normalized_volume + 0.30 × ema_audit_score

Attack Category Scoring ensures miners provide FULL coverage across:
- Layer 3: IP validation, bogon filtering, blacklist enforcement
- Layer 4 TCP: SYN flood, flag anomalies (XMAS, NULL, etc.)
- Layer 4 UDP: Flood protection, amplification attack mitigation
- Layer 3 ICMP: Flood protection
- Layer 7: Rate limiting (slowloris, HTTP floods)
- Fragmentation: Overlap and tiny fragment attacks

COMPETITIVE DIFFERENTIATION:
The scoring system rewards miners who excel in different areas:
- Some miners may have better rate limiting accuracy
- Others may have lower false positive rates
- Some may have better latency or availability
This prevents gaming and creates a diverse, resilient network.

Weights are configurable via environment variables (see audit_config.py).
"""

import math
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from loguru import logger

# Import configurable weights (with fallbacks for backward compatibility)
try:
    from tensorprox.config.audit_config import (
        SCORING_FACTOR_WEIGHTS,
        CATEGORY_SCORING_WEIGHTS,
        XDP_RATELIMIT_SYN,
        XDP_RATELIMIT_UDP,
        XDP_RATELIMIT_ICMP,
        XDP_RATELIMIT_APP,
        XDP_RATELIMIT_WINDOW_SECONDS,
    )
    _USE_CONFIG_WEIGHTS = True
except ImportError:
    _USE_CONFIG_WEIGHTS = False
    SCORING_FACTOR_WEIGHTS = {}
    CATEGORY_SCORING_WEIGHTS = {}
    # Fallback values matching xdp_wg_audit.c defaults
    XDP_RATELIMIT_SYN = 25
    XDP_RATELIMIT_UDP = 35
    XDP_RATELIMIT_ICMP = 20
    XDP_RATELIMIT_APP = 25
    XDP_RATELIMIT_WINDOW_SECONDS = 2.0


class AttackCategory(Enum):
    """
    Attack categories matching TensorProx protection offering.

    Categories are split into two types:
    1. SIGNATURE-BASED: All matching packets should be blocked (percentage scoring)
    2. RATE-LIMIT: Only excess traffic blocked (binary scoring: triggered or not)

    Each category represents a class of DDoS attacks that miners
    MUST be able to mitigate to receive full rewards.
    """
    # === SIGNATURE-BASED CATEGORIES (percentage scoring) ===
    LAYER3_IP = "layer3_ip"           # Spoofed IPs, bogon, blacklist
    LAYER4_TCP_FLAG = "layer4_tcp_flag"  # TCP flag anomalies (XMAS, NULL, SYN+FIN, etc.)
    LAYER4_UDP_AMP = "layer4_udp_amp"    # UDP amplification ports (DNS, NTP, SSDP, etc.)
    FRAGMENTATION = "fragmentation"   # Overlap fragments, tiny fragments
    MALFORMED = "malformed"           # Invalid headers, protocol violations

    # === RATE-LIMIT CATEGORIES (binary scoring: triggered or not) ===
    RATELIMIT_SYN = "ratelimit_syn"      # SYN flood rate limiting
    RATELIMIT_UDP = "ratelimit_udp"      # UDP flood rate limiting
    RATELIMIT_ICMP = "ratelimit_icmp"    # ICMP flood rate limiting
    RATELIMIT_TCP = "ratelimit_tcp"      # General TCP rate limiting
    RATELIMIT_APP = "ratelimit_app"      # App layer rate limiting (slowloris, HTTP)


@dataclass
class AttackCategoryMetrics:
    """
    Per-category attack metrics for granular scoring.

    Each category tracks:
    - attacks_sent: Total attack packets sent in this category
    - attacks_blocked: Attack packets correctly blocked
    - attacks_passed: Attack packets incorrectly passed (false negatives)
    - coverage_rate: attacks_blocked / attacks_sent (0-1)
    """
    attacks_sent: int = 0
    attacks_blocked: int = 0
    attacks_passed: int = 0

    @property
    def coverage_rate(self) -> float:
        """Calculate coverage rate for this category."""
        if self.attacks_sent == 0:
            return 0.0
        # Cap blocked at sent (rate limiters may count background traffic)
        effective_blocked = min(self.attacks_blocked, self.attacks_sent)
        return effective_blocked / self.attacks_sent


@dataclass
class MinerMetrics:
    """
    Production metrics for a miner based on real traffic handling.

    These metrics are collected from:
    - XDP stats (via ecp-agent health reports every 30s)
    - Exit hub traffic inspection (validator audit point)
    - Synthetic traffic simulation results (validator challenges)
    - Lifetime counters (cumulative across restarts/failovers)

    CRITICAL: Attack category metrics are REQUIRED for full scoring.
    Miners without per-category data receive penalty.
    """

    uid: int = -1

    # === VOLUME METRICS (Primary) ===
    total_bytes_processed: int = 0
    total_connections: int = 0
    origins_served: int = 0
    xdp_pass_count: int = 0

    # === LATENCY METRICS ===
    avg_rtt_ms: float = 0.0
    min_rtt_ms: float = 0.0  # Minimum RTT observed (for fallback)
    p95_rtt_ms: float = 0.0
    p99_rtt_ms: float = 0.0
    syn_synack_ratio: float = 1.0

    # === GEOLOCATION FOR DISTANCE-BASED NORMALIZATION ===
    scrubber_ip: str = ""  # Scrubber's public IP address
    validator_ip: str = ""  # Validator's public IP address

    # === AVAILABILITY METRICS ===
    uptime_percent: float = 0.0
    failover_count: int = 0
    heartbeat_misses: int = 0
    restart_count: int = 0

    # === SIGNATURE-BASED ATTACK METRICS (percentage scoring) ===
    # Layer 3 IP attacks (bogon, spoofed, blacklist)
    layer3_ip_sent: int = 0
    layer3_ip_blocked: int = 0

    # Layer 4 TCP flag attacks (XMAS, NULL, SYN+FIN, etc.) - NOT SYN flood
    layer4_tcp_flag_sent: int = 0
    layer4_tcp_flag_blocked: int = 0

    # Layer 4 UDP amplification attacks (DNS, NTP, SSDP ports) - NOT UDP flood
    layer4_udp_amp_sent: int = 0
    layer4_udp_amp_blocked: int = 0

    # Fragmentation attacks
    fragmentation_sent: int = 0
    fragmentation_blocked: int = 0

    # Malformed packet attacks
    malformed_sent: int = 0
    malformed_blocked: int = 0

    # === RATE-LIMIT ATTACK METRICS (binary scoring: triggered or not) ===
    # SYN flood (rate limited)
    ratelimit_syn_sent: int = 0
    ratelimit_syn_blocked: int = 0

    # UDP flood (rate limited) - NOT amp ports
    ratelimit_udp_sent: int = 0
    ratelimit_udp_blocked: int = 0

    # ICMP flood (rate limited)
    ratelimit_icmp_sent: int = 0
    ratelimit_icmp_blocked: int = 0

    # General TCP rate limiting
    ratelimit_tcp_sent: int = 0
    ratelimit_tcp_blocked: int = 0

    # App layer rate limiting (slowloris, HTTP flood)
    ratelimit_app_sent: int = 0
    ratelimit_app_blocked: int = 0

    # === LEGACY FIELDS (backward compatibility) ===
    layer4_tcp_sent: int = 0  # Deprecated: use layer4_tcp_flag_sent + ratelimit_syn_sent
    layer4_tcp_blocked: int = 0
    layer4_udp_sent: int = 0  # Deprecated: use layer4_udp_amp_sent + ratelimit_udp_sent
    layer4_udp_blocked: int = 0
    layer3_icmp_sent: int = 0  # Deprecated: use ratelimit_icmp_sent
    layer3_icmp_blocked: int = 0
    layer7_app_sent: int = 0  # Deprecated: use ratelimit_app_sent
    layer7_app_blocked: int = 0

    # === XDP DROP STATISTICS (granular) ===
    xdp_drop_blacklist: int = 0
    xdp_drop_ratelimit: int = 0
    xdp_drop_quarantine: int = 0
    xdp_drop_bogon: int = 0
    xdp_drop_invalid_ip: int = 0
    xdp_drop_tcp_xmas: int = 0
    xdp_drop_tcp_null: int = 0
    xdp_drop_tcp_synfin: int = 0
    xdp_drop_tcp_synrst: int = 0
    xdp_drop_syn_flood: int = 0
    xdp_drop_udp_amp: int = 0
    xdp_drop_icmp_flood: int = 0
    xdp_drop_frag: int = 0
    xdp_syncookie_challenge: int = 0

    # === BENIGN TRAFFIC METRICS ===
    benign_sent: int = 0
    benign_passed: int = 0
    benign_blocked: int = 0  # False positives

    # === LEGACY SYNTHETIC METRICS (for backward compatibility) ===
    synthetic_attack_sent: int = 0
    synthetic_benign_sent: int = 0
    attacks_detected: int = 0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    synthetic_spoofed_blocked: int = 0
    synthetic_malformed_blocked: int = 0
    synthetic_bogon_blocked: int = 0
    synthetic_blacklist_blocked: int = 0
    synthetic_benign_passed: int = 0

    def get_category_metrics(self, category: AttackCategory) -> AttackCategoryMetrics:
        """Get metrics for a specific attack category."""
        # === SIGNATURE-BASED CATEGORIES ===
        if category == AttackCategory.LAYER3_IP:
            return AttackCategoryMetrics(
                attacks_sent=self.layer3_ip_sent,
                attacks_blocked=self.layer3_ip_blocked,
                attacks_passed=max(0, self.layer3_ip_sent - self.layer3_ip_blocked)
            )
        elif category == AttackCategory.LAYER4_TCP_FLAG:
            return AttackCategoryMetrics(
                attacks_sent=self.layer4_tcp_flag_sent,
                attacks_blocked=self.layer4_tcp_flag_blocked,
                attacks_passed=max(0, self.layer4_tcp_flag_sent - self.layer4_tcp_flag_blocked)
            )
        elif category == AttackCategory.LAYER4_UDP_AMP:
            return AttackCategoryMetrics(
                attacks_sent=self.layer4_udp_amp_sent,
                attacks_blocked=self.layer4_udp_amp_blocked,
                attacks_passed=max(0, self.layer4_udp_amp_sent - self.layer4_udp_amp_blocked)
            )
        elif category == AttackCategory.FRAGMENTATION:
            return AttackCategoryMetrics(
                attacks_sent=self.fragmentation_sent,
                attacks_blocked=self.fragmentation_blocked,
                attacks_passed=max(0, self.fragmentation_sent - self.fragmentation_blocked)
            )
        elif category == AttackCategory.MALFORMED:
            return AttackCategoryMetrics(
                attacks_sent=self.malformed_sent,
                attacks_blocked=self.malformed_blocked,
                attacks_passed=max(0, self.malformed_sent - self.malformed_blocked)
            )
        # === RATE-LIMIT CATEGORIES ===
        elif category == AttackCategory.RATELIMIT_SYN:
            return AttackCategoryMetrics(
                attacks_sent=self.ratelimit_syn_sent,
                attacks_blocked=self.ratelimit_syn_blocked,
                attacks_passed=max(0, self.ratelimit_syn_sent - self.ratelimit_syn_blocked)
            )
        elif category == AttackCategory.RATELIMIT_UDP:
            return AttackCategoryMetrics(
                attacks_sent=self.ratelimit_udp_sent,
                attacks_blocked=self.ratelimit_udp_blocked,
                attacks_passed=max(0, self.ratelimit_udp_sent - self.ratelimit_udp_blocked)
            )
        elif category == AttackCategory.RATELIMIT_ICMP:
            return AttackCategoryMetrics(
                attacks_sent=self.ratelimit_icmp_sent,
                attacks_blocked=self.ratelimit_icmp_blocked,
                attacks_passed=max(0, self.ratelimit_icmp_sent - self.ratelimit_icmp_blocked)
            )
        elif category == AttackCategory.RATELIMIT_TCP:
            return AttackCategoryMetrics(
                attacks_sent=self.ratelimit_tcp_sent,
                attacks_blocked=self.ratelimit_tcp_blocked,
                attacks_passed=max(0, self.ratelimit_tcp_sent - self.ratelimit_tcp_blocked)
            )
        elif category == AttackCategory.RATELIMIT_APP:
            return AttackCategoryMetrics(
                attacks_sent=self.ratelimit_app_sent,
                attacks_blocked=self.ratelimit_app_blocked,
                attacks_passed=max(0, self.ratelimit_app_sent - self.ratelimit_app_blocked)
            )
        # Note: RATELIMIT_TCP removed from CATEGORY_WEIGHTS - no ground truth traffic
        # The elif for it remains for defensive coding but will never match
        else:
            return AttackCategoryMetrics()

    def has_category_data(self) -> bool:
        """Check if miner has per-category attack data.

        Checks both new category fields and legacy fields for backward compatibility.
        """
        # New signature-based category fields
        signature_sent = (
            self.layer3_ip_sent +
            self.layer4_tcp_flag_sent +
            self.layer4_udp_amp_sent +
            self.fragmentation_sent +
            self.malformed_sent
        )
        # New rate-limit category fields
        ratelimit_sent = (
            self.ratelimit_syn_sent +
            self.ratelimit_udp_sent +
            self.ratelimit_icmp_sent +
            self.ratelimit_app_sent
        )
        # Legacy fields (for backward compatibility with older audits)
        legacy_sent = (
            self.layer4_tcp_sent + self.layer4_udp_sent +
            self.layer3_icmp_sent + self.layer7_app_sent
        )
        return (signature_sent + ratelimit_sent + legacy_sent) > 0


@dataclass
class CategoryScore:
    """Score breakdown for a single attack category."""
    category: AttackCategory
    coverage_rate: float      # 0-1, how many attacks blocked
    weight: float             # Category weight in overall score
    weighted_score: float     # coverage_rate * weight
    meets_minimum: bool       # True if >= minimum threshold
    attacks_sent: int
    attacks_blocked: int


@dataclass
class RewardEvent:
    """
    Complete reward calculation results for an audit cycle.

    Contains all intermediate metrics and final rewards for
    transparency, debugging, and on-chain verification.
    """

    # Final rewards (0-1 scale) indexed by UID position
    rewards: List[float] = field(default_factory=list)

    # Component scores per miner
    volume_scores: List[float] = field(default_factory=list)
    latency_scores: List[float] = field(default_factory=list)
    availability_scores: List[float] = field(default_factory=list)
    attack_coverage_scores: List[float] = field(default_factory=list)
    false_positive_scores: List[float] = field(default_factory=list)

    # Per-category breakdown per miner
    category_scores: List[Dict[str, CategoryScore]] = field(default_factory=list)

    # Detailed metrics
    bytes_normalized: List[float] = field(default_factory=list)
    connections_normalized: List[float] = field(default_factory=list)
    origins_normalized: List[float] = field(default_factory=list)
    rtt_normalized: List[float] = field(default_factory=list)
    uptime_normalized: List[float] = field(default_factory=list)
    failover_penalty: List[float] = field(default_factory=list)

    # Distance-normalized latency details
    baseline_rtt: List[float] = field(default_factory=list)  # Expected RTT based on distance (or min_rtt fallback)
    normalized_rtt: List[float] = field(default_factory=list)  # actual_rtt / expected_rtt
    distances_km: List[float] = field(default_factory=list)  # Geographic distance validator <-> scrubber

    # Benchmarks (for normalization)
    max_bytes: int = 0
    max_connections: int = 0
    max_origins: int = 0
    min_rtt: float = float("inf")
    max_uptime: float = 0.0

    # Overall stats
    best_miner_uid: int = -1
    best_miner_score: float = 0.0
    avg_reward: float = 0.0

    # Category coverage summary
    avg_category_coverage: Dict[str, float] = field(default_factory=dict)
    miners_with_full_coverage: int = 0


class ProductionRewardModel:
    """
    Production-grade reward model for TensorProx subnet.

    AUDIT SCORE MEASURES CAPABILITY (not volume - that's in Bittensor weight):

    1. ATTACK COVERAGE (45%)
       Primary function - can the scrubber block attacks?
       Per-category scoring with 70% minimum threshold.

    2. FALSE POSITIVE (25%)
       Critical for UX - don't block legitimate traffic.
       High false positive rate severely penalized.

    3. LATENCY (15%)
       Response time during filtering.
       Fast processing is important but secondary to correctness.

    4. AVAILABILITY (15%)
       Always-on, always-available service.
       Penalizes failovers, restarts, heartbeat misses.
       Creates competitive differentiation for reliable miners.

    Volume is NOT included here because:
    - Audit uses fixed sample size (not real volume)
    - Volume is already 70% of Bittensor weight formula
    - Including it here would double-count volume

    Final Bittensor Weight = 0.70 × normalized_volume + 0.30 × ema_audit_score

    COMPETITIVE DIFFERENTIATION:
    Weights are configurable via environment variables (audit_config.py).
    This allows the subnet to tune scoring emphasis over time without code changes.
    """

    # === FACTOR WEIGHTS (must sum to 1.0) ===
    # Configurable via SCORING_FACTOR_WEIGHTS in audit_config.py
    # Defaults used if config not available
    ATTACK_COVERAGE_WEIGHT = SCORING_FACTOR_WEIGHTS.get("attack_coverage", 0.55) if _USE_CONFIG_WEIGHTS else 0.55
    FALSE_POSITIVE_WEIGHT = SCORING_FACTOR_WEIGHTS.get("false_positive", 0.25) if _USE_CONFIG_WEIGHTS else 0.25
    LATENCY_WEIGHT = SCORING_FACTOR_WEIGHTS.get("latency", 0.20) if _USE_CONFIG_WEIGHTS else 0.20

    # === CATEGORY WEIGHTS (must sum to 1.0) ===
    # Configurable via CATEGORY_SCORING_WEIGHTS in audit_config.py
    # Split into signature-based (percentage scoring) and rate-limit (binary scoring)
    @staticmethod
    def _get_category_weights() -> Dict['AttackCategory', float]:
        """Get category weights, using config if available."""
        if _USE_CONFIG_WEIGHTS and CATEGORY_SCORING_WEIGHTS:
            return {
                AttackCategory.LAYER3_IP: CATEGORY_SCORING_WEIGHTS.get("layer3_ip", 0.15),
                AttackCategory.LAYER4_TCP_FLAG: CATEGORY_SCORING_WEIGHTS.get("layer4_tcp_flag", 0.15),
                AttackCategory.LAYER4_UDP_AMP: CATEGORY_SCORING_WEIGHTS.get("layer4_udp_amp", 0.12),
                AttackCategory.FRAGMENTATION: CATEGORY_SCORING_WEIGHTS.get("fragmentation", 0.10),
                AttackCategory.MALFORMED: CATEGORY_SCORING_WEIGHTS.get("malformed", 0.08),
                AttackCategory.RATELIMIT_SYN: CATEGORY_SCORING_WEIGHTS.get("ratelimit_syn", 0.17),
                AttackCategory.RATELIMIT_UDP: CATEGORY_SCORING_WEIGHTS.get("ratelimit_udp", 0.14),
                AttackCategory.RATELIMIT_ICMP: CATEGORY_SCORING_WEIGHTS.get("ratelimit_icmp", 0.05),
                AttackCategory.RATELIMIT_APP: CATEGORY_SCORING_WEIGHTS.get("ratelimit_app", 0.04),
            }
        # Default weights (hardcoded fallback)
        return {
            AttackCategory.LAYER3_IP: 0.15,
            AttackCategory.LAYER4_TCP_FLAG: 0.15,
            AttackCategory.LAYER4_UDP_AMP: 0.12,
            AttackCategory.FRAGMENTATION: 0.10,
            AttackCategory.MALFORMED: 0.08,
            AttackCategory.RATELIMIT_SYN: 0.17,
            AttackCategory.RATELIMIT_UDP: 0.14,
            AttackCategory.RATELIMIT_ICMP: 0.05,
            AttackCategory.RATELIMIT_APP: 0.04,
        }

    # Initialize with defaults (will use config if available)
    CATEGORY_WEIGHTS = {
        # Signature-based (60% total) - scored by attacks_blocked / attacks_sent
        AttackCategory.LAYER3_IP: 0.15,        # Bogon, blacklist
        AttackCategory.LAYER4_TCP_FLAG: 0.15,  # TCP flag anomalies (XMAS, NULL, etc.)
        AttackCategory.LAYER4_UDP_AMP: 0.12,   # UDP amplification ports
        AttackCategory.FRAGMENTATION: 0.10,    # Fragment attacks
        AttackCategory.MALFORMED: 0.08,        # Malformed packets

        # Rate-limit (40% total) - scored by triggered + block ratio
        # Rate limiters use per-window thresholds. Volumetric attack mitigation
        # is the core of DDoS protection and must be weighted accordingly.
        AttackCategory.RATELIMIT_SYN: 0.17,    # SYN flood rate limiting
        AttackCategory.RATELIMIT_UDP: 0.14,    # UDP flood rate limiting
        AttackCategory.RATELIMIT_ICMP: 0.05,   # ICMP flood rate limiting
        AttackCategory.RATELIMIT_APP: 0.04,    # App layer rate limiting
    }

    # === CATEGORY TYPES ===
    # Rate-limit categories use THRESHOLD-BASED scoring
    # Signature categories use PERCENTAGE scoring (attacks_blocked / attacks_sent)
    # NOTE: RATELIMIT_TCP removed - no ground truth traffic generated for this category
    RATELIMIT_CATEGORIES = {
        AttackCategory.RATELIMIT_SYN,
        AttackCategory.RATELIMIT_UDP,
        AttackCategory.RATELIMIT_ICMP,
        AttackCategory.RATELIMIT_APP,
    }

    # === XDP RATE LIMIT THRESHOLDS (from xdp_wg_audit.c) ===
    # These are the default thresholds configured in the scrubber's XDP program.
    # The validator uses these to calculate expected blocked packets.
    #
    # Rate limiting behavior:
    # - Packets 1 to threshold: ALLOWED (below limit)
    # - Packets threshold+1 to end: BLOCKED (limit exceeded)
    #
    # Scoring: actual_blocked / expected_blocked
    # This rewards scrubbers that correctly block AFTER threshold is reached.

    # Global rate limits (packets per rate-limit window)
    # These are loaded from audit_config.py (configurable via env vars)
    @staticmethod
    def _get_rate_limit_thresholds():
        """Get XDP rate limit thresholds from config."""
        return {
            AttackCategory.RATELIMIT_SYN: XDP_RATELIMIT_SYN,
            AttackCategory.RATELIMIT_UDP: XDP_RATELIMIT_UDP,
            AttackCategory.RATELIMIT_ICMP: XDP_RATELIMIT_ICMP,
            AttackCategory.RATELIMIT_APP: XDP_RATELIMIT_APP,
        }

    # Minimum score for partial blocking (prevents gaming with 1 packet)
    RATELIMIT_MIN_SCORE_THRESHOLD = 0.5  # Must block at least 50% of expected

    # Minimum category coverage threshold (70%)
    MINIMUM_CATEGORY_COVERAGE = 0.7  # Below this = 50% penalty

    # False positive severity (FP is worse than FN)
    FALSE_POSITIVE_SEVERITY = 2.0  # 2x penalty for false positives

    # === LATENCY THRESHOLDS ===
    TARGET_RTT_MS = 20.0
    MAX_ACCEPTABLE_RTT_MS = 100.0

    def __init__(self):
        """Initialize the reward model with configurable weights."""
        self.e_minus_1 = math.e - 1

        # Load category weights from config (or use defaults)
        self.CATEGORY_WEIGHTS = self._get_category_weights()

        # Validate weights sum to 1.0
        factor_sum = (
            self.ATTACK_COVERAGE_WEIGHT +
            self.FALSE_POSITIVE_WEIGHT +
            self.LATENCY_WEIGHT
        )
        if abs(factor_sum - 1.0) >= 0.001:
            logger.warning(f"Factor weights sum to {factor_sum}, normalizing to 1.0")
            # Normalize instead of failing
            self.ATTACK_COVERAGE_WEIGHT /= factor_sum
            self.FALSE_POSITIVE_WEIGHT /= factor_sum
            self.LATENCY_WEIGHT /= factor_sum

        category_sum = sum(self.CATEGORY_WEIGHTS.values())
        if abs(category_sum - 1.0) >= 0.001:
            logger.warning(f"Category weights sum to {category_sum}, normalizing to 1.0")
            # Normalize instead of failing
            self.CATEGORY_WEIGHTS = {k: v / category_sum for k, v in self.CATEGORY_WEIGHTS.items()}

        if _USE_CONFIG_WEIGHTS:
            logger.debug(
                f"Reward model using config weights: "
                f"attack={self.ATTACK_COVERAGE_WEIGHT:.2f}, fp={self.FALSE_POSITIVE_WEIGHT:.2f}, "
                f"latency={self.LATENCY_WEIGHT:.2f}"
            )

    def compute_rewards(
        self,
        metrics_list: List[MinerMetrics]
    ) -> RewardEvent:
        """
        Compute rewards for all miners in an audit cycle.

        This is the main entry point for reward calculation. It:
        1. Validates input metrics
        2. Computes benchmarks for normalization
        3. Calculates raw latency scores and normalizes across all miners
        4. Calculates per-category attack coverage
        5. Combines all factors into final reward
        6. Returns detailed breakdown for transparency

        Latency scoring uses distance-based normalization with logarithmic decay:
        - raw_score = 1 / (actual_rtt / expected_rtt)
        - Scores are then normalized across all miners so best = 1.0
        This ensures miners compete fairly regardless of geographic location.

        Args:
            metrics_list: List of MinerMetrics for each audited miner.

        Returns:
            RewardEvent with all calculated rewards and intermediate values.
        """
        event = RewardEvent()

        if not metrics_list:
            logger.warning("No metrics provided for reward calculation")
            return event

        # Validate and log input
        valid_metrics = self._validate_metrics(metrics_list)
        if not valid_metrics:
            logger.error("No valid metrics after validation")
            return event

        # Compute benchmarks for normalization
        self._compute_benchmarks(valid_metrics, event)

        logger.debug(
            f"Reward benchmarks: max_bytes={event.max_bytes:,}, "
            f"max_connections={event.max_connections:,}, "
            f"min_rtt={event.min_rtt:.2f}ms, max_uptime={event.max_uptime:.2f}%"
        )

        # === PHASE 1: Calculate raw latency scores for all miners ===
        raw_latency_scores = []
        for metrics in valid_metrics:
            raw_score, _ = self._compute_raw_latency_score(metrics, event)
            raw_latency_scores.append(raw_score)

        # === PHASE 2: Normalize latency scores across all miners ===
        # For single-miner scoring, cap at 1.0 but allow penalty for slow (ratio > 1)
        # For batch scoring, normalize so best performer = 1.0
        if len(raw_latency_scores) == 1:
            normalized_latency_scores = [min(1.0, raw_latency_scores[0])]
        else:
            max_latency_score = max(raw_latency_scores) if raw_latency_scores else 1.0
            if max_latency_score > 0:
                normalized_latency_scores = [s / max_latency_score for s in raw_latency_scores]
            else:
                normalized_latency_scores = [0.0] * len(raw_latency_scores)

        # === PHASE 3: Compute rewards for each miner using normalized latency ===
        full_coverage_count = 0
        for i, metrics in enumerate(valid_metrics):
            reward, has_full_coverage = self._compute_miner_reward(
                metrics, event, normalized_latency_scores[i]
            )
            event.rewards.append(reward)
            event.latency_scores.append(normalized_latency_scores[i])

            if has_full_coverage:
                full_coverage_count += 1

        event.miners_with_full_coverage = full_coverage_count

        # Compute aggregate category coverage
        self._compute_aggregate_coverage(event)

        # Track overall stats
        if event.rewards:
            event.best_miner_score = max(event.rewards)
            event.avg_reward = sum(event.rewards) / len(event.rewards)
            best_idx = event.rewards.index(event.best_miner_score)
            event.best_miner_uid = valid_metrics[best_idx].uid

            # Only log leaderboard for batch scoring (multiple miners)
            # Per-miner scoring during concurrent audits uses DEBUG level
            if len(valid_metrics) == 1:
                # Single miner scoring (during concurrent audit) - DEBUG level
                m = valid_metrics[0]
                logger.debug(
                    f"Score UID {m.uid}: {event.rewards[0]:.3f} "
                    f"(atk={event.attack_coverage_scores[0]:.2f} "
                    f"fp={event.false_positive_scores[0]:.2f} "
                    f"lat={event.latency_scores[0]:.2f})"
                )
            else:
                # Log summary at debug level (validator.py logs the detailed leaderboard)
                logger.debug(
                    f"Rewards computed: {len(valid_metrics)} miners | "
                    f"best={event.best_miner_uid}:{event.best_miner_score:.3f} | "
                    f"avg={event.avg_reward:.3f}"
                )

        return event

    def _validate_metrics(
        self,
        metrics_list: List[MinerMetrics]
    ) -> List[MinerMetrics]:
        """
        Validate metrics and filter out invalid entries.

        Validation rules:
        - UID must be >= 0
        - Uptime must be 0-100
        - Rates must be 0-1
        - Counts must be non-negative
        """
        valid = []
        for m in metrics_list:
            issues = []

            if m.uid < 0:
                issues.append(f"invalid uid={m.uid}")

            if not (0 <= m.uptime_percent <= 100):
                issues.append(f"uptime out of range: {m.uptime_percent}")
                m.uptime_percent = max(0, min(100, m.uptime_percent))

            if not (0 <= m.false_positive_rate <= 1):
                issues.append(f"false_positive_rate out of range: {m.false_positive_rate}")
                m.false_positive_rate = max(0, min(1, m.false_positive_rate))

            if not (0 <= m.false_negative_rate <= 1):
                issues.append(f"false_negative_rate out of range: {m.false_negative_rate}")
                m.false_negative_rate = max(0, min(1, m.false_negative_rate))

            # Log warnings but still include
            if issues:
                logger.warning(f"Miner {m.uid} validation issues: {issues}")

            if m.uid >= 0:
                valid.append(m)

        return valid

    def _compute_benchmarks(
        self,
        metrics_list: List[MinerMetrics],
        event: RewardEvent
    ) -> None:
        """Compute benchmark values for normalization."""
        for metrics in metrics_list:
            event.max_bytes = max(event.max_bytes, metrics.total_bytes_processed)
            event.max_connections = max(event.max_connections, metrics.total_connections)
            event.max_origins = max(event.max_origins, metrics.origins_served)

            if metrics.avg_rtt_ms > 0:
                event.min_rtt = min(event.min_rtt, metrics.avg_rtt_ms)

            event.max_uptime = max(event.max_uptime, metrics.uptime_percent)

        # Handle edge case where no valid RTT data
        if event.min_rtt == float("inf"):
            event.min_rtt = self.TARGET_RTT_MS

    def _compute_miner_reward(
        self,
        metrics: MinerMetrics,
        event: RewardEvent,
        normalized_latency_score: float
    ) -> Tuple[float, bool]:
        """
        Compute audit reward for a single miner.

        Audit score = 45% Attack Coverage + 25% False Positive + 15% Latency + 15% Availability

        This 4-factor model rewards:
        - Attack mitigation capability (primary function)
        - Legitimate traffic protection (user experience)
        - Response time performance
        - Always-on reliability (competitive differentiation)

        Args:
            metrics: Miner metrics
            event: RewardEvent to store intermediate values
            normalized_latency_score: Pre-computed and normalized latency score [0, 1]

        Returns:
            Tuple of (final_reward, has_full_coverage)
        """
        # 1. Attack Coverage Score (45%) - Primary: block attacks
        attack_coverage_score, category_breakdown, has_full_coverage = (
            self._compute_attack_coverage_score(metrics)
        )
        event.attack_coverage_scores.append(attack_coverage_score)
        event.category_scores.append(category_breakdown)

        # 2. False Positive Score (25%) - Critical: don't block legit traffic
        false_positive_score = self._compute_false_positive_score(metrics)
        event.false_positive_scores.append(false_positive_score)

        # 3. Latency Score (20%) - Already normalized, passed in
        latency_score = normalized_latency_score

        # Combined weighted reward (3 factors) - simple weighted sum
        # Attack 55%, FP Prevention 25%, Latency 20%
        reward = (
            self.ATTACK_COVERAGE_WEIGHT * attack_coverage_score +
            self.FALSE_POSITIVE_WEIGHT * false_positive_score +
            self.LATENCY_WEIGHT * latency_score
        )

        # Clamp to [0, 1]
        reward = min(1.0, max(0.0, reward))

        # Log detailed breakdown
        logger.debug(
            f"Miner {metrics.uid} audit score: "
            f"attack={attack_coverage_score:.3f} ({self.ATTACK_COVERAGE_WEIGHT*100:.0f}%), "
            f"fp={false_positive_score:.3f} ({self.FALSE_POSITIVE_WEIGHT*100:.0f}%), "
            f"latency={latency_score:.3f} ({self.LATENCY_WEIGHT*100:.0f}%) "
            f"=> total={reward:.4f} (full_coverage={has_full_coverage})"
        )

        return reward, has_full_coverage

    def _compute_volume_score(
        self,
        metrics: MinerMetrics,
        event: RewardEvent
    ) -> float:
        """
        Compute volume handling score (30% of total reward).

        Uses geometric mean with exponential scaling to reward
        high-volume miners proportionally more.
        """
        # Normalize each dimension
        bytes_norm = (
            metrics.total_bytes_processed / event.max_bytes
            if event.max_bytes > 0 else 0.0
        )
        connections_norm = (
            metrics.total_connections / event.max_connections
            if event.max_connections > 0 else 0.0
        )
        origins_norm = (
            metrics.origins_served / event.max_origins
            if event.max_origins > 0 else 0.0
        )

        # Store intermediate values
        event.bytes_normalized.append(bytes_norm)
        event.connections_normalized.append(connections_norm)
        event.origins_normalized.append(origins_norm)

        # Geometric mean with weighted exponents
        # Bytes most important (0.5), connections (0.3), origins (0.2)
        if bytes_norm > 0 and connections_norm > 0 and origins_norm > 0:
            geometric_mean = (
                (bytes_norm ** 0.5) *
                (connections_norm ** 0.3) *
                (origins_norm ** 0.2)
            )
        elif bytes_norm > 0:
            # Partial data - use what we have with penalty
            geometric_mean = bytes_norm * 0.6
        else:
            geometric_mean = 0.0

        # Exponential scaling: exp(x^2) - 1 / (e - 1)
        volume_score = (math.exp(geometric_mean ** 2) - 1) / self.e_minus_1

        return min(1.0, max(0.0, volume_score))

    def _compute_raw_latency_score(
        self,
        metrics: MinerMetrics,
        event: RewardEvent
    ) -> Tuple[float, Dict[str, float]]:
        """
        Compute RAW latency score using 1/ratio formula (logarithmic decay).

        This score is NOT bounded to [0, 1] - it will be normalized across
        all miners in the compute_rewards() method.

        Formula: raw_score = 1 / ratio
        Where: ratio = actual_rtt / expected_rtt

        This gives:
        - ratio 0.5 (2x faster) → score 2.0
        - ratio 1.0 (as expected) → score 1.0
        - ratio 2.0 (2x slower) → score 0.5
        - ratio 5.0 (5x slower) → score 0.2

        Distance-Based Expected RTT:
        We use IP geolocation to calculate the physical distance between
        the validator and scrubber, then compute an expected RTT based on
        the speed of light in fiber (~50 km per ms RTT).

        Fallback to min_rtt baseline if geolocation fails.

        Returns:
            Tuple of (raw_score, details_dict)
        """
        from tensorprox.services.geoip import get_geoip_service

        geoip = get_geoip_service()
        expected_rtt_ms = None
        distance_km = None

        # Try distance-based normalization first
        if metrics.validator_ip and metrics.scrubber_ip:
            distance_km, expected_rtt_ms = geoip.get_expected_rtt_between_ips(
                metrics.validator_ip,
                metrics.scrubber_ip
            )

        details = {
            "expected_rtt": 0.0,
            "actual_rtt": metrics.avg_rtt_ms,
            "ratio": 1.0,
            "distance_km": distance_km or 0.0,
            "method": "none"
        }

        if metrics.avg_rtt_ms > 0:
            if expected_rtt_ms and expected_rtt_ms > 0:
                # DISTANCE-BASED NORMALIZATION
                ratio = metrics.avg_rtt_ms / expected_rtt_ms
                details["expected_rtt"] = expected_rtt_ms
                details["ratio"] = ratio
                details["method"] = "distance"

                event.baseline_rtt.append(expected_rtt_ms)
                event.normalized_rtt.append(ratio)
                event.distances_km.append(distance_km or 0.0)
            else:
                # FALLBACK: Use min_rtt baseline if geolocation failed
                MIN_BASELINE_MS = 5.0
                if metrics.min_rtt_ms > 0:
                    baseline_rtt_ms = max(MIN_BASELINE_MS, metrics.min_rtt_ms)
                else:
                    baseline_rtt_ms = max(MIN_BASELINE_MS, metrics.avg_rtt_ms * 0.7)

                ratio = metrics.avg_rtt_ms / baseline_rtt_ms
                details["expected_rtt"] = baseline_rtt_ms
                details["ratio"] = ratio
                details["method"] = "baseline"

                event.baseline_rtt.append(baseline_rtt_ms)
                event.normalized_rtt.append(ratio)
                event.distances_km.append(0.0)
        else:
            # No RTT data - use neutral ratio of 1.0
            ratio = 1.0
            details["ratio"] = ratio
            details["method"] = "no_data"

            event.baseline_rtt.append(0.0)
            event.normalized_rtt.append(1.0)
            event.distances_km.append(0.0)

        # Raw score = 1 / ratio (logarithmic decay)
        # This will be normalized across all miners later
        if ratio > 0:
            raw_score = 1.0 / ratio
        else:
            raw_score = 1.0  # Fallback for invalid ratio

        # Store RTT normalized value for event (this is the ratio, not final score)
        event.rtt_normalized.append(ratio)

        return raw_score, details

    def _compute_availability_score(
        self,
        metrics: MinerMetrics,
        event: RewardEvent
    ) -> float:
        """
        Compute availability score (15% of total audit score).

        Creates competitive differentiation for always-on, always-available miners.

        Components:
        - Uptime percentage (primary) - from ecp-agent health reports
        - Failover penalty (0.95^count) - 5% per failover
        - Heartbeat miss penalty (0.99^count) - 1% per miss
        - Restart penalty (0.97^count) - 3% per restart
        """
        # Uptime component (normalized to [0, 1])
        uptime_norm = metrics.uptime_percent / 100.0
        event.uptime_normalized.append(uptime_norm)

        # Penalties (multiplicative)
        failover_penalty = 0.95 ** metrics.failover_count
        heartbeat_penalty = 0.99 ** metrics.heartbeat_misses
        restart_penalty = 0.97 ** metrics.restart_count

        event.failover_penalty.append(failover_penalty)

        # Combined score
        availability_score = uptime_norm * failover_penalty * heartbeat_penalty * restart_penalty

        return min(1.0, max(0.0, availability_score))

    def _compute_attack_coverage_score(
        self,
        metrics: MinerMetrics
    ) -> Tuple[float, Dict[str, CategoryScore], bool]:
        """
        Compute attack coverage score (45% of total audit score).

        This is the CORE innovation - scoring per attack category.

        Returns:
            Tuple of (score, category_breakdown, has_full_coverage)

        Scoring Logic:
        1. Calculate coverage rate for each category
        2. Apply minimum threshold (70%) - below = 50% penalty
        3. Weight by category importance
        4. Sum weighted scores

        Full coverage = ALL categories above minimum threshold
        """
        category_breakdown = {}
        total_weighted_score = 0.0
        categories_with_data = 0

        # Check if miner has per-category data
        has_category_data = metrics.has_category_data()

        if not has_category_data:
            # Fall back to legacy scoring
            return self._compute_legacy_attack_score(metrics)

        # Score each category with different logic for signature vs rate-limit
        # Simple and fair: validator controls packet distribution, miner just responds
        total_weight_used = 0.0

        for category, weight in self.CATEGORY_WEIGHTS.items():
            cat_metrics = metrics.get_category_metrics(category)

            if cat_metrics.attacks_sent == 0:
                # No attacks sent for this category - skip it entirely
                # Don't penalize miner for categories not tested
                continue

            if category in self.RATELIMIT_CATEGORIES:
                # === RATE-LIMIT SCORING (windowed threshold-based) ===
                # Rate limiting uses per-window thresholds (e.g., 25 SYNs per 2-second window).
                # Traffic is spread over multiple windows, so we can't expect all excess to be blocked.
                #
                # Approach: Score based on whether rate limiting TRIGGERED and blocked SOME traffic.
                # - If traffic > threshold and blocked > 0: rate limiting works, score proportionally
                # - If traffic > threshold and blocked = 0: rate limiting failed, score 0
                # - If traffic <= threshold: can't test rate limiting, give neutral score
                #
                # This prevents gaming (blocking 1 packet is low score) while being fair
                # to scrubbers that correctly implement windowed rate limiting.

                threshold = self._get_rate_limit_thresholds().get(category, 50)
                attacks_sent = cat_metrics.attacks_sent
                actual_blocked = cat_metrics.attacks_blocked

                if attacks_sent > threshold:
                    # Traffic exceeded threshold - rate limiting SHOULD have triggered
                    if actual_blocked > 0:
                        # Rate limiting triggered - score based on block ratio
                        # Expect to block roughly (sent - threshold) / sent of traffic
                        # But windowed limits mean actual blocked varies
                        # Use blocked/sent ratio with minimum expectation of 10%
                        block_ratio = actual_blocked / attacks_sent
                        # Scale: 0% blocked = 0, 50%+ blocked = 1.0
                        coverage_rate = min(1.0, block_ratio * 2.0)
                        scoring_method = f"ratelimit:sent={attacks_sent}>threshold={threshold},blocked={actual_blocked}({block_ratio*100:.1f}%),score={coverage_rate*100:.1f}%"
                    else:
                        # Rate limiting should have triggered but didn't block anything
                        coverage_rate = 0.0
                        scoring_method = f"ratelimit:FAILED(sent={attacks_sent}>threshold={threshold},blocked=0)"
                elif attacks_sent > 0:
                    # Under threshold - can't properly test rate limiting
                    # Give neutral score (don't penalize, don't reward)
                    if actual_blocked == 0:
                        coverage_rate = 1.0  # Correct: didn't block under-threshold traffic
                        scoring_method = f"ratelimit:under_threshold({attacks_sent}<={threshold}),no_blocks=CORRECT"
                    else:
                        coverage_rate = 0.9  # Slight penalty for over-blocking
                        scoring_method = f"ratelimit:under_threshold({attacks_sent}<={threshold}),blocked={actual_blocked}=OVER_BLOCKING"
                else:
                    # No traffic sent
                    coverage_rate = 0.0
                    scoring_method = f"ratelimit:no_traffic"
            else:
                # === SIGNATURE-BASED SCORING (percentage of attacks blocked) ===
                # Simple: score = blocked / sent (no penalties)
                coverage_rate = cat_metrics.coverage_rate
                scoring_method = f"signature({coverage_rate*100:.1f}%)"

            # Simple weighted score - no penalties
            weighted_score = coverage_rate * weight
            total_weighted_score += weighted_score
            total_weight_used += weight
            categories_with_data += 1

            # Store breakdown
            category_breakdown[category.value] = CategoryScore(
                category=category,
                coverage_rate=coverage_rate,
                weight=weight,
                weighted_score=weighted_score,
                meets_minimum=True,  # Always true now (no minimum thresholds)
                attacks_sent=cat_metrics.attacks_sent,
                attacks_blocked=cat_metrics.attacks_blocked
            )

            # Log per-category details
            # Rate-limit categories at INFO level for debugging, others at DEBUG
            if cat_metrics.attacks_sent > 0:
                display_blocked = min(cat_metrics.attacks_blocked, cat_metrics.attacks_sent)
                log_msg = (
                    f"  {category.value}: {display_blocked}/{cat_metrics.attacks_sent} "
                    f"({coverage_rate*100:.1f}%) weight={weight:.2f} [{scoring_method}]"
                )
                logger.debug(log_msg)

        # Normalize by weights actually used (fair scoring for categories tested)
        if total_weight_used > 0:
            final_score = total_weighted_score / total_weight_used
        else:
            final_score = 0.0

        has_full_coverage = categories_with_data >= 5

        return min(1.0, max(0.0, final_score)), category_breakdown, has_full_coverage

    def _compute_legacy_attack_score(
        self,
        metrics: MinerMetrics
    ) -> Tuple[float, Dict[str, CategoryScore], bool]:
        """
        Fallback scoring for miners without per-category data.

        Uses legacy synthetic traffic results with reduced score ceiling.
        """
        # Calculate from legacy metrics
        correct_blocks = (
            metrics.synthetic_spoofed_blocked +
            metrics.synthetic_malformed_blocked +
            metrics.synthetic_bogon_blocked +
            metrics.synthetic_blacklist_blocked
        )
        correct_passes = metrics.synthetic_benign_passed

        total_sent = metrics.synthetic_attack_sent + metrics.synthetic_benign_sent

        if total_sent > 0:
            accuracy = (correct_blocks + correct_passes) / total_sent
        else:
            accuracy = 0.5

        # Legacy mode capped at 80% to incentivize upgrading
        legacy_score = min(0.8, accuracy)

        # Create placeholder breakdown
        category_breakdown = {
            "legacy": CategoryScore(
                category=AttackCategory.LAYER3_IP,  # Placeholder
                coverage_rate=accuracy,
                weight=1.0,
                weighted_score=legacy_score,
                meets_minimum=accuracy >= self.MINIMUM_CATEGORY_COVERAGE,
                attacks_sent=total_sent,
                attacks_blocked=correct_blocks
            )
        }

        logger.debug(
            f"  Legacy scoring: {correct_blocks}/{metrics.synthetic_attack_sent} blocked, "
            f"accuracy={accuracy*100:.1f}%, capped_score={legacy_score:.3f}"
        )

        return legacy_score, category_breakdown, False

    def _compute_false_positive_score(
        self,
        metrics: MinerMetrics
    ) -> float:
        """
        Compute false positive protection score (10% of total reward).

        FALSE POSITIVES ARE CRITICAL - blocking legitimate traffic
        directly harms users and undermines trust in the service.

        Scoring:
        - 100% benign passed = 1.0 score
        - Each % blocked = severe penalty
        - Uses exponential penalty for high FP rates
        """
        # Calculate FP rate from traffic data if available
        if metrics.benign_sent > 0:
            fp_rate = metrics.benign_blocked / metrics.benign_sent
        else:
            fp_rate = metrics.false_positive_rate

        # Ensure in range [0, 1]
        fp_rate = min(1.0, max(0.0, fp_rate))

        # Exponential penalty: score = (1 - fp_rate)^severity
        # With severity=2.0, 10% FP rate = 0.81, 20% = 0.64, 50% = 0.25
        fp_score = (1.0 - fp_rate) ** self.FALSE_POSITIVE_SEVERITY

        return min(1.0, max(0.0, fp_score))

    def _compute_aggregate_coverage(self, event: RewardEvent) -> None:
        """Compute aggregate category coverage across all miners."""
        if not event.category_scores:
            return

        # Initialize aggregates
        category_totals = {cat.value: [] for cat in AttackCategory}

        for miner_scores in event.category_scores:
            for cat_name, score in miner_scores.items():
                if cat_name in category_totals and isinstance(score, CategoryScore):
                    category_totals[cat_name].append(score.coverage_rate)

        # Compute averages
        for cat_name, rates in category_totals.items():
            if rates:
                event.avg_category_coverage[cat_name] = sum(rates) / len(rates)
            else:
                event.avg_category_coverage[cat_name] = 0.0


def compute_rewards(
    metrics_by_uid: Dict[int, Dict[str, Any]]
) -> RewardEvent:
    """
    Convenience function to compute rewards from a metrics dictionary.

    This is the main entry point for validators calling the reward system.

    Latency scoring uses baseline normalization - comparing avg_rtt to the
    minimum observed RTT (representing inherent network latency). This ensures
    miners aren't penalized for being geographically far from the validator.

    Args:
        metrics_by_uid: Dict mapping UID to metrics dict with keys matching
                       MinerMetrics field names.

    Returns:
        RewardEvent with computed rewards indexed by UID order.

    Example:
        metrics = {
            5: {
                "total_bytes_processed": 500_000_000_000,
                "avg_rtt_ms": 45.0,
                "layer3_ip_sent": 100,
                "layer3_ip_blocked": 95,
                "layer4_tcp_sent": 200,
                "layer4_tcp_blocked": 190,
                ...
            },
        }
        event = compute_rewards(metrics)
    """
    model = ProductionRewardModel()

    # Convert dict to MinerMetrics objects
    metrics_list = []
    for uid, md in sorted(metrics_by_uid.items()):
        metrics = MinerMetrics(
            uid=uid,
            # Volume metrics
            total_bytes_processed=md.get("total_bytes_processed", 0),
            total_connections=md.get("total_connections", 0),
            origins_served=md.get("origins_served", 0),
            xdp_pass_count=md.get("xdp_pass_count", 0),
            # Latency metrics
            avg_rtt_ms=md.get("avg_rtt_ms", 0.0),
            min_rtt_ms=md.get("min_rtt_ms", 0.0),  # Fallback for baseline normalization
            p95_rtt_ms=md.get("p95_rtt_ms", 0.0),
            p99_rtt_ms=md.get("p99_rtt_ms", 0.0),
            syn_synack_ratio=md.get("syn_synack_ratio", 1.0),
            # Geolocation for distance-based normalization
            scrubber_ip=md.get("scrubber_ip", ""),
            validator_ip=md.get("validator_ip", ""),
            # Availability metrics
            uptime_percent=md.get("uptime_percent", 0.0),
            failover_count=md.get("failover_count", 0),
            heartbeat_misses=md.get("heartbeat_misses", 0),
            restart_count=md.get("restart_count", 0),
            # === SIGNATURE-BASED ATTACK CATEGORIES (percentage scoring) ===
            layer3_ip_sent=md.get("layer3_ip_sent", 0),
            layer3_ip_blocked=md.get("layer3_ip_blocked", 0),
            layer4_tcp_flag_sent=md.get("layer4_tcp_flag_sent", 0),
            layer4_tcp_flag_blocked=md.get("layer4_tcp_flag_blocked", 0),
            layer4_udp_amp_sent=md.get("layer4_udp_amp_sent", 0),
            layer4_udp_amp_blocked=md.get("layer4_udp_amp_blocked", 0),
            fragmentation_sent=md.get("fragmentation_sent", 0),
            fragmentation_blocked=md.get("fragmentation_blocked", 0),
            malformed_sent=md.get("malformed_sent", 0),
            malformed_blocked=md.get("malformed_blocked", 0),
            # === RATE-LIMIT ATTACK CATEGORIES (binary scoring) ===
            ratelimit_syn_sent=md.get("ratelimit_syn_sent", 0),
            ratelimit_syn_blocked=md.get("ratelimit_syn_blocked", 0),
            ratelimit_udp_sent=md.get("ratelimit_udp_sent", 0),
            ratelimit_udp_blocked=md.get("ratelimit_udp_blocked", 0),
            ratelimit_icmp_sent=md.get("ratelimit_icmp_sent", 0),
            ratelimit_icmp_blocked=md.get("ratelimit_icmp_blocked", 0),
            ratelimit_tcp_sent=md.get("ratelimit_tcp_sent", 0),
            ratelimit_tcp_blocked=md.get("ratelimit_tcp_blocked", 0),
            ratelimit_app_sent=md.get("ratelimit_app_sent", 0),
            ratelimit_app_blocked=md.get("ratelimit_app_blocked", 0),
            # === LEGACY FIELDS (backward compatibility) ===
            layer4_tcp_sent=md.get("layer4_tcp_sent", 0),
            layer4_tcp_blocked=md.get("layer4_tcp_blocked", 0),
            layer4_udp_sent=md.get("layer4_udp_sent", 0),
            layer4_udp_blocked=md.get("layer4_udp_blocked", 0),
            layer3_icmp_sent=md.get("layer3_icmp_sent", 0),
            layer3_icmp_blocked=md.get("layer3_icmp_blocked", 0),
            layer7_app_sent=md.get("layer7_app_sent", 0),
            layer7_app_blocked=md.get("layer7_app_blocked", 0),
            # XDP drop statistics (granular)
            xdp_drop_blacklist=md.get("xdp_drop_blacklist", 0),
            xdp_drop_ratelimit=md.get("xdp_drop_ratelimit", 0),
            xdp_drop_quarantine=md.get("xdp_drop_quarantine", 0),
            xdp_drop_bogon=md.get("xdp_drop_bogon", 0),
            xdp_drop_invalid_ip=md.get("xdp_drop_invalid_ip", 0),
            xdp_drop_tcp_xmas=md.get("xdp_drop_tcp_xmas", 0),
            xdp_drop_tcp_null=md.get("xdp_drop_tcp_null", 0),
            xdp_drop_tcp_synfin=md.get("xdp_drop_tcp_synfin", 0),
            xdp_drop_tcp_synrst=md.get("xdp_drop_tcp_synrst", 0),
            xdp_drop_syn_flood=md.get("xdp_drop_syn_flood", 0),
            xdp_drop_udp_amp=md.get("xdp_drop_udp_amp", 0),
            xdp_drop_icmp_flood=md.get("xdp_drop_icmp_flood", 0),
            xdp_drop_frag=md.get("xdp_drop_frag", 0),
            xdp_syncookie_challenge=md.get("xdp_syncookie_challenge", 0),
            # Benign traffic metrics
            benign_sent=md.get("benign_sent", 0),
            benign_passed=md.get("benign_passed", 0),
            benign_blocked=md.get("benign_blocked", 0),
            # Legacy synthetic metrics (backward compatibility)
            synthetic_attack_sent=md.get("synthetic_attack_sent", 0),
            synthetic_benign_sent=md.get("synthetic_benign_sent", 0),
            attacks_detected=md.get("attacks_detected", 0),
            false_positive_rate=md.get("false_positive_rate", 0.0),
            false_negative_rate=md.get("false_negative_rate", 0.0),
            synthetic_spoofed_blocked=md.get("synthetic_spoofed_blocked", 0),
            synthetic_malformed_blocked=md.get("synthetic_malformed_blocked", 0),
            synthetic_bogon_blocked=md.get("synthetic_bogon_blocked", 0),
            synthetic_blacklist_blocked=md.get("synthetic_blacklist_blocked", 0),
            synthetic_benign_passed=md.get("synthetic_benign_passed", 0),
        )
        metrics_list.append(metrics)

    logger.debug(f"Computing rewards for {len(metrics_list)} miners")
    return model.compute_rewards(metrics_list)


def compute_rewards_from_audit(
    audit_results: Dict[int, 'AuditResultData'],
    validator_ip: str = "",
) -> RewardEvent:
    """
    Compute rewards from audit results.

    This function converts AuditResult data into MinerMetrics
    for the standard reward computation pipeline.

    Args:
        audit_results: Dict mapping UID to AuditResultData
        validator_ip: Validator's IP for distance-based latency normalization

    Returns:
        RewardEvent with computed rewards

    Example:
        from tensorprox.services.validator_audit_service import AuditRoundResult

        results = await audit_service.run_audit_round(targets)

        audit_data = {
            result.uid: AuditResultData(
                accuracy_score=result.accuracy_score,
                false_positive_rate=result.false_positive_rate,
                category_coverage=result.category_coverage,
                throughput_level=result.max_throughput_achieved,
                scrubber_ip=targets[i].scrubber_ip,
            )
            for i, result in enumerate(results)
            if result.success
        }

        event = compute_rewards_from_audit(audit_data, validator_ip)
    """
    model = ProductionRewardModel()
    metrics_list = []

    for uid, audit_data in sorted(audit_results.items()):
        # Map crypto audit categories to MinerMetrics category fields
        # Crypto audit uses AttackCategory enum values, map to reward model categories
        category_map = {
            "bogon": ("layer3_ip", 1.0),
            "blacklist": ("layer3_ip", 1.0),
            "tcp_flag_anomaly": ("layer4_tcp", 1.0),
            "udp_amplification": ("layer4_udp", 1.0),
            "fragmentation": ("fragmentation", 1.0),
            "malformed": ("malformed", 1.0),
            "syn_flood": ("layer4_tcp", 0.7),  # Rate-limited, partial credit
            "udp_flood": ("layer4_udp", 0.7),
            "icmp_flood": ("layer3_icmp", 0.7),
            "benign": ("benign", 1.0),
        }

        # Initialize category metrics
        category_sent = {
            "layer3_ip": 0, "layer4_tcp": 0, "layer4_udp": 0,
            "layer3_icmp": 0, "layer7_app": 0, "fragmentation": 0,
            "malformed": 0, "benign": 0,
        }
        category_blocked = {k: 0 for k in category_sent}

        # Aggregate from crypto audit category coverage
        coverage = audit_data.category_coverage
        for crypto_cat, (reward_cat, weight) in category_map.items():
            if crypto_cat in coverage:
                # Estimate sent/blocked from coverage rate
                # Assume 100 packets per category as baseline
                sent = 100
                blocked = int(coverage[crypto_cat] * sent * weight)
                category_sent[reward_cat] += sent
                category_blocked[reward_cat] += blocked

        # Build MinerMetrics
        metrics = MinerMetrics(
            uid=uid,
            # Volume not included in audit (handled by Bittensor weight separately)
            total_bytes_processed=0,
            total_connections=0,
            origins_served=0,

            # Latency from audit (if available)
            avg_rtt_ms=getattr(audit_data, 'avg_rtt_ms', 0.0),
            min_rtt_ms=getattr(audit_data, 'min_rtt_ms', 0.0),

            # Geolocation for distance normalization
            scrubber_ip=getattr(audit_data, 'scrubber_ip', ''),
            validator_ip=validator_ip,

            # Per-category attack metrics (from verified proofs)
            layer3_ip_sent=category_sent["layer3_ip"],
            layer3_ip_blocked=category_blocked["layer3_ip"],
            layer4_tcp_sent=category_sent["layer4_tcp"],
            layer4_tcp_blocked=category_blocked["layer4_tcp"],
            layer4_udp_sent=category_sent["layer4_udp"],
            layer4_udp_blocked=category_blocked["layer4_udp"],
            layer3_icmp_sent=category_sent["layer3_icmp"],
            layer3_icmp_blocked=category_blocked["layer3_icmp"],
            fragmentation_sent=category_sent["fragmentation"],
            fragmentation_blocked=category_blocked["fragmentation"],
            malformed_sent=category_sent["malformed"],
            malformed_blocked=category_blocked["malformed"],

            # L7 metrics from L7 audit (if available)
            # If L7 audit was run, use those results; otherwise don't penalize
            layer7_app_sent=audit_data.l7_patterns_sent if audit_data.l7_patterns_sent > 0 else 0,
            layer7_app_blocked=audit_data.l7_patterns_blocked if audit_data.l7_patterns_sent > 0 else 0,

            # Benign traffic (false positive calculation)
            benign_sent=category_sent["benign"],
            benign_passed=int(category_sent["benign"] * (1 - audit_data.false_positive_rate)),
            benign_blocked=int(category_sent["benign"] * audit_data.false_positive_rate),

            # Set false positive rate directly from verified data
            false_positive_rate=audit_data.false_positive_rate,
        )

        metrics_list.append(metrics)

    logger.info(f"Computing crypto audit rewards for {len(metrics_list)} miners")
    return model.compute_rewards(metrics_list)


@dataclass
class AuditResultData:
    """
    Data structure for crypto audit results.

    Used by compute_rewards_from_audit() to convert
    validator audit service results to reward metrics.
    """
    accuracy_score: float = 0.0
    false_positive_rate: float = 0.0
    category_coverage: Dict[str, float] = field(default_factory=dict)
    throughput_level: int = 0
    scrubber_ip: str = ""
    avg_rtt_ms: float = 0.0
    min_rtt_ms: float = 0.0

    # L7 Audit Results (optional - from L7AuditResult)
    l7_detection_score: float = 0.0  # How many L7 attacks were detected
    l7_blocking_score: float = 0.0   # How many detected attacks were blocked
    l7_overall_score: float = 0.0    # Combined L7 protection score
    l7_false_positive_rate: float = 0.0  # L7-specific FP rate
    l7_patterns_sent: int = 0  # Total L7 attack patterns sent
    l7_patterns_blocked: int = 0  # L7 patterns blocked


def convert_audit_result_to_data(
    result: 'AuditRoundResult',
    scrubber_ip: str = "",
    l7_result: Optional['L7AuditResult'] = None,
) -> AuditResultData:
    """
    Convert AuditRoundResult to AuditResultData.

    Helper function for integrating with ValidatorAuditService.

    Args:
        result: AuditRoundResult from ValidatorAuditService
        scrubber_ip: Scrubber IP address
        l7_result: Optional L7AuditResult from L7 audit

    Returns:
        AuditResultData for reward computation
    """
    data = AuditResultData(
        accuracy_score=result.accuracy_score,
        false_positive_rate=result.false_positive_rate,
        category_coverage=result.category_coverage,
        throughput_level=result.max_throughput_achieved,
        scrubber_ip=scrubber_ip,
    )

    # Add L7 audit results if available
    if l7_result:
        data.l7_detection_score = l7_result.detection_score
        data.l7_blocking_score = l7_result.blocking_score
        data.l7_overall_score = l7_result.overall_score
        data.l7_false_positive_rate = l7_result.false_positive_rate
        data.l7_patterns_sent = l7_result.total_attack_patterns + l7_result.benign_patterns_sent
        data.l7_patterns_blocked = l7_result.patterns_blocked

    return data
