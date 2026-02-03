"""
TensorProx Validator implementation - Production Ready.

Implements unified leaderboard-based auditing:
- All miners are ranked by EMA audit score
- Miners become eligible for assignment when EMA >= threshold
- TPM picks highest-ranked eligible miners for origin assignment
- No separate "pre-assignment" phase - just continuous auditing
"""

import random
import time
import asyncio
import threading
import secrets
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, Any, List, Set, ClassVar, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

import bittensor as bt
from pydantic import Field
from loguru import logger

from tensorprox.base.validator import BaseValidatorNeuron
from tensorprox.base.protocol import ScrubberConfig, AuditChallengeSynapse
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.rewards.reward import compute_rewards, ProductionRewardModel
from tensorprox.rewards.weight_setter import WeightSetter
from tensorprox.rewards.leaderboard import (
    MinerLeaderboard,
    compute_rewards_with_state,
    compute_bittensor_weights,
    compute_weights_normalized,
    EMA_ALPHA,
)
from tensorprox.services.synthetic_traffic import SyntheticTrafficGenerator, TrafficTestResult
from tensorprox.services.real_packet_sender import RealPacketSender, RealTrafficResult, AuditProfile, SCAPY_AVAILABLE
from tensorprox.services.tpm_client import TPMClient, ProductionMetrics
from tensorprox.services.audit_tunnel import SynapseBasedTunnelManager, generate_wireguard_keypair
from tensorprox.settings import Settings, get_settings
from shared.utils.bpf_helpers import bpf_read_xdp_stats
import subprocess


@dataclass
class AuditContext:
    """
    Holds state for a single miner's audit across all phases.

    This enables the pipeline architecture where each phase runs
    for ALL miners in parallel before moving to the next phase.
    """
    uid: int
    scrubber_ip: str
    challenge_id: str
    result: 'AuditResult'

    # Tunnel setup
    validator_private_key: Optional[str] = None
    validator_public_key: Optional[str] = None
    local_ip: Optional[str] = None
    validator_port: int = 0
    tunnel_ip_validator: str = ""
    tunnel_ip_scrubber: str = ""
    tunnel_manager: Optional[SynapseBasedTunnelManager] = None
    tunnel_established: bool = False

    # Traffic sending
    traffic_result: Optional[RealTrafficResult] = None
    tunnel_interface: Optional[str] = None
    tunnel_dest_ip: Optional[str] = None

    # Collection
    collect_response: Optional[Any] = None

    # Error tracking
    phase_failed: Optional[str] = None  # Which phase failed
    error_message: Optional[str] = None


# =============================================================================
# AUDIT SAMPLE SIZE - STATISTICAL CONFIDENCE ANALYSIS
# =============================================================================
#
# We measure attack coverage per category. The smallest categories (fragmentation,
# malformed) receive only 5% of total packets. Sample size must ensure tight
# confidence intervals for ALL categories.
#
# Wilson Score 95% Confidence Interval at p=0.70 (our minimum threshold):
#
#   Total Attacks | Smallest Category (5%) | 95% CI Margin | Quality
#   ------------- | ---------------------- | ------------- | --------
#         500     |          25            |    ±16.9%     | Poor
#       2,000     |         100            |     ±8.8%     | Acceptable
#       5,000     |         250            |     ±5.6%     | Good
#      10,000     |         500            |     ±4.0%     | Very Good
#      20,000     |       1,000            |     ±2.8%     | Excellent
#
# Formula: margin ≈ 1.96 * sqrt(p*(1-p)/n) where n = packets in category
#
# UNIFIED AUDIT: 5,000 attacks for all miners (±5.6% margin - Good)
# This provides sufficient confidence for eligibility decisions while being
# bandwidth-efficient for continuous auditing.
#
# =============================================================================

# =============================================================================
# AUDIT DESIGN PHILOSOPHY - SIMPLIFIED LEADERBOARD MODEL
# =============================================================================
# - AUDIT tests CORRECTNESS: Are XDP rules configured properly?
# - VOLUME tests CAPACITY: Can the scrubber handle the load? (from TPM)
#
# All miners are audited uniformly. The leaderboard EMA score determines
# eligibility for assignment. No separate "pre-assignment" phase - miners
# simply need to achieve EMA >= threshold to become eligible.
#
# TPM picks miners based on:
# 1. EMA score >= eligibility threshold (0.8)
# 2. Availability (online)
# 3. Capacity (not overloaded)
# 4. Rank in leaderboard (highest EMA first)


# Audit packet counts are configured in AuditProfile.BASE_ATTACK_COUNT (10,000 base).
# Actual counts are randomized each round: attacks ±50%, benign ratio 1:3 to 1:10.


class MinerState(Enum):
    """Miner lifecycle states - TPM controls assignments.

    State transitions:
    - PENDING -> ACTIVE: TPM assigns miner to origin(s)
    - ACTIVE -> PENDING: TPM unassigns miner (still eligible, just not needed)
    - ACTIVE -> FLAGGED: Miner fails audits, reported to TPM
    - FLAGGED -> PENDING: Miner EMA recovers above threshold (eligible again)
    - FLAGGED -> ACTIVE: TPM re-assigns miner (TPM is source of truth)
    """
    PENDING = "pending"  # Not currently assigned (new or unassigned by TPM)
    ACTIVE = "active"  # Assigned to origin(s) by TPM
    FLAGGED = "flagged"  # Failed audits, reported to TPM for reassignment


@dataclass
class MinerRecord:
    """Comprehensive miner tracking - simplified leaderboard model."""

    uid: int
    hotkey: str
    state: MinerState = MinerState.PENDING

    # Configuration
    scrubber_config: Optional[ScrubberConfig] = None
    scrubber_ips: List[str] = field(default_factory=list)

    # Assignment tracking
    assigned_origins: List[str] = field(default_factory=list)
    assigned_origin_ips: Dict[str, str] = field(default_factory=dict)  # origin_id -> origin_ip (shard EIP)

    # Audit history
    last_audit: Optional[datetime] = None
    audit_count: int = 0

    # Scoring
    current_score: float = 0.0
    score_history: List[float] = field(default_factory=list)
    consecutive_low_scores: int = 0

    # EMA-based leaderboard scoring (alpha configurable via settings.ema_alpha)
    ema_audit_score: float = 0.0  # Exponential moving average of audit scores
    ema_production_score: float = 0.0  # EMA of production XDP metrics (for assigned miners)
    ema_initialized: bool = False  # Whether EMA has been initialized
    production_ema_initialized: bool = False  # Whether production EMA has been initialized

    # Score components from last audit (for W&B detailed logging)
    # Weights: Attack 55%, FP Prevention 25%, Latency 20%
    last_attack_score: float = 0.0       # Attack coverage component (55%)
    last_fp_score: float = 0.0           # False positive prevention component (25%)
    last_latency_score: float = 0.0      # Latency performance component (20%)

    # Performance metrics (latest audit)
    total_bytes_processed: int = 0
    total_connections: int = 0
    avg_rtt_ms: float = 0.0
    failover_count: int = 0

    # Availability
    is_available: bool = False
    last_seen: Optional[datetime] = None

    # Thread-safe state machine locking (initialized in __post_init__)
    _state_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def is_eligible(self, threshold: float = 0.8) -> bool:
        """Check if miner is eligible for assignment based on EMA score."""
        return (
            self.ema_initialized and
            self.ema_audit_score >= threshold and
            self.is_available and
            self.state != MinerState.FLAGGED
        )

    def get_combined_ema(self, production_weight: float = 0.7) -> float:
        """
        Get combined EMA score using dual scoring model.

        For active miners with production data: weighted combination of audit + production
        For pending/new miners: audit only

        Args:
            production_weight: Weight for production EMA when available (default 0.7 = 70%)

        Returns:
            Combined EMA score (0-1)
        """
        if not self.ema_initialized:
            return 0.0

        # For miners without production data, use audit only
        if not self.production_ema_initialized:
            return self.ema_audit_score

        # For miners with production data: weighted combination
        # Production (70%) + Audit (30%) = ungameable production validation
        audit_weight = 1.0 - production_weight
        return (
            production_weight * self.ema_production_score +
            audit_weight * self.ema_audit_score
        )

    def transition_state(self, new_state: MinerState) -> bool:
        """
        Thread-safe state transition.

        Args:
            new_state: The state to transition to

        Returns:
            True if transition was successful, False if state was already at new_state
        """
        with self._state_lock:
            if self.state == new_state:
                return False
            old_state = self.state
            self.state = new_state
            logger.trace(f"Miner {self.uid} state: {old_state.value} -> {new_state.value}")
            return True


@dataclass
class AuditResult:
    """Result from auditing a miner."""

    uid: int
    timestamp: datetime
    miner_state: MinerState
    success: bool = False

    # Test results
    synthetic_test: Optional[TrafficTestResult] = None

    # Metrics collected
    metrics: Dict[str, Any] = field(default_factory=dict)

    # Scoring
    score: float = 0.0
    passed_threshold: bool = False

    # Error tracking
    error: Optional[str] = None


@dataclass
class MinerAuditMetrics:
    """Per-miner audit metrics for detailed tracking."""
    uid: int
    score: float = 0.0
    ema_score: float = 0.0
    attacks_sent: int = 0
    attacks_blocked: int = 0
    block_rate: float = 0.0
    benign_sent: int = 0
    benign_passed: int = 0
    benign_rate: float = 0.0
    eligible: bool = False
    error: Optional[str] = None


@dataclass
class AuditCycleStats:
    """
    Aggregated statistics for an audit cycle.

    Tracks BOTH aggregate stats AND per-miner breakdown for transparency.
    """
    total_miners: int = 0
    successful_audits: int = 0
    failed_audits: int = 0

    # Score distribution
    scores: List[float] = field(default_factory=list)
    avg_score: float = 0.0
    min_score: float = 0.0
    max_score: float = 0.0
    median_score: float = 0.0

    # Attack blocking stats
    total_attacks_sent: int = 0
    total_attacks_blocked: int = 0
    avg_block_rate: float = 0.0

    # Benign pass stats
    total_benign_sent: int = 0
    total_benign_passed: int = 0
    avg_benign_pass_rate: float = 0.0

    # State tracking
    eligible_count: int = 0
    flagged_count: int = 0
    new_flags: List[int] = field(default_factory=list)  # UIDs flagged this cycle

    # Duration
    duration_seconds: float = 0.0

    # === PER-MINER METRICS (new) ===
    miner_metrics: List[MinerAuditMetrics] = field(default_factory=list)

    def compute_from_results(
        self,
        results: List['AuditResult'],
        eligibility_threshold: float = 0.8,
        miners_db: Optional[Dict[int, 'MinerRecord']] = None
    ):
        """Compute aggregated statistics AND per-miner metrics from audit results."""
        self.total_miners = len(results)
        self.successful_audits = sum(1 for r in results if r.success)
        self.failed_audits = self.total_miners - self.successful_audits
        self.miner_metrics = []  # Reset per-miner list

        # Score statistics
        self.scores = [r.score for r in results if r.success]
        if self.scores:
            self.avg_score = sum(self.scores) / len(self.scores)
            self.min_score = min(self.scores)
            self.max_score = max(self.scores)
            sorted_scores = sorted(self.scores)
            mid = len(sorted_scores) // 2
            self.median_score = sorted_scores[mid] if len(sorted_scores) % 2 else (sorted_scores[mid-1] + sorted_scores[mid]) / 2

        # Eligible count
        self.eligible_count = sum(1 for r in results if r.passed_threshold)

        # Signature-based categories (deterministic blocking, no false positives)
        SIGNATURE_CATEGORIES = {
            "blacklist", "bogon", "land",
            "tcp_xmas", "tcp_null", "tcp_synfin", "tcp_synrst",
            "tcp_fin", "tcp_rst", "tcp_ack",
            "udp_amp", "frag", "malformed",
        }

        # Rate-limited categories (blocked when above threshold)
        RATELIMIT_CATEGORIES = {
            "syn_flood", "udp_flood", "icmp_flood",
            "http_flood", "slowloris",
        }

        for r in results:
            # Create per-miner metrics entry
            miner_metric = MinerAuditMetrics(
                uid=r.uid,
                score=r.score if r.success else 0.0,
                eligible=r.passed_threshold,
                error=r.error if not r.success else None,
            )

            # Get EMA from miners_db if available
            if miners_db and r.uid in miners_db:
                miner_metric.ema_score = miners_db[r.uid].ema_audit_score

            if r.success and r.metrics:
                gt = r.metrics.get("ground_truth", {})
                mr = r.metrics.get("miner_reported", {})

                attacks = gt.get("attack_sent", 0)
                benign = gt.get("benign_sent", 0)

                # All attacks are now detectable (spoofed category removed)
                detectable_attacks = attacks

                # Count blocked by category type
                blocked_dict = mr.get("blocked", {})
                signature_blocked = sum(
                    v for k, v in blocked_dict.items()
                    if k in SIGNATURE_CATEGORIES
                ) if blocked_dict else 0

                # Rate-limited blocked (for display metric)
                ratelimit_blocked = sum(
                    v for k, v in blocked_dict.items()
                    if k in RATELIMIT_CATEGORIES
                ) if blocked_dict else 0

                # Generic per-source ratelimit (XDP catches attacks via per-IP rate limiting
                # but increments a generic counter instead of attack-specific ones)
                generic_ratelimit = blocked_dict.get("ratelimit", 0) if blocked_dict else 0

                # Quarantine + temp_blacklist: IPs quarantined after repeated rate limit violations
                quarantine_blocked = (
                    blocked_dict.get("quarantine", 0) +
                    blocked_dict.get("temp_blacklist", 0)
                ) if blocked_dict else 0

                # SYN cookie challenges/rejects (primary SYN flood mitigation)
                syncookie_blocked = (
                    blocked_dict.get("syncookie_challenge", 0) +
                    blocked_dict.get("syncookie_reject", 0)
                ) if blocked_dict else 0

                # Combined blocked for display (all attack-related drops)
                display_blocked = (
                    signature_blocked + ratelimit_blocked + generic_ratelimit +
                    quarantine_blocked + syncookie_blocked
                )

                # Total blocked for benign calculation — exclude syncookie because
                # it also challenges benign SYNs during floods
                total_blocked = sum(
                    v for k, v in blocked_dict.items()
                    if k not in {"counter_reset_detected", "invalid_ip",
                                 "syncookie_challenge", "syncookie_reject"}
                ) if blocked_dict else 0

                passed = mr.get("passed", 0)

                # Aggregate stats - use display_blocked for accurate block rate
                self.total_attacks_sent += detectable_attacks
                self.total_attacks_blocked += display_blocked
                self.total_benign_sent += benign

                # Per-miner benign calculation
                attacks_passed = max(0, attacks - total_blocked)
                estimated_benign_passed = max(0, passed - attacks_passed)
                estimated_benign_passed = min(benign, estimated_benign_passed)

                self.total_benign_passed += estimated_benign_passed

                # Store per-miner metrics
                # Use display_blocked (signature + rate-limited) for accurate block rate
                miner_metric.attacks_sent = detectable_attacks
                miner_metric.attacks_blocked = display_blocked
                if display_blocked > detectable_attacks:
                    logger.warning(
                        f"UID {r.uid}: blocked ({display_blocked}) > sent ({detectable_attacks}) - "
                        f"concurrent traffic interference detected"
                    )
                miner_metric.block_rate = min(1.0, display_blocked / detectable_attacks) if detectable_attacks > 0 else 0.0
                miner_metric.benign_sent = benign
                miner_metric.benign_passed = estimated_benign_passed
                miner_metric.benign_rate = estimated_benign_passed / benign if benign > 0 else 0.0

            self.miner_metrics.append(miner_metric)

        # Sort by score descending
        self.miner_metrics.sort(key=lambda m: m.score, reverse=True)

        if self.total_attacks_sent > 0:
            self.avg_block_rate = self.total_attacks_blocked / self.total_attacks_sent
        if self.total_benign_sent > 0:
            self.avg_benign_pass_rate = self.total_benign_passed / self.total_benign_sent

    def format_summary(self) -> str:
        """Format a concise summary for logging."""
        return (
            f"miners={self.successful_audits}/{self.total_miners} | "
            f"avg={self.avg_score:.3f} med={self.median_score:.3f} "
            f"[{self.min_score:.2f}-{self.max_score:.2f}] | "
            f"block={self.avg_block_rate:.1%} benign={self.avg_benign_pass_rate:.1%} | "
            f"eligible={self.eligible_count} flagged={self.flagged_count}"
        )

    def format_top_miners(self, top_n: int = 3) -> str:
        """
        Format top N miners with their individual metrics for this audit round.

        Shows: UID | Score | EMA | Block% | Benign% | Attacks | Benign
        """
        if not self.miner_metrics:
            return "No miner metrics"

        lines = []
        # Only show successful miners, sorted by score (already sorted)
        successful = [m for m in self.miner_metrics if not m.error][:top_n]

        for rank, m in enumerate(successful, 1):
            lines.append(
                f"  #{rank} UID {m.uid}: score={m.score:.3f} ema={m.ema_score:.3f} | "
                f"block={m.block_rate:.1%} ({m.attacks_blocked}/{m.attacks_sent}) | "
                f"benign={m.benign_rate:.1%} ({m.benign_passed}/{m.benign_sent})"
            )

        return "\n".join(lines)


def compute_production_score(metrics: ProductionMetrics) -> float:
    """
    Compute production performance score from XDP metrics.

    DESIGN PHILOSOPHY: Only penalize for SEVERE, UNAMBIGUOUS failures.

    NO minor penalties - they accumulate in EMA and cause false flagging.
    Score is either 1.0 (healthy) or very low (clear failure).

    CRITICAL SAFEGUARDS (to avoid false positives):
    1. Minimum bidirectional traffic threshold - require meaningful traffic
       in BOTH directions before scoring
    2. Origin-down vs Flood distinction:
       - Low traffic + no SYN-ACK = origin problem → DON'T penalize scrubber
       - High SYN traffic + low SYN-ACK = actual flood → penalize scrubber

    SEVERE FAILURES (score = 0.3):
    1. HIGH SYN count (>1000) AND SYN/SYN-ACK ratio > 10 = unmitigated SYN flood
    2. Zero xdp_pass with active origins = blocking ALL traffic

    EVERYTHING ELSE = 1.0 (healthy):
    - Low traffic = normal (origin not set up, DNS not configured, quiet origin)
    - Low/high drop rate = normal (depends on attack volume)
    - Brief ratio spikes = normal (attacks happen)

    Returns:
        1.0 = Healthy (default)
        0.3 = Severe failure
    """
    # ==========================================================================
    # BINARY SCORING: Either healthy (1.0) or severe failure (0.3)
    # No intermediate penalties that could accumulate unfairly
    # ==========================================================================

    # ==========================================================================
    # SAFEGUARD 1: Minimum bidirectional traffic threshold
    # ==========================================================================
    # Don't score if there's insufficient traffic to make a determination.
    # This prevents false positives when:
    # - Origin not set up yet (no DNS)
    # - Origin server is down (not scrubber's fault)
    # - Very quiet period with no real traffic
    #
    # Thresholds:
    # - MIN_SYN_FOR_SCORING: Need at least this many SYNs to evaluate ratio
    # - MIN_SYNACK_FOR_HEALTHY: Need at least this many SYN-ACKs to confirm origin is responding

    MIN_SYN_FOR_SCORING = 50      # Need meaningful traffic to evaluate
    MIN_SYNACK_FOR_HEALTHY = 5    # Origin must show signs of life

    # If we don't have enough SYNs, we can't make a determination
    # This covers: origin not deployed, DNS not set, no client traffic
    if metrics.total_syn < MIN_SYN_FOR_SCORING:
        # Not enough traffic to score - assume healthy (don't penalize)
        return 1.0

    # ==========================================================================
    # SAFEGUARD 2: Origin-down vs Flood distinction
    # ==========================================================================
    # If SYN count is low-to-moderate but SYN-ACK is zero/near-zero,
    # this is likely an origin problem, NOT a scrubber problem.
    #
    # Origin-down indicators:
    # - Some SYNs present (traffic is flowing to origin)
    # - Zero or near-zero SYN-ACKs (origin not responding)
    # - Total traffic is low-to-moderate (not a massive attack)
    #
    # Flood indicators:
    # - HIGH SYN count (attack volume)
    # - Low SYN-ACK (origin overwhelmed or scrubber not mitigating)
    # - The key difference is VOLUME - floods have high SYN counts

    SYN_FLOOD_THRESHOLD = 1000  # This many SYNs suggests actual attack traffic

    # Case: Low-moderate SYN count + no SYN-ACK = origin problem
    # Don't penalize scrubber for origin being down
    if metrics.total_syn < SYN_FLOOD_THRESHOLD and metrics.total_synack < MIN_SYNACK_FOR_HEALTHY:
        # Origin appears to be down or not responding
        # This is NOT the scrubber's fault - return healthy
        return 1.0

    # --------------------------------------------------------------------------
    # FAILURE 1: Severe unmitigated SYN flood
    # --------------------------------------------------------------------------
    # Now we know:
    # - We have significant SYN traffic (>= MIN_SYN_FOR_SCORING)
    # - Either origin is responding (synack >= MIN_SYNACK) OR
    #   we have flood-level traffic (syn >= SYN_FLOOD_THRESHOLD)
    #
    # A high ratio NOW indicates scrubber failure to mitigate

    ratio = metrics.syn_synack_ratio

    # Only penalize if:
    # 1. Ratio is high (> 10) AND
    # 2. We have flood-level SYN traffic OR origin is responding (has SYN-ACKs)
    if ratio > 10.0:
        # Check if this is a real flood (high SYN count) or origin responding
        has_flood_traffic = metrics.total_syn >= SYN_FLOOD_THRESHOLD
        origin_is_responding = metrics.total_synack >= MIN_SYNACK_FOR_HEALTHY

        if has_flood_traffic or origin_is_responding:
            # This is a real failure - either:
            # - Flood traffic not being mitigated (has_flood_traffic)
            # - Origin responding but connections not completing (origin_is_responding)
            return 0.3
        # else: Low traffic + no response = origin problem, don't penalize

    # --------------------------------------------------------------------------
    # FAILURE 2: Blocking ALL traffic (no legitimate traffic passing)
    # --------------------------------------------------------------------------
    # If scrubber has active origins but xdp_pass = 0, it's blocking everything.
    # This catches malicious scrubbers that block legitimate client traffic.
    #
    # We check: has origins AND processed some packets AND zero passed through
    # This means the scrubber received traffic but blocked 100% of it.
    #
    # Note: We don't penalize if total_packets = 0 (might just be quiet period)

    if metrics.origin_count > 0 and metrics.total_packets > 100:
        # Has origins and received meaningful traffic
        if metrics.xdp_pass == 0:
            # Blocked 100% of traffic - likely misconfigured or malicious
            return 0.3

        # Also check pass rate - if less than 1% passes, something is wrong
        total_processed = metrics.xdp_pass + metrics.total_drops
        if total_processed > 0:
            pass_rate = metrics.xdp_pass / total_processed
            if pass_rate < 0.01:  # Less than 1% passing
                return 0.3

    # --------------------------------------------------------------------------
    # HEALTHY: Everything else
    # --------------------------------------------------------------------------
    # - Insufficient traffic to score (origin not set up) → healthy
    # - Low traffic + no response (origin down) → healthy (not scrubber's fault)
    # - Traffic is passing (xdp_pass > 0) → healthy
    # - Connections are completing (ratio < 10) → healthy
    # - Drop rate doesn't matter (could be under attack)

    return 1.0


class TensorProxValidator(BaseValidatorNeuron):
    """
    Production-ready TensorProx validator.

    Implements:
    - Pre-assignment testing for new miners
    - Production auditing via direct scrubber auditing + synthetic traffic
    - TPM integration for score reporting and assignment queries
    - Volume-weighted reward calculation
    """

    model_config = {"arbitrary_types_allowed": True}

    # Miner tracking
    miners: Dict[int, MinerRecord] = Field(default_factory=dict)

    # Audit configuration - unified for all miners
    audit_interval: int = Field(
        default=0,  # DEPRECATED: Audits now run continuously
        description="DEPRECATED: Audits run continuously. This field is ignored."
    )
    audit_duration: int = Field(
        default=60,
        description="Duration of each audit in seconds"
    )
    max_concurrent_audits: int = Field(
        default=256,
        description="Maximum number of concurrent audits (defaults to 256, subnet size)"
    )

    # ==========================================================================
    # ELIGIBILITY & PERFORMANCE THRESHOLDS
    # ==========================================================================
    # Miners become eligible for assignment when their EMA score >= threshold.
    # Once assigned, if performance drops below threshold, they get flagged.
    # ==========================================================================

    eligibility_threshold: float = Field(
        default=0.8,
        description="Minimum EMA score to be eligible for assignment"
    )

    # Immediate flag: catastrophic single audit (client at risk NOW)
    immediate_flag_threshold: float = Field(
        default=0.5,
        description="Single audit below this = immediate flag (emergency)"
    )

    # EMA-based flag: sustained poor performance
    # Set to same as eligibility threshold - if EMA drops below, miner loses eligibility
    ema_flag_threshold: float = Field(
        default=0.80,
        description="EMA below this triggers consecutive failure counting"
    )

    consecutive_failures_to_flag: int = Field(
        default=2,
        description="Consecutive EMA failures before flagging"
    )

    # Service integrations
    synthetic_traffic: Optional[SyntheticTrafficGenerator] = Field(default=None)
    tpm_client: Optional[TPMClient] = Field(default=None)
    weight_setter: Optional[WeightSetter] = Field(default=None)

    # Real packet sender for actual XDP testing
    real_packet_sender: Optional[RealPacketSender] = Field(default=None)
    use_real_audits: bool = Field(
        default=True,
        description="Use real traffic audits instead of simulated (requires scapy)"
    )

    # Reward model
    reward_model: ProductionRewardModel = Field(
        default_factory=ProductionRewardModel
    )

    # EMA-based leaderboard for miner ranking and selection
    leaderboard: MinerLeaderboard = Field(default_factory=MinerLeaderboard)

    # Audit tracking - unified for all miners
    last_audit_cycle: float = Field(default=0.0)

    # === AUDIT QUEUE MANAGEMENT FOR SCALABILITY ===
    # Prevents unbounded task creation and detects audit cycle overlaps
    audit_in_progress: bool = Field(
        default=False,
        description="Flag indicating if an audit cycle is currently running"
    )
    audit_start_time: float = Field(
        default=0.0,
        description="Timestamp when current audit cycle started"
    )
    audit_timeout: int = Field(
        default=600,  # 10 minutes max audit duration
        description="Maximum time allowed for an audit cycle before forced completion"
    )
    max_pending_audits: int = Field(
        default=1000,
        description="Maximum number of miners that can be queued for audit"
    )
    audit_overlap_count: int = Field(
        default=0,
        description="Counter for audit cycle overlaps (for monitoring)"
    )

    # TPM leaderboard sync (for region-aware, availability-based assignment)
    last_leaderboard_sync: float = Field(default=0.0)
    leaderboard_sync_interval: int = Field(
        default=60,  # Reduced from 300s to 60s for faster state sync
        description="Interval in seconds between leaderboard syncs to TPM"
    )

    # Validator's public IP for distance-based latency normalization
    validator_public_ip: str = Field(
        default="",
        description="Validator's public IP for GeoIP-based distance calculation"
    )

    # TPM-Lite Integration (Decentralized TPM) - Always enabled, mandatory for validators
    tpm_port: int = Field(
        default=5001,
        description="Port for TPM-Lite API"
    )
    tpm_integration: Optional[Any] = Field(
        default=None,
        description="TPM integration service instance (None if failed to initialize)"
    )
    wandb_reporter: Optional[Any] = Field(
        default=None,
        description="W&B reporter for audit metrics"
    )

    def __init__(
        self,
        settings: Optional[Settings] = None,
        **kwargs
    ):
        """Initialize the production validator."""
        super().__init__(settings=settings, **kwargs)

    def setup(self) -> None:
        """Set up the validator with all integrations."""
        super().setup()

        # Check file descriptor limits for 256-miner scalability
        self._check_file_descriptor_limits()

        # Configure larger thread pool for concurrent tunnel operations
        # Default is min(32, cpu+4) which is too small for 256 concurrent audits
        # Each audit does blocking subprocess calls for WireGuard setup
        # With 256 concurrent audits, we need enough workers to avoid queuing delays
        # Dynamic sizing: max(256, max_concurrent_audits + 32) to handle peak load
        thread_pool_size = max(256, self.max_concurrent_audits + 32)
        self._tunnel_executor = ThreadPoolExecutor(max_workers=thread_pool_size, thread_name_prefix="tunnel")
        try:
            loop = asyncio.get_running_loop()
            loop.set_default_executor(self._tunnel_executor)
            logger.info(f"Configured thread pool with {thread_pool_size} workers for concurrent tunnel operations")
        except RuntimeError:
            # No running loop yet, will be set when loop starts
            logger.debug("Event loop not running yet, executor will be set later")

        # Initialize leaderboard with configured EMA alpha
        ema_alpha = getattr(self.settings, 'ema_alpha', 0.2)
        self.leaderboard = MinerLeaderboard(ema_alpha=ema_alpha)
        logger.info(f"Leaderboard initialized with EMA alpha={ema_alpha} (effective period ~{2/ema_alpha - 1:.1f} audits)")

        # Initialize synthetic traffic generator (for simulated tests)
        self.synthetic_traffic = SyntheticTrafficGenerator(
            attack_count=self.settings.synthetic_attack_count if hasattr(self.settings, 'synthetic_attack_count') else 1000,
            benign_count=self.settings.synthetic_benign_count if hasattr(self.settings, 'synthetic_benign_count') else 200,
        )

        # Initialize REAL packet sender for actual XDP testing (dynamic ratio per round)
        if SCAPY_AVAILABLE:
            self.real_packet_sender = RealPacketSender(
                base_attack_count=getattr(self.settings, 'real_audit_attack_count', 500),
                base_benign_count=getattr(self.settings, 'real_audit_benign_count', 100),
            )
            logger.info("Real packet sender initialized - ACTUAL XDP testing enabled")
        else:
            self.real_packet_sender = None
            logger.warning("Scapy not available - falling back to simulated tests (NOT RECOMMENDED)")

        # Flag for using real vs simulated audits
        self.use_real_audits = SCAPY_AVAILABLE and getattr(self.settings, 'use_real_audits', True)

        # Initialize TPM client
        if hasattr(self.settings, 'tpm_api_url'):
            self.tpm_client = TPMClient(
                tpm_api_url=self.settings.tpm_api_url,
                api_key=getattr(self.settings, 'tpm_api_key', None),
            )

            # Check TPM connectivity
            if self.tpm_client.health_check():
                logger.info("TPM connectivity verified")
            else:
                logger.warning("TPM health check failed - assignment queries may fail")
        else:
            logger.warning("TPM API not configured - assignment tracking disabled")

        # Initialize weight setter
        self.weight_setter = WeightSetter(settings=self.settings)

        # Set max concurrent audits from settings (configurable via TP_MAX_CONCURRENT_AUDITS)
        # Validators with limited resources can reduce this to batch audits
        self.max_concurrent_audits = self.settings.max_concurrent_audits
        logger.info(f"Max concurrent audits: {self.max_concurrent_audits}")

        # Get and cache validator's public IP for distance-based latency normalization
        self.validator_public_ip = self._get_validator_public_ip()
        if self.validator_public_ip:
            logger.info("Validator public IP detected successfully")
        else:
            logger.warning("Could not determine validator public IP - latency normalization will use fallback")

        # Initialize W&B reporter for audit metrics
        # Miners can view scores at: https://wandb.ai/shugo-labs/tensorprox
        self.wandb_reporter = None
        wandb_enabled = getattr(self.settings, 'wandb_enabled', False) or getattr(self.settings, 'wandb_on', False)
        if wandb_enabled:
            try:
                from tensorprox.services.wandb_reporter import init_wandb_reporter
                self.wandb_reporter = init_wandb_reporter(
                    project=getattr(self.settings, 'wandb_project', 'tensorprox'),
                    entity=getattr(self.settings, 'wandb_entity', 'shugo-labs'),
                    api_key=getattr(self.settings, 'wandb_api_key', None),
                    validator_uid=self.uid,
                    validator_hotkey=self.settings.wallet.hotkey.ss58_address if self.settings.wallet else None,
                    enabled=True,
                    wallet=self.settings.wallet,
                    netuid=getattr(self.settings, 'netuid', None),
                )
                logger.info("W&B audit reporting enabled - miners can view scores at wandb.ai/shugo-labs/tensorprox")
            except Exception as e:
                logger.warning(f"Failed to initialize W&B reporter: {e}")

        # Initialize TPM-Lite (mandatory for validators)
        # Each TPM operates independently with exclusive ownership of its origins
        try:
            from tensorprox.services.tpm_integration import init_tpm_integration
            self.tpm_integration = init_tpm_integration(
                validator=self,
                port=self.tpm_port,
            )
            # Start TPM will be done in run() to properly handle async
            logger.info(f"TPM-Lite integration initialized: port={self.tpm_port}")
        except ImportError as e:
            logger.warning(f"TPM-Lite modules not available: {e}")
            self.tpm_integration = None
        except Exception as e:
            logger.error(f"Failed to initialize TPM-Lite: {e}")
            self.tpm_integration = None

        logger.info("Production validator setup complete")

    def _check_file_descriptor_limits(self) -> None:
        """
        Check system file descriptor limits and warn if too low for 256-miner audits.

        Each concurrent audit uses approximately 5-8 file descriptors for:
        - SSH connections to scrubbers
        - WireGuard tunnel setup
        - Subprocess pipes
        - Network sockets

        For 256 concurrent audits, we need at least 2048 FDs (256 * 8).
        We recommend 4096+ for safety margin.
        """
        try:
            import resource

            # Get current soft and hard limits
            soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)

            # Calculate recommended minimum based on max_concurrent_audits
            fd_per_audit = 8  # Conservative estimate
            min_recommended = self.max_concurrent_audits * fd_per_audit
            safe_recommended = min_recommended * 2  # Double for safety margin

            if soft_limit < min_recommended:
                logger.error(
                    f"FILE DESCRIPTOR LIMIT TOO LOW FOR {self.max_concurrent_audits} CONCURRENT AUDITS!\n"
                    f"  Current limit: {soft_limit}\n"
                    f"  Minimum needed: {min_recommended}\n"
                    f"  Recommended: {safe_recommended}\n"
                    f"  Hard limit: {hard_limit}\n"
                    f"  FIX: Run 'ulimit -n {safe_recommended}' before starting validator,\n"
                    f"       or add 'LimitNOFILE={safe_recommended}' to systemd service file."
                )

                # Try to increase the soft limit if hard limit allows
                if hard_limit >= safe_recommended:
                    try:
                        resource.setrlimit(resource.RLIMIT_NOFILE, (safe_recommended, hard_limit))
                        new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
                        logger.info(f"Automatically increased file descriptor limit: {soft_limit} -> {new_soft}")
                    except (ValueError, OSError) as e:
                        logger.warning(f"Could not auto-increase FD limit: {e}")
                elif hard_limit >= min_recommended:
                    try:
                        resource.setrlimit(resource.RLIMIT_NOFILE, (min_recommended, hard_limit))
                        new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
                        logger.warning(f"Increased file descriptor limit to minimum: {soft_limit} -> {new_soft}")
                    except (ValueError, OSError) as e:
                        logger.warning(f"Could not auto-increase FD limit: {e}")

            elif soft_limit < safe_recommended:
                logger.warning(
                    f"File descriptor limit ({soft_limit}) is below recommended ({safe_recommended}) "
                    f"for {self.max_concurrent_audits} concurrent audits. Consider increasing with "
                    f"'ulimit -n {safe_recommended}'"
                )
            else:
                logger.info(f"File descriptor limit OK: {soft_limit} (recommended: {safe_recommended})")

        except ImportError:
            # resource module not available on Windows
            logger.debug("File descriptor limit check skipped (resource module not available)")
        except Exception as e:
            logger.warning(f"Could not check file descriptor limits: {e}")

    def _get_validator_public_ip(self) -> str:
        """
        Get the validator's public IP address for distance-based latency normalization.

        Tries multiple methods:
        1. External API (ipify, icanhazip)
        2. Local network interface detection

        Returns:
            Public IP address as string, or empty string if detection failed
        """
        import subprocess

        # Try external API first (most reliable for public IP)
        try:
            import requests
            # Try ipify (simple, returns just the IP)
            try:
                response = requests.get("https://api.ipify.org", timeout=5.0)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if ip and "." in ip:  # Basic validation
                        return ip
            except Exception:
                pass

            # Fallback to icanhazip
            try:
                response = requests.get("https://icanhazip.com", timeout=5.0)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if ip and "." in ip:
                        return ip
            except Exception:
                pass
        except ImportError:
            pass

        # Fallback: try to detect from local interfaces
        try:
            result = subprocess.run(
                ["hostname", "-I"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                # First IP is usually the primary
                ip = result.stdout.strip().split()[0]
                # Skip private IPs (we want public)
                if not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172."):
                    return ip
        except Exception:
            pass

        return ""

    async def discover_miners(self) -> Dict[int, MinerRecord]:
        """
        Discover and track all miners.

        Updates miner records with availability and configuration.
        """
        miner_uids = self.get_miner_uids()
        logger.info(f"Discovering {len(miner_uids)} miners...")

        # Renew bootstrap token before querying miners
        # This ensures miners get a fresh token for TPM registration
        self._renew_bootstrap_token()

        # Refresh dendrite to avoid stale connections causing timeouts
        # The cached dendrite can accumulate stale TCP connections in long-running processes,
        # causing miners to appear unavailable when they're actually online
        self.dendrite = bt.Dendrite(wallet=self.wallet)
        logger.debug("Refreshed dendrite for miner discovery")

        # Query availability
        available = await self.query_miners_availability(miner_uids)

        now = datetime.utcnow()

        for uid in miner_uids:
            # Initialize record if new
            if uid not in self.miners:
                hotkey = self.metagraph.hotkeys[uid]
                self.miners[uid] = MinerRecord(
                    uid=uid,
                    hotkey=hotkey,
                    state=MinerState.PENDING,  # Start as pending, build EMA score
                )

            record = self.miners[uid]

            # Update from ping response
            if uid in available:
                ping = available[uid]
                record.is_available = True
                record.last_seen = now
                record.scrubber_config = ping.scrubber_config

                if ping.scrubber_config and hasattr(ping.scrubber_config, 'active_nodes'):
                    record.scrubber_ips = ping.scrubber_config.active_nodes or []
            else:
                record.is_available = False

        # Sync with TPM to get assignment info for active miners
        if self.tpm_client:
            self._sync_assignments_from_tpm()

        active_count = sum(1 for m in self.miners.values() if m.state == MinerState.ACTIVE)
        pending_count = sum(1 for m in self.miners.values() if m.state == MinerState.PENDING)
        eligible_count = sum(1 for m in self.miners.values() if m.is_eligible(self.eligibility_threshold))

        logger.info(
            f"Miner discovery complete: {active_count} active, "
            f"{pending_count} pending, {eligible_count} eligible, {len(available)} available"
        )

        return self.miners

    def _sync_assignments_from_tpm(self) -> None:
        """Sync miner-to-origin assignments from TPM.

        TPM is the source of truth for assignments. This function:
        1. Fetches current assignments from TPM
        2. Updates local state to match TPM exactly
        3. Transitions miner states based on assignment changes:
           - PENDING/FLAGGED -> ACTIVE: When TPM assigns a miner
           - ACTIVE -> PENDING: When TPM unassigns a miner (still eligible, just not assigned)
        """
        if not self.tpm_client:
            logger.debug("No TPM client configured, skipping assignment sync")
            return

        assignments = self.tpm_client.get_miner_assignments()

        # Build map of current TPM assignments: uid -> list of origin_ids
        # Also build origin_ip map for production benign tests
        tpm_assignments: dict[int, list[str]] = {}
        tpm_origin_ips: dict[int, dict[str, str]] = {}  # uid -> {origin_id: origin_ip}
        for assignment in assignments:
            uid = assignment.miner_uid
            if uid not in tpm_assignments:
                tpm_assignments[uid] = []
                tpm_origin_ips[uid] = {}
            tpm_assignments[uid].append(assignment.origin_id)
            if assignment.origin_ip:
                tpm_origin_ips[uid][assignment.origin_id] = assignment.origin_ip

        # Log assignment sync results
        if tpm_assignments:
            logger.info(f"TPM assignments: {sum(len(v) for v in tpm_assignments.values())} origins assigned to UIDs {list(tpm_assignments.keys())}")
        else:
            logger.debug("TPM returned no assignments")

        # Check for TPM assignments to unknown UIDs
        known_uids = set(self.miners.keys())
        tpm_uids = set(tpm_assignments.keys())
        unknown_uids = tpm_uids - known_uids
        if unknown_uids:
            logger.warning(f"TPM has assignments for UIDs not in local registry: {unknown_uids}")

        # Track state transitions
        newly_active = []
        newly_unassigned = []

        # Sync all miners with TPM state (thread-safe state transitions)
        for uid, record in self.miners.items():
            tpm_origins = tpm_assignments.get(uid, [])
            has_assignments = len(tpm_origins) > 0

            # Use thread-safe lock for state check and transition
            with record._state_lock:
                old_state = record.state

                # Update assignments to match TPM exactly
                record.assigned_origins = tpm_origins.copy()
                record.assigned_origin_ips = tpm_origin_ips.get(uid, {})

                # State transitions based on assignment changes
                if has_assignments:
                    # Miner is assigned by TPM -> should be ACTIVE
                    if record.state != MinerState.ACTIVE:
                        logger.debug(f"Miner {uid}: {old_state.value} -> ACTIVE (TPM assigned origins: {tpm_origins})")
                        record.state = MinerState.ACTIVE
                        newly_active.append(uid)
                else:
                    # Miner is NOT assigned by TPM
                    if record.state == MinerState.ACTIVE:
                        # Was active but TPM removed assignment -> back to PENDING
                        logger.debug(f"Miner {uid}: ACTIVE -> PENDING (TPM removed assignment)")
                        record.state = MinerState.PENDING
                        newly_unassigned.append(uid)

        if newly_active:
            logger.info(f"Miners marked ACTIVE from TPM assignments: UIDs {newly_active}")
        if newly_unassigned:
            logger.info(f"Miners returned to PENDING (TPM unassigned): UIDs {newly_unassigned}")

        # Log final state counts after sync
        active_after = sum(1 for m in self.miners.values() if m.state == MinerState.ACTIVE)
        with_assignments = sum(1 for m in self.miners.values() if m.assigned_origins)
        logger.info(f"After TPM sync: {active_after} ACTIVE miners, {with_assignments} with assignments")

    async def _run_audit_with_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        audit_func,
        uid: int
    ):
        """Run a single audit with semaphore-based concurrency control."""
        async with semaphore:
            return await audit_func(uid)

    async def run_audits(self) -> List[AuditResult]:
        """
        Run audits on all available miners using PIPELINE ARCHITECTURE.

        PIPELINE PHASES (each phase runs ALL miners in parallel, then waits):
        1. SETUP TUNNELS: Generate keys, send START synapse, setup local WireGuard
        2. SEND TRAFFIC: Send audit packets through all tunnels simultaneously
        3. COLLECT RESULTS: Gather XDP stats from all miners
        4. SCORE & REPORT: Compute scores and update leaderboard

        This ensures true parallelism - no miner blocks another.
        """
        # Check for audit overlap (previous cycle still running)
        current_time = time.time()
        if self.audit_in_progress:
            time_since_start = current_time - self.audit_start_time
            if time_since_start < self.audit_timeout:
                self.audit_overlap_count += 1
                logger.warning(
                    f"Audit overlap detected: previous cycle still running "
                    f"({time_since_start:.1f}s elapsed, overlap_count={self.audit_overlap_count}). "
                    f"Skipping this cycle."
                )
                return []
            else:
                logger.warning(
                    f"Previous audit cycle timed out ({time_since_start:.1f}s > {self.audit_timeout}s). "
                    f"Forcing new cycle."
                )

        # Mark audit as in progress
        self.audit_in_progress = True
        self.audit_start_time = current_time

        # CRITICAL: Ensure thread pool executor is set on the RUNNING loop
        if hasattr(self, '_tunnel_executor'):
            try:
                running_loop = asyncio.get_running_loop()
                running_loop.set_default_executor(self._tunnel_executor)
                logger.info(f"Executor ready: {self._tunnel_executor._max_workers} workers, loop={id(running_loop)}")
            except Exception as e:
                logger.warning(f"Failed to set thread pool executor: {e}")

        # Refresh dendrite to avoid stale connections
        self.dendrite = bt.Dendrite(wallet=self.wallet)

        try:
            # Select all available miners for audit
            available_miners = [
                uid for uid, record in self.miners.items()
                if record.is_available
            ]

            if not available_miners:
                return []

            # Apply queue limit to prevent memory exhaustion
            if len(available_miners) > self.max_pending_audits:
                logger.warning(
                    f"Too many miners ({len(available_miners)} > {self.max_pending_audits}). Limiting."
                )
                sorted_miners = sorted(
                    available_miners,
                    key=lambda uid: self.leaderboard.get_final_score(uid)
                )
                available_miners = sorted_miners[:self.max_pending_audits]

            num_miners = len(available_miners)

            # Initialize audit contexts for all miners
            contexts: Dict[int, AuditContext] = {}
            for uid in available_miners:
                record = self.miners[uid]
                if not record.scrubber_ips:
                    continue
                scrubber_ip = record.scrubber_ips[0]
                challenge_id = f"audit-{self.uid}-{uid}-{int(time.time())}"
                result = AuditResult(
                    uid=uid,
                    timestamp=datetime.utcnow(),
                    miner_state=record.state,
                )
                contexts[uid] = AuditContext(
                    uid=uid,
                    scrubber_ip=scrubber_ip,
                    challenge_id=challenge_id,
                    result=result,
                )

            if not contexts:
                logger.warning("No miners with scrubber IPs available")
                return []

            # ============================================================
            # PHASE TIMEOUTS - Fixed values for up to 256 miners
            # ============================================================
            # With true parallelism, all miners run simultaneously.
            # Timeout = slowest miner + resource contention buffer.
            TUNNEL_SETUP_TIMEOUT = 60.0   # Batched SSH ~5-30s
            TRAFFIC_SEND_TIMEOUT = 600.0  # Packet gen + network (supports 256 miners with 32 workers)
            COLLECT_TIMEOUT = 60.0        # SSH stats read
            SCORING_TIMEOUT = 15.0        # Local computation only (~3s)
            
            ready_uids = list(contexts.keys())
            logger.info(f"Starting audit cycle for available miners..")

            # ============================================================
            # TUNNEL SETUP (parallel for all miners)
            # ============================================================
            tunnel_start = time.time()
            logger.info(f"⚙️ [1/4] Setting up wireguard tunnels for UIDs: {ready_uids}")

            setup_tasks = [
                self._setup_tunnel(ctx)
                for ctx in contexts.values()
            ]
            try:
                await asyncio.wait_for(
                    asyncio.gather(*setup_tasks, return_exceptions=True),
                    timeout=TUNNEL_SETUP_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.warning(f"Tunnel setup timeout after {TUNNEL_SETUP_TIMEOUT}s")

            # Count successful tunnel setups
            tunnels_ready = [uid for uid, ctx in contexts.items() if ctx.tunnel_established]
            tunnels_failed = [uid for uid, ctx in contexts.items() if not ctx.tunnel_established]
            tunnel_elapsed = time.time() - tunnel_start
            logger.info(f"{len(tunnels_ready)}/{len(contexts)} tunnels ready in {tunnel_elapsed:.2f}s")

            if tunnels_failed:
                logger.warning(f"Tunnel setup failed for UIDs: {tunnels_failed}")

            if not tunnels_ready:
                logger.error("No tunnels established - aborting audit cycle")
                return []

            # ============================================================
            # GENERATE SHARED AUDIT PROFILE (fairness: same traffic for all miners)
            # ============================================================
            # Generate ONE profile for the entire round - ensures fair comparison
            round_audit_profile = AuditProfile.generate()

            # ============================================================
            # TRAFFIC SEND (parallel for all miners with tunnels)
            # ============================================================
            traffic_start = time.time()
            logger.info(f"🚦 [2/4] Sending traffic to audit scrubbers for UIDs: {tunnels_ready}")

            traffic_tasks = [
                self._send_traffic(contexts[uid], round_audit_profile)
                for uid in tunnels_ready
            ]
            try:
                await asyncio.wait_for(
                    asyncio.gather(*traffic_tasks, return_exceptions=True),
                    timeout=TRAFFIC_SEND_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.warning(f"Traffic generation timed out after {TRAFFIC_SEND_TIMEOUT}s")

            # Count successful traffic sends
            traffic_sent = [uid for uid in tunnels_ready if contexts[uid].traffic_result is not None]
            traffic_elapsed = time.time() - traffic_start
            logger.info(f"Traffic generation step completed in {traffic_elapsed:.2f}s")

            if not traffic_sent:
                logger.error("No traffic sent - aborting audit cycle")
                # Cleanup tunnels
                for uid in tunnels_ready:
                    ctx = contexts[uid]
                    if ctx.tunnel_manager:
                        try:
                            ctx.tunnel_manager.teardown_local()
                        except Exception:
                            pass
                return []

            # Wait for XDP to process packets before collecting
            await asyncio.sleep(5)

            # ============================================================
            # COLLECT RESULTS (parallel for all miners)
            # ============================================================
            collect_start = time.time()
            logger.info(f"📥 [3/4] Collecting XDP stats for UIDs: {traffic_sent}")

            collect_tasks = [
                self._collect_results(contexts[uid])
                for uid in traffic_sent
            ]
            try:
                await asyncio.wait_for(
                    asyncio.gather(*collect_tasks, return_exceptions=True),
                    timeout=COLLECT_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.warning(f"Collect phase timed out after {COLLECT_TIMEOUT}s")

            # Count successful collections
            collected = [uid for uid in traffic_sent if contexts[uid].collect_response is not None]
            collect_elapsed = time.time() - collect_start
            logger.info(f"Collect phase completed in {collect_elapsed:.2f}s")

            # ============================================================
            # SCORING (batch all miners together for proper normalization)
            # ============================================================
            scoring_start = time.time()
            logger.info(f"🎯 [4/4] Scoring UIDs: {collected}")

            # BATCH SCORING: Build metrics for ALL miners first, then score together
            # This ensures latency normalization works correctly across all miners
            all_metrics: Dict[int, Dict[str, Any]] = {}
            scorable_contexts: Dict[int, AuditContext] = {}

            for uid in collected:
                ctx = contexts[uid]
                if not ctx.collect_response or not ctx.traffic_result:
                    continue

                # Build metrics dict for this miner
                tunnel_rtt = ctx.tunnel_manager.tunnel_rtt_ms if ctx.tunnel_manager else 0.0
                metrics_dict = self._build_metrics_for_reward_model(
                    uid, ctx.traffic_result, ctx.collect_response,
                    tunnel_rtt_ms=tunnel_rtt,
                    scrubber_ip=ctx.scrubber_ip,
                    validator_ip=self.validator_public_ip
                )
                all_metrics[uid] = metrics_dict
                scorable_contexts[uid] = ctx

            # Score ALL miners together in one batch call
            if all_metrics:
                try:
                    event = compute_rewards(all_metrics)

                    # Apply scores back to each context
                    for idx, (uid, metrics_dict) in enumerate(sorted(all_metrics.items())):
                        ctx = scorable_contexts[uid]
                        ctx.result.success = True

                        if idx < len(event.rewards):
                            score = event.rewards[idx]
                            ctx.result.score = score
                            ctx.result.passed_threshold = score >= self.eligibility_threshold

                            # Extract component scores for W&B logging
                            attack_score = event.attack_coverage_scores[idx] if idx < len(event.attack_coverage_scores) else 0.0
                            fp_score = event.false_positive_scores[idx] if idx < len(event.false_positive_scores) else 0.0
                            latency_score = event.latency_scores[idx] if idx < len(event.latency_scores) else 0.0

                            # Store component scores in MinerRecord
                            record = self.miners.get(uid)
                            if record:
                                record.last_attack_score = attack_score
                                record.last_fp_score = fp_score
                                record.last_latency_score = latency_score
                                record.avg_rtt_ms = metrics_dict.get("avg_rtt_ms", 0.0)

                            logger.debug(
                                f"Score UID {uid}: total={score:.3f} | "
                                f"cov={attack_score:.3f}(55%) fp={fp_score:.3f}(25%) lat={latency_score:.3f}(20%)"
                            )
                        else:
                            ctx.result.score = 0.5
                            ctx.result.passed_threshold = False
                            logger.warning(f"No reward computed for UID {uid}, falling back to 0.5")

                        # Store metrics in result
                        miner_response = ctx.collect_response
                        ctx.result.metrics = {
                            "challenge_id": ctx.challenge_id,
                            "ground_truth": {
                                "attack_sent": ctx.traffic_result.attack_sent,
                                "benign_sent": ctx.traffic_result.benign_sent,
                            },
                            "miner_reported": {
                                "blocked": miner_response.reported_blocked,
                                "passed": miner_response.reported_passed,
                            },
                            "audit_type": "real",
                        }

                except Exception as e:
                    logger.error(f"Batch scoring failed: {e}")
                    # Mark all contexts as failed
                    for uid, ctx in scorable_contexts.items():
                        ctx.result.error = f"Batch scoring failed: {e}"
                        ctx.result.success = False

            # Cleanup tunnels for all miners (including failed ones)
            for ctx in contexts.values():
                if ctx.tunnel_manager:
                    try:
                        ctx.tunnel_manager.teardown_local()
                    except Exception:
                        pass

            scoring_elapsed = time.time() - scoring_start
            logger.info(f"{len(collected)} miners scored in {scoring_elapsed:.2f}s")

            # ============================================================
            # PROCESS RESULTS
            # ============================================================
            processed_results = []
            for uid, ctx in contexts.items():
                result = ctx.result
                if isinstance(result, Exception):
                    logger.error(f"Audit exception for UID {uid}: {result}")
                    failed_result = AuditResult(
                        uid=uid,
                        timestamp=datetime.utcnow(),
                        miner_state=self.miners[uid].state if uid in self.miners else MinerState.PENDING,
                        success=False,
                        error=str(result),
                    )
                    processed_results.append(failed_result)
                    if uid in self.miners:
                        self._process_audit_result(failed_result)
                else:
                    processed_results.append(result)
                    self._process_audit_result(result)

            duration = time.time() - self.audit_start_time

            # Compute aggregated statistics for summary logging
            cycle_stats = AuditCycleStats()
            cycle_stats.duration_seconds = duration
            cycle_stats.compute_from_results(processed_results, self.eligibility_threshold, self.miners)

            # Single summary log instead of per-miner spam
            logger.info(f"AUDIT CYCLE COMPLETE ({duration:.1f}s): {cycle_stats.format_summary()}")

            # === TOP 3 MINERS THIS ROUND (with full metrics) ===
            logger.info(f"TOP MINERS THIS AUDIT:\n{cycle_stats.format_top_miners(3)}")

            # === EMA LEADERBOARD (top 10 by EMA score) ===
            # Show current standings based on EMA (long-term performance)
            ema_ranking = []
            for uid, record in self.miners.items():
                if record.ema_audit_score > 0:
                    ema_ranking.append((uid, record.ema_audit_score))
            ema_ranking.sort(key=lambda x: x[1], reverse=True)
            top_3_ema = ema_ranking[:3]
            if top_3_ema:
                ema_str = " | ".join([f"{uid}:{ema:.3f}" for uid, ema in top_3_ema])
                logger.info(f"EMA LEADERBOARD (top {len(top_3_ema)}): {ema_str}")

            # Log failures and anomalies only (not successful audits)
            if cycle_stats.failed_audits > 0:
                failed_uids = [r.uid for r in processed_results if not r.success]
                logger.warning(f"Audit failures ({cycle_stats.failed_audits}): UIDs {failed_uids[:10]}{'...' if len(failed_uids) > 10 else ''}")

            # Log poor performers only (score < 0.5)
            poor_miners = [(r.uid, r.score) for r in processed_results if r.success and r.score < 0.5]
            if poor_miners:
                poor_str = ', '.join(f"{uid}:{score:.2f}" for uid, score in poor_miners[:5])
                logger.warning(f"Poor performers ({len(poor_miners)}): {poor_str}{'...' if len(poor_miners) > 5 else ''}")

            self.last_audit_cycle = time.time()
            return processed_results

        finally:
            # Always mark audit as complete
            self.audit_in_progress = False

    # =========================================================================
    # PIPELINE PHASE METHODS
    # =========================================================================

    async def _setup_tunnel(self, ctx: AuditContext) -> None:
        """
        TUNNEL SETUP: Setup tunnel for a single miner.

        Steps:
        1. Generate WireGuard keypair
        2. Get local IP for scrubber
        3. Send START synapse to miner (miner sets up its side)
        4. Setup local WireGuard interface
        5. Verify tunnel connectivity
        """
        uid = ctx.uid
        scrubber_ip = ctx.scrubber_ip
        loop = asyncio.get_running_loop()

        try:
            # Step 1: Generate WireGuard keypair (in thread pool)
            # CRITICAL: Use explicit executor to guarantee parallelism
            ctx.validator_private_key, ctx.validator_public_key = await loop.run_in_executor(
                self._tunnel_executor,
                generate_wireguard_keypair
            )

            # Step 2: Get local IP for scrubber (in thread pool)
            def _get_local_ip():
                try:
                    result = subprocess.run(
                        ["ip", "route", "get", scrubber_ip],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        parts = result.stdout.split()
                        for i, part in enumerate(parts):
                            if part == "src" and i + 1 < len(parts):
                                return parts[i + 1]
                except Exception:
                    pass
                return None

            ctx.local_ip = await loop.run_in_executor(self._tunnel_executor, _get_local_ip)
            if not ctx.local_ip:
                ctx.local_ip = self.validator_public_ip

            # Calculate tunnel config
            ctx.validator_port = 10000 + (self.uid * 216 + uid)
            subnet_second = 100 + (self.uid % 156)
            ctx.tunnel_ip_validator = f"10.{subnet_second}.{uid}.2"
            ctx.tunnel_ip_scrubber = f"10.{subnet_second}.{uid}.1"

            # Step 3: Send START synapse to miner
            start_synapse = AuditChallengeSynapse(
                challenge_id=ctx.challenge_id,
                phase="start",
                scrubber_ip=scrubber_ip,
                expected_duration_seconds=30,
                validator_pubkey=ctx.validator_public_key,
                validator_ip=ctx.local_ip or "",
                validator_port=ctx.validator_port,
                validator_uid=self.uid,
            )

            # Per-miner timeout: generous to handle slow miners but not infinite
            # Miner needs to: SSH to scrubber (~2s), run batched commands (~5-10s)
            # Network latency varies by region (10-200ms RTT)
            START_TIMEOUT = 90.0  # Reduced from 120s - batched SSH is faster
            MAX_RETRIES = 1  # Reduced retries - timeout handles failures

            start_time = time.time()
            logger.debug(f"UID {uid}: Sending START synapse...")
            start_response = None
            for attempt in range(MAX_RETRIES):
                if attempt > 0:
                    await asyncio.sleep(5.0)

                try:
                    responses = await self.dendrite.forward(
                        axons=[self.metagraph.axons[uid]],
                        synapse=start_synapse,
                        timeout=START_TIMEOUT,
                    )
                    if responses and responses[0].success:
                        start_response = responses[0]
                        break
                except Exception as e:
                    logger.trace(f"START UID {uid} attempt {attempt+1} error: {e}")

            start_elapsed = time.time() - start_time
            if not start_response:
                ctx.phase_failed = "start"
                ctx.error_message = f"Miner failed to respond to START (after {start_elapsed:.1f}s)"
                ctx.result.error = ctx.error_message
                logger.warning(f"UID {uid}: START FAILED after {start_elapsed:.1f}s - miner may be slow/offline")
                return

            # Log with timing categories for diagnostics
            if start_elapsed < 15:
                logger.debug(f"UID {uid}: START OK (fast) in {start_elapsed:.1f}s")
            elif start_elapsed < 45:
                logger.debug(f"UID {uid}: START OK (normal) in {start_elapsed:.1f}s")
            else:
                logger.debug(f"UID {uid}: START OK (slow) in {start_elapsed:.1f}s - consider investigating")

            # Step 4: Setup local WireGuard interface
            if start_response.scrubber_pubkey and start_response.scrubber_port:
                ctx.tunnel_manager = SynapseBasedTunnelManager(
                    scrubber_ip=scrubber_ip,
                    miner_uid=uid,
                    validator_uid=self.uid,
                )
                ctx.tunnel_manager.validator_private_key = ctx.validator_private_key
                ctx.tunnel_manager.validator_public_key = ctx.validator_public_key
                ctx.tunnel_manager.scrubber_public_key = start_response.scrubber_pubkey
                ctx.tunnel_manager.scrubber_port = start_response.scrubber_port
                ctx.tunnel_manager.tunnel_ip_scrubber = start_response.tunnel_ip_scrubber or ctx.tunnel_ip_scrubber
                ctx.tunnel_manager.tunnel_ip_validator = start_response.tunnel_ip_validator or ctx.tunnel_ip_validator

                # Setup local interface (in thread pool - explicit executor for parallelism)
                setup_ok = await loop.run_in_executor(
                    self._tunnel_executor,
                    ctx.tunnel_manager._setup_local_interface
                )
                if setup_ok:
                    # Verify tunnel and measure RTT (used for latency scoring)
                    tunnel_ok, rtt_ms = await loop.run_in_executor(
                        self._tunnel_executor,
                        ctx.tunnel_manager._verify_tunnel
                    )
                    ctx.tunnel_manager.tunnel_rtt_ms = rtt_ms
                    if tunnel_ok:
                        logger.debug(f"Tunnel verified UID {uid} RTT={rtt_ms:.1f}ms")
                    else:
                        logger.warning(f"Tunnel verification failed UID {uid}, RTT unknown")

                    ctx.tunnel_established = True
                    ctx.tunnel_interface = ctx.tunnel_manager.get_tunnel_interface()
                    ctx.tunnel_dest_ip = ctx.tunnel_manager.get_tunnel_destination()
                    logger.trace(f"Tunnel ready UID {uid}")
                else:
                    ctx.phase_failed = "tunnel_setup"
                    ctx.error_message = "Local WireGuard setup failed"
                    ctx.result.error = ctx.error_message
            else:
                ctx.phase_failed = "tunnel_config"
                ctx.error_message = "Miner didn't return tunnel config"
                ctx.result.error = ctx.error_message

        except Exception as e:
            ctx.phase_failed = "setup"
            ctx.error_message = str(e)
            ctx.result.error = f"Tunnel setup error: {e}"
            logger.error(f"[TUNNEL] UID {uid} error: {e}")

    async def _send_traffic(self, ctx: AuditContext, audit_profile: Optional[AuditProfile] = None) -> None:
        """
        TRAFFIC SEND: Send audit traffic through the tunnel.

        FAIRNESS: When audit_profile is provided, all miners receive identical
        traffic patterns for fair comparison within the same round.
        """
        uid = ctx.uid

        if not ctx.tunnel_established:
            return

        try:
            # Send traffic using shared audit profile for fair comparison
            ctx.traffic_result = await self.real_packet_sender.send_real_traffic(
                scrubber_ip=ctx.scrubber_ip,
                challenge_id=ctx.challenge_id,
                tunnel_interface=ctx.tunnel_interface,
                tunnel_dest_ip=ctx.tunnel_dest_ip,
                audit_profile=audit_profile,
            )
            logger.trace(f"Traffic sent UID {uid}: {ctx.traffic_result.total_sent} packets")

        except Exception as e:
            ctx.phase_failed = "traffic"
            ctx.error_message = str(e)
            ctx.result.error = f"Traffic send failed: {e}"
            logger.error(f"[TRAFFIC] UID {uid} error: {e}")

    async def _collect_results(self, ctx: AuditContext) -> None:
        """
        COLLECT: Collect XDP stats from miner.
        """
        uid = ctx.uid

        if not ctx.traffic_result:
            return

        try:
            collect_synapse = AuditChallengeSynapse(
                challenge_id=ctx.challenge_id,
                phase="collect",
                scrubber_ip=ctx.scrubber_ip,
                challenge_nonce=ctx.traffic_result.challenge_nonce,
                validator_uid=self.uid,
            )

            # Per-miner collect timeout: miner reads XDP stats via SSH
            # Should be fast (~5-10s) but allow buffer for slow networks
            MINER_COLLECT_TIMEOUT = 30.0
            MAX_RETRIES = 1  # Phase timeout handles failures

            for attempt in range(MAX_RETRIES):
                if attempt > 0:
                    await asyncio.sleep(2.0)

                try:
                    responses = await self.dendrite.forward(
                        axons=[self.metagraph.axons[uid]],
                        synapse=collect_synapse,
                        timeout=MINER_COLLECT_TIMEOUT,
                    )
                    if responses and responses[0].success:
                        ctx.collect_response = responses[0]
                        break
                except Exception as e:
                    logger.trace(f"COLLECT UID {uid} attempt {attempt+1} error: {e}")

            if not ctx.collect_response:
                ctx.phase_failed = "collect"
                ctx.error_message = "Miner failed to return stats"
                ctx.result.error = ctx.error_message
                ctx.result.score = 0.1
                ctx.result.success = False

        except Exception as e:
            ctx.phase_failed = "collect"
            ctx.error_message = str(e)
            ctx.result.error = f"Collect failed: {e}"
            logger.error(f"[COLLECT] UID {uid} error: {e}")

    async def _score_miner(self, ctx: AuditContext) -> None:
        """
        SCORING: Score the miner based on collected results.
        """
        uid = ctx.uid

        if not ctx.collect_response or not ctx.traffic_result:
            return

        try:
            miner_response = ctx.collect_response

            # Compute score using reward model
            tunnel_rtt = ctx.tunnel_manager.tunnel_rtt_ms if ctx.tunnel_manager else 0.0
            ctx.result.success = True
            ctx.result.score = self._compute_reward_model_score(
                uid, ctx.traffic_result, miner_response,
                tunnel_rtt_ms=tunnel_rtt,
                scrubber_ip=ctx.scrubber_ip,
                validator_ip=self.validator_public_ip
            )
            ctx.result.passed_threshold = ctx.result.score >= self.eligibility_threshold

            # Store metrics
            ctx.result.metrics = {
                "challenge_id": ctx.challenge_id,
                "ground_truth": {
                    "attack_sent": ctx.traffic_result.attack_sent,
                    "benign_sent": ctx.traffic_result.benign_sent,
                },
                "miner_reported": {
                    "blocked": miner_response.reported_blocked,
                    "passed": miner_response.reported_passed,
                },
                "audit_type": "real",
            }

            logger.trace(f"Scored UID {uid}: {ctx.result.score:.3f}")

        except Exception as e:
            ctx.result.error = f"Scoring failed: {e}"
            ctx.result.success = False
            logger.error(f"[SCORING] UID {uid} error: {e}")

    async def _audit_miner(self, uid: int) -> AuditResult:
        """
        Audit a miner using REAL traffic.

        This uses the challenge-response system to verify the miner's
        XDP program is actually filtering traffic, not faking results.

        Flow:
        1. Send 'start' to miner - miner snapshots XDP stats
        2. Send REAL packets to scrubber IP
        3. Send 'collect' to miner - miner returns XDP stats delta
        4. Compare miner's report with ground truth
        """
        record = self.miners[uid]
        result = AuditResult(
            uid=uid,
            timestamp=datetime.utcnow(),
            miner_state=record.state,
        )

        try:
            if not record.scrubber_ips:
                result.error = "No scrubber IPs available"
                return result

            scrubber_ip = record.scrubber_ips[0]

            # Use real audit if available, otherwise fall back to simulated
            if self.use_real_audits and self.real_packet_sender:
                result = await self._run_real_audit(uid, scrubber_ip, result)
            else:
                # Fallback to simulated test (NOT RECOMMENDED for production)
                logger.trace(f"Using SIMULATED audit for UID {uid}")
                result = await self._run_simulated_audit(uid, scrubber_ip, result)

        except Exception as e:
            logger.error(f"Pre-assignment audit error for UID {uid}: {e}")
            result.error = str(e)

        return result

    async def _run_real_audit(
        self,
        uid: int,
        scrubber_ip: str,
        result: AuditResult
    ) -> AuditResult:
        """
        Run a REAL traffic audit with challenge-response verification.

        SCALABLE 2-ROUND-TRIP FLOW:
        1. START synapse includes tunnel config - miner sets up WG + snapshots XDP stats
        2. Validator sets up local WG interface from miner's response
        3. Send traffic through tunnel
        4. COLLECT synapse - miner returns XDP stats delta

        This eliminates the separate SetupTunnelSynapse round-trip for scalability.
        """
        record = self.miners[uid]
        # Include validator UID in challenge_id to ensure uniqueness across validators
        # Format: audit-{validator_uid}-{miner_uid}-{timestamp}
        challenge_id = f"audit-{self.uid}-{uid}-{int(time.time())}"
        tunnel_manager = None
        tunnel_rtt_ms = 0.0

        # Per-miner audit start at TRACE level to reduce spam with 50+ miners
        logger.trace(f"Audit UID {uid}: challenge={challenge_id}")

        # Step 0: Generate local WireGuard keypair for tunnel
        # We'll include this in the START synapse for combined tunnel+audit flow
        # Run in thread pool to avoid blocking event loop (critical for 256+ concurrent audits)
        import subprocess
        validator_private_key, validator_public_key = await asyncio.to_thread(generate_wireguard_keypair)

        # Get local IP that can reach the scrubber (for tunnel endpoint)
        # Use ip route get to find the correct outgoing interface IP
        # Run in thread pool to avoid blocking event loop
        def _get_local_ip_for_scrubber():
            try:
                result = subprocess.run(
                    ["ip", "route", "get", scrubber_ip],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    parts = result.stdout.split()
                    for i, part in enumerate(parts):
                        if part == "src" and i + 1 < len(parts):
                            return parts[i + 1]
            except Exception:
                pass
            return None

        local_ip = await asyncio.to_thread(_get_local_ip_for_scrubber)

        # Fallback to cached validator public IP
        if not local_ip:
            local_ip = self.validator_public_ip

        # Calculate tunnel config (scalable for 256 miners per validator)
        # Port formula: 10000 + V*216 + M (max port = 65335, no collisions)
        validator_port = 10000 + (self.uid * 216 + uid)
        # Interface name: wga{V}_{M} - max 10 chars, fits Linux 15-char limit
        tunnel_name = f"wga{self.uid}_{uid}"
        # Subnet: 10.{100+V%156}.{M}.{1,2}/30 - supports up to 156 validators
        subnet_second = 100 + (self.uid % 156)
        tunnel_ip_validator = f"10.{subnet_second}.{uid}.2"
        tunnel_ip_scrubber = f"10.{subnet_second}.{uid}.1"

        # NOTE: Validator does NOT read XDP stats directly from scrubber
        # Only the miner has access to its scrubber machines
        # The miner will snapshot stats and report delta back to us

        # Step 1: Send 'start' phase to miner WITH tunnel config
        # This combines tunnel setup + stats snapshot into one round-trip
        #
        # RELIABILITY: Use retry logic for start phase. The miner must SSH to scrubber
        # and set up WireGuard tunnel (17+ commands), which can fail due to network issues.
        start_synapse = AuditChallengeSynapse(
            challenge_id=challenge_id,
            phase="start",
            scrubber_ip=scrubber_ip,
            expected_duration_seconds=30,
            # Include tunnel setup fields for combined flow
            validator_pubkey=validator_public_key,
            validator_ip=local_ip or "",
            validator_port=validator_port,
            validator_uid=self.uid,
        )

        # Retry configuration for reliability
        START_TIMEOUT = 120.0  # Generous timeout for cross-region SSH latency
        MAX_START_RETRIES = 2  # Try up to 2 times
        START_RETRY_DELAY = 5.0  # Wait 5 seconds between retries

        start_responses = None
        last_start_error = None

        for attempt in range(MAX_START_RETRIES):
            if attempt > 0:
                logger.debug(f"Start retry {attempt + 1}/{MAX_START_RETRIES} for UID {uid} after {START_RETRY_DELAY}s delay")
                await asyncio.sleep(START_RETRY_DELAY)

            try:
                start_responses = await self.dendrite.forward(
                    axons=[self.metagraph.axons[uid]],
                    synapse=start_synapse,
                    timeout=START_TIMEOUT,
                )

                if start_responses and start_responses[0].success:
                    break  # Success! Exit retry loop
                else:
                    last_start_error = start_responses[0].error_message if start_responses else "No response"
                    logger.trace(f"Start UID {uid} attempt {attempt + 1} failed: {last_start_error}")

            except Exception as e:
                last_start_error = str(e)
                logger.warning(f"Start UID {uid} attempt {attempt + 1} exception: {e}")
                start_responses = None

        if not start_responses or not start_responses[0].success:
            error_msg = last_start_error or "No response after retries"
            result.error = f"Miner failed to start audit: {error_msg}"
            logger.error(f"Audit start failed for UID {uid} after {MAX_START_RETRIES} attempts: {result.error}")
            return result

        start_response = start_responses[0]
        logger.trace(f"Miner {uid} audit started")

        # Step 2: Set up local WireGuard interface using miner's response
        if start_response.scrubber_pubkey and start_response.scrubber_port:
            try:
                tunnel_manager = SynapseBasedTunnelManager(
                    scrubber_ip=scrubber_ip,
                    miner_uid=uid,
                    validator_uid=self.uid,
                )
                # Set the received config
                tunnel_manager.validator_private_key = validator_private_key
                tunnel_manager.validator_public_key = validator_public_key
                tunnel_manager.scrubber_public_key = start_response.scrubber_pubkey
                tunnel_manager.scrubber_port = start_response.scrubber_port
                tunnel_manager.tunnel_ip_scrubber = start_response.tunnel_ip_scrubber or tunnel_ip_scrubber
                tunnel_manager.tunnel_ip_validator = start_response.tunnel_ip_validator or tunnel_ip_validator

                # Set up local WireGuard interface only (scrubber side already done by miner)
                # Run in thread pool to avoid blocking event loop (critical for 256+ concurrent audits)
                setup_ok = await asyncio.to_thread(tunnel_manager._setup_local_interface)
                if setup_ok:
                    # Verify tunnel with small probe packet before sending audit traffic
                    # This helps distinguish tunnel failure from filtering failure
                    tunnel_verified = await self._verify_tunnel_with_probe(tunnel_manager, uid)
                    if tunnel_verified:
                        tunnel_manager.tunnel_established = True
                        logger.trace(f"WireGuard tunnel verified UID {uid}")
                    else:
                        # Log warning but continue - XDP may block probe as bogon (10.x.x.x)
                        # We still mark tunnel as established since setup succeeded
                        tunnel_manager.tunnel_established = True
                        tunnel_manager.tunnel_rtt_ms = 0.0  # Unknown without verification
                        logger.warning(f"WireGuard tunnel probe failed UID {uid} - continuing (XDP may block probe)")
                else:
                    logger.warning(f"Local WireGuard setup failed UID {uid} - score 0")
                    result.error = "Tunnel setup failed on validator side"
                    return result
            except Exception as e:
                logger.warning(f"WireGuard local setup error UID {uid}: {e} - score 0")
                result.error = f"Tunnel setup error: {e}"
                return result
        else:
            # SECURITY: Never send traffic without tunnel encryption
            # If miner doesn't return tunnel config, score them 0
            logger.warning(f"Miner {uid} didn't return tunnel config - score 0")
            result.error = "Miner failed to provide tunnel config"
            return result

        # Step 2: Send REAL packets to scrubber (via tunnel ONLY - no direct send)
        tunnel_interface = tunnel_manager.get_tunnel_interface()
        tunnel_dest_ip = tunnel_manager.get_tunnel_destination()

        try:
            single_profile = AuditProfile.generate()
            traffic_result = await self.real_packet_sender.send_real_traffic(
                scrubber_ip=scrubber_ip,
                challenge_id=challenge_id,
                tunnel_interface=tunnel_interface,
                tunnel_dest_ip=tunnel_dest_ip,
                audit_profile=single_profile,
            )

            logger.trace(f"Traffic sent UID {uid}: {traffic_result.total_sent} pkts via tunnel {tunnel_manager.tunnel_name}")
        except Exception as e:
            logger.error(f"Failed to send audit traffic: {e}")
            if tunnel_manager:
                tunnel_manager.teardown_local()
            result.error = f"Traffic send failed: {e}"
            return result

        # Delay to ensure XDP has processed all packets before collecting stats
        # Increased from 2s to 5s to handle high-volume audits and slow XDP processing
        await asyncio.sleep(5)

        # Step 3: Send 'collect' phase to miner BEFORE tunnel teardown
        # (tunnel teardown can affect local networking when validator/miner are co-located)
        #
        # RELIABILITY: Use retry logic with increased timeout for collect phase.
        # The miner must SSH to scrubber and run multiple bpftool commands to collect
        # XDP stats, which can take 5-15 seconds on cross-region connections.
        # Timeout increased from 30s to 60s, with one retry on failure.
        collect_synapse = AuditChallengeSynapse(
            challenge_id=challenge_id,
            phase="collect",
            scrubber_ip=scrubber_ip,
            challenge_nonce=traffic_result.challenge_nonce,
            validator_uid=self.uid,  # Needed for miner to find correct XDP stats map
        )

        # Retry configuration for reliability
        COLLECT_TIMEOUT = 60.0  # Increased from 30s for cross-region miners
        MAX_COLLECT_RETRIES = 2  # Try up to 2 times
        RETRY_DELAY = 3.0  # Wait 3 seconds between retries

        collect_responses = None
        last_error = None

        for attempt in range(MAX_COLLECT_RETRIES):
            if attempt > 0:
                logger.debug(f"Collect retry {attempt + 1}/{MAX_COLLECT_RETRIES} for UID {uid} after {RETRY_DELAY}s delay")
                await asyncio.sleep(RETRY_DELAY)

            logger.trace(f"Collect phase UID {uid} (attempt {attempt + 1})")

            try:
                collect_responses = await self.dendrite.forward(
                    axons=[self.metagraph.axons[uid]],
                    synapse=collect_synapse,
                    timeout=COLLECT_TIMEOUT,
                )

                # Check if we got a successful response
                if collect_responses and collect_responses[0].success:
                    resp = collect_responses[0]
                    blocked = sum(resp.reported_blocked.values()) if resp.reported_blocked else 0
                    logger.trace(f"Collect UID {uid}: blocked={blocked}, passed={resp.reported_passed}")
                    break  # Success! Exit retry loop
                else:
                    # Got response but not successful
                    if collect_responses:
                        last_error = collect_responses[0].error_message or "Unknown error"
                        logger.trace(f"Collect UID {uid} attempt {attempt + 1} failed: {last_error}")
                    else:
                        last_error = "No response"
                        logger.trace(f"Collect UID {uid} attempt {attempt + 1}: no response")

            except Exception as e:
                last_error = str(e)
                logger.warning(f"Collect UID {uid} attempt {attempt + 1} exception: {e}")
                collect_responses = None

        # Check final result after all retries
        if not collect_responses or not collect_responses[0].success:
            error_msg = last_error or "No response after retries"
            # Miner failed to report stats - audit fails with low score
            result.error = f"Miner failed to collect audit results: {error_msg}"
            logger.error(f"Audit collect failed for UID {uid} after {MAX_COLLECT_RETRIES} attempts: {result.error}")
            result.score = 0.1  # Low score for non-responsive miner
            result.success = False
            # Cleanup tunnel on error path
            if tunnel_manager:
                try:
                    tunnel_manager.teardown_local()
                except Exception as e:
                    logger.warning(f"Tunnel teardown error: {e}")
            return result

        miner_response = collect_responses[0]

        # Log miner-reported stats (detail at trace level)
        # Exclude aggregate counters (ratelimit, quarantine, invalid_ip) from blocked total
        # These are not specific attack types we send and can cause inflated counts
        EXCLUDE_FROM_BLOCKED = {"ratelimit", "quarantine", "invalid_ip"}
        blocked_total = sum(
            v for k, v in miner_response.reported_blocked.items()
            if k not in EXCLUDE_FROM_BLOCKED
        ) if miner_response.reported_blocked else 0
        logger.trace(f"Miner {uid} stats: blocked={blocked_total}, passed={miner_response.reported_passed}")

        # Step 4: Score using ProductionRewardModel (includes distance-based latency normalization)
        result.success = True
        tunnel_rtt = tunnel_manager.tunnel_rtt_ms if tunnel_manager else 0.0
        result.score = self._compute_reward_model_score(
            uid, traffic_result, miner_response,
            tunnel_rtt_ms=tunnel_rtt,
            scrubber_ip=scrubber_ip,
            validator_ip=self.validator_public_ip
        )
        result.passed_threshold = result.score >= self.eligibility_threshold

        # Store detailed metrics
        result.metrics = {
            "challenge_id": challenge_id,
            "ground_truth": {
                "attack_sent": traffic_result.attack_sent,
                "benign_sent": traffic_result.benign_sent,
                "malformed_sent": traffic_result.malformed_sent,
                "bogon_sent": traffic_result.bogon_sent,
                "blacklist_sent": traffic_result.blacklist_sent,
                # Sequence tracking for duplicate detection
                "seq_start": traffic_result.seq_start,
                "seq_end": traffic_result.seq_end,
            },
            "miner_reported": {
                "blocked": miner_response.reported_blocked,
                "passed": miner_response.reported_passed,
                "stats_delta": miner_response.stats_delta,
            },
            "audit_type": "real",
        }

        # Final audit result - the key metric
        # Note: reported_passed is ALL packets that passed XDP (attacks + benign)
        attacks_passed = max(0, traffic_result.attack_sent - blocked_total)
        estimated_benign_passed = max(0, miner_response.reported_passed - attacks_passed)
        # MULTI-MINER: Per-miner results at TRACE level, summary logged at cycle end
        logger.trace(
            f"Audit UID {uid}: score={result.score:.3f}, "
            f"blocked={blocked_total}/{traffic_result.attack_sent}, "
            f"benign={estimated_benign_passed}/{traffic_result.benign_sent}"
        )

        # Teardown tunnel AFTER collect phase is complete
        if tunnel_manager:
            try:
                tunnel_manager.teardown_local()
            except Exception as e:
                logger.warning(f"Tunnel teardown error: {e}")

        return result

    async def _verify_tunnel_with_probe(
        self,
        tunnel_manager,
        uid: int,
        timeout: float = 2.0
    ) -> bool:
        """
        Verify tunnel connectivity with a small probe packet.

        Sends a single ICMP ping through the tunnel to verify it's working
        before sending audit traffic. This helps distinguish tunnel failures
        from legitimate XDP filtering.

        Note: XDP may block the probe as bogon (10.x.x.x private IPs), so
        failure here doesn't necessarily mean the tunnel is broken.

        Args:
            tunnel_manager: The tunnel manager with connection details
            uid: Miner UID for logging
            timeout: Timeout in seconds for the probe

        Returns:
            True if probe succeeded, False otherwise
        """
        import subprocess

        tunnel_dest = tunnel_manager.get_tunnel_destination()
        tunnel_iface = tunnel_manager.get_tunnel_interface()

        if not tunnel_dest or not tunnel_iface:
            logger.trace(f"Tunnel probe UID {uid}: missing dest or interface")
            return False

        def _do_ping():
            try:
                # Single ping with short timeout through the tunnel interface
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", str(int(timeout)), "-I", tunnel_iface, tunnel_dest],
                    capture_output=True,
                    text=True,
                    timeout=timeout + 1
                )
                if result.returncode == 0:
                    # Extract RTT from ping output
                    # Format: "rtt min/avg/max/mdev = 1.234/1.234/1.234/0.000 ms"
                    for line in result.stdout.split('\n'):
                        if 'rtt' in line and 'avg' in line:
                            try:
                                # Parse avg RTT
                                parts = line.split('=')[1].split('/') if '=' in line else []
                                if len(parts) >= 2:
                                    tunnel_manager.tunnel_rtt_ms = float(parts[1])
                            except (IndexError, ValueError):
                                pass
                    return True
                return False
            except subprocess.TimeoutExpired:
                return False
            except Exception as e:
                logger.trace(f"Tunnel probe error UID {uid}: {e}")
                return False

        # Run ping in thread pool to avoid blocking
        return await asyncio.to_thread(_do_ping)

    def _build_metrics_for_reward_model(
        self,
        uid: int,
        ground_truth,  # TrafficTestResult or RealTrafficResult
        miner_response: Optional[AuditChallengeSynapse] = None,
        tunnel_rtt_ms: float = 0.0,  # RTT from tunnel verification
        scrubber_ip: str = "",  # Scrubber's public IP for distance calculation
        validator_ip: str = ""  # Validator's public IP for distance calculation
    ) -> Dict[str, Any]:
        """
        Build metrics dict for ProductionRewardModel from audit results.

        Maps all attack categories from ground truth and miner response:
        - Layer 3 IP: spoofed, bogon, blacklist, invalid_ip
        - Layer 4 TCP: syn_flood, xmas, null, fin, rst, ack, synfin, synrst
        - Layer 4 UDP: udp_flood, udp_amp (dns, ntp, memcached, ssdp, snmp, chargen)
        - Layer 3 ICMP: icmp_flood, icmp_frag
        - Fragmentation: frag_overlap, frag_tiny
        - Layer 7: slowloris, http_flood (caught by rate limiting)
        - Malformed: malformed packets

        Args:
            uid: Miner's UID
            ground_truth: Results from synthetic (TrafficTestResult) or real (RealTrafficResult) traffic test
            miner_response: Optional miner-reported stats from real audit
            tunnel_rtt_ms: RTT measured from tunnel ping (for real audits)
            scrubber_ip: Scrubber's public IP for geographic distance calculation
            validator_ip: Validator's public IP for geographic distance calculation

        Returns:
            Dict compatible with compute_rewards()
        """
        # Check if this is a TrafficTestResult (simulated) or RealTrafficResult
        is_simulated = hasattr(ground_truth, 'spoofed_blocked')
        is_real = hasattr(ground_truth, 'get_attack_breakdown')

        # === SENT COUNTS (from ground truth) ===
        # Separate signature-based vs rate-limited attacks for proper scoring
        if is_real and hasattr(ground_truth, 'get_attack_breakdown'):
            # Layer 3 IP: bogon + blacklist + land
            layer3_ip_sent = (
                getattr(ground_truth, 'bogon_sent', 0) +
                getattr(ground_truth, 'blacklist_sent', 0) +
                getattr(ground_truth, 'land_attack_sent', 0)
            )

            # Layer 4 TCP FLAG attacks (signature-based, not rate-limited)
            layer4_tcp_flag_sent = (
                getattr(ground_truth, 'tcp_xmas_sent', 0) +
                getattr(ground_truth, 'tcp_null_sent', 0) +
                getattr(ground_truth, 'tcp_synfin_sent', 0) +
                getattr(ground_truth, 'tcp_synrst_sent', 0) +
                getattr(ground_truth, 'tcp_fin_sent', 0) +
                getattr(ground_truth, 'tcp_rst_sent', 0) +
                getattr(ground_truth, 'tcp_ack_sent', 0)
            )

            # Layer 4 UDP AMP attacks (signature-based, port detection)
            layer4_udp_amp_sent = (
                getattr(ground_truth, 'udp_amp_dns_sent', 0) +
                getattr(ground_truth, 'udp_amp_ntp_sent', 0) +
                getattr(ground_truth, 'udp_amp_memcached_sent', 0) +
                getattr(ground_truth, 'udp_amp_ssdp_sent', 0) +
                getattr(ground_truth, 'udp_amp_snmp_sent', 0) +
                getattr(ground_truth, 'udp_amp_chargen_sent', 0)
            )

            # Rate-limited attacks (binary scoring: triggered or not)
            ratelimit_syn_sent = getattr(ground_truth, 'syn_flood_sent', 0)
            ratelimit_udp_sent = getattr(ground_truth, 'udp_flood_sent', 0)
            # ICMP includes both flood and frag - both are rate-limited by XDP
            ratelimit_icmp_sent = (
                getattr(ground_truth, 'icmp_flood_sent', 0) +
                getattr(ground_truth, 'icmp_frag_sent', 0)
            )
            ratelimit_tcp_sent = 0  # Not used - no ground truth traffic generated
            ratelimit_app_sent = (
                getattr(ground_truth, 'slowloris_sent', 0) +
                getattr(ground_truth, 'http_flood_sent', 0)
            )

            # Fragmentation and malformed
            fragmentation_sent = (
                getattr(ground_truth, 'frag_overlap_sent', 0) +
                getattr(ground_truth, 'frag_tiny_sent', 0)
            )
            malformed_sent = getattr(ground_truth, 'malformed_sent', 0)
            benign_sent = getattr(ground_truth, 'benign_sent', 0)

            # For backward compatibility, also compute combined counts
            layer4_tcp_sent = layer4_tcp_flag_sent + ratelimit_syn_sent
            layer4_udp_sent = layer4_udp_amp_sent + ratelimit_udp_sent
            layer3_icmp_sent = ratelimit_icmp_sent
            layer7_app_sent = ratelimit_app_sent
        else:
            # Fallback for simulated or legacy results
            bogon_sent = getattr(ground_truth, 'bogon_sent', 0)
            blacklist_sent = getattr(ground_truth, 'blacklist_sent', 0)
            land_attack_sent = getattr(ground_truth, 'land_attack_sent', 0)
            layer3_ip_sent = bogon_sent + blacklist_sent + land_attack_sent
            layer4_tcp_flag_sent = 0
            layer4_udp_amp_sent = 0
            layer4_tcp_sent = 0
            layer4_udp_sent = 0
            layer3_icmp_sent = 0
            fragmentation_sent = 0
            ratelimit_syn_sent = 0
            ratelimit_udp_sent = 0
            ratelimit_icmp_sent = 0
            ratelimit_tcp_sent = 0
            ratelimit_app_sent = 0
            layer7_app_sent = 0
            malformed_sent = getattr(ground_truth, 'malformed_sent', 0)
            benign_sent = getattr(ground_truth, 'benign_sent', 0)

        # === BLOCKED COUNTS (from miner response) ===
        if miner_response and miner_response.reported_blocked:
            blocked = miner_response.reported_blocked

            # Layer 3 IP: blacklist, bogon, invalid_ip, land (spoofed IPs caught here)
            layer3_ip_blocked = (
                blocked.get("blacklist", 0) +
                blocked.get("bogon", 0) +
                blocked.get("invalid_ip", 0) +
                blocked.get("land", 0)
            )

            # Layer 4 TCP FLAG attacks (signature-based)
            layer4_tcp_flag_blocked = (
                blocked.get("tcp_xmas", 0) +
                blocked.get("tcp_null", 0) +
                blocked.get("tcp_synfin", 0) +
                blocked.get("tcp_synrst", 0) +
                blocked.get("tcp_fin", 0) +
                blocked.get("tcp_rst", 0) +
                blocked.get("tcp_ack", 0)
            )

            # Layer 4 UDP AMP attacks (signature-based port detection)
            layer4_udp_amp_blocked = blocked.get("udp_amp", 0)

            # Rate-limited attacks - these use binary scoring
            # syn_flood, udp_flood, icmp_flood are rate-limited, not signature-based
            # SYN flood includes hard drops + SYN cookie challenges/rejects.
            # SYN cookies are the primary SYN flood mitigation — they drop the first SYN from
            # each source and wait for retry. Spoofed IPs never retry, so cookies = effective drops.
            # Cookie counters are reported separately because they also catch benign SYNs during floods,
            # so we only add them here (for scoring) and NOT in total_blocked (for benign calculation).
            ratelimit_syn_blocked = (
                blocked.get("syn_flood", 0) +
                blocked.get("syncookie_challenge", 0) +
                blocked.get("syncookie_reject", 0)
            )
            ratelimit_udp_blocked = blocked.get("udp_flood", 0)
            ratelimit_icmp_blocked = blocked.get("icmp_flood", 0)
            ratelimit_tcp_blocked = 0  # Not used - no ground truth traffic generated
            # App layer (L7) blocking - combines XDP L7 detection + nginx rate limiting
            # XDP reports http_flood and slowloris separately (xdp_drop_http_flood, xdp_drop_slowloris)
            # nginx reports L7 rate limiting as ratelimit_app
            ratelimit_app_blocked = (
                blocked.get("http_flood", 0) +
                blocked.get("slowloris", 0) +
                blocked.get("ratelimit_app", 0)  # nginx L7 rate limiting
            )

            # Redistribute generic drops across rate-limited categories.
            # XDP has several counters that capture attack drops but aren't attack-specific:
            # - "ratelimit": per-source rate limiter (generic counter)
            # - "quarantine": IPs quarantined after repeated violations
            # - "temp_blacklist": temporarily blacklisted IPs
            # Distribute proportionally by sent counts so scoring properly credits the miner.
            generic_ratelimit = (
                blocked.get("ratelimit", 0) +
                blocked.get("quarantine", 0) +
                blocked.get("temp_blacklist", 0)
            )
            if generic_ratelimit > 0:
                total_rl_sent = ratelimit_syn_sent + ratelimit_udp_sent + ratelimit_icmp_sent + ratelimit_app_sent
                if total_rl_sent > 0:
                    ratelimit_syn_blocked += int(generic_ratelimit * ratelimit_syn_sent / total_rl_sent)
                    ratelimit_udp_blocked += int(generic_ratelimit * ratelimit_udp_sent / total_rl_sent)
                    ratelimit_icmp_blocked += int(generic_ratelimit * ratelimit_icmp_sent / total_rl_sent)
                    ratelimit_app_blocked += int(generic_ratelimit * ratelimit_app_sent / total_rl_sent)

            # Fragmentation attacks
            fragmentation_blocked = blocked.get("frag", 0)

            # Malformed packets
            malformed_blocked = blocked.get("malformed", 0)

            # For backward compatibility, compute combined counts
            layer4_tcp_blocked = layer4_tcp_flag_blocked + ratelimit_syn_blocked
            layer4_udp_blocked = layer4_udp_amp_blocked + ratelimit_udp_blocked
            layer3_icmp_blocked = ratelimit_icmp_blocked
            layer7_app_blocked = ratelimit_app_blocked

            # Calculate total blocked attacks first (needed for benign_passed calculation)
            # Exclude syncookie counters — they catch benign SYNs too during floods,
            # so including them would inflate total_blocked and undercount benign_passed.
            total_blocked = sum(
                v for k, v in blocked.items()
                if k not in {"syncookie_challenge", "syncookie_reject", "counter_reset_detected"}
            )
            total_attacks_sent = (
                layer3_ip_sent + layer4_tcp_sent + layer4_udp_sent +
                layer3_icmp_sent + fragmentation_sent + layer7_app_sent +
                malformed_sent
            )

            # Benign traffic - FIX: reported_passed includes ALL packets that passed,
            # not just benign ones. We need to subtract attacks that passed (weren't blocked).
            # attacks_passed = attacks_sent - attacks_blocked
            attacks_passed = max(0, total_attacks_sent - total_blocked)
            # benign_passed = total_passed - attacks_passed
            benign_passed = max(0, miner_response.reported_passed - attacks_passed)

            # False positives = benign packets that were blocked
            benign_blocked = max(0, benign_sent - benign_passed)

        elif is_simulated:
            # Use traffic_result directly (simulated audit has blocked counts)
            layer3_ip_blocked = (
                getattr(ground_truth, 'spoofed_blocked', 0) +
                getattr(ground_truth, 'bogon_blocked', 0) +
                getattr(ground_truth, 'blacklist_blocked', 0)
            )
            layer4_tcp_flag_blocked = 0
            layer4_udp_amp_blocked = 0
            layer4_tcp_blocked = 0
            layer4_udp_blocked = 0
            layer3_icmp_blocked = 0
            fragmentation_blocked = 0
            layer7_app_blocked = 0
            malformed_blocked = getattr(ground_truth, 'malformed_blocked', 0)
            benign_passed = getattr(ground_truth, 'benign_passed', 0)
            benign_blocked = getattr(ground_truth, 'benign_blocked', 0)
            # Rate limit fields (simulated doesn't test these)
            ratelimit_syn_blocked = 0
            ratelimit_udp_blocked = 0
            ratelimit_icmp_blocked = 0
            ratelimit_tcp_blocked = 0
            ratelimit_app_blocked = 0
        else:
            # Real audit without miner response - can't determine blocked counts
            layer3_ip_blocked = 0
            layer4_tcp_flag_blocked = 0
            layer4_udp_amp_blocked = 0
            layer4_tcp_blocked = 0
            layer4_udp_blocked = 0
            layer3_icmp_blocked = 0
            fragmentation_blocked = 0
            layer7_app_blocked = 0
            malformed_blocked = 0
            benign_passed = benign_sent  # Assume all passed (worst case)
            benign_blocked = 0
            # Rate limit fields
            ratelimit_syn_blocked = 0
            ratelimit_udp_blocked = 0
            ratelimit_icmp_blocked = 0
            ratelimit_tcp_blocked = 0
            ratelimit_app_blocked = 0

        # === RTT METRICS ===
        if hasattr(ground_truth, 'avg_rtt_ms') and ground_truth.avg_rtt_ms > 0:
            avg_rtt = ground_truth.avg_rtt_ms
            min_rtt = getattr(ground_truth, 'min_rtt_ms', avg_rtt * 0.7)
            p95_rtt = getattr(ground_truth, 'p95_rtt_ms', avg_rtt * 1.3)
            p99_rtt = getattr(ground_truth, 'p99_rtt_ms', avg_rtt * 1.5)
        elif tunnel_rtt_ms > 0:
            # Use tunnel ping RTT as baseline
            avg_rtt = tunnel_rtt_ms
            min_rtt = tunnel_rtt_ms
            p95_rtt = tunnel_rtt_ms * 1.2
            p99_rtt = tunnel_rtt_ms * 1.5
        else:
            # No RTT data - use neutral values
            avg_rtt = 0.0
            min_rtt = 0.0
            p95_rtt = 0.0
            p99_rtt = 0.0

        # Log the category breakdown at trace level (per-miner detail)
        logger.trace(
            f"UID {uid} metrics: L3={layer3_ip_blocked}/{layer3_ip_sent} TCP={layer4_tcp_blocked}/{layer4_tcp_sent} "
            f"UDP={layer4_udp_blocked}/{layer4_udp_sent} ICMP={layer3_icmp_blocked}/{layer3_icmp_sent} "
            f"benign={benign_passed}/{benign_sent}"
        )

        return {
            # Latency metrics with IPs for distance-based normalization
            "avg_rtt_ms": avg_rtt,
            "min_rtt_ms": min_rtt,
            "p95_rtt_ms": p95_rtt,
            "p99_rtt_ms": p99_rtt,
            "scrubber_ip": scrubber_ip,
            "validator_ip": validator_ip,

            # Signature-based attack categories (percentage-based scoring)
            "layer3_ip_sent": layer3_ip_sent,
            "layer3_ip_blocked": layer3_ip_blocked,
            "layer4_tcp_flag_sent": layer4_tcp_flag_sent,
            "layer4_tcp_flag_blocked": layer4_tcp_flag_blocked,
            "layer4_udp_amp_sent": layer4_udp_amp_sent,
            "layer4_udp_amp_blocked": layer4_udp_amp_blocked,
            "fragmentation_sent": fragmentation_sent,
            "fragmentation_blocked": fragmentation_blocked,
            "malformed_sent": malformed_sent,
            "malformed_blocked": malformed_blocked,

            # Rate-limited attack categories (binary scoring: triggered or not)
            "ratelimit_syn_sent": ratelimit_syn_sent,
            "ratelimit_syn_blocked": ratelimit_syn_blocked,
            "ratelimit_udp_sent": ratelimit_udp_sent,
            "ratelimit_udp_blocked": ratelimit_udp_blocked,
            "ratelimit_icmp_sent": ratelimit_icmp_sent,
            "ratelimit_icmp_blocked": ratelimit_icmp_blocked,
            "ratelimit_tcp_sent": ratelimit_tcp_sent,
            "ratelimit_tcp_blocked": ratelimit_tcp_blocked,
            "ratelimit_app_sent": ratelimit_app_sent,
            "ratelimit_app_blocked": ratelimit_app_blocked,

            # Legacy combined fields (for backward compatibility)
            "layer4_tcp_sent": layer4_tcp_sent,
            "layer4_tcp_blocked": layer4_tcp_blocked,
            "layer4_udp_sent": layer4_udp_sent,
            "layer4_udp_blocked": layer4_udp_blocked,
            "layer3_icmp_sent": layer3_icmp_sent,
            "layer3_icmp_blocked": layer3_icmp_blocked,
            "layer7_app_sent": layer7_app_sent,
            "layer7_app_blocked": layer7_app_blocked,

            # Benign traffic (for false positive scoring)
            "benign_sent": benign_sent,
            "benign_passed": benign_passed,
            "benign_blocked": benign_blocked,
        }

    def _compute_reward_model_score(
        self,
        uid: int,
        ground_truth,  # TrafficTestResult or RealTrafficResult
        miner_response: Optional[AuditChallengeSynapse] = None,
        tunnel_rtt_ms: float = 0.0,
        scrubber_ip: str = "",
        validator_ip: str = ""
    ) -> float:
        """
        Compute audit score using ProductionRewardModel.

        This provides:
        - Distance-normalized latency scoring (using GeoIP-based expected RTT)
        - Per-category attack coverage scoring
        - False positive penalty

        Returns:
            Audit score from 0.0 to 1.0
        """
        metrics_dict = self._build_metrics_for_reward_model(
            uid, ground_truth, miner_response, tunnel_rtt_ms,
            scrubber_ip=scrubber_ip, validator_ip=validator_ip
        )

        # Use ProductionRewardModel for scoring
        event = compute_rewards({uid: metrics_dict})

        if event.rewards:
            score = event.rewards[0]

            # Extract component scores (Attack 55%, FP 25%, Latency 20%)
            attack_score = event.attack_coverage_scores[0] if event.attack_coverage_scores else 0.0
            fp_score = event.false_positive_scores[0] if event.false_positive_scores else 0.0
            latency_score = event.latency_scores[0] if event.latency_scores else 0.0

            # Store component scores in MinerRecord for W&B logging
            record = self.miners.get(uid)
            if record:
                record.last_attack_score = attack_score
                record.last_fp_score = fp_score
                record.last_latency_score = latency_score
                record.avg_rtt_ms = metrics_dict.get("avg_rtt_ms", 0.0)

            # Log score breakdown
            logger.debug(
                f"Score UID {uid}: total={score:.3f} | "
                f"cov={attack_score:.3f}(55%) "
                f"fp={fp_score:.3f}(25%) "
                f"lat={latency_score:.3f}(20%)"
            )
            return score
        else:
            logger.warning(f"No reward computed for UID {uid}, falling back to 0.5")
            return 0.5

    async def _run_simulated_audit(
        self,
        uid: int,
        scrubber_ip: str,
        result: AuditResult
    ) -> AuditResult:
        """
        Fallback simulated audit (NOT RECOMMENDED for production).

        This uses the old simulation method when real packet sending is unavailable.
        """
        test_result = await self.synthetic_traffic.run_test(
            scrubber_ip=scrubber_ip,
            target_port=80,
            timeout=60.0,
        )

        result.synthetic_test = test_result
        result.success = True

        # Score using ProductionRewardModel (includes distance-based latency normalization)
        result.score = self._compute_reward_model_score(
            uid, test_result,
            scrubber_ip=scrubber_ip,
            validator_ip=self.validator_public_ip
        )
        result.passed_threshold = result.score >= self.eligibility_threshold

        result.metrics = {
            "audit_type": "simulated",
            "warning": "Using simulated audit - results may not reflect actual XDP filtering",
            "accuracy": test_result.accuracy,
            "false_positive_rate": test_result.false_positive_rate,
            "false_negative_rate": test_result.false_negative_rate,
            "avg_rtt_ms": test_result.avg_rtt_ms,
            "min_rtt_ms": test_result.min_rtt_ms,
        }

        # MULTI-MINER: Per-miner results at TRACE level
        logger.trace(
            f"SIMULATED audit UID {uid}: score={result.score:.3f}, "
            f"rtt={test_result.avg_rtt_ms:.1f}ms"
        )

        return result

    def _process_audit_result(self, result: AuditResult) -> None:
        """
        Process audit result and update miner state.

        Simplified leaderboard model:
        - Update EMA score in leaderboard
        - Check eligibility based on EMA threshold
        - Flag miners with catastrophic or sustained poor performance
        """
        record = self.miners.get(result.uid)
        if not record:
            return

        record.last_audit = result.timestamp
        record.audit_count += 1
        record.current_score = result.score
        record.score_history.append(result.score)

        # Update EMA score in leaderboard
        ema_score = self.leaderboard.update_score(
            uid=result.uid,
            audit_score=result.score,
            hotkey=record.hotkey,
            is_active=(record.state == MinerState.ACTIVE),
            is_available=record.is_available,
            volume_processed=record.total_bytes_processed
        )

        # Update EMA in miner record
        record.ema_audit_score = ema_score
        record.ema_initialized = True

        # Log eligibility status at trace level (per-miner detail)
        is_eligible = record.is_eligible(self.eligibility_threshold)
        logger.trace(f"EMA update UID {result.uid}: score={result.score:.3f} EMA={ema_score:.3f} eligible={is_eligible}")

        # =====================================================================
        # FLAGGING LOGIC - Different rules for ACTIVE vs PENDING miners
        # =====================================================================
        # ACTIVE miners (protecting origins): Flagged ONLY by production EMA
        #   - They run xdp_wan.c in production, not xdp_wg_audit.c
        #   - Production EMA is the real measure of their performance
        #   - See _check_production_ema_flagging() for production-based flagging
        #
        # PENDING miners (not yet assigned): Flagged by audit EMA
        #   - They need to prove they can pass audits before getting assigned
        #   - Audit EMA determines eligibility for assignment
        # =====================================================================

        # Use thread-safe state check and transition to prevent race conditions
        with record._state_lock:
            if record.state == MinerState.ACTIVE:
                # ACTIVE miners: NO audit-based flagging
                # They are flagged ONLY by production EMA (in _check_production_ema_flagging)
                # Just track consecutive low scores for monitoring
                if ema_score < self.ema_flag_threshold:
                    record.consecutive_low_scores += 1
                    logger.debug(
                        f"Active miner {result.uid} audit EMA below threshold: {ema_score:.3f} "
                        f"(not flagging - production EMA is used for active miners)"
                    )
                else:
                    record.consecutive_low_scores = 0

            elif record.state == MinerState.PENDING:
                # Warm-up immunity: new miners building EMA from zero aren't flagged
                # Their EMA starts at 0 and needs time to converge before we trust it
                warmup_audits = getattr(self.settings, 'ema_warmup_audits', 9)
                if record.audit_count < warmup_audits:
                    pass  # Immune during warm-up - EMA still building up from zero
                elif ema_score < self.ema_flag_threshold:
                    record.consecutive_low_scores += 1
                    if record.consecutive_low_scores >= self.consecutive_failures_to_flag:
                        logger.warning(
                            f"AUDIT FLAG: Pending miner {result.uid} sustained poor audit EMA "
                            f"{ema_score:.3f} < {self.ema_flag_threshold} - flagging"
                        )
                        record.state = MinerState.FLAGGED
                else:
                    record.consecutive_low_scores = 0

            elif record.state == MinerState.FLAGGED:
                # Check if flagged miner has recovered - EMA back above threshold
                if ema_score >= self.ema_flag_threshold:
                    logger.info(
                        f"UNFLAG: Miner {result.uid} EMA recovered to {ema_score:.3f} >= {self.ema_flag_threshold} - "
                        f"transitioning FLAGGED -> PENDING"
                    )
                    record.state = MinerState.PENDING
                    record.consecutive_low_scores = 0

    # Production EMA threshold for flagging (independent of audit threshold)
    # Very lenient - only flag for sustained clear failures
    # With EMA smoothing (alpha=0.2), a miner needs ~5 consecutive bad scores
    # to drop from 1.0 to 0.50
    PRODUCTION_FLAG_THRESHOLD: ClassVar[float] = 0.50

    def _check_production_ema_flagging(self, uid: int, production_score: float) -> None:
        """
        Check if active miner should be flagged based on production EMA ONLY.

        This closes the production audit gap - miners can't pass audits (xdp_wg_audit.c)
        but fail in production (xdp_wan.c) without being flagged.

        NOTE: This is completely independent of audit EMA. A miner can have
        perfect audit scores but still be flagged if production performance is poor.

        Args:
            uid: Miner UID
            production_score: Latest production score from XDP metrics
        """
        record = self.miners.get(uid)
        if not record or record.state != MinerState.ACTIVE:
            return

        with record._state_lock:
            if record.production_ema_initialized and record.ema_production_score < self.PRODUCTION_FLAG_THRESHOLD:
                logger.warning(
                    f"PRODUCTION FLAG: Miner {uid} production EMA {record.ema_production_score:.3f} "
                    f"< {self.PRODUCTION_FLAG_THRESHOLD} - triggering reassignment"
                )
                record.state = MinerState.FLAGGED

                # Report to TPM for immediate reassignment
                if self.tpm_client:
                    self.tpm_client.report_miner_failure(
                        miner_uid=uid,
                        reason=f"PRODUCTION: Poor production EMA {record.ema_production_score:.3f} (threshold={self.PRODUCTION_FLAG_THRESHOLD})",
                        severity="critical",
                    )

    def _update_production_ema_scores(self) -> Tuple[Dict[int, float], Set[int]]:
        """
        Fetch and update production EMA scores for active miners.

        This closes the production audit gap by scoring miners based on
        their actual production XDP metrics (xdp_wan.c), not just audit
        performance (xdp_wg_audit.c).

        Returns:
            Tuple of:
            - Dict mapping miner_uid -> production_score for this round
            - Set of miner UIDs where this validator's TPM has real exit hub
              metrics (i.e., this validator "owns" the origin). Only these
              miners should be subject to benign test penalties.
        """
        if not self.tpm_client:
            logger.debug("No TPM client, skipping production metrics")
            return {}, set()

        # Only update production EMA for active miners (those with assignments)
        active_uids = [
            uid for uid, record in self.miners.items()
            if record.state == MinerState.ACTIVE and record.assigned_origins
        ]

        if not active_uids:
            logger.debug("No active miners with assignments, skipping production metrics")
            return {}, set()

        # Fetch production metrics from TPM
        try:
            production_metrics = self.tpm_client.get_production_metrics()
        except Exception as e:
            logger.warning(f"Failed to fetch production metrics: {e}")
            return {}, set()

        if not production_metrics:
            logger.debug("No production metrics available from TPM")
            return {}, set()

        production_scores = {}
        owned_uids: Set[int] = set()

        for uid, metrics in production_metrics.items():
            record = self.miners.get(uid)
            if not record:
                continue

            # Determine if this validator's TPM owns this miner's origin.
            # The exit hub reports metrics only to the owning validator's TPM.
            # If any origin has has_metrics=true, this TPM has real data.
            has_real_metrics = any(
                o.get('has_metrics', False) for o in metrics.origins
            ) if metrics.origins else metrics.total_packets > 0
            if has_real_metrics:
                owned_uids.add(uid)

            # Compute production score
            prod_score = compute_production_score(metrics)
            production_scores[uid] = prod_score

            # Update production EMA using same alpha as audit EMA
            if record.production_ema_initialized:
                # EMA update: new_ema = alpha * new_score + (1 - alpha) * old_ema
                alpha = EMA_ALPHA
                record.ema_production_score = (
                    alpha * prod_score +
                    (1 - alpha) * record.ema_production_score
                )
            else:
                # Initialize with first score
                record.ema_production_score = prod_score
                record.production_ema_initialized = True

            logger.trace(
                f"Production EMA update UID {uid}: score={prod_score:.3f} "
                f"EMA={record.ema_production_score:.3f} "
                f"(ratio={metrics.syn_synack_ratio:.2f}, drop={metrics.drop_rate:.1%})"
            )

            # Check if this miner should be flagged for poor production performance
            self._check_production_ema_flagging(uid, prod_score)

        if production_scores:
            avg_score = sum(production_scores.values()) / len(production_scores)
            logger.info(
                f"Production metrics: {len(production_scores)} miners scored, "
                f"avg={avg_score:.3f} (owned={len(owned_uids)}/{len(production_scores)})"
            )

        return production_scores, owned_uids

    async def _run_production_benign_tests(
        self,
        active_uids: List[int],
        packets_per_miner: int = 20
    ) -> Dict[int, float]:
        """
        Run light synthetic benign tests through the PRODUCTION path.

        Each packet contains a unique hash ID in the payload, allowing the exit hub
        to report exactly which packets arrived. This gives us accurate pass rates
        without interference from other production traffic.

        Flow:
        1. Generate packets with unique hash IDs in payload
        2. Send directly to scrubber production IP (goes through xdp_wan.c)
        3. Exit hub logs received packet IDs
        4. Query TPM for received packet IDs
        5. Calculate: pass_rate = received_ids / sent_ids

        Args:
            active_uids: List of active miner UIDs to test
            packets_per_miner: Number of benign packets to send per miner

        Returns:
            Dict mapping uid -> benign_pass_rate (0.0 to 1.0)
        """
        results: Dict[int, float] = {}

        if not SCAPY_AVAILABLE:
            logger.debug("Scapy not available, skipping production benign tests")
            return results

        if not self.tpm_client:
            logger.debug("No TPM client, skipping production benign tests")
            return results

        for uid in active_uids:
            record = self.miners.get(uid)
            if not record:
                continue

            # Get origin info for this miner (need exit hub to verify)
            if not record.assigned_origins:
                continue

            # Use the production shard EIP (origin_ip from assignment), not the
            # audit scrubber IP. The audit scrubber has no WG tunnel to the exit
            # hub — only the production shard does. Packets must traverse:
            # validator -> shard EIP -> XDP/TC -> WG tunnel -> exit hub
            origin_id = record.assigned_origins[0]
            production_ip = record.assigned_origin_ips.get(origin_id)
            if not production_ip:
                # Fallback to audit scrubber IP if origin_ip unavailable
                if not record.scrubber_ips:
                    continue
                production_ip = record.scrubber_ips[0]

            # Generate and send packets with unique IDs
            try:
                test_id, packet_ids = await self._send_tracked_benign_packets(
                    scrubber_ip=production_ip,
                    miner_uid=uid,
                    count=packets_per_miner
                )
            except Exception as e:
                logger.debug(f"Failed to send tracked benign packets to UID {uid}: {e}")
                continue

            if not packet_ids:
                continue

            # Wait for packets to traverse the network
            await asyncio.sleep(1.0)

            # Query exit hub for received packet IDs
            try:
                received_ids = await self._query_received_packet_ids(
                    miner_uid=uid,
                    test_id=test_id
                )
            except Exception as e:
                logger.debug(f"Failed to query received packets for UID {uid}: {e}")
                continue

            # Calculate pass rate based on tracked packets
            sent_count = len(packet_ids)
            received_count = len(received_ids & packet_ids)  # Intersection
            pass_rate = received_count / sent_count if sent_count > 0 else 0.0

            results[uid] = pass_rate

            logger.trace(
                f"Production benign test UID {uid}: sent={sent_count}, "
                f"received={received_count}, rate={pass_rate:.1%}"
            )

        if results:
            avg_rate = sum(results.values()) / len(results)
            passed = sum(1 for r in results.values() if r >= 0.5)
            logger.info(
                f"Production benign tests: {passed}/{len(results)} passed, "
                f"avg pass rate={avg_rate:.1%}"
            )

        return results

    async def _send_tracked_benign_packets(
        self,
        scrubber_ip: str,
        miner_uid: int,
        count: int = 20,
        dest_port: int = 80
    ) -> Tuple[str, Set[str]]:
        """
        Send benign TCP packets with unique hash IDs in payload.

        Each packet contains a payload with format:
        TPTEST:{test_id}:{packet_id}:{timestamp}

        The exit hub can extract these IDs and report which ones arrived.

        Args:
            scrubber_ip: Scrubber's public IP address
            miner_uid: Miner UID (for test ID generation)
            count: Number of packets to send
            dest_port: Destination port (default 80 for HTTP)

        Returns:
            Tuple of (test_id, set of packet_ids sent)
        """
        if not SCAPY_AVAILABLE:
            return "", set()

        from scapy.all import IP, TCP, Raw, send, conf
        conf.verb = 0

        # Generate unique test ID for this batch
        test_id = f"{miner_uid}_{int(time.time() * 1000)}_{secrets.token_hex(4)}"
        packet_ids: Set[str] = set()

        # Use validator's public IP as source
        src_ip = self.validator_public_ip or "0.0.0.0"

        packets = []
        for i in range(count):
            # Generate unique packet ID
            packet_id = f"{i:04d}_{secrets.token_hex(8)}"
            packet_ids.add(packet_id)

            # Create payload with tracking info
            # Format: TPTEST:{test_id}:{packet_id}:{timestamp}
            payload = f"TPTEST:{test_id}:{packet_id}:{time.time()}"

            # Random source port (ephemeral range)
            src_port = random.randint(32768, 60999)

            # TCP packet with PSH+ACK (looks like HTTP request data)
            # This is more likely to pass through than just SYN
            pkt = IP(src=src_ip, dst=scrubber_ip) / TCP(
                sport=src_port,
                dport=dest_port,
                flags="PA",  # PSH+ACK - data packet
                seq=random.randint(1000000, 9999999),
                ack=random.randint(1000000, 9999999)
            ) / Raw(load=payload.encode())

            packets.append(pkt)

        # Register test with TPM BEFORE sending packets, so the exit hub's
        # report-received calls don't get 404. Packets can traverse the network
        # and be reported within milliseconds of sending.
        try:
            self.tpm_client.register_benign_test(
                test_id=test_id,
                miner_uid=miner_uid,
                packet_ids=list(packet_ids)
            )
        except Exception as e:
            logger.debug(f"Failed to register benign test with TPM: {e}")
            return "", set()

        # Send packets
        try:
            send(packets, verbose=0)
            logger.trace(f"Sent {len(packets)} tracked benign packets to miner UID {miner_uid}")
        except Exception as e:
            logger.debug(f"Error sending tracked packets: {e}")
            return "", set()

        return test_id, packet_ids

    async def _query_received_packet_ids(
        self,
        miner_uid: int,
        test_id: str
    ) -> Set[str]:
        """
        Query TPM/exit hub for which packet IDs were received.

        The exit hub inspects incoming packets for TPTEST payloads
        and reports the packet IDs back to TPM.

        Args:
            miner_uid: Miner UID
            test_id: Test batch ID

        Returns:
            Set of packet IDs that were received at exit hub
        """
        if not self.tpm_client:
            return set()

        try:
            received = self.tpm_client.get_benign_test_results(
                test_id=test_id,
                miner_uid=miner_uid
            )
            if not received:
                return set()
            # Result is a dict with "received_ids" list — extract it
            received_ids = received.get("received_ids", [])
            return set(received_ids)
        except Exception as e:
            logger.debug(f"Failed to get benign test results: {e}")
            return set()

    async def run_audit_cycle(self) -> List[AuditResult]:
        """
        Run complete audit cycle for all available miners.

        The audit cycle is continuous - no fixed interval. Each cycle:
        1. Discovers miners and queries availability
        2. Runs audits on all available miners (xdp_wg_audit.c)
        3. Updates production EMA for active miners (xdp_wan.c metrics)
        4. Updates scores using dual EMA model and syncs to TPM

        The dual EMA model closes the production audit gap:
        - Audit EMA: Tests XDP correctness via xdp_wg_audit.c
        - Production EMA: Tests real-world performance via xdp_wan.c metrics

        Returns:
            List of all audit results.
        """
        all_results = []

        # Discover miners and query availability at the start of each audit
        await self.discover_miners()

        # Run audits on available miners
        results = await self.run_audits()
        all_results.extend(results)

        # Update production EMA for active miners (internal enforcement only).
        # Production EMA is NOT used for weight calculation — only for flagging
        # and reassignment by the owning validator. This ensures consensus.
        production_scores, owned_uids = self._update_production_ema_scores()

        # Run benign tests ONLY for miners this validator owns (has real exit
        # hub metrics for). Non-owning validators can't verify benign tests
        # because the exit hub reports to the owning validator's TPM only.
        if owned_uids:
            benign_results = await self._run_production_benign_tests(
                list(owned_uids)
            )

            # Penalize production EMA for miners failing benign tests.
            # This only affects flagging/reassignment, NOT weight calculation.
            for uid, benign_pass_rate in benign_results.items():
                if benign_pass_rate < 0.5:  # Less than 50% of benign traffic passed
                    record = self.miners.get(uid)
                    if record:
                        # Force production EMA down (for flagging threshold)
                        alpha = EMA_ALPHA
                        record.ema_production_score = (
                            alpha * 0.3 +
                            (1 - alpha) * record.ema_production_score
                        )
                        logger.warning(
                            f"PRODUCTION BENIGN TEST FAILED for UID {uid}: "
                            f"only {benign_pass_rate:.1%} of benign traffic passed - "
                            f"scrubber may be blocking legitimate client traffic"
                        )
                        self._check_production_ema_flagging(uid, 0.3)

        # Update validator scores array using audit EMA only (consensus-safe)
        if all_results:
            self._update_scores_from_audits(all_results)

            # Report audit EMA scores to TPM
            if self.tpm_client:
                scores_to_report = {}
                for r in all_results:
                    if r.success:
                        record = self.miners.get(r.uid)
                        if record:
                            scores_to_report[r.uid] = record.ema_audit_score
                        else:
                            scores_to_report[r.uid] = r.score

                if scores_to_report:
                    self.tpm_client.report_scores(
                        validator_uid=self.uid,
                        validator_hotkey=self.wallet.hotkey.ss58_address,
                        scores=scores_to_report,
                    )

        # Sync leaderboard to TPM (for region-aware, availability-based assignment)
        time_since_sync = time.time() - self.last_leaderboard_sync
        if time_since_sync >= self.leaderboard_sync_interval:
            self._sync_leaderboard_to_tpm()

        return all_results

    def _sync_leaderboard_to_tpm(self) -> None:
        """
        Sync miner leaderboard data to TPM.

        Sends EMA scores, availability status, and region info for all miners.
        TPM uses this for intelligent origin-to-miner assignment:
        - Prefer miners in same region as origin
        - Only assign to available miners
        - Prioritize by EMA score
        """
        if not self.tpm_client:
            return

        miners_data = []

        for uid, record in self.miners.items():
            # Get region and provider from scrubber config if available
            region = None
            provider = None
            if record.scrubber_config:
                region = getattr(record.scrubber_config, 'region', None)
                provider = getattr(record.scrubber_config, 'provider', None)

            # Get hotkey from metagraph (needed for TPM to auto-register miners)
            hotkey = self.metagraph.hotkeys[uid] if uid < len(self.metagraph.hotkeys) else record.hotkey

            miners_data.append({
                'miner_uid': uid,
                'hotkey': hotkey,  # Include hotkey for TPM registration
                'ema_score': record.ema_audit_score,
                'last_audit_score': record.current_score,  # Raw score for deployment fallback during EMA warm-up
                'ema_production_score': record.ema_production_score if record.production_ema_initialized else None,
                'combined_ema': record.get_combined_ema(),  # Dual EMA score
                'is_available': record.is_available,
                'region': region,
                'provider': provider,
                'last_heartbeat': record.last_seen.isoformat() if record.last_seen else None,
            })

        if miners_data:
            result = self.tpm_client.sync_leaderboard(
                validator_uid=self.uid,
                validator_hotkey=self.wallet.hotkey.ss58_address,
                miners=miners_data,
            )

            self.last_leaderboard_sync = time.time()

            created = result.get('miners_created', 0)
            updated = result.get('miners_updated', 0)
            not_found = len(result.get('miners_not_found', []))

            # Log at INFO if miners were created (important event)
            if created > 0:
                logger.info(f"TPM sync: {created} miners registered, {updated} updated")
            else:
                logger.debug(f"TPM sync: {updated} updated, {not_found} not found")

    def _update_scores_from_audits(self, results: List[AuditResult]) -> None:
        """
        Update validator scores array with audit results.

        Uses normalized volume scoring with audit EMA:
        - Formula: weight = 0.7 * normalized_volume + 0.3 * audit_ema
        - normalized_volume = volume / max_volume (highest volume miner gets 1.0)
        - Audit EMA is the same across all validators (consensus-safe)

        Volume data comes from TPM-verified volumes (summed across all origins per miner).

        NOTE: Production EMA is intentionally NOT used for weight calculation.
        It is only used for internal enforcement (flagging/reassignment) by the
        owning validator. This ensures all validators compute the same weights
        for consensus, regardless of which origins they own.
        """
        if self.scores is None:
            return

        # Get all UIDs
        all_uids = list(self.miners.keys())

        # Fetch TPM-verified volumes (summed across all origins per miner)
        miner_volumes: Dict[int, int] = {uid: 0 for uid in all_uids}
        using_tpm = False

        if self.tpm_client:
            try:
                tpm_volumes = self.tpm_client.get_all_verified_volumes()
                if tpm_volumes:
                    for uid, vol in tpm_volumes.items():
                        if uid in miner_volumes:
                            miner_volumes[uid] = vol.total_verified_bytes
                    using_tpm = True
                    logger.info(
                        f"Fetched TPM-verified volumes for {len(tpm_volumes)} miners"
                    )
            except Exception as e:
                logger.warning(f"Failed to fetch TPM-verified volumes: {e}")

        # Compute weights using normalized volume + audit EMA only.
        # Production EMA is NOT used for weights — it's only for internal
        # enforcement (flagging/reassignment). This ensures all validators
        # compute identical weights for consensus.
        weights = compute_weights_normalized(
            leaderboard=self.leaderboard,
            miner_volumes=miner_volumes,
            all_uids=all_uids,
            combined_ema_scores=None,  # Audit EMA only — consensus-safe
        )

        # Set scores directly from computed weights (no EMA smoothing here —
        # the leaderboard already maintains EMA on audit scores, so smoothing
        # again here would cause stale accumulation for inactive UIDs)
        for uid, weight in weights.items():
            if 0 <= uid < len(self.scores):
                self.scores[uid] = weight

        # Log reward distribution summary
        active_count = sum(1 for uid in all_uids if miner_volumes.get(uid, 0) > 0)
        audit_only_uids = [uid for uid in all_uids if miner_volumes.get(uid, 0) == 0]

        logger.info(
            f"Rewards: {active_count} with volume, {len(audit_only_uids)} audit-only"
        )

    # Legacy methods (kept for compatibility, not used in production flow)
    async def run_setup_phase(self, uids: List[int]) -> Dict[int, Dict[str, Any]]:
        """Not used in production flow."""
        return {}

    async def run_challenge_phase(self, uids: List[int]) -> Dict[int, Dict[str, Any]]:
        """Not used in production flow."""
        return {}

    async def run_lockdown_phase(self, uids: List[int]) -> Dict[int, Dict[str, Any]]:
        """Not used in production flow."""
        return {}

    def run(self) -> None:
        """Main run loop for production validator."""
        logger.info("Starting TensorProx production validator...")

        self.setup()
        self.is_running = True

        loop = asyncio.get_event_loop()

        # Set the thread pool executor for concurrent tunnel operations
        if hasattr(self, '_tunnel_executor'):
            loop.set_default_executor(self._tunnel_executor)
            logger.info("Thread pool executor configured for event loop")

        # Start TPM-Lite (mandatory for validators)
        if self.tpm_integration:
            try:
                logger.info("Starting TPM-Lite...")
                loop.run_until_complete(self.tpm_integration.start())
                logger.info("TPM-Lite started successfully")
            except Exception as e:
                logger.error(f"Failed to start TPM-Lite: {e}")
                self.tpm_integration = None

        try:
            while self.is_running:
                try:
                    # Sync with network
                    if self.should_sync_metagraph():
                        self.sync()

                    # Run audit cycle (includes miner discovery)
                    results = loop.run_until_complete(self.run_audit_cycle())

                    if results:
                        logger.info(
                            f"Audit cycle complete: {len(results)} miners audited"
                        )

                    # Set weights if needed (block-based check)
                    metagraph_last = self.settings.metagraph.last_update[self.uid]
                    effective_last = max(metagraph_last, self._last_weight_set_block)
                    blocks_since = self.block - effective_last
                    should_set = self.should_set_weights()
                    logger.info(f"Weight check: block={self.block}, last_update={effective_last}, blocks_since={blocks_since}, threshold={self.settings.weight_setter_step}, should_set={should_set}")
                    if should_set:
                        logger.info(f"Setting weights on chain...")
                        if self.weight_setter:
                            self.weight_setter.update_weights(self.scores)
                            loop.run_until_complete(self.weight_setter.run_once())
                        else:
                            self.set_weights()
                        # Mark weights set locally (in case metagraph doesn't update immediately)
                        self.mark_weights_set()
                        logger.debug(f"Marked weights set at block {self._last_weight_set_block}")
                        # Resync metagraph to get updated last_update
                        self.resync_metagraph()

                    # Log status
                    self.log_status()
                    self._log_miner_summary()

                    # Log to W&B for miner transparency
                    self._log_to_wandb()

                    # Increment step
                    self.step += 1

                    # Brief cooldown before next audit cycle
                    time.sleep(30)

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logger.error(f"Error in validation loop: {e}")
                    time.sleep(60)

        finally:
            self.shutdown()

    def _log_miner_summary(self) -> None:
        """Log summary of miner states and leaderboard."""
        state_counts = {
            MinerState.PENDING: 0,
            MinerState.ACTIVE: 0,
            MinerState.FLAGGED: 0,
        }

        for record in self.miners.values():
            state_counts[record.state] += 1

        eligible_count = sum(
            1 for m in self.miners.values()
            if m.is_eligible(self.eligibility_threshold)
        )

        logger.info(
            f"Miner states: "
            f"{state_counts[MinerState.ACTIVE]} active (assigned), "
            f"{state_counts[MinerState.PENDING]} pending, "
            f"{eligible_count} eligible, "
            f"{state_counts[MinerState.FLAGGED]} flagged"
        )


    def _log_to_wandb(self) -> None:
        """
        Log per-miner audit metrics to W&B for transparency.

        Logs parallel lists where index = UID (index 60 = UID 60's data).
        Miners can view at: https://wandb.ai/shugo-labs/tensorprox
        """
        if not self.wandb_reporter:
            return

        try:
            import wandb
            from datetime import datetime, timezone

            rankings = self.leaderboard.get_ranking()
            uid_to_rank = {e.uid: rank for rank, e in enumerate(rankings, 1)}

            # Size arrays to cover ALL metagraph UIDs (not just tracked miners)
            # This ensures index = UID mapping works for the full metagraph
            metagraph_size = len(self.metagraph.S) if hasattr(self, 'metagraph') and self.metagraph is not None else 0
            max_uid = max(metagraph_size - 1, max(self.miners.keys()) if self.miners else 0)

            # Get TPM-verified volumes for all miners (aggregated across all exit hubs)
            tpm_volumes: Dict[int, int] = {}
            if self.tpm_client:
                try:
                    tpm_vol_data = self.tpm_client.get_all_verified_volumes()
                    if tpm_vol_data:
                        for uid, vol in tpm_vol_data.items():
                            tpm_volumes[uid] = vol.total_verified_bytes
                except Exception as e:
                    logger.debug(f"Failed to fetch TPM volumes for W&B: {e}")

            # Initialize lists with 0 for all possible UIDs (index = UID)
            ranks = [0] * (max_uid + 1)
            is_active = [False] * (max_uid + 1)
            origins = [0] * (max_uid + 1)
            current_score = [0.0] * (max_uid + 1)
            ema_score = [0.0] * (max_uid + 1)
            attack_coverage = [0.0] * (max_uid + 1)
            benign_pass_rate = [0.0] * (max_uid + 1)
            latency = [0.0] * (max_uid + 1)
            rtt_ms = [0.0] * (max_uid + 1)
            volume_bytes = [0] * (max_uid + 1)

            # Fill in data at correct index (index = UID)
            for uid, record in self.miners.items():
                entry = next((e for e in rankings if e.uid == uid), None)
                ema = entry.ema_score if entry else 0.0
                rank = uid_to_rank.get(uid, 0)
                active = record.state == MinerState.ACTIVE
                origin_count = len(record.assigned_origins) if active else 0

                ranks[uid] = rank
                is_active[uid] = active
                origins[uid] = origin_count
                current_score[uid] = float(record.current_score)
                ema_score[uid] = float(ema)
                attack_coverage[uid] = float(record.last_attack_score)
                benign_pass_rate[uid] = float(record.last_fp_score)  # 1 = all benign traffic passed correctly
                latency[uid] = float(record.last_latency_score)
                rtt_ms[uid] = float(record.avg_rtt_ms)
                # Use TPM-verified volume if available, otherwise fall back to record volume
                volume_bytes[uid] = tpm_volumes.get(uid, record.total_bytes_processed)

            # Get top miner details
            top_miner = {}
            if rankings:
                top_uid = rankings[0].uid
                top_record = self.miners.get(top_uid)
                if top_record:
                    top_active = top_record.state == MinerState.ACTIVE
                    top_miner = {
                        "top_miner_uid": top_uid,
                        "top_miner_ema_score": float(rankings[0].ema_score),
                        "top_miner_current_score": float(top_record.current_score),
                        "top_miner_attack_coverage": float(top_record.last_attack_score),
                        "top_miner_benign_pass_rate": float(top_record.last_fp_score),
                        "top_miner_latency_score": float(top_record.last_latency_score),
                        "top_miner_rtt_ms": float(top_record.avg_rtt_ms),
                        "top_miner_origins": len(top_record.assigned_origins) if top_active else 0,
                        "top_miner_volume_bytes": tpm_volumes.get(top_uid, top_record.total_bytes_processed),
                        "top_miner_is_active": top_active,
                    }

            # Log event data (index = UID)
            # Global params: step, timestamp, block for tracking each step's timing
            data = {
                "step": self.step,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "block": self.block,
                "ranks": ranks,
                "is_active": is_active,
                "origins": origins,
                "current_score": current_score,
                "ema_score": ema_score,
                "attack_coverage": attack_coverage,
                "benign_pass_rate": benign_pass_rate,  # 1 = all benign traffic passed (not false positive rate)
                "latency": latency,
                "rtt_ms": rtt_ms,
                "volume_bytes": volume_bytes,  # TPM-verified volume per UID (informational, not used in rewards)
                **top_miner,
            }

            if wandb.run is not None:
                wandb.log(data, step=self.step)
                logger.info(f"W&B: {len(self.miners)} miners logged at step {self.step}")

        except Exception as e:
            logger.error(f"W&B logging error: {e}")

    def shutdown(self) -> None:
        """Shutdown the validator."""
        logger.info("Shutting down TensorProx validator...")

        # Close SSH connection pool
        try:
            from shared.utils.ssh import SSHConnectionPool
            pool = SSHConnectionPool.get_instance()
            stats = pool.get_stats()
            logger.info(f"SSH pool stats: {stats}")
            pool.close_all()
        except Exception as e:
            logger.warning(f"Error closing SSH pool: {e}")

        # Stop TPM-Lite if running
        if self.tpm_integration and self.tpm_integration.is_running:
            try:
                loop = asyncio.get_event_loop()
                loop.run_until_complete(self.tpm_integration.stop())
                logger.info("TPM-Lite stopped")
            except Exception as e:
                logger.warning(f"Error stopping TPM-Lite: {e}")

        self.is_running = False

        if self.weight_setter:
            asyncio.get_event_loop().run_until_complete(
                self.weight_setter.stop()
            )

        # Finish W&B run
        if self.wandb_reporter:
            try:
                self.wandb_reporter.finish()
                logger.info("W&B run finished")
            except Exception as e:
                logger.debug(f"Error finishing W&B: {e}")
