"""
EMA-based Leaderboard for miner selection and reward distribution.

Simplified Leaderboard Model:
- All miners are ranked by EMA audit score
- Miners become eligible for assignment when EMA >= threshold (0.8)
- TPM picks highest-ranked eligible miners for origin assignment
- No separate "pre-assignment" phase - just continuous auditing

This module implements:
1. EMA score tracking for all miners
2. Eligibility checking (EMA >= threshold + available)
3. Ranking for TPM assignment decisions
4. Normalized volume scoring for Bittensor weights
5. Variance-penalized scoring for stability differentiation

Primary Reward Formula (compute_weights_normalized):
    weight = 0.7 * normalized_volume + 0.3 * steepened_ema_score

Where:
- normalized_volume = volume / max_volume (highest volume miner gets 1.0)
- steepened_ema_score = ((ema - 0.8) / 0.2) ** 2  (amplifies top-end differences)
- Miners without assigned volume naturally get max 30% (audit-only)
- No artificial caps needed - the formula handles everything

Steepening Example (baseline=0.8, power=2):
- 0.80 EMA → 0.00 steepened (baseline = zero EMA reward)
- 0.90 EMA → 0.25 steepened
- 0.93 EMA → 0.42 steepened
- 0.96 EMA → 0.64 steepened
- Difference 0.93 vs 0.96: 0.22 (vs 0.03 linear) - 7x amplification!

Variance-Penalized Scoring:
- Tracks exponential moving variance of audit scores
- Consistent miners (low variance) get stability bonus
- Inconsistent miners (high variance) get penalty
- final_score = ema_score * (STABILITY_BASE + STABILITY_BONUS * stability_factor)

EMA Parameters:
- Alpha = 0.2 (gives ~9 sample effective period)
- Variance penalty starts at 0.3 deviation threshold
"""

from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import math
import threading
import time
from copy import deepcopy

from loguru import logger


# === THREAD SAFETY FOR MULTI-VALIDATOR SCALABILITY ===
# The leaderboard is accessed concurrently by:
# - Multiple audit tasks (asyncio.gather runs 256 concurrent)
# - Leaderboard sync operations
# - Score queries for weight calculation
# RLock allows same thread to acquire multiple times (reentrant)


# Default EMA decay factor for audit score smoothing
# α=0.2 gives ~9 sample effective period (~45 min with 5-min audits)
# - Stable enough for ranking (less volatility from single audits)
# - Responsive enough to detect sustained performance issues
# - Immediate flagging (score < 0.5) handles catastrophic failures separately
# Can be overridden via settings.ema_alpha (TP_EMA_ALPHA env var)
EMA_ALPHA = 0.2

# Eligibility threshold - miners need EMA >= this to be eligible for assignment
# Matches EMA_STEEPEN_BASELINE - miners below this get zero EMA reward anyway
ELIGIBILITY_THRESHOLD = 0.8

# Reward weights for active miners
ACTIVE_VOLUME_WEIGHT = 0.00  # Disabled: volume not yet consensus-safe (per-TPM only)
ACTIVE_AUDIT_WEIGHT = 1.00   # 100% of reward from audit EMA (consensus-safe)

# Non-assigned miners naturally get max 30% (audit-only, no volume)

# Variance tracking (for monitoring, no penalty applied)
VARIANCE_THRESHOLD = 0.15  # Threshold for tracking high variance miners

# Throughput level tracking
THROUGHPUT_DECAY_FACTOR = 0.3  # How much previous throughput level matters

# Warm-up period: new miners start EMA at 0 and build up naturally.
# During this period they are immune from flagging and ineligible for assignment.
# Computed dynamically from alpha using the equivalent SMA span: ceil((2/alpha) - 1).
# For alpha=0.2 → 9, alpha=0.3 → 6, alpha=0.1 → 19.
def compute_ema_warmup(alpha: float) -> int:
    """Compute warm-up audit count from EMA alpha using equivalent SMA span."""
    return math.ceil((2.0 / alpha) - 1)

EMA_WARMUP_AUDITS = compute_ema_warmup(EMA_ALPHA)  # Default for alpha=0.2 → 9


# ============================================================================
# EMA SCORE STEEPENING - Amplify small differences at the top
# ============================================================================
# Problem: Most miners score 0.90-0.96, making differences tiny (0.03 = 0.9% reward diff)
# Solution: Normalize to competitive range, then apply power function
#
# Formula: steepened = ((ema - baseline) / (1 - baseline)) ** power
#
# With baseline=0.8, power=2:
#   0.80 → 0.00 (baseline = zero reward from EMA)
#   0.85 → 0.0625
#   0.90 → 0.25
#   0.93 → 0.4225
#   0.96 → 0.64
#   0.99 → 0.9025
#   1.00 → 1.00
#
# Difference 0.93 vs 0.96: 0.64 - 0.42 = 0.22 (vs 0.03 linear)
# This provides strong incentive to improve from "good" to "excellent"
EMA_STEEPEN_BASELINE = 0.80  # Below this = zero EMA reward
EMA_STEEPEN_POWER = 4.0      # Power of 4 for aggressive top-end differentiation


def steepen_ema_score(ema_score: float) -> float:
    """
    Apply steepening function to EMA score for reward calculation.

    Normalizes score to competitive range (baseline to 1.0), then applies
    power function to amplify small differences at the top.

    Args:
        ema_score: Raw EMA audit score (0-1)

    Returns:
        Steepened score (0-1) for reward calculation
    """
    if ema_score <= EMA_STEEPEN_BASELINE:
        return 0.0

    # Normalize to 0-1 range above baseline
    normalized = (ema_score - EMA_STEEPEN_BASELINE) / (1.0 - EMA_STEEPEN_BASELINE)

    # Apply power function to spread out top performers
    steepened = normalized ** EMA_STEEPEN_POWER

    return min(1.0, steepened)


@dataclass
class LeaderboardEntry:
    """
    Entry in the miner leaderboard with variance tracking.

    Tracks:
    - EMA score: Exponential moving average of audit scores
    - EMA variance: How much scores vary around the EMA (stability)
    - Throughput level: Highest sustained throughput level achieved
    - Final score: EMA with variance penalty applied
    """
    uid: int
    hotkey: str
    ema_score: float = 0.0
    audit_count: int = 0
    is_active: bool = False  # Assigned to origin
    is_available: bool = False  # Currently online
    volume_processed: int = 0  # Total bytes processed (active miners only)
    rank: int = 0  # Position in leaderboard (1-indexed)

    # Variance tracking for stability differentiation
    ema_variance: float = 0.0  # Exponential moving variance (deviation from EMA)
    last_audit_score: float = 0.0  # For variance calculation

    # Throughput capacity tracking
    max_throughput_level: int = 0  # Highest level passed (0-3)
    ema_throughput_level: float = 0.0  # Smoothed throughput capacity

    # Computed final score
    final_score: float = 0.0

    def is_eligible(self, threshold: float = ELIGIBILITY_THRESHOLD, warmup: int = EMA_WARMUP_AUDITS) -> bool:
        """Check if miner is eligible for assignment based on final score and warmup."""
        return (
            self.audit_count >= warmup and  # Must complete warm-up period
            self.final_score >= threshold and
            self.is_available
        )

    def get_stability_factor(self) -> float:
        """
        Calculate stability factor from variance.

        Returns:
            1.0 for perfectly stable, 0.0 for highly unstable
        """
        if self.ema_variance <= 0:
            return 1.0

        # Normalize variance: 0 variance = 1.0, high variance = 0.0
        # Using sigmoid-like decay
        normalized = min(1.0, self.ema_variance / VARIANCE_THRESHOLD)
        return max(0.0, 1.0 - normalized)

    def compute_final_score(self) -> float:
        """
        Compute final score from EMA score.

        Formula:
            final = ema_score

        Simple and direct - the EMA score from audits is the final score.
        Anti-gaming protection comes from the validator reading XDP stats
        directly from the scrubber via SSH, not from miner self-reporting.
        """
        self.final_score = self.ema_score
        return self.final_score


class MinerLeaderboard:
    """
    EMA-based leaderboard for miner ranking and selection.

    THREAD SAFETY: All public methods are protected by RLock for concurrent access.
    This is critical for multi-validator scalability where:
    - 256 concurrent audits may update scores simultaneously
    - Score queries happen during weight calculation
    - Leaderboard syncs happen on separate intervals

    The leaderboard maintains:
    - EMA scores for all miners based on audit results
    - Ranking by EMA score for origin assignment
    - Selection logic for choosing miners to assign origins

    Usage:
        leaderboard = MinerLeaderboard()
        leaderboard.update_score(uid=5, audit_score=0.85)
        top_miners = leaderboard.get_top_available(n=10)
    """

    def __init__(self, ema_alpha: float = EMA_ALPHA):
        """
        Initialize the leaderboard.

        Args:
            ema_alpha: EMA decay factor (0-1). Higher = more weight on recent audits.
        """
        self.ema_alpha = ema_alpha
        self.warmup_audits = compute_ema_warmup(ema_alpha)
        self.entries: Dict[int, LeaderboardEntry] = {}
        self._rank_cache: List[int] = []  # Cached ranking by UID
        self._rank_dirty: bool = True  # Whether cache needs refresh

        # Thread synchronization for concurrent access
        # RLock allows same thread to acquire multiple times (reentrant)
        self._lock = threading.RLock()

        # Memory management: track last cleanup time
        self._last_cleanup = time.time()
        self._cleanup_interval = 3600  # Cleanup every hour
        self._max_inactive_age = 86400  # Remove entries inactive for 24h

    def update_score(
        self,
        uid: int,
        audit_score: float,
        hotkey: str = "",
        is_active: bool = False,
        is_available: bool = True,
        volume_processed: int = 0,
        throughput_level: int = 0,
    ) -> float:
        """
        Update a miner's EMA score after an audit with variance tracking.

        THREAD SAFE: Protected by RLock for concurrent audit updates.

        Args:
            uid: Miner UID
            audit_score: Score from latest audit (0-1)
            hotkey: Miner hotkey (for identification)
            is_active: Whether miner is assigned to origin
            is_available: Whether miner is currently online
            volume_processed: Total bytes processed (active miners)
            throughput_level: Throughput level achieved in audit (0-3)

        Returns:
            New final score (EMA score)
        """
        with self._lock:
            return self._update_score_unlocked(
                uid, audit_score, hotkey, is_active, is_available,
                volume_processed, throughput_level
            )

    def _update_score_unlocked(
        self,
        uid: int,
        audit_score: float,
        hotkey: str = "",
        is_active: bool = False,
        is_available: bool = True,
        volume_processed: int = 0,
        throughput_level: int = 0,
    ) -> float:
        """Internal unlocked version of update_score (caller must hold lock)."""
        if uid not in self.entries:
            # First audit - EMA builds up from zero (cold start)
            # Equivalent to: alpha * audit_score + (1 - alpha) * 0.0
            initial_ema = self.ema_alpha * audit_score
            self.entries[uid] = LeaderboardEntry(
                uid=uid,
                hotkey=hotkey,
                ema_score=initial_ema,
                audit_count=1,
                is_active=is_active,
                is_available=is_available,
                volume_processed=volume_processed,
                last_audit_score=audit_score,
                ema_variance=0.0,  # No variance on first audit
                max_throughput_level=throughput_level,
                ema_throughput_level=float(throughput_level),
            )
            self.entries[uid].compute_final_score()
        else:
            entry = self.entries[uid]
            old_ema = entry.ema_score

            # Calculate deviation from current EMA (before update)
            deviation = abs(audit_score - old_ema)

            # Update EMA variance (exponential moving variance)
            # new_variance = alpha * deviation + (1 - alpha) * old_variance
            old_variance = entry.ema_variance
            new_variance = self.ema_alpha * deviation + (1 - self.ema_alpha) * old_variance
            entry.ema_variance = new_variance

            # Update EMA score: new_ema = alpha * new_score + (1 - alpha) * old_ema
            new_ema = self.ema_alpha * audit_score + (1 - self.ema_alpha) * old_ema
            entry.ema_score = new_ema

            # Update other fields
            entry.audit_count += 1
            entry.hotkey = hotkey or entry.hotkey
            entry.is_active = is_active
            entry.is_available = is_available
            entry.volume_processed = volume_processed
            entry.last_audit_score = audit_score

            # Update throughput tracking
            if throughput_level > entry.max_throughput_level:
                entry.max_throughput_level = throughput_level
            entry.ema_throughput_level = (
                THROUGHPUT_DECAY_FACTOR * throughput_level +
                (1 - THROUGHPUT_DECAY_FACTOR) * entry.ema_throughput_level
            )

            # Compute final score
            entry.compute_final_score()

        self._rank_dirty = True
        return self.entries[uid].final_score

    def set_active(self, uid: int, is_active: bool, volume_processed: int = 0) -> None:
        """Set whether a miner is active (assigned to origin). Thread safe."""
        with self._lock:
            if uid in self.entries:
                self.entries[uid].is_active = is_active
                self.entries[uid].volume_processed = volume_processed

    def set_available(self, uid: int, is_available: bool) -> None:
        """Set whether a miner is available (online). Thread safe."""
        with self._lock:
            if uid in self.entries:
                self.entries[uid].is_available = is_available

    def _refresh_rankings(self) -> None:
        """
        Refresh the internal ranking cache using final scores.

        NOTE: Caller must hold self._lock before calling this method.
        """
        if not self._rank_dirty:
            return

        # Take a snapshot of entries for consistent sorting
        # This prevents issues if entries dict is modified during sort
        entries_snapshot = list(self.entries.values())

        # Sort by final_score descending (includes variance penalty)
        sorted_entries = sorted(
            entries_snapshot,
            key=lambda e: e.final_score,
            reverse=True
        )

        # Update ranks and cache
        self._rank_cache = []
        for rank, entry in enumerate(sorted_entries, start=1):
            # Update rank in original entry (safe because we hold the lock)
            if entry.uid in self.entries:
                self.entries[entry.uid].rank = rank
            self._rank_cache.append(entry.uid)

        self._rank_dirty = False

    def get_ranking(self) -> List[LeaderboardEntry]:
        """
        Get full leaderboard ranking. Thread safe.

        Returns:
            List of LeaderboardEntry copies sorted by EMA score (best first)
        """
        with self._lock:
            self._refresh_rankings()
            # Return deep copies to prevent external modification
            return [deepcopy(self.entries[uid]) for uid in self._rank_cache if uid in self.entries]

    def get_rank(self, uid: int) -> int:
        """Get a miner's current rank (1-indexed, lower is better). Thread safe."""
        with self._lock:
            self._refresh_rankings()
            if uid in self.entries:
                return self.entries[uid].rank
            return len(self.entries) + 1  # Not ranked

    def get_eligible_miners(
        self,
        n: Optional[int] = None,
        threshold: float = ELIGIBILITY_THRESHOLD,
        exclude_active: bool = True
    ) -> List[LeaderboardEntry]:
        """
        Get eligible miners for origin assignment, ranked by EMA score. Thread safe.

        A miner is eligible if:
        - EMA score >= threshold
        - Is available (online)
        - Has been audited at least once

        Args:
            n: Maximum number of miners to return (None = all)
            threshold: Minimum EMA score for eligibility
            exclude_active: If True, only return miners not already assigned

        Returns:
            List of eligible miner copies by EMA score (best first)
        """
        with self._lock:
            self._refresh_rankings()

            result = []
            for uid in self._rank_cache:
                if uid not in self.entries:
                    continue
                entry = self.entries[uid]

                # Check eligibility (use leaderboard's computed warmup)
                if not entry.is_eligible(threshold, warmup=self.warmup_audits):
                    continue

                # Skip already active miners if requested
                if exclude_active and entry.is_active:
                    continue

                # Return copy to prevent external modification
                result.append(deepcopy(entry))
                if n is not None and len(result) >= n:
                    break

            return result

    def get_top_available(self, n: int, exclude_active: bool = True) -> List[LeaderboardEntry]:
        """
        Get top N available miners for origin assignment. Thread safe.

        Note: Use get_eligible_miners() for eligibility-aware selection.

        Args:
            n: Number of miners to return
            exclude_active: If True, only return miners not already assigned

        Returns:
            List of top available miner copies by EMA score
        """
        with self._lock:
            self._refresh_rankings()

            result = []
            for uid in self._rank_cache:
                if uid not in self.entries:
                    continue
                entry = self.entries[uid]

                # Skip unavailable miners
                if not entry.is_available:
                    continue

                # Skip already active miners if requested
                if exclude_active and entry.is_active:
                    continue

                result.append(deepcopy(entry))
                if len(result) >= n:
                    break

            return result

    def select_for_assignment(self, threshold: float = ELIGIBILITY_THRESHOLD) -> Optional[LeaderboardEntry]:
        """
        Select the best eligible miner for a new origin assignment. Thread safe.

        Uses eligibility criteria (EMA >= threshold, available, audited).

        Args:
            threshold: Minimum EMA score for eligibility

        Returns:
            Best eligible miner copy or None if none available
        """
        eligible = self.get_eligible_miners(n=1, threshold=threshold, exclude_active=True)
        return eligible[0] if eligible else None

    def get_ema_score(self, uid: int) -> float:
        """Get a miner's current EMA score (without variance penalty). Thread safe."""
        with self._lock:
            if uid in self.entries:
                return self.entries[uid].ema_score
            return 0.0

    def get_final_score(self, uid: int) -> float:
        """Get a miner's final score (EMA with variance penalty applied). Thread safe."""
        with self._lock:
            if uid in self.entries:
                return self.entries[uid].final_score
            return 0.0

    def get_entry(self, uid: int) -> Optional[LeaderboardEntry]:
        """Get a copy of a miner's full leaderboard entry. Thread safe."""
        with self._lock:
            entry = self.entries.get(uid)
            return deepcopy(entry) if entry else None

    def get_variance(self, uid: int) -> float:
        """Get a miner's EMA variance (stability metric). Thread safe."""
        with self._lock:
            if uid in self.entries:
                return self.entries[uid].ema_variance
            return 0.0

    def get_stability_factor(self, uid: int) -> float:
        """Get a miner's stability factor (1.0 = stable, 0.0 = unstable). Thread safe."""
        with self._lock:
            if uid in self.entries:
                return self.entries[uid].get_stability_factor()
            return 0.0

    def get_throughput_level(self, uid: int) -> Tuple[int, float]:
        """
        Get a miner's throughput capacity. Thread safe.

        Returns:
            Tuple of (max_level_achieved, ema_throughput_level)
        """
        with self._lock:
            if uid in self.entries:
                entry = self.entries[uid]
                return entry.max_throughput_level, entry.ema_throughput_level
            return 0, 0.0

    def count_eligible(self, threshold: float = ELIGIBILITY_THRESHOLD) -> int:
        """Count miners that are eligible for assignment. Thread safe."""
        with self._lock:
            return sum(
                1 for entry in self.entries.values()
                if entry.is_eligible(threshold, warmup=self.warmup_audits)
            )

    def get_detailed_stats(self, uid: int) -> Dict[str, Any]:
        """
        Get detailed statistics for a miner. Thread safe.

        Returns dict with all metrics for debugging/display.
        """
        with self._lock:
            if uid not in self.entries:
                return {}

            entry = self.entries[uid]
            return {
                "uid": entry.uid,
                "hotkey": entry.hotkey,
                "ema_score": entry.ema_score,
                "ema_variance": entry.ema_variance,
                "stability_factor": entry.get_stability_factor(),
                "final_score": entry.final_score,
                "max_throughput_level": entry.max_throughput_level,
                "ema_throughput_level": entry.ema_throughput_level,
                "audit_count": entry.audit_count,
                "last_audit_score": entry.last_audit_score,
                "rank": entry.rank,
                "is_active": entry.is_active,
                "is_available": entry.is_available,
                "is_eligible": entry.is_eligible(warmup=self.warmup_audits),
            }

    def remove_miner(self, uid: int) -> bool:
        """
        Remove a miner from the leaderboard. Thread safe.

        Used for cleanup of deregistered miners.

        Args:
            uid: Miner UID to remove

        Returns:
            True if miner was removed, False if not found
        """
        with self._lock:
            if uid in self.entries:
                del self.entries[uid]
                self._rank_dirty = True
                return True
            return False

    def cleanup_inactive_miners(self, max_age_seconds: int = 86400) -> int:
        """
        Remove miners that haven't been audited in max_age_seconds. Thread safe.

        This prevents memory leaks from deregistered miners.

        Args:
            max_age_seconds: Maximum age since last audit (default 24h)

        Returns:
            Number of miners removed
        """
        with self._lock:
            current_time = time.time()

            # Skip cleanup if not enough time has passed
            if current_time - self._last_cleanup < self._cleanup_interval:
                return 0

            self._last_cleanup = current_time

            # Find miners to remove (no recent audits)
            # Note: We don't have explicit timestamp, so we use audit_count=0
            # and is_available=False as a proxy for inactive
            to_remove = []
            for uid, entry in self.entries.items():
                if entry.audit_count == 0 and not entry.is_available:
                    to_remove.append(uid)

            # Remove inactive miners
            for uid in to_remove:
                del self.entries[uid]

            if to_remove:
                self._rank_dirty = True
                logger.info(f"Cleaned up {len(to_remove)} inactive miners from leaderboard")

            return len(to_remove)

    def get_all_entries_snapshot(self) -> Dict[int, LeaderboardEntry]:
        """
        Get a thread-safe snapshot of all entries. Thread safe.

        Returns:
            Dict mapping UID to LeaderboardEntry copy
        """
        with self._lock:
            return {uid: deepcopy(entry) for uid, entry in self.entries.items()}


@dataclass
class VerifiedVolumeData:
    """Volume data from TPM (via exit hub) for reward calculation."""
    verified_bytes: int = 0




def compute_weights_normalized(
    leaderboard: MinerLeaderboard,
    miner_volumes: Dict[int, int],  # UID -> volume_processed (bytes)
    all_uids: List[int],
    combined_ema_scores: Optional[Dict[int, float]] = None,  # Override EMA with combined audit+production
) -> Dict[int, float]:
    """
    Compute Bittensor weights with normalized volume scoring.

    Simple formula: weight = 0.7 * normalized_volume + 0.3 * final_score

    Where:
    - normalized_volume = volume / max_volume (among all miners)
    - final_score = ema_score (or combined_ema if provided for active miners)
    - The miner processing the most volume gets normalized_volume = 1.0
    - Miners not assigned (volume=0) naturally get: 0.7 * 0 + 0.3 * audit = max 30%

    No bonuses or penalties - straightforward linear weighting.

    DUAL EMA SUPPORT:
    The combined_ema_scores parameter allows validators to provide a dual EMA score
    that combines audit EMA (from xdp_wg_audit.c) with production EMA (from xdp_wan.c).
    This closes the "production audit gap" where miners could optimize for audits
    but use different configs in production.

    Args:
        leaderboard: The miner leaderboard with EMA tracking
        miner_volumes: Dict of miner UID -> volume processed (bytes)
        all_uids: List of all miner UIDs to assign weights
        combined_ema_scores: Optional override EMA scores (e.g., combined audit+production)

    Returns:
        Dict mapping UID to weight (normalized to sum to 1.0)
    """
    raw_weights: Dict[int, float] = {}

    # Find max volume for normalization
    volumes = [miner_volumes.get(uid, 0) for uid in all_uids]
    max_volume = max(volumes) if volumes else 1
    if max_volume == 0:
        max_volume = 1  # Avoid division by zero

    for uid in all_uids:
        volume = miner_volumes.get(uid, 0)

        # Use combined EMA if provided, otherwise fall back to leaderboard score
        if combined_ema_scores and uid in combined_ema_scores:
            raw_ema = combined_ema_scores[uid]
        else:
            raw_ema = leaderboard.get_final_score(uid)

        # Apply steepening to EMA score to amplify top-end differences
        # This makes small differences (0.93 vs 0.96) much more impactful
        steepened_score = steepen_ema_score(raw_ema)

        # Normalize volume: miner with highest volume gets 1.0
        normalized_volume = volume / max_volume

        # Formula: 70% volume + 30% steepened audit score
        weight = (
            ACTIVE_VOLUME_WEIGHT * normalized_volume +
            ACTIVE_AUDIT_WEIGHT * steepened_score
        )

        raw_weights[uid] = max(0.0, weight)


    # Normalize weights to sum to 1.0
    total = sum(raw_weights.values())
    if total > 0:
        normalized = {uid: w / total for uid, w in raw_weights.items()}
    else:
        # No miners earned any weight — return zeros (don't distribute equal weights)
        normalized = {uid: 0.0 for uid in all_uids}

    # Summary logging
    active_count = sum(1 for uid in all_uids if miner_volumes.get(uid, 0) > 0)
    logger.info(
        f"Weights computed: {active_count} with volume, "
        f"{len(all_uids) - active_count} audit-only, "
        f"max_volume={max_volume}, total_raw={total:.4f}"
    )

    return normalized


def compute_bittensor_weights(
    leaderboard: MinerLeaderboard,
    active_miners: Dict[int, int],  # UID -> volume_processed (fallback if no verified_volumes)
    all_uids: List[int],
    verified_volumes: Optional[Dict[int, VerifiedVolumeData]] = None,  # TPM exit hub volumes
) -> Dict[int, float]:
    """
    Compute Bittensor weight distribution for all miners.

    Simple formula for all miners:
        weight = 0.7 * volume_score + 0.3 * ema_score

    No bonuses or penalties - straightforward linear weighting.
    Non-assigned miners: volume=0 -> max 30% from audit score.

    Volume comes from TPM-managed exit hubs (ground truth, non-gameable).

    Args:
        leaderboard: The miner leaderboard with EMA scores
        active_miners: Fallback volume data if verified_volumes not available
        all_uids: List of all miner UIDs to assign weights
        verified_volumes: TPM exit hub volume data (preferred)

    Returns:
        Dict mapping UID to weight (normalized to sum to 1.0)
    """
    raw_weights: Dict[int, float] = {}

    # Use verified volumes if provided, otherwise fall back to active_miners
    use_verified = verified_volumes is not None

    # Get volume data for all miners (non-assigned miners have 0 volume)
    all_volumes: Dict[int, int] = {}

    for uid in all_uids:
        if use_verified and verified_volumes and uid in verified_volumes:
            all_volumes[uid] = verified_volumes[uid].verified_bytes
        elif uid in active_miners:
            all_volumes[uid] = active_miners.get(uid, 0)
        else:
            all_volumes[uid] = 0  # Non-assigned miners have 0 volume

    # Calculate max volume for normalization
    max_volume = max(all_volumes.values()) if all_volumes else 1
    if max_volume == 0:
        max_volume = 1  # Avoid division by zero

    for uid in all_uids:
        raw_ema = leaderboard.get_final_score(uid)
        volume = all_volumes.get(uid, 0)
        volume_score = volume / max_volume if max_volume > 0 else 0

        # Apply steepening to EMA score to amplify top-end differences
        # This makes small differences (0.93 vs 0.96) much more impactful
        steepened_score = steepen_ema_score(raw_ema)

        # Formula: 70% volume + 30% steepened audit score
        weight = (
            ACTIVE_VOLUME_WEIGHT * volume_score +
            ACTIVE_AUDIT_WEIGHT * steepened_score
        )


        raw_weights[uid] = max(0.0, weight)

    # Normalize weights to sum to 1.0
    total = sum(raw_weights.values())
    if total > 0:
        normalized = {uid: w / total for uid, w in raw_weights.items()}
    else:
        # No miners earned any weight — return zeros (don't distribute equal weights)
        normalized = {uid: 0.0 for uid in all_uids}

    assigned_count = sum(1 for uid in all_uids if all_volumes.get(uid, 0) > 0)

    logger.info(
        f"Bittensor weights computed: {assigned_count} assigned, "
        f"{len(all_uids) - assigned_count} not assigned, "
        f"total_raw={total:.4f}, using_verified={use_verified}"
    )

    return normalized


def compute_rewards_with_state(
    audit_scores: Dict[int, float],
    assigned_miners: Dict[int, int],  # UID -> volume_processed
    leaderboard: MinerLeaderboard
) -> Dict[int, float]:
    """
    Compute rewards using unified formula.

    Simplified Model - same formula for all miners:
        reward = 0.7 * volume_score + 0.3 * audit_score

    Non-assigned miners (volume=0) naturally get max 30% from audit only.

    This entry point:
    1. Updates EMA scores from audit results
    2. Computes weighted rewards using normalized volume

    Args:
        audit_scores: Dict of UID -> raw audit score (0-1)
        assigned_miners: Dict of assigned miner UIDs to volume processed
        leaderboard: The leaderboard to update

    Returns:
        Dict mapping UID to final reward score
    """
    rewards: Dict[int, float] = {}

    # Calculate max volume for normalization
    max_volume = max(assigned_miners.values()) if assigned_miners else 1
    if max_volume == 0:
        max_volume = 1  # Avoid division by zero

    for uid, audit_score in audit_scores.items():
        # Update EMA in leaderboard
        is_assigned = uid in assigned_miners
        volume = assigned_miners.get(uid, 0)

        leaderboard.update_score(
            uid=uid,
            audit_score=audit_score,
            is_active=is_assigned,
            volume_processed=volume
        )

        # Unified formula: 70% volume + 30% steepened audit
        # Non-assigned miners: volume=0 -> max 30% from audit
        volume_score = volume / max_volume if max_volume > 0 else 0

        # Apply steepening to audit score to amplify top-end differences
        steepened_score = steepen_ema_score(audit_score)

        reward = (
            ACTIVE_VOLUME_WEIGHT * volume_score +
            ACTIVE_AUDIT_WEIGHT * steepened_score
        )


        rewards[uid] = max(0.0, min(1.0, reward))

    return rewards
