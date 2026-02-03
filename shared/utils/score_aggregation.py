"""
Multi-Validator Score Aggregation

This module provides utilities for aggregating miner scores from multiple validators.
It's designed to be used by the TPM server to combine scores from all validators
into a consensus score for each miner.

SCALABILITY FEATURES:
- Thread-safe for concurrent validator submissions
- Weighted aggregation based on validator stake
- Outlier detection to handle Byzantine validators
- Time-decay for stale scores
- Memory-efficient storage with automatic cleanup

AGGREGATION STRATEGY:
1. Collect scores from multiple validators (at least N for consensus)
2. Apply stake weighting (higher stake = more influence)
3. Detect and exclude outliers (scores > 2 std dev from median)
4. Compute weighted median or mean
5. Apply time decay for older submissions
"""

import threading
import time
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from loguru import logger


# === CONFIGURATION ===
MIN_VALIDATORS_FOR_CONSENSUS = 2       # Minimum validators needed for reliable score
OUTLIER_THRESHOLD_STDDEV = 2.0         # Scores beyond this many std devs are outliers
SCORE_STALENESS_SECONDS = 300          # Scores older than this get time decay
SCORE_EXPIRY_SECONDS = 600             # Scores older than this are removed
CLEANUP_INTERVAL_SECONDS = 60          # How often to cleanup expired scores
DEFAULT_STAKE_WEIGHT = 1.0             # Default weight when stake unknown


@dataclass
class ValidatorScore:
    """A score submission from a single validator."""
    validator_uid: int
    validator_hotkey: str
    score: float
    timestamp: float
    stake_weight: float = DEFAULT_STAKE_WEIGHT
    version: Optional[str] = None  # For idempotency tracking


@dataclass
class MinerScoreState:
    """Aggregated score state for a single miner."""
    miner_uid: int
    scores: Dict[int, ValidatorScore] = field(default_factory=dict)  # validator_uid -> score
    last_aggregated: float = 0.0
    aggregated_score: float = 0.0
    consensus_count: int = 0
    outliers_excluded: int = 0


@dataclass
class AggregationResult:
    """Result of score aggregation for a miner."""
    miner_uid: int
    aggregated_score: float
    validator_count: int
    consensus_reached: bool
    outliers_excluded: int
    score_variance: float
    staleness_factor: float  # 1.0 = all fresh, lower = some stale


class ScoreAggregator:
    """
    Thread-safe score aggregation for multiple validators.

    Usage:
        aggregator = ScoreAggregator()

        # Submit scores from validators
        aggregator.submit_score(
            miner_uid=42,
            validator_uid=1,
            validator_hotkey="5Grwva...",
            score=0.85,
            stake_weight=1000.0
        )

        # Get aggregated score
        result = aggregator.get_aggregated_score(miner_uid=42)
        print(f"Miner 42 score: {result.aggregated_score}")
    """

    def __init__(
        self,
        min_validators: int = MIN_VALIDATORS_FOR_CONSENSUS,
        outlier_threshold: float = OUTLIER_THRESHOLD_STDDEV,
        score_staleness: float = SCORE_STALENESS_SECONDS,
        score_expiry: float = SCORE_EXPIRY_SECONDS,
    ):
        """
        Initialize score aggregator.

        Args:
            min_validators: Minimum validators needed for consensus
            outlier_threshold: Std devs beyond which scores are outliers
            score_staleness: Seconds after which scores start decaying
            score_expiry: Seconds after which scores are removed
        """
        self.min_validators = min_validators
        self.outlier_threshold = outlier_threshold
        self.score_staleness = score_staleness
        self.score_expiry = score_expiry

        # Thread-safe storage
        self._lock = threading.RLock()
        self._miner_states: Dict[int, MinerScoreState] = {}
        self._last_cleanup = time.time()

        # Track validator versions for idempotency
        self._validator_versions: Dict[Tuple[int, int], str] = {}  # (validator, miner) -> version

    def submit_score(
        self,
        miner_uid: int,
        validator_uid: int,
        validator_hotkey: str,
        score: float,
        stake_weight: float = DEFAULT_STAKE_WEIGHT,
        version: Optional[str] = None,
    ) -> bool:
        """
        Submit a score from a validator.

        Args:
            miner_uid: Miner being scored
            validator_uid: Validator providing the score
            validator_hotkey: Validator's hotkey
            score: Score value (0.0 to 1.0)
            stake_weight: Validator's stake weight for weighted aggregation
            version: Optional version/nonce for idempotency

        Returns:
            True if score was accepted, False if duplicate version
        """
        with self._lock:
            # Check for duplicate submission (idempotency)
            if version:
                key = (validator_uid, miner_uid)
                existing_version = self._validator_versions.get(key)
                if existing_version == version:
                    logger.debug(
                        f"Duplicate score submission ignored: validator {validator_uid}, "
                        f"miner {miner_uid}, version {version}"
                    )
                    return False
                self._validator_versions[key] = version

            # Get or create miner state
            if miner_uid not in self._miner_states:
                self._miner_states[miner_uid] = MinerScoreState(miner_uid=miner_uid)

            state = self._miner_states[miner_uid]

            # Record validator's score
            state.scores[validator_uid] = ValidatorScore(
                validator_uid=validator_uid,
                validator_hotkey=validator_hotkey,
                score=max(0.0, min(1.0, score)),  # Clamp to [0, 1]
                timestamp=time.time(),
                stake_weight=max(0.0, stake_weight),
                version=version,
            )

            logger.debug(
                f"Score submitted: miner {miner_uid}, validator {validator_uid}, "
                f"score {score:.4f}, stake {stake_weight:.2f}"
            )

            # Trigger cleanup periodically
            self._maybe_cleanup()

            return True

    def get_aggregated_score(self, miner_uid: int) -> Optional[AggregationResult]:
        """
        Get aggregated score for a miner.

        Returns None if miner has no scores or consensus not reached.
        """
        with self._lock:
            state = self._miner_states.get(miner_uid)
            if not state or not state.scores:
                return None

            return self._compute_aggregation(state)

    def get_all_aggregated_scores(self) -> Dict[int, AggregationResult]:
        """
        Get aggregated scores for all miners.

        Returns dict mapping miner_uid to AggregationResult.
        """
        with self._lock:
            results = {}
            for miner_uid, state in self._miner_states.items():
                if state.scores:
                    result = self._compute_aggregation(state)
                    if result:
                        results[miner_uid] = result
            return results

    def _compute_aggregation(self, state: MinerScoreState) -> AggregationResult:
        """
        Compute aggregated score for a miner.

        Uses stake-weighted median with outlier exclusion.
        """
        current_time = time.time()

        # Filter and prepare scores
        valid_scores: List[Tuple[float, float, float]] = []  # (score, weight, staleness)

        for vs in state.scores.values():
            age = current_time - vs.timestamp

            # Skip expired scores
            if age > self.score_expiry:
                continue

            # Calculate staleness factor (1.0 = fresh, decays over time)
            if age > self.score_staleness:
                staleness = max(0.5, 1.0 - (age - self.score_staleness) / self.score_staleness)
            else:
                staleness = 1.0

            valid_scores.append((vs.score, vs.stake_weight, staleness))

        if not valid_scores:
            return AggregationResult(
                miner_uid=state.miner_uid,
                aggregated_score=0.0,
                validator_count=0,
                consensus_reached=False,
                outliers_excluded=0,
                score_variance=0.0,
                staleness_factor=0.0,
            )

        # Detect and exclude outliers
        scores_only = [s[0] for s in valid_scores]
        median = self._median(scores_only)
        stddev = self._stddev(scores_only)

        outliers_excluded = 0
        filtered_scores: List[Tuple[float, float, float]] = []

        for score, weight, staleness in valid_scores:
            if stddev > 0 and abs(score - median) > self.outlier_threshold * stddev:
                outliers_excluded += 1
                logger.debug(
                    f"Outlier excluded for miner {state.miner_uid}: score {score:.4f} "
                    f"(median {median:.4f}, stddev {stddev:.4f})"
                )
            else:
                filtered_scores.append((score, weight, staleness))

        # If all scores were outliers, use unfiltered
        if not filtered_scores:
            filtered_scores = valid_scores
            outliers_excluded = 0

        # Compute stake-weighted average with staleness adjustment
        total_weight = sum(w * s for _, w, s in filtered_scores)
        if total_weight > 0:
            aggregated = sum(score * w * s for score, w, s in filtered_scores) / total_weight
        else:
            aggregated = sum(s[0] for s in filtered_scores) / len(filtered_scores)

        # Calculate average staleness
        avg_staleness = sum(s[2] for s in filtered_scores) / len(filtered_scores)

        # Calculate variance of filtered scores
        filtered_scores_only = [s[0] for s in filtered_scores]
        variance = self._variance(filtered_scores_only)

        # Check consensus
        consensus_reached = len(filtered_scores) >= self.min_validators

        # Update state
        state.aggregated_score = aggregated
        state.consensus_count = len(filtered_scores)
        state.outliers_excluded = outliers_excluded
        state.last_aggregated = current_time

        return AggregationResult(
            miner_uid=state.miner_uid,
            aggregated_score=aggregated,
            validator_count=len(filtered_scores),
            consensus_reached=consensus_reached,
            outliers_excluded=outliers_excluded,
            score_variance=variance,
            staleness_factor=avg_staleness,
        )

    def _median(self, values: List[float]) -> float:
        """Calculate median of a list of values."""
        if not values:
            return 0.0
        sorted_values = sorted(values)
        n = len(sorted_values)
        if n % 2 == 0:
            return (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2
        return sorted_values[n // 2]

    def _stddev(self, values: List[float]) -> float:
        """Calculate standard deviation of a list of values."""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)

    def _variance(self, values: List[float]) -> float:
        """Calculate variance of a list of values."""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)

    def _maybe_cleanup(self):
        """Periodically cleanup expired scores."""
        current_time = time.time()
        if current_time - self._last_cleanup < CLEANUP_INTERVAL_SECONDS:
            return

        self._last_cleanup = current_time

        # Clean up expired scores
        expired_miners = []
        for miner_uid, state in self._miner_states.items():
            expired_validators = []
            for validator_uid, vs in state.scores.items():
                if current_time - vs.timestamp > self.score_expiry:
                    expired_validators.append(validator_uid)

            for v_uid in expired_validators:
                del state.scores[v_uid]

            if not state.scores:
                expired_miners.append(miner_uid)

        for miner_uid in expired_miners:
            del self._miner_states[miner_uid]

        # Clean up old version tracking
        old_versions = []
        for key in self._validator_versions:
            # Keep versions for miners that still have scores
            validator_uid, miner_uid = key
            if miner_uid not in self._miner_states:
                old_versions.append(key)

        for key in old_versions:
            del self._validator_versions[key]

        if expired_miners or old_versions:
            logger.debug(
                f"Score aggregator cleanup: removed {len(expired_miners)} miners, "
                f"{len(old_versions)} version entries"
            )

    def get_status(self) -> Dict:
        """Get aggregator status for monitoring."""
        with self._lock:
            total_scores = sum(len(s.scores) for s in self._miner_states.values())
            miners_with_consensus = sum(
                1 for s in self._miner_states.values()
                if len(s.scores) >= self.min_validators
            )

            return {
                "miners_tracked": len(self._miner_states),
                "total_scores": total_scores,
                "miners_with_consensus": miners_with_consensus,
                "min_validators_required": self.min_validators,
                "version_entries": len(self._validator_versions),
            }

    def get_validator_submissions(self) -> Dict[int, List[int]]:
        """
        Get which validators have submitted scores for which miners.

        Returns dict mapping validator_uid to list of miner_uids they've scored.
        """
        with self._lock:
            submissions: Dict[int, List[int]] = defaultdict(list)

            for miner_uid, state in self._miner_states.items():
                for validator_uid in state.scores:
                    submissions[validator_uid].append(miner_uid)

            return dict(submissions)

    def clear_validator(self, validator_uid: int):
        """
        Clear all scores from a specific validator.

        Used when a validator is deregistered or needs to be excluded.
        """
        with self._lock:
            for state in self._miner_states.values():
                if validator_uid in state.scores:
                    del state.scores[validator_uid]

            # Clear version tracking for this validator
            keys_to_remove = [
                key for key in self._validator_versions
                if key[0] == validator_uid
            ]
            for key in keys_to_remove:
                del self._validator_versions[key]

            logger.info(f"Cleared all scores from validator {validator_uid}")

    def reset(self):
        """Reset all aggregation state (for testing)."""
        with self._lock:
            self._miner_states.clear()
            self._validator_versions.clear()
            self._last_cleanup = time.time()
            logger.info("Score aggregator reset")


# Singleton instance for shared use
_score_aggregator: Optional[ScoreAggregator] = None


def get_score_aggregator() -> ScoreAggregator:
    """Get the singleton score aggregator instance."""
    global _score_aggregator
    if _score_aggregator is None:
        _score_aggregator = ScoreAggregator()
    return _score_aggregator
