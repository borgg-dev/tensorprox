"""
Failover Protection - Cascade Prevention and Rate Limiting

This module provides protection against cascading failures in the TensorProx
failover system. It implements:

1. Rate limiting for origin reassignments to prevent overloading miners
2. Circuit breaker for detecting cascade failures
3. Load-aware assignment to distribute origins across available miners

SCALABILITY FEATURES:
- Prevents one miner failure from cascading to N+1 failures
- Rate limits how many origins can be reassigned to a single miner
- Detects cascade patterns and triggers emergency mode
"""

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from enum import Enum
from loguru import logger


# === CONFIGURATION ===
# Rate limiting for origin reassignments
MAX_REASSIGNMENTS_PER_MINER_PER_MINUTE = 10  # Max origins that can be reassigned to one miner
REASSIGNMENT_WINDOW_SECONDS = 60             # Window for rate limiting

# Cascade detection
CASCADE_FAILURE_THRESHOLD = 3                # Number of failures in window to trigger cascade mode
CASCADE_WINDOW_SECONDS = 120                 # Window for cascade detection (2 minutes)
CASCADE_COOLDOWN_SECONDS = 300               # Cooldown before allowing new reassignments (5 minutes)

# Load balancing
MAX_ORIGINS_PER_MINER = 50                   # Maximum origins a single miner should handle
LOAD_DISTRIBUTION_FACTOR = 0.8               # Don't assign to miner if >80% loaded


class CascadeState(Enum):
    """System cascade state."""
    NORMAL = "normal"           # Normal operation
    ELEVATED = "elevated"       # Some failures detected, be cautious
    CASCADE = "cascade"         # Cascade detected, limit reassignments
    EMERGENCY = "emergency"     # Too many failures, stop reassignments


@dataclass
class ReassignmentRecord:
    """Record of an origin reassignment."""
    origin_id: str
    from_miner_uid: int
    to_miner_uid: int
    timestamp: float
    reason: str


@dataclass
class MinerLoadState:
    """Track miner load for assignment decisions."""
    miner_uid: int
    current_origins: int = 0
    max_origins: int = MAX_ORIGINS_PER_MINER
    recent_reassignments: int = 0  # In the last window
    last_failure_time: float = 0.0

    def is_overloaded(self) -> bool:
        """Check if miner is already at capacity."""
        return self.current_origins >= self.max_origins

    def load_factor(self) -> float:
        """Get current load as percentage (0.0 to 1.0)."""
        if self.max_origins == 0:
            return 1.0
        return self.current_origins / self.max_origins

    def can_accept_origins(self, count: int = 1) -> bool:
        """Check if miner can accept more origins."""
        return (
            self.current_origins + count <= self.max_origins and
            self.load_factor() < LOAD_DISTRIBUTION_FACTOR
        )


class FailoverProtection:
    """
    Failover protection with cascade prevention and rate limiting.

    Thread-safe singleton that tracks:
    - Reassignment rates per miner
    - Overall system failure rate
    - Cascade state

    Usage:
        protection = get_failover_protection()

        # Before reassigning origins
        if protection.can_reassign(miner_uid, origin_count=5):
            protection.record_reassignment(origin_id, from_miner, to_miner)
            # Do the reassignment
        else:
            # Skip or queue the reassignment
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._data_lock = threading.RLock()

        # Reassignment tracking
        self._reassignment_history: List[ReassignmentRecord] = []
        self._miner_reassignment_counts: Dict[int, List[float]] = defaultdict(list)

        # Failure tracking for cascade detection
        self._failure_timestamps: List[float] = []
        self._cascade_state = CascadeState.NORMAL
        self._cascade_start_time = 0.0

        # Miner load tracking
        self._miner_loads: Dict[int, MinerLoadState] = {}

        # Emergency mode tracking
        self._emergency_blocked_origins: Set[str] = set()

        logger.info("Failover protection initialized")

    def _cleanup_old_records(self):
        """Remove old records outside the tracking windows."""
        current_time = time.time()

        # Clean up reassignment history
        cutoff = current_time - REASSIGNMENT_WINDOW_SECONDS
        self._reassignment_history = [
            r for r in self._reassignment_history
            if r.timestamp > cutoff
        ]

        # Clean up per-miner counts
        for miner_uid in list(self._miner_reassignment_counts.keys()):
            self._miner_reassignment_counts[miner_uid] = [
                ts for ts in self._miner_reassignment_counts[miner_uid]
                if ts > cutoff
            ]
            if not self._miner_reassignment_counts[miner_uid]:
                del self._miner_reassignment_counts[miner_uid]

        # Clean up failure timestamps
        failure_cutoff = current_time - CASCADE_WINDOW_SECONDS
        self._failure_timestamps = [
            ts for ts in self._failure_timestamps
            if ts > failure_cutoff
        ]

    def _update_cascade_state(self):
        """Update cascade state based on recent failures."""
        current_time = time.time()
        recent_failures = len(self._failure_timestamps)

        # Check if we're in cooldown from previous cascade
        if self._cascade_state in (CascadeState.CASCADE, CascadeState.EMERGENCY):
            if current_time - self._cascade_start_time > CASCADE_COOLDOWN_SECONDS:
                if recent_failures < CASCADE_FAILURE_THRESHOLD:
                    logger.info("Cascade cooldown complete, returning to normal state")
                    self._cascade_state = CascadeState.NORMAL
                    return

        # Determine state based on failure count
        if recent_failures >= CASCADE_FAILURE_THRESHOLD * 2:
            if self._cascade_state != CascadeState.EMERGENCY:
                logger.critical(
                    f"EMERGENCY: {recent_failures} failures in {CASCADE_WINDOW_SECONDS}s, "
                    "halting reassignments"
                )
                self._cascade_state = CascadeState.EMERGENCY
                self._cascade_start_time = current_time
        elif recent_failures >= CASCADE_FAILURE_THRESHOLD:
            if self._cascade_state == CascadeState.NORMAL:
                logger.warning(
                    f"CASCADE DETECTED: {recent_failures} failures in {CASCADE_WINDOW_SECONDS}s, "
                    "limiting reassignments"
                )
                self._cascade_state = CascadeState.CASCADE
                self._cascade_start_time = current_time
        elif recent_failures > 0:
            if self._cascade_state == CascadeState.NORMAL:
                self._cascade_state = CascadeState.ELEVATED
        else:
            self._cascade_state = CascadeState.NORMAL

    def record_failure(self, miner_uid: int, reason: str = ""):
        """Record a miner failure for cascade detection."""
        with self._data_lock:
            current_time = time.time()
            self._failure_timestamps.append(current_time)

            # Update miner state
            if miner_uid in self._miner_loads:
                self._miner_loads[miner_uid].last_failure_time = current_time

            self._cleanup_old_records()
            self._update_cascade_state()

            logger.info(
                f"Recorded failure for miner {miner_uid}: {reason}, "
                f"cascade_state={self._cascade_state.value}"
            )

    def can_reassign(
        self,
        to_miner_uid: int,
        origin_count: int = 1,
    ) -> Tuple[bool, str]:
        """
        Check if origins can be reassigned to a miner.

        Args:
            to_miner_uid: Target miner UID
            origin_count: Number of origins to reassign

        Returns:
            Tuple of (can_reassign, reason)
        """
        with self._data_lock:
            self._cleanup_old_records()
            self._update_cascade_state()

            # Emergency mode: no reassignments
            if self._cascade_state == CascadeState.EMERGENCY:
                return False, "Emergency mode: reassignments halted"

            # Check rate limit for this miner
            recent_count = len(self._miner_reassignment_counts.get(to_miner_uid, []))
            if recent_count + origin_count > MAX_REASSIGNMENTS_PER_MINER_PER_MINUTE:
                return False, (
                    f"Rate limit: miner {to_miner_uid} has received "
                    f"{recent_count} reassignments in last {REASSIGNMENT_WINDOW_SECONDS}s"
                )

            # Check miner load
            miner_load = self._miner_loads.get(to_miner_uid)
            if miner_load:
                if miner_load.is_overloaded():
                    return False, f"Miner {to_miner_uid} is at max capacity"
                if not miner_load.can_accept_origins(origin_count):
                    return False, f"Miner {to_miner_uid} would exceed load threshold"

            # Cascade mode: reduce limits
            if self._cascade_state == CascadeState.CASCADE:
                reduced_limit = MAX_REASSIGNMENTS_PER_MINER_PER_MINUTE // 2
                if recent_count + origin_count > reduced_limit:
                    return False, "Cascade mode: reduced rate limit in effect"

            return True, "OK"

    def record_reassignment(
        self,
        origin_id: str,
        from_miner_uid: int,
        to_miner_uid: int,
        reason: str = ""
    ):
        """Record a successful reassignment."""
        with self._data_lock:
            current_time = time.time()

            # Record in history
            record = ReassignmentRecord(
                origin_id=origin_id,
                from_miner_uid=from_miner_uid,
                to_miner_uid=to_miner_uid,
                timestamp=current_time,
                reason=reason
            )
            self._reassignment_history.append(record)

            # Update per-miner counts
            self._miner_reassignment_counts[to_miner_uid].append(current_time)

            # Update miner loads
            if from_miner_uid in self._miner_loads:
                self._miner_loads[from_miner_uid].current_origins = max(
                    0, self._miner_loads[from_miner_uid].current_origins - 1
                )
            if to_miner_uid in self._miner_loads:
                self._miner_loads[to_miner_uid].current_origins += 1

            logger.debug(
                f"Recorded reassignment: {origin_id} from {from_miner_uid} to {to_miner_uid}"
            )

    def update_miner_load(
        self,
        miner_uid: int,
        current_origins: int,
        max_origins: int = MAX_ORIGINS_PER_MINER
    ):
        """Update miner load information."""
        with self._data_lock:
            if miner_uid not in self._miner_loads:
                self._miner_loads[miner_uid] = MinerLoadState(
                    miner_uid=miner_uid,
                    current_origins=current_origins,
                    max_origins=max_origins
                )
            else:
                self._miner_loads[miner_uid].current_origins = current_origins
                self._miner_loads[miner_uid].max_origins = max_origins

    def get_best_target_miners(
        self,
        available_miners: List[int],
        origin_count: int = 1
    ) -> List[int]:
        """
        Get the best miners to receive origins, sorted by load.

        Implements load balancing: distributes across multiple miners
        instead of all-to-one.

        Args:
            available_miners: List of available miner UIDs
            origin_count: Number of origins to assign

        Returns:
            List of miner UIDs sorted by preference (least loaded first)
        """
        with self._data_lock:
            # Score miners by load and recent reassignments
            scored = []
            for miner_uid in available_miners:
                load = self._miner_loads.get(miner_uid)
                recent_count = len(self._miner_reassignment_counts.get(miner_uid, []))

                load_factor = load.load_factor() if load else 0.0

                # Skip overloaded miners
                if load and load.is_overloaded():
                    continue

                # Skip rate-limited miners
                if recent_count >= MAX_REASSIGNMENTS_PER_MINER_PER_MINUTE:
                    continue

                # Score: lower is better (prefer low load and few recent reassignments)
                score = load_factor + (recent_count / MAX_REASSIGNMENTS_PER_MINER_PER_MINUTE)
                scored.append((miner_uid, score))

            # Sort by score (ascending)
            scored.sort(key=lambda x: x[1])

            return [uid for uid, _ in scored]

    def get_cascade_state(self) -> CascadeState:
        """Get current cascade state."""
        with self._data_lock:
            self._cleanup_old_records()
            self._update_cascade_state()
            return self._cascade_state

    def get_status(self) -> Dict:
        """Get protection status for monitoring."""
        with self._data_lock:
            self._cleanup_old_records()
            return {
                "cascade_state": self._cascade_state.value,
                "recent_failures": len(self._failure_timestamps),
                "recent_reassignments": len(self._reassignment_history),
                "tracked_miners": len(self._miner_loads),
                "rate_limited_miners": sum(
                    1 for counts in self._miner_reassignment_counts.values()
                    if len(counts) >= MAX_REASSIGNMENTS_PER_MINER_PER_MINUTE
                ),
            }

    def reset(self):
        """Reset protection state (for testing)."""
        with self._data_lock:
            self._reassignment_history.clear()
            self._miner_reassignment_counts.clear()
            self._failure_timestamps.clear()
            self._cascade_state = CascadeState.NORMAL
            self._cascade_start_time = 0.0
            self._miner_loads.clear()
            self._emergency_blocked_origins.clear()
            logger.info("Failover protection reset")


# Singleton accessor
_failover_protection: Optional[FailoverProtection] = None


def get_failover_protection() -> FailoverProtection:
    """Get the singleton failover protection instance."""
    global _failover_protection
    if _failover_protection is None:
        _failover_protection = FailoverProtection()
    return _failover_protection
