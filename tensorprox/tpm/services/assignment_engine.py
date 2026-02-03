"""
Assignment Engine Service

Handles origin-to-miner assignment decisions based on validator scores.
Implements the assignment strategy specified in the subnet architecture.

Key Features:
- Assign origins to best-performing miners (score >= 0.8)
- Region-aware selection with nearest-region fallback
- Balance load across miners based on capacity
- Trigger reassignment when miners are flagged
- Periodic rebalancing based on updated scores

Region Selection Strategy:
1. Exact region match (if miners available in preferred region)
2. Nearest region fallback (sorted by Haversine distance)
3. Any region (if no miners in nearby regions)
"""

import logging
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor

from tensorprox.tpm.services.geolocation import get_regions_by_proximity, infer_provider_from_region

logger = logging.getLogger(__name__)


@dataclass
class MinerCandidate:
    """Miner candidate for assignment."""
    miner_uid: int
    aggregated_score: float
    origins_assigned: int
    max_origins: int
    scrubber_ip: str
    region: Optional[str] = None  # AWS/cloud region (e.g., 'us-east-1')
    is_available: bool = True  # Whether miner is online
    ema_score: float = 0.0  # EMA score from validator leaderboard
    miner_id: Optional[str] = None  # TPM miner_id (UUID) - for deployment integration
    hotkey: Optional[str] = None  # Bittensor hotkey

    @property
    def available_capacity(self) -> int:
        """Returns number of origins this miner can still handle."""
        return self.max_origins - self.origins_assigned

    @property
    def load_factor(self) -> float:
        """Returns load percentage (0.0 to 1.0)."""
        if self.max_origins == 0:
            return 1.0
        return self.origins_assigned / self.max_origins


@dataclass
class OriginAssignment:
    """Origin assignment details."""
    assignment_id: int
    origin_id: str
    origin_ip: str
    miner_uid: int
    scrubber_ip: str
    exit_hub_ip: str
    tunnel_name: str
    assigned_at: datetime
    reassigned_count: int
    expected_bandwidth_mbps: Optional[int] = None
    traffic_type: Optional[str] = None


@dataclass
class AssignmentRequest:
    """Request to assign an origin to a miner."""
    origin_id: str
    origin_ip: str
    expected_bandwidth_mbps: Optional[int] = None
    traffic_type: Optional[str] = None
    preferred_region: Optional[str] = None
    cloud_provider: Optional[str] = None  # aws, linode, etc.


class AssignmentEngine:
    """
    Assignment Engine

    Assigns origins to miners based on:
    1. Validator scores (aggregated median)
    2. Miner capacity (origins_assigned < max_origins)
    3. Load balancing (prefer less loaded miners)

    Assignment Strategy:
    - MIN_SCORE: 0.8 (only assign to miners with score >= 0.8)
    - BEST_SCORE: Prefer highest-scored miners
    - CAPACITY_BASED: Among high-scored miners, prefer those with lower load

    Staleness Handling:
    - If validator hasn't synced in 30+ minutes, data may be stale
    - Stale mode: relax availability requirement, use aggregated_score as fallback
    """

    MIN_SCORE = 0.8  # Minimum score to receive assignments
    STALE_DATA_THRESHOLD_MINUTES = 30  # Data older than this is considered stale

    def __init__(self, db_conn):
        """
        Initialize assignment engine.

        Args:
            db_conn: PostgreSQL database connection
        """
        self.db_conn = db_conn

    def check_data_freshness(self) -> Tuple[bool, Optional[datetime], int]:
        """
        Check if leaderboard data is fresh (recently synced by validator).

        Returns:
            Tuple of (is_fresh, last_update_time, miners_with_fresh_data)
        """
        with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    MAX(updated_at) as last_update,
                    COUNT(*) FILTER (
                        WHERE updated_at > NOW() - INTERVAL '%s minutes'
                    ) as fresh_count
                FROM subnet_miners
                WHERE state = 'active'
            """, (self.STALE_DATA_THRESHOLD_MINUTES,))

            row = cur.fetchone()
            last_update = row['last_update'] if row else None
            fresh_count = row['fresh_count'] if row else 0

            is_fresh = fresh_count > 0

            return is_fresh, last_update, fresh_count

    def get_available_miners(
        self,
        min_score: float = MIN_SCORE,
        limit: int = 10,
        preferred_region: Optional[str] = None,
        region_filter: Optional[List[str]] = None,
        require_available: bool = True
    ) -> List[MinerCandidate]:
        """
        Get available miners for assignment.

        Returns miners in 'active' state with:
        - Score >= min_score
        - Available capacity (origins_assigned < max_origins)
        - is_available = True (if require_available)
        - Matching region (if preferred_region or region_filter specified)

        Sorted by:
        1. Region match (preferred region first, then by proximity order)
        2. EMA score (descending) - validator's real-time leaderboard
        3. Load factor (ascending)

        Args:
            min_score: Minimum aggregated score required
            limit: Maximum number of miners to return
            preferred_region: Preferred AWS/cloud region for geo-aware assignment
            region_filter: List of regions to include (ordered by preference)
            require_available: Only return miners that are online

        Returns:
            List of miner candidates
        """
        with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Build query with optional filters
            query = """
                SELECT
                    miner_uid,
                    miner_id,
                    hotkey,
                    aggregated_score,
                    origins_assigned,
                    max_origins,
                    scrubber_ip,
                    region,
                    is_available,
                    COALESCE(ema_score, aggregated_score) as ema_score
                FROM subnet_miners
                WHERE state = 'active'
                  AND aggregated_score >= %s
                  AND origins_assigned < max_origins
            """
            params: List = [min_score]

            # Filter by availability
            if require_available:
                query += " AND is_available = TRUE"

            # Filter by region list (if provided) or single preferred region
            if region_filter:
                # Filter to specific regions (includes NULL for miners without region set)
                placeholders = ','.join(['%s'] * len(region_filter))
                query += f" AND (region IN ({placeholders}) OR region IS NULL)"
                params.extend(region_filter)
            elif preferred_region:
                # Legacy single-region filter
                query += " AND (region = %s OR region IS NULL)"
                params.append(preferred_region)

            # Sort: region preference order, then EMA score, then load
            if region_filter:
                # Build CASE statement for region ordering based on proximity
                case_when = "CASE region "
                for idx, region in enumerate(region_filter):
                    case_when += f"WHEN %s THEN {idx} "
                    params.append(region)
                case_when += f"ELSE {len(region_filter)} END"  # NULL regions last

                query += f"""
                ORDER BY
                    {case_when},
                    COALESCE(ema_score, aggregated_score) DESC,
                    origins_assigned ASC
                LIMIT %s
                """
                params.append(limit)
            elif preferred_region:
                query += """
                ORDER BY
                    CASE WHEN region = %s THEN 0 ELSE 1 END,
                    COALESCE(ema_score, aggregated_score) DESC,
                    origins_assigned ASC
                LIMIT %s
                """
                params.extend([preferred_region, limit])
            else:
                query += """
                ORDER BY
                    COALESCE(ema_score, aggregated_score) DESC,
                    origins_assigned ASC
                LIMIT %s
                """
                params.append(limit)

            cur.execute(query, params)
            rows = cur.fetchall()

            candidates = []
            for row in rows:
                candidates.append(MinerCandidate(
                    miner_uid=row['miner_uid'],
                    miner_id=row.get('miner_id'),
                    hotkey=row.get('hotkey'),
                    aggregated_score=float(row['aggregated_score']),
                    origins_assigned=row['origins_assigned'],
                    max_origins=row['max_origins'],
                    scrubber_ip=row['scrubber_ip'],
                    region=row.get('region'),
                    is_available=row.get('is_available', True),
                    ema_score=float(row.get('ema_score', 0))
                ))

            return candidates

    def select_best_miner(
        self,
        request: AssignmentRequest,
        provider: str = "aws"
    ) -> Optional[MinerCandidate]:
        """
        Select best miner for an origin assignment request.

        Region Selection Strategy (with nearest-region fallback):
        1. If preferred_region specified, get regions sorted by proximity
        2. Try exact region match first
        3. Fall back to nearest regions (using Haversine distance)
        4. Finally try any region if no nearby miners

        General Strategy:
        1. Check data freshness - if stale, use fallback mode
        2. Filter miners with score >= MIN_SCORE, available capacity, and online
        3. Prefer miners in same/nearest region as requested
        4. Sort by EMA score (descending), then load (ascending)
        5. Return top miner

        Fallback Mode (stale data):
        - Relax availability requirement (validator hasn't updated is_available)
        - Still require MIN_SCORE threshold
        - Log warning about stale data

        Args:
            request: Assignment request details
            provider: Cloud provider for region proximity calculation ("aws", "linode")
                      Falls back to request.cloud_provider or inference from region

        Returns:
            Best miner candidate, or None if no suitable miners
        """
        # Determine effective provider: param > request > inferred from region > default
        effective_provider = provider
        if request.cloud_provider:
            effective_provider = request.cloud_provider
        elif request.preferred_region and provider == "aws":
            # If provider wasn't explicitly set (still default), try to infer
            effective_provider = infer_provider_from_region(request.preferred_region)

        # Check data freshness
        is_fresh, last_update, fresh_count = self.check_data_freshness()

        if not is_fresh:
            logger.warning(
                "Leaderboard data is STALE (last update: %s, fresh miners: %d). "
                "Using fallback mode - availability data may be outdated.",
                last_update,
                fresh_count
            )

        candidates = []

        # If preferred region specified, use proximity-based selection
        if request.preferred_region:
            # Get regions sorted by proximity to preferred region
            regions_by_proximity = get_regions_by_proximity(
                origin_region=request.preferred_region,
                provider=effective_provider
            )

            logger.debug(
                "Region proximity order for %s: %s",
                request.preferred_region,
                regions_by_proximity[:5]  # Log first 5
            )

            # Try with regions sorted by proximity
            candidates = self.get_available_miners(
                min_score=self.MIN_SCORE,
                limit=10,
                region_filter=regions_by_proximity,
                require_available=is_fresh
            )

            # Log which region was selected
            if candidates:
                selected_region = candidates[0].region
                if selected_region != request.preferred_region:
                    # Calculate which position in proximity list
                    try:
                        proximity_rank = regions_by_proximity.index(selected_region) + 1
                    except ValueError:
                        proximity_rank = -1  # Region not in list (NULL?)

                    logger.info(
                        "No miner in exact region %s, using nearest region %s (proximity rank: %d)",
                        request.preferred_region,
                        selected_region or 'unknown',
                        proximity_rank
                    )
        else:
            # No region preference - just get best by score
            candidates = self.get_available_miners(
                min_score=self.MIN_SCORE,
                limit=10,
                require_available=is_fresh
            )

        # If no candidates and data was fresh, try without availability requirement
        if not candidates and is_fresh:
            logger.warning(
                "No available miners with require_available=True, "
                "trying without availability filter..."
            )
            if request.preferred_region:
                regions_by_proximity = get_regions_by_proximity(
                    origin_region=request.preferred_region,
                    provider=provider
                )
                candidates = self.get_available_miners(
                    min_score=self.MIN_SCORE,
                    limit=10,
                    region_filter=regions_by_proximity,
                    require_available=False
                )
            else:
                candidates = self.get_available_miners(
                    min_score=self.MIN_SCORE,
                    limit=10,
                    require_available=False
                )

        # Last resort: try without region filter entirely
        if not candidates and request.preferred_region:
            logger.warning(
                "No miners in proximity regions, trying any region..."
            )
            candidates = self.get_available_miners(
                min_score=self.MIN_SCORE,
                limit=10,
                require_available=is_fresh
            )

            if not candidates and is_fresh:
                candidates = self.get_available_miners(
                    min_score=self.MIN_SCORE,
                    limit=10,
                    require_available=False
                )

        if not candidates:
            logger.error(
                "No miners available for assignment (score >= %.2f, region=%s, stale=%s)",
                self.MIN_SCORE,
                request.preferred_region,
                not is_fresh
            )
            return None

        # Already sorted by region proximity, EMA score DESC, load ASC
        best = candidates[0]

        # Determine if this was exact match, nearest, or any region
        region_match_type = "any"
        if request.preferred_region:
            if best.region == request.preferred_region:
                region_match_type = "exact"
            elif best.region:
                region_match_type = "nearest"

        logger.info(
            "Selected miner UID %d (ema=%.3f, region=%s [%s match], load=%d/%d, stale_mode=%s) for origin %s",
            best.miner_uid,
            best.ema_score,
            best.region or 'unknown',
            region_match_type,
            best.origins_assigned,
            best.max_origins,
            not is_fresh,
            request.origin_id
        )

        return best

    def assign_origin(
        self,
        request: AssignmentRequest,
        exit_hub_ip: str,
        tunnel_name: str
    ) -> Optional[OriginAssignment]:
        """
        Assign origin to best available miner.

        Steps:
        1. Select best miner based on score and capacity
        2. Create assignment record in database
        3. Update miner's assignment count
        4. Return assignment details

        Args:
            request: Assignment request
            exit_hub_ip: Exit hub IP for this origin
            tunnel_name: WireGuard tunnel name (e.g., "wg-miner-42")

        Returns:
            Assignment details, or None if assignment failed
        """
        # Select best miner
        miner = self.select_best_miner(request)
        if not miner:
            logger.error("No suitable miner found for origin %s", request.origin_id)
            return None

        # Create assignment using database function
        try:
            with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT assign_origin_to_miner(
                        %s, %s, %s, %s, %s, %s, %s, %s
                    ) AS assignment_id
                """, (
                    request.origin_id,
                    miner.miner_uid,
                    request.origin_ip,
                    miner.scrubber_ip,
                    exit_hub_ip,
                    tunnel_name,
                    request.expected_bandwidth_mbps,
                    request.traffic_type
                ))

                result = cur.fetchone()
                assignment_id = result['assignment_id']
                self.db_conn.commit()

                logger.info(
                    "Assigned origin %s to miner UID %d (assignment_id=%d)",
                    request.origin_id,
                    miner.miner_uid,
                    assignment_id
                )

                # Return assignment details
                return OriginAssignment(
                    assignment_id=assignment_id,
                    origin_id=request.origin_id,
                    origin_ip=request.origin_ip,
                    miner_uid=miner.miner_uid,
                    scrubber_ip=miner.scrubber_ip,
                    exit_hub_ip=exit_hub_ip,
                    tunnel_name=tunnel_name,
                    assigned_at=datetime.now(),
                    reassigned_count=0,
                    expected_bandwidth_mbps=request.expected_bandwidth_mbps,
                    traffic_type=request.traffic_type
                )

        except Exception as e:
            self.db_conn.rollback()
            logger.error("Failed to assign origin %s: %s", request.origin_id, e)
            return None

    def get_miner_assignments(self, miner_uid: int) -> List[OriginAssignment]:
        """
        Get all active assignments for a miner.

        Args:
            miner_uid: Miner UID to query

        Returns:
            List of active assignments
        """
        with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    assignment_id,
                    origin_id,
                    origin_ip,
                    miner_uid,
                    scrubber_ip,
                    exit_hub_ip,
                    tunnel_name,
                    assigned_at,
                    reassigned_count,
                    expected_bandwidth_mbps,
                    traffic_type
                FROM miner_assignments
                WHERE miner_uid = %s AND status = 'active'
                ORDER BY assigned_at DESC
            """, (miner_uid,))

            rows = cur.fetchall()
            return [OriginAssignment(**row) for row in rows]

    def get_all_assignments(self) -> List[OriginAssignment]:
        """
        Get all active assignments across all miners.

        Returns:
            List of all active assignments
        """
        with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    assignment_id,
                    origin_id,
                    origin_ip,
                    miner_uid,
                    scrubber_ip,
                    exit_hub_ip,
                    tunnel_name,
                    assigned_at,
                    reassigned_count,
                    expected_bandwidth_mbps,
                    traffic_type
                FROM miner_assignments
                WHERE status = 'active'
                ORDER BY miner_uid, assigned_at DESC
            """)

            rows = cur.fetchall()
            return [OriginAssignment(**row) for row in rows]

    def reassign_origin(
        self,
        origin_id: str,
        reason: str
    ) -> Optional[OriginAssignment]:
        """
        Reassign origin to a different miner.

        Steps:
        1. Get current assignment details
        2. Mark current assignment as 'draining'
        3. Find new miner (excluding current one)
        4. Create new assignment
        5. Decrement old miner's count, increment new miner's count
        6. Update reassignment metadata

        Args:
            origin_id: Origin to reassign
            reason: Reason for reassignment

        Returns:
            New assignment details, or None if reassignment failed
        """
        try:
            with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Get current assignment
                cur.execute("""
                    SELECT
                        origin_id, origin_ip, miner_uid, exit_hub_ip,
                        tunnel_name, expected_bandwidth_mbps, traffic_type,
                        reassigned_count
                    FROM miner_assignments
                    WHERE origin_id = %s AND status = 'active'
                """, (origin_id,))

                current = cur.fetchone()
                if not current:
                    logger.warning("No active assignment found for origin %s", origin_id)
                    return None

                old_miner_uid = current['miner_uid']

                # Mark current assignment as draining
                cur.execute("""
                    UPDATE miner_assignments
                    SET status = 'draining',
                        last_reassignment_reason = %s
                    WHERE origin_id = %s AND status = 'active'
                """, (reason, origin_id))

                # Create assignment request
                request = AssignmentRequest(
                    origin_id=origin_id,
                    origin_ip=current['origin_ip'],
                    expected_bandwidth_mbps=current['expected_bandwidth_mbps'],
                    traffic_type=current['traffic_type']
                )

                # Assign to new miner
                new_assignment = self.assign_origin(
                    request=request,
                    exit_hub_ip=current['exit_hub_ip'],
                    tunnel_name=current['tunnel_name']
                )

                if not new_assignment:
                    # Rollback draining status
                    cur.execute("""
                        UPDATE miner_assignments
                        SET status = 'active'
                        WHERE origin_id = %s AND status = 'draining'
                    """, (origin_id,))
                    self.db_conn.commit()
                    return None

                # Update reassignment metadata
                cur.execute("""
                    UPDATE miner_assignments
                    SET reassigned_count = %s,
                        last_reassignment_reason = %s
                    WHERE assignment_id = %s
                """, (
                    current['reassigned_count'] + 1,
                    reason,
                    new_assignment.assignment_id
                ))

                # Decrement old miner's count
                cur.execute("""
                    UPDATE subnet_miners
                    SET origins_assigned = origins_assigned - 1,
                        updated_at = NOW()
                    WHERE miner_uid = %s
                """, (old_miner_uid,))

                self.db_conn.commit()

                logger.info(
                    "Reassigned origin %s from miner %d to miner %d (reason: %s)",
                    origin_id,
                    old_miner_uid,
                    new_assignment.miner_uid,
                    reason
                )

                return new_assignment

        except Exception as e:
            self.db_conn.rollback()
            logger.error("Failed to reassign origin %s: %s", origin_id, e)
            return None

    def reassign_flagged_miner_origins(self, miner_uid: int) -> int:
        """
        Reassign all origins from a flagged miner.

        Called when a miner is flagged due to consecutive failures.

        Args:
            miner_uid: Flagged miner UID

        Returns:
            Number of origins successfully reassigned
        """
        assignments = self.get_miner_assignments(miner_uid)

        if not assignments:
            logger.info("No active assignments for flagged miner %d", miner_uid)
            return 0

        logger.warning(
            "Reassigning %d origins from flagged miner %d",
            len(assignments),
            miner_uid
        )

        reassigned_count = 0
        for assignment in assignments:
            result = self.reassign_origin(
                origin_id=assignment.origin_id,
                reason=f"Miner {miner_uid} flagged (consecutive failures)"
            )
            if result:
                reassigned_count += 1

        logger.info(
            "Reassigned %d/%d origins from flagged miner %d",
            reassigned_count,
            len(assignments),
            miner_uid
        )

        return reassigned_count

    def rebalance_assignments(
        self,
        rebalance_threshold: float = 0.15
    ) -> Dict[str, int]:
        """
        Periodic rebalancing of assignments based on updated scores.

        Strategy:
        - Identify miners with low scores (< MIN_SCORE + threshold)
        - Reassign their origins to higher-scored miners
        - Avoid excessive churn (only rebalance if score difference > threshold)

        Args:
            rebalance_threshold: Score difference threshold for rebalancing

        Returns:
            Dict with rebalancing stats: {'reassigned': N, 'failed': M}
        """
        stats = {'reassigned': 0, 'failed': 0}

        try:
            with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Find miners with active assignments but low scores
                cur.execute("""
                    SELECT
                        sm.miner_uid,
                        sm.aggregated_score,
                        sm.origins_assigned
                    FROM subnet_miners sm
                    WHERE sm.state = 'active'
                      AND sm.origins_assigned > 0
                      AND sm.aggregated_score < %s
                    ORDER BY sm.aggregated_score ASC
                """, (self.MIN_SCORE + rebalance_threshold,))

                low_score_miners = cur.fetchall()

                if not low_score_miners:
                    logger.info("No miners require rebalancing")
                    return stats

                logger.info(
                    "Rebalancing: %d miners below threshold (score < %.2f)",
                    len(low_score_miners),
                    self.MIN_SCORE + rebalance_threshold
                )

                # Reassign origins from low-scored miners
                for miner in low_score_miners:
                    assignments = self.get_miner_assignments(miner['miner_uid'])

                    for assignment in assignments:
                        result = self.reassign_origin(
                            origin_id=assignment.origin_id,
                            reason=f"Rebalancing: miner score {miner['aggregated_score']:.3f} below threshold"
                        )

                        if result:
                            stats['reassigned'] += 1
                        else:
                            stats['failed'] += 1

                logger.info(
                    "Rebalancing complete: %d reassigned, %d failed",
                    stats['reassigned'],
                    stats['failed']
                )

        except Exception as e:
            logger.error("Rebalancing failed: %s", e)

        return stats
