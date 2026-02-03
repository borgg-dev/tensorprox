"""
Score Aggregator Service

Processes validator score reports and calculates aggregated miner scores.
Implements the scoring aggregation strategy from the subnet architecture.

Key Features:
- Store raw validator scores
- Calculate aggregated score (median of last 5 validator reports)
- Weight recent scores higher
- Detect score changes and trigger rebalancing
- Track validator consensus
"""

import logging
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


@dataclass
class ScoreReport:
    """Validator score report for a miner."""
    validator_uid: int
    validator_hotkey: str
    miner_uid: int
    score: float
    score_components: Optional[Dict[str, float]] = None
    audit_type: Optional[str] = None  # 'pre_assignment' or 'production'
    validator_version: Optional[str] = None


@dataclass
class MinerScore:
    """Aggregated score for a miner."""
    miner_uid: int
    aggregated_score: float
    validator_count: int
    score_stddev: float
    last_updated: datetime


class ScoreAggregator:
    """
    Score Aggregator

    Aggregates validator scores using median of last 5 reports.

    Aggregation Method:
    - MEDIAN: Use median to reduce impact of outliers
    - LAST_5: Only consider most recent report from each validator (max 5)
    - CONSENSUS: Track how many validators agree (within ±0.1)

    Score Components:
    - volume: 40% (bytes, connections, origins)
    - latency: 30% (RTT, SYN/SYN-ACK ratio)
    - availability: 20% (uptime, failover count)
    - mitigation: 10% (attack detection accuracy)
    """

    SCORE_CHANGE_THRESHOLD = 0.15  # Trigger rebalancing if score changes > 15%
    MIN_VALIDATORS_FOR_CONSENSUS = 3  # Minimum validators needed for reliable score

    def __init__(self, db_conn):
        """
        Initialize score aggregator.

        Args:
            db_conn: PostgreSQL database connection
        """
        self.db_conn = db_conn

    def process_validator_scores(
        self,
        validator_uid: int,
        validator_hotkey: str,
        scores: Dict[int, float],
        score_components: Optional[Dict[int, Dict[str, float]]] = None,
        audit_type: str = "production",
        validator_version: Optional[str] = None
    ) -> Dict[int, float]:
        """
        Process scores from a validator for multiple miners.

        Steps:
        1. Store raw scores in database
        2. Update aggregated score for each miner
        3. Check if rebalancing is needed (score change > threshold)

        Args:
            validator_uid: Validator UID reporting scores
            validator_hotkey: Validator hotkey
            scores: Dict mapping miner_uid -> score (0.0 to 1.0)
            score_components: Optional breakdown of score components
            audit_type: 'pre_assignment' or 'production'
            validator_version: Validator software version

        Returns:
            Dict mapping miner_uid -> updated aggregated score
        """
        if not scores:
            logger.warning("Validator %d submitted empty scores", validator_uid)
            return {}

        logger.info(
            "Processing scores from validator %d for %d miners",
            validator_uid,
            len(scores)
        )

        updated_scores = {}

        try:
            with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
                for miner_uid, score in scores.items():
                    # Validate score range
                    if not (0.0 <= score <= 1.0):
                        logger.warning(
                            "Invalid score %.3f from validator %d for miner %d (must be 0.0-1.0)",
                            score,
                            validator_uid,
                            miner_uid
                        )
                        continue

                    # Get score components for this miner
                    components = None
                    if score_components and miner_uid in score_components:
                        components = score_components[miner_uid]

                    # Insert raw score
                    cur.execute("""
                        INSERT INTO validator_scores (
                            validator_uid,
                            validator_hotkey,
                            miner_uid,
                            score,
                            score_components,
                            audit_type,
                            validator_version,
                            reported_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    """, (
                        validator_uid,
                        validator_hotkey,
                        miner_uid,
                        score,
                        psycopg2.extras.Json(components) if components else None,
                        audit_type,
                        validator_version
                    ))

                    # Update aggregated score using database function
                    cur.execute("""
                        SELECT update_miner_aggregated_score(%s) AS new_score
                    """, (miner_uid,))

                    result = cur.fetchone()
                    new_score = float(result['new_score']) if result else 0.0
                    updated_scores[miner_uid] = new_score

                    logger.debug(
                        "Miner %d: raw score %.3f from validator %d, aggregated score %.3f",
                        miner_uid,
                        score,
                        validator_uid,
                        new_score
                    )

                self.db_conn.commit()

                logger.info(
                    "Stored %d scores from validator %d, updated aggregated scores",
                    len(updated_scores),
                    validator_uid
                )

        except Exception as e:
            self.db_conn.rollback()
            logger.error("Failed to process validator scores: %s", e)
            return {}

        return updated_scores

    def get_miner_score(
        self,
        miner_uid: int
    ) -> Optional[MinerScore]:
        """
        Get aggregated score for a miner.

        Returns:
            MinerScore with aggregated score, validator count, and metadata
        """
        with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    miner_uid,
                    aggregated_score,
                    last_score_update
                FROM subnet_miners
                WHERE miner_uid = %s
            """, (miner_uid,))

            row = cur.fetchone()
            if not row:
                return None

            # Get validator consensus stats
            cur.execute("""
                SELECT
                    COUNT(DISTINCT validator_uid) AS validator_count,
                    STDDEV(score) AS score_stddev
                FROM (
                    SELECT DISTINCT ON (validator_uid) score
                    FROM validator_scores
                    WHERE miner_uid = %s
                    ORDER BY validator_uid, reported_at DESC
                    LIMIT 5
                ) recent_scores
            """, (miner_uid,))

            stats = cur.fetchone()

            return MinerScore(
                miner_uid=miner_uid,
                aggregated_score=float(row['aggregated_score']),
                validator_count=stats['validator_count'] or 0,
                score_stddev=float(stats['score_stddev']) if stats['score_stddev'] else 0.0,
                last_updated=row['last_score_update'] or datetime.now()
            )

    def get_validator_scores_for_miner(
        self,
        miner_uid: int,
        limit: int = 10
    ) -> List[Dict]:
        """
        Get recent validator scores for a miner.

        Args:
            miner_uid: Miner UID
            limit: Maximum number of scores to return

        Returns:
            List of score records (most recent first)
        """
        with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    validator_uid,
                    validator_hotkey,
                    score,
                    score_components,
                    audit_type,
                    reported_at
                FROM validator_scores
                WHERE miner_uid = %s
                ORDER BY reported_at DESC
                LIMIT %s
            """, (miner_uid, limit))

            return [dict(row) for row in cur.fetchall()]

    def check_score_consensus(
        self,
        miner_uid: int,
        consensus_threshold: float = 0.1
    ) -> Tuple[bool, float]:
        """
        Check if validators have consensus on a miner's score.

        Consensus is defined as:
        - At least MIN_VALIDATORS_FOR_CONSENSUS validators reporting
        - Score standard deviation < consensus_threshold

        Args:
            miner_uid: Miner UID
            consensus_threshold: Maximum acceptable std deviation

        Returns:
            Tuple of (has_consensus, score_stddev)
        """
        miner_score = self.get_miner_score(miner_uid)

        if not miner_score:
            return False, 0.0

        has_consensus = (
            miner_score.validator_count >= self.MIN_VALIDATORS_FOR_CONSENSUS and
            miner_score.score_stddev < consensus_threshold
        )

        if not has_consensus:
            logger.warning(
                "Miner %d lacks consensus: %d validators, stddev %.3f",
                miner_uid,
                miner_score.validator_count,
                miner_score.score_stddev
            )

        return has_consensus, miner_score.score_stddev

    def promote_miner_to_active(
        self,
        miner_uid: int,
        pass_threshold: float = 0.8
    ) -> bool:
        """
        Promote miner from PRE_ASSIGNMENT to ACTIVE state.

        Called when miner passes pre-assignment testing.

        Args:
            miner_uid: Miner UID
            pass_threshold: Minimum score required to pass (default 0.8)

        Returns:
            True if promoted, False if score insufficient or miner not found
        """
        miner_score = self.get_miner_score(miner_uid)

        if not miner_score:
            logger.error("Cannot promote miner %d: not found", miner_uid)
            return False

        if miner_score.aggregated_score < pass_threshold:
            logger.info(
                "Miner %d score %.3f below threshold %.2f, not promoted",
                miner_uid,
                miner_score.aggregated_score,
                pass_threshold
            )
            return False

        try:
            with self.db_conn.cursor() as cur:
                cur.execute("""
                    UPDATE subnet_miners
                    SET state = 'active',
                        updated_at = NOW()
                    WHERE miner_uid = %s AND state = 'pre_assignment'
                """, (miner_uid,))

                if cur.rowcount == 0:
                    logger.warning(
                        "Miner %d not promoted (not in pre_assignment state)",
                        miner_uid
                    )
                    return False

                self.db_conn.commit()

                logger.info(
                    "Promoted miner %d to ACTIVE (score %.3f >= threshold %.2f)",
                    miner_uid,
                    miner_score.aggregated_score,
                    pass_threshold
                )

                return True

        except Exception as e:
            self.db_conn.rollback()
            logger.error("Failed to promote miner %d: %s", miner_uid, e)
            return False

    def flag_miner(
        self,
        miner_uid: int,
        reason: str
    ) -> bool:
        """
        Flag miner due to poor performance.

        Args:
            miner_uid: Miner UID
            reason: Reason for flagging

        Returns:
            True if flagged, False if failed
        """
        try:
            with self.db_conn.cursor() as cur:
                cur.execute("""
                    UPDATE subnet_miners
                    SET state = 'flagged',
                        updated_at = NOW()
                    WHERE miner_uid = %s AND state != 'flagged'
                """, (miner_uid,))

                if cur.rowcount == 0:
                    logger.warning("Miner %d already flagged or not found", miner_uid)
                    return False

                self.db_conn.commit()

                logger.warning(
                    "Flagged miner %d (reason: %s)",
                    miner_uid,
                    reason
                )

                return True

        except Exception as e:
            self.db_conn.rollback()
            logger.error("Failed to flag miner %d: %s", miner_uid, e)
            return False

    def get_top_miners(
        self,
        limit: int = 10,
        min_validators: int = MIN_VALIDATORS_FOR_CONSENSUS
    ) -> List[MinerScore]:
        """
        Get top-scored miners with consensus.

        Args:
            limit: Maximum number of miners to return
            min_validators: Minimum validators required for consensus

        Returns:
            List of top miners sorted by score (descending)
        """
        with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    sm.miner_uid,
                    sm.aggregated_score,
                    sm.last_score_update,
                    COUNT(DISTINCT vs.validator_uid) AS validator_count,
                    STDDEV(vs.score) AS score_stddev
                FROM subnet_miners sm
                LEFT JOIN (
                    SELECT DISTINCT ON (validator_uid, miner_uid)
                        validator_uid,
                        miner_uid,
                        score
                    FROM validator_scores
                    ORDER BY validator_uid, miner_uid, reported_at DESC
                ) vs ON sm.miner_uid = vs.miner_uid
                WHERE sm.state IN ('active', 'pre_assignment')
                GROUP BY sm.miner_uid, sm.aggregated_score, sm.last_score_update
                HAVING COUNT(DISTINCT vs.validator_uid) >= %s
                ORDER BY sm.aggregated_score DESC
                LIMIT %s
            """, (min_validators, limit))

            rows = cur.fetchall()

            return [
                MinerScore(
                    miner_uid=row['miner_uid'],
                    aggregated_score=float(row['aggregated_score']),
                    validator_count=row['validator_count'],
                    score_stddev=float(row['score_stddev']) if row['score_stddev'] else 0.0,
                    last_updated=row['last_score_update'] or datetime.now()
                )
                for row in rows
            ]

    def get_score_statistics(self) -> Dict:
        """
        Get overall scoring statistics for monitoring.

        Returns:
            Dict with stats: active_miners, avg_score, median_score, etc.
        """
        with self.db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    COUNT(*) FILTER (WHERE state = 'active') AS active_miners,
                    COUNT(*) FILTER (WHERE state = 'pre_assignment') AS pre_assignment_miners,
                    COUNT(*) FILTER (WHERE state = 'flagged') AS flagged_miners,
                    AVG(aggregated_score) FILTER (WHERE state = 'active') AS avg_score,
                    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY aggregated_score) FILTER (WHERE state = 'active') AS median_score,
                    MAX(aggregated_score) FILTER (WHERE state = 'active') AS max_score,
                    MIN(aggregated_score) FILTER (WHERE state = 'active') AS min_score
                FROM subnet_miners
            """)

            stats = cur.fetchone()

            return {
                'active_miners': stats['active_miners'] or 0,
                'pre_assignment_miners': stats['pre_assignment_miners'] or 0,
                'flagged_miners': stats['flagged_miners'] or 0,
                'avg_score': float(stats['avg_score']) if stats['avg_score'] else 0.0,
                'median_score': float(stats['median_score']) if stats['median_score'] else 0.0,
                'max_score': float(stats['max_score']) if stats['max_score'] else 0.0,
                'min_score': float(stats['min_score']) if stats['min_score'] else 0.0
            }
