"""Repository for miner operation queue management.

Provides CRUD operations for tensorprox_miner_operations table with
atomic claim_next for FIFO processing.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from psycopg2.extras import Json

from shared.utils.logging import get_logger

from .base import BaseRepository

logger = get_logger(__name__)


@dataclass
class MinerOperation:
    """Represents a queued miner operation."""

    operation_id: UUID
    miner_id: UUID
    operation_type: str
    status: str
    priority: int
    payload: Dict[str, Any]
    result: Optional[Dict[str, Any]]
    error: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    updated_at: datetime
    exit_hub_id: Optional[UUID]
    origin_id: Optional[str]
    shard_id: Optional[str]

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> MinerOperation:
        """Create MinerOperation from database row."""
        return cls(
            operation_id=row["operation_id"],
            miner_id=row["miner_id"],
            operation_type=row["operation_type"],
            status=row["status"],
            priority=row["priority"],
            payload=row.get("payload") or {},
            result=row.get("result"),
            error=row.get("error"),
            created_at=row["created_at"],
            started_at=row.get("started_at"),
            completed_at=row.get("completed_at"),
            updated_at=row["updated_at"],
            exit_hub_id=row.get("exit_hub_id"),
            origin_id=row.get("origin_id"),
            shard_id=row.get("shard_id"),
        )


class MinerOperationRepository(BaseRepository):
    """Manage miner operation queue with FIFO semantics."""

    def create(
        self,
        miner_id: str,
        operation_type: str,
        payload: Dict[str, Any],
        exit_hub_id: Optional[str] = None,
        origin_id: Optional[str] = None,
        shard_id: Optional[str] = None,
        priority: int = 100,
    ) -> MinerOperation:
        """Create a new queued operation.

        Args:
            miner_id: UUID of the target miner
            operation_type: One of 'deploy_shard', 'register_origin', 'delete_origin'
            payload: Operation-specific data
            exit_hub_id: Optional exit hub UUID for tracing
            origin_id: Optional origin ID for tracing
            shard_id: Optional shard ID for tracing
            priority: Priority (lower = higher priority), default 100

        Returns:
            Created MinerOperation
        """
        with self.connection() as db:
            row = db.execute_returning_one(
                """
                INSERT INTO tensorprox_miner_operations
                    (miner_id, operation_type, payload, exit_hub_id, origin_id,
                     shard_id, priority, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued')
                RETURNING *;
                """,
                (
                    miner_id,
                    operation_type,
                    Json(payload),
                    exit_hub_id,
                    origin_id,
                    shard_id,
                    priority,
                ),
            )
        logger.debug(
            "Created miner operation %s: type=%s miner=%s",
            row["operation_id"],
            operation_type,
            miner_id,
        )
        return MinerOperation.from_row(row)

    def claim_next(self, miner_id: str) -> Optional[MinerOperation]:
        """Atomically claim the next queued operation for a miner.

        Uses SELECT FOR UPDATE SKIP LOCKED to ensure only one worker
        can claim each operation, even under concurrent access.

        Args:
            miner_id: UUID of the miner to claim for

        Returns:
            Claimed MinerOperation with status='processing', or None if queue empty
        """
        with self.connection() as db:
            # Atomic claim: select + update in single transaction
            row = db.execute_returning_one(
                """
                UPDATE tensorprox_miner_operations
                SET status = 'processing',
                    started_at = NOW(),
                    updated_at = NOW()
                WHERE operation_id = (
                    SELECT operation_id
                    FROM tensorprox_miner_operations
                    WHERE miner_id = %s AND status = 'queued'
                    ORDER BY priority ASC, created_at ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING *;
                """,
                (miner_id,),
            )
        if row:
            logger.debug(
                "Claimed operation %s for miner %s",
                row["operation_id"],
                miner_id,
            )
            return MinerOperation.from_row(row)
        return None

    def complete(
        self,
        operation_id: str,
        result: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Mark operation as succeeded with optional result.

        Args:
            operation_id: UUID of the operation
            result: Optional result data to store
        """
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_miner_operations
                SET status = 'succeeded',
                    result = %s,
                    completed_at = NOW(),
                    updated_at = NOW()
                WHERE operation_id = %s;
                """,
                (Json(result) if result else None, operation_id),
            )
        logger.debug("Completed operation %s", operation_id)

    def fail(self, operation_id: str, error: str) -> None:
        """Mark operation as failed with error message.

        Args:
            operation_id: UUID of the operation
            error: Error message
        """
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_miner_operations
                SET status = 'failed',
                    error = %s,
                    completed_at = NOW(),
                    updated_at = NOW()
                WHERE operation_id = %s;
                """,
                (error, operation_id),
            )
        logger.debug("Failed operation %s: %s", operation_id, error)

    def cancel(self, operation_id: str) -> bool:
        """Cancel a queued operation.

        Only operations with status='queued' can be cancelled.

        Args:
            operation_id: UUID of the operation

        Returns:
            True if cancelled, False if not found or not in queued state
        """
        with self.connection() as db:
            with db.conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE tensorprox_miner_operations
                    SET status = 'cancelled',
                        completed_at = NOW(),
                        updated_at = NOW()
                    WHERE operation_id = %s AND status = 'queued';
                    """,
                    (operation_id,),
                )
                rowcount = cursor.rowcount
            db.conn.commit()
        cancelled = rowcount > 0
        if cancelled:
            logger.debug("Cancelled operation %s", operation_id)
        return cancelled

    def cancel_by_exit_hub(self, exit_hub_id: str) -> int:
        """Cancel all queued operations for an exit hub.

        Used during cancel flow to abort pending operations.

        Args:
            exit_hub_id: UUID of the exit hub

        Returns:
            Number of operations cancelled
        """
        with self.connection() as db:
            with db.conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE tensorprox_miner_operations
                    SET status = 'cancelled',
                        completed_at = NOW(),
                        updated_at = NOW()
                    WHERE exit_hub_id = %s AND status = 'queued';
                    """,
                    (exit_hub_id,),
                )
                rowcount = cursor.rowcount
            db.conn.commit()
        if rowcount:
            logger.info("Cancelled %d operations for exit_hub %s", rowcount, exit_hub_id)
        return rowcount

    def get_by_id(self, operation_id: str) -> Optional[MinerOperation]:
        """Get operation by ID.

        Args:
            operation_id: UUID of the operation

        Returns:
            MinerOperation or None if not found
        """
        with self.connection() as db:
            row = db.query_one(
                "SELECT * FROM tensorprox_miner_operations WHERE operation_id = %s;",
                (operation_id,),
            )
        if row:
            return MinerOperation.from_row(row)
        return None

    def get_queue_position(self, miner_id: str, operation_id: str) -> int:
        """Get position of operation in miner's queue.

        Args:
            miner_id: UUID of the miner
            operation_id: UUID of the operation

        Returns:
            Position (1-based), or 0 if not in queue
        """
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT COUNT(*) + 1 as position
                FROM tensorprox_miner_operations
                WHERE miner_id = %s
                  AND status = 'queued'
                  AND (priority, created_at) < (
                      SELECT priority, created_at
                      FROM tensorprox_miner_operations
                      WHERE operation_id = %s
                  );
                """,
                (miner_id, operation_id),
            )
        return row["position"] if row else 0

    def get_queue_depth(self, miner_id: str) -> int:
        """Get number of pending operations for a miner (queued + processing).

        This gives the true queue position: if there's 1 processing and 1 queued,
        a new operation would be at position 3.

        Args:
            miner_id: UUID of the miner

        Returns:
            Number of queued + processing operations
        """
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT COUNT(*) as depth
                FROM tensorprox_miner_operations
                WHERE miner_id = %s AND status IN ('queued', 'processing');
                """,
                (miner_id,),
            )
        return row["depth"] if row else 0

    def is_miner_busy(self, miner_id: str) -> bool:
        """Check if miner has any processing operation.

        Args:
            miner_id: UUID of the miner

        Returns:
            True if miner is currently processing an operation
        """
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT EXISTS(
                    SELECT 1 FROM tensorprox_miner_operations
                    WHERE miner_id = %s AND status = 'processing'
                ) as is_busy;
                """,
                (miner_id,),
            )
        return row["is_busy"] if row else False

    def get_processing(self, miner_id: str) -> Optional[MinerOperation]:
        """Get currently processing operation for a miner.

        Args:
            miner_id: UUID of the miner

        Returns:
            Processing MinerOperation or None
        """
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT * FROM tensorprox_miner_operations
                WHERE miner_id = %s AND status = 'processing'
                LIMIT 1;
                """,
                (miner_id,),
            )
        if row:
            return MinerOperation.from_row(row)
        return None

    def recover_orphaned(self, max_age_seconds: int = 3600) -> int:
        """Mark orphaned processing operations as failed.

        Called on TPM startup to recover from crashes. Operations that
        have been processing for longer than max_age_seconds are marked
        as failed.

        Args:
            max_age_seconds: Maximum age for processing operations

        Returns:
            Number of operations recovered
        """
        with self.connection() as db:
            with db.conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE tensorprox_miner_operations
                    SET status = 'failed',
                        error = 'TPM restart - operation orphaned',
                        completed_at = NOW(),
                        updated_at = NOW()
                    WHERE status = 'processing'
                      AND started_at < NOW() - INTERVAL '%s seconds';
                    """,
                    (max_age_seconds,),
                )
                rowcount = cursor.rowcount
            db.conn.commit()
        if rowcount:
            logger.warning("Recovered %d orphaned operations", rowcount)
        return rowcount

    def list_by_miner(
        self,
        miner_id: str,
        statuses: Optional[List[str]] = None,
        limit: int = 100,
    ) -> List[MinerOperation]:
        """List operations for a miner.

        Args:
            miner_id: UUID of the miner
            statuses: Optional list of statuses to filter
            limit: Maximum number to return

        Returns:
            List of MinerOperation
        """
        with self.connection() as db:
            if statuses:
                rows = db.query_all(
                    """
                    SELECT * FROM tensorprox_miner_operations
                    WHERE miner_id = %s AND status = ANY(%s)
                    ORDER BY created_at DESC
                    LIMIT %s;
                    """,
                    (miner_id, statuses, limit),
                )
            else:
                rows = db.query_all(
                    """
                    SELECT * FROM tensorprox_miner_operations
                    WHERE miner_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s;
                    """,
                    (miner_id, limit),
                )
        return [MinerOperation.from_row(r) for r in rows]

    def cleanup_old(self, days: int = 7) -> int:
        """Delete completed operations older than specified days.

        Args:
            days: Age threshold in days

        Returns:
            Number of operations deleted
        """
        with self.connection() as db:
            with db.conn.cursor() as cursor:
                cursor.execute(
                    """
                    DELETE FROM tensorprox_miner_operations
                    WHERE status IN ('succeeded', 'failed', 'cancelled')
                      AND completed_at < NOW() - INTERVAL '%s days';
                    """,
                    (days,),
                )
                rowcount = cursor.rowcount
            db.conn.commit()
        if rowcount:
            logger.info("Cleaned up %d old operations", rowcount)
        return rowcount
