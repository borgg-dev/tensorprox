"""Shard repository for TensorProx Management."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from shared.utils.logging import get_logger

from .base import BaseRepository

logger = get_logger(__name__)


class ShardRepository(BaseRepository):
    """Manage miner shard cache in TPM."""

    def upsert_shard(
        self,
        miner_id: UUID,
        shard_id: str,
        region: str,
        status: str = "active",
        shard_type: str = "audit",
    ) -> None:
        """Insert or update a shard record.

        Args:
            miner_id: The miner owning this shard
            shard_id: Unique identifier for the shard
            region: AWS region
            status: Shard status ('active', 'deploying', 'failed')
            shard_type: 'audit' (validator scoring) or 'production' (customer origins)
        """
        with self.connection() as db:
            db.execute(
                """
                INSERT INTO tensorprox_miner_shards
                    (miner_id, shard_id, region, status, shard_type, last_synced_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                ON CONFLICT (miner_id, shard_id) DO UPDATE SET
                    region = EXCLUDED.region,
                    status = EXCLUDED.status,
                    shard_type = EXCLUDED.shard_type,
                    last_synced_at = NOW(),
                    updated_at = NOW();
                """,
                (str(miner_id), shard_id, region, status, shard_type),
            )

    def get_shards_for_miner(self, miner_id: UUID) -> List[Dict[str, Any]]:
        """Get all shards for a miner."""
        with self.connection() as db:
            rows = db.query_all(
                """
                SELECT miner_id, shard_id, region, status, shard_type, last_synced_at,
                       created_at, updated_at, origin_count
                FROM tensorprox_miner_shards
                WHERE miner_id = %s
                ORDER BY shard_id;
                """,
                (str(miner_id),),
            )
        return [dict(row) for row in rows]

    def get_shard(self, miner_id: UUID, shard_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific shard."""
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT miner_id, shard_id, region, status, shard_type, last_synced_at,
                       created_at, updated_at, origin_count
                FROM tensorprox_miner_shards
                WHERE miner_id = %s AND shard_id = %s;
                """,
                (str(miner_id), shard_id),
            )
        return dict(row) if row else None

    def delete_shard(self, miner_id: UUID, shard_id: str) -> None:
        """Remove a shard record."""
        with self.connection() as db:
            db.execute(
                """
                DELETE FROM tensorprox_miner_shards
                WHERE miner_id = %s AND shard_id = %s;
                """,
                (str(miner_id), shard_id),
            )

    def sync_shards_from_miner(
        self,
        miner_id: UUID,
        shards: List[Dict[str, Any]],
    ) -> None:
        """Bulk sync shards from Miner API response.

        FULL RECONCILIATION: This method ensures TPM's shard cache exactly matches
        what the miner reports. Shards that exist in TPM but not in the miner's
        response are deleted to prevent stale records causing deployment failures.

        Preserves shard_type from miner response ('audit' or 'production').
        """
        now = datetime.now(timezone.utc)
        miner_id_str = str(miner_id)

        # Get set of shard IDs from miner response
        miner_shard_ids = {shard["shard_id"] for shard in shards}

        with self.connection() as db:
            # Step 1: Get existing shards in TPM for this miner
            existing_rows = db.query_all(
                """
                SELECT shard_id FROM tensorprox_miner_shards
                WHERE miner_id = %s;
                """,
                (miner_id_str,),
            )
            existing_shard_ids = {row["shard_id"] for row in existing_rows} if existing_rows else set()

            # Step 2: Delete shards that exist in TPM but not on miner (stale records)
            stale_shard_ids = existing_shard_ids - miner_shard_ids
            if stale_shard_ids:
                logger.info(
                    "Miner %s: removing %d stale shards from TPM cache: %s",
                    miner_id_str[:8], len(stale_shard_ids), list(stale_shard_ids)
                )
                for stale_id in stale_shard_ids:
                    db.execute(
                        """
                        DELETE FROM tensorprox_miner_shards
                        WHERE miner_id = %s AND shard_id = %s;
                        """,
                        (miner_id_str, stale_id),
                    )

            # Step 3: Upsert each shard from miner response
            for shard in shards:
                db.execute(
                    """
                    INSERT INTO tensorprox_miner_shards
                        (miner_id, shard_id, region, status, shard_type, last_synced_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (miner_id, shard_id) DO UPDATE SET
                        region = EXCLUDED.region,
                        status = EXCLUDED.status,
                        shard_type = EXCLUDED.shard_type,
                        last_synced_at = EXCLUDED.last_synced_at,
                        updated_at = NOW();
                    """,
                    (
                        miner_id_str,
                        shard["shard_id"],
                        shard["region"],
                        shard.get("status", "active"),
                        shard.get("shard_type", "audit"),  # Default to audit if not specified
                        now,
                    ),
                )

    # --- Sweep tracking methods ---

    def schedule_sweep(
        self, miner_id: UUID, shard_id: str, grace_minutes: int = 10
    ) -> None:
        """Schedule shard for sweep after grace period (status stays 'active').

        Only schedules sweep for PRODUCTION shards - audit shards are never swept.
        Audit shards must remain always active for validator scoring.
        """
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_miner_shards
                SET sweep_after = NOW() + INTERVAL '%s minutes',
                    updated_at = NOW()
                WHERE miner_id = %s AND shard_id = %s
                  AND status = 'active'
                  AND shard_type = 'production';
                """,
                (grace_minutes, str(miner_id), shard_id),
            )

    def cancel_sweep(self, miner_id: UUID, shard_id: str) -> None:
        """Cancel scheduled sweep (new origin deployed)."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_miner_shards
                SET sweep_after = NULL,
                    updated_at = NOW()
                WHERE miner_id = %s AND shard_id = %s;
                """,
                (str(miner_id), shard_id),
            )

    def get_sweepable_shards(self) -> List[Dict[str, Any]]:
        """Get shards ready for sweep (grace period expired, still active).

        Only returns PRODUCTION shards - audit shards are never swept.
        Audit shards must remain always active for validator scoring.
        """
        with self.connection() as db:
            rows = db.query_all(
                """
                SELECT miner_id, shard_id, region, sweep_after, shard_type
                FROM tensorprox_miner_shards
                WHERE sweep_after IS NOT NULL
                  AND sweep_after <= NOW()
                  AND status = 'active'
                  AND shard_type = 'production';
                """
            )
        return [dict(row) for row in rows] if rows else []

    def increment_origin_count(self, miner_id: UUID, shard_id: str) -> int:
        """Increment origin count, cancel any pending sweep."""
        with self.connection() as db:
            row = db.execute_returning_one(
                """
                UPDATE tensorprox_miner_shards
                SET origin_count = origin_count + 1,
                    sweep_after = NULL,
                    status = 'active',
                    updated_at = NOW()
                WHERE miner_id = %s AND shard_id = %s
                RETURNING origin_count;
                """,
                (str(miner_id), shard_id),
            )
        return row['origin_count'] if row else 0

    def decrement_origin_count(self, miner_id: UUID, shard_id: str) -> int:
        """Decrement origin count, return new count for sweep check."""
        with self.connection() as db:
            row = db.execute_returning_one(
                """
                UPDATE tensorprox_miner_shards
                SET origin_count = GREATEST(0, origin_count - 1),
                    updated_at = NOW()
                WHERE miner_id = %s AND shard_id = %s
                RETURNING origin_count;
                """,
                (str(miner_id), shard_id),
            )
        return row['origin_count'] if row else 0

    def get_miners_with_active_shards(self) -> List[str]:
        """Get list of miner IDs that have at least one active shard.

        Used for miner assignment validation - only assign to miners
        that have deployed infrastructure.
        """
        with self.connection() as db:
            rows = db.query_all(
                """
                SELECT DISTINCT miner_id::text
                FROM tensorprox_miner_shards
                WHERE status = 'active';
                """
            )
        return [row['miner_id'] for row in rows] if rows else []

    def get_production_shards_for_miner(self, miner_id: UUID) -> List[Dict[str, Any]]:
        """Get only production shards for a miner (for origin deployment).

        Excludes audit shards which are reserved for validator scoring only.
        """
        with self.connection() as db:
            rows = db.query_all(
                """
                SELECT miner_id, shard_id, region, status, shard_type, last_synced_at,
                       created_at, updated_at, origin_count
                FROM tensorprox_miner_shards
                WHERE miner_id = %s AND shard_type = 'production' AND status = 'active'
                ORDER BY shard_id;
                """,
                (str(miner_id),),
            )
        return [dict(row) for row in rows]

    def get_audit_shard_for_miner(self, miner_id: UUID) -> Optional[Dict[str, Any]]:
        """Get the audit shard for a miner (for validator scoring).

        Each miner should have exactly one audit shard created on startup.
        """
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT miner_id, shard_id, region, status, shard_type, last_synced_at,
                       created_at, updated_at, origin_count
                FROM tensorprox_miner_shards
                WHERE miner_id = %s AND shard_type = 'audit' AND status = 'active'
                LIMIT 1;
                """,
                (str(miner_id),),
            )
        return dict(row) if row else None

    def miner_has_active_shards(self, miner_id: UUID) -> bool:
        """Check if a specific miner has at least one active shard."""
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT 1 FROM tensorprox_miner_shards
                WHERE miner_id = %s AND status = 'active'
                LIMIT 1;
                """,
                (str(miner_id),),
            )
        return row is not None

    def get_stale_deploying_shards(self, threshold_minutes: int = 30) -> List[Dict[str, Any]]:
        """Get shards stuck in 'deploying' status for longer than threshold.

        These are shards where node deployment likely failed but the shard
        record persists, causing validators to select broken shards.

        Args:
            threshold_minutes: Shards older than this are considered stale

        Returns:
            List of shard dicts with miner_id, shard_id, region, last_synced_at
        """
        with self.connection() as db:
            rows = db.query_all(
                """
                SELECT miner_id, shard_id, region, status, origin_count, last_synced_at
                FROM tensorprox_miner_shards
                WHERE status = 'deploying'
                  AND origin_count = 0
                  AND last_synced_at < NOW() - INTERVAL '%s minutes'
                ORDER BY last_synced_at ASC;
                """,
                (threshold_minutes,),
            )
        return rows if rows else []

    def mark_shard_as_failed(self, miner_id: UUID, shard_id: str) -> None:
        """Mark a shard as failed (will be excluded from deployment selection)."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_miner_shards
                SET status = 'failed', last_synced_at = NOW(), updated_at = NOW()
                WHERE miner_id = %s AND shard_id = %s;
                """,
                (str(miner_id), shard_id),
            )

    def update_shard_status(self, miner_id: UUID, shard_id: str, status: str) -> None:
        """Update shard status."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_miner_shards
                SET status = %s, last_synced_at = NOW(), updated_at = NOW()
                WHERE miner_id = %s AND shard_id = %s;
                """,
                (status, str(miner_id), shard_id),
            )
