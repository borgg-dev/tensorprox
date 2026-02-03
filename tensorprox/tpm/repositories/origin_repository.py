"""Origin repository for TensorProx Management."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional

from psycopg2.extras import Json

from shared.utils.logging import get_logger

from .base import BaseRepository

logger = get_logger(__name__)

ORIGIN_ID_PATTERN = re.compile(r"(\d+)$")


class OriginRepository(BaseRepository):
    """Manage origin inventory and numbering."""

    def find_by_origin_id(self, origin_id: str) -> Optional[Dict[str, Any]]:
        """Return origin row with all fields including deployment data."""
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT o.client_id, o.origin_id, o.origin_num, o.status,
                       o.miner_id, o.miner_ip, o.shard_id, o.tensorprox_ip,
                       o.last_exit_hub_id, o.deletion_error,
                       ms.region
                FROM tensorprox_origins o
                LEFT JOIN tensorprox_miner_shards ms
                    ON o.miner_id IS NOT NULL
                       AND o.miner_id::uuid = ms.miner_id
                       AND o.shard_id = ms.shard_id
                WHERE o.origin_id = %s
                ORDER BY o.updated_at DESC
                LIMIT 1;
                """,
                (origin_id,),
            )
        return row

    def delete_origin(self, client_id: str, origin_id: str) -> None:
        """Remove origin record entirely."""
        with self.connection() as db:
            db.execute(
                "DELETE FROM tensorprox_origins WHERE client_id = %s AND origin_id = %s;",
                (client_id, origin_id),
            )

    def reserve_origin(
        self,
        client_id: str,
        requested_origin_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Reserve (or create) a globally unique origin ID.

        Rules:
        - Active/provisioning origins are unique globally.
        - Terminated/failed origins can be recycled into the pool.
        """
        with self.connection() as db:
            conn = db.conn
            cur = conn.cursor()

            if requested_origin_id:
                # Enforce global uniqueness: lock any existing row for this origin_id.
                existing = self._get_origin_global(cur, requested_origin_id)
                if existing:
                    if existing["status"] not in {"terminated", "failed"}:
                        raise ValueError(
                            f"origin_id {requested_origin_id} already assigned to client {existing['client_id']}"
                        )
                    row = self._reuse_origin(cur, client_id, requested_origin_id, existing.get("origin_num"))
                    conn.commit()
                    return row

                origin_num = self._infer_origin_num(requested_origin_id) or self._next_global_origin_num(cur)
                row = self._insert_origin(cur, client_id, requested_origin_id, origin_num)
                conn.commit()
                return row

            # Reuse a terminated/failed origin from the global pool if available
            reusable = self._claim_reusable_origin(cur, client_id)
            if reusable:
                conn.commit()
                return reusable

            # Auto-assign a new globally unique origin_id
            origin_num = self._next_global_origin_num(cur)
            origin_id = f"O{origin_num}"
            row = self._insert_origin(cur, client_id, origin_id, origin_num)
            conn.commit()
            return row

    def update_status(self, client_id: str, origin_id: str, status: str) -> None:
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_origins
                SET status = %s,
                    updated_at = NOW()
                WHERE client_id = %s AND origin_id = %s;
                """,
                (status, client_id, origin_id),
            )

    def release_origin(self, client_id: str, origin_id: str) -> None:
        """Mark origin as terminated so it can be reused later."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_origins
                SET status = 'terminated',
                    updated_at = NOW()
                WHERE client_id = %s AND origin_id = %s;
                """,
                (client_id, origin_id),
            )

    def set_miner_assignment(
        self,
        client_id: str,
        origin_id: str,
        miner_id: Optional[str],
        miner_ip: Optional[str]
    ) -> None:
        """Persist miner metadata for an origin."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_origins
                SET miner_id = %s,
                    miner_ip = %s,
                    updated_at = NOW()
                WHERE client_id = %s AND origin_id = %s;
                """,
                (miner_id, miner_ip, client_id, origin_id),
            )

    def set_deployment_result(
        self,
        client_id: str,
        origin_id: str,
        *,
        shard_id: str,
        tensorprox_ip: str,
    ) -> None:
        """Persist deployment result after successful Miner registration."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_origins
                SET shard_id = %s,
                    tensorprox_ip = %s,
                    updated_at = NOW()
                WHERE client_id = %s AND origin_id = %s;
                """,
                (shard_id, tensorprox_ip, client_id, origin_id),
            )

    def clear_deployment(self, client_id: str, origin_id: str) -> None:
        """Clear deployment fields on termination."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_origins
                SET shard_id = NULL,
                    tensorprox_ip = NULL,
                    updated_at = NOW()
                WHERE client_id = %s AND origin_id = %s;
                """,
                (client_id, origin_id),
            )

    # ------------------------------------------------------------------ #
    # Termination tracking methods
    # ------------------------------------------------------------------ #
    def set_last_exit_hub_id(self, origin_id: str, exit_hub_id: str) -> None:
        """Store exit_hub_id association for reliable termination notification."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_origins
                SET last_exit_hub_id = %s,
                    updated_at = NOW()
                WHERE origin_id = %s;
                """,
                (exit_hub_id, origin_id),
            )

    def get_last_exit_hub_id(self, origin_id: str) -> Optional[str]:
        """Retrieve stored exit_hub_id for notification purposes."""
        with self.connection() as db:
            row = db.query_one(
                "SELECT last_exit_hub_id FROM tensorprox_origins WHERE origin_id = %s;",
                (origin_id,),
            )
        if row and row.get("last_exit_hub_id"):
            return str(row["last_exit_hub_id"])
        return None

    def set_deletion_error(self, origin_id: str, error: Optional[str]) -> None:
        """Store internal deletion error (not exposed to webapp)."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_origins
                SET deletion_error = %s,
                    updated_at = NOW()
                WHERE origin_id = %s;
                """,
                (error, origin_id),
            )

    def mark_terminated_with_error(
        self,
        client_id: str,
        origin_id: str,
        error: Optional[str] = None
    ) -> None:
        """Mark origin as terminated with optional internal error tracking."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_origins
                SET status = 'terminated',
                    deletion_error = %s,
                    shard_id = NULL,
                    tensorprox_ip = NULL,
                    updated_at = NOW()
                WHERE client_id = %s AND origin_id = %s;
                """,
                (error, client_id, origin_id),
            )

    # ------------------------------------------------------------------ #
    # Egress routing methods
    # ------------------------------------------------------------------ #
    def set_egress_config(self, origin_id: str, questionnaire: dict) -> None:
        """Store egress questionnaire responses for an origin."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_origins
                SET egress_questionnaire = %s,
                    updated_at = NOW()
                WHERE origin_id = %s;
                """,
                (Json(questionnaire), origin_id),
            )

    def get_egress_config(self, origin_id: str) -> Optional[Dict[str, Any]]:
        """Return egress configuration fields for an origin."""
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT egress_enabled, egress_questionnaire, egress_activated_at
                FROM tensorprox_origins
                WHERE origin_id = %s;
                """,
                (origin_id,),
            )
        if not row:
            return None
        return {
            "egress_enabled": row.get("egress_enabled"),
            "egress_questionnaire": row.get("egress_questionnaire"),
            "egress_activated_at": row.get("egress_activated_at"),
        }

    def set_egress_enabled(
        self,
        origin_id: str,
        enabled: bool,
        activated_at: Optional[datetime] = None,
    ) -> None:
        """Enable or disable egress routing for an origin."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_origins
                SET egress_enabled = %s,
                    egress_activated_at = %s,
                    updated_at = NOW()
                WHERE origin_id = %s;
                """,
                (enabled, activated_at, origin_id),
            )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _get_origin(self, cur, client_id: str, origin_id: str) -> Optional[Dict[str, Any]]:
        cur.execute(
            """
            SELECT client_id, origin_id, origin_num, status
            FROM tensorprox_origins
            WHERE client_id = %s AND origin_id = %s
            FOR UPDATE;
            """,
            (client_id, origin_id),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "client_id": row[0],
            "origin_id": row[1],
            "origin_num": row[2],
            "status": row[3],
        }

    def _insert_origin(
        self,
        cur,
        client_id: str,
        origin_id: str,
        origin_num: Optional[int]
    ) -> Dict[str, Any]:
        # Get validator UID from TPM app context
        from tensorprox.tpm.app import get_validator_uid
        validator_uid = get_validator_uid()

        cur.execute(
            """
            INSERT INTO tensorprox_origins (client_id, origin_id, origin_num, status, validator_uid)
            VALUES (%s, %s, %s, 'provisioning', %s)
            ON CONFLICT (client_id, origin_id) DO UPDATE
            SET origin_num = COALESCE(EXCLUDED.origin_num, tensorprox_origins.origin_num),
                status = 'provisioning',
                validator_uid = COALESCE(EXCLUDED.validator_uid, tensorprox_origins.validator_uid),
                updated_at = NOW()
            RETURNING client_id, origin_id, origin_num, status;
            """,
            (client_id, origin_id, origin_num, validator_uid),
        )
        row = cur.fetchone()
        return {
            "client_id": row[0],
            "origin_id": row[1],
            "origin_num": row[2],
            "status": row[3],
        }

    def _set_status(self, cur, client_id: str, origin_id: str, status: str) -> None:
        cur.execute(
            """
            UPDATE tensorprox_origins
            SET status = %s,
                updated_at = NOW()
            WHERE client_id = %s AND origin_id = %s;
            """,
            (status, client_id, origin_id),
        )

    def _infer_origin_num(self, origin_id: str) -> Optional[int]:
        match = ORIGIN_ID_PATTERN.search(origin_id)
        if not match:
            return None
        return int(match.group(1))

    def _next_global_origin_num(self, cur) -> int:
        """Allocate a globally unique origin number via sequence."""
        cur.execute("CREATE SEQUENCE IF NOT EXISTS tensorprox_origin_id_seq MINVALUE 1;")
        cur.execute("SELECT nextval('tensorprox_origin_id_seq');")
        row = cur.fetchone()
        if not row or row[0] is None:
            raise RuntimeError("Failed to allocate global origin number")
        return int(row[0])

    def _get_origin_global(self, cur, origin_id: str) -> Optional[Dict[str, Any]]:
        cur.execute(
            """
            SELECT client_id, origin_id, origin_num, status
            FROM tensorprox_origins
            WHERE origin_id = %s
            FOR UPDATE;
            """,
            (origin_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "client_id": row[0],
            "origin_id": row[1],
            "origin_num": row[2],
            "status": row[3],
        }

    def _claim_reusable_origin(self, cur, client_id: str) -> Optional[Dict[str, Any]]:
        """Recycle a terminated/failed origin globally into this client."""
        cur.execute(
            """
            SELECT origin_id, origin_num
            FROM tensorprox_origins
            WHERE status IN ('terminated', 'failed')
            ORDER BY origin_num NULLS LAST, origin_id
            LIMIT 1
            FOR UPDATE SKIP LOCKED;
            """
        )
        row = cur.fetchone()
        if not row:
            return None
        origin_id, origin_num = row
        return self._reuse_origin(cur, client_id, origin_id, origin_num)

    def _reuse_origin(self, cur, client_id: str, origin_id: str, origin_num: Optional[int]) -> Dict[str, Any]:
        """Reassign a recycled origin to a client and mark provisioning."""
        # Clear any existing rows for this origin_id to avoid conflicts
        cur.execute("DELETE FROM tensorprox_origins WHERE origin_id = %s;", (origin_id,))
        cur.execute(
            """
            INSERT INTO tensorprox_origins (client_id, origin_id, origin_num, status, miner_id, miner_ip)
            VALUES (%s, %s, %s, 'provisioning', NULL, NULL)
            RETURNING client_id, origin_id, origin_num, status;
            """,
            (client_id, origin_id, origin_num),
        )
        row = cur.fetchone()
        return {
            "client_id": row[0],
            "origin_id": row[1],
            "origin_num": row[2],
            "status": row[3],
        }
