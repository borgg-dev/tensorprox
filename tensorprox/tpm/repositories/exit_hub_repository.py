"""Exit hub persistence helpers."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from shared.utils.logging import get_logger

from .base import BaseRepository

logger = get_logger(__name__)
_UNSET = object()

# Terminal statuses that cannot be overwritten by workers
TERMINAL_STATUSES = frozenset({'cancelled', 'terminated', 'failed'})


class ExitHubRepository(BaseRepository):
    """CRUD helpers for tensorprox_exit_hubs table."""

    def create_exit_hub(
        self,
        *,
        exit_hub_id: UUID,
        client_id: Optional[str],
        origin_id: str,
        origin_ip: str,
        status: str,
        instance_id: Optional[str] = None,
        exit_hub_ip: Optional[str] = None,
        miner_id: Optional[str] = None,
        miner_ip: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Insert a new exit hub record."""
        with self.connection() as db:
            db.execute(
                """
                INSERT INTO tensorprox_exit_hubs (
                    exit_hub_id, client_id, origin_id, origin_ip,
                    instance_id, exit_hub_ip, status, miner_id, miner_ip, metadata
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT (exit_hub_id) DO NOTHING;
                """,
                (
                    str(exit_hub_id),
                    client_id,
                    origin_id,
                    origin_ip,
                    instance_id,
                    exit_hub_ip,
                    status,
                    miner_id,
                    miner_ip,
                    json.dumps(metadata or {}),
                ),
            )

    def update_exit_hub(
        self,
        exit_hub_id: Union[str, UUID],
        *,
        status: Optional[str] = None,
        instance_id: Union[str, None, object] = _UNSET,
        exit_hub_ip: Union[str, None, object] = _UNSET,
        tensorprox_ip: Optional[str] = None,
        secret: Optional[str] = None,
        wg_interface: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        miner_id: Optional[str] = None,
        miner_ip: Optional[str] = None,
        last_error: Union[str, None, object] = _UNSET,
        force: bool = False
    ) -> bool:
        """Update fields for an exit hub.

        Args:
            force: If True, bypass terminal status protection. Use for cancel/terminate.

        Returns:
            True if update was applied, False if blocked by terminal status.
        """
        # Check terminal status protection (unless force=True)
        if status is not None and not force:
            current = self.get_exit_hub(exit_hub_id)
            if current and current.get('status') in TERMINAL_STATUSES:
                logger.warning(
                    "Blocked status update %s→%s for %s (terminal status protected)",
                    current['status'], status, exit_hub_id
                )
                return False

        updates = []
        params: List[Any] = []

        if status is not None:
            updates.append("status = %s")
            params.append(status)

        if instance_id is not _UNSET:
            updates.append("instance_id = %s")
            params.append(instance_id)

        if exit_hub_ip is not _UNSET:
            updates.append("exit_hub_ip = %s")
            params.append(exit_hub_ip)

        if secret is not None:
            updates.append("secret = %s")
            params.append(secret)

        if wg_interface is not None:
            updates.append("wg_interface = %s")
            params.append(wg_interface)

        if metadata is not None:
            updates.append("metadata = %s::jsonb")
            params.append(json.dumps(metadata))

        if miner_id is not None:
            updates.append("miner_id = %s")
            params.append(miner_id)

        if miner_ip is not None:
            updates.append("miner_ip = %s")
            params.append(miner_ip)

        if tensorprox_ip is not None:
            updates.append("tensorprox_ip = %s")
            params.append(tensorprox_ip)

        if last_error is not _UNSET:
            updates.append("last_error = %s")
            params.append(last_error)

        if not updates:
            return True

        updates.append("updated_at = NOW()")
        params.append(str(exit_hub_id))

        sql = f"""
            UPDATE tensorprox_exit_hubs
            SET {', '.join(updates)}
            WHERE exit_hub_id = %s;
        """

        with self.connection() as db:
            db.execute(sql, tuple(params))
        return True

    def list_exit_hubs(
        self,
        *,
        statuses: Optional[List[str]] = None,
        client_id: Optional[str] = None,
        origin_id: Optional[str] = None,
        miner_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return exit hubs filtered by the provided criteria.

        Uses JOINs to fetch canonical data from related tables while maintaining
        backward compatibility via COALESCE for fields being migrated from
        exit_hubs to origins/miners/miner_shards.
        """
        clauses: List[str] = []
        params: List[Any] = []

        if statuses:
            placeholders = ", ".join(["%s"] * len(statuses))
            clauses.append(f"eh.status IN ({placeholders})")
            params.extend(statuses)

        if client_id:
            clauses.append("COALESCE(o.client_id, eh.client_id) = %s")
            params.append(client_id)

        if origin_id:
            clauses.append("eh.origin_id = %s")
            params.append(origin_id)

        if miner_id:
            clauses.append("COALESCE(o.miner_id, eh.miner_id) = %s")
            params.append(miner_id)

        where_clause = ""
        if clauses:
            where_clause = f"WHERE {' AND '.join(clauses)}"

        with self.connection() as db:
            rows = db.query_all(
                f"""
                SELECT
                    eh.exit_hub_id,
                    eh.origin_id,
                    eh.origin_ip,
                    eh.instance_id,
                    eh.exit_hub_ip,
                    eh.status,
                    eh.secret,
                    eh.wg_interface,
                    eh.metadata,
                    eh.last_error,
                    eh.created_at,
                    eh.updated_at,
                    COALESCE(o.client_id, eh.client_id) AS client_id,
                    o.tensorprox_ip AS tensorprox_ip,
                    o.shard_id AS shard_id,
                    COALESCE(o.miner_id, eh.miner_id) AS miner_id,
                    COALESCE(m.current_ip, o.miner_ip, eh.miner_ip) AS miner_ip,
                    ms.region AS region
                FROM tensorprox_exit_hubs eh
                LEFT JOIN tensorprox_origins o ON eh.origin_id = o.origin_id
                LEFT JOIN tensorprox_miners m ON o.miner_id::uuid = m.miner_id
                LEFT JOIN tensorprox_miner_shards ms
                    ON o.miner_id::uuid = ms.miner_id AND o.shard_id = ms.shard_id
                {where_clause}
                ORDER BY eh.created_at DESC;
                """,
                tuple(params)
            )
        return [self._serialize_record(row) for row in rows]

    def get_exit_hub(self, exit_hub_id: Union[str, UUID]) -> Optional[Dict[str, Any]]:
        """Fetch a single exit hub by id.

        Uses JOINs to fetch canonical data from related tables while maintaining
        backward compatibility via COALESCE for fields being migrated from
        exit_hubs to origins/miners/miner_shards.
        """
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT
                    eh.exit_hub_id,
                    eh.origin_id,
                    eh.origin_ip,
                    eh.instance_id,
                    eh.exit_hub_ip,
                    eh.status,
                    eh.secret,
                    eh.wg_interface,
                    eh.metadata,
                    eh.last_error,
                    eh.created_at,
                    eh.updated_at,
                    COALESCE(o.client_id, eh.client_id) AS client_id,
                    o.tensorprox_ip AS tensorprox_ip,
                    o.shard_id AS shard_id,
                    COALESCE(o.miner_id, eh.miner_id) AS miner_id,
                    COALESCE(m.current_ip, o.miner_ip, eh.miner_ip) AS miner_ip,
                    ms.region AS region
                FROM tensorprox_exit_hubs eh
                LEFT JOIN tensorprox_origins o ON eh.origin_id = o.origin_id
                LEFT JOIN tensorprox_miners m ON o.miner_id::uuid = m.miner_id
                LEFT JOIN tensorprox_miner_shards ms
                    ON o.miner_id::uuid = ms.miner_id AND o.shard_id = ms.shard_id
                WHERE eh.exit_hub_id = %s;
                """,
                (str(exit_hub_id),),
            )
        return self._serialize_record(row) if row else None

    def get_exit_hub_by_origin(self, origin_id: str) -> Optional[Dict[str, Any]]:
        """Fetch latest exit hub record for an origin.

        Uses JOINs to fetch canonical data from related tables while maintaining
        backward compatibility via COALESCE for fields being migrated from
        exit_hubs to origins/miners/miner_shards.
        """
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT
                    eh.exit_hub_id,
                    eh.origin_id,
                    eh.origin_ip,
                    eh.instance_id,
                    eh.exit_hub_ip,
                    eh.status,
                    eh.secret,
                    eh.wg_interface,
                    eh.metadata,
                    eh.last_error,
                    eh.created_at,
                    eh.updated_at,
                    COALESCE(o.client_id, eh.client_id) AS client_id,
                    o.tensorprox_ip AS tensorprox_ip,
                    o.shard_id AS shard_id,
                    COALESCE(o.miner_id, eh.miner_id) AS miner_id,
                    COALESCE(m.current_ip, o.miner_ip, eh.miner_ip) AS miner_ip,
                    ms.region AS region
                FROM tensorprox_exit_hubs eh
                LEFT JOIN tensorprox_origins o ON eh.origin_id = o.origin_id
                LEFT JOIN tensorprox_miners m ON o.miner_id::uuid = m.miner_id
                LEFT JOIN tensorprox_miner_shards ms
                    ON o.miner_id::uuid = ms.miner_id AND o.shard_id = ms.shard_id
                WHERE eh.origin_id = %s
                ORDER BY eh.updated_at DESC
                LIMIT 1;
                """,
                (origin_id,),
            )
        return self._serialize_record(row) if row else None

    def update_metadata(self, exit_hub_id: Union[str, UUID], updates: Dict[str, Any]) -> None:
        """Merge metadata JSON with provided updates."""
        if not updates:
            return

        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_exit_hubs
                SET metadata = COALESCE(metadata, '{}'::jsonb) || %s::jsonb,
                    updated_at = NOW()
                WHERE exit_hub_id = %s;
                """,
                (json.dumps(updates), str(exit_hub_id)),
            )

    def update_metadata_by_origin(
        self, origin_id: str, updates: Dict[str, Any], *, status: str = "active"
    ) -> bool:
        """
        Merge metadata JSON for the active exit hub of an origin.

        Args:
            origin_id: The origin to update
            updates: Key-value pairs to merge into metadata
            status: Only update exit hubs with this status (default: active)

        Returns:
            True if a record was updated, False if no matching record found.
        """
        if not updates:
            return False

        with self.connection() as db:
            result = db.execute(
                """
                UPDATE tensorprox_exit_hubs
                SET metadata = COALESCE(metadata, '{}'::jsonb) || %s::jsonb,
                    updated_at = NOW()
                WHERE origin_id = %s AND status = %s;
                """,
                (json.dumps(updates), origin_id, status),
            )
            updated = result.rowcount > 0 if hasattr(result, 'rowcount') else True

        if updated:
            logger.info(
                "Updated metadata for origin=%s status=%s: %s",
                origin_id, status, list(updates.keys())
            )
        else:
            logger.warning(
                "No exit hub found for origin=%s status=%s to update metadata",
                origin_id, status
            )
        return updated

    def delete_exit_hub(self, exit_hub_id: Union[str, UUID]) -> None:
        """Hard-delete an exit hub record."""
        with self.connection() as db:
            db.execute(
                "DELETE FROM tensorprox_exit_hubs WHERE exit_hub_id = %s;",
                (str(exit_hub_id),)
            )

    # ------------------------------------------------------------------ #
    # Deferred purge methods for reliable termination notification
    # ------------------------------------------------------------------ #
    def mark_for_purge(
        self,
        exit_hub_id: Union[str, UUID],
        purge_after: datetime
    ) -> None:
        """Mark exit hub for deferred deletion by background sweeper."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_exit_hubs
                SET purge_after = %s,
                    updated_at = NOW()
                WHERE exit_hub_id = %s;
                """,
                (purge_after, str(exit_hub_id)),
            )

    def get_purgeable_exit_hubs(self) -> List[Dict[str, Any]]:
        """Return exit hubs ready for permanent deletion."""
        with self.connection() as db:
            rows = db.query_all(
                """
                SELECT exit_hub_id, origin_id, status, purge_after
                FROM tensorprox_exit_hubs
                WHERE purge_after IS NOT NULL
                  AND purge_after <= NOW();
                """
            )
        return [dict(row) for row in rows] if rows else []

    def purge_all(self) -> int:
        """Delete ALL exit hub records. Used by /cleanup endpoint."""
        with self.connection() as db:
            result = db.execute("DELETE FROM tensorprox_exit_hubs;")
            count = result.rowcount if hasattr(result, 'rowcount') else 0
        logger.info("Purged all exit hub records: %d deleted", count)
        return count

    @staticmethod
    def _serialize_record(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not row:
            return None

        record = dict(row)
        record['exit_hub_id'] = str(record['exit_hub_id'])
        if record.get('client_id') is None:
            record['client_id'] = None

        for ts_key in ('created_at', 'updated_at'):
            value = record.get(ts_key)
            if isinstance(value, datetime):
                record[ts_key] = value.isoformat()

        metadata = record.get('metadata')
        if isinstance(metadata, str):
            try:
                record['metadata'] = json.loads(metadata)
            except json.JSONDecodeError:
                logger.warning("Failed to decode metadata for exit_hub_id=%s", record['exit_hub_id'])
                record['metadata'] = {}
        elif metadata is None:
            record['metadata'] = {}

        return record
