"""Miner repository for registration and lifecycle state."""
from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from shared.utils.logging import get_logger

from .base import BaseRepository

logger = get_logger(__name__)


class MinerRepository(BaseRepository):
    """CRUD helpers for tensorprox_miners table."""

    def create_miner(
        self,
        *,
        miner_id: UUID,
        name: Optional[str],
        secret_hash: str,
        secret_plaintext: str,
        current_ip: Optional[str],
        metadata: Optional[Dict[str, Any]] = None,
        miner_public_key: Optional[bytes] = None,
        cloud_credentials_enc: Optional[bytes] = None,
    ) -> None:
        """Create a new miner registration record.

        Args:
            miner_id: UUID for the new miner
            name: Display name for the miner
            secret_hash: SHA256 hash of the miner secret
            secret_plaintext: Plaintext secret for TPM to use when calling miner
            current_ip: Current public IP of the miner
            metadata: Additional metadata as JSON
            miner_public_key: X25519 public key for credential encryption (32 bytes)
            cloud_credentials_enc: Fernet-encrypted cloud credentials
        """
        with self.connection() as db:
            db.execute(
                """
                INSERT INTO tensorprox_miners (
                    miner_id, name, current_ip, status,
                    secret_hash, secret_plaintext, metadata,
                    miner_public_key, cloud_credentials_enc
                )
                VALUES (%s, %s, %s, 'active', %s, %s, %s::jsonb, %s, %s)
                ON CONFLICT (miner_id) DO NOTHING;
                """,
                (
                    str(miner_id),
                    name,
                    current_ip,
                    secret_hash,
                    secret_plaintext,
                    json.dumps(metadata or {}),
                    miner_public_key,
                    cloud_credentials_enc,
                ),
            )

    def update_miner(
        self,
        miner_id: Union[str, UUID],
        *,
        name: Optional[str] = None,
        current_ip: Optional[str] = None,
        status: Optional[str] = None,
        secret_hash: Optional[str] = None,
        secret_plaintext: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        last_seen: Optional[datetime] = None,
        miner_public_key: Optional[bytes] = None,
        cloud_credentials_enc: Optional[bytes] = None,
    ) -> None:
        """Update miner fields. Only provided fields are modified.

        Args:
            miner_id: UUID of the miner to update
            name: New display name
            current_ip: New public IP
            status: New status (active/revoked)
            secret_hash: New secret hash
            secret_plaintext: New plaintext secret
            metadata: New metadata
            last_seen: Last heartbeat timestamp
            miner_public_key: New X25519 public key
            cloud_credentials_enc: New encrypted credentials
        """
        updates = []
        params: List[Any] = []

        if name is not None:
            updates.append("name = %s")
            params.append(name)
        if current_ip is not None:
            updates.append("current_ip = %s")
            params.append(current_ip)
        if status is not None:
            updates.append("status = %s")
            params.append(status)
        if secret_hash is not None:
            updates.append("secret_hash = %s")
            params.append(secret_hash)
        if secret_plaintext is not None:
            updates.append("secret_plaintext = %s")
            params.append(secret_plaintext)
        if metadata is not None:
            updates.append("metadata = %s::jsonb")
            params.append(json.dumps(metadata))
        if last_seen is not None:
            updates.append("last_seen = %s")
            params.append(last_seen)
        if miner_public_key is not None:
            updates.append("miner_public_key = %s")
            params.append(miner_public_key)
        if cloud_credentials_enc is not None:
            updates.append("cloud_credentials_enc = %s")
            params.append(cloud_credentials_enc)

        if not updates:
            return

        updates.append("updated_at = NOW()")
        params.append(str(miner_id))

        sql = f"""
            UPDATE tensorprox_miners
            SET {', '.join(updates)}
            WHERE miner_id = %s;
        """
        with self.connection() as db:
            db.execute(sql, tuple(params))

    def update_credentials(
        self,
        miner_id: Union[str, UUID],
        *,
        miner_public_key: bytes,
        cloud_credentials_enc: bytes,
    ) -> None:
        """Update miner's public key and encrypted credentials."""
        with self.connection() as db:
            db.execute(
                """
                UPDATE tensorprox_miners
                SET miner_public_key = %s,
                    cloud_credentials_enc = %s,
                    updated_at = NOW()
                WHERE miner_id = %s;
                """,
                (miner_public_key, cloud_credentials_enc, str(miner_id)),
            )

    def get_miner(self, miner_id: Union[str, UUID]) -> Optional[Dict[str, Any]]:
        with self.connection() as db:
            row = db.query_one(
                "SELECT * FROM tensorprox_miners WHERE miner_id = %s;",
                (str(miner_id),),
            )
        return self._serialize(row)

    def list_miners(self) -> List[Dict[str, Any]]:
        with self.connection() as db:
            rows = db.query_all(
                """
                SELECT *
                FROM tensorprox_miners
                ORDER BY created_at DESC;
                """
            )
        return [self._serialize(row) for row in rows]

    def _serialize(self, row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not row:
            return None
        record = dict(row)
        record["miner_id"] = str(record["miner_id"])

        for ts_key in ("created_at", "updated_at", "last_seen"):
            value = record.get(ts_key)
            if isinstance(value, datetime):
                record[ts_key] = value.isoformat()

        metadata = record.get("metadata")
        if isinstance(metadata, str):
            try:
                record["metadata"] = json.loads(metadata)
            except json.JSONDecodeError:
                logger.warning("Invalid metadata for miner %s", record["miner_id"])
                record["metadata"] = {}
        elif metadata is None:
            record["metadata"] = {}

        # Handle BYTEA columns (psycopg2 returns memoryview, not JSON serializable)
        for bytea_key in ("miner_public_key", "cloud_credentials_enc"):
            value = record.get(bytea_key)
            if value is not None and isinstance(value, (bytes, memoryview)):
                record[bytea_key] = base64.b64encode(bytes(value)).decode("ascii")

        return record
