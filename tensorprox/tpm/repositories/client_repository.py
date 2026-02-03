"""Client repository for TensorProx Management."""
from __future__ import annotations

from typing import Any, Dict, Optional

from shared.utils.logging import get_logger

from .base import BaseRepository

logger = get_logger(__name__)


class ClientRepository(BaseRepository):
    """Manages tensorprox_clients records."""

    def find_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Return client row by exact name."""
        with self.connection() as db:
            row = db.query_one(
                """
                SELECT client_id, name, auto_generated, next_origin_number
                FROM tensorprox_clients
                WHERE name = %s
                ORDER BY updated_at DESC, created_at DESC
                LIMIT 1;
                """,
                (name,),
            )
        return row

    def create_client(self, name: Optional[str] = None, auto_generated: bool = True) -> str:
        """Create a new client with an auto-generated ID."""
        with self.connection() as db:
            row = db.execute_returning_one(
                """
                INSERT INTO tensorprox_clients (client_id, name, auto_generated)
                VALUES (
                    CONCAT('C', LPAD(nextval('tensorprox_client_id_seq')::text, 4, '0')),
                    %s,
                    %s
                )
                RETURNING client_id;
                """,
                (name, auto_generated),
            )
        return row["client_id"]

    def ensure_client(self, client_id: str, name: Optional[str] = None) -> None:
        """Ensure a client row exists for the provided ID."""
        with self.connection() as db:
            db.execute(
                """
                INSERT INTO tensorprox_clients (client_id, name, auto_generated)
                VALUES (%s, %s, FALSE)
                ON CONFLICT (client_id) DO UPDATE
                SET name = COALESCE(EXCLUDED.name, tensorprox_clients.name),
                    updated_at = NOW();
                """,
                (client_id, name),
            )

    def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        with self.connection() as db:
            row = db.query_one(
                "SELECT * FROM tensorprox_clients WHERE client_id = %s;",
                (client_id,),
            )
        return row
