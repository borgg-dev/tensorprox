"""Client and origin assignment service."""
from __future__ import annotations

from typing import Optional, Tuple

from shared.utils.logging import get_logger

from tensorprox.tpm.repositories.client_repository import ClientRepository
from tensorprox.tpm.repositories.origin_repository import OriginRepository


logger = get_logger(__name__)


class ClientRegistry:
    """Central authority for client + origin identifiers."""

    def __init__(self):
        self.clients = ClientRepository()
        self.origins = OriginRepository()

    def assign_client_and_origin(
        self,
        client_id: Optional[str],
        client_name: Optional[str],
        origin_id: Optional[str]
    ) -> Tuple[str, str, Optional[int]]:
        """Ensure client exists and reserve an origin ID."""
        resolved_client_id = client_id

        if resolved_client_id:
            self.clients.ensure_client(resolved_client_id, client_name)
        else:
            # Prefer existing client by name to avoid duplicating origin namespaces.
            if client_name:
                existing = self.clients.find_by_name(client_name)
                if existing and existing.get("client_id"):
                    resolved_client_id = existing["client_id"]
                    logger.info("Reusing existing client_id=%s for name=%s", resolved_client_id, client_name)
            if not resolved_client_id:
                resolved_client_id = self.clients.create_client(client_name, auto_generated=True)
                logger.info("Created auto-generated client_id=%s", resolved_client_id)

        origin_row = self.origins.reserve_origin(resolved_client_id, origin_id)
        return resolved_client_id, origin_row["origin_id"], origin_row.get("origin_num")

    def mark_origin_active(self, client_id: str, origin_id: str) -> None:
        self.origins.update_status(client_id, origin_id, "active")

    def mark_origin_failed(self, client_id: str, origin_id: str) -> None:
        self.origins.update_status(client_id, origin_id, "failed")

    def mark_origin_terminated(self, client_id: str, origin_id: str) -> None:
        self.origins.release_origin(client_id, origin_id)

    def set_miner_assignment(
        self,
        client_id: str,
        origin_id: str,
        miner_id: Optional[str],
        miner_ip: Optional[str]
    ) -> None:
        self.origins.set_miner_assignment(client_id, origin_id, miner_id, miner_ip)
