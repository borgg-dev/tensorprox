"""Shard sweeper service - cleans up empty shards after grace period.

Monitors shards that became empty after origin deletions. If no new origins
deploy to the shard within the grace period (10 minutes), the shard is
deleted from the miner to free resources.

The grace period is restart-persistent (stored in DB), so pending sweeps
survive TPM restarts.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

import requests

from shared.utils.logging import get_logger
from tensorprox.tpm.repositories.shard_repository import ShardRepository
from tensorprox.tpm.repositories.system_error_repository import SystemErrorRepository
from tensorprox.tpm.services.miner_registry import MinerRegistry

logger = get_logger(__name__)

# Singleton for system error logging
_error_repo: SystemErrorRepository | None = None


def _get_error_repo() -> SystemErrorRepository:
    """Get or create singleton SystemErrorRepository."""
    global _error_repo
    if _error_repo is None:
        _error_repo = SystemErrorRepository()
    return _error_repo

SWEEP_INTERVAL_SECONDS = 60  # Check every minute
GRACE_PERIOD_MINUTES = 10    # Wait 10 minutes before sweep
STALE_SHARD_THRESHOLD_MINUTES = 30  # Shards stuck in 'deploying' for 30+ minutes are stale
DEFAULT_MINER_PORT = 8000    # Default miner control plane port


class ShardSweeper:
    """Background service that sweeps empty shards after grace period."""

    def __init__(
        self,
        shard_repository: ShardRepository,
        miner_registry: MinerRegistry,
        interval_seconds: int = SWEEP_INTERVAL_SECONDS,
        enabled: bool = True,
    ):
        self.shard_repo = shard_repository
        self.miner_registry = miner_registry
        self.interval = interval_seconds
        self.enabled = enabled
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the background sweeper thread."""
        if not self.enabled:
            logger.info("Shard sweeper disabled")
            return
        if self._thread and self._thread.is_alive():
            logger.warning("Shard sweeper already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="shard-sweeper",
            daemon=True,
        )
        self._thread.start()
        logger.info("Shard sweeper started (interval=%ds)", self.interval)

    def stop(self) -> None:
        """Stop the background sweeper thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Shard sweeper stopped")

    def sweep_now(self) -> Dict[str, Any]:
        """Run a sweep immediately. Returns summary of actions taken."""
        return self._sweep()

    def _run_loop(self) -> None:
        """Main loop that runs sweeps periodically."""
        while not self._stop_event.is_set():
            try:
                self._sweep()
                self._clean_stale_shards()
            except Exception as exc:
                logger.error("Shard sweeper error: %s", exc, exc_info=True)
            self._stop_event.wait(timeout=self.interval)

    def _sweep(self) -> Dict[str, Any]:
        """Find and delete empty PRODUCTION shards with expired grace period.

        Note: Audit shards are NEVER swept - they must remain active for validator scoring.
        """
        sweepable = self.shard_repo.get_sweepable_shards()
        if not sweepable:
            return {"checked": 0, "deleted": 0, "skipped": 0}

        logger.info(
            "Shard sweeper: found %d PRODUCTION shards ready for sweep (audit shards excluded)",
            len(sweepable)
        )

        deleted = []
        skipped = []

        for shard in sweepable:
            miner_id = shard["miner_id"]
            shard_id = shard["shard_id"]
            region = shard["region"]

            try:
                # Verify shard is still empty on miner before deleting
                if not self._verify_shard_empty(miner_id, shard_id):
                    logger.info(
                        "Shard %s on miner %s has origins, skipping sweep",
                        shard_id, miner_id
                    )
                    # Cancel the sweep, shard is not empty
                    self.shard_repo.cancel_sweep(UUID(str(miner_id)), shard_id)
                    skipped.append(shard_id)
                    continue

                # Delete shard from miner
                success = self._delete_shard_on_miner(miner_id, shard_id)
                if success:
                    # Hard delete from TPM database (no orphans)
                    self.shard_repo.delete_shard(UUID(str(miner_id)), shard_id)
                    deleted.append(shard_id)
                    logger.info(
                        "Shard sweeper: deleted shard %s from miner %s and TPM (region=%s)",
                        shard_id, miner_id, region
                    )
                else:
                    skipped.append(shard_id)

            except Exception as exc:
                logger.error(
                    "Shard sweeper: failed to sweep %s on miner %s: %s",
                    shard_id, miner_id, exc
                )
                skipped.append(shard_id)

        return {
            "checked": len(sweepable),
            "deleted": len(deleted),
            "skipped": len(skipped),
            "deleted_shards": deleted,
        }

    def _clean_stale_shards(self) -> Dict[str, Any]:
        """Clean up shards stuck in 'deploying' status with no nodes.

        These are shards where node deployment failed but the shard record
        persists in TPM database, causing validators to select broken shards.
        """
        stale_shards = self.shard_repo.get_stale_deploying_shards(
            threshold_minutes=STALE_SHARD_THRESHOLD_MINUTES
        )

        if not stale_shards:
            return {"checked": 0, "cleaned": 0, "skipped": 0}

        logger.info("Shard sweeper: found %d stale deploying shards", len(stale_shards))

        cleaned = []
        skipped = []

        for shard in stale_shards:
            miner_id = shard["miner_id"]
            shard_id = shard["shard_id"]

            try:
                # Verify shard actually has no nodes (is broken)
                miner_ip, miner_port = self._get_miner_connection_info(miner_id)
                secret = self.miner_registry.get_plaintext_secret(miner_id)

                response = requests.get(
                    f"http://{miner_ip}:{miner_port}/api/v1/admin/shards/{shard_id}",
                    headers={"Authorization": f"Bearer {secret}"},
                    timeout=30,
                )

                # If shard doesn't exist on miner (404), delete from TPM
                if response.status_code == 404:
                    self.shard_repo.delete_shard(UUID(str(miner_id)), shard_id)
                    cleaned.append(shard_id)
                    logger.info(
                        "Stale shard cleanup: deleted shard %s (404 on miner %s)",
                        shard_id, miner_id
                    )
                    continue

                # If shard exists, check if it has nodes
                if response.status_code == 200:
                    data = response.json()
                    nodes = data.get("nodes", [])
                    if not nodes or not any(n.get("ready") for n in nodes):
                        # Shard exists but has no ready nodes - mark as failed in TPM
                        self.shard_repo.mark_shard_as_failed(UUID(str(miner_id)), shard_id)
                        cleaned.append(shard_id)
                        logger.info(
                            "Stale shard cleanup: marked shard %s as failed (no ready nodes)",
                            shard_id
                        )
                    else:
                        # Shard has nodes, update status to active
                        self.shard_repo.update_shard_status(
                            UUID(str(miner_id)), shard_id, "active"
                        )
                        logger.info(
                            "Stale shard cleanup: recovered shard %s (has %d nodes)",
                            shard_id, len(nodes)
                        )
                        skipped.append(shard_id)
                else:
                    logger.warning(
                        "Stale shard cleanup: unexpected HTTP %d for shard %s",
                        response.status_code, shard_id
                    )
                    skipped.append(shard_id)

            except Exception as exc:
                logger.error(
                    "Stale shard cleanup: failed to check shard %s: %s",
                    shard_id, exc
                )
                skipped.append(shard_id)

        return {
            "checked": len(stale_shards),
            "cleaned": len(cleaned),
            "skipped": len(skipped),
            "cleaned_shards": cleaned,
        }

    def _get_miner_connection_info(self, miner_id: str) -> tuple[str, int]:
        """Extract connection IP and port from miner registry.

        Returns:
            Tuple of (ip_address, port)
        """
        miner = self.miner_registry.get_miner(miner_id)
        if not miner:
            return self.miner_registry.get_miner_ip(miner_id) or "127.0.0.1", DEFAULT_MINER_PORT

        metadata = miner.get("metadata") or {}
        ip = metadata.get("emn_ip") or miner.get("current_ip") or "127.0.0.1"
        port = metadata.get("emn_port") or DEFAULT_MINER_PORT
        return str(ip), int(port)

    def _verify_shard_empty(self, miner_id: str, shard_id: str) -> bool:
        """Query miner to verify shard has no origins."""
        try:
            miner_ip, miner_port = self._get_miner_connection_info(miner_id)
            secret = self.miner_registry.get_plaintext_secret(miner_id)

            # GET /api/v1/admin/shards/{shard_id}
            response = requests.get(
                f"http://{miner_ip}:{miner_port}/api/v1/admin/shards/{shard_id}",
                headers={"Authorization": f"Bearer {secret}"},
                timeout=30,
            )

            if response.status_code == 404:
                # Shard already gone on miner, proceed to delete from TPM
                return True

            if response.status_code != 200:
                logger.warning(
                    "Shard verification failed for %s: HTTP %d",
                    shard_id, response.status_code
                )
                _get_error_repo().log_error(
                    error_source="shard_sweeper",
                    error_code="verify_failed",
                    error_message=f"Miner returned HTTP {response.status_code} during shard verification",
                    miner_id=UUID(str(miner_id)),
                    context={
                        "shard_id": shard_id,
                        "http_status": response.status_code,
                        "response_body": response.text[:500] if response.text else None,
                    },
                )
                return False

            data = response.json()
            origins_count = data.get("origins_count", 0)
            return origins_count == 0

        except Exception as exc:
            logger.error("Failed to verify shard %s: %s", shard_id, exc)
            _get_error_repo().log_error(
                error_source="shard_sweeper",
                error_code="verify_exception",
                error_message=f"Exception during shard verification: {exc}",
                miner_id=UUID(str(miner_id)),
                context={
                    "shard_id": shard_id,
                    "exception_type": type(exc).__name__,
                },
            )
            return False  # Don't delete if we can't verify

    def _delete_shard_on_miner(self, miner_id: str, shard_id: str) -> bool:
        """Delete shard from miner via API."""
        try:
            miner_ip, miner_port = self._get_miner_connection_info(miner_id)
            secret = self.miner_registry.get_plaintext_secret(miner_id)

            # DELETE /api/v1/admin/shards/{shard_id}
            response = requests.delete(
                f"http://{miner_ip}:{miner_port}/api/v1/admin/shards/{shard_id}",
                headers={"Authorization": f"Bearer {secret}"},
                timeout=60,
            )

            if response.status_code in (200, 204, 404):
                return True  # 404 = already gone, that's fine

            logger.warning(
                "Failed to delete shard %s on miner %s: HTTP %d - %s",
                shard_id, miner_id, response.status_code, response.text
            )
            _get_error_repo().log_error(
                error_source="shard_sweeper",
                error_code="delete_failed",
                error_message=f"Miner returned HTTP {response.status_code} during shard deletion",
                miner_id=UUID(str(miner_id)),
                context={
                    "shard_id": shard_id,
                    "http_status": response.status_code,
                    "response_body": response.text[:500] if response.text else None,
                },
            )
            return False

        except Exception as exc:
            logger.error("Failed to delete shard %s: %s", shard_id, exc)
            _get_error_repo().log_error(
                error_source="shard_sweeper",
                error_code="delete_exception",
                error_message=f"Exception during shard deletion: {exc}",
                miner_id=UUID(str(miner_id)),
                context={
                    "shard_id": shard_id,
                    "exception_type": type(exc).__name__,
                },
            )
            return False


# Singleton instance
_sweeper: Optional[ShardSweeper] = None


def get_shard_sweeper() -> ShardSweeper:
    """Get or create the singleton shard sweeper."""
    global _sweeper
    if _sweeper is None:
        from tensorprox.tpm.services.miner_registry import get_miner_registry

        _sweeper = ShardSweeper(
            shard_repository=ShardRepository(),
            miner_registry=get_miner_registry(),
        )
    return _sweeper


def start_shard_sweeper() -> None:
    """Start the shard sweeper background service."""
    get_shard_sweeper().start()
