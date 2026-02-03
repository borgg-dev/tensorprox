"""Automatic exit_hub purge sweeper.

Periodically scans for exit_hub records that have exceeded their purge_after
timestamp and permanently deletes them from the database.

This is the final cleanup step in the deferred deletion flow:
1. terminate/cancel marks exit_hub with purge_after = now + 1 hour
2. SSE notification is sent to webapp
3. After 1 hour, this sweeper deletes the record permanently
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

from shared.utils.logging import get_logger

from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository

logger = get_logger(__name__)


class PurgeSweeper:
    """Background service that deletes expired exit_hub records."""

    def __init__(
        self,
        repository: ExitHubRepository,
        interval_seconds: int = 300,  # 5 minutes
        enabled: bool = True,
    ):
        self.repository = repository
        self.interval = interval_seconds
        self.enabled = enabled
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the background sweeper thread."""
        if not self.enabled:
            logger.info("Purge sweeper disabled")
            return
        if self._thread and self._thread.is_alive():
            logger.warning("Purge sweeper already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="purge-sweeper",
            daemon=True,
        )
        self._thread.start()
        logger.info("Purge sweeper started (interval=%ds)", self.interval)

    def stop(self) -> None:
        """Stop the background sweeper thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Purge sweeper stopped")

    def sweep_now(self) -> Dict[str, any]:
        """Run a sweep immediately. Returns summary of actions taken."""
        return self._sweep()

    def _run_loop(self) -> None:
        """Main loop that runs sweeps periodically."""
        while not self._stop_event.is_set():
            try:
                self._sweep()
            except Exception as exc:
                logger.error("Purge sweeper error: %s", exc, exc_info=True)
            self._stop_event.wait(timeout=self.interval)

    def _sweep(self) -> Dict[str, any]:
        """Find and delete expired exit_hub records."""
        logger.debug("Purge sweeper: starting scan")

        try:
            purgeable = self.repository.get_purgeable_exit_hubs()
        except Exception as exc:
            logger.error("Purge sweeper: database query failed: %s", exc)
            return {"scanned": 0, "purged": 0, "errors": 1}

        if not purgeable:
            logger.debug("Purge sweeper: no expired exit_hubs found")
            return {"scanned": 0, "purged": 0, "errors": 0}

        purged = []
        errors = 0

        for record in purgeable:
            exit_hub_id = str(record["exit_hub_id"])
            origin_id = record.get("origin_id")
            status = record.get("status")

            try:
                self.repository.delete_exit_hub(exit_hub_id)
                purged.append(exit_hub_id)
                logger.info(
                    "Purge sweeper: deleted exit_hub %s (origin=%s, status=%s)",
                    exit_hub_id, origin_id, status
                )
            except Exception as exc:
                logger.error(
                    "Purge sweeper: failed to delete %s: %s",
                    exit_hub_id, exc
                )
                errors += 1

        logger.info(
            "Purge sweeper: found=%d, purged=%d, errors=%d",
            len(purgeable), len(purged), errors
        )
        return {
            "scanned": len(purgeable),
            "purged": len(purged),
            "purged_ids": purged,
            "errors": errors,
        }


# Singleton for use by the application
_sweeper: Optional[PurgeSweeper] = None


def get_purge_sweeper() -> PurgeSweeper:
    """Get or create the singleton purge sweeper."""
    global _sweeper
    if _sweeper is None:
        _sweeper = PurgeSweeper(
            repository=ExitHubRepository(),
            interval_seconds=300,  # 5 minutes
        )
    return _sweeper


def start_purge_sweeper() -> None:
    """Start the purge sweeper background service."""
    get_purge_sweeper().start()


def purge_expired_now() -> Dict[str, any]:
    """Run an immediate purge sweep. Returns summary."""
    return get_purge_sweeper().sweep_now()
