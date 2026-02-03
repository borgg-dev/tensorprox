"""Background Validation Queue.

PURPOSE:
    This module provides asynchronous execution of miner validation workflows.
    When a miner registers with credentials, we don't want to block the HTTP
    response waiting for AWS API calls. Instead, we queue the validation job
    and return immediately. Background workers process jobs and store results.

DESIGN:
    - Thread pool with configurable worker count (default: 2)
    - In-memory queue with max size (default: 100)
    - Fire-and-forget: caller doesn't wait for result
    - Graceful degradation: if queue full, job is dropped with warning

INTEGRATION:
    Called from miner_registry.py after successful registration:

        if cloud_credentials_enc:
            trigger_miner_validation(miner_id)

WORKER LOOP:
    Each worker thread:
    1. Blocks on queue.get() with 1s timeout (allows shutdown check)
    2. Calls orchestrator.run_{workflow}(miner_id)
    3. Orchestrator handles credential decryption, plugin dispatch, storage
    4. Worker catches and logs any exceptions (doesn't crash)

ADDING NEW WORKFLOWS:
    To dispatch a new workflow type:
    1. Add workflow name to ValidationJob.workflow
    2. Add dispatch case in _worker_loop():
        elif job.workflow == "verify_traffic":
            orchestrator.run_verify_traffic(job.miner_id, ...)
    3. Call: queue.enqueue(miner_id, workflow="verify_traffic")

CONFIGURATION:
    - worker_count: Number of background threads (default: 2)
    - max_queue_size: Maximum pending jobs before dropping (default: 100)
"""
from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from typing import Optional

from shared.utils.logging import get_logger

from tensorprox.tpm.repositories import SystemErrorRepository

from .orchestrator import get_orchestrator

# Module-level repository for system error logging
_system_error_repo = SystemErrorRepository()

logger = get_logger(__name__)


@dataclass
class ValidationJob:
    """A queued validation job."""

    miner_id: str
    workflow: str = "discover_regions"


class MinerValidationQueue:
    """Background worker pool for miner validation.

    Usage:
        queue = MinerValidationQueue(worker_count=2)
        queue.enqueue("miner-uuid", workflow="discover_regions")
    """

    def __init__(
        self,
        worker_count: int = 2,
        max_queue_size: int = 100,
    ):
        self._queue: queue.Queue[ValidationJob] = queue.Queue(maxsize=max_queue_size)
        self._shutdown = threading.Event()
        self._workers: list[threading.Thread] = []

        for idx in range(worker_count):
            thread = threading.Thread(
                target=self._worker_loop,
                name=f"validation-worker-{idx + 1}",
                daemon=True,
            )
            thread.start()
            self._workers.append(thread)
            logger.info("Started validation worker thread: %s", thread.name)

    def enqueue(
        self,
        miner_id: str,
        workflow: str = "discover_regions",
    ) -> bool:
        """Queue a validation job for async execution.

        Args:
            miner_id: UUID of the miner to validate
            workflow: Workflow to execute (default: discover_regions)

        Returns:
            True if queued successfully, False if queue is full
        """
        job = ValidationJob(miner_id=miner_id, workflow=workflow)

        try:
            self._queue.put_nowait(job)
            logger.debug(
                "Queued validation job: miner=%s workflow=%s",
                miner_id,
                workflow,
            )
            return True
        except queue.Full:
            logger.warning(
                "Validation queue full, dropping job: miner=%s workflow=%s",
                miner_id,
                workflow,
            )
            _system_error_repo.log_error(
                error_source="queue",
                error_code="validation_queue_full",
                error_message=f"Validation queue full, rejected job for miner {miner_id}",
                context={
                    "queue_type": "validation",
                    "miner_id": str(miner_id),
                    "queue_size": self._queue.qsize(),
                    "workflow": workflow,
                },
                miner_id=miner_id,
            )
            return False

    def _worker_loop(self) -> None:
        """Worker thread main loop."""
        orchestrator = get_orchestrator()

        while not self._shutdown.is_set():
            try:
                job = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                logger.debug("Processing validation job: miner=%s", job.miner_id)

                if job.workflow == "discover_regions":
                    orchestrator.run_discover_regions(job.miner_id)
                else:
                    logger.warning("Unknown validation workflow: %s", job.workflow)

            except Exception as exc:
                logger.error(
                    "Validation job failed: miner=%s workflow=%s error=%s",
                    job.miner_id,
                    job.workflow,
                    exc,
                    exc_info=True,
                )
            finally:
                self._queue.task_done()

    def shutdown(self, timeout: float = 5.0) -> None:
        """Gracefully shutdown worker threads."""
        logger.info("Shutting down validation queue...")
        self._shutdown.set()

        for worker in self._workers:
            worker.join(timeout=timeout)
            if worker.is_alive():
                logger.warning("Worker %s did not shutdown cleanly", worker.name)


_validation_queue: Optional[MinerValidationQueue] = None
_init_lock = threading.Lock()


def get_validation_queue() -> MinerValidationQueue:
    """Get or create the singleton validation queue."""
    global _validation_queue

    if _validation_queue is None:
        with _init_lock:
            if _validation_queue is None:
                _validation_queue = MinerValidationQueue()

    return _validation_queue


def trigger_miner_validation(miner_id: str) -> None:
    """Convenience function to enqueue validation for a miner.

    Called after successful miner registration.
    """
    validation_queue = get_validation_queue()
    validation_queue.enqueue(miner_id, workflow="discover_regions")
