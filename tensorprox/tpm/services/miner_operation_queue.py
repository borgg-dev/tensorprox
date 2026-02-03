"""Per-miner FIFO operation queue with DB persistence.

Serializes miner operations to prevent concurrent long-running operations
from overwhelming miners. Each miner processes one operation at a time.

Operations:
    - deploy_shard: Creates scrubber infrastructure (~5-7 min)
    - register_origin: Registers origin with miner (~30-60s)
    - delete_origin: Removes origin from miner (~30-60s)

Notifications:
    The queue emits SSE notifications at key state transitions:
    - queued: Operation submitted, includes queue_position
    - processing: Operation started executing
    - succeeded/failed: Operation completed

Usage:
    queue = get_miner_operation_queue()

    # Submit operation
    op = queue.submit(
        miner_id='...',
        operation_type='deploy_shard',
        payload={'region': 'us-east-1'},
        exit_hub_id='...',
    )

    # Wait for completion
    result = queue.wait_for_completion(op.operation_id, timeout=600)
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional
from uuid import UUID

from shared.utils.logging import get_logger
from tensorprox.tpm.repositories.miner_operation_repository import (
    MinerOperation,
    MinerOperationRepository,
)
from tensorprox.tpm.services.operation_tracker import get_operation_tracker

# Structured error types for exception preservation through queue
STRUCTURED_ERROR_TYPES = {
    "ShardNotReadyError",
    "ShardNotFoundError",
    "CapacityExhaustedError",
}

logger = get_logger(__name__)


@dataclass
class OperationContext:
    """Context for SSE notifications."""
    exit_hub_id: str | None = None
    origin_id: str | None = None
    client_id: str | None = None
    miner_id: str | None = None
    miner_ip: str | None = None


class MinerOperationQueue:
    """Per-miner FIFO queue with DB persistence and lazy workers."""

    def __init__(
        self,
        poll_interval: float = 1.0,
        idle_timeout: float = 300.0,
    ):
        """Initialize the queue.

        Args:
            poll_interval: Seconds between queue polls per worker
            idle_timeout: Seconds of idle before worker thread exits
        """
        self._repo = MinerOperationRepository()
        self._poll_interval = poll_interval
        self._idle_timeout = idle_timeout

        # Per-miner worker threads (lazy-started)
        self._workers: Dict[str, threading.Thread] = {}
        self._worker_lock = threading.Lock()

        # Shutdown flag
        self._shutdown = threading.Event()

        # Condition variables for waiting on operation completion
        self._completion_conditions: Dict[str, threading.Condition] = {}
        self._completion_lock = threading.Lock()

        # Operation executors (registered by integration code)
        self._executors: Dict[str, Callable[[MinerOperation], Dict[str, Any]]] = {}

        # SSE notifier (set via set_notifier)
        self._notifier: Any = None

        # Operation context for notifications (operation_id -> OperationContext)
        self._operation_contexts: Dict[str, OperationContext] = {}
        self._context_lock = threading.Lock()

        # Track last emitted queue position to avoid duplicate notifications
        self._last_emitted_positions: Dict[str, int] = {}
        self._positions_lock = threading.Lock()

    def set_notifier(self, notifier: Any) -> None:
        """Set the notifier for SSE events.

        Args:
            notifier: ExitHubNotifier instance with exit_hub_state_changed method
        """
        self._notifier = notifier
        logger.info("Miner operation queue: SSE notifier configured")

    def register_executor(
        self,
        operation_type: str,
        executor: Callable[[MinerOperation], Dict[str, Any]],
    ) -> None:
        """Register an executor function for an operation type.

        The executor is called when an operation of this type is claimed.
        It should perform the actual work and return a result dict.

        Args:
            operation_type: One of 'deploy_shard', 'register_origin', 'delete_origin'
            executor: Function that takes MinerOperation and returns result dict
        """
        self._executors[operation_type] = executor
        logger.info("Registered executor for operation type: %s", operation_type)

    def get_operation_context(self, operation_id: str) -> Optional[OperationContext]:
        """Get the context for an operation.

        Used by executors to access exit_hub_id, client_id, etc. for SSE notifications.

        Args:
            operation_id: UUID of the operation

        Returns:
            OperationContext or None if not found
        """
        with self._context_lock:
            return self._operation_contexts.get(operation_id)

    def submit(
        self,
        miner_id: str,
        operation_type: str,
        payload: Dict[str, Any],
        exit_hub_id: Optional[str] = None,
        origin_id: Optional[str] = None,
        shard_id: Optional[str] = None,
        priority: int = 100,
        context: Optional[OperationContext] = None,
    ) -> MinerOperation:
        """Submit an operation to the queue.

        The operation is persisted to the database and a worker is
        started for the miner if not already running.

        Args:
            miner_id: UUID of the target miner
            operation_type: One of 'deploy_shard', 'register_origin', 'delete_origin'
            payload: Operation-specific data
            exit_hub_id: Optional exit hub UUID for tracing and cancel
            origin_id: Optional origin ID for tracing
            shard_id: Optional shard ID for tracing
            priority: Priority (lower = higher priority), default 100
            context: Optional context for SSE notifications (client_id, miner_ip, etc.)

        Returns:
            Created MinerOperation with status='queued'
        """
        op = self._repo.create(
            miner_id=miner_id,
            operation_type=operation_type,
            payload=payload,
            exit_hub_id=exit_hub_id,
            origin_id=origin_id,
            shard_id=shard_id,
            priority=priority,
        )

        # Create completion condition for this operation
        with self._completion_lock:
            self._completion_conditions[str(op.operation_id)] = threading.Condition()

        # Store context for notifications
        if context or exit_hub_id:
            ctx = context or OperationContext()
            ctx.exit_hub_id = ctx.exit_hub_id or exit_hub_id
            ctx.origin_id = ctx.origin_id or origin_id
            ctx.miner_id = ctx.miner_id or miner_id
            with self._context_lock:
                self._operation_contexts[str(op.operation_id)] = ctx

        # Ensure worker exists for this miner
        self._ensure_worker(miner_id)

        # Calculate queue position (includes this op + any processing/queued ahead)
        queue_depth = self._repo.get_queue_depth(miner_id)

        # Check if miner was busy BEFORE this submission (queue_depth > 1 means others ahead)
        # queue_depth=1 means only this op, miner is idle → will process immediately
        # queue_depth>1 means there are ops ahead → must wait
        miner_was_busy = queue_depth > 1

        logger.info(
            "Submitted operation %s: type=%s miner=%s exit_hub=%s queue_position=%d busy=%s",
            op.operation_id,
            operation_type,
            miner_id,
            exit_hub_id,
            queue_depth,
            miner_was_busy,
        )

        # Send SSE notification based on whether miner is busy
        if miner_was_busy:
            # Miner busy - show queue position via unified tracker
            ctx = context or OperationContext()
            get_operation_tracker().track(
                exit_hub_id=ctx.exit_hub_id or exit_hub_id or "",
                status="queued_for_miner",
                client_id=ctx.client_id,
                origin_id=ctx.origin_id or origin_id,
                miner_id=ctx.miner_id or miner_id,
                miner_ip=ctx.miner_ip,
                queue_position=queue_depth,
                metadata={"operation_type": operation_type},
            )
        else:
            # Miner idle - will process immediately, skip "queued" notification
            # Worker will emit "processing" status when it picks this up
            logger.debug(
                "Miner idle, operation %s will process immediately",
                op.operation_id,
            )

        return op

    def wait_for_completion(
        self,
        operation_id: str,
        timeout: float = 600.0,
    ) -> MinerOperation:
        """Wait for an operation to complete.

        Blocks until the operation reaches a terminal state (succeeded,
        failed, cancelled) or the timeout expires.

        IMPORTANT: Timeout is calculated from when processing STARTS, not
        from when the operation was queued. This ensures queued operations
        get their full timeout for actual execution.

        Args:
            operation_id: UUID of the operation
            timeout: Maximum seconds to wait (from processing start)

        Returns:
            MinerOperation in terminal state

        Raises:
            TimeoutError: If timeout expires before completion
        """
        op_id_str = str(operation_id)
        processing_deadline: float | None = None  # Set when processing starts

        while True:
            # Check current state
            op = self._repo.get_by_id(op_id_str)
            if not op:
                raise ValueError(f"Operation {op_id_str} not found")

            if op.status in ("succeeded", "failed", "cancelled"):
                # Cleanup condition
                with self._completion_lock:
                    self._completion_conditions.pop(op_id_str, None)
                return op

            # Set deadline from when processing actually starts
            if op.status == "processing" and processing_deadline is None:
                processing_deadline = time.time() + timeout
                logger.debug(
                    "Operation %s started processing, deadline set to %ss from now",
                    op_id_str,
                    timeout,
                )

            # Check timeout only if processing has started
            if processing_deadline is not None:
                remaining = processing_deadline - time.time()
                if remaining <= 0:
                    raise TimeoutError(
                        f"Operation {op_id_str} did not complete within {timeout}s "
                        f"of processing start"
                    )
            else:
                remaining = timeout  # Use full timeout for poll interval while queued

            # Wait for notification or poll timeout
            with self._completion_lock:
                condition = self._completion_conditions.get(op_id_str)
            if condition:
                with condition:
                    condition.wait(timeout=min(remaining, self._poll_interval))
            else:
                time.sleep(min(remaining, self._poll_interval))

    def cancel_by_exit_hub(self, exit_hub_id: str) -> int:
        """Cancel all queued operations for an exit hub.

        Args:
            exit_hub_id: UUID of the exit hub

        Returns:
            Number of operations cancelled
        """
        count = self._repo.cancel_by_exit_hub(exit_hub_id)
        if count:
            logger.info(
                "Cancelled %d queued operations for exit_hub %s",
                count,
                exit_hub_id,
            )
        return count

    def get_queue_position(self, miner_id: str, operation_id: str) -> int:
        """Get position of operation in miner's queue.

        Args:
            miner_id: UUID of the miner
            operation_id: UUID of the operation

        Returns:
            Position (1-based), or 0 if not in queue
        """
        return self._repo.get_queue_position(miner_id, operation_id)

    def get_queue_depth(self, miner_id: str) -> int:
        """Get number of queued operations for a miner.

        Args:
            miner_id: UUID of the miner

        Returns:
            Number of queued operations
        """
        return self._repo.get_queue_depth(miner_id)

    def recover_on_startup(self, max_age_seconds: int = 3600) -> int:
        """Recover orphaned operations on startup.

        Marks operations that were processing when TPM crashed as failed.

        Args:
            max_age_seconds: Maximum age for processing operations

        Returns:
            Number of operations recovered
        """
        count = self._repo.recover_orphaned(max_age_seconds)
        if count:
            logger.warning("Recovered %d orphaned operations on startup", count)
        return count

    def shutdown(self, timeout: float = 10.0) -> None:
        """Gracefully shutdown all worker threads.

        Args:
            timeout: Maximum seconds to wait for each worker
        """
        logger.info("Shutting down miner operation queue...")
        self._shutdown.set()

        with self._worker_lock:
            workers = list(self._workers.values())

        for worker in workers:
            worker.join(timeout=timeout)
            if worker.is_alive():
                logger.warning("Worker %s did not shutdown cleanly", worker.name)

        logger.info("Miner operation queue shutdown complete")

    def _ensure_worker(self, miner_id: str) -> None:
        """Ensure a worker thread exists for a miner.

        Workers are lazy-started and auto-exit after idle timeout.
        """
        with self._worker_lock:
            existing = self._workers.get(miner_id)
            if existing and existing.is_alive():
                return

            thread = threading.Thread(
                target=self._worker_loop,
                args=(miner_id,),
                name=f"miner-op-worker-{miner_id[:8]}",
                daemon=True,
            )
            thread.start()
            self._workers[miner_id] = thread
            logger.info("Started worker thread for miner %s", miner_id)

    def _worker_loop(self, miner_id: str) -> None:
        """Process FIFO queue for one miner.

        Runs until shutdown or idle timeout.
        """
        last_activity = time.time()

        while not self._shutdown.is_set():
            # Try to claim next operation
            op = self._repo.claim_next(miner_id)

            if not op:
                # No work - check idle timeout
                if time.time() - last_activity > self._idle_timeout:
                    logger.debug(
                        "Worker for miner %s exiting due to idle timeout",
                        miner_id,
                    )
                    break
                time.sleep(self._poll_interval)
                continue

            last_activity = time.time()
            op_id_str = str(op.operation_id)

            # Skip if cancelled while waiting
            if op.status == "cancelled":
                self._notify_completion(op_id_str)
                continue

            # Notify: processing started via unified tracker
            logger.info(
                "Executing operation %s: type=%s miner=%s",
                op.operation_id,
                op.operation_type,
                miner_id,
            )
            ctx = self._operation_contexts.get(op_id_str)
            if ctx and ctx.exit_hub_id:
                get_operation_tracker().track(
                    exit_hub_id=ctx.exit_hub_id,
                    status=_status_for_operation(op.operation_type),
                    client_id=ctx.client_id,
                    origin_id=ctx.origin_id,
                    miner_id=ctx.miner_id,
                    miner_ip=ctx.miner_ip,
                    metadata={"operation_type": op.operation_type},
                )

            try:
                result = self._execute_operation(op)
                self._repo.complete(op_id_str, result)
                logger.info(
                    "Operation %s succeeded",
                    op.operation_id,
                )

                # After successful delete_origin, check if shard needs sweeping
                if op.operation_type == "delete_origin" and op.shard_id:
                    self._check_shard_for_sweep(op.miner_id, op.shard_id)
            except Exception as exc:
                # Serialize structured exceptions for re-raising by caller
                exc_type = type(exc).__name__
                if exc_type in STRUCTURED_ERROR_TYPES:
                    error_data = {
                        "_structured": True,
                        "type": exc_type,
                        "message": str(exc),
                    }
                    # Preserve exception-specific attributes
                    if hasattr(exc, "shard_id"):
                        error_data["shard_id"] = exc.shard_id
                    if hasattr(exc, "job_id"):
                        error_data["job_id"] = exc.job_id
                    if hasattr(exc, "hard_capacity"):
                        error_data["hard_capacity"] = exc.hard_capacity
                    error_msg = json.dumps(error_data)
                else:
                    error_msg = str(exc)

                self._repo.fail(op_id_str, error_msg)
                logger.error(
                    "Operation %s failed: %s",
                    op.operation_id,
                    error_msg,
                    exc_info=True,
                )

            self._notify_completion(op_id_str)
            # Position updates handled by OperationTracker deduplication

        # Cleanup worker reference
        with self._worker_lock:
            self._workers.pop(miner_id, None)

    def _check_shard_for_sweep(self, miner_id: str, shard_id: str) -> None:
        """Check if shard is now empty and schedule sweep if needed.

        Note: Only PRODUCTION shards are swept. Audit shards are excluded
        to ensure they remain always active for validator scoring.
        """
        try:
            from tensorprox.tpm.repositories.shard_repository import ShardRepository
            shard_repo = ShardRepository()

            # Decrement and get new count
            new_count = shard_repo.decrement_origin_count(UUID(miner_id), shard_id)

            if new_count == 0:
                # schedule_sweep only affects production shards (audit shards excluded)
                shard_repo.schedule_sweep(UUID(miner_id), shard_id, grace_minutes=10)
                logger.info(
                    "Shard %s empty after origin deletion, sweep scheduled in 10 minutes "
                    "(production shards only, audit shards excluded)",
                    shard_id
                )
        except Exception as exc:
            logger.warning("Failed to check shard for sweep: %s", exc)

    def _execute_operation(self, op: MinerOperation) -> Dict[str, Any]:
        """Execute an operation using the registered executor.

        Args:
            op: The operation to execute

        Returns:
            Result dict from executor

        Raises:
            RuntimeError: If no executor registered for operation type
        """
        executor = self._executors.get(op.operation_type)
        if not executor:
            raise RuntimeError(
                f"No executor registered for operation type: {op.operation_type}"
            )
        return executor(op)

    def _notify_completion(self, operation_id: str) -> None:
        """Notify waiters that an operation completed."""
        with self._completion_lock:
            condition = self._completion_conditions.get(operation_id)
        if condition:
            with condition:
                condition.notify_all()
        # Cleanup context
        with self._context_lock:
            self._operation_contexts.pop(operation_id, None)
        # Cleanup position tracking
        with self._positions_lock:
            self._last_emitted_positions.pop(operation_id, None)

def _status_for_operation(operation_type: str) -> str:
    """Map operation type to exit hub status."""
    return {
        "deploy_shard": "deploying_scrubbers",
        "register_origin": "registering_origin",
        "delete_origin": "miner_cleanup",
    }.get(operation_type, "miner_processing")


# Singleton instance
_queue: Optional[MinerOperationQueue] = None
_init_lock = threading.Lock()


def get_miner_operation_queue() -> MinerOperationQueue:
    """Get or create the singleton miner operation queue."""
    global _queue

    if _queue is None:
        with _init_lock:
            if _queue is None:
                _queue = MinerOperationQueue()

    return _queue
