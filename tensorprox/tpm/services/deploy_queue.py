"""Background worker pool that executes exit-hub deployments asynchronously."""
from __future__ import annotations

import queue
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Optional
from uuid import UUID

from shared.config import get_tp_management_settings
from shared.models import ExitHubDeployRequest
from shared.utils.logging import get_logger

from tensorprox.tpm.services.deployment_decision import (
    DeploymentTarget,
    MinerUnreachableError,
    NoCapacityError,
    select_deployment_target,
)
from tensorprox.tpm.services.geolocation import (
    infer_provider_from_region,
    get_default_region_for_provider,
    get_fallback_regions,
)
from tensorprox.tpm.services.operation_tracker import get_operation_tracker
from tensorprox.tpm.services.exithub_manager import exithub_manager
from tensorprox.tpm.services.system_bootstrap import ensure_miner_ready
from tensorprox.tpm.utils.miner_capability import (
    check_miner_capacity,
    deploy_scrubbers_and_wait,
    request_shard_deploy,
    wait_for_job,
)
from tensorprox.tpm.workflows.exit_hub_lifecycle import (
    CapacityExhaustedError,
    RegionCapacityExhaustedError,
    ShardNotFoundError,
    ShardNotReadyError,
)
from tensorprox.tpm.services.miner_operation_queue import (
    get_miner_operation_queue,
    OperationContext,
)
from tensorprox.tpm.repositories.miner_operation_repository import MinerOperation


logger = get_logger(__name__)


class DeployQueueFullError(Exception):
    """Raised when no more deploy jobs can be accepted."""


class CancelledException(Exception):
    """Raised when a job is cancelled mid-execution."""


@dataclass
class _DeployJob:
    exit_hub_id: UUID
    request: ExitHubDeployRequest
    origin_num: Optional[int]


class DeployWorkerPool:
    """Simple in-process worker pool bound to ExitHubManager."""

    def __init__(
        self,
        *,
        manager,
        worker_count: int,
        max_queue_size: int,
        job_timeout: int,
        auto_start_services: bool,
    ) -> None:
        self.manager = manager
        self.queue: queue.Queue[_DeployJob] = queue.Queue(maxsize=max_queue_size)
        self._job_timeout = job_timeout
        self._auto_start_services = auto_start_services
        self._cancelled_jobs: set[str] = set()
        self._cancel_lock = threading.Lock()
        # Per-miner tracking: miner_id -> list of (exit_hub_id, job) in queue order
        self._pending_per_miner: dict[str, list[tuple[str, _DeployJob]]] = {}
        self._pending_lock = threading.Lock()
        # Per-miner execution lock to serialize jobs to same miner
        self._miner_locks: dict[str, threading.Lock] = {}
        self._miner_locks_lock = threading.Lock()
        self._register_miner_operation_executors()
        self._start_workers(worker_count)

    def _register_miner_operation_executors(self) -> None:
        """Register executors for miner operations with the queue."""
        miner_queue = get_miner_operation_queue()

        def deploy_shard_executor(op: MinerOperation) -> dict:
            """Execute deploy_shard operation."""
            payload = op.payload
            ok, reason, shard_id = deploy_scrubbers_and_wait(
                miner_id=str(op.miner_id),
                miner_ip=payload["miner_ip"],
                registry=self.manager.miner_registry,
                min_nodes=payload.get("min_nodes", 2),
                region=payload.get("region"),
                shard_id=payload.get("shard_id"),
                shard_type=payload.get("shard_type", "production"),  # TPM creates production shards
                miner_port=payload.get("miner_port", 8000),
            )
            if not ok:
                raise RuntimeError(f"Shard deploy failed: {reason}")
            return {"ok": True, "reason": reason, "shard_id": shard_id}

        miner_queue.register_executor("deploy_shard", deploy_shard_executor)

        def register_origin_executor(op: MinerOperation) -> dict:
            """Execute register_origin operation."""
            import requests as req
            payload = op.payload
            miner_id = str(op.miner_id)
            emn_ip = payload["emn_ip"]
            emn_port = payload.get("emn_port", 8000)

            # Get auth headers
            secret = self.manager.miner_registry.get_plaintext_secret(miner_id)
            headers = {"Authorization": f"Bearer {secret}"}

            url = f"http://{emn_ip}:{emn_port}/api/v1/origins"
            body = {
                "origin_id": payload["origin_id"],
                "exit_hub_ip": payload["exit_hub_ip"],
                "origin_ip": payload["origin_ip"],
                "required_ports": payload.get("ports", [80, 443]),
                "shard_id": payload["shard_id"],
            }

            logger.info(
                "Registering origin %s with miner %s via queue",
                payload["origin_id"],
                miner_id,
            )
            resp = req.post(url, json=body, headers=headers, timeout=(5, 120))

            if resp.status_code >= 400:
                # Parse structured error response from miner
                error_body = {}
                try:
                    error_body = resp.json()
                except Exception:
                    pass

                error_code = error_body.get("code")
                error_message = error_body.get("error") or resp.text[:200] or "no body"
                error_shard_id = error_body.get("shard_id")

                # Raise specific exceptions for known error codes (fail-fast)
                if resp.status_code == 404 and error_code == "shard_not_found":
                    logger.warning(
                        "Miner returned shard_not_found for shard %s",
                        error_shard_id
                    )
                    raise ShardNotFoundError(error_message, shard_id=error_shard_id)

                if resp.status_code == 409:
                    if error_code == "shard_not_ready":
                        job_id = error_body.get("job_id")
                        logger.warning(
                            "Miner returned shard_not_ready for shard %s (job_id=%s)",
                            error_shard_id,
                            job_id
                        )
                        raise ShardNotReadyError(
                            error_message,
                            shard_id=error_shard_id,
                            job_id=job_id
                        )

                    if error_code == "capacity_exhausted":
                        hard_capacity = error_body.get("hard_capacity")
                        logger.warning(
                            "Miner returned capacity_exhausted for shard %s",
                            error_shard_id
                        )
                        raise CapacityExhaustedError(
                            error_message,
                            shard_id=error_shard_id,
                            hard_capacity=hard_capacity
                        )

                # Generic error for unknown codes
                raise RuntimeError(
                    f"Origin registration failed: HTTP {resp.status_code} - {error_message}"
                )

            return resp.json()

        miner_queue.register_executor("register_origin", register_origin_executor)

        def delete_origin_executor(op: MinerOperation) -> dict:
            """Execute delete_origin operation via async job with SSE progress.

            Miner returns 202 with job_id for async processing.
            We poll until the job completes, emitting SSE progress updates.
            """
            import requests as req
            import time

            payload = op.payload
            miner_id = str(op.miner_id)
            emn_ip = payload["emn_ip"]
            emn_port = payload.get("emn_port", 8000)
            origin_id = payload["origin_id"]
            op_id_str = str(op.operation_id)

            # Get auth headers
            secret = self.manager.miner_registry.get_plaintext_secret(miner_id)
            headers = {"Authorization": f"Bearer {secret}"}

            # Get context for SSE notifications
            ctx = miner_queue.get_operation_context(op_id_str)

            url = f"http://{emn_ip}:{emn_port}/api/v1/origins/{origin_id}"

            logger.info(
                "Submitting delete_origin for %s to miner %s",
                origin_id,
                miner_id,
            )
            resp = req.delete(url, headers=headers, timeout=(5, 30))

            if resp.status_code == 404:
                return {"status": "not_found"}

            # Handle async job response (202 Accepted)
            if resp.status_code == 202:
                try:
                    job_data = resp.json()
                    job_id = job_data.get("job_id")
                except Exception:
                    job_id = None

                if not job_id:
                    raise RuntimeError("Miner returned 202 but no job_id in response")

                logger.info(
                    "Miner created async job %s for origin %s deletion",
                    job_id,
                    origin_id,
                )

                # Poll for job completion WITH SSE progress updates
                # Japan operations can take 15+ minutes due to cross-region SSH
                job_url = f"http://{emn_ip}:{emn_port}/api/v1/admin/jobs/{job_id}"
                poll_interval = 5
                timeout_seconds = 900  # 15 minutes for slow cross-region ops
                deadline = timeout_seconds
                last_progress = -1

                poll_count = 0
                consecutive_404_count = 0
                MAX_CONSECUTIVE_404 = 5  # Exit early after 5 consecutive 404s

                while deadline > 0:
                    time.sleep(poll_interval)
                    deadline -= poll_interval
                    poll_count += 1

                    try:
                        job_resp = req.get(job_url, headers=headers, timeout=(5, 30))
                    except req.RequestException as exc:
                        logger.warning("Job %s poll #%d failed: %s", job_id, poll_count, exc)
                        continue

                    if job_resp.status_code == 404:
                        consecutive_404_count += 1
                        if consecutive_404_count >= MAX_CONSECUTIVE_404:
                            # Job doesn't exist on miner - either completed and cleared,
                            # or miner restarted. Check if origin still exists.
                            logger.warning(
                                "Job %s: %d consecutive 404s - checking if origin %s still exists",
                                job_id, consecutive_404_count, origin_id
                            )
                            try:
                                check_url = f"http://{emn_ip}:{emn_port}/api/v1/origins/{origin_id}"
                                check_resp = req.get(check_url, headers=headers, timeout=(5, 10))
                                if check_resp.status_code == 404:
                                    logger.info(
                                        "Job %s lost but origin %s is gone - treating as success",
                                        job_id, origin_id
                                    )
                                    return {"status": "success", "job_id": job_id, "job_lost": True}
                            except Exception as check_exc:
                                logger.warning("Origin existence check failed: %s", check_exc)
                            # If origin still exists or check failed, raise error
                            raise RuntimeError(
                                f"Miner lost track of job {job_id} and origin {origin_id} still exists"
                            )
                        logger.warning("Job %s poll #%d returned 404 (%d consecutive)",
                                      job_id, poll_count, consecutive_404_count)
                        continue
                    elif job_resp.status_code != 200:
                        consecutive_404_count = 0  # Reset on non-404 errors
                        logger.warning("Job %s poll #%d returned %s", job_id, poll_count, job_resp.status_code)
                        continue
                    else:
                        consecutive_404_count = 0  # Reset on success

                    try:
                        resp_data = job_resp.json()
                        job = resp_data.get("job", {})
                        state = job.get("state")
                        progress = job.get("progress", 0)
                        progress_msg = job.get("progress_message", "")
                        error = job.get("error")
                    except Exception as exc:
                        logger.warning("Job %s poll #%d parse error: %s (body=%s)",
                            job_id, poll_count, exc, job_resp.text[:200] if job_resp.text else "empty")
                        continue

                    # Emit SSE progress update if progress changed
                    if ctx and ctx.exit_hub_id and progress != last_progress:
                        last_progress = progress
                        label = f"Cleaning up routing ({progress}%)"
                        if progress_msg:
                            label = f"Cleaning up: {progress_msg}"
                        get_operation_tracker().track(
                            exit_hub_id=ctx.exit_hub_id,
                            status="miner_cleanup",
                            client_id=ctx.client_id,
                            origin_id=ctx.origin_id,
                            miner_id=ctx.miner_id,
                            miner_ip=ctx.miner_ip,
                            metadata={
                                "deletion_progress": progress,
                                "deletion_message": label,
                            },
                        )

                    # Check terminal states
                    if state == "succeeded":
                        logger.info("Job %s succeeded", job_id)
                        return {"status": "success", "job_id": job_id}

                    if state == "failed":
                        raise RuntimeError(
                            f"Origin deletion job failed: {error or 'unknown'}"
                        )

                    if state == "cancelled":
                        raise RuntimeError("Origin deletion job was cancelled")

                    logger.debug(
                        "Job %s: state=%s progress=%d%% (%ds left)",
                        job_id, state, progress, deadline
                    )

                # Timeout - but check if origin is actually gone before failing
                # This handles cases where job completed but we missed the notification
                logger.warning(
                    "Job %s polling timed out after %ds, checking if origin still exists",
                    job_id, timeout_seconds
                )
                try:
                    check_url = f"http://{emn_ip}:{emn_port}/api/v1/origins/{origin_id}"
                    check_resp = req.get(check_url, headers=headers, timeout=(5, 10))
                    if check_resp.status_code == 404:
                        # Origin is gone - deletion actually succeeded
                        logger.info(
                            "Job %s timed out but origin %s is gone - treating as success",
                            job_id, origin_id
                        )
                        return {"status": "success", "job_id": job_id, "fallback": True}
                    else:
                        logger.error(
                            "Job %s timed out and origin %s still exists (status=%s)",
                            job_id, origin_id, check_resp.status_code
                        )
                except Exception as check_exc:
                    logger.warning("Origin existence check failed: %s", check_exc)

                raise RuntimeError(
                    f"Timeout waiting for deletion job {job_id} after {timeout_seconds}s"
                )

            # Handle errors
            if resp.status_code >= 400:
                error_msg = resp.text[:200] if resp.text else "no body"
                raise RuntimeError(
                    f"Origin deletion failed: HTTP {resp.status_code} - {error_msg}"
                )

            # Legacy sync response (200 OK) - backward compatible
            return resp.json() if resp.text else {"status": "success"}

        miner_queue.register_executor("delete_origin", delete_origin_executor)

    def _get_miner_lock(self, miner_id: str) -> threading.Lock:
        """Get or create a lock for serializing jobs to a specific miner."""
        with self._miner_locks_lock:
            if miner_id not in self._miner_locks:
                self._miner_locks[miner_id] = threading.Lock()
            return self._miner_locks[miner_id]

    def _get_queue_position(self, miner_id: str) -> int:
        """Get current queue depth for a miner (0 = no one ahead)."""
        with self._pending_lock:
            pending = self._pending_per_miner.get(miner_id, [])
            return len(pending)

    def _add_to_pending(self, miner_id: str, exit_hub_id: str, job: _DeployJob) -> int:
        """Add job to per-miner pending list. Returns position (1-based)."""
        with self._pending_lock:
            if miner_id not in self._pending_per_miner:
                self._pending_per_miner[miner_id] = []
            self._pending_per_miner[miner_id].append((exit_hub_id, job))
            return len(self._pending_per_miner[miner_id])

    def _remove_from_pending(self, miner_id: str, exit_hub_id: str) -> None:
        """Remove job from per-miner pending list."""
        with self._pending_lock:
            pending = self._pending_per_miner.get(miner_id, [])
            self._pending_per_miner[miner_id] = [
                (eid, j) for eid, j in pending if eid != exit_hub_id
            ]
            # Position updates handled by OperationTracker deduplication

    def cancel_job(self, exit_hub_id: str) -> bool:
        """Register job for cancellation. Returns True."""
        with self._cancel_lock:
            self._cancelled_jobs.add(str(exit_hub_id))
            logger.info("Registered cancellation for job %s", exit_hub_id)
        return True

    def is_cancelled(self, exit_hub_id: str) -> bool:
        """Check if job has been cancelled."""
        with self._cancel_lock:
            return str(exit_hub_id) in self._cancelled_jobs

    def clear_cancelled(self, exit_hub_id: str) -> None:
        """Remove from cancelled set after cleanup complete."""
        with self._cancel_lock:
            self._cancelled_jobs.discard(str(exit_hub_id))
            logger.debug("Cleared cancellation flag for job %s", exit_hub_id)

    def _start_workers(self, worker_count: int) -> None:
        for idx in range(worker_count):
            thread = threading.Thread(
                target=self._worker_loop,
                name=f"deploy-worker-{idx+1}",
                daemon=True,
            )
            thread.start()
            logger.info("Started deploy worker thread %s", thread.name)

    def enqueue(self, request: ExitHubDeployRequest) -> tuple[UUID, ExitHubDeployRequest]:
        """Validate + persist identifiers, then queue the job.

        Calculates queue position per-miner and emits it immediately so users
        see their position in the queue right away, before any processing starts.
        """
        exit_hub_id, prepared_req, origin_num = self.manager.prepare_deploy(request)
        job = _DeployJob(exit_hub_id=exit_hub_id, request=prepared_req, origin_num=origin_num)

        # Track per-miner queue position
        miner_id = prepared_req.miner_id or "unknown"
        queue_position = self._add_to_pending(miner_id, str(exit_hub_id), job)

        self.manager.repository.update_exit_hub(exit_hub_id, status='queued')
        logger.info(
            "Queued deploy %s for miner=%s origin=%s client=%s (position=%d)",
            exit_hub_id,
            prepared_req.miner_id,
            prepared_req.origin_id,
            prepared_req.client_id,
            queue_position,
        )

        # Emit queue status with position - this is the FIRST notification the user sees
        if queue_position > 1:
            label = f"Waiting in queue (position {queue_position})"
        else:
            label = "Processing deployment"
        try:
            self.manager._notify_state_change(
                exit_hub_id=str(exit_hub_id),
                status='queued',
                client_id=prepared_req.client_id,
                origin_id=prepared_req.origin_id,
                miner_id=prepared_req.miner_id,
                miner_ip=prepared_req.emn_ip,
                metadata={
                    "origin_num": origin_num,
                    "queue_position": queue_position,
                    "progress": {
                        "label": label,
                        "status": "queued",
                    },
                },
            )
        except Exception:
            logger.debug("Unable to notify queued status for %s", exit_hub_id)

        try:
            self.queue.put_nowait(job)
        except queue.Full as exc:  # pragma: no cover - defensive path
            logger.error("Deployment queue full; rejecting %s", exit_hub_id)
            self._remove_from_pending(miner_id, str(exit_hub_id))
            self.manager.repository.update_exit_hub(
                exit_hub_id,
                status='failed',
                last_error='deployment_queue_full'
            )
            if prepared_req.client_id and prepared_req.origin_id:
                self.manager.client_registry.mark_origin_failed(
                    prepared_req.client_id,
                    prepared_req.origin_id,
                )
            raise DeployQueueFullError from exc
        return exit_hub_id, prepared_req

    def _worker_loop(self) -> None:
        while True:
            job = self.queue.get()
            miner_id = job.request.miner_id or "unknown"
            miner_lock = self._get_miner_lock(miner_id)

            try:
                # Check if already cancelled before starting
                if self.is_cancelled(str(job.exit_hub_id)):
                    logger.info("Job %s already cancelled, skipping", job.exit_hub_id)
                    self._remove_from_pending(miner_id, str(job.exit_hub_id))
                    continue

                # Acquire per-miner lock to serialize jobs going to the same miner
                # This prevents race conditions and overwhelming the miner
                logger.debug(
                    "Job %s waiting for miner %s lock",
                    job.exit_hub_id,
                    miner_id[:8] if miner_id != "unknown" else miner_id,
                )
                with miner_lock:
                    logger.info(
                        "Deploy worker acquired lock and picked up job %s for miner %s",
                        job.exit_hub_id,
                        miner_id[:8] if miner_id != "unknown" else miner_id,
                    )
                    self._run_job_with_timeout(job)

            except CancelledException:
                logger.info("Job %s was cancelled during execution", job.exit_hub_id)
                # Don't call handle_worker_failure - cancellation is handled elsewhere
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Deployment %s failed in worker: %s",
                    job.exit_hub_id,
                    exc,
                    exc_info=True,
                )
                self.manager.handle_worker_failure(job.exit_hub_id, job.request, exc)
            finally:
                # Remove from pending and notify remaining jobs of updated positions
                self._remove_from_pending(miner_id, str(job.exit_hub_id))
                self.queue.task_done()

    def _run_job_with_timeout(self, job: _DeployJob) -> None:
        def _check_cancelled():
            if self.is_cancelled(str(job.exit_hub_id)):
                raise CancelledException(f"Job {job.exit_hub_id} cancelled by user")

        _check_cancelled()  # Checkpoint 1: Before deployment target selection

        # Emit selecting_target state
        self.manager.repository.update_exit_hub(
            job.exit_hub_id,
            status='selecting_target',
            last_error=None,
        )
        self.manager._notify_state_change(
            exit_hub_id=str(job.exit_hub_id),
            status='selecting_target',
            client_id=job.request.client_id,
            origin_id=job.request.origin_id,
            miner_id=job.request.miner_id,
            miner_ip=job.request.emn_ip,
            error=None,
        )

        # Region is already resolved by prepare_deploy() with geolocation
        # Use provider-aware default if region not specified
        if job.request.region:
            preferred_region = job.request.region
        else:
            provider = job.request.cloud_provider or "aws"
            preferred_region = get_default_region_for_provider(provider)
        logger.debug(
            "Job %s: using region %s for deployment",
            job.exit_hub_id,
            preferred_region,
        )

        # Track regions tried for fallback logic
        tried_regions: set[str] = set()
        current_region = preferred_region
        max_region_attempts = 4  # Original + 3 fallbacks

        for region_attempt in range(max_region_attempts):
            tried_regions.add(current_region)

            # Update job request with current region for this attempt
            if region_attempt > 0:
                logger.info(
                    "Job %s: attempting fallback region %s (attempt %d/%d)",
                    job.exit_hub_id,
                    current_region,
                    region_attempt + 1,
                    max_region_attempts,
                )
                # Update the request with the new region
                job.request = job.request.model_copy(update={"region": current_region})
                # Update metadata to reflect the new region
                self.manager.repository.update_metadata(
                    job.exit_hub_id,
                    {
                        "exit_region": current_region,
                        "placement_reason": f"fallback:{current_region}",
                        "region_attempt": region_attempt + 1,
                        "tried_regions": list(tried_regions),
                    }
                )
                self.manager._notify_state_change(
                    exit_hub_id=str(job.exit_hub_id),
                    status='selecting_target',
                    client_id=job.request.client_id,
                    origin_id=job.request.origin_id,
                    miner_id=job.request.miner_id,
                    miner_ip=job.request.emn_ip,
                    metadata={
                        "fallback_region": current_region,
                        "region_attempt": region_attempt + 1,
                    },
                    error=None,
                )

            try:
                self._run_deployment_attempt(job, current_region, _check_cancelled)
                # Success - break out of region retry loop
                return
            except RegionCapacityExhaustedError as e:
                logger.warning(
                    "Job %s: region %s capacity exhausted: %s",
                    job.exit_hub_id,
                    e.region,
                    str(e),
                )
                # Get fallback regions sorted by proximity
                provider = job.request.cloud_provider or "aws"
                fallback_regions = get_fallback_regions(
                    failed_region=e.region,
                    provider=provider,
                    max_fallbacks=max_region_attempts - region_attempt - 1,
                    excluded_regions=list(tried_regions),
                )
                if not fallback_regions:
                    logger.error(
                        "Job %s: no fallback regions available after trying %s",
                        job.exit_hub_id,
                        sorted(tried_regions),
                    )
                    raise RuntimeError(
                        f"All regions exhausted. Tried: {sorted(tried_regions)}"
                    ) from e
                current_region = fallback_regions[0]
                logger.info(
                    "Job %s: will try fallback region %s (available fallbacks: %s)",
                    job.exit_hub_id,
                    current_region,
                    fallback_regions,
                )
                continue

        # Should not reach here, but just in case
        raise RuntimeError(f"Deployment failed after {max_region_attempts} region attempts")

    def _run_deployment_attempt(
        self,
        job: _DeployJob,
        preferred_region: str,
        _check_cancelled,
    ) -> None:
        """Execute a single deployment attempt for a given region."""
        excluded_shards: set[str] = set()
        max_reselection_attempts = 3
        reselection_attempt = 0

        # Track shard state using mutable dict so changes persist across function calls
        shard_state = {
            "created_by_tpm": False,
            "job_id": None,
        }

        for reselection_attempt in range(max_reselection_attempts):
            # Select optimal miner + shard using deployment decision logic
            try:
                target: DeploymentTarget = select_deployment_target(
                    preferred_region=preferred_region,
                    registry=self.manager.miner_registry,
                    excluded_shards=excluded_shards,
                )
            except MinerUnreachableError as e:
                logger.error(
                    "Job %s: deployment decision failed - miner unreachable: %s",
                    job.exit_hub_id,
                    e,
                )
                raise RuntimeError(f"No reachable miners: {e}") from e
            except NoCapacityError as e:
                logger.error(
                    "Job %s: deployment decision failed - no capacity: %s",
                    job.exit_hub_id,
                    e,
                )
                raise RuntimeError("All regions at capacity") from e

            # Skip excluded shards from previous capacity exhaustion failures
            if target.shard_id in excluded_shards:
                logger.warning(
                    "Job %s: selected shard %s was previously exhausted, reselecting "
                    "(reselection_attempt %d/%d)",
                    job.exit_hub_id,
                    target.shard_id,
                    reselection_attempt + 1,
                    max_reselection_attempts,
                )
                continue

            # Update request with selected deployment target
            job.request.miner_id = target.miner_id
            job.request.emn_ip = target.miner_ip
            job.request.emn_port = target.miner_port
            job.request.shard_id = target.shard_id
            job.request.region = target.region

            # Persist miner assignment to origin early (before cloud deploy)
            self.manager.origin_repository.set_miner_assignment(
                job.request.client_id,
                job.request.origin_id,
                miner_id=target.miner_id,
                miner_ip=target.miner_ip,
            )
            # Note: tensorprox_ip and shard_id set later after Miner registration

            logger.info(
                "Job %s: deployment target selected - miner=%s, region=%s, shard=%s, "
                "needs_new_shard=%s, capacity=%s",
                job.exit_hub_id,
                target.miner_id,
                target.region,
                target.shard_id,
                target.needs_new_shard,
                target.capacity_info,
            )

            # Try to deploy with this target (may trigger CapacityExhaustedError)
            try:
                self._execute_deployment_with_target(
                    job=job,
                    target=target,
                    shard_state=shard_state,
                )
                # Success - break out of reselection loop
                break

            except CapacityExhaustedError as e:
                logger.warning(
                    "Job %s: shard %s capacity exhausted - adding to exclusion list and reselecting "
                    "(reselection_attempt %d/%d)",
                    job.exit_hub_id,
                    e.shard_id or target.shard_id,
                    reselection_attempt + 1,
                    max_reselection_attempts,
                )
                exhausted_shard = e.shard_id or target.shard_id
                excluded_shards.add(exhausted_shard)
                # Continue to next reselection attempt
                continue
        else:
            # Exhausted all reselection attempts
            raise RuntimeError(
                f"All target reselection attempts exhausted after {max_reselection_attempts} "
                f"capacity failures. Excluded shards: {excluded_shards}"
            )

    def _execute_deployment_with_target(
        self,
        job: _DeployJob,
        target: DeploymentTarget,
        shard_state: dict,
    ) -> None:
        """Execute deployment with the selected target. Raises CapacityExhaustedError if shard is full.

        Args:
            job: Deployment job details
            target: Selected deployment target (miner + shard)
            shard_state: Mutable dict tracking shard creation state with keys:
                - created_by_tpm: bool - Whether TPM created this shard
                - job_id: Optional[str] - Shard deploy job ID if created by TPM
        """
        def _check_cancelled():
            if self.is_cancelled(str(job.exit_hub_id)):
                raise CancelledException(f"Job {job.exit_hub_id} cancelled by user")

        # Create new shard if needed
        if target.needs_new_shard:
            _check_cancelled()  # Checkpoint 2: Before scrubber deploy

            logger.info(
                "Job %s: creating new shard %s in region %s on miner %s",
                job.exit_hub_id,
                target.shard_id,
                target.region,
                target.miner_id,
            )
            # Submit shard creation to miner operation queue (FIFO per miner)
            miner_queue = get_miner_operation_queue()
            queue_depth = miner_queue.get_queue_depth(target.miner_id)

            # Notify: entering miner queue
            self.manager.repository.update_exit_hub(
                job.exit_hub_id,
                status='queued_for_miner',
                last_error=None,
            )
            self.manager._notify_state_change(
                exit_hub_id=str(job.exit_hub_id),
                status='queued_for_miner',
                client_id=job.request.client_id,
                origin_id=job.request.origin_id,
                miner_id=target.miner_id,
                miner_ip=target.miner_ip,
                metadata={
                    "shard_id": target.shard_id,
                    "shard_created_by_tpm": True,
                    "queue_position": queue_depth + 1,
                    "operation_type": "deploy_shard",
                },
                error=None,
            )

            # Submit to queue
            # New shards created by TPM are ALWAYS production shards (for customer origins)
            # Audit shards are only created by miners on startup
            miner_op = miner_queue.submit(
                miner_id=target.miner_id,
                operation_type="deploy_shard",
                payload={
                    "miner_ip": target.miner_ip,
                    "miner_port": target.miner_port,
                    "region": target.region,
                    "shard_id": target.shard_id,
                    "shard_type": "production",  # TPM always creates production shards for origins
                    "min_nodes": 2,
                },
                exit_hub_id=str(job.exit_hub_id),
                origin_id=job.request.origin_id,
                shard_id=target.shard_id,
                context=OperationContext(
                    exit_hub_id=str(job.exit_hub_id),
                    origin_id=job.request.origin_id,
                    client_id=job.request.client_id,
                    miner_id=target.miner_id,
                    miner_ip=target.miner_ip,
                ),
            )

            # Notify: miner is now processing
            self.manager.repository.update_exit_hub(
                job.exit_hub_id,
                status='deploying_scrubbers',
                last_error=None,
            )
            self.manager._notify_state_change(
                exit_hub_id=str(job.exit_hub_id),
                status='deploying_scrubbers',
                client_id=job.request.client_id,
                origin_id=job.request.origin_id,
                miner_id=target.miner_id,
                miner_ip=target.miner_ip,
                metadata={
                    "shard_id": target.shard_id,
                    "shard_created_by_tpm": True,
                    "operation_id": str(miner_op.operation_id),
                },
                error=None,
            )

            # Wait for queue completion
            try:
                completed_op = miner_queue.wait_for_completion(
                    str(miner_op.operation_id),
                    timeout=self._job_timeout,
                )
            except TimeoutError as e:
                logger.error(
                    "Job %s: shard creation timed out on miner %s",
                    job.exit_hub_id,
                    target.miner_id,
                )
                raise RuntimeError(f"Shard creation timed out: {e}") from e

            if completed_op.status == "cancelled":
                raise CancelledException("Shard creation cancelled")

            if completed_op.status == "failed":
                logger.error(
                    "Job %s: shard creation failed on miner %s: %s",
                    job.exit_hub_id,
                    target.miner_id,
                    completed_op.error,
                )
                raise RuntimeError(f"Shard creation failed ({completed_op.error})")

            # Extract result
            result = completed_op.result or {}
            ok_deploy = result.get("ok", False)
            deploy_reason = result.get("reason", "unknown")
            created_shard_id = result.get("shard_id")

            if not ok_deploy:
                logger.error(
                    "Job %s: shard creation failed on miner %s: %s",
                    job.exit_hub_id,
                    target.miner_id,
                    deploy_reason,
                )
                raise RuntimeError(f"Shard creation failed ({deploy_reason})")

            # Mark that TPM created this shard
            shard_state["created_by_tpm"] = True

            # Verify shard_id matches what we requested
            if created_shard_id and created_shard_id != target.shard_id:
                logger.warning(
                    "Job %s: miner returned different shard_id: requested=%s, got=%s",
                    job.exit_hub_id,
                    target.shard_id,
                    created_shard_id,
                )
                job.request.shard_id = created_shard_id

            # Verify capacity after shard creation
            # NOTE: We don't filter by region - scrubbers can protect origins
            # in any region, not just their own region
            ok, reason, payload = check_miner_capacity(
                target.miner_id,
                target.miner_ip,
                registry=self.manager.miner_registry,
                min_nodes=2,
                region=None,  # Don't filter by region - scrubbers work cross-region
                miner_port=target.miner_port,
            )
            if not ok:
                logger.error(
                    "Job %s: miner lacks capacity after shard creation: %s",
                    job.exit_hub_id,
                    reason,
                )
                raise RuntimeError(f"Capacity check failed after shard creation ({reason})")

            # Store shard metadata for cleanup tracking
            shard_metadata = {
                "shard_id": target.shard_id,
                "shard_created_by_tpm": True,
            }
            if shard_state["job_id"]:
                shard_metadata["shard_job_id"] = shard_state["job_id"]

            self.manager.repository.update_exit_hub(
                job.exit_hub_id,
                status='scrubbers_ready',
                last_error=None,
            )
            self.manager._notify_state_change(
                exit_hub_id=str(job.exit_hub_id),
                status='scrubbers_ready',
                client_id=job.request.client_id,
                origin_id=job.request.origin_id,
                miner_id=target.miner_id,
                miner_ip=target.miner_ip,
                metadata=shard_metadata,
                error=None,
            )
            logger.info(
                "Job %s: shard %s ready; proceeding with exit hub deploy",
                job.exit_hub_id,
                target.shard_id,
            )
        else:
            # Existing shard with capacity - verify nodes are ready
            # NOTE: We don't filter by region - scrubbers can protect origins
            # in any region, not just their own region
            ok, reason, payload = check_miner_capacity(
                target.miner_id,
                target.miner_ip,
                registry=self.manager.miner_registry,
                min_nodes=2,
                region=None,  # Don't filter by region - scrubbers work cross-region
                miner_port=target.miner_port,
            )
            if not ok:
                logger.error(
                    "Job %s: selected shard %s has no ready nodes: %s",
                    job.exit_hub_id,
                    target.shard_id,
                    reason,
                )
                raise RuntimeError(f"Selected shard has no ready nodes ({reason})")

            logger.info(
                "Job %s: existing shard %s has capacity; proceeding with exit hub deploy",
                job.exit_hub_id,
                target.shard_id,
            )

        _check_cancelled()  # Checkpoint 3: Before exit hub deploy

        ensure_miner_ready(job.request.emn_ip, auto_start_local=self._auto_start_services, port=job.request.emn_port)

        # Attempt deployment with exception handling for shard-related errors
        max_origin_registration_retries = 2
        registration_retry_count = 0

        while registration_retry_count < max_origin_registration_retries:
            try:
                logger.info(
                    "Job %s: launching deploy pipeline (timeout=%ss, registration_attempt=%d/%d)",
                    job.exit_hub_id,
                    self._job_timeout,
                    registration_retry_count + 1,
                    max_origin_registration_retries,
                )
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(
                        self.manager.deploy_exit_hub,
                        job.request,
                        exit_hub_id=job.exit_hub_id,
                        origin_num=job.origin_num,
                        prepared=True,
                        cancel_checker=_check_cancelled,
                    )
                    try:
                        future.result(timeout=self._job_timeout)
                        # Success - break out of retry loop
                        break
                    except FutureTimeoutError:
                        future.cancel()
                        logger.error(
                            "Deployment %s exceeded %ss timeout",
                            job.exit_hub_id,
                            self._job_timeout,
                        )
                        self.manager.handle_worker_timeout(
                            job.exit_hub_id,
                            job.request,
                            timeout_seconds=self._job_timeout,
                        )
                        raise  # Don't retry timeout errors

            except ShardNotFoundError as e:
                logger.warning(
                    "Job %s: shard %s not found during origin registration - "
                    "creating shard and retrying (attempt %d/%d)",
                    job.exit_hub_id,
                    e.shard_id or job.request.shard_id,
                    registration_retry_count + 1,
                    max_origin_registration_retries,
                )

                # Emit waiting_for_shard state
                self.manager.repository.update_exit_hub(
                    job.exit_hub_id,
                    status='waiting_for_shard',
                    last_error=None,
                )
                self.manager._notify_state_change(
                    exit_hub_id=str(job.exit_hub_id),
                    status='waiting_for_shard',
                    client_id=job.request.client_id,
                    origin_id=job.request.origin_id,
                    miner_id=job.request.miner_id,
                    miner_ip=job.request.emn_ip,
                    metadata={
                        "shard_id": e.shard_id or job.request.shard_id,
                        "reason": "shard_not_found",
                    },
                    error=None,
                )

                # Create the missing shard
                shard_to_create = e.shard_id or job.request.shard_id
                ok_req, req_reason, created_job_id, created_shard_id = request_shard_deploy(
                    miner_id=job.request.miner_id,
                    miner_ip=job.request.emn_ip,
                    region=job.request.region or preferred_region,
                    shard_id=shard_to_create,
                    registry=self.manager.miner_registry,
                    miner_port=job.request.emn_port,
                )

                if not ok_req:
                    logger.error(
                        "Job %s: shard deploy request failed: %s",
                        job.exit_hub_id,
                        req_reason,
                    )
                    raise RuntimeError(f"Shard deploy request failed: {req_reason}")

                # If shard already exists, we're good
                if req_reason == "already_exists":
                    logger.info(
                        "Job %s: shard %s already exists after shard_not_found error",
                        job.exit_hub_id,
                        created_shard_id,
                    )
                    registration_retry_count += 1
                    continue

                # Wait for job completion
                if created_job_id:
                    shard_state["job_id"] = created_job_id
                    logger.info(
                        "Job %s: waiting for shard deploy job %s (shard=%s)",
                        job.exit_hub_id,
                        created_job_id,
                        created_shard_id,
                    )
                    job_ok, job_state, job_error = wait_for_job(
                        miner_id=job.request.miner_id,
                        miner_ip=job.request.emn_ip,
                        job_id=created_job_id,
                        registry=self.manager.miner_registry,
                        timeout_seconds=360,
                        poll_interval=15,
                        miner_port=job.request.emn_port,
                    )

                    if not job_ok:
                        logger.error(
                            "Job %s: shard deploy job %s failed: state=%s, error=%s",
                            job.exit_hub_id,
                            created_job_id,
                            job_state,
                            job_error,
                        )
                        raise RuntimeError(f"Shard deploy job failed: {job_state} - {job_error}")

                # Mark shard as created by TPM
                shard_state["created_by_tpm"] = True

                # Retry origin registration
                registration_retry_count += 1
                logger.info(
                    "Job %s: shard %s created, retrying origin registration",
                    job.exit_hub_id,
                    created_shard_id or shard_to_create,
                )
                continue

            except ShardNotReadyError as e:
                logger.warning(
                    "Job %s: shard %s not ready during origin registration - "
                    "waiting for job %s (attempt %d/%d)",
                    job.exit_hub_id,
                    e.shard_id or job.request.shard_id,
                    e.job_id,
                    registration_retry_count + 1,
                    max_origin_registration_retries,
                )

                # Emit waiting_for_shard state
                self.manager.repository.update_exit_hub(
                    job.exit_hub_id,
                    status='waiting_for_shard',
                    last_error=None,
                )
                self.manager._notify_state_change(
                    exit_hub_id=str(job.exit_hub_id),
                    status='waiting_for_shard',
                    client_id=job.request.client_id,
                    origin_id=job.request.origin_id,
                    miner_id=job.request.miner_id,
                    miner_ip=job.request.emn_ip,
                    metadata={
                        "shard_id": e.shard_id or job.request.shard_id,
                        "job_id": e.job_id,
                        "reason": "shard_not_ready",
                    },
                    error=None,
                )

                if e.job_id:
                    logger.info(
                        "Job %s: waiting for existing shard deploy job %s (shard=%s)",
                        job.exit_hub_id,
                        e.job_id,
                        e.shard_id,
                    )
                    job_ok, job_state, job_error = wait_for_job(
                        miner_id=job.request.miner_id,
                        miner_ip=job.request.emn_ip,
                        job_id=e.job_id,
                        registry=self.manager.miner_registry,
                        timeout_seconds=360,
                        poll_interval=15,
                        miner_port=job.request.emn_port,
                    )

                    if not job_ok:
                        logger.error(
                            "Job %s: shard deploy job %s failed: state=%s, error=%s",
                            job.exit_hub_id,
                            e.job_id,
                            job_state,
                            job_error,
                        )
                        raise RuntimeError(f"Shard deploy job failed: {job_state} - {job_error}")

                # Retry origin registration
                registration_retry_count += 1
                logger.info(
                    "Job %s: shard %s ready, retrying origin registration",
                    job.exit_hub_id,
                    e.shard_id or job.request.shard_id,
                )
                continue

            except CapacityExhaustedError as e:
                logger.warning(
                    "Job %s: shard %s capacity exhausted during origin registration - "
                    "re-raising to trigger reselection (attempt %d/%d)",
                    job.exit_hub_id,
                    e.shard_id or job.request.shard_id,
                    registration_retry_count + 1,
                    max_origin_registration_retries,
                )

                # Re-raise to be caught by outer reselection loop
                raise

        else:
            # Exhausted all registration retries
            raise RuntimeError(
                f"Origin registration failed after {max_origin_registration_retries} attempts"
            )

        # Store final shard metadata if TPM created the shard
        if shard_state["created_by_tpm"]:
            final_metadata = {
                "shard_id": job.request.shard_id,
                "shard_created_by_tpm": True,
            }
            if shard_state["job_id"]:
                final_metadata["shard_job_id"] = shard_state["job_id"]

            # Update metadata in database
            current = self.manager.repository.get_exit_hub(job.exit_hub_id)
            if current:
                existing_metadata = current.get("metadata", {})
                if isinstance(existing_metadata, dict):
                    existing_metadata.update(final_metadata)
                    self.manager.repository.update_metadata(
                        job.exit_hub_id,
                        existing_metadata
                    )


_settings = get_tp_management_settings()
deploy_queue = DeployWorkerPool(
    manager=exithub_manager,
    worker_count=max(1, _settings.tp_deploy_worker_threads),
    max_queue_size=max(1, _settings.tp_deploy_queue_size),
    job_timeout=max(30, _settings.cloud_deploy_timeout_seconds),
    auto_start_services=_settings.tp_auto_start_local_services,
)


def get_deploy_queue() -> DeployWorkerPool:
    """Get the global deploy queue singleton"""
    return deploy_queue
