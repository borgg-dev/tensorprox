"""Job Worker - Asynchronous job execution for long-running operations

Executes long-running operations in the background without blocking API responses.

Supported job types:
- deploy_shard: Creates scrubber infrastructure (~5-7 min)
- delete_origin: Removes origin from miner (~2-4 min)

Architecture:
- Jobs are created in deployment_jobs table with state='pending'
- Worker thread polls for pending jobs (every 5 seconds)
- Executes one job at a time per shard/origin (per-resource locking)
- Updates progress frequently for UI display
- Handles failures with rollback and error logging

Job lifecycle:
  pending → running → succeeded (or failed)

Thread safety:
- Per-resource locks prevent concurrent operations on same resource
- Database operations use fresh connections per job
- State manager updates are thread-safe via RLock
"""
import uuid
import threading
import logging
from typing import Optional, Dict, Any, List
from psycopg2.extras import Json
from shared.database import get_db_connection
from shared.node import Node
from shared.utils.database_helpers import db_delete_node
from miner_control_plane.services.state_manager import state_manager

logger = logging.getLogger(__name__)

# Global locks per resource to prevent concurrent operations
_resource_locks: Dict[str, threading.Lock] = {}
_resource_locks_lock = threading.Lock()


def _get_resource_lock(resource_id: str) -> threading.Lock:
    """
    Get or create a lock for a specific resource (shard or origin).

    Args:
        resource_id: Resource identifier (shard_id or origin_id)

    Returns:
        Lock instance for this resource
    """
    with _resource_locks_lock:
        if resource_id not in _resource_locks:
            _resource_locks[resource_id] = threading.Lock()
        return _resource_locks[resource_id]


def create_job(
    job_type: str,
    shard_id: Optional[str] = None,
    region: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    miner_id: Optional[str] = None
) -> str:
    """
    Create a new job in pending state.

    Args:
        job_type: Type of job ('deploy_shard', 'delete_origin', etc.)
        shard_id: Target shard ID (required for deploy_shard)
        region: AWS region (required for deploy_shard)
        metadata: Job-specific metadata stored in result JSONB.
                  For delete_origin: {'origin_id': '...', 'shard_id': '...'}
        miner_id: UUID of the miner this job belongs to (for multi-miner isolation)

    Returns:
        job_id: UUID of created job

    Raises:
        Exception: If database operation fails
    """
    job_id = str(uuid.uuid4())
    db = get_db_connection()

    # For delete_origin jobs, extract shard_id from metadata if not provided directly
    effective_shard_id = shard_id
    if not effective_shard_id and metadata:
        effective_shard_id = metadata.get('shard_id')

    # Get miner_id from identity manager if not provided
    effective_miner_id = miner_id
    if not effective_miner_id:
        from miner_control_plane.services.miner_identity import get_miner_identity
        identity = get_miner_identity()
        effective_miner_id = identity.miner_id

    try:
        db.execute("""
            INSERT INTO deployment_jobs (
                job_id, type, state, progress, progress_message,
                shard_id, region, result, miner_id
            )
            VALUES (%s, %s, 'pending', 0, 'Job queued',
                    %s, %s, %s, %s)
        """, (job_id, job_type, effective_shard_id, region, Json(metadata) if metadata else None, effective_miner_id))

        # Log appropriate resource identifier
        if job_type == 'delete_origin' and metadata:
            origin_id = metadata.get('origin_id', 'unknown')
            logger.info(f"Created job {job_id}: {job_type} for origin {origin_id} (miner_id={effective_miner_id})")
        else:
            logger.info(f"Created job {job_id}: {job_type} for shard {effective_shard_id} in {region} (miner_id={effective_miner_id})")

        return job_id

    finally:
        db.close()


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve job status and details.

    Args:
        job_id: Job UUID

    Returns:
        Job dictionary or None if not found
    """
    db = get_db_connection()

    try:
        job = db.query_one("""
            SELECT job_id, type, state, progress, progress_message,
                   shard_id, region, error, result,
                   created_at, updated_at, completed_at
            FROM deployment_jobs
            WHERE job_id = %s
        """, (job_id,))

        return dict(job) if job else None

    finally:
        db.close()


def update_job_progress(
    job_id: str,
    progress: int,
    message: str
) -> None:
    """
    Update job progress for UI display.

    Args:
        job_id: Job UUID
        progress: Progress percentage (0-100)
        message: Human-readable progress description
    """
    db = get_db_connection()

    try:
        db.execute("""
            UPDATE deployment_jobs
            SET progress = %s,
                progress_message = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_id = %s
        """, (progress, message, job_id))

        logger.debug(f"Job {job_id}: {progress}% - {message}")

    finally:
        db.close()


def complete_job(
    job_id: str,
    result: Optional[Dict[str, Any]] = None
) -> None:
    """
    Mark job as completed with result data.

    Args:
        job_id: Job UUID
        result: Optional result data (stored as JSONB)
    """
    db = get_db_connection()

    try:
        db.execute("""
            UPDATE deployment_jobs
            SET state = 'succeeded',
                progress = 100,
                progress_message = 'Job succeeded',
                result = %s,
                completed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_id = %s
        """, (Json(result) if result else None, job_id))

        logger.info(f"Job {job_id} succeeded")

    finally:
        db.close()


def fail_job(
    job_id: str,
    error: str
) -> None:
    """
    Mark job as failed with error message.

    Args:
        job_id: Job UUID
        error: Error message/stack trace
    """
    db = get_db_connection()

    try:
        db.execute("""
            UPDATE deployment_jobs
            SET state = 'failed',
                error = %s,
                completed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_id = %s
        """, (error, job_id))

        logger.error(f"Job {job_id} failed: {error}")

    finally:
        db.close()


def _set_job_running(job_id: str) -> None:
    """
    Mark job as running (internal helper).

    Args:
        job_id: Job UUID
    """
    db = get_db_connection()

    try:
        db.execute("""
            UPDATE deployment_jobs
            SET state = 'running',
                updated_at = CURRENT_TIMESTAMP
            WHERE job_id = %s
        """, (job_id,))

    finally:
        db.close()


def _execute_deploy_shard_job(job: Dict[str, Any]) -> None:
    """
    Execute a deploy_shard job (mirrors create_shard() logic from admin.py).

    This function performs the same steps as the synchronous create_shard()
    but updates job progress at each stage.

    WARM POOL INTEGRATION: Before deploying new instances, checks for
    available warm scrubbers in the target region and repurposes them.

    Args:
        job: Job dictionary with job_id, shard_id, region, etc.

    Raises:
        Exception: If any deployment step fails (caller handles rollback)
    """
    from miner_control_plane.api.admin import (
        deploy_single_scrubber,
        get_warm_scrubbers,
        repurpose_warm_scrubber
    )

    job_id = job['job_id']
    shard_id = job['shard_id']
    region = job['region']
    metadata = job.get('result') or {}
    shard_type = metadata.get('shard_type', 'production')  # Default to production

    deployed_nodes = {}

    try:
        logger.info(f"[Job {job_id}] Starting deploy_shard: {shard_id} ({shard_type}) in {region}")

        # Check if shard already has deployed nodes (idempotent)
        # A shard record may exist (created by API for FK constraint) but
        # deployment only skips if nodes are actually deployed
        existing_nodes = state_manager.get_nodes_for_shard(shard_id)
        if existing_nodes:
            logger.info(f"[Job {job_id}] Shard {shard_id} already has {len(existing_nodes)} nodes (idempotent)")
            complete_job(job_id, {
                'shard_id': shard_id,
                'region': region,
                'status': 'already_exists',
                'nodes': [
                    {
                        'node_id': n['node_id'],
                        'role': n['role'],
                        'public_ip': n['public_ip']
                    }
                    for n in existing_nodes
                ]
            })
            return

        # Acquire per-shard lock to prevent concurrent deploys
        shard_lock = _get_resource_lock(shard_id)
        if not shard_lock.acquire(blocking=False):
            raise Exception(f"Shard {shard_id} is already being deployed by another job")

        try:
            # Progress: 5% - Shard registered
            update_job_progress(job_id, 5, "Creating shard in database")
            state_manager.create_shard(shard_id, region, shard_type=shard_type)

            # Check for warm scrubbers before deploying new instances
            warm_scrubbers = get_warm_scrubbers(region)
            warm_active = None
            warm_standby = None

            if warm_scrubbers:
                logger.info(f"[Job {job_id}] Found {len(warm_scrubbers)} warm scrubbers in {region}")
                # Find one for active (prefer is_active)
                # Only look for standby if this is a production shard
                for ws in warm_scrubbers:
                    if warm_active is None and ws.get("is_active"):
                        warm_active = ws
                    elif shard_type == 'production' and warm_standby is None and ws.get("is_standby"):
                        warm_standby = ws
                # Fallback: use any available warm scrubbers
                for ws in warm_scrubbers:
                    if warm_active is None and ws != warm_standby:
                        warm_active = ws
                    elif shard_type == 'production' and warm_standby is None and ws != warm_active:
                        warm_standby = ws

                if warm_active:
                    logger.info(f"[Job {job_id}] Will repurpose {warm_active['instance_id']} as active")
                if warm_standby:
                    logger.info(f"[Job {job_id}] Will repurpose {warm_standby['instance_id']} as standby")
            else:
                logger.info(f"[Job {job_id}] No warm scrubbers available in {region}, deploying fresh")

            # Deploy/repurpose active node (5% → 50%)
            node_a_name = f"{shard_id}-a"
            if warm_active:
                logger.info(f"[Job {job_id}] Repurposing warm scrubber as active: {node_a_name}")
                update_job_progress(job_id, 10, f"Repurposing warm scrubber as active {node_a_name}")
                node_a = repurpose_warm_scrubber(
                    warm_scrubber=warm_active,
                    shard_id=shard_id,
                    region=region,
                    node_name=node_a_name,
                    role='active'
                )
            else:
                logger.info(f"[Job {job_id}] Deploying active node: {node_a_name}")
                update_job_progress(job_id, 10, f"Deploying active node {node_a_name}")
                node_a = deploy_single_scrubber(
                    shard_id=shard_id,
                    region=region,
                    node_name=node_a_name,
                    role='active'
                )
            deployed_nodes[node_a_name] = node_a

            update_job_progress(
                job_id, 50,
                f"Active node {node_a_name} ready at {node_a['public_ip']}"
            )

            # Deploy/repurpose standby node (50% → 95%) - ONLY for production shards
            # Audit shards use only 1 active node (no standby needed for validator scoring)
            node_b = None
            if shard_type == 'production':
                node_b_name = f"{shard_id}-b"
                if warm_standby:
                    logger.info(f"[Job {job_id}] Repurposing warm scrubber as standby: {node_b_name}")
                    update_job_progress(job_id, 55, f"Repurposing warm scrubber as standby {node_b_name}")
                    node_b = repurpose_warm_scrubber(
                        warm_scrubber=warm_standby,
                        shard_id=shard_id,
                        region=region,
                        node_name=node_b_name,
                        role='standby'
                    )
                else:
                    logger.info(f"[Job {job_id}] Deploying standby node: {node_b_name}")
                    update_job_progress(job_id, 55, f"Deploying standby node {node_b_name}")
                    node_b = deploy_single_scrubber(
                        shard_id=shard_id,
                        region=region,
                        node_name=node_b_name,
                        role='standby'
                    )
                deployed_nodes[node_b_name] = node_b

                update_job_progress(
                    job_id, 95,
                    f"Standby node {node_b_name} ready at {node_b['public_ip']}"
                )
            else:
                # Audit shard - no standby
                logger.info(f"[Job {job_id}] Audit shard - skipping standby deployment (1 active only)")
                update_job_progress(job_id, 95, f"Audit shard ready (active only, no standby)")

            # Set shard state (active/standby)
            state_manager.update_shard_state(
                shard_id=shard_id,
                active_node=node_a['node_id'],
                standby_node=node_b['node_id'] if node_b else None
            )

            # Update shard status to active
            state_manager.update_shard_status(shard_id, 'active')

            # Progress: 100% - Complete
            nodes_result = [
                {
                    'node_id': node_a['node_id'],
                    'instance_name': node_a_name,
                    'role': 'active',
                    'public_ip': node_a['public_ip']
                }
            ]
            if node_b:
                nodes_result.append({
                    'node_id': node_b['node_id'],
                    'instance_name': f"{shard_id}-b",
                    'role': 'standby',
                    'public_ip': node_b['public_ip']
                })

            result = {
                'shard_id': shard_id,
                'region': region,
                'status': 'active',
                'shard_type': shard_type,
                'nodes': nodes_result
            }

            complete_job(job_id, result)
            node_count = len(nodes_result)
            logger.info(f"[Job {job_id}] Shard {shard_id} ({shard_type}) deployment completed: {node_count} node(s)")

        finally:
            shard_lock.release()

    except Exception as e:
        logger.error(f"[Job {job_id}] Deployment failed: {e}", exc_info=True)

        # Rollback: destroy deployed nodes
        if deployed_nodes:
            logger.warning(f"[Job {job_id}] Rolling back {len(deployed_nodes)} deployed nodes...")
            for node_name, node_info in deployed_nodes.items():
                try:
                    rollback_node = Node(node_type="scrubber")
                    rollback_node.destroy(node_info['node_id'])
                    db = get_db_connection()
                    try:
                        db_delete_node(node_info['node_id'], db)
                    finally:
                        db.close()
                    state_manager.remove_node(node_info['node_id'])
                    logger.info(f"[Job {job_id}] Rolled back node {node_name}")
                except Exception as rollback_err:
                    logger.error(f"[Job {job_id}] Rollback failed for {node_name}: {rollback_err}")

            # Delete shard from database if partially created
            try:
                state_manager.delete_shard(shard_id)
            except Exception:
                pass

        # Mark job as failed
        fail_job(job_id, str(e))
        raise


def _execute_delete_origin_job(job: Dict[str, Any]) -> None:
    """
    Execute a delete_origin job.

    This function calls origin_service.delete_origin() to perform the actual
    deletion, updating job progress at each major stage.

    Args:
        job: Job dictionary with job_id, result (containing origin_id, shard_id)

    Raises:
        Exception: If deletion fails (caller handles marking job as failed)
    """
    from miner_control_plane.services.origin_service import origin_service

    job_id = job['job_id']
    metadata = job.get('result') or {}
    origin_id = metadata.get('origin_id')
    shard_id = metadata.get('shard_id') or job.get('shard_id')

    if not origin_id:
        raise ValueError(f"Job {job_id} missing origin_id in metadata")

    logger.info(f"[Job {job_id}] Starting delete_origin: {origin_id} in shard {shard_id}")

    # Acquire per-origin lock to prevent concurrent deletions
    origin_lock = _get_resource_lock(f"origin:{origin_id}")
    if not origin_lock.acquire(blocking=False):
        raise Exception(f"Origin {origin_id} is already being deleted by another job")

    try:
        # Progress: 5% - Starting deletion
        update_job_progress(job_id, 5, f"Starting deletion of origin {origin_id}")

        # Execute the actual deletion via origin_service
        # The delete_origin method handles all cleanup (BPF maps, WireGuard, EIPs, etc.)
        result = origin_service.delete_origin(
            origin_id,
            job_id=job_id,  # Pass job_id for progress updates
        )

        # Progress: 100% - Complete
        complete_job(job_id, {
            'origin_id': origin_id,
            'shard_id': shard_id,
            'status': 'deleted',
            'details': result,
        })
        logger.info(f"[Job {job_id}] Origin {origin_id} deletion completed successfully")

    except Exception as e:
        logger.error(f"[Job {job_id}] Delete origin failed: {e}", exc_info=True)
        fail_job(job_id, str(e))
        raise

    finally:
        origin_lock.release()


class JobWorker:
    """
    Background worker that polls for pending jobs and executes them.

    Architecture:
    - Runs in a daemon thread
    - Polls deployment_jobs table every 5 seconds
    - Executes jobs one at a time per shard (per-shard locking)
    - Handles job lifecycle (pending → running → succeeded/failed)
    """

    def __init__(self, poll_interval: int = 5):
        """
        Initialize job worker.

        Args:
            poll_interval: Seconds between polls for pending jobs (default: 5)
        """
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        """
        Start the job worker thread.
        """
        if self._running:
            logger.warning("Job worker already running")
            return

        self._running = True
        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="JobWorker"
        )
        self._worker_thread.start()
        logger.info(f"Job worker started (poll interval: {self.poll_interval}s)")

    def stop(self) -> None:
        """
        Stop the job worker thread.
        """
        if not self._running:
            return

        logger.info("Stopping job worker...")
        self._stop_event.set()
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=10)
        logger.info("Job worker stopped")

    def _worker_loop(self) -> None:
        """
        Main worker loop: poll for pending jobs and execute them.
        """
        logger.info("Job worker loop started")

        while not self._stop_event.is_set():
            try:
                # Poll for pending jobs
                pending_jobs = self._get_pending_jobs()

                if pending_jobs:
                    logger.debug(f"Found {len(pending_jobs)} pending job(s)")

                for job in pending_jobs:
                    if self._stop_event.is_set():
                        break

                    try:
                        self._execute_job(job)
                    except Exception as e:
                        logger.error(f"Job execution failed: {e}", exc_info=True)

            except Exception as e:
                logger.error(f"Worker loop error: {e}", exc_info=True)

            # Wait for next poll interval
            self._stop_event.wait(self.poll_interval)

        logger.info("Job worker loop exited")

    def _get_pending_jobs(self) -> list:
        """
        Query database for pending jobs belonging to this miner.

        Only returns jobs where miner_id matches this miner's identity,
        ensuring multi-miner setups don't process each other's jobs.

        Returns:
            List of pending job dictionaries (oldest first)
        """
        from miner_control_plane.services.miner_identity import get_miner_identity

        db = get_db_connection()

        try:
            # Get this miner's identity
            identity = get_miner_identity()
            current_miner_id = identity.miner_id

            if not current_miner_id:
                logger.warning("Miner identity not available, skipping job poll")
                return []

            # Only fetch jobs belonging to this miner
            jobs = db.query_all("""
                SELECT job_id, type, state, shard_id, region, result, created_at, miner_id
                FROM deployment_jobs
                WHERE state = 'pending'
                  AND miner_id = %s
                ORDER BY created_at ASC
                LIMIT 10
            """, (current_miner_id,))

            return [dict(job) for job in jobs]

        finally:
            db.close()

    def _execute_job(self, job: Dict[str, Any]) -> None:
        """
        Execute a single job based on its type.

        Args:
            job: Job dictionary with job_id, type, shard_id, region, result, etc.
        """
        job_id = job['job_id']
        job_type = job['type']
        shard_id = job.get('shard_id')
        metadata = job.get('result') or {}

        # Log appropriate identifier based on job type
        if job_type == 'delete_origin':
            origin_id = metadata.get('origin_id', 'unknown')
            logger.info(f"Executing job {job_id}: {job_type} for origin {origin_id}")
        else:
            logger.info(f"Executing job {job_id}: {job_type} for shard {shard_id}")

        # Mark job as running
        _set_job_running(job_id)

        # Execute based on job type
        try:
            if job_type == 'deploy_shard':
                _execute_deploy_shard_job(job)
            elif job_type == 'delete_origin':
                _execute_delete_origin_job(job)
            else:
                fail_job(job_id, f"Unknown job type: {job_type}")
                logger.error(f"Unknown job type: {job_type}")

        except Exception as e:
            # Error already logged and job marked as failed in job executor
            logger.error(f"Job {job_id} execution failed: {e}")


# Global worker instance
_worker: Optional[JobWorker] = None


def start_job_worker_thread(poll_interval: int = 5) -> None:
    """
    Start the job worker background thread.

    Called from miner_control_plane.py during service initialization.

    Args:
        poll_interval: Seconds between polls for pending jobs (default: 5)
    """
    global _worker

    if _worker is not None:
        logger.warning("Job worker already started")
        return

    _worker = JobWorker(poll_interval=poll_interval)
    _worker.start()


def stop_job_worker_thread() -> None:
    """
    Stop the job worker background thread.

    Called during service shutdown (if needed).
    """
    global _worker

    if _worker is not None:
        _worker.stop()
        _worker = None
