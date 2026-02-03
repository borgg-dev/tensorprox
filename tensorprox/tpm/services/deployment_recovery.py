"""Startup recovery for stuck deployments.

Recovers exit hubs stuck in intermediate deployment states on startup.
This handles cases where:
- TPM crashed/restarted during deployment
- Cloud instance was created but miner registration didn't complete
- Deployment worker died mid-operation
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Union

from dateutil import parser as dateutil_parser

from shared.utils.logging import get_logger


def _parse_datetime(value: Union[str, datetime, None]) -> datetime | None:
    """Parse a datetime value that might be a string or datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return dateutil_parser.parse(value)
    except (ValueError, TypeError):
        return None
from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository

logger = get_logger(__name__)

# Deployment states that indicate an incomplete deployment
STUCK_DEPLOYMENT_STATES = [
    "requested",
    "queued",
    "selecting_target",
    "deploying_scrubbers",
    "deploying",
    "registering",
    "registering_origin",
    "stabilizing",
]

# How long a deployment can be in an intermediate state before considered stuck
STUCK_THRESHOLD_MINUTES = 10


def recover_stuck_deployments() -> Dict[str, Any]:
    """Recover exit hubs stuck in intermediate deployment states.

    Called at startup to handle deployments that were interrupted.

    For stuck deployments:
    - If cloud instance exists but registration failed -> mark as failed (orphan sweeper will cleanup)
    - If no cloud instance -> mark as failed
    - Webapp will see "failed" status when it queries the exit hub

    Returns:
        Dict with counts of recovered and errors
    """
    results = {
        "recovered": 0,
        "errors": 0,
        "details": [],
    }

    exit_hub_repo = ExitHubRepository()

    # Find all exit hubs stuck in intermediate deployment states
    stuck_hubs = exit_hub_repo.list_exit_hubs(statuses=STUCK_DEPLOYMENT_STATES)

    if not stuck_hubs:
        logger.info("No exit hubs stuck in deployment states")
        return results

    # Filter to only those that are actually stuck (older than threshold)
    threshold = datetime.now(timezone.utc) - timedelta(minutes=STUCK_THRESHOLD_MINUTES)
    actually_stuck: List[Dict] = []

    for hub in stuck_hubs:
        updated_at = _parse_datetime(hub.get("updated_at"))
        if updated_at and updated_at < threshold:
            actually_stuck.append(hub)

    if not actually_stuck:
        logger.info(
            "Found %d exit hubs in deployment states but none older than %d minutes",
            len(stuck_hubs),
            STUCK_THRESHOLD_MINUTES,
        )
        return results

    logger.warning(
        "Found %d exit hubs stuck in deployment - recovering...",
        len(actually_stuck),
    )

    for hub in actually_stuck:
        exit_hub_id = hub.get("exit_hub_id")
        origin_id = hub.get("origin_id")
        status = hub.get("status")
        instance_id = hub.get("instance_id")

        logger.info(
            "Recovering stuck deployment: exit_hub_id=%s, origin_id=%s, status=%s, instance_id=%s",
            exit_hub_id,
            origin_id,
            status,
            instance_id,
        )

        try:
            # Mark as failed - the orphan sweeper will clean up any cloud instances
            error_msg = f"Deployment interrupted by TPM restart (was in {status} state)"

            exit_hub_repo.update_exit_hub(
                exit_hub_id,
                status="failed",
                last_error=error_msg,
                force=True,
            )

            # Update metadata with recovery note
            exit_hub_repo.update_metadata(exit_hub_id, {
                "recovery_note": f"Recovered at startup - was stuck in {status}",
                "recovered_at": datetime.now(timezone.utc).isoformat(),
            })

            # Note: SSE notification is not sent here since notifier isn't wired yet at startup.
            # The webapp will see the "failed" status when it queries the exit hub.

            results["recovered"] += 1
            results["details"].append({
                "exit_hub_id": exit_hub_id,
                "origin_id": origin_id,
                "previous_status": status,
                "had_instance": bool(instance_id),
                "action": "marked_failed",
            })

            logger.info(
                "Recovered stuck deployment %s (was %s, had_instance=%s)",
                exit_hub_id,
                status,
                bool(instance_id),
            )

        except Exception as exc:
            logger.error(
                "Failed to recover stuck deployment %s: %s",
                exit_hub_id,
                exc,
                exc_info=True,
            )
            results["errors"] += 1
            results["details"].append({
                "exit_hub_id": exit_hub_id,
                "action": "error",
                "reason": str(exc),
            })

    logger.info(
        "Deployment recovery complete: recovered=%d, errors=%d",
        results["recovered"],
        results["errors"],
    )

    return results
