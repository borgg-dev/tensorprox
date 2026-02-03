"""Startup recovery for stuck terminations.

Recovers exit hubs stuck in 'miner_cleanup' status on startup.
This handles cases where:
- TPM crashed during termination
- Miner operation completed but notification was missed
- Network issues prevented status updates
"""

import requests
from datetime import datetime, timezone
from typing import List, Dict, Any

from shared.utils.logging import get_logger
from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository
from tensorprox.tpm.repositories.origin_repository import OriginRepository
from tensorprox.tpm.services.miner_registry import MinerRegistry
from tensorprox.tpm.services.client_registry import ClientRegistry

logger = get_logger(__name__)


def _check_origin_exists_on_miner(
    origin_id: str,
    miner_ip: str,
    miner_port: int,
    secret: str,
) -> bool:
    """Check if origin still exists on the miner.

    Returns True if origin exists, False if gone (404), None if check failed.
    """
    url = f"http://{miner_ip}:{miner_port}/api/v1/origins/{origin_id}"
    headers = {"Authorization": f"Bearer {secret}"}

    try:
        resp = requests.get(url, headers=headers, timeout=(5, 10))
        if resp.status_code == 404:
            return False  # Origin is gone
        elif resp.status_code == 200:
            return True  # Origin still exists
        else:
            logger.warning(
                "Origin check for %s returned unexpected status %s",
                origin_id, resp.status_code
            )
            return None  # Uncertain
    except Exception as exc:
        logger.warning("Origin check failed for %s: %s", origin_id, exc)
        return None  # Uncertain


def recover_stuck_terminations() -> Dict[str, Any]:
    """Recover exit hubs stuck in 'miner_cleanup' status.

    Called at startup to handle terminations that were interrupted.

    Returns:
        Dict with counts of recovered, still_stuck, and errors
    """
    results = {
        "recovered": 0,
        "still_stuck": 0,
        "errors": 0,
        "details": [],
    }

    # Initialize repositories
    exit_hub_repo = ExitHubRepository()
    miner_registry = MinerRegistry()
    client_registry = ClientRegistry()
    origin_repo = OriginRepository()

    # Find all exit hubs stuck in miner_cleanup
    stuck_hubs = exit_hub_repo.list_exit_hubs(statuses=["miner_cleanup"])

    if not stuck_hubs:
        logger.info("No exit hubs stuck in miner_cleanup status")
        return results

    logger.warning(
        "Found %d exit hubs stuck in miner_cleanup - recovering...",
        len(stuck_hubs)
    )

    for hub in stuck_hubs:
        exit_hub_id = hub.get("exit_hub_id")
        origin_id = hub.get("origin_id")
        miner_id = hub.get("miner_id")
        client_id = hub.get("client_id")

        if not all([exit_hub_id, origin_id, miner_id]):
            logger.error(
                "Stuck hub %s missing required fields (origin_id=%s, miner_id=%s)",
                exit_hub_id, origin_id, miner_id
            )
            results["errors"] += 1
            results["details"].append({
                "exit_hub_id": exit_hub_id,
                "action": "skip",
                "reason": "missing_fields",
            })
            continue

        # Get miner connection info
        miner = miner_registry.get_miner(miner_id)
        if not miner:
            logger.error("Stuck hub %s references unknown miner %s", exit_hub_id, miner_id)
            results["errors"] += 1
            results["details"].append({
                "exit_hub_id": exit_hub_id,
                "action": "skip",
                "reason": "unknown_miner",
            })
            continue

        miner_ip = miner.get("current_ip")
        miner_port = miner.get("port", 8000)
        secret = miner_registry.get_plaintext_secret(miner_id)

        if not miner_ip or not secret:
            logger.error(
                "Cannot check miner for stuck hub %s - missing ip or secret",
                exit_hub_id
            )
            results["errors"] += 1
            results["details"].append({
                "exit_hub_id": exit_hub_id,
                "action": "skip",
                "reason": "miner_unreachable",
            })
            continue

        # Check if origin still exists on miner
        origin_exists = _check_origin_exists_on_miner(
            origin_id, miner_ip, miner_port, secret
        )

        if origin_exists is False:
            # Origin is gone - termination actually completed
            logger.info(
                "Recovering stuck hub %s - origin %s is gone from miner",
                exit_hub_id, origin_id
            )

            try:
                # Update exit hub to terminated
                exit_hub_repo.update_exit_hub(
                    exit_hub_id,
                    status="terminated",
                    last_error=None,
                    force=True,
                )

                # Update metadata
                exit_hub_repo.update_metadata(exit_hub_id, {
                    "terminated_at": datetime.now(timezone.utc).isoformat(),
                    "recovery_note": "Recovered at startup - origin was already gone",
                })

                # Update client/origin registries
                if client_id:
                    try:
                        client_registry.mark_origin_terminated(client_id, origin_id)
                        origin_repo.clear_deployment(client_id, origin_id)
                    except Exception as exc:
                        logger.warning(
                            "Failed to update client registry for %s: %s",
                            origin_id, exc
                        )

                results["recovered"] += 1
                results["details"].append({
                    "exit_hub_id": exit_hub_id,
                    "origin_id": origin_id,
                    "action": "recovered",
                    "reason": "origin_gone_from_miner",
                })

            except Exception as exc:
                logger.error(
                    "Failed to recover stuck hub %s: %s",
                    exit_hub_id, exc, exc_info=True
                )
                results["errors"] += 1
                results["details"].append({
                    "exit_hub_id": exit_hub_id,
                    "action": "error",
                    "reason": str(exc),
                })

        elif origin_exists is True:
            # Origin still exists - termination didn't complete
            # Mark as failed so user can retry
            logger.warning(
                "Stuck hub %s - origin %s still exists on miner, marking as failed",
                exit_hub_id, origin_id
            )

            try:
                exit_hub_repo.update_exit_hub(
                    exit_hub_id,
                    status="failed",
                    last_error="Termination interrupted - origin still exists on miner",
                    force=True,
                )
                exit_hub_repo.update_metadata(exit_hub_id, {
                    "recovery_note": "Marked failed at startup - origin still exists",
                })

                results["still_stuck"] += 1
                results["details"].append({
                    "exit_hub_id": exit_hub_id,
                    "origin_id": origin_id,
                    "action": "marked_failed",
                    "reason": "origin_still_exists",
                })

            except Exception as exc:
                logger.error(
                    "Failed to mark stuck hub %s as failed: %s",
                    exit_hub_id, exc, exc_info=True
                )
                results["errors"] += 1

        else:
            # Could not determine origin status - leave as is for manual intervention
            logger.warning(
                "Cannot determine origin status for stuck hub %s - leaving in miner_cleanup",
                exit_hub_id
            )
            results["still_stuck"] += 1
            results["details"].append({
                "exit_hub_id": exit_hub_id,
                "origin_id": origin_id,
                "action": "unchanged",
                "reason": "origin_status_unknown",
            })

    logger.info(
        "Termination recovery complete: recovered=%d, still_stuck=%d, errors=%d",
        results["recovered"], results["still_stuck"], results["errors"]
    )

    return results
