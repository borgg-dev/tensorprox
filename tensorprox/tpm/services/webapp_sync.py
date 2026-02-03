"""Webapp Sync Service - Sync origin deletions from webapp.

When a validator goes offline, customers may delete origins via webapp.
This service syncs with webapp on startup to find and cleanup orphaned origins.

Flow:
1. TPM starts after being offline
2. Queries webapp for all origins owned by this TPM
3. Compares against local TPM database
4. Terminates any origins that webapp has deleted

This ensures no billing continues for deleted origins and no orphaned
AWS resources remain after validator downtime.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import requests

from shared.config import get_settings
from shared.utils.logging import get_logger

logger = get_logger(__name__)


def get_webapp_base_url() -> Optional[str]:
    """Get webapp API base URL from environment.

    Configuration:
        Environment: TP_WEBAPP_URL=https://api.tensorprox.io
    """
    webapp_url = os.environ.get("TP_WEBAPP_URL")
    if webapp_url:
        return webapp_url.rstrip("/")

    return None


def get_webapp_api_key() -> Optional[str]:
    """Get API key for webapp authentication."""
    api_key = os.environ.get("TP_WEBAPP_API_KEY")
    if api_key:
        return api_key

    return None


def query_webapp_origins(validator_uid: int) -> List[Dict[str, Any]]:
    """Query webapp for origins owned by this TPM.

    Args:
        validator_uid: This TPM's validator UID

    Returns:
        List of origin records from webapp, each containing:
        - origin_id: str
        - status: str ('active', 'deleted', etc.)
        - deleted_at: Optional[str] (ISO timestamp)
    """
    base_url = get_webapp_base_url()
    api_key = get_webapp_api_key()

    if not base_url:
        logger.warning("Webapp sync: no webapp URL configured")
        return []

    url = f"{base_url}/api/tpm/origins"
    headers = {"Content-Type": "application/json"}

    if api_key:
        headers["X-TPM-Secret"] = api_key

    params = {"validator_uid": validator_uid, "include_deleted": "true"}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=(10, 30))
        resp.raise_for_status()
        data = resp.json()
        return data.get("origins", [])
    except requests.exceptions.RequestException as e:
        logger.error("Webapp sync: failed to query origins: %s", e)
        return []


def sync_deletions_from_webapp(validator_uid: int) -> Dict[str, Any]:
    """Sync origin deletions from webapp to TPM.

    Called at startup to find origins that webapp deleted while TPM was offline.

    Args:
        validator_uid: This TPM's validator UID

    Returns:
        Dict with counts: synced, errors, skipped
    """
    from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository
    from tensorprox.tpm.services.exithub_manager import exithub_manager

    results = {
        "synced": 0,
        "errors": 0,
        "skipped": 0,
        "details": [],
    }

    # Get origins from webapp
    webapp_origins = query_webapp_origins(validator_uid)
    if not webapp_origins:
        logger.info("Webapp sync: no origins returned from webapp")
        return results

    # Build set of deleted origin IDs from webapp
    deleted_origin_ids: Set[str] = set()
    for origin in webapp_origins:
        if origin.get("status") == "deleted" or origin.get("deleted_at"):
            deleted_origin_ids.add(origin.get("origin_id"))

    if not deleted_origin_ids:
        logger.info("Webapp sync: no deleted origins found in webapp")
        return results

    logger.info(
        "Webapp sync: found %d deleted origins in webapp, checking TPM...",
        len(deleted_origin_ids)
    )

    # Check TPM database for these origins
    repo = ExitHubRepository()

    for origin_id in deleted_origin_ids:
        try:
            exit_hub = repo.get_exit_hub_by_origin(origin_id)

            if not exit_hub:
                # Not in TPM - already cleaned up
                results["skipped"] += 1
                continue

            status = exit_hub.get("status", "")
            if status in ("terminated", "cancelled"):
                # Already terminated
                results["skipped"] += 1
                continue

            # Origin exists in TPM but deleted in webapp - terminate it
            exit_hub_id = exit_hub.get("exit_hub_id")
            logger.warning(
                "Webapp sync: terminating orphaned exit hub %s (origin=%s, status=%s) - "
                "deleted in webapp while TPM was offline",
                exit_hub_id, origin_id, status
            )

            try:
                exithub_manager.terminate_exit_hub(exit_hub_id, purge=True)
                results["synced"] += 1
                results["details"].append({
                    "origin_id": origin_id,
                    "exit_hub_id": exit_hub_id,
                    "action": "terminated",
                })
            except Exception as e:
                logger.error(
                    "Webapp sync: failed to terminate exit hub %s: %s",
                    exit_hub_id, e
                )
                results["errors"] += 1
                results["details"].append({
                    "origin_id": origin_id,
                    "exit_hub_id": exit_hub_id,
                    "action": "error",
                    "error": str(e),
                })

        except Exception as e:
            logger.error("Webapp sync: error processing origin %s: %s", origin_id, e)
            results["errors"] += 1

    logger.info(
        "Webapp sync complete: synced=%d, errors=%d, skipped=%d",
        results["synced"], results["errors"], results["skipped"]
    )

    return results


def run_webapp_sync() -> Dict[str, Any]:
    """Run webapp sync using the current validator UID.

    Called from TPM startup tasks.

    Required configuration:
        TP_WEBAPP_URL: Webapp's external URL (e.g., https://api.tensorprox.io)
        TP_WEBAPP_API_KEY: Shared secret matching webapp's TPM_INTERNAL_SECRET
    """
    from tensorprox.tpm.app import get_validator_uid

    validator_uid = get_validator_uid()
    if validator_uid is None:
        logger.warning("Webapp sync: no validator UID configured, skipping")
        return {"error": "no_validator_uid"}

    # Check if webapp URL is configured
    webapp_url = get_webapp_base_url()
    if not webapp_url:
        logger.info(
            "Webapp sync: TP_WEBAPP_URL not configured, skipping. "
            "This is required for production to sync deletions."
        )
        return {"error": "no_webapp_url", "skipped": True}

    return sync_deletions_from_webapp(validator_uid)
