"""
Shard Sync Service

Syncs shard state from miners to TPM database.
Ensures TPM's shard cache exactly matches what miners actually have.

Called on startup and can be called periodically to prevent stale records
from causing deployment failures.
"""
from __future__ import annotations

from typing import Any, Dict
from uuid import UUID

from shared.utils.logging import get_logger

logger = get_logger(__name__)


def sync_all_miner_shards() -> Dict[str, Any]:
    """
    Sync shards from all registered miners.

    For each miner:
    1. Query current shards from miner API
    2. Full reconciliation: add new, update existing, DELETE stale

    Returns:
        Dict with sync results:
        - synced: number of miners successfully synced
        - failed: number of miners that failed to sync
        - stale_removed: number of stale shard records removed
        - errors: list of error messages
    """
    from tensorprox.tpm.services.miner_registry import MinerRegistry
    from tensorprox.tpm.services.deployment_decision import query_miner_shards, get_miner_connection_info
    from tensorprox.tpm.repositories.shard_repository import ShardRepository

    results = {
        "synced": 0,
        "failed": 0,
        "stale_removed": 0,
        "errors": [],
    }

    try:
        registry = MinerRegistry()
        shard_repo = ShardRepository()

        # Get all registered miners
        miners = registry.repository.list_miners()
        if not miners:
            logger.info("No registered miners, skipping shard sync")
            return results

        logger.info("Starting shard sync for %d registered miners", len(miners))

        for miner in miners:
            miner_id = miner.get("miner_id")
            if not miner_id:
                continue

            try:
                # Get miner connection info
                miner_ip, miner_port = get_miner_connection_info(miner)
                if not miner_ip:
                    logger.warning("Miner %s has no IP, skipping sync", miner_id[:8])
                    continue

                # Get miner secret for auth
                try:
                    secret = registry.get_plaintext_secret(str(miner_id))
                except Exception:
                    logger.warning("Miner %s: no secret, skipping sync", miner_id[:8])
                    continue

                # Count existing shards before sync
                existing_shards = shard_repo.get_shards_for_miner(UUID(miner_id))
                existing_count = len(existing_shards)

                # Query and sync shards (this does full reconciliation including delete)
                try:
                    shards = query_miner_shards(miner_id, miner_ip, registry, miner_port=miner_port)
                    new_count = len(shards)

                    # Calculate stale removed (if existing > new after sync)
                    # Only count as stale if miner confirmed it has fewer shards
                    if existing_count > new_count:
                        results["stale_removed"] += existing_count - new_count

                    results["synced"] += 1
                    logger.info(
                        "Miner %s: synced %d shards (was %d in TPM cache)",
                        miner_id[:8], new_count, existing_count
                    )

                except Exception as e:
                    # Miner unreachable - DO NOT delete shards, just skip
                    # We only delete when miner confirms shards don't exist
                    logger.warning(
                        "Miner %s unreachable (%s), keeping %d cached shards (will retry later)",
                        miner_id[:8], str(e)[:50], existing_count
                    )
                    results["failed"] += 1
                    # Don't delete - miner might just be temporarily down

            except Exception as e:
                error_msg = f"Miner {miner_id[:8]}: {e}"
                results["errors"].append(error_msg)
                results["failed"] += 1
                logger.error("Shard sync error for miner %s: %s", miner_id[:8], e)

        logger.info(
            "Shard sync complete: %d synced, %d failed, %d stale removed",
            results["synced"], results["failed"], results["stale_removed"]
        )

    except Exception as e:
        logger.error("Shard sync failed: %s", e, exc_info=True)
        results["errors"].append(str(e))

    return results


def sync_miner_shards(miner_id: str) -> Dict[str, Any]:
    """
    Sync shards for a specific miner.

    Args:
        miner_id: UUID of the miner to sync

    Returns:
        Dict with sync results
    """
    from tensorprox.tpm.services.miner_registry import MinerRegistry
    from tensorprox.tpm.services.deployment_decision import query_miner_shards, get_miner_connection_info
    from tensorprox.tpm.repositories.shard_repository import ShardRepository

    results = {
        "synced": False,
        "shard_count": 0,
        "stale_removed": 0,
        "error": None,
    }

    try:
        registry = MinerRegistry()
        shard_repo = ShardRepository()

        # Get miner record
        miner = registry.repository.get_miner(miner_id)
        if not miner:
            results["error"] = "Miner not found"
            return results

        # Get connection info
        miner_ip, miner_port = get_miner_connection_info(miner)
        if not miner_ip:
            results["error"] = "Miner has no IP"
            return results

        # Count existing shards
        existing_shards = shard_repo.get_shards_for_miner(UUID(miner_id))
        existing_count = len(existing_shards)

        # Query and sync (registry handles secret lookup internally)
        shards = query_miner_shards(miner_id, miner_ip, registry, miner_port=miner_port)

        results["synced"] = True
        results["shard_count"] = len(shards)
        if existing_count > len(shards):
            results["stale_removed"] = existing_count - len(shards)

    except Exception as e:
        results["error"] = str(e)
        logger.error("Shard sync for miner %s failed: %s", miner_id[:8], e)

    return results
