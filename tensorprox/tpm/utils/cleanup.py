"""Shared cleanup helpers for failed deployments."""
from __future__ import annotations

from typing import Optional

from shared.utils.logging import get_logger

logger = get_logger(__name__)


def cleanup_failed_exit_hub(
    *,
    node,
    instance_id: Optional[str],
    origin_id: Optional[str],
    emn_ip: Optional[str],
    miner_id: Optional[str],
    shard_id: Optional[str] = None,
    lifecycle,
) -> None:
    """
    Best-effort teardown for failed exit-hub deployments.

    - Destroy cloud instance if instance_id is known.
    - Notify Miner/EMN to decommission origin if origin_id/emn_ip are provided.
    """
    # Destroy cloud instance
    if node and instance_id:
        try:
            destroyed = node.destroy(instance_id)
            if destroyed:
                logger.info("Cleanup: destroyed instance %s", instance_id)
            else:
                logger.warning("Cleanup: instance %s destroy returned false (may already be gone)", instance_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cleanup: failed to destroy instance %s: %s", instance_id, exc)

    # Decommission origin on Miner/EMN
    if origin_id and emn_ip:
        try:
            lifecycle.decommission_origin(
                origin_id=origin_id,
                emn_ip=emn_ip,
                miner_id=miner_id,
                shard_id=shard_id,
            )
            logger.info("Cleanup: decommissioned origin %s via EMN %s (shard_id=%s)", origin_id, emn_ip, shard_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Cleanup: failed to decommission origin %s via EMN %s: %s",
                origin_id,
                emn_ip,
                exc,
            )
