"""Placement helper for exit hubs based on miner location and optional hints."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from shared.utils.logging import get_logger

logger = get_logger(__name__)


def select_exit_hub_location(
    *,
    miner_record: Optional[Dict[str, Any]],
    requested_provider: Optional[str],
    requested_region: Optional[str],
    default_provider: str,
    default_region: str,
) -> Tuple[str, str, str]:
    """
    Choose exit hub provider/region given miner location and optional request hints.

    Preference:
    1) Explicit request (provider/region) if both provided.
    2) Miner provider/region if present.
    3) Defaults from tp.env.
    """
    miner_metadata = (miner_record or {}).get("metadata") or {}
    miner_provider = miner_metadata.get("provider")
    miner_region = miner_metadata.get("region")

    provider = requested_provider or miner_provider or default_provider
    region = requested_region or miner_region or default_region

    if requested_provider and requested_region:
        reason = f"requested:{requested_provider}/{requested_region}"
    elif miner_provider and miner_region:
        reason = f"miner:{miner_provider}/{miner_region}"
    else:
        reason = f"default:{default_provider}/{default_region}"

    logger.info(
        "Exit hub placement selected provider=%s region=%s reason=%s",
        provider,
        region,
        reason,
    )
    return provider, region, reason
