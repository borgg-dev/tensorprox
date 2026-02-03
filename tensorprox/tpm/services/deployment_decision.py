"""Deployment Decision Logic for Shard-Aware Origin Placement.

PURPOSE:
    Determines optimal miner + shard for new origin deployments based on:
    - Validator audit scores (miners with score >= 0.8 preferred)
    - Existing shard availability (prefer existing over new)
    - Geographic proximity (must be within 1000km threshold)
    - Shard capacity (5 origins per shard default)

SIMPLIFIED 2-PHASE ALGORITHM:
    Phase 1: Find existing NEARBY shard (same region OR within 1000km proximity threshold)
             from highest-scored miner (score >= 0.8)
    Phase 2: Best-scored miner (score >= 0.8) deploys NEW shard in the target region

    SCORE FALLBACK:
    If no miners have EMA score >= 0.8, the system falls back to using
    aggregated_score >= 0.8 for ALL miners. This handles fresh networks
    where EMA hasn't been established yet.

KEY CONSTRAINTS:
    - Shards must be within 1000km of the target region to be considered
    - This prevents assigning distant shards that would cause high latency
    - If no nearby shards exist, a new shard is deployed in the target region

USAGE:
    from tensorprox.tpm.services.deployment_decision import (
        select_deployment_target,
        MinerUnreachableError,
        NoCapacityError,
        get_miner_connection_info,
    )

    target = select_deployment_target(
        preferred_region="eu-central-1",
        registry=miner_registry,
    )
    # target.miner_id, target.shard_id, target.needs_new_shard

GEOGRAPHIC LOGIC:
    All geographic calculations (coordinates, distances, region matching)
    are delegated to services/geolocation.py for clean separation of concerns.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, List
from uuid import UUID

import requests

from shared.utils.logging import get_logger
from shared.database import get_connection
from tensorprox.tpm.repositories import SystemErrorRepository
from tensorprox.tpm.services.geolocation import get_regions_by_proximity, haversine_distance, REGION_COORDINATES

if TYPE_CHECKING:
    from tensorprox.tpm.services.miner_registry import MinerRegistry

logger = get_logger(__name__)

# Module-level repository for system error logging
_system_error_repo = SystemErrorRepository()

# =============================================================================
# Constants
# =============================================================================

DEFAULT_ORIGINS_PER_SHARD = 5
DEFAULT_EIPS_PER_REGION = 50
MIN_AUDIT_SCORE = 0.8  # Minimum score for assignment (EMA preferred, fallback to aggregated)
PROXIMITY_THRESHOLD_KM = 1000  # Max distance for "nearby" shard (same continent, minimal latency)
DEFAULT_MINER_PORT = 8000


# =============================================================================
# Helper Functions
# =============================================================================

def get_miner_connection_info(miner: dict) -> tuple[str, int]:
    """Extract connection IP and port from miner record.

    Looks up emn_ip and emn_port from metadata, falling back to current_ip
    and default port if not present.

    Args:
        miner: Miner record dict with current_ip and optional metadata

    Returns:
        Tuple of (ip_address, port)
    """
    metadata = miner.get("metadata") or {}

    # Prefer emn_ip from metadata, fall back to current_ip
    ip = metadata.get("emn_ip") or miner.get("current_ip") or "127.0.0.1"

    # Prefer emn_port from metadata, fall back to default
    port = metadata.get("emn_port") or DEFAULT_MINER_PORT

    return str(ip), int(port)


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class DeploymentTarget:
    """Result of deployment target selection."""

    miner_id: str
    miner_ip: str
    miner_port: int
    region: str
    shard_id: str
    needs_new_shard: bool
    capacity_info: dict


# =============================================================================
# Exceptions
# =============================================================================

class DeploymentDecisionError(Exception):
    """Base exception for deployment decision failures."""

    pass


class MinerUnreachableError(DeploymentDecisionError):
    """Could not query miner for shard capacity."""

    def __init__(self, miner_id: str, reason: str):
        self.miner_id = miner_id
        self.reason = reason
        super().__init__(f"Miner {miner_id} unreachable: {reason}")


def _log_miner_unreachable(
    miner_id: str,
    miner_ip: str | None,
    reason: str,
    http_status: int | None = None,
) -> None:
    """Log miner unreachable error to system_errors table.

    Args:
        miner_id: UUID of the miner
        miner_ip: IP address of the miner (may be None if unknown)
        reason: Short reason code for the failure
        http_status: HTTP status code (if applicable)
    """
    context: dict = {
        "miner_id": str(miner_id),
        "reason": reason,
    }
    if miner_ip:
        context["miner_ip"] = miner_ip
    if http_status is not None:
        context["http_status"] = http_status

    try:
        _system_error_repo.log_error(
            error_source="target_selection",
            error_code="miner_unreachable",
            error_message=f"Miner {miner_id} unreachable: {reason}",
            context=context,
            miner_id=UUID(miner_id),
        )
    except Exception as exc:
        # Don't let logging failure prevent the main error from being raised
        logger.warning(
            "Failed to log miner unreachable error to DB: %s",
            exc,
        )


class NoCapacityError(DeploymentDecisionError):
    """All regions exhausted - no capacity available."""

    def __init__(self, tried_regions: list[str], message: str | None = None):
        self.tried_regions = tried_regions
        msg = message or f"No capacity in any region. Tried: {tried_regions}"
        super().__init__(msg)


# =============================================================================
# Miner Query
# =============================================================================

def query_miner_shards(
    miner_id: str,
    miner_ip: str,
    registry: MinerRegistry,
    timeout: tuple[int, int] = (3, 10),
    miner_port: int = DEFAULT_MINER_PORT,
) -> list[dict]:
    """Query miner for all shards and their capacity.

    Args:
        miner_id: Miner UUID
        miner_ip: Miner IP address
        registry: MinerRegistry for secret lookup
        timeout: (connect_timeout, read_timeout) in seconds
        miner_port: Port the miner control plane is listening on

    Returns:
        List of shard dicts with keys: shard_id, region, status, origins_count

    Raises:
        MinerUnreachableError: If miner cannot be queried
    """
    try:
        secret = registry.get_plaintext_secret(miner_id)
    except Exception as exc:
        logger.error("Failed to load miner secret for %s: %s", miner_id, exc)
        _log_miner_unreachable(miner_id, miner_ip, "secret_lookup_failed")
        raise MinerUnreachableError(miner_id, "secret_lookup_failed") from exc

    url = f"http://{miner_ip}:{miner_port}/api/v1/admin/shards"
    headers = {"Authorization": f"Bearer {secret}"}

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        logger.warning("Miner %s unreachable at %s: %s", miner_id, url, exc)
        _log_miner_unreachable(miner_id, miner_ip, f"request_failed: {exc}")
        raise MinerUnreachableError(miner_id, f"request_failed: {exc}") from exc

    if resp.status_code == 401:
        _log_miner_unreachable(miner_id, miner_ip, "auth_failed", http_status=401)
        raise MinerUnreachableError(miner_id, "auth_failed")
    if resp.status_code >= 400:
        reason = f"http_{resp.status_code}: {resp.text[:100]}"
        _log_miner_unreachable(miner_id, miner_ip, reason, http_status=resp.status_code)
        raise MinerUnreachableError(miner_id, reason)

    try:
        payload = resp.json()
    except ValueError as exc:
        _log_miner_unreachable(miner_id, miner_ip, f"invalid_json: {exc}")
        raise MinerUnreachableError(miner_id, f"invalid_json: {exc}") from exc

    if payload.get("status") != "success":
        _log_miner_unreachable(miner_id, miner_ip, f"api_error: {payload}")
        raise MinerUnreachableError(miner_id, f"api_error: {payload}")

    shards = payload.get("shards", [])

    # Sync shards to TPM database for local caching and region derivation
    from tensorprox.tpm.repositories.shard_repository import ShardRepository
    shard_repo = ShardRepository()
    shard_repo.sync_shards_from_miner(UUID(miner_id), shards)

    logger.info(
        "Queried miner %s: found %d shards (synced to TPM database)",
        miner_id,
        len(shards),
    )

    return shards


# =============================================================================
# Shard Selection
# =============================================================================

def _is_shard_ready(shard: dict) -> bool:
    """Check if shard nodes are ready.

    Args:
        shard: Shard dict from miner response

    Returns:
        True if active node is ready, False otherwise.

    Supports two miner response formats:
        - List format: nodes: [{node_id, ready, role}, ...] (current miner API)
        - Dict format: nodes: {ready: bool} (legacy/backward compat)
    """
    shard_id = shard.get("shard_id", "unknown")
    nodes = shard.get("nodes")

    # No nodes field at all
    if nodes is None:
        logger.warning(
            "Shard %s missing nodes field, marking NOT ready",
            shard_id
        )
        return False

    # List format: [{node_id, ready, role}, ...] - check active node
    if isinstance(nodes, list):
        if not nodes:
            logger.warning(
                "Shard %s has empty nodes list, marking NOT ready",
                shard_id
            )
            return False

        # Find active node and check its ready status
        for node in nodes:
            if isinstance(node, dict) and node.get("role") == "active":
                ready = node.get("ready")
                if ready is None:
                    logger.warning(
                        "Shard %s active node missing ready field, marking NOT ready",
                        shard_id
                    )
                    return False
                return bool(ready)

        # No active node found - check if any node is ready
        logger.debug(
            "Shard %s has no node with role=active, checking all nodes",
            shard_id
        )
        for node in nodes:
            if isinstance(node, dict) and node.get("ready"):
                return True

        logger.warning(
            "Shard %s has no ready nodes, marking NOT ready",
            shard_id
        )
        return False

    # Dict format: {ready: bool} - legacy/backward compat
    if isinstance(nodes, dict):
        ready = nodes.get("ready")
        if ready is None:
            logger.warning(
                "Shard %s missing nodes.ready field, marking NOT ready",
                shard_id
            )
            return False
        return bool(ready)

    # Unknown format
    logger.warning(
        "Shard %s has invalid nodes field (type=%s), marking NOT ready",
        shard_id,
        type(nodes).__name__
    )
    return False


def _check_hard_capacity(shard: dict) -> tuple[bool, str]:
    """Check if shard has hard capacity available.

    Args:
        shard: Shard dict from miner response

    Returns:
        Tuple of (has_capacity, reason_string)
        has_capacity=True if:
          - hard_capacity.origin_slots_available >= 1, OR
          - capacity_model in {"unbounded", "unknown"}, OR
          - hard_capacity missing (backward compat)
          - EIP availability check passes (eip_available >= 1 or not present)
    """
    hard_capacity = shard.get("hard_capacity")
    shard_id = shard.get("shard_id", "unknown")

    # Backward compatibility: missing hard_capacity means use policy-only
    if hard_capacity is None:
        logger.debug(
            "Shard %s missing hard_capacity field, using policy-only (backward compat)",
            shard_id
        )
        return True, "backward_compat"

    if not isinstance(hard_capacity, dict):
        logger.warning(
            "Shard %s has invalid hard_capacity field (not dict), assuming available",
            shard_id
        )
        return True, "invalid_field"

    capacity_model = hard_capacity.get("capacity_model")
    slots_available = hard_capacity.get("origin_slots_available")

    # Unbounded or unknown capacity models bypass slot checks
    if capacity_model in {"unbounded", "unknown"}:
        logger.debug(
            "Shard %s has capacity_model=%s, bypassing slot check",
            shard_id,
            capacity_model
        )
        return True, f"capacity_model_{capacity_model}"

    # Check available slots
    if slots_available is None:
        logger.warning(
            "Shard %s missing origin_slots_available, assuming unavailable",
            shard_id
        )
        return False, "missing_slots_available"

    if not isinstance(slots_available, (int, float)):
        logger.warning(
            "Shard %s has invalid origin_slots_available type, assuming unavailable",
            shard_id
        )
        return False, "invalid_slots_type"

    # Check EIP availability (new field from miner)
    # Backward compatibility: if not present, assume available
    eip_available = hard_capacity.get("eip_available")
    if eip_available is not None:
        if isinstance(eip_available, (int, float)) and eip_available < 1:
            logger.debug(
                "Shard %s has no EIPs available (eip_available=%d), marking unavailable",
                shard_id,
                eip_available
            )
            return False, "no_eips_available"

    has_capacity = slots_available >= 1
    reason = f"slots_available={slots_available}" if has_capacity else "no_slots"

    logger.debug(
        "Shard %s hard capacity check: available=%d, eip_available=%s, result=%s",
        shard_id,
        slots_available,
        eip_available,
        "PASS" if has_capacity else "FAIL"
    )

    return has_capacity, reason


def generate_next_shard_id(region: str, existing_shards: list[dict], miner_id: str = "") -> str:
    """Generate next shard ID for a region.

    Convention (includes miner_id prefix to prevent cross-miner conflicts):
    - First shard: region-{miner_id_prefix} (e.g., "eu-central-1-beaf4b50")
    - Subsequent: region-{miner_id_prefix}-N (e.g., "eu-central-1-beaf4b50-2")

    Args:
        region: AWS region name
        existing_shards: List of existing shards in this region for this miner
        miner_id: Miner UUID to include in shard_id (prevents cross-miner conflicts)

    Returns:
        New shard ID string
    """
    # Include miner_id prefix to prevent cross-miner shard_id conflicts
    miner_prefix = miner_id[:8] if miner_id else "unknown"
    base_id = f"{region}-{miner_prefix}"

    if not existing_shards:
        return base_id

    # Count existing shards with this base pattern
    max_suffix = 0
    for shard in existing_shards:
        shard_id = shard.get("shard_id", "")
        if shard_id == base_id:
            max_suffix = max(max_suffix, 1)  # First shard counts as 1
            continue

        # Extract numeric suffix: "eu-central-1-beaf4b50-2" -> "2"
        if shard_id.startswith(base_id) and len(shard_id) > len(base_id):
            suffix_part = shard_id[len(base_id):]
            if suffix_part.startswith("-") and suffix_part[1:].isdigit():
                suffix_num = int(suffix_part[1:])
                max_suffix = max(max_suffix, suffix_num)

    # Generate new ID
    if max_suffix == 0:
        new_id = base_id  # First shard for this miner in this region
    else:
        new_id = f"{base_id}-{max_suffix + 1}"

    logger.debug(
        "Generated shard ID %s (region=%s, miner=%s, existing=%d)",
        new_id,
        region,
        miner_prefix,
        len(existing_shards),
    )
    return new_id


def _get_scored_miners(min_score: float = MIN_AUDIT_SCORE) -> List[dict]:
    """Get miners from subnet_miners table sorted by audit score.

    Args:
        min_score: Minimum validator score required (default: 0.8)

    Returns:
        List of miner dicts with miner_id, miner_uid, score, region, etc.
        Sorted by ema_score descending.
    """
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            # First try EMA score (more reliable/stable)
            cur.execute("""
                SELECT
                    miner_id,
                    miner_uid,
                    hotkey,
                    ema_score as score,
                    aggregated_score,
                    region,
                    scrubber_ip,
                    is_available,
                    origins_assigned,
                    max_origins
                FROM subnet_miners
                WHERE state = 'active'
                  AND ema_score >= %s
                ORDER BY ema_score DESC
            """, (min_score,))

            rows = cur.fetchall()

            # Fallback: if no miners have EMA >= threshold, use last raw audit score.
            # This handles EMA warm-up (cold start from zero) where EMA is still building
            # but the miner's latest audit proves it can perform.
            if not rows:
                logger.info(
                    "No miners with ema_score >= %.2f, falling back to last_audit_score",
                    min_score
                )
                cur.execute("""
                    SELECT
                        miner_id,
                        miner_uid,
                        hotkey,
                        last_audit_score as score,
                        aggregated_score,
                        region,
                        scrubber_ip,
                        is_available,
                        origins_assigned,
                        max_origins
                    FROM subnet_miners
                    WHERE state = 'active'
                      AND last_audit_score >= %s
                    ORDER BY last_audit_score DESC
                """, (min_score,))
                rows = cur.fetchall()

            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        logger.warning("Could not fetch scored miners from subnet_miners: %s", e)
        return []
    finally:
        if conn:
            conn.close()


def _calculate_shard_distance(shard_region: str, target_region: str) -> float:
    """Calculate distance between shard region and target region.

    Args:
        shard_region: Region of the shard
        target_region: Target/preferred region

    Returns:
        Distance in km, or float('inf') if regions unknown
    """
    # Try AWS coordinates first, then Linode
    shard_coords = REGION_COORDINATES.get("aws", {}).get(shard_region)
    if not shard_coords:
        shard_coords = REGION_COORDINATES.get("linode", {}).get(shard_region)

    target_coords = REGION_COORDINATES.get("aws", {}).get(target_region)
    if not target_coords:
        target_coords = REGION_COORDINATES.get("linode", {}).get(target_region)

    if not shard_coords or not target_coords:
        return float('inf')

    return haversine_distance(shard_coords[0], shard_coords[1], target_coords[0], target_coords[1])


def _create_deployment_target_with_registration(
    registry: MinerRegistry,
    miner_id: str,
    miner_ip: str,
    **kwargs
) -> DeploymentTarget:
    """Helper to create DeploymentTarget and ensure miner is registered.

    In decentralized mode, miners may not be explicitly registered in
    tensorprox_miners table. This ensures they're registered with a secret
    so TPM can authenticate for delete operations later.
    """
    # Ensure miner is registered with secret for authentication
    try:
        registry.ensure_miner_registered(miner_id=miner_id, miner_ip=miner_ip)
    except Exception as exc:
        logger.warning(
            "Failed to ensure miner %s is registered: %s",
            miner_id, exc
        )

    return DeploymentTarget(
        miner_id=miner_id,
        miner_ip=miner_ip,
        **kwargs
    )


def select_deployment_target(
    preferred_region: str,
    *,
    registry: MinerRegistry,
    origins_per_shard: int = DEFAULT_ORIGINS_PER_SHARD,
    eips_per_region: int = DEFAULT_EIPS_PER_REGION,
    excluded_shards: set[str] | None = None,
) -> DeploymentTarget:
    """Select optimal miner and shard for new origin deployment.

    SIMPLIFIED 2-PHASE ALGORITHM:
    Phase 1: Find existing shard in SAME region OR within 500km (proximity threshold)
    Phase 2: Deploy new shard in the preferred region

    SCORE SELECTION:
    Uses EMA score >= 0.8 for reliability. If no miners have sufficient EMA,
    falls back to aggregated_score >= 0.8 for all miners.

    Args:
        preferred_region: Desired AWS region for the origin
        registry: MinerRegistry for miner lookup and authentication
        origins_per_shard: Max origins per shard (default: 5)
        eips_per_region: Max EIPs per region (default: 50)
        excluded_shards: Set of shard IDs to skip

    Returns:
        DeploymentTarget with selected miner, region, shard_id

    Raises:
        MinerUnreachableError: No miners reachable
        NoCapacityError: No suitable miners/shards available
    """
    logger.info(
        "Selecting deployment target (2-phase): preferred_region=%s, "
        "proximity_threshold=%dkm, min_audit_score=%.2f, origins_per_shard=%d",
        preferred_region,
        PROXIMITY_THRESHOLD_KM,
        MIN_AUDIT_SCORE,
        origins_per_shard,
    )

    # Get miners sorted by audit score from validator leaderboard
    scored_miners = _get_scored_miners(MIN_AUDIT_SCORE)

    # Also get all registered miners from TPM for fallback
    registered_miners = registry.list_active_miners()

    if not scored_miners and not registered_miners:
        raise NoCapacityError([], "No miners available")

    logger.info(
        "Found %d scored miners (score >= %.2f), %d registered miners",
        len(scored_miners),
        MIN_AUDIT_SCORE,
        len(registered_miners),
    )

    # Build a map of miner_id -> score for quick lookup
    miner_scores = {m.get("miner_id"): m.get("score", 0) for m in scored_miners if m.get("miner_id")}

    # Collect candidate shards from scored miners (NEARBY ONLY - within 500km)
    nearby_candidates = []
    last_error: Exception | None = None
    best_miner_for_new_shard = None
    best_miner_score = 0

    # Query shards from all registered miners
    for miner in registered_miners:
        miner_id = str(miner.get("miner_id", ""))
        miner_ip, miner_port = get_miner_connection_info(miner)

        if not miner_id or not miner_ip:
            continue

        # Get audit score for this miner (0 if not in leaderboard)
        miner_score = miner_scores.get(miner_id, 0)

        # Track best miner for potential new shard deployment (Phase 2)
        if miner_score >= MIN_AUDIT_SCORE and miner_score > best_miner_score:
            best_miner_score = miner_score
            best_miner_for_new_shard = miner

        # Skip miners below minimum score for existing shards
        if miner_score < MIN_AUDIT_SCORE:
            logger.debug(
                "Miner %s has score %.2f < %.2f, skipping for Phase 1",
                miner_id, miner_score, MIN_AUDIT_SCORE
            )
            continue

        # Query this miner's shards
        try:
            shards = query_miner_shards(miner_id, miner_ip, registry, miner_port=miner_port)
        except MinerUnreachableError as e:
            logger.warning("Miner %s unreachable: %s", miner_id, e.reason)
            last_error = e
            continue

        # Evaluate each shard - ONLY consider PRODUCTION shards within proximity threshold
        # Audit shards are reserved for validator scoring and should not be used for customer origins
        for shard in shards:
            shard_id = shard.get("shard_id", "unknown")
            shard_region = shard.get("region", "")
            shard_type = shard.get("shard_type", "audit")  # Default to audit if not specified

            # Skip excluded shards
            if excluded_shards and shard_id in excluded_shards:
                continue

            # Skip audit shards - they are reserved for validator scoring only
            if shard_type == "audit":
                logger.debug("Shard %s is audit shard, skipping (reserved for validators)", shard_id)
                continue

            # Check shard readiness
            if not _is_shard_ready(shard):
                logger.debug("Shard %s not ready, skipping", shard_id)
                continue

            # Check capacity
            shard_origins = shard.get("origins_count", 0)
            if shard_origins >= origins_per_shard:
                logger.debug("Shard %s at capacity (%d/%d)", shard_id, shard_origins, origins_per_shard)
                continue

            has_hard_capacity, capacity_reason = _check_hard_capacity(shard)
            if not has_hard_capacity:
                logger.debug("Shard %s no hard capacity: %s", shard_id, capacity_reason)
                continue

            # Calculate distance to preferred region
            distance = _calculate_shard_distance(shard_region, preferred_region)
            is_same_region = (shard_region == preferred_region)

            # ONLY consider shards within proximity threshold (500km) or same region
            if not is_same_region and distance > PROXIMITY_THRESHOLD_KM:
                logger.debug(
                    "Shard %s too far (%.0f km > %d km threshold), skipping",
                    shard_id, distance, PROXIMITY_THRESHOLD_KM
                )
                continue

            nearby_candidates.append({
                "miner_id": miner_id,
                "miner_ip": miner_ip,
                "miner_port": miner_port,
                "miner_score": miner_score,
                "shard": shard,
                "shard_id": shard_id,
                "shard_region": shard_region,
                "shard_origins": shard_origins,
                "distance": distance,
                "is_same_region": is_same_region,
                "capacity_reason": capacity_reason,
            })

    logger.info(
        "Found %d nearby candidate shards (within %d km) from scored miners",
        len(nearby_candidates),
        PROXIMITY_THRESHOLD_KM,
    )

    # PHASE 1: Select from nearby candidates
    if nearby_candidates:
        # Sort by: same_region first (distance=0), then distance, then score (descending)
        nearby_candidates.sort(
            key=lambda c: (c["distance"], -c["miner_score"])
        )
        best = nearby_candidates[0]

        phase_desc = "same region" if best["is_same_region"] else f"{best['distance']:.0f}km away"
        logger.info(
            "PHASE 1 SUCCESS: Selected nearby existing shard (%s): "
            "miner=%s (score=%.2f), shard=%s, region=%s, origins=%d/%d",
            phase_desc,
            best["miner_id"],
            best["miner_score"],
            best["shard_id"],
            best["shard_region"],
            best["shard_origins"],
            origins_per_shard,
        )

        return _create_deployment_target_with_registration(
            registry=registry,
            miner_id=best["miner_id"],
            miner_ip=best["miner_ip"],
            miner_port=best["miner_port"],
            region=best["shard_region"],
            shard_id=best["shard_id"],
            needs_new_shard=False,
            capacity_info={
                "selection_phase": "nearby_existing",
                "miner_score": best["miner_score"],
                "origins_in_shard": best["shard_origins"],
                "distance_km": best["distance"],
                "proximity_threshold_km": PROXIMITY_THRESHOLD_KM,
            },
        )

    # PHASE 2: Deploy new shard in the preferred region
    if best_miner_for_new_shard and best_miner_score >= MIN_AUDIT_SCORE:
        miner_id = str(best_miner_for_new_shard.get("miner_id", ""))
        miner_ip, miner_port = get_miner_connection_info(best_miner_for_new_shard)

        # Query existing shards to generate next shard ID
        try:
            existing_shards = query_miner_shards(miner_id, miner_ip, registry, miner_port=miner_port)
        except MinerUnreachableError:
            existing_shards = []

        region_shards = [s for s in existing_shards if s.get("region") == preferred_region]
        new_shard_id = generate_next_shard_id(preferred_region, region_shards, miner_id=miner_id)

        logger.info(
            "PHASE 2: No nearby production shards available. Deploying new PRODUCTION shard in target region: "
            "miner=%s (score=%.2f), new_shard=%s, region=%s",
            miner_id,
            best_miner_score,
            new_shard_id,
            preferred_region,
        )

        return _create_deployment_target_with_registration(
            registry=registry,
            miner_id=miner_id,
            miner_ip=miner_ip,
            miner_port=miner_port,
            region=preferred_region,
            shard_id=new_shard_id,
            needs_new_shard=True,
            capacity_info={
                "selection_phase": "new_shard",
                "shard_type": "production",  # New shards for origins are always production
                "miner_score": best_miner_score,
                "existing_shards_in_region": len(region_shards),
                "proximity_threshold_km": PROXIMITY_THRESHOLD_KM,
            },
        )

    # No miners with score >= 0.8 available (neither EMA nor last_audit_score)
    logger.warning(
        "No miners with score >= %.2f available (checked both EMA and last_audit_score)",
        MIN_AUDIT_SCORE,
    )

    if last_error:
        raise last_error

    raise NoCapacityError([], "No capacity available")
