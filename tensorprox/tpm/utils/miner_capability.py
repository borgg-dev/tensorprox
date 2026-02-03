"""Miner capability probe before deployments.

Uses the authenticated Miner admin endpoint to verify the target Miner has
active scrubber nodes available before we attempt origin registration.

This module supports both synchronous node checking and asynchronous job-based
shard deployment with polling.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING, Dict, Tuple
from uuid import UUID

import requests

from shared.utils.logging import get_logger
from tensorprox.tpm.repositories import SystemErrorRepository
from tensorprox.tpm.services.miner_registry import MinerRegistry
from tensorprox.tpm.services.geolocation import (
    infer_provider_from_region,
    get_default_region_for_provider,
)

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)

# Default port for miner control plane
DEFAULT_MINER_PORT = 8000

# Module-level repository for system error logging
_system_error_repo = SystemErrorRepository()


def _log_capacity_check_failure(
    miner_id: str | None,
    miner_ip: str,
    reason: str,
    details: Dict,
) -> None:
    """Log capacity check failure to system_errors table.

    Args:
        miner_id: UUID of the miner (may be empty string if missing)
        miner_ip: IP address of the miner
        reason: Short reason code for the failure
        details: Additional details dict from the capacity check
    """
    context: dict = {
        "miner_id": str(miner_id) if miner_id else "unknown",
        "miner_ip": miner_ip,
        "reason": reason,
        "details": details,
    }

    try:
        _system_error_repo.log_error(
            error_source="capacity_check",
            error_code=reason,
            error_message=f"Miner {miner_id or 'unknown'} capacity check failed: {reason}",
            context=context,
            miner_id=UUID(miner_id) if miner_id else None,
        )
    except Exception as exc:
        # Don't let logging failure prevent the main error from being raised
        logger.warning(
            "Failed to log capacity check error to DB: %s",
            exc,
        )


def check_miner_capacity(
    miner_id: str,
    miner_ip: str,
    *,
    registry: MinerRegistry,
    min_nodes: int = 1,
    region: str | None = None,
    timeout: Tuple[int, int] = (3, 5),
    miner_port: int = DEFAULT_MINER_PORT,
) -> Tuple[bool, str, Dict]:
    """Return (ok, reason, payload) after probing /api/v1/admin/nodes.

    Reasons: unreachable, auth_failed, invalid_response, no_nodes,
    insufficient_nodes, exception.
    """
    if not miner_id:
        logger.error("Miner capacity check called without miner_id")
        _log_capacity_check_failure(None, miner_ip, "secret_lookup_failed", {})
        return False, "secret_lookup_failed", {}
    try:
        secret = registry.get_plaintext_secret(miner_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load miner secret for %s: %s", miner_id, exc)
        details = {"error": str(exc)}
        _log_capacity_check_failure(miner_id, miner_ip, "secret_lookup_failed", details)
        return False, "secret_lookup_failed", {}

    url = f"http://{miner_ip}:{miner_port}/api/v1/admin/nodes"
    headers = {"Authorization": f"Bearer {secret}"}

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as exc:  # noqa: BLE001
        logger.warning("Miner %s unreachable at %s: %s", miner_id, url, exc)
        details = {"error": str(exc)}
        _log_capacity_check_failure(miner_id, miner_ip, "unreachable", details)
        return False, "unreachable", {"error": str(exc)}

    if resp.status_code == 401:
        details = {"status_code": resp.status_code, "body": resp.text}
        _log_capacity_check_failure(miner_id, miner_ip, "auth_failed", details)
        return False, "auth_failed", {"status_code": resp.status_code, "body": resp.text}
    if resp.status_code >= 400:
        details = {"status_code": resp.status_code, "body": resp.text}
        _log_capacity_check_failure(miner_id, miner_ip, "http_error", details)
        return False, "http_error", {"status_code": resp.status_code, "body": resp.text}

    try:
        payload = resp.json()
    except ValueError as exc:  # noqa: BLE001
        details = {"error": str(exc), "body": resp.text}
        _log_capacity_check_failure(miner_id, miner_ip, "invalid_response", details)
        return False, "invalid_response", {"error": str(exc), "body": resp.text}

    if payload.get("status") != "success":
        _log_capacity_check_failure(miner_id, miner_ip, "invalid_response", payload)
        return False, "invalid_response", payload

    nodes = payload.get("nodes") or []
    # Filter nodes by region if provided; fallback to reported count otherwise.
    if nodes:
        filtered = [
            n for n in nodes
            if region is None or str(n.get("region")) == str(region)
        ]
        count = len(filtered)
        payload["count"] = count
    else:
        count = payload.get("count", 0) or 0
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 0

    if count < min_nodes:
        _log_capacity_check_failure(miner_id, miner_ip, "insufficient_nodes", payload)
        return False, "insufficient_nodes", payload

    logger.info(
        "Miner %s capacity OK via /admin/nodes (count=%s, min_required=%s, region=%s)",
        miner_id,
        count,
        min_nodes,
        region or "any",
    )
    return True, "ok", payload


def request_shard_deploy(
    miner_id: str,
    miner_ip: str,
    region: str,
    shard_id: str | None,
    *,
    registry: MinerRegistry,
    timeout: Tuple[int, int] = (5, 360),
    miner_port: int = DEFAULT_MINER_PORT,
    shard_type: str = "production",
) -> Tuple[bool, str, str | None, str | None]:
    """Request shard deployment via POST /api/v1/admin/shards.

    Args:
        miner_id: Miner UUID
        miner_ip: Miner IP address
        region: AWS region for shard deployment
        shard_id: Optional explicit shard ID (defaults to region if not provided)
        registry: MinerRegistry for secret lookup
        timeout: (connect_timeout, read_timeout) for HTTP request
        miner_port: Port the miner control plane is listening on
        shard_type: 'audit' for validator scoring, 'production' for customer origins (default)

    Returns:
        (ok, reason, job_id, shard_id)

        Reasons:
        - "secret_lookup_failed": Failed to retrieve miner secret
        - "already_exists": Shard already deployed and ready (200 response)
        - "accepted": Deploy job accepted (202 response)
        - "already_running": Deploy already in progress (409 response)
        - "request_error": Network or connection error
        - "auth_failed": 401 authentication error
        - "http_error": Other HTTP error (4xx/5xx)
        - "invalid_response": Malformed JSON or unexpected structure
    """
    try:
        secret = registry.get_plaintext_secret(miner_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load miner secret for %s: %s", miner_id, exc)
        return False, "secret_lookup_failed", None, None

    url = f"http://{miner_ip}:{miner_port}/api/v1/admin/shards"
    headers = {"Authorization": f"Bearer {secret}"}
    request_shard_id = shard_id or region
    payload = {"region": region, "shard_id": request_shard_id, "shard_type": shard_type}

    try:
        logger.info(
            "Requesting shard deploy on miner %s: region=%s, shard_id=%s",
            miner_id, region, request_shard_id
        )
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    except requests.RequestException as exc:  # noqa: BLE001
        logger.error("Miner %s shard deploy request failed: %s", miner_id, exc)
        return False, "request_error", None, None

    # Handle authentication failure
    if resp.status_code == 401:
        logger.error("Miner %s shard deploy auth failed", miner_id)
        return False, "auth_failed", None, None

    # Handle 200: Shard already exists and is ready
    if resp.status_code == 200:
        try:
            resp_data = resp.json()
            returned_shard_id = resp_data.get("shard", {}).get("shard_id") or request_shard_id
            logger.info("Miner %s shard already exists: %s", miner_id, returned_shard_id)
            return True, "already_exists", None, returned_shard_id
        except Exception as exc:  # noqa: BLE001
            logger.warning("Miner %s returned 200 but invalid JSON: %s", miner_id, exc)
            return False, "invalid_response", None, None

    # Handle 202: Deploy job accepted
    if resp.status_code == 202:
        try:
            resp_data = resp.json()
            if resp_data.get("status") != "accepted":
                logger.error("Miner %s 202 response missing 'accepted' status", miner_id)
                return False, "invalid_response", None, None

            job_id = resp_data.get("job_id")
            returned_shard_id = resp_data.get("shard_id") or request_shard_id

            if not job_id:
                logger.error("Miner %s 202 response missing job_id", miner_id)
                return False, "invalid_response", None, None

            logger.info(
                "Miner %s accepted shard deploy: job_id=%s, shard_id=%s",
                miner_id, job_id, returned_shard_id
            )
            return True, "accepted", job_id, returned_shard_id
        except Exception as exc:  # noqa: BLE001
            logger.error("Miner %s 202 response parse error: %s", miner_id, exc)
            return False, "invalid_response", None, None

    # Handle 409: Deploy already running for this shard
    if resp.status_code == 409:
        try:
            resp_data = resp.json()
            job_id = resp_data.get("job_id")
            returned_shard_id = resp_data.get("shard_id") or request_shard_id

            if job_id:
                logger.info(
                    "Miner %s shard deploy already running: job_id=%s, shard_id=%s",
                    miner_id, job_id, returned_shard_id
                )
                return True, "already_running", job_id, returned_shard_id
            else:
                logger.warning("Miner %s 409 response missing job_id", miner_id)
                return False, "invalid_response", None, None
        except Exception as exc:  # noqa: BLE001
            logger.warning("Miner %s 409 response parse error: %s", miner_id, exc)
            return False, "invalid_response", None, None

    # Handle other HTTP errors
    error_body = resp.text[:200] if resp.text else "no body"
    logger.error(
        "Miner %s shard deploy returned %s: %s",
        miner_id, resp.status_code, error_body
    )
    return False, "http_error", None, None


def wait_for_job(
    miner_id: str,
    miner_ip: str,
    job_id: str,
    *,
    registry: MinerRegistry,
    timeout_seconds: int = 360,
    poll_interval: int = 15,
    miner_port: int = DEFAULT_MINER_PORT,
) -> Tuple[bool, str, str | None]:
    """Poll GET /api/v1/admin/jobs/<job_id> until terminal state.

    Args:
        miner_id: Miner UUID
        miner_ip: Miner IP address
        job_id: Job ID to poll
        registry: MinerRegistry for secret lookup
        timeout_seconds: Total seconds to wait for job completion
        poll_interval: Seconds between polls
        miner_port: Port the miner control plane is listening on

    Returns:
        (ok, state, error)

        ok=True states:
        - "succeeded": Job completed successfully

        ok=False states:
        - "secret_lookup_failed": Failed to retrieve miner secret
        - "failed": Job failed (check error for details)
        - "cancelled": Job was cancelled
        - "timeout": Polling timed out before terminal state
        - "request_error": Network or connection error
        - "auth_failed": 401 authentication error
        - "http_error": HTTP error (4xx/5xx)
        - "invalid_response": Malformed JSON or unexpected structure

        error: Error message from job (if failed) or None
    """
    try:
        secret = registry.get_plaintext_secret(miner_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load miner secret for %s: %s", miner_id, exc)
        return False, "secret_lookup_failed", None

    url = f"http://{miner_ip}:{miner_port}/api/v1/admin/jobs/{job_id}"
    headers = {"Authorization": f"Bearer {secret}"}
    deadline = timeout_seconds

    logger.info(
        "Polling job %s on miner %s (timeout=%ss, interval=%ss)",
        job_id, miner_id, timeout_seconds, poll_interval
    )

    while deadline > 0:
        try:
            resp = requests.get(url, headers=headers, timeout=(3, 10))
        except requests.RequestException as exc:  # noqa: BLE001
            logger.warning("Miner %s job poll request failed: %s", miner_id, exc)
            return False, "request_error", str(exc)

        # Handle authentication failure
        if resp.status_code == 401:
            logger.error("Miner %s job poll auth failed", miner_id)
            return False, "auth_failed", None

        # Handle other HTTP errors
        if resp.status_code >= 400:
            error_body = resp.text[:200] if resp.text else "no body"
            logger.error(
                "Miner %s job poll returned %s: %s",
                miner_id, resp.status_code, error_body
            )
            return False, "http_error", error_body

        # Parse response
        try:
            resp_data = resp.json()
            if resp_data.get("status") != "success":
                logger.error("Miner %s job poll invalid status: %s", miner_id, resp_data)
                return False, "invalid_response", None

            job = resp_data.get("job", {})
            state = job.get("state")
            error = job.get("error")
            progress = job.get("progress", 0)

            if not state:
                logger.error("Miner %s job poll missing state field", miner_id)
                return False, "invalid_response", None

        except Exception as exc:  # noqa: BLE001
            logger.error("Miner %s job poll parse error: %s", miner_id, exc)
            return False, "invalid_response", str(exc)

        # Check for terminal states
        if state == "succeeded":
            logger.info("Miner %s job %s succeeded", miner_id, job_id)
            return True, "succeeded", None

        if state == "failed":
            logger.error("Miner %s job %s failed: %s", miner_id, job_id, error)
            return False, "failed", error

        if state == "cancelled":
            logger.warning("Miner %s job %s was cancelled", miner_id, job_id)
            return False, "cancelled", None

        # Non-terminal states: queued, running
        logger.info(
            "Miner %s job %s state=%s, progress=%s%%; rechecking in %ss (time_left=%ss)",
            miner_id, job_id, state, progress, poll_interval, deadline
        )

        time.sleep(poll_interval)
        deadline -= poll_interval

    logger.error("Miner %s job %s timed out after %ss", miner_id, job_id, timeout_seconds)
    return False, "timeout", None


def deploy_scrubbers_and_wait(
    miner_id: str,
    miner_ip: str,
    *,
    registry: MinerRegistry,
    min_nodes: int = 2,
    region: str | None = None,
    shard_id: str | None = None,
    shard_type: str = "production",
    deploy_timeout: Tuple[int, int] = (5, 360),
    poll_interval: int = 15,
    poll_timeout: int = 360,
    miner_port: int = DEFAULT_MINER_PORT,
) -> Tuple[bool, str, str | None]:
    """Request shard deployment and poll job status until ready.

    Uses request_shard_deploy() + wait_for_job() for async job-based deployment.

    Args:
        miner_id: Miner UUID
        miner_ip: Miner IP address
        registry: MinerRegistry for secret lookup
        min_nodes: Minimum nodes required for success (default: 2)
        region: AWS region for shard deployment
        shard_id: Optional explicit shard ID (defaults to region name if not provided)
        deploy_timeout: (connect_timeout, read_timeout) for deploy request
        poll_interval: Seconds between job status polls
        poll_timeout: Total seconds to wait for job completion

    Returns:
        (ok, reason, shard_id)

        Success reasons:
        - "ok": Shard deployed and ready

        Failure reasons (from request_shard_deploy):
        - "secret_lookup_failed": Failed to retrieve miner secret
        - "request_error": Network or connection error
        - "auth_failed": 401 authentication error
        - "http_error": Other HTTP error
        - "invalid_response": Malformed response

        Failure reasons (from wait_for_job):
        - "job_failed": Deployment job failed
        - "job_cancelled": Deployment job was cancelled
        - "job_timeout": Job polling timed out
    """
    # Determine shard region (default to region param or provider-aware fallback)
    if region:
        shard_region = region
    else:
        # Infer provider from shard_id if available, otherwise default to AWS
        provider = "aws"
        if shard_id:
            provider = infer_provider_from_region(shard_id)
        shard_region = get_default_region_for_provider(provider)

    # Step 1: Request shard deployment
    ok, reason, job_id, returned_shard_id = request_shard_deploy(
        miner_id=miner_id,
        miner_ip=miner_ip,
        region=shard_region,
        shard_id=shard_id,
        registry=registry,
        timeout=deploy_timeout,
        miner_port=miner_port,
        shard_type=shard_type,
    )

    if not ok:
        # Deploy request failed (network, auth, etc.)
        logger.error(
            "Miner %s shard deploy request failed: %s",
            miner_id, reason
        )
        return False, reason, None

    # Handle 200 response: Shard already exists
    if reason == "already_exists":
        logger.info(
            "Miner %s shard already exists: %s (skipping job poll)",
            miner_id, returned_shard_id
        )
        return True, "ok", returned_shard_id

    # Handle 202 or 409: Job exists, poll for completion
    if reason in {"accepted", "already_running"}:
        if not job_id:
            logger.error("Miner %s deploy returned %s but no job_id", miner_id, reason)
            return False, "invalid_response", None

        logger.info(
            "Miner %s shard deploy %s: job_id=%s, shard_id=%s (polling for completion)",
            miner_id, reason, job_id, returned_shard_id
        )

        # Step 2: Wait for job completion
        job_ok, job_state, job_error = wait_for_job(
            miner_id=miner_id,
            miner_ip=miner_ip,
            job_id=job_id,
            registry=registry,
            timeout_seconds=poll_timeout,
            poll_interval=poll_interval,
            miner_port=miner_port,
        )

        if not job_ok:
            # Job failed, cancelled, or timed out
            if job_state == "failed":
                logger.error(
                    "Miner %s shard deploy job %s failed: %s",
                    miner_id, job_id, job_error
                )
                return False, "job_failed", None
            elif job_state == "cancelled":
                logger.warning("Miner %s shard deploy job %s was cancelled", miner_id, job_id)
                return False, "job_cancelled", None
            elif job_state == "timeout":
                logger.error(
                    "Miner %s shard deploy job %s timed out after %ss",
                    miner_id, job_id, poll_timeout
                )
                return False, "job_timeout", None
            else:
                # Other failure (secret_lookup, request_error, auth_failed, etc.)
                logger.error("Miner %s job poll failed: %s", miner_id, job_state)
                return False, job_state, None

        # Job succeeded
        logger.info(
            "Miner %s shard deploy job %s succeeded: shard_id=%s",
            miner_id, job_id, returned_shard_id
        )
        return True, "ok", returned_shard_id

    # Unexpected reason
    logger.error("Miner %s shard deploy returned unexpected reason: %s", miner_id, reason)
    return False, "invalid_response", None
