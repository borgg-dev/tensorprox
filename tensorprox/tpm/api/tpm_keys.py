"""Flask blueprint for TPM public info exposure to miners.

These endpoints allow miners to retrieve TPM info before/after registration:
- /public-key: X25519 public key for credential encryption
- /redis-info: Redis connection info for metrics fan-out

No authentication required - miners need this info for discovery and registration.
"""

from __future__ import annotations

from flask import Blueprint, jsonify

from shared.config import get_settings
from shared.utils.logging import get_logger
from tensorprox.tpm.services.tpm_keypair import (
    KeypairNotInitializedError,
    get_public_key_base64,
    get_key_id,
)

bp = Blueprint("tpm_keys", __name__, url_prefix="/api/v1/tpm")
logger = get_logger(__name__)
settings = get_settings()


@bp.get("/public-key")
def get_tpm_public_key():
    """
    Expose TPM's X25519 public key for miner credential encryption.

    No authentication required - this is public information needed before registration.

    Returns:
        200: JSON with public_key (base64), algorithm, and key_id
        503: Keypair not initialized (service not ready)

    Example response:
        {
            "public_key": "VGhpc0lzQTMyQnl0ZVB1YmxpY0tleUV4YW1wbGVGb3JUZXN0",
            "algorithm": "X25519",
            "key_id": "a3f7c9d2"
        }
    """
    logger.info("TPM public key request from client")

    try:
        public_key = get_public_key_base64()
        key_id = get_key_id()

        logger.debug("Returning public key with key_id=%s", key_id)

        return jsonify({
            "public_key": public_key,
            "algorithm": "X25519",
            "key_id": key_id,
        }), 200

    except KeypairNotInitializedError as exc:
        logger.error("Keypair not initialized: %s", exc)
        return jsonify({
            "error": "keypair_not_ready",
            "message": "TPM keypair not initialized. Service may still be starting.",
        }), 503


@bp.get("/redis-info")
def get_redis_info():
    """
    Expose TPM's Redis connection info for miner metrics fan-out.

    No authentication required - miners need this to discover all TPM Redis
    endpoints and publish metrics to all of them.

    Returns:
        200: JSON with host, port, and channel for metrics publishing
        503: Redis not configured on this TPM

    Example response:
        {
            "host": "validator1.example.com",
            "port": 6379,
            "channel": "metrics.aggregated",
            "validator_uid": 5
        }
    """
    from tensorprox.tpm.app import get_validator_uid

    host = settings.tp_redis_external_host
    port = settings.tp_redis_external_port

    if not host:
        logger.debug("Redis external host not configured")
        return jsonify({
            "error": "redis_not_configured",
            "message": "Redis external access not configured on this TPM.",
        }), 503

    validator_uid = get_validator_uid()

    logger.debug("Returning Redis info: host=%s, port=%d, validator_uid=%s",
                 host, port, validator_uid)

    return jsonify({
        "host": host,
        "port": port,
        "channel": "metrics.aggregated",
        "validator_uid": validator_uid,
    }), 200
