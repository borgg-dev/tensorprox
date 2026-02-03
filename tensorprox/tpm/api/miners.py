"""Flask blueprint for miner registration and lifecycle APIs."""
from __future__ import annotations

import base64
import json

from flask import Blueprint, jsonify, request

from shared.config import get_tp_management_settings
from shared.providers import SCRUBBER_SUPPORTED_PROVIDERS
from shared.utils.logging import get_logger

from tensorprox.tpm.services import credential_encryption, tpm_keypair
from tensorprox.tpm.services.miner_registry import (
    MinerNotFoundError,
    MinerRegistry,
    MinerRegistryError,
    MinerSecretInvalidError,
)

bp = Blueprint("tp_miners", __name__, url_prefix="/api/v1/miners")
logger = get_logger(__name__)
registry = MinerRegistry()
settings = get_tp_management_settings()


@bp.post("/register")
def register_miner():
    payload = request.get_json(silent=True) or {}
    miner_id = payload.get("miner_id")
    provided_secret = payload.get("miner_secret")
    name = payload.get("name")
    metadata = payload.get("metadata") or {}
    public_ip = payload.get("public_ip") or request.remote_addr
    provider = metadata.get("provider")
    region = metadata.get("region")
    hotkey = payload.get("hotkey")  # Bittensor hotkey for subnet_miners linkage

    # Extract optional encrypted credential fields
    miner_public_key_b64 = payload.get("miner_public_key")
    cloud_credentials_enc_b64 = payload.get("cloud_credentials_enc")

    logger.info(
        "Register miner request miner_id=%s name=%s public_ip=%s hotkey=%s credentials_provided=%s",
        miner_id or "auto",
        name,
        public_ip,
        hotkey[:16] + "..." if hotkey else None,
        bool(miner_public_key_b64 and cloud_credentials_enc_b64),
    )

    if not provider or not region:
        return jsonify({"error": "provider and region are required in metadata"}), 400

    # Only AWS is currently supported for scrubber deployment and management.
    # Linode scrubber support is not yet implemented (different EIP handling, networking).
    if provider.lower() not in SCRUBBER_SUPPORTED_PROVIDERS:
        return jsonify({
            "error": f"Unsupported scrubber provider: '{provider}'. "
                     f"Only AWS is currently supported for scrubber deployment. "
                     f"Supported providers: {list(SCRUBBER_SUPPORTED_PROVIDERS)}"
        }), 400

    if not miner_id and not _bootstrap_authorized():
        return jsonify({"error": "bootstrap_token_required"}), 401

    # Process encrypted credentials if provided
    miner_public_key_raw = None
    cloud_credentials_fernet = None

    if miner_public_key_b64 or cloud_credentials_enc_b64:
        # Both must be provided together
        if not (miner_public_key_b64 and cloud_credentials_enc_b64):
            return jsonify({
                "error": "miner_public_key and cloud_credentials_enc must be provided together"
            }), 400

        # Process credentials
        result = _process_encrypted_credentials(miner_public_key_b64, cloud_credentials_enc_b64)
        if "error" in result:
            return jsonify(result), 400

        miner_public_key_raw = result["miner_public_key"]
        cloud_credentials_fernet = result["cloud_credentials_enc"]

    try:
        record, secret = registry.register_or_update(
            miner_id=miner_id,
            provided_secret=provided_secret,
            name=name,
            public_ip=public_ip,
            metadata=metadata,
            miner_public_key=miner_public_key_raw,
            cloud_credentials_enc=cloud_credentials_fernet,
            hotkey=hotkey,
        )
    except MinerSecretInvalidError as exc:
        return jsonify({"error": str(exc)}), 401
    except MinerNotFoundError:
        return jsonify({"error": "miner_not_found"}), 404
    except MinerRegistryError as exc:  # pragma: no cover - defensive
        logger.error("Miner registration failed: %s", exc, exc_info=True)
        return jsonify({"error": "registration_failed"}), 500

    # Link miner_id to subnet_miners if hotkey provided
    if hotkey:
        _link_miner_to_subnet(record.get("miner_id"), hotkey)

    response = {
        "miner": _sanitize_record(record),
        "status": "created" if secret else "updated",
    }
    if secret:
        response["miner_secret"] = secret

    # Include Redis credentials for pub/sub access (on both create and update)
    redis_creds = _build_redis_credentials()
    if redis_creds:
        response["redis"] = redis_creds

    return jsonify(response), 201 if secret else 200


@bp.get("")
def list_miners():
    if not _bootstrap_authorized():
        return jsonify({"error": "unauthorized"}), 401
    records = [
        _sanitize_record(rec)
        for rec in registry.repository.list_miners()
    ]
    return jsonify({"miners": records})


@bp.get("/<miner_id>")
def get_miner(miner_id: str):
    if not _bootstrap_authorized():
        return jsonify({"error": "unauthorized"}), 401
    record = registry.repository.get_miner(miner_id)
    if not record:
        return jsonify({"error": "miner_not_found"}), 404
    return jsonify({"miner": _sanitize_record(record)})


@bp.delete("/<miner_id>")
def delete_miner(miner_id: str):
    if not _bootstrap_authorized():
        return jsonify({"error": "unauthorized"}), 401
    try:
        registry.revoke_miner(miner_id)
    except MinerNotFoundError:
        return jsonify({"error": "miner_not_found"}), 404
    return jsonify({"status": "revoked", "miner_id": miner_id})


def _process_encrypted_credentials(
    miner_public_key_b64: str,
    cloud_credentials_enc_b64: str,
) -> dict:
    """Process encrypted credentials from miner registration.

    Args:
        miner_public_key_b64: Base64-encoded miner X25519 public key (32 bytes)
        cloud_credentials_enc_b64: Base64-encoded NaCl box ciphertext

    Returns:
        Dict with 'miner_public_key' and 'cloud_credentials_enc' as bytes,
        or dict with 'error' key on failure.
    """
    # Step 1: Decode miner public key from base64
    try:
        miner_public_key_raw = base64.b64decode(miner_public_key_b64)
        if len(miner_public_key_raw) != 32:
            logger.warning(
                "Invalid miner_public_key length: %d bytes (expected 32)",
                len(miner_public_key_raw),
            )
            return {"error": "invalid_miner_public_key"}
    except Exception as exc:
        logger.warning("Failed to decode miner_public_key: %s", exc)
        return {"error": "invalid_miner_public_key"}

    # Step 2: Decode encrypted credentials from base64
    try:
        nacl_ciphertext = base64.b64decode(cloud_credentials_enc_b64)
    except Exception as exc:
        logger.warning("Failed to decode cloud_credentials_enc: %s", exc)
        return {"error": "invalid_cloud_credentials_enc"}

    # Step 3: Decrypt credentials using TPM's private key
    try:
        decrypted_bytes = tpm_keypair.decrypt_with_private_key(nacl_ciphertext, miner_public_key_raw)
    except Exception as exc:
        logger.warning("Failed to decrypt credentials: %s", exc)
        return {"error": "credential_decryption_failed"}

    # Step 4: Parse decrypted bytes as JSON
    try:
        credentials_dict = json.loads(decrypted_bytes)
        if not isinstance(credentials_dict, dict):
            raise ValueError("Credentials must be a JSON object")
    except Exception as exc:
        logger.warning("Failed to parse decrypted credentials as JSON: %s", exc)
        return {"error": "invalid_credential_format"}

    # Step 5: Re-encrypt with Fernet for storage
    try:
        fernet_encrypted = credential_encryption.encrypt_credentials(credentials_dict)
    except Exception as exc:
        logger.error("Failed to re-encrypt credentials with Fernet: %s", exc, exc_info=True)
        return {"error": "credential_encryption_failed"}

    logger.info("Successfully processed encrypted credentials (size: %d bytes)", len(fernet_encrypted))

    return {
        "miner_public_key": miner_public_key_raw,
        "cloud_credentials_enc": fernet_encrypted,
    }


def _sanitize_record(record):
    if not record:
        return {}
    cleaned = dict(record)
    # Remove sensitive authentication and credential fields
    cleaned.pop("secret_hash", None)
    cleaned.pop("secret_plaintext", None)
    cleaned.pop("miner_public_key", None)
    cleaned.pop("cloud_credentials_enc", None)
    return cleaned


def _bootstrap_authorized() -> bool:
    """
    Check if miner registration is authorized via bootstrap token.

    Accepts tokens that were:
    1. Registered by a validator via POST /api/v1/validators/bootstrap-token
    2. Match the static tp_miner_bootstrap_token setting (legacy fallback)

    If no static token is configured and no validator tokens exist, allows all registrations.
    """
    header = request.headers.get("X-TPM-Bootstrap")

    # Check validator-registered tokens first (dynamic tokens)
    from tensorprox.tpm.api.validators import validate_bootstrap_token
    if header and validate_bootstrap_token(header):
        return True

    # Fallback to static token from settings (legacy)
    static_token = settings.tp_miner_bootstrap_token
    if static_token:
        return header == static_token

    # No tokens configured - allow registration (open mode)
    return True


def _build_redis_credentials() -> dict | None:
    """Build Redis credentials for miner pub/sub access.

    Returns dict with host, port, password, and channels if configured,
    or None if Redis external access is not configured.
    """
    host = settings.tp_redis_external_host
    password = settings.tp_redis_password

    if not host or not password:
        logger.debug(
            "Redis credentials not configured (host=%s, password=%s)",
            bool(host),
            bool(password),
        )
        return None

    return {
        "host": host,
        "port": settings.tp_redis_external_port,
        "password": password,
        "channels": {
            "exit_hubs": "tensorprox.exit_hubs",
            "miner_ports": "tensorprox.miner_ports",
            "metrics": "metrics.aggregated",
        },
    }


def _link_miner_to_subnet(miner_id: str, hotkey: str) -> bool:
    """Link a registered miner to the subnet_miners table via hotkey.

    This updates the subnet_miners record (created by validators) to include
    the miner_id from tensorprox_miners, enabling the deployment decision
    logic to find miners with sufficient audit scores.

    Args:
        miner_id: UUID from tensorprox_miners table
        hotkey: Bittensor hotkey to match in subnet_miners

    Returns:
        True if a row was updated, False otherwise
    """
    from shared.database import get_connection

    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE subnet_miners
                SET miner_id = %s, updated_at = NOW()
                WHERE hotkey = %s AND (miner_id IS NULL OR miner_id != %s)
                """,
                (miner_id, hotkey, miner_id),
            )
            rows_updated = cur.rowcount
            conn.commit()

        if rows_updated > 0:
            logger.info(
                "Linked miner_id=%s to subnet_miners via hotkey=%s...",
                miner_id,
                hotkey[:16] if hotkey else None,
            )
            return True
        else:
            logger.debug(
                "No subnet_miners row found or already linked for hotkey=%s...",
                hotkey[:16] if hotkey else None,
            )
            return False
    except Exception as exc:
        logger.warning(
            "Failed to link miner_id=%s to subnet_miners: %s",
            miner_id,
            exc,
        )
        return False
