"""Flask blueprint for validator APIs including bootstrap token management."""
from __future__ import annotations

import time
import threading
from typing import Dict, Optional

from flask import Blueprint, jsonify, request

from shared.utils.logging import get_logger

bp = Blueprint("tp_validators", __name__, url_prefix="/api/v1/validators")
logger = get_logger(__name__)

# Token storage: {token: {"validator_uid": uid, "validator_hotkey": hotkey, "expires_at": timestamp}}
# Tokens expire after 10 minutes (enough for a full cycle)
_bootstrap_tokens: Dict[str, Dict] = {}
_tokens_lock = threading.Lock()
TOKEN_TTL_SECONDS = 600  # 10 minutes


def _cleanup_expired_tokens() -> None:
    """Remove expired tokens from storage."""
    now = time.time()
    with _tokens_lock:
        expired = [t for t, data in _bootstrap_tokens.items() if data["expires_at"] < now]
        for token in expired:
            del _bootstrap_tokens[token]
        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired bootstrap tokens")


def validate_bootstrap_token(token: str) -> bool:
    """
    Check if a bootstrap token is valid (registered by a validator and not expired).

    Called by miners.py _bootstrap_authorized() to validate miner registration requests.
    """
    if not token:
        return False

    _cleanup_expired_tokens()

    with _tokens_lock:
        if token in _bootstrap_tokens:
            data = _bootstrap_tokens[token]
            if data["expires_at"] > time.time():
                logger.debug(
                    f"Bootstrap token validated (validator_uid={data.get('validator_uid')})"
                )
                return True
    return False


def get_active_token_count() -> int:
    """Get count of active (non-expired) tokens."""
    _cleanup_expired_tokens()
    with _tokens_lock:
        return len(_bootstrap_tokens)


@bp.post("/bootstrap-token")
def register_bootstrap_token():
    """
    Register a bootstrap token for miner onboarding.

    Validators call this at the start of each cycle to register a fresh token.
    Miners receive this token in PingSynapse and use it to register with TPM.

    Request body:
        {
            "token": "the-bootstrap-token",
            "validator_uid": 58,
            "validator_hotkey": "5DJgs8eg..."
        }

    Returns:
        {"success": true, "expires_in": 600}
    """
    payload = request.get_json(silent=True) or {}
    token = payload.get("token")
    validator_uid = payload.get("validator_uid")
    validator_hotkey = payload.get("validator_hotkey")

    if not token:
        return jsonify({"error": "token is required"}), 400

    if validator_uid is None:
        return jsonify({"error": "validator_uid is required"}), 400

    # Store the token with expiration
    expires_at = time.time() + TOKEN_TTL_SECONDS

    with _tokens_lock:
        _bootstrap_tokens[token] = {
            "validator_uid": validator_uid,
            "validator_hotkey": validator_hotkey,
            "expires_at": expires_at,
            "registered_at": time.time(),
        }

    logger.info(
        f"Bootstrap token registered by validator UID={validator_uid}, "
        f"expires_in={TOKEN_TTL_SECONDS}s, active_tokens={get_active_token_count()}"
    )

    return jsonify({
        "success": True,
        "expires_in": TOKEN_TTL_SECONDS,
    })


@bp.get("/bootstrap-tokens/count")
def get_token_count():
    """Get the number of active bootstrap tokens (for monitoring)."""
    return jsonify({
        "active_tokens": get_active_token_count(),
    })
