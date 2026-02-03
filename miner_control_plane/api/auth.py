"""Authorization helpers for Miner API endpoints."""
from __future__ import annotations

from functools import wraps
from typing import Callable, TypeVar

from flask import jsonify, request

from miner_control_plane.services.miner_identity import miner_identity

F = TypeVar("F", bound=Callable)


def require_tpm_auth(func: F) -> F:
    """Ensure the request carries a valid TensorProx authorization header."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not miner_identity.verify_authorization_header(auth_header):
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]
