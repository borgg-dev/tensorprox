"""API key + IP whitelist enforcement for TensorProx Management external calls."""
from __future__ import annotations

from typing import Tuple

from flask import request

from shared.config import get_tp_management_settings
from shared.utils.logging import get_logger

logger = get_logger(__name__)


def _get_client_ip() -> str:
    """Extract client IP from X-Forwarded-For or remote_addr."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def _ip_allowed(ip: str, allowed_ips: list[str]) -> bool:
    # Normalize localhost dual-stack
    if ip == "::1" and "127.0.0.1" in allowed_ips:
        return True
    if ip == "127.0.0.1" and "::1" in allowed_ips:
        return True
    return ip in allowed_ips


def validate_api_request() -> Tuple[bool, str]:
    """Validate IP + API key per tp-webapp mechanism.

    Returns:
        (ok, message) where ok is True if validated, otherwise message explains why.
    """
    settings = get_tp_management_settings()
    client_ip = _get_client_ip()

    # IP whitelist
    if settings.enforce_ip_whitelist:
        if not _ip_allowed(client_ip, settings.allowed_api_ips):
            return False, f"unauthorized_ip:{client_ip}"

    # API key
    if settings.enforce_api_key:
        expected = (settings.api_secret_key or "").strip()
        provided = (request.headers.get("X-API-Key") or "").strip()
        if not expected:
            logger.error("API key enforcement enabled but api_secret_key is missing")
            return False, "api_key_not_configured"
        if provided != expected:
            return False, "invalid_api_key"

    return True, ""
