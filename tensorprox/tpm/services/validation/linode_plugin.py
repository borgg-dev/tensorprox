"""Linode Validation Plugin.

PURPOSE:
    This plugin implements Linode-specific validation workflows using the miner's
    Linode API token. Linode has a simpler permission model than AWS, so some
    workflows that are necessary for AWS may return NOT_APPLICABLE here.

LINODE vs AWS DIFFERENCES:
    - Regions: Linode regions are universally available to all accounts.
      No per-account region discovery needed (returns NOT_APPLICABLE).
    - Authentication: Simple Bearer token vs AWS Signature V4.
    - Permissions: Linode tokens have scopes, but region access is not restricted.

IMPLEMENTED WORKFLOWS:
    - discover_regions: Returns NOT_APPLICABLE (all Linode regions are available)
    - validate_credentials: Validates token against Linode API

FUTURE WORKFLOWS (examples):
    - verify_traffic_volume: Call Linode API to get transfer usage
    - check_token_scopes: Verify token has required permissions

CREDENTIAL FORMAT:
    Expects credentials dict with keys:
    - linode_token: Linode Personal Access Token

API REFERENCE:
    - Linode API: https://www.linode.com/docs/api/
    - Regions: https://www.linode.com/docs/api/regions/
"""
from __future__ import annotations

import time
from typing import Any, Dict

import requests

from shared.utils.logging import get_logger

from .base import (
    MinerValidationPlugin,
    ValidationResult,
    ValidationStatus,
)

logger = get_logger(__name__)


class LinodeValidationPlugin(MinerValidationPlugin):
    """Linode-specific validation plugin.

    Linode has a simpler permission model where all regions
    are available to all accounts with valid API tokens.
    """

    @property
    def provider_name(self) -> str:
        return "linode"

    def discover_regions(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Return NOT_APPLICABLE - Linode regions are universally available.

        Unlike AWS, Linode doesn't require per-account region discovery.
        All regions are available if the API token is valid.
        """
        logger.debug("Linode region discovery: not applicable")

        return ValidationResult(
            workflow="discover_regions",
            status=ValidationStatus.NOT_APPLICABLE,
            message="Linode regions are universally available; no discovery needed",
            duration_ms=0,
        )

    def validate_credentials(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Validate Linode API token by calling the account endpoint.

        Calls GET /v4/account to verify token validity and permissions.
        This endpoint requires 'account:read_only' scope at minimum.
        """
        token = credentials.get("linode_token")

        if not token:
            return ValidationResult(
                workflow="validate_credentials",
                status=ValidationStatus.FAILED,
                message="Missing linode_token in credentials",
            )

        start_time = time.time()

        try:
            response = requests.get(
                "https://api.linode.com/v4/account",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                timeout=10,
            )

            duration_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                account_data = response.json()
                email = account_data.get("email", "unknown")
                # Log validation success without PII (email)
                logger.info("Linode token validated successfully")
                return ValidationResult(
                    workflow="validate_credentials",
                    status=ValidationStatus.SUCCESS,
                    message=f"Linode token valid for account: {email}",
                    duration_ms=duration_ms,
                    data={"email": email},
                )
            elif response.status_code == 401:
                logger.warning("Linode token validation failed: invalid or expired token")
                return ValidationResult(
                    workflow="validate_credentials",
                    status=ValidationStatus.FAILED,
                    message="Invalid or expired Linode token",
                    duration_ms=duration_ms,
                )
            elif response.status_code == 403:
                logger.warning("Linode token validation failed: insufficient permissions")
                return ValidationResult(
                    workflow="validate_credentials",
                    status=ValidationStatus.FAILED,
                    message="Linode token lacks required permissions (needs account:read_only)",
                    duration_ms=duration_ms,
                )
            else:
                logger.error(f"Linode API returned unexpected status: {response.status_code}")
                return ValidationResult(
                    workflow="validate_credentials",
                    status=ValidationStatus.FAILED,
                    message=f"Linode API error: HTTP {response.status_code}",
                    duration_ms=duration_ms,
                )

        except requests.exceptions.Timeout:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error("Linode token validation timed out")
            return ValidationResult(
                workflow="validate_credentials",
                status=ValidationStatus.FAILED,
                message="Linode API request timed out",
                duration_ms=duration_ms,
            )
        except requests.exceptions.RequestException as e:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error(f"Linode token validation request failed: {e}")
            return ValidationResult(
                workflow="validate_credentials",
                status=ValidationStatus.FAILED,
                message=f"Linode API request failed: {str(e)}",
                duration_ms=duration_ms,
            )


_linode_plugin: LinodeValidationPlugin | None = None


def get_linode_plugin() -> LinodeValidationPlugin:
    """Get singleton Linode validation plugin instance."""
    global _linode_plugin
    if _linode_plugin is None:
        _linode_plugin = LinodeValidationPlugin()
    return _linode_plugin
