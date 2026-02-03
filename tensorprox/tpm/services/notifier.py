"""Redis-backed event notifier for exit-hub state changes."""
from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any, Dict, Optional

from shared.config import get_tp_management_settings
from shared.utils.logging import get_logger

if TYPE_CHECKING:
    from tensorprox.tpm.repositories.origin_repository import OriginRepository

try:
    import redis  # type: ignore
except ImportError:  # pragma: no cover
    redis = None


class ExitHubNotifier:
    """Publishes exit-hub lifecycle events to Redis (optional)."""

    CHANNEL = "tensorprox.exit_hubs"  # Shared channel for all validators

    def __init__(self, *, enabled: Optional[bool] = None, validator_uid: Optional[int] = None):
        self.logger = get_logger(__name__)
        settings = get_tp_management_settings()
        env_enabled = settings.tp_exit_hub_notifier_enabled
        if enabled is None and os.getenv("TP_EXIT_HUB_NOTIFIER_ENABLED") is not None:
            env_enabled = os.getenv("TP_EXIT_HUB_NOTIFIER_ENABLED", "false").lower() in {
                "1",
                "true",
                "yes",
            }

        self.enabled = env_enabled if enabled is None else enabled
        self._client = None
        self.validator_uid = validator_uid
        self.channel = self.CHANNEL

        if not self.enabled:
            self.logger.info(
                "Exit-hub notifier disabled (tp_exit_hub_notifier_enabled=%s).",
                env_enabled,
            )
            return

        if not redis:
            self.logger.warning(
                "Exit-hub notifier enabled but redis library missing; disabling publisher."
            )
            self.enabled = False
            return

        settings = get_tp_management_settings()
        self._client = redis.Redis.from_url(settings.tp_redis_url)
        self.logger.info(
            "Exit-hub notifier enabled (channel=%s, redis=%s, validator_uid=%s)",
            self.channel,
            settings.tp_redis_url,
            validator_uid,
        )

    def exit_hub_state_changed(
        self,
        *,
        exit_hub_id: str,
        status: str,
        client_id: Optional[str] = None,
        origin_id: Optional[str] = None,
        miner_id: Optional[str] = None,
        miner_ip: Optional[str] = None,
        tensorprox_ip: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        origin_repository: Optional[OriginRepository] = None,
    ) -> None:
        """Publish a lifecycle event if the notifier is enabled.

        Args:
            exit_hub_id: Exit hub UUID
            status: Current deployment status
            client_id: Client ID (optional - fetched from origin if available)
            origin_id: Origin ID (optional but recommended)
            miner_id: Miner UUID (optional - fetched from origin if available)
            miner_ip: Miner IP address (optional - fetched from origin if available)
            tensorprox_ip: EIP assigned (optional - fetched from origin if available)
            metadata: Additional deployment metadata
            error: Error message if status indicates failure
            origin_repository: Optional repository to fetch canonical origin data

        Note:
            If origin_repository is provided and origin_id is available, the method
            will attempt to fetch canonical data from the origin table. Values passed
            as parameters take precedence over fetched data (COALESCE logic).
        """
        if not self.enabled or not self._client:
            return

        # If origin_repository provided, look up canonical data from origin table
        origin_data = None
        if origin_repository and origin_id:
            try:
                origin_data = origin_repository.find_by_origin_id(origin_id)
                if origin_data:
                    self.logger.debug(
                        "Fetched origin data for origin_id=%s (tensorprox_ip=%s)",
                        origin_id,
                        origin_data.get('tensorprox_ip'),
                    )
            except Exception as exc:  # noqa: BLE001
                self.logger.warning(
                    "Failed to fetch origin data for origin_id=%s: %s",
                    origin_id,
                    exc,
                )

        # Use COALESCE logic: prefer passed parameters, fall back to origin data
        effective_client_id = client_id
        effective_miner_id = miner_id
        effective_miner_ip = miner_ip
        effective_tensorprox_ip = tensorprox_ip

        if origin_data:
            effective_client_id = client_id or origin_data.get('client_id')
            effective_miner_id = miner_id or origin_data.get('miner_id')
            effective_miner_ip = miner_ip or origin_data.get('miner_ip')
            effective_tensorprox_ip = tensorprox_ip or origin_data.get('tensorprox_ip')

        # Backward compatibility: extract tensorprox_ip from metadata if not set
        if not effective_tensorprox_ip and metadata:
            effective_tensorprox_ip = metadata.get('tensorprox_ip')

        # Get validator_uid from Flask context or app config (for decentralized mode)
        validator_uid = self.validator_uid  # Use instance validator_uid if set
        if validator_uid is None:
            try:
                from flask import g, current_app
                # Try request context first
                validator_uid = getattr(g, 'validator_uid', None)
                # Fall back to app config
                if validator_uid is None and current_app:
                    validator_uid = current_app.config.get('TPM_VALIDATOR_UID')
            except (ImportError, RuntimeError):
                # Not in Flask context
                pass

        payload: Dict[str, Any] = {
            "exit_hub_id": exit_hub_id,
            "status": status,
            "client_id": effective_client_id,
            "origin_id": origin_id,
            "miner_id": effective_miner_id,
            "miner_ip": effective_miner_ip,
            "tensorprox_ip": effective_tensorprox_ip,
            "validator_uid": validator_uid,  # For decentralized TPM-Lite
            "metadata": metadata or {},
            "error": error,  # Always include for consistent schema
        }

        message = json.dumps(payload, default=str)
        try:
            self._client.publish(self.channel, message)
            self.logger.debug(
                "Published exit-hub event status=%s exit_hub_id=%s channel=%s",
                status,
                exit_hub_id,
                self.channel,
            )
        except Exception as exc:  # noqa: BLE001
            self.logger.error("Failed to publish exit-hub event: %s", exc, exc_info=True)
