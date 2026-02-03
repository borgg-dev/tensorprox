"""Validation Orchestrator.

PURPOSE:
    The orchestrator is the central coordinator for all miner validation workflows.
    It abstracts away provider-specific details from TPM business logic by:
    1. Retrieving and decrypting miner credentials from the database
    2. Determining the cloud provider from credentials
    3. Dispatching to the appropriate provider plugin
    4. Storing validation results back to the miner's database record

RESPONSIBILITIES:
    - Credential management: Uses miner_credentials service to decrypt stored credentials
    - Plugin dispatch: Routes to AWS/Linode/etc plugin based on provider field
    - Result storage: Persists results in metadata.validation.{workflow} JSONB
    - Error handling: Gracefully handles missing credentials, unknown providers

WORKFLOW EXECUTION:
    orchestrator.run_discover_regions(miner_id):
        1. Call get_credentials(miner_id) → decrypts Fernet-encrypted credentials
        2. Extract provider from credentials["provider"]
        3. Look up plugin: self._plugins[provider]
        4. Call plugin.discover_regions(credentials)
        5. Store result via _store_result() → updates miner metadata

ADDING NEW WORKFLOWS:
    1. Add method to base.py MinerValidationPlugin (with default NOT_APPLICABLE)
    2. Implement in provider plugins (aws_plugin.py, linode_plugin.py)
    3. Add run_{workflow}() method here that follows the pattern above
    4. Optionally add queue dispatch in queue.py for async execution

RESULT STORAGE FORMAT:
    metadata.validation.{workflow} = {
        "workflow": "discover_regions",
        "status": "success",
        "data": [...],
        "message": "...",
        "duration_ms": 84,
        "updated_at": "2025-12-21T13:19:59.988967+00:00"
    }
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from shared.utils.logging import get_logger

from tensorprox.tpm.repositories.miner_repository import MinerRepository
from tensorprox.tpm.services.miner_credentials import (
    CredentialsNotFoundError,
    MinerCredentialsError,
    get_credentials,
)

from .aws_plugin import get_aws_plugin
from .base import MinerValidationPlugin, ValidationResult, ValidationStatus
from .linode_plugin import get_linode_plugin

logger = get_logger(__name__)


class ValidationOrchestrator:
    """Orchestrates validation workflows across providers.

    Usage:
        orchestrator = ValidationOrchestrator()
        result = orchestrator.run_discover_regions("miner-uuid-here")
    """

    def __init__(
        self,
        repository: Optional[MinerRepository] = None,
    ):
        self.repository = repository or MinerRepository()

        self._plugins: Dict[str, MinerValidationPlugin] = {
            "aws": get_aws_plugin(),
            "linode": get_linode_plugin(),
        }

    def get_plugin(self, provider: str) -> Optional[MinerValidationPlugin]:
        """Get validation plugin for provider."""
        return self._plugins.get(provider.lower())

    def run_discover_regions(self, miner_id: str) -> ValidationResult:
        """Execute region discovery for a miner.

        Process:
        1. Retrieve and decrypt miner credentials
        2. Determine provider from credentials
        3. Dispatch to appropriate plugin
        4. Store result in miner metadata

        Args:
            miner_id: UUID of the miner

        Returns:
            ValidationResult with regions or error
        """
        workflow = "discover_regions"

        try:
            credentials = get_credentials(miner_id)
        except CredentialsNotFoundError:
            logger.info("Miner %s has no credentials, skipping validation", miner_id)
            result = ValidationResult(
                workflow=workflow,
                status=ValidationStatus.SKIPPED,
                message="No credentials stored for this miner",
            )
            self._store_result(miner_id, result)
            return result
        except MinerCredentialsError as exc:
            logger.warning(
                "Failed to retrieve credentials for miner %s: %s",
                miner_id,
                exc,
            )
            result = ValidationResult(
                workflow=workflow,
                status=ValidationStatus.FAILED,
                message=f"Credential retrieval failed: {exc}",
            )
            self._store_result(miner_id, result)
            return result

        provider = credentials.get("provider", "").lower()
        if not provider:
            logger.warning("Miner %s credentials missing provider field", miner_id)
            result = ValidationResult(
                workflow=workflow,
                status=ValidationStatus.FAILED,
                message="Credentials missing 'provider' field",
            )
            self._store_result(miner_id, result)
            return result

        plugin = self.get_plugin(provider)
        if not plugin:
            logger.warning("No validation plugin for provider: %s", provider)
            result = ValidationResult(
                workflow=workflow,
                status=ValidationStatus.SKIPPED,
                message=f"No validation plugin for provider: {provider}",
            )
            self._store_result(miner_id, result)
            return result

        logger.info(
            "Running %s for miner %s (provider: %s)",
            workflow,
            miner_id,
            provider,
        )
        result = plugin.discover_regions(credentials)

        self._store_result(miner_id, result)

        logger.info(
            "Validation %s for miner %s completed: status=%s",
            workflow,
            miner_id,
            result.status.value,
        )

        return result

    def _store_result(self, miner_id: str, result: ValidationResult) -> None:
        """Store validation result in miner metadata.

        Updates metadata.validation.{workflow} with result data.
        """
        try:
            miner = self.repository.get_miner(miner_id)
            if not miner:
                logger.error("Cannot store result: miner %s not found", miner_id)
                return

            metadata = miner.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}

            if "validation" not in metadata:
                metadata["validation"] = {}

            metadata["validation"][result.workflow] = {
                **result.to_dict(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            self.repository.update_miner(miner_id, metadata=metadata)

            logger.debug(
                "Stored validation result for miner %s: %s=%s",
                miner_id,
                result.workflow,
                result.status.value,
            )

        except Exception as exc:
            logger.error(
                "Failed to store validation result for miner %s: %s",
                miner_id,
                exc,
                exc_info=True,
            )


_orchestrator: ValidationOrchestrator | None = None


def get_orchestrator() -> ValidationOrchestrator:
    """Get singleton orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ValidationOrchestrator()
    return _orchestrator
