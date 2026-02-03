"""Abstract Interface for Miner Validation Plugins.

PURPOSE:
    This module defines the abstract base class that all provider-specific
    validation plugins must implement. It establishes the contract between
    TPM's orchestrator and cloud provider implementations.

DESIGN PRINCIPLES:
    - Stateless: Plugins receive credentials per-call, never store them
    - Thread-safe: Plugins may be called concurrently from worker threads
    - Graceful degradation: Plugins can return NOT_APPLICABLE for unsupported workflows
    - Provider-agnostic: Common interface regardless of cloud provider

KEY TYPES:
    - ValidationStatus: Enum of possible outcomes (SUCCESS, FAILED, NOT_APPLICABLE, SKIPPED)
    - ValidationResult: Dataclass containing workflow result with status, data, message
    - MinerValidationPlugin: Abstract base class that provider plugins extend

VALIDATION STATUSES:
    - SUCCESS: Validation completed, data field contains results
    - NOT_APPLICABLE: This workflow doesn't apply to this provider (e.g., Linode regions)
    - FAILED: Validation attempted but failed (API error, invalid credentials)
    - SKIPPED: Validation skipped (no credentials, unknown provider)

EXTENDING:
    To add a new provider, create a new plugin class extending MinerValidationPlugin:

    class GCPValidationPlugin(MinerValidationPlugin):
        @property
        def provider_name(self) -> str:
            return "gcp"

        def discover_regions(self, credentials: Dict[str, Any]) -> ValidationResult:
            # Call GCP API with credentials
            ...

    Then register it in orchestrator.py's __init__.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class ValidationStatus(Enum):
    """Result status for validation workflows."""

    SUCCESS = "success"
    NOT_APPLICABLE = "not_applicable"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ValidationResult:
    """Result of a validation workflow execution.

    Attributes:
        workflow: Name of the workflow (e.g., "discover_regions")
        status: ValidationStatus enum
        data: Result data (e.g., list of regions)
        message: Human-readable message (especially for errors)
        duration_ms: Execution time in milliseconds
    """

    workflow: str
    status: ValidationStatus
    data: Optional[Any] = None
    message: Optional[str] = None
    duration_ms: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for JSON storage."""
        return {
            "workflow": self.workflow,
            "status": self.status.value,
            "data": self.data,
            "message": self.message,
            "duration_ms": self.duration_ms,
        }


class MinerValidationPlugin(ABC):
    """Abstract base class for provider-specific validation plugins.

    Each cloud provider implements this interface to handle
    validation workflows using miner-specific credentials.

    Implementations must be:
    - Stateless (credentials passed per method call)
    - Thread-safe (may be called concurrently)
    - Non-blocking (or handle timeouts internally)
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return provider identifier (e.g., 'aws', 'linode')."""

    @abstractmethod
    def discover_regions(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Discover available regions for this miner's account.

        Args:
            credentials: Decrypted credentials dict with provider-specific keys
                        e.g., {"provider": "aws", "aws_access_key_id": "...", ...}

        Returns:
            ValidationResult with:
            - status=SUCCESS, data=["us-east-1", "eu-central-1", ...]
            - status=NOT_APPLICABLE if provider doesn't need discovery
            - status=FAILED with error message
        """

    def validate_credentials(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Validate that credentials are functional.

        Default implementation calls discover_regions as a basic check.
        Override for more specific validation.

        Args:
            credentials: Decrypted credentials dict

        Returns:
            ValidationResult indicating credential validity
        """
        return self.discover_regions(credentials)


class ValidationPluginError(Exception):
    """Base exception for validation plugin errors."""

    def __init__(self, message: str, provider: str, workflow: str):
        self.provider = provider
        self.workflow = workflow
        super().__init__(f"[{provider}:{workflow}] {message}")
