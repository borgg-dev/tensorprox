"""Miner Validation Plugin System.

PURPOSE:
    This package provides a provider-agnostic abstraction layer for validating
    miner claims against cloud provider APIs. TPM (TensorProx Management) needs
    to verify information that miners report - such as available regions, traffic
    volumes, or resource capacity - by making direct API calls using the miner's
    own cloud credentials.

ARCHITECTURE:
    The system follows a plugin pattern where TPM business logic calls abstract
    validation methods, and provider-specific plugins (AWS, Linode, etc.) handle
    the actual cloud API calls.

    ┌─────────────────┐
    │  TPM Business   │  "Validate this miner's claim"
    │     Logic       │
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │  Orchestrator   │  Decrypts credentials, dispatches to plugin, stores result
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │  Plugin (AWS)   │  Makes cloud API call with miner's credentials
    └─────────────────┘

COMPONENTS:
    - base.py: Abstract interface (MinerValidationPlugin) and result types
    - aws_plugin.py: AWS implementation using Signature V4 REST API
    - linode_plugin.py: Linode implementation (or NOT_APPLICABLE stubs)
    - orchestrator.py: Dispatches to plugins based on provider, stores results
    - queue.py: Background worker pool for async validation

WORKFLOW:
    1. Miner registers with TPM, providing encrypted cloud credentials
    2. On registration success, trigger_miner_validation(miner_id) is called
    3. Background worker picks up the job
    4. Orchestrator decrypts credentials, determines provider
    5. Orchestrator calls plugin.discover_regions(credentials)
    6. Plugin makes cloud API call (e.g., AWS EC2 DescribeRegions)
    7. Result stored in miner's metadata.validation.{workflow}

USAGE:
    # Async (fire-and-forget, recommended for registration flow)
    from tensorprox.tpm.services.validation import trigger_miner_validation
    trigger_miner_validation(miner_id)

    # Sync (blocking, for manual validation or testing)
    from tensorprox.tpm.services.validation import get_orchestrator
    result = get_orchestrator().run_discover_regions(miner_id)

EXTENSION:
    See CLAUDE.md for instructions on adding new providers or validation methods.
"""
from tensorprox.tpm.services.validation.base import (
    MinerValidationPlugin,
    ValidationResult,
    ValidationStatus,
    ValidationPluginError,
)
from tensorprox.tpm.services.validation.orchestrator import (
    ValidationOrchestrator,
    get_orchestrator,
)
from tensorprox.tpm.services.validation.queue import (
    MinerValidationQueue,
    get_validation_queue,
    trigger_miner_validation,
)

__all__ = [
    "MinerValidationPlugin",
    "ValidationResult",
    "ValidationStatus",
    "ValidationPluginError",
    "ValidationOrchestrator",
    "get_orchestrator",
    "MinerValidationQueue",
    "get_validation_queue",
    "trigger_miner_validation",
]
