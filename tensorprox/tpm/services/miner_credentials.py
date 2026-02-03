"""Service for retrieving and decrypting stored miner credentials.

This service provides safe retrieval and decryption of cloud credentials stored
in the database. It is used when TPM needs to:
- Validate miner-provided credentials against cloud provider APIs
- Make cloud API calls on behalf of miners
- Audit credential status

Flow:
    1. Retrieve miner record from database
    2. Validate credentials exist
    3. Decode from base64 (database storage format)
    4. Decrypt using Fernet key (TPM_CREDENTIALS_ENCRYPTION_KEY)
    5. Return plaintext credentials dict
"""

from __future__ import annotations

import base64
from typing import Any, Dict
from uuid import UUID

from shared.utils.logging import get_logger

from tensorprox.tpm.repositories.miner_repository import MinerRepository
from tensorprox.tpm.services.credential_encryption import (
    CredentialDecryptionError,
    decrypt_credentials,
)

logger = get_logger(__name__)


class MinerCredentialsError(Exception):
    """Base exception for miner credential operations."""


class MinerNotFoundError(MinerCredentialsError):
    """Raised when miner record cannot be located."""


class CredentialsNotFoundError(MinerCredentialsError):
    """Raised when miner has no stored credentials."""


def get_credentials(miner_id: str) -> Dict[str, Any]:
    """
    Retrieve and decrypt a miner's cloud credentials.

    Process:
    1. Validate miner_id format (must be valid UUID)
    2. Retrieve miner record from database
    3. Check if cloud_credentials_enc field exists
    4. Decode from base64 to bytes
    5. Decrypt using Fernet encryption
    6. Return credentials dictionary

    Args:
        miner_id: UUID of the miner

    Returns:
        Decrypted credentials as dict
        (e.g., {"provider": "aws", "aws_access_key_id": "...", "aws_secret_access_key": "..."})

    Raises:
        MinerNotFoundError: If miner doesn't exist or miner_id format invalid
        CredentialsNotFoundError: If miner has no stored credentials
        CredentialDecryptionError: If decryption fails (wrong key, corrupted data)

    Example:
        >>> creds = get_credentials("550e8400-e29b-41d4-a716-446655440000")
        >>> creds["provider"]
        'aws'
        >>> creds["aws_access_key_id"]
        'AKIAIOSFODNN7EXAMPLE'
    """
    # Normalize miner_id to UUID string format
    try:
        normalized_id = str(UUID(str(miner_id)))
    except (ValueError, TypeError) as exc:
        logger.error(f"Invalid miner_id format: {miner_id}")
        raise MinerNotFoundError(f"Invalid miner_id format: {miner_id}") from exc

    # Retrieve miner record from database
    repository = MinerRepository()
    miner = repository.get_miner(normalized_id)

    if not miner:
        logger.warning(f"Miner not found: {normalized_id}")
        raise MinerNotFoundError(f"Miner not found: {normalized_id}")

    # Check if credentials exist in database
    cloud_credentials_enc = miner.get("cloud_credentials_enc")
    if not cloud_credentials_enc:
        logger.warning(f"Miner {normalized_id} has no stored credentials")
        raise CredentialsNotFoundError(f"Miner {normalized_id} has no stored credentials")

    # Decode from base64 (MinerRepository._serialize converts BYTEA to base64)
    try:
        ciphertext = base64.b64decode(cloud_credentials_enc)
    except Exception as exc:
        logger.error(
            f"Failed to decode base64 credentials for miner {normalized_id}: {exc}",
            exc_info=True,
        )
        raise CredentialDecryptionError(f"Invalid base64 encoding: {exc}") from exc

    # Decrypt credentials using Fernet
    try:
        credentials = decrypt_credentials(ciphertext)
        logger.info(
            f"Successfully retrieved credentials for miner {normalized_id} "
            f"(provider: {credentials.get('provider', 'unknown')})"
        )
        return credentials

    except CredentialDecryptionError:
        # Re-raise decryption errors as-is (already logged in credential_encryption)
        logger.error(f"Failed to decrypt credentials for miner {normalized_id}")
        raise


def has_credentials(miner_id: str) -> bool:
    """
    Check if a miner has stored credentials.

    This is a non-throwing helper for checking credential presence without
    attempting decryption. Useful for UI state, conditional logic, etc.

    Args:
        miner_id: UUID of the miner

    Returns:
        True if miner exists and has credentials, False otherwise
        (returns False for invalid miner_id, missing miner, or missing credentials)

    Example:
        >>> has_credentials("550e8400-e29b-41d4-a716-446655440000")
        True
        >>> has_credentials("invalid-uuid")
        False
        >>> has_credentials("550e8400-e29b-41d4-a716-000000000000")  # miner doesn't exist
        False
    """
    # Normalize miner_id to UUID string format
    try:
        normalized_id = str(UUID(str(miner_id)))
    except (ValueError, TypeError):
        logger.debug(f"Invalid miner_id format in has_credentials check: {miner_id}")
        return False

    # Retrieve miner record from database
    repository = MinerRepository()
    miner = repository.get_miner(normalized_id)

    if not miner:
        logger.debug(f"Miner not found in has_credentials check: {normalized_id}")
        return False

    # Check if credentials field exists and is non-empty
    cloud_credentials_enc = miner.get("cloud_credentials_enc")
    has_creds = bool(cloud_credentials_enc)

    logger.debug(f"Miner {normalized_id} has credentials: {has_creds}")
    return has_creds
