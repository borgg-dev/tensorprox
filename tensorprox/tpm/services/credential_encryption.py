"""Fernet-based encryption/decryption of cloud credentials at rest.

This module handles symmetric encryption of cloud credentials in the database.
After TPM decrypts credentials from the miner (using X25519), they are re-encrypted
with Fernet before storage. When TPM needs to use credentials, they are decrypted
from storage.

Flow:
    Miner sends encrypted creds
        → tpm_keypair.decrypt_with_private_key()
        → credential_encryption.encrypt_credentials()  [Store in DB]

    Retrieve from DB
        → credential_encryption.decrypt_credentials()
        → Use credentials
"""

from __future__ import annotations

import json
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken

from shared.config import get_tp_management_settings
from shared.utils.logging import get_logger

logger = get_logger(__name__)

# Module-level cached Fernet instance
_fernet: Optional[Fernet] = None


class CredentialEncryptionError(Exception):
    """Base exception for credential encryption operations."""


class EncryptionKeyNotConfiguredError(CredentialEncryptionError):
    """Raised when TPM_CREDENTIALS_ENCRYPTION_KEY is not configured."""


class CredentialDecryptionError(CredentialEncryptionError):
    """Raised when credential decryption fails."""


def _get_fernet() -> Fernet:
    """
    Get or create cached Fernet instance.

    Initializes Fernet with TPM_CREDENTIALS_ENCRYPTION_KEY on first call,
    then returns the cached instance on subsequent calls.

    Returns:
        Fernet: Cached Fernet instance for encryption/decryption

    Raises:
        EncryptionKeyNotConfiguredError: If encryption key not configured or invalid
    """
    global _fernet

    if _fernet is None:
        settings = get_tp_management_settings()

        if not settings.tpm_credentials_encryption_key:
            raise EncryptionKeyNotConfiguredError(
                "tpm_credentials_encryption_key not configured in tp_m.env. "
                "Set TPM_CREDENTIALS_ENCRYPTION_KEY to a Fernet-compatible base64 key. "
                "Generate with: python -c 'from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())'"
            )

        try:
            _fernet = Fernet(settings.tpm_credentials_encryption_key.encode("ascii"))
            logger.debug("Initialized Fernet instance for credential encryption")
        except InvalidToken as exc:
            raise EncryptionKeyNotConfiguredError(
                "Invalid encryption key format. TPM_CREDENTIALS_ENCRYPTION_KEY must be a "
                "valid Fernet base64 key. Generate with: python -c 'from cryptography.fernet "
                "import Fernet; print(Fernet.generate_key().decode())'"
            ) from exc

    return _fernet


def encrypt_credentials(credentials: dict[str, Any]) -> bytes:
    """
    Encrypt credentials dictionary for storage in database.

    Process:
    1. Validate encryption key is configured
    2. Serialize credentials dict to JSON
    3. Encrypt with Fernet using TPM_CREDENTIALS_ENCRYPTION_KEY
    4. Return encrypted bytes

    Args:
        credentials: Dictionary of cloud credentials to encrypt
                    (e.g., {"access_key": "...", "secret_key": "..."})

    Returns:
        bytes: Fernet-encrypted ciphertext

    Raises:
        EncryptionKeyNotConfiguredError: If encryption key not configured
        CredentialEncryptionError: If encryption fails

    Example:
        >>> creds = {"access_key": "AKIA...", "secret_key": "wJalr..."}
        >>> encrypted = encrypt_credentials(creds)
        >>> type(encrypted)
        <class 'bytes'>
    """
    try:
        # Get cached Fernet instance
        fernet = _get_fernet()

        # Serialize credentials to JSON
        plaintext = json.dumps(credentials, separators=(",", ":"))
        plaintext_bytes = plaintext.encode("utf-8")

        # Encrypt
        ciphertext = fernet.encrypt(plaintext_bytes)

        logger.debug(f"Encrypted credentials dictionary ({len(plaintext_bytes)} bytes plaintext)")
        return ciphertext

    except EncryptionKeyNotConfiguredError:
        # Re-raise key configuration errors
        raise

    except Exception as exc:
        logger.error(f"Failed to encrypt credentials: {exc}")
        raise CredentialEncryptionError(f"Encryption failed: {exc}") from exc


def decrypt_credentials(ciphertext: bytes) -> dict[str, Any]:
    """
    Decrypt stored credentials from database.

    Process:
    1. Validate encryption key is configured
    2. Decrypt ciphertext with Fernet
    3. Deserialize JSON to dict
    4. Return credentials dict

    Args:
        ciphertext: Fernet-encrypted credentials from database

    Returns:
        dict: Decrypted credentials dictionary

    Raises:
        EncryptionKeyNotConfiguredError: If encryption key not configured
        CredentialDecryptionError: If decryption or JSON parsing fails

    Example:
        >>> encrypted = b'gAAAAABl...'
        >>> creds = decrypt_credentials(encrypted)
        >>> creds.keys()
        dict_keys(['access_key', 'secret_key'])
    """
    try:
        # Get cached Fernet instance
        fernet = _get_fernet()

        # Decrypt
        plaintext_bytes = fernet.decrypt(ciphertext)

        # Deserialize JSON
        plaintext = plaintext_bytes.decode("utf-8")
        credentials = json.loads(plaintext)

        logger.debug(f"Decrypted credentials dictionary ({len(plaintext_bytes)} bytes plaintext)")
        return credentials

    except EncryptionKeyNotConfiguredError:
        # Re-raise key configuration errors
        raise

    except InvalidToken as exc:
        logger.error("Failed to decrypt credentials: invalid token or wrong encryption key")
        raise CredentialDecryptionError(
            "Decryption failed: invalid token or wrong encryption key"
        ) from exc

    except json.JSONDecodeError as exc:
        logger.error(f"Failed to parse decrypted credentials as JSON: {exc}")
        raise CredentialDecryptionError(f"Decrypted data is not valid JSON: {exc}") from exc

    except Exception as exc:
        logger.error(f"Failed to decrypt credentials: {exc}")
        raise CredentialDecryptionError(f"Decryption failed: {exc}") from exc
