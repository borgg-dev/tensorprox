"""TPM X25519 keypair management for miner credential exchange.

This module manages TPM's long-lived X25519 keypair used for:
1. Publishing public key to miners via /api/v1/miners/tpm-public-key
2. Decrypting miner credentials encrypted with TPM's public key

The private key is stored on disk with chmod 600, public key is cached in memory.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import nacl.public
import nacl.utils
import nacl.exceptions

from shared.config import get_tp_management_settings
from shared.utils.logging import get_logger

logger = get_logger(__name__)


# Module-level state (cached after load_or_generate_keypair)
_private_key: Optional[x25519.X25519PrivateKey] = None
_public_key_bytes: Optional[bytes] = None


class KeypairError(Exception):
    """Base exception for keypair operations."""


class KeypairNotInitializedError(KeypairError):
    """Raised when keypair functions are called before initialization."""


class DecryptionError(KeypairError):
    """Raised when decryption fails."""


class KeypairConfigError(KeypairError):
    """Raised when TPM_PRIVATE_KEY_PATH is not configured."""


def load_or_generate_keypair() -> None:
    """
    Load existing keypair from TPM_PRIVATE_KEY_PATH or generate new one.

    Process:
    1. Check if TPM_PRIVATE_KEY_PATH is configured
    2. If file exists: load private key (32 raw bytes)
    3. If file doesn't exist: generate X25519 keypair, save private key with chmod 600
    4. Derive public key and cache in memory

    Raises:
        KeypairConfigError: If tpm_private_key_path is not configured
        KeypairError: If file operations or key derivation fails
    """
    global _private_key, _public_key_bytes

    settings = get_tp_management_settings()

    if not settings.tpm_private_key_path:
        raise KeypairConfigError(
            "tpm_private_key_path not configured in tp_m.env. "
            "Set TPM_PRIVATE_KEY_PATH to a secure file path (e.g., /etc/tensorprox/tpm.key)"
        )

    key_path = Path(settings.tpm_private_key_path)

    try:
        if key_path.exists():
            logger.info(f"Loading existing TPM private key from {key_path}")
            _load_existing_key(key_path)
        else:
            logger.info(f"Generating new TPM X25519 keypair, saving to {key_path}")
            _generate_and_save_key(key_path)

        logger.info(
            f"TPM keypair initialized. Key ID: {get_key_id()}, "
            f"Public Key (base64): {get_public_key_base64()[:32]}..."
        )

    except Exception as exc:
        logger.error(f"Failed to initialize TPM keypair: {exc}")
        raise KeypairError(f"Keypair initialization failed: {exc}") from exc


def _load_existing_key(key_path: Path) -> None:
    """Load private key from file and derive public key."""
    global _private_key, _public_key_bytes

    with open(key_path, "rb") as f:
        private_key_bytes = f.read()

    # Verify and repair file permissions if insecure
    current_mode = key_path.stat().st_mode & 0o777
    if current_mode != 0o600:
        logger.warning(
            f"Private key file {key_path} has insecure permissions {oct(current_mode)}. "
            f"Repairing to 0o600."
        )
        os.chmod(key_path, 0o600)

    if len(private_key_bytes) != 32:
        raise KeypairError(
            f"Invalid private key file: expected 32 bytes, got {len(private_key_bytes)}"
        )

    # Reconstruct X25519PrivateKey from raw bytes
    _private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    _public_key_bytes = _private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    logger.debug(f"Loaded private key from {key_path} (32 bytes)")


def _generate_and_save_key(key_path: Path) -> None:
    """Generate new X25519 keypair and save to disk with chmod 600."""
    global _private_key, _public_key_bytes

    # Ensure parent directory exists
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate X25519 keypair
    _private_key = x25519.X25519PrivateKey.generate()
    _public_key_bytes = _private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # Serialize private key as raw 32 bytes
    private_key_bytes = _private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Write to file atomically with correct permissions (0o600)
    # Use os.open with O_CREAT | O_EXCL to prevent TOCTOU race condition
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_key_bytes)

    logger.info(f"Generated new X25519 keypair, saved to {key_path} (chmod 600)")


def get_public_key() -> bytes:
    """
    Return the 32-byte X25519 public key (raw bytes).

    Returns:
        bytes: 32-byte X25519 public key

    Raises:
        KeypairNotInitializedError: If load_or_generate_keypair() not called
    """
    if _public_key_bytes is None:
        raise KeypairNotInitializedError(
            "Keypair not initialized. Call load_or_generate_keypair() first."
        )
    return _public_key_bytes


def get_public_key_base64() -> str:
    """
    Return the public key as base64-encoded string.

    Returns:
        str: Base64-encoded public key (44 characters for 32 bytes)

    Raises:
        KeypairNotInitializedError: If load_or_generate_keypair() not called
    """
    return base64.b64encode(get_public_key()).decode("ascii")


def get_key_id() -> str:
    """
    Return SHA256 fingerprint of public key (first 8 hex chars).

    Returns:
        str: 8-character hex fingerprint (e.g., "a3f7c9d2")

    Raises:
        KeypairNotInitializedError: If load_or_generate_keypair() not called
    """
    public_key = get_public_key()
    fingerprint = hashlib.sha256(public_key).hexdigest()
    return fingerprint[:8]


def decrypt_with_private_key(ciphertext: bytes, sender_public_key: bytes) -> bytes:
    """
    Decrypt NaCl box ciphertext using TPM private key + sender's public key.

    The ciphertext must be in NaCl box format:
    - First 24 bytes: nonce
    - Remaining bytes: encrypted data + authentication tag

    Args:
        ciphertext: NaCl box format (nonce + encrypted data)
        sender_public_key: 32-byte X25519 public key from miner

    Returns:
        bytes: Decrypted plaintext

    Raises:
        KeypairNotInitializedError: If keypair not initialized
        DecryptionError: If decryption fails (wrong key, corrupted data, etc.)
    """
    if _private_key is None:
        raise KeypairNotInitializedError(
            "Keypair not initialized. Call load_or_generate_keypair() first."
        )

    if len(sender_public_key) != 32:
        raise DecryptionError(
            f"Invalid sender public key: expected 32 bytes, got {len(sender_public_key)}"
        )

    try:
        # Convert cryptography X25519PrivateKey to NaCl format
        # Extract raw 32-byte private key
        tpm_private_bytes = _private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Create NaCl PrivateKey and PublicKey objects
        tpm_nacl_private = nacl.public.PrivateKey(tpm_private_bytes)
        sender_nacl_public = nacl.public.PublicKey(sender_public_key)

        # Create Box for decryption (TPM private key + sender public key)
        box = nacl.public.Box(tpm_nacl_private, sender_nacl_public)

        # Decrypt (NaCl Box.decrypt expects nonce prepended to ciphertext)
        plaintext = box.decrypt(ciphertext)

        logger.debug(f"Successfully decrypted {len(ciphertext)} bytes to {len(plaintext)} bytes")
        return plaintext

    except nacl.exceptions.CryptoError as exc:
        logger.error(f"Decryption failed: {exc}")
        raise DecryptionError(f"Failed to decrypt ciphertext: {exc}") from exc
