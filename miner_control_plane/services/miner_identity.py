"""Miner-side registration and authentication helpers."""
from __future__ import annotations

import base64
import hmac
import json
import os
import socket
import threading
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import UUID

import requests

try:
    from nacl.public import Box, PrivateKey, PublicKey
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

from shared.config import TensorProxSettings
from shared.utils.logging import get_logger

logger = get_logger(__name__)


def _get_default_identity_path() -> Path:
    """
    Get the default identity path, unique per hotkey.

    If MINER_IDENTITY_PATH is set, use that directly.
    Otherwise, derive the path from the wallet hotkey to ensure
    each miner has its own identity file.
    """
    explicit_path = os.environ.get("MINER_IDENTITY_PATH")
    if explicit_path:
        return Path(explicit_path).expanduser()

    # Try to get hotkey name from tensorprox settings for unique identity file
    try:
        from tensorprox.settings import get_settings as get_tensorprox_settings
        tp_settings = get_tensorprox_settings()
        hotkey_name = tp_settings.wallet_hotkey
        if hotkey_name and hotkey_name != "default":
            return Path(f"~/.tensorprox/miner_identity_{hotkey_name}.json").expanduser()
    except Exception:
        pass

    # Fallback to default path
    return Path("~/.tensorprox/miner_identity.json").expanduser()


class MinerIdentityManager:
    """Persist miner credentials and register with TensorProx Management."""

    def __init__(self, identity_path: Optional[Path] = None):
        self.identity_path = identity_path or _get_default_identity_path()
        self._miner_id: Optional[str] = None
        self._miner_secret: Optional[str] = None
        self._miner_private_key: Optional[bytes] = None  # For credential updates
        self._redis_host: Optional[str] = None
        self._redis_port: Optional[int] = None
        self._redis_password: Optional[str] = None
        self._redis_channels: Optional[Dict[str, str]] = None
        self._session = requests.Session()
        self._lock = threading.Lock()
        self._validator_bootstrap_token: Optional[str] = None  # Token from validator PingSynapse

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def set_bootstrap_token(self, token: str, settings: Optional[TensorProxSettings] = None) -> bool:
        """
        Set bootstrap token received from validator and retry registration if needed.

        Called by the miner when it receives a PingSynapse with a bootstrap_token.
        If not already registered, attempts registration with the new token.

        Args:
            token: Bootstrap token from validator's PingSynapse
            settings: TensorProx settings (fetched if not provided)

        Returns:
            True if already registered or registration succeeded, False otherwise
        """
        with self._lock:
            self._validator_bootstrap_token = token

            # If already registered, no need to retry
            if self._miner_id and self._miner_secret:
                logger.debug("Already registered with TPM, ignoring new bootstrap token")
                return True

            # Try to register with the new token
            if settings is None:
                from shared.config import get_settings
                settings = get_settings()

            try:
                logger.info("Attempting TPM registration with validator-provided bootstrap token")
                self._register_with_tensorprox(settings)
                return True
            except RuntimeError as e:
                logger.warning(f"TPM registration with bootstrap token failed: {e}")
                return False

    @property
    def is_registered(self) -> bool:
        """Check if miner is registered with TPM."""
        return bool(self._miner_id and self._miner_secret)

    def ensure_registered(self, settings: TensorProxSettings) -> None:
        """Load cached identity and register/refresh credentials with TPM."""
        with self._lock:
            self._load_identity()
            try:
                self._register_with_tensorprox(settings)
            except RuntimeError as e:
                # If TPM unavailable but we have cached credentials, continue
                if self._miner_id and self._miner_secret:
                    logger.warning(
                        f"TPM registration failed ({e}), using cached credentials "
                        f"(miner_id={self._miner_id})"
                    )
                else:
                    raise

    def verify_authorization_header(self, header_value: Optional[str]) -> bool:
        """Return True if the provided Authorization header matches the secret."""
        secret = self._miner_secret
        if not secret:
            logger.warning("Miner secret unavailable; registration required")
            return False

        token = self._extract_bearer_token(header_value)
        if not token:
            return False

        return hmac.compare_digest(secret, token)

    @property
    def miner_id(self) -> Optional[str]:
        return self._miner_id

    @property
    def redis_config(self) -> Optional[Dict[str, Any]]:
        """Return Redis connection config if available from TPM registration."""
        if not self._redis_host:
            return None
        return {
            "host": self._redis_host,
            "port": self._redis_port or 6379,
            "password": self._redis_password,
            "channels": self._redis_channels or {},
        }

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _register_with_tensorprox(
        self, settings: TensorProxSettings, _retry: bool = False
    ) -> None:
        url = f"{self._tensorprox_base(settings)}/api/v1/miners/register"
        payload = self._build_payload(settings)
        headers = {}
        # Prefer validator-provided token (from PingSynapse), fall back to settings
        bootstrap_token = self._validator_bootstrap_token or settings.tp_miner_bootstrap_token
        if bootstrap_token:
            headers["X-TPM-Bootstrap"] = bootstrap_token

        try:
            response = self._session.post(
                url,
                json=payload,
                headers=headers,
                timeout=(5, 20),
            )
        except requests.RequestException as exc:  # pragma: no cover - network layer
            raise RuntimeError(f"Miner registration request failed: {exc}") from exc

        # Handle 404 "miner_not_found" - clear stale identity and re-register
        if response.status_code == 404 and not _retry:
            if "miner_not_found" in response.text:
                old_miner_id = self._miner_id  # Capture before clearing
                logger.warning(
                    "TPM returned miner_not_found for cached ID %s, "
                    "clearing identity and re-registering",
                    self._miner_id,
                )
                self._clear_identity()
                # Re-register to get new miner_id
                self._register_with_tensorprox(settings, _retry=True)
                # Migrate database records from old to new miner_id
                if old_miner_id and self._miner_id and old_miner_id != self._miner_id:
                    self._migrate_miner_id_records(old_miner_id, self._miner_id)
                return

        if response.status_code >= 400:
            raise RuntimeError(
                f"Miner registration failed "
                f"({response.status_code}): {response.text}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError("Invalid JSON response from TensorProx") from exc

        miner = data.get("miner") or {}
        miner_id = miner.get("miner_id") or miner.get("id")
        if not miner_id:
            raise RuntimeError("TensorProx did not return a miner_id")

        self._miner_id = str(miner_id)
        new_secret = data.get("miner_secret")
        if new_secret:
            self._miner_secret = str(new_secret)
        elif not self._miner_secret:
            existing_secret = payload.get("miner_secret")
            if existing_secret:
                self._miner_secret = existing_secret
        if not self._miner_secret:
            raise RuntimeError("Miner secret missing after registration")

        # Extract Redis credentials if provided
        redis_config = data.get("redis")
        if redis_config:
            self._redis_host = redis_config.get("host")
            self._redis_port = redis_config.get("port", 6379)
            self._redis_password = redis_config.get("password")
            self._redis_channels = redis_config.get("channels", {})
            logger.info(
                "Received Redis credentials from TPM (host=%s, channels=%s)",
                self._redis_host,
                list(self._redis_channels.keys()) if self._redis_channels else [],
            )

        self._persist_identity()
        logger.info("Miner registered with TensorProx as %s", self._miner_id)

    def _tensorprox_base(self, settings: TensorProxSettings) -> str:
        host = getattr(settings, "tensorprox_host", "127.0.0.1")
        if host.startswith(("http://", "https://")):
            return host.rstrip("/")
        if ":" in host:
            return f"http://{host}"
        return f"http://{host}:{settings.tensorprox_port}"

    def _build_payload(self, settings: TensorProxSettings) -> Dict[str, object]:
        # When TPM is localhost, register with localhost so TPM can reach us
        tpm_host = getattr(settings, "tensorprox_host", "127.0.0.1")
        is_local_tpm = tpm_host in ("127.0.0.1", "localhost", "0.0.0.0")
        contact_ip = "127.0.0.1" if is_local_tpm else settings.emn_ip

        metadata = {
            "emn_ip": contact_ip,
            "emn_port": settings.emn_port,
            "hostname": socket.gethostname(),
            "provider": settings.scrubber_provider,
            "region": settings.scrubber_region,
        }
        payload: Dict[str, object] = {
            "name": socket.gethostname(),
            "metadata": metadata,
        }
        if self._miner_id:
            payload["miner_id"] = self._miner_id
        if self._miner_secret:
            payload["miner_secret"] = self._miner_secret

        # Get Bittensor hotkey directly from wallet for subnet_miners linkage
        hotkey = self._get_bittensor_hotkey()
        if hotkey:
            payload["hotkey"] = hotkey
            logger.info("Including Bittensor hotkey in registration: %s...", hotkey[:16])

        # Add encrypted cloud credentials if available
        encrypted = self._prepare_encrypted_credentials(settings)
        if encrypted:
            payload["miner_public_key"] = encrypted["miner_public_key"]
            payload["cloud_credentials_enc"] = encrypted["cloud_credentials_enc"]

        return payload

    def _get_bittensor_hotkey(self) -> Optional[str]:
        """Get the SS58 hotkey address from Bittensor wallet.

        Loads the wallet using tensorprox settings and returns the
        hotkey's SS58 address for subnet_miners linkage.
        """
        try:
            from tensorprox.settings import get_settings as get_tensorprox_settings
            tp_settings = get_tensorprox_settings()
            hotkey_ss58 = tp_settings.wallet.hotkey.ss58_address
            logger.debug("Retrieved Bittensor hotkey: %s", hotkey_ss58[:16] if hotkey_ss58 else None)
            return hotkey_ss58
        except Exception as exc:
            logger.warning("Failed to get Bittensor hotkey from wallet: %s", exc)
            return None

    def _prepare_encrypted_credentials(
        self, settings: TensorProxSettings
    ) -> Optional[Dict[str, str]]:
        """Encrypt cloud credentials for secure transmission to TPM.

        Returns:
            Dict with miner_public_key and cloud_credentials_enc (base64),
            or None if credentials unavailable or encryption not possible.
        """
        if not NACL_AVAILABLE:
            logger.debug("NaCl not available, skipping credential encryption")
            return None

        # Get cloud credentials based on provider
        credentials = self._get_cloud_credentials(settings)
        if not credentials:
            logger.debug("No cloud credentials available for provider %s",
                         settings.scrubber_provider)
            return None

        # Fetch TPM's public key
        tpm_public_key = self._fetch_tpm_public_key(settings)
        if not tpm_public_key:
            logger.warning("Could not fetch TPM public key, skipping credential encryption")
            return None

        # Encrypt credentials
        try:
            encrypted = self._encrypt_credentials(credentials, tpm_public_key)
            logger.info(
                "Encrypted cloud credentials for provider %s (size: %d bytes)",
                settings.scrubber_provider,
                len(encrypted["cloud_credentials_enc"]),
            )
            return encrypted
        except Exception as exc:
            logger.error("Failed to encrypt credentials: %s", exc)
            return None

    def _get_cloud_credentials(
        self, settings: TensorProxSettings
    ) -> Optional[Dict[str, Any]]:
        """Build provider-specific credential dict from settings."""
        provider = settings.scrubber_provider.lower()

        if provider == "aws":
            access_key = getattr(settings, "aws_access_key_id", None)
            secret_key = getattr(settings, "aws_secret_access_key", None)
            region = getattr(settings, "aws_region", None) or settings.scrubber_region

            if access_key and secret_key:
                return {
                    "provider": "aws",
                    "aws_access_key_id": access_key,
                    "aws_secret_access_key": secret_key,
                    "aws_region": region,
                }
            logger.debug("AWS credentials not configured in settings")
            return None

        elif provider == "linode":
            token = getattr(settings, "linode_token", None)

            if token:
                return {
                    "provider": "linode",
                    "linode_token": token,
                }
            logger.debug("Linode token not configured in settings")
            return None

        else:
            logger.debug("Unknown provider %s, no credential mapping", provider)
            return None

    def _fetch_tpm_public_key(self, settings: TensorProxSettings) -> Optional[bytes]:
        """Fetch TPM's X25519 public key for credential encryption."""
        url = f"{self._tensorprox_base(settings)}/api/v1/tpm/public-key"

        try:
            response = self._session.get(url, timeout=(5, 10))
            if response.status_code != 200:
                logger.warning(
                    "TPM public key request failed (%d): %s",
                    response.status_code,
                    response.text[:200],
                )
                return None

            data = response.json()
            public_key_b64 = data.get("public_key")
            if not public_key_b64:
                logger.warning("TPM public key response missing 'public_key' field")
                return None

            public_key = base64.b64decode(public_key_b64)
            if len(public_key) != 32:
                logger.warning(
                    "TPM public key invalid length: %d (expected 32)", len(public_key)
                )
                return None

            logger.debug(
                "Fetched TPM public key (key_id=%s)",
                data.get("key_id", "unknown"),
            )
            return public_key

        except requests.RequestException as exc:
            logger.warning("Failed to fetch TPM public key: %s", exc)
            return None
        except (ValueError, KeyError) as exc:
            logger.warning("Failed to parse TPM public key response: %s", exc)
            return None

    def _encrypt_credentials(
        self, credentials: Dict[str, Any], tpm_public_key: bytes
    ) -> Dict[str, str]:
        """Encrypt credentials using NaCl box (X25519 + XSalsa20-Poly1305).

        Args:
            credentials: Plaintext credentials dict
            tpm_public_key: TPM's 32-byte X25519 public key

        Returns:
            Dict with:
              - miner_public_key: Base64-encoded 32-byte miner public key
              - cloud_credentials_enc: Base64-encoded NaCl box ciphertext
        """
        # Use existing keypair or generate new one
        if self._miner_private_key:
            miner_private = PrivateKey(self._miner_private_key)
        else:
            miner_private = PrivateKey.generate()
            self._miner_private_key = bytes(miner_private)

        miner_public = miner_private.public_key
        tpm_public = PublicKey(tpm_public_key)

        # Encrypt credentials
        box = Box(miner_private, tpm_public)
        plaintext = json.dumps(credentials, separators=(",", ":")).encode("utf-8")
        ciphertext = box.encrypt(plaintext)  # Includes nonce

        return {
            "miner_public_key": base64.b64encode(bytes(miner_public)).decode("ascii"),
            "cloud_credentials_enc": base64.b64encode(ciphertext).decode("ascii"),
        }

    def _load_identity(self) -> None:
        path = self.identity_path
        if not path.exists():
            return
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            logger.warning("Failed to read miner identity from %s: %s", path, exc)
            return

        miner_id = data.get("miner_id")
        miner_secret = data.get("miner_secret")
        if miner_id and miner_secret:
            try:
                self._miner_id = str(UUID(str(miner_id)))
            except ValueError:
                logger.warning("Miner identity contains invalid miner_id; ignoring")
                return
            self._miner_secret = str(miner_secret)

            # Load miner private key if present (for credential updates)
            miner_private_key_b64 = data.get("miner_private_key")
            if miner_private_key_b64:
                try:
                    self._miner_private_key = base64.b64decode(miner_private_key_b64)
                except Exception as exc:
                    logger.warning("Failed to decode miner_private_key: %s", exc)

            redis_data = data.get("redis")
            if redis_data:
                self._redis_host = redis_data.get("host")
                self._redis_port = redis_data.get("port")
                self._redis_password = redis_data.get("password")
                self._redis_channels = redis_data.get("channels")
        else:
            logger.warning("Miner identity file %s missing fields; ignoring", path)

    def _persist_identity(self) -> None:
        if not self._miner_id or not self._miner_secret:
            return

        payload: Dict[str, Any] = {
            "miner_id": self._miner_id,
            "miner_secret": self._miner_secret,
        }

        # Persist miner private key for credential updates
        if self._miner_private_key:
            payload["miner_private_key"] = base64.b64encode(
                self._miner_private_key
            ).decode("ascii")

        if self._redis_host:
            payload["redis"] = {
                "host": self._redis_host,
                "port": self._redis_port,
                "password": self._redis_password,
                "channels": self._redis_channels,
            }

        path = self.identity_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = path.with_name(path.name + ".tmp")
            with tmp_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
            os.chmod(tmp_path, 0o600)
            tmp_path.replace(path)
        except OSError as exc:
            raise RuntimeError(f"Failed to persist miner identity: {exc}") from exc

    def _migrate_miner_id_records(self, old_miner_id: str, new_miner_id: str) -> None:
        """
        Migrate database records from old miner_id to new miner_id.

        This is called when TPM re-registration assigns a new miner_id (e.g., after
        TPM database was cleared). Updates all local ECP database records to use
        the new miner_id so they remain accessible.

        Tables migrated:
        - shards: Shard definitions owned by this miner
        - nodes: Scrubber instances owned by this miner
        - origins: Customer origins deployed on this miner
        - deployment_jobs: Jobs belonging to this miner
        """
        try:
            from shared.database import get_db_connection

            logger.info(
                "Migrating database records from miner_id %s to %s",
                old_miner_id, new_miner_id
            )

            db = get_db_connection()
            cur = db.conn.cursor()

            tables = ['shards', 'nodes', 'origins', 'deployment_jobs']
            total_updated = 0

            for table in tables:
                try:
                    cur.execute(
                        f"UPDATE {table} SET miner_id = %s WHERE miner_id = %s",
                        (new_miner_id, old_miner_id)
                    )
                    updated = cur.rowcount
                    if updated > 0:
                        logger.info(f"Migrated {updated} rows in {table}")
                        total_updated += updated
                except Exception as e:
                    logger.warning(f"Failed to migrate {table}: {e}")
                    db.conn.rollback()

            db.conn.commit()
            cur.close()

            if total_updated > 0:
                logger.info(
                    "Miner ID migration complete: %d total records migrated from %s to %s",
                    total_updated, old_miner_id, new_miner_id
                )
            else:
                logger.info(
                    "Miner ID migration: no records found for old_miner_id %s",
                    old_miner_id
                )

        except Exception as e:
            logger.error(f"Miner ID migration failed: {e}", exc_info=True)

    def clear_identity(self) -> None:
        """Clear cached credentials and delete identity file (public API)."""
        self._clear_identity()

    def _clear_identity(self) -> None:
        """Clear cached credentials and delete identity file."""
        self._miner_id = None
        self._miner_secret = None
        self._miner_private_key = None
        self._redis_host = None
        self._redis_port = None
        self._redis_password = None
        self._redis_channels = None
        try:
            if self.identity_path.exists():
                self.identity_path.unlink()
                logger.info("Deleted stale identity file %s", self.identity_path)
        except OSError as exc:
            logger.warning("Failed to delete identity file: %s", exc)

    @staticmethod
    def _extract_bearer_token(header_value: Optional[str]) -> Optional[str]:
        if not header_value:
            return None
        value = header_value.strip()
        if not value:
            return None
        if value.lower().startswith("bearer "):
            return value[7:].strip()
        return value


_miner_identity_instance: Optional[MinerIdentityManager] = None


def get_miner_identity() -> MinerIdentityManager:
    """
    Get the miner identity manager singleton.

    Lazy initialization ensures the identity path is resolved
    after environment variables (like TP_WALLET_HOTKEY) are set.
    """
    global _miner_identity_instance
    if _miner_identity_instance is None:
        _miner_identity_instance = MinerIdentityManager()
    return _miner_identity_instance


# For backwards compatibility - will be lazily initialized on first access
class _LazyMinerIdentity:
    """Lazy proxy for miner_identity singleton."""

    def __getattr__(self, name):
        return getattr(get_miner_identity(), name)


miner_identity = _LazyMinerIdentity()
