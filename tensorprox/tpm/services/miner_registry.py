"""Service responsible for miner registration and authentication state."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
from uuid import UUID, uuid4

from shared.utils.logging import get_logger

from tensorprox.tpm.repositories.miner_repository import MinerRepository
from tensorprox.tpm.services.validation.queue import trigger_miner_validation

logger = get_logger(__name__)


class MinerRegistryError(Exception):
    """Base error for miner registration flows."""


class MinerSecretInvalidError(MinerRegistryError):
    """Raised when a provided secret does not match the stored hash."""


class MinerNotFoundError(MinerRegistryError):
    """Raised when a miner record cannot be located."""


def normalize_miner_id(value: str) -> str:
    """Ensure miner IDs are valid UUID strings."""
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError) as exc:
        raise MinerSecretInvalidError("miner_id must be a valid UUID") from exc


class MinerRegistry:
    """Central authority for miner identifiers and secrets."""

    def __init__(self):
        self.repository = MinerRepository()

    def _revoke_stale_endpoint_owners(
        self,
        emn_ip: str,
        emn_port: int,
        exclude_miner_id: Optional[str] = None,
    ) -> int:
        """Revoke miners that claim the same endpoint but aren't the current owner.

        When a miner registers with an emn_ip:emn_port combination, any OTHER
        miners that previously claimed that endpoint are stale and should be
        revoked. This prevents auth failures when TPM tries to reach a miner
        at an endpoint owned by a different miner.

        Args:
            emn_ip: The EMN IP address being claimed
            emn_port: The EMN port being claimed
            exclude_miner_id: The miner_id to NOT revoke (the current owner)

        Returns:
            Number of stale miners revoked
        """
        revoked_count = 0
        all_miners = self.repository.list_miners()

        for miner in all_miners:
            miner_id = miner.get("miner_id")
            status = miner.get("status")

            # Skip the miner we're registering/updating
            if exclude_miner_id and miner_id == exclude_miner_id:
                continue

            # Skip already revoked miners
            if status != "active":
                continue

            # Check if this miner claims the same endpoint
            metadata = miner.get("metadata") or {}
            miner_emn_ip = metadata.get("emn_ip")
            miner_emn_port = metadata.get("emn_port", 8000)

            if miner_emn_ip == emn_ip and miner_emn_port == emn_port:
                logger.warning(
                    "Revoking stale miner %s: endpoint %s:%s now claimed by %s",
                    miner_id,
                    emn_ip,
                    emn_port,
                    exclude_miner_id or "new miner",
                )
                try:
                    self.repository.update_miner(miner_id, status="revoked")
                    revoked_count += 1
                except Exception as exc:
                    logger.error("Failed to revoke stale miner %s: %s", miner_id, exc)

        if revoked_count > 0:
            logger.info(
                "Revoked %d stale miner(s) claiming endpoint %s:%s",
                revoked_count,
                emn_ip,
                emn_port,
            )

        return revoked_count

    def register_or_update(
        self,
        *,
        miner_id: Optional[str],
        provided_secret: Optional[str],
        name: Optional[str],
        public_ip: Optional[str],
        metadata: Optional[Dict[str, object]] = None,
        miner_public_key: Optional[bytes] = None,
        cloud_credentials_enc: Optional[bytes] = None,
        hotkey: Optional[str] = None,
    ) -> Tuple[Dict[str, object], Optional[str]]:
        """Register a new miner or update an existing one.

        Args:
            miner_id: Existing miner UUID (if updating)
            provided_secret: Secret for authentication (required for updates)
            name: Display name for the miner
            public_ip: Current public IP
            metadata: Additional metadata
            miner_public_key: X25519 public key for credential encryption
            cloud_credentials_enc: Fernet-encrypted cloud credentials
            hotkey: Bittensor hotkey for linking to subnet_miners table

        Returns (record, plaintext_secret). Secret is only returned when a new
        miner is created.
        """
        # Store hotkey in metadata for later linkage to subnet_miners
        if hotkey:
            metadata = metadata or {}
            metadata["hotkey"] = hotkey

        if miner_id:
            normalized = normalize_miner_id(miner_id)
            return self._update_existing(
                miner_id=normalized,
                provided_secret=provided_secret,
                name=name,
                public_ip=public_ip,
                metadata=metadata,
                miner_public_key=miner_public_key,
                cloud_credentials_enc=cloud_credentials_enc,
            )
        return self._create_new(
            name=name,
            public_ip=public_ip,
            metadata=metadata,
            miner_public_key=miner_public_key,
            cloud_credentials_enc=cloud_credentials_enc,
        )

    def get_plaintext_secret(self, miner_id: str) -> str:
        normalized = normalize_miner_id(miner_id)
        record = self.repository.get_miner(normalized)
        if not record:
            raise MinerNotFoundError(normalized)
        if record.get("status") != "active":
            raise MinerRegistryError(f"Miner {normalized} is not active")
        secret = record.get("secret_plaintext")
        if not secret:
            raise MinerRegistryError(f"Miner {normalized} does not have a stored secret")
        return str(secret)

    def get_miner_ip(self, miner_id: str) -> str:
        """Get the current IP address for a miner.

        Args:
            miner_id: UUID of the miner

        Returns:
            The miner's current IP address

        Raises:
            MinerNotFoundError: If miner doesn't exist
            MinerRegistryError: If miner has no IP or is not active
        """
        normalized = normalize_miner_id(miner_id)
        record = self.repository.get_miner(normalized)
        if not record:
            raise MinerNotFoundError(normalized)
        if record.get("status") != "active":
            raise MinerRegistryError(f"Miner {normalized} is not active")
        current_ip = record.get("current_ip")
        if not current_ip:
            raise MinerRegistryError(f"Miner {normalized} does not have a current IP")
        return str(current_ip)

    def get_miner(self, miner_id: str) -> Dict[str, object] | None:
        """Get full miner record by ID.

        Args:
            miner_id: UUID of the miner

        Returns:
            Miner record dict or None if not found
        """
        normalized = normalize_miner_id(miner_id)
        return self.repository.get_miner(normalized)

    def revoke_miner(self, miner_id: str) -> None:
        normalized = normalize_miner_id(miner_id)
        record = self.repository.get_miner(normalized)
        if not record:
            raise MinerNotFoundError(normalized)
        now = datetime.now(timezone.utc)
        self.repository.update_miner(normalized, status="revoked", last_seen=now)

    def list_active_miners(self) -> list[Dict[str, object]]:
        """Return active miners with a current_ip set (sorted by last_seen desc)."""
        all_miners = self.repository.list_miners()
        active = [m for m in all_miners if m.get("status") == "active" and m.get("current_ip")]
        def _last_seen(rec):
            ts = rec.get("last_seen")
            return ts or ""
        return sorted(active, key=_last_seen, reverse=True)

    def get_all_available_regions(self) -> list[str]:
        """Get union of available regions from all active miners.

        Collects regions from each miner's validation results
        (metadata.validation.discover_regions.data).

        Returns:
            Sorted list of unique region identifiers that at least one miner can serve.
            Returns empty list if no miners have validated regions.
        """
        all_regions: set[str] = set()

        for miner in self.list_active_miners():
            metadata = miner.get("metadata", {})
            if not isinstance(metadata, dict):
                continue

            validation = metadata.get("validation", {})
            if not isinstance(validation, dict):
                continue

            discover_regions = validation.get("discover_regions", {})
            if not isinstance(discover_regions, dict):
                continue

            if discover_regions.get("status") != "success":
                continue

            regions = discover_regions.get("data", [])
            if isinstance(regions, list):
                all_regions.update(regions)

        return sorted(all_regions)

    def get_miner_available_regions(self, miner_id: str) -> list[str]:
        """Get available regions for a specific miner.

        Args:
            miner_id: UUID of the miner

        Returns:
            List of region identifiers from validation results, or empty list.
        """
        normalized = normalize_miner_id(miner_id)
        miner = self.repository.get_miner(normalized)
        if not miner:
            return []

        metadata = miner.get("metadata", {})
        if not isinstance(metadata, dict):
            return []

        validation = metadata.get("validation", {})
        if not isinstance(validation, dict):
            return []

        discover_regions = validation.get("discover_regions", {})
        if not isinstance(discover_regions, dict):
            return []

        if discover_regions.get("status") != "success":
            return []

        regions = discover_regions.get("data", [])
        return regions if isinstance(regions, list) else []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _create_new(
        self,
        *,
        name: Optional[str],
        public_ip: Optional[str],
        metadata: Optional[Dict[str, object]],
        miner_public_key: Optional[bytes] = None,
        cloud_credentials_enc: Optional[bytes] = None,
    ) -> Tuple[Dict[str, object], str]:
        miner_uuid = uuid4()
        miner_id = str(miner_uuid)

        # Revoke any stale miners claiming the same endpoint before registration
        # This prevents auth failures when the new miner takes over an endpoint
        if metadata:
            emn_ip = metadata.get("emn_ip")
            emn_port = metadata.get("emn_port", 8000)
            if emn_ip:
                self._revoke_stale_endpoint_owners(emn_ip, emn_port, exclude_miner_id=miner_id)

        secret = self._issue_secret()
        secret_hash = self._hash_secret(secret)
        now = datetime.now(timezone.utc)
        self.repository.create_miner(
            miner_id=miner_uuid,
            name=name,
            secret_hash=secret_hash,
            secret_plaintext=secret,
            current_ip=public_ip,
            metadata=metadata or {},
            miner_public_key=miner_public_key,
            cloud_credentials_enc=cloud_credentials_enc,
        )
        self.repository.update_miner(miner_id, last_seen=now)
        record = self.repository.get_miner(miner_id) or {}
        if miner_public_key:
            logger.info(
                "Registered new miner %s with cloud credentials (key size: %d bytes)",
                miner_id,
                len(miner_public_key),
            )

        if cloud_credentials_enc:
            try:
                trigger_miner_validation(miner_id)
                logger.info("Triggered async validation for miner %s", miner_id)
            except Exception as exc:
                logger.warning("Failed to queue validation for miner %s: %s", miner_id, exc)

        return record, secret

    def _update_existing(
        self,
        *,
        miner_id: str,
        provided_secret: Optional[str],
        name: Optional[str],
        public_ip: Optional[str],
        metadata: Optional[Dict[str, object]],
        miner_public_key: Optional[bytes] = None,
        cloud_credentials_enc: Optional[bytes] = None,
    ) -> Tuple[Dict[str, object], Optional[str]]:
        record = self.repository.get_miner(miner_id)
        if not record:
            raise MinerNotFoundError(miner_id)
        if not provided_secret or not self._verify_secret(record, provided_secret):
            raise MinerSecretInvalidError("Miner secret invalid")

        # Revoke any stale miners claiming the same endpoint when metadata changes
        # Use new metadata if provided, otherwise use existing metadata
        effective_metadata = metadata if metadata is not None else (record.get("metadata") or {})
        if effective_metadata:
            emn_ip = effective_metadata.get("emn_ip")
            emn_port = effective_metadata.get("emn_port", 8000)
            if emn_ip:
                self._revoke_stale_endpoint_owners(emn_ip, emn_port, exclude_miner_id=miner_id)

        now = datetime.now(timezone.utc)
        status_update = "active" if record.get("status") != "active" else None
        update_metadata = metadata if metadata is not None else None
        self.repository.update_miner(
            miner_id,
            name=name if name is not None else None,
            current_ip=public_ip if public_ip is not None else None,
            metadata=update_metadata,
            last_seen=now,
            status=status_update,
            miner_public_key=miner_public_key,
            cloud_credentials_enc=cloud_credentials_enc,
        )
        if miner_public_key:
            logger.info(
                "Updated credentials for miner %s (key size: %d bytes)",
                miner_id,
                len(miner_public_key),
            )

        if cloud_credentials_enc:
            try:
                trigger_miner_validation(miner_id)
                logger.info("Triggered async validation for miner %s", miner_id)
            except Exception as exc:
                logger.warning("Failed to queue validation for miner %s: %s", miner_id, exc)

        updated = self.repository.get_miner(miner_id) or record
        return updated, None

    @staticmethod
    def _hash_secret(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def _verify_secret(self, record: Dict[str, object], provided: str) -> bool:
        expected = record.get("secret_hash")
        return bool(expected) and expected == self._hash_secret(provided)

    @staticmethod
    def _issue_secret() -> str:
        return secrets.token_urlsafe(32)

    def ensure_miner_registered(
        self,
        miner_id: str,
        miner_ip: Optional[str] = None,
        miner_secret: Optional[str] = None,
    ) -> bool:
        """Ensure miner is registered in tensorprox_miners table.

        In decentralized mode, miners are discovered from subnet_miners (validator
        leaderboard) but that table doesn't have secret_plaintext. This method
        ensures the miner exists in tensorprox_miners with a secret for authentication.

        Args:
            miner_id: Miner UUID
            miner_ip: Optional miner IP (from metadata)
            miner_secret: Optional miner secret (if known, e.g., from bootstrap)

        Returns:
            True if miner was registered/updated, False if already existed

        This is called during deployment target selection to ensure TPM can
        authenticate to miners for delete operations later.
        """
        normalized = normalize_miner_id(miner_id)
        record = self.repository.get_miner(normalized)

        # Miner already registered with secret
        if record and record.get("secret_plaintext"):
            return False

        # Issue new secret if not provided
        if not miner_secret:
            miner_secret = self._issue_secret()

        # Register or update miner
        now = datetime.now(timezone.utc)
        secret_hash = self._hash_secret(miner_secret)

        if not record:
            # Create new miner record
            logger.info(
                "Registering miner %s in decentralized mode (auto-generated secret)",
                normalized
            )
            self.repository.create_miner(
                miner_id=UUID(normalized),
                name=f"miner-{normalized[:8]}",
                secret_hash=secret_hash,
                secret_plaintext=miner_secret,
                current_ip=miner_ip or "0.0.0.0",
                metadata={
                    "registered_mode": "decentralized",
                    "registered_at": now.isoformat(),
                },
            )
            return True
        else:
            # Update existing miner with secret
            logger.info(
                "Updating miner %s with secret for decentralized mode",
                normalized
            )
            self.repository.update_miner(
                UUID(normalized),
                secret_hash=secret_hash,
                secret_plaintext=miner_secret,
                current_ip=miner_ip or record.get("current_ip"),
                last_seen=now,
            )
            return True


# Singleton for use by other services
_registry: Optional[MinerRegistry] = None


def get_miner_registry() -> MinerRegistry:
    """Get or create the singleton miner registry."""
    global _registry
    if _registry is None:
        _registry = MinerRegistry()
    return _registry
