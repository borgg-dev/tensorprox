"""Provider capability registry for exit-hub placement and defaults."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Optional

from shared.config import TensorProxSettings, get_tp_management_settings
from shared.providers.aws_provider import AWSProvider
from shared.providers.linode import LinodeProvider
from shared.utils.logging import get_logger


@dataclass
class ProviderCapabilities:
    """Encapsulate provider-specific defaults."""

    name: str
    default_region: Callable[[TensorProxSettings], str]
    default_instance_type: Callable[[TensorProxSettings], str]
    available_regions: Optional[list[str]] = None


def _aws_default_instance_type(settings: TensorProxSettings) -> str:
    """Pick an AWS-friendly instance type when no explicit override is given."""
    configured = settings.exit_hub_instance_type
    if configured and not configured.startswith("g6-"):
        return configured
    return "t3.medium"


class ProviderRegistry:
    """Central registry to resolve provider defaults for exit hubs."""

    def __init__(self, settings: TensorProxSettings):
        self.settings = settings
        self.logger = get_logger(__name__)
        region_catalog = self._load_region_catalog()
        self._providers: Dict[str, ProviderCapabilities] = {
            "linode": ProviderCapabilities(
                name="linode",
                default_region=lambda s: s.exit_hub_region or s.linode_region,
                default_instance_type=lambda s: s.exit_hub_instance_type,
                available_regions=region_catalog.get("linode"),
            ),
            "aws": ProviderCapabilities(
                name="aws",
                default_region=lambda s: s.aws_region,
                default_instance_type=_aws_default_instance_type,
                available_regions=region_catalog.get("aws"),
            ),
        }

    @property
    def default_provider(self) -> str:
        """Fallback provider when none is specified."""
        return (self.settings.scrubber_provider or "linode").lower()

    def resolve_provider(
        self,
        requested_provider: Optional[str],
        miner_provider: Optional[str],
    ) -> str:
        """Pick provider using request hint → miner metadata → default."""
        for candidate in (requested_provider, miner_provider, self.default_provider):
            if candidate:
                return str(candidate).lower()
        return self.default_provider

    def resolve_region(
        self,
        provider: str,
        requested_region: Optional[str],
        miner_region: Optional[str],
    ) -> str:
        """Pick region using request hint → miner metadata → provider defaults."""
        if requested_region:
            return requested_region
        if miner_region:
            return miner_region
        caps = self._providers.get(provider)
        if caps:
            return caps.default_region(self.settings)
        # Fallback: use existing exit_hub_region or provider-agnostic default.
        return self.settings.exit_hub_region

    def resolve_instance_type(
        self,
        provider: str,
        requested_instance_type: Optional[str],
    ) -> Optional[str]:
        """Pick instance type using request hint → provider defaults."""
        if requested_instance_type:
            return requested_instance_type
        caps = self._providers.get(provider)
        if caps:
            return caps.default_instance_type(self.settings)
        return self.settings.exit_hub_instance_type

    def available_regions(self, provider: str) -> Optional[list[str]]:
        caps = self._providers.get(provider)
        return caps.available_regions if caps else None

    def validate_region(self, provider: str, region: str) -> None:
        """Ensure region is known for provider when catalog is available."""
        regions = self.available_regions(provider)
        if regions is None:
            return
        if region not in regions:
            raise ValueError(f"Region {region} not available for provider {provider}")

    def get_provider(self, name: str):
        """Get a provider instance by name.

        Uses TPM's own credentials (from .env) for exit hub deployments,
        NOT the miner's credentials.

        Args:
            name: Provider name ('aws' or 'linode')

        Returns:
            Provider instance (AWSProvider or LinodeProvider)
        """
        name = name.lower()
        tpm_settings = get_tp_management_settings()
        if name == "aws":
            # Use TPM's AWS credentials for exit hub deployment
            return AWSProvider(
                access_key_id=tpm_settings.aws_access_key_id,
                secret_access_key=tpm_settings.aws_secret_access_key,
                region=tpm_settings.aws_region,
            )
        elif name == "linode":
            return LinodeProvider(token=tpm_settings.linode_token)
        raise ValueError(f"Unknown provider: {name}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load_region_catalog(self) -> Dict[str, list[str]]:
        """Load available regions per provider (best-effort)."""
        catalog: Dict[str, list[str]] = {}
        tpm_settings = get_tp_management_settings()

        # AWS regions (using TPM's credentials)
        try:
            aws = AWSProvider(
                access_key_id=tpm_settings.aws_access_key_id,
                secret_access_key=tpm_settings.aws_secret_access_key,
                region=tpm_settings.aws_region,
            )
            catalog["aws"] = aws.describe_regions()
        except Exception as exc:  # noqa: BLE001
            self.logger.warning("Unable to load AWS regions: %s", exc)

        # Linode regions
        try:
            linode = LinodeProvider(token=tpm_settings.linode_token)
            catalog["linode"] = linode.list_regions()
        except Exception as exc:  # noqa: BLE001
            self.logger.warning("Unable to load Linode regions: %s", exc)

        return catalog
