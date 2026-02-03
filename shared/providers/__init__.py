"""Provider factory and exports"""
from .base import BaseProvider, ProviderError
from .linode import LinodeProvider
from .aws_provider import AWSProvider

# Supported cloud providers per node type.
# Scrubbers currently only support AWS due to ENI/EIP requirements and XDP
# bootstrap scripts that depend on AWS-specific networking (ens5, metadata service).
# Linode support is not implemented for scrubbers.
SCRUBBER_SUPPORTED_PROVIDERS = ("aws",)


def get_provider(name: str) -> BaseProvider:
    """
    Factory function to get provider instance.

    Args:
        name: Provider name ('aws', 'linode')

    Returns:
        Provider instance

    Raises:
        ValueError: If provider name is unknown
    """
    providers = {
        'linode': LinodeProvider,
        'aws': AWSProvider,
    }

    name_lower = name.lower()

    if name_lower not in providers:
        available = list(providers.keys())
        raise ValueError(
            f"Unknown provider: {name}. Available providers: {available}"
        )

    return providers[name_lower]()


__all__ = [
    'BaseProvider', 'ProviderError', 'LinodeProvider', 'AWSProvider',
    'get_provider', 'SCRUBBER_SUPPORTED_PROVIDERS',
]
