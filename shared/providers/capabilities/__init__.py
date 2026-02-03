"""Capability interfaces for optional provider features.

Capabilities allow providers to declare support for features beyond
the base instance lifecycle. Code can check for capabilities before
using them.

IMPORTANT: Capability methods return Dict/List[Dict] for backward
compatibility, not dataclasses.
"""

from typing import Optional, Type, TypeVar

from shared.providers.base import BaseProvider

T = TypeVar("T")


def has_capability(provider: BaseProvider, capability_name: str) -> bool:
    """Check if provider supports a capability."""
    return capability_name in provider.capabilities


def get_capability(provider: BaseProvider, capability_class: Type[T]) -> Optional[T]:
    """Get capability adapter from provider if supported."""
    if isinstance(provider, capability_class):
        return provider

    capability_name = getattr(capability_class, "capability_name", None)
    if capability_name and has_capability(provider, capability_name):
        adapter_method = getattr(provider, f"get_{capability_name}_adapter", None)
        if adapter_method:
            return adapter_method()

    return None


__all__ = ["has_capability", "get_capability"]
