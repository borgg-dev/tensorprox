"""
Policy registry for selecting the appropriate NetworkPolicy based on provider.

This module provides the central policy selection mechanism that maps
cloud providers to their corresponding NetworkPolicy implementations.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from miner_control_plane.services.network_policies.base import NetworkPolicy
from shared.config import get_settings

if TYPE_CHECKING:
    from miner_control_plane.services.state_manager import StateManager

logger = logging.getLogger(__name__)

# Global cache for policy instances (avoid recreating on every call)
_policy_cache: dict[str, NetworkPolicy] = {}


def _get_or_create_policy(provider: str) -> NetworkPolicy:
    """
    Get or create a cached policy instance for the given provider.

    Args:
        provider: Provider identifier (e.g., "aws", "linode", "gcp")

    Returns:
        NetworkPolicy instance for the provider
    """
    if provider in _policy_cache:
        return _policy_cache[provider]

    # Import policies lazily to avoid circular dependencies
    # and allow for policies that don't exist yet
    policy: NetworkPolicy

    if provider.lower() == "aws":
        # AWS uses secondary private IPv4 addressing
        try:
            from miner_control_plane.services.network_policies.aws_secondary_ipv4 import (
                AwsSecondaryIpv4Policy,
            )

            policy = AwsSecondaryIpv4Policy()
            logger.info(f"Loaded AwsSecondaryIpv4Policy for provider: {provider}")
        except ImportError:
            logger.warning("AwsSecondaryIpv4Policy not yet implemented, falling back to NoopPolicy")
            # Fallback to NoopPolicy if AWS policy doesn't exist yet
            from miner_control_plane.services.network_policies.noop import NoopPolicy

            policy = NoopPolicy(provider="aws")
    else:
        # Other providers use NoopPolicy (no per-origin addressing required)
        try:
            from miner_control_plane.services.network_policies.noop import NoopPolicy

            policy = NoopPolicy(provider=provider)
            logger.info(f"Loaded NoopPolicy for provider: {provider}")
        except ImportError:
            logger.error(
                f"NoopPolicy not yet implemented, cannot load policy for provider: {provider}"
            )
            raise RuntimeError(
                f"No policy available for provider: {provider}. "
                "NoopPolicy must be implemented as the fallback."
            )

    # Cache the policy instance
    _policy_cache[provider] = policy
    return policy


def get_policy_for_shard(shard_id: str, state_manager: StateManager) -> NetworkPolicy:
    """
    Select and return the appropriate NetworkPolicy for a shard.

    Determines the provider by inspecting the shard's nodes. If nodes exist,
    uses the provider from the first node (all nodes in a shard should have
    the same provider). If no nodes exist yet, falls back to the miner's
    default configured provider.

    Policy instances are cached to avoid recreation on every call.

    Args:
        shard_id: Shard identifier to get policy for
        state_manager: StateManager instance for accessing shard/node state

    Returns:
        NetworkPolicy instance appropriate for the shard's provider

    Raises:
        ValueError: If shard_id is invalid or provider cannot be determined
        RuntimeError: If no policy implementation exists for the provider

    Example:
        >>> policy = get_policy_for_shard("eu-central-1", state_manager)
        >>> capacity = policy.shard_hard_capacity(shard_id="eu-central-1")
        >>> print(f"Available slots: {capacity.origin_slots_available}")
    """
    # Get nodes for this shard to determine provider
    nodes = state_manager.get_nodes_for_shard(shard_id)

    if not nodes:
        # No nodes yet - use default provider from config
        settings = get_settings()
        provider = settings.scrubber_provider
        logger.debug(f"No nodes found for shard {shard_id}, using default provider: {provider}")
    else:
        # Use provider from first node (all nodes in a shard should have same provider)
        provider = nodes[0].get("provider")

        if not provider:
            # Provider field not set - fall back to config default
            settings = get_settings()
            provider = settings.scrubber_provider
            logger.warning(
                f"Node {nodes[0].get('node_id')} in shard {shard_id} has no provider set, "
                f"using default: {provider}"
            )
        else:
            logger.debug(f"Shard {shard_id} uses provider: {provider}")

    if not provider:
        raise ValueError(
            f"Cannot determine provider for shard {shard_id}: "
            "no nodes exist and no default provider configured"
        )

    # Get or create the appropriate policy
    return _get_or_create_policy(provider)


def clear_policy_cache() -> None:
    """
    Clear the policy instance cache.

    This is primarily useful for testing or during development to force
    policy instances to be recreated.

    Warning:
        In production, this should only be called if policy implementations
        need to be hot-reloaded (e.g., during a rolling update).
    """
    global _policy_cache
    _policy_cache.clear()
    logger.info("Policy cache cleared")
