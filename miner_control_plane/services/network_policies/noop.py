"""
NoopPolicy: Generic fallback network policy for providers without per-origin addressing.

This policy is used for cloud providers that don't require per-origin private IP
allocation. Capacity is derived from static configuration rather than computed
from provider-specific limits (like ENI IP addresses).

This is suitable for providers where:
- Origin routing doesn't require dedicated private IPs per origin
- Traffic can be handled through shared infrastructure
- Capacity is limited by configuration/policy rather than technical constraints
"""

from __future__ import annotations

import logging
from typing import Any

from miner_control_plane.services.network_policies.base import (
    AllocationResult,
    HardCapacity,
)

logger = logging.getLogger(__name__)

# Default origin capacity per shard for noop providers
# This can be overridden via config in the future
DEFAULT_ORIGINS_PER_SHARD = 50


class NoopPolicy:
    """
    Generic network policy that performs no per-origin resource allocation.

    This policy is suitable for cloud providers where origin traffic routing
    does not require allocating dedicated private IP addresses or other
    per-origin network resources.

    Capacity is determined by a static configuration value rather than
    computed from provider-specific limits.

    Attributes:
        name: Human-readable policy name
        provider: Provider this policy is configured for
        capacity_per_shard: Maximum origins allowed per shard
    """

    def __init__(
        self,
        provider: str = "generic",
        capacity_per_shard: int = DEFAULT_ORIGINS_PER_SHARD,
    ):
        """
        Initialize NoopPolicy.

        Args:
            provider: Provider identifier this policy is for (e.g., "linode", "gcp")
            capacity_per_shard: Maximum number of origins allowed per shard
        """
        self.name = "noop"
        self.provider = provider
        self.capacity_per_shard = capacity_per_shard
        logger.info(
            f"Initialized NoopPolicy for provider '{provider}' "
            f"with capacity_per_shard={capacity_per_shard}"
        )

    def shard_hard_capacity(self, *, shard_id: str) -> HardCapacity:
        """
        Calculate hard capacity based on configuration.

        For NoopPolicy, capacity is static and configured at initialization.
        The only dynamic element is counting how many origins are already
        deployed on the shard.

        Args:
            shard_id: Shard to calculate capacity for

        Returns:
            HardCapacity with configuration-based limits

        Example:
            >>> policy = NoopPolicy(provider="linode", capacity_per_shard=50)
            >>> capacity = policy.shard_hard_capacity(shard_id="us-east-1")
            >>> print(capacity.origin_slots_available)  # e.g., 47 if 3 origins exist
        """
        # Import here to avoid circular dependency
        from miner_control_plane.services.state_manager import state_manager

        # Count how many origins are currently deployed on this shard
        origins = state_manager.get_origins_for_shard(shard_id)
        origin_slots_used = len(origins)
        origin_slots_available = self.capacity_per_shard - origin_slots_used

        logger.debug(
            f"NoopPolicy capacity for shard {shard_id}: "
            f"{origin_slots_used}/{self.capacity_per_shard} slots used, "
            f"{origin_slots_available} available"
        )

        return HardCapacity(
            capacity_model="configured",
            origin_slots_total=self.capacity_per_shard,
            origin_slots_used=origin_slots_used,
            origin_slots_available=origin_slots_available,
            limiting_factor=f"Configuration-based capacity (max {self.capacity_per_shard} origins/shard)",
            details={
                "provider": self.provider,
                "policy": self.name,
                "capacity_per_shard": self.capacity_per_shard,
                "origins_deployed": origin_slots_used,
            },
        )

    def ensure_origin_attachment(
        self, *, shard_id: str, origin_id: str, context: dict[str, Any]
    ) -> AllocationResult:
        """
        Perform no-op attachment (no resources to allocate).

        For NoopPolicy, origin attachment doesn't require allocating
        provider-specific resources like private IPs. The origin can be
        routed through shared infrastructure.

        Args:
            shard_id: Shard to attach origin to
            origin_id: Origin being attached
            context: Additional context (unused for noop)

        Returns:
            AllocationResult with empty allocation details

        Example:
            >>> policy = NoopPolicy(provider="linode")
            >>> result = policy.ensure_origin_attachment(
            ...     shard_id="us-east-1",
            ...     origin_id="O1",
            ...     context={"exit_hub_ip": "1.2.3.4"}
            ... )
            >>> print(result.attachment_type)  # "noop"
            >>> print(result.active)  # {}
        """
        logger.info(
            f"NoopPolicy: No-op attachment for origin {origin_id} on shard {shard_id} "
            f"(provider: {self.provider})"
        )

        # Return empty allocation - no provider-specific resources allocated
        return AllocationResult(
            attachment_type="noop",
            active={},
            standby={},
        )

    def release_origin_attachment(
        self, *, shard_id: str, origin_id: str, allocation: AllocationResult
    ) -> None:
        """
        Perform no-op release (no resources to deallocate).

        For NoopPolicy, there are no provider-specific resources to clean up
        since none were allocated during attachment.

        Args:
            shard_id: Shard the origin was attached to
            origin_id: Origin being released
            allocation: The allocation result from ensure_origin_attachment (unused)

        Example:
            >>> policy = NoopPolicy(provider="linode")
            >>> policy.release_origin_attachment(
            ...     shard_id="us-east-1",
            ...     origin_id="O1",
            ...     allocation=AllocationResult(attachment_type="noop", active={}, standby={})
            ... )
            # No-op, just logs
        """
        logger.info(
            f"NoopPolicy: No-op release for origin {origin_id} on shard {shard_id} "
            f"(provider: {self.provider})"
        )

        # Nothing to release - this is a no-op provider
        pass
