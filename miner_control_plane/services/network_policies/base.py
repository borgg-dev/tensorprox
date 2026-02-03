"""
Base interfaces for network policy subsystem.

This module defines the core abstractions that all network policies must implement,
enabling provider-agnostic capacity calculation and resource allocation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class HardCapacity:
    """
    Represents the technical/hard capacity limits for a shard.

    This structure communicates how many origin slots are available on a shard
    *right now*, based on provider-specific constraints (e.g., ENI IP limits,
    EIP availability, configured quotas, or unbounded capacity).

    TPM uses this to make placement decisions, avoiding timeouts and provider
    errors. TPM may enforce additional policy caps (e.g., "5 origins/shard")
    even if hard capacity is higher.

    Attributes:
        capacity_model: How capacity was determined:
            - "computed": Calculated from provider limits (e.g., ENI IPs)
            - "configured": From static configuration
            - "unbounded": No technical limit
            - "unknown": Unable to determine
        origin_slots_total: Total origin slots available on this shard.
            None if unbounded or unknown.
        origin_slots_used: Number of origin slots currently in use.
        origin_slots_available: Remaining origin slots (total - used).
            None if unbounded or unknown. This is the MIN of ENI slots and
            EIP availability when both constraints apply.
        limiting_factor: Human-readable description of the constraint
            (e.g., "ENI IPv4 addresses per interface", "EIP quota", "configured limit").
            None if no specific constraint.
        details: Provider-specific details for debugging/diagnostics
            (e.g., per-node breakdown, instance types, current IP counts).
        eip_quota: Configured EIP quota per region. None if not applicable.
        eip_used: Number of EIPs currently in use in the region. None if not applicable.
        eip_available: Number of EIPs available in the region. None if not applicable.
    """

    capacity_model: str
    origin_slots_total: int | None
    origin_slots_used: int
    origin_slots_available: int | None
    limiting_factor: str | None
    details: dict[str, Any]
    eip_quota: int | None = None
    eip_used: int | None = None
    eip_available: int | None = None


@dataclass
class AllocationResult:
    """
    Result of attaching an origin to the dataplane.

    Encapsulates provider-specific addressing/networking details for both
    active and standby nodes in a shard.

    Attributes:
        attachment_type: Type of attachment performed:
            - "aws_secondary_private_ipv4": AWS secondary IP allocation
            - "noop": No attachment required
            - "floating_ip": Floating IP assignment
            - (other provider-specific types)
        active: Provider-specific details for active node attachment.
            For AWS: {"private_ip": "10.0.1.50", "eni_id": "eni-..."}
            For noop: {}
        standby: Provider-specific details for standby node attachment.
            Same structure as active.
    """

    attachment_type: str
    active: dict[str, Any]
    standby: dict[str, Any]


class NetworkPolicy(Protocol):
    """
    Protocol for provider-specific network policy implementations.

    Each provider/network model implements this protocol to handle:
    - Capacity calculation based on provider constraints
    - Resource allocation for origin attachment
    - Resource cleanup on origin decommission

    Implementations must be stateless and thread-safe. All state lives in
    the database and is accessed via state_manager.

    Attributes:
        name: Human-readable policy name (e.g., "AWS Secondary IPv4")
        provider: Provider identifier (e.g., "aws", "linode", "gcp")
    """

    name: str
    provider: str

    def shard_hard_capacity(self, *, shard_id: str) -> HardCapacity:
        """
        Calculate current hard capacity for a shard.

        This method must be fast and cacheable. It should not perform
        expensive operations or long-running provider API calls.

        Args:
            shard_id: Shard identifier to check capacity for

        Returns:
            HardCapacity structure with current capacity state

        Raises:
            ValueError: If shard_id is invalid or not found
            Exception: Provider-specific errors during capacity calculation
        """
        ...

    def ensure_origin_attachment(
        self, *, shard_id: str, origin_id: str, context: dict[str, Any]
    ) -> AllocationResult:
        """
        Allocate and configure dataplane resources for an origin.

        This method performs all provider-specific steps to attach an origin
        to the shard's active and standby nodes (e.g., allocate secondary IPs,
        configure OS interfaces, update routing tables).

        Must be idempotent: calling multiple times with the same parameters
        should not create duplicate resources.

        Args:
            shard_id: Shard to attach origin to
            origin_id: Origin identifier being attached
            context: Provider-specific context (e.g., required_ports, exit_hub_ip)

        Returns:
            AllocationResult with provider-specific attachment details

        Raises:
            ValueError: If parameters are invalid
            CapacityError: If no capacity available
            Exception: Provider-specific errors during allocation
        """
        ...

    def release_origin_attachment(
        self, *, shard_id: str, origin_id: str, allocation: AllocationResult
    ) -> None:
        """
        Release dataplane resources for an origin.

        This method performs cleanup of all provider-specific resources
        allocated by ensure_origin_attachment (e.g., deallocate secondary IPs,
        remove OS interface configuration).

        Must be idempotent: calling multiple times should be safe.

        Args:
            shard_id: Shard the origin was attached to
            origin_id: Origin identifier being released
            allocation: The AllocationResult returned from ensure_origin_attachment

        Raises:
            Exception: Provider-specific errors during cleanup (should log but not fail)
        """
        ...
