"""
Network policy subsystem for provider-agnostic capacity and addressing.

This module provides abstractions for:
- Computing hard capacity limits per shard
- Allocating dataplane attachment resources (e.g., private IPs)
- Releasing resources on origin decommission

Different providers/network models implement different policies
(e.g., AWS secondary IPv4, floating IPs, or no-op for providers
that don't require per-origin addressing).
"""

from miner_control_plane.services.network_policies.base import (
    AllocationResult,
    HardCapacity,
    NetworkPolicy,
)
from miner_control_plane.services.network_policies.registry import (
    clear_policy_cache,
    get_policy_for_shard,
)

__all__ = [
    "AllocationResult",
    "HardCapacity",
    "NetworkPolicy",
    "get_policy_for_shard",
    "clear_policy_cache",
]
