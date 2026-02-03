"""
AWS Secondary IPv4 Network Policy.

Implements dynamic IP allocation for AWS scrubbers using secondary private IPv4
addresses on ENIs. This eliminates hard-coded IP ranges and enables
provider-agnostic capacity calculation.

Architecture:
- Capacity: Calculated from ENI IPv4 limits minus current usage
- Allocation: Uses AWS auto-assign for secondary IPs + OS configuration
- Release: Removes IPs from ENI and OS interface

Reference: MINER-SPEC.md Section 3.2
"""

import logging
from typing import Any

from miner_control_plane.services.network_policies.base import (
    AllocationResult,
    HardCapacity,
)
from miner_control_plane.services.eip_availability import eip_availability
from shared.config import get_settings
from shared.providers import get_provider
from shared.utils.ssh import ssh_exec

logger = logging.getLogger(__name__)


class AwsSecondaryIpv4Policy:
    """
    AWS network policy using secondary private IPv4 addresses on ENIs.

    Provides dynamic capacity calculation based on AWS ENI IP limits and
    automatic IP allocation without hard-coded ranges.

    Attributes:
        name: Policy identifier ("AWS Secondary IPv4")
        provider: Provider identifier ("aws")
    """

    name = "AWS Secondary IPv4"
    provider = "aws"

    def __init__(self):
        """Initialize AWS policy with settings and provider."""
        self.settings = get_settings()
        self._provider = None
        self._instance_type_limits_cache: dict[str, int] = {}

    def _get_provider(self):
        """Lazy-load AWS provider to avoid circular imports."""
        if self._provider is None:
            self._provider = get_provider("aws")
        return self._provider

    def _get_instance_type_limit(self, instance_type: str) -> int:
        """
        Get IPv4 addresses per interface limit for an instance type (cached).

        Args:
            instance_type: AWS instance type (e.g., 't3.medium')

        Returns:
            Maximum IPv4 addresses per ENI for this instance type

        Raises:
            Exception: If instance type not found or API call fails
        """
        if instance_type in self._instance_type_limits_cache:
            return self._instance_type_limits_cache[instance_type]

        provider = self._get_provider()
        instance_types = provider.describe_instance_types([instance_type])

        if not instance_types:
            raise Exception(
                f"Instance type {instance_type} not found in AWS API response"
            )

        limit = instance_types[0]["ipv4_addresses_per_interface"]
        self._instance_type_limits_cache[instance_type] = limit
        logger.debug(f"Cached IPv4 limit for {instance_type}: {limit}")
        return limit

    def _get_current_ip_count(self, eni_id: str, region: str = None) -> int:
        """
        Get current number of private IPs assigned to an ENI.

        Args:
            eni_id: Network interface ID
            region: AWS region (required for multi-region support)

        Returns:
            Number of private IPs currently assigned (primary + secondary)

        Raises:
            Exception: If ENI not found or API call fails
        """
        provider = self._get_provider()
        enis = provider.describe_network_interfaces_by_id([eni_id], region=region)

        if not enis:
            raise Exception(f"ENI {eni_id} not found in AWS (region={region})")

        return len(enis[0]["private_ip_addresses"])

    def _get_state_manager(self):
        """Get state_manager instance (lazy import to avoid circular deps)."""
        from miner_control_plane.services.state_manager import state_manager

        return state_manager

    def shard_hard_capacity(self, *, shard_id: str) -> HardCapacity:
        """
        Calculate current hard capacity for a shard based on ENI IPv4 limits.

        This method:
        1. Gets active and standby nodes for the shard
        2. Queries instance type IPv4 limit from AWS
        3. Queries current IP usage on each node's ENI
        4. Calculates available slots (minimum of active and standby)
        5. Subtracts already-allocated origins

        Args:
            shard_id: Shard identifier to check capacity for

        Returns:
            HardCapacity with:
                - capacity_model: "computed"
                - origin_slots_total: Min available slots across active/standby
                - origin_slots_used: Number of origins already in shard
                - origin_slots_available: Remaining slots
                - limiting_factor: "ENI IPv4 addresses per interface"
                - details: Per-node breakdown for diagnostics

        Raises:
            ValueError: If shard not found or has no nodes
            Exception: If AWS API calls fail

        Note:
            This method must be fast and cacheable. The instance type limit
            is cached in-memory after first query.
        """
        state_manager = self._get_state_manager()

        # Get nodes for this shard
        nodes = state_manager.get_nodes_for_shard(shard_id)
        if not nodes:
            raise ValueError(f"Shard {shard_id} has no nodes")

        # Get region from shard for AWS API calls
        shard = state_manager.get_shard(shard_id)
        region = shard.get("region") if shard else None

        if len(nodes) < 2:
            raise ValueError(
                f"Shard {shard_id} has only {len(nodes)} node(s), "
                f"expected active + standby"
            )

        # Identify active and standby nodes
        active_node = next((n for n in nodes if n.get("role") == "active"), None)
        standby_node = next((n for n in nodes if n.get("role") == "standby"), None)

        if not active_node or not standby_node:
            raise ValueError(
                f"Shard {shard_id} missing active or standby node "
                f"(found roles: {[n.get('role') for n in nodes]})"
            )

        # Get instance type (all scrubbers use same type from settings)
        instance_type = self.settings.scrubber_instance_type

        # Get IPv4 limit per ENI for this instance type
        ipv4_limit = self._get_instance_type_limit(instance_type)

        # Get current IP usage for each node
        active_eni_id = active_node.get("eni_id")
        standby_eni_id = standby_node.get("eni_id")

        if not active_eni_id or not standby_eni_id:
            raise ValueError(
                f"Shard {shard_id} nodes missing ENI IDs: "
                f"active={active_eni_id}, standby={standby_eni_id}"
            )

        active_ip_count = self._get_current_ip_count(active_eni_id, region=region)
        standby_ip_count = self._get_current_ip_count(standby_eni_id, region=region)

        # Calculate available slots per node (current IPs include primary)
        active_available = ipv4_limit - active_ip_count
        standby_available = ipv4_limit - standby_ip_count

        # Static total capacity: IPv4 limit minus 1 for primary IP
        # This is the MAX origins this shard can ever hold
        origin_slots_total = ipv4_limit - 1

        # Get number of origins already using this shard (for reporting)
        origins = state_manager.get_origins_for_shard(shard_id)
        origin_slots_used = len(origins)

        # Available capacity from actual ENI state (minimum of both nodes for HA)
        # This already accounts for current usage via IP counts
        eni_slots_available = min(active_available, standby_available)

        # Query EIP availability for this region
        eip_quota, eip_used, eip_avail = eip_availability.get_eip_usage(region)

        # The actual available capacity is the minimum of ENI slots and EIP availability
        origin_slots_available = min(eni_slots_available, eip_avail)

        # Determine limiting factor
        if eip_avail < eni_slots_available:
            limiting_factor = "EIP quota per region"
        else:
            limiting_factor = "ENI IPv4 addresses per interface"

        return HardCapacity(
            capacity_model="computed",
            origin_slots_total=origin_slots_total,
            origin_slots_used=origin_slots_used,
            origin_slots_available=origin_slots_available,
            limiting_factor=limiting_factor,
            details={
                "shard_id": shard_id,
                "region": region,
                "instance_type": instance_type,
                "ipv4_limit_per_eni": ipv4_limit,
                "eni_slots_available": eni_slots_available,
                "active_node": {
                    "node_id": active_node.get("node_id"),
                    "eni_id": active_eni_id,
                    "current_ips": active_ip_count,
                    "available_ips": active_available,
                },
                "standby_node": {
                    "node_id": standby_node.get("node_id"),
                    "eni_id": standby_eni_id,
                    "current_ips": standby_ip_count,
                    "available_ips": standby_available,
                },
                "origins_in_shard": origin_slots_used,
            },
            eip_quota=eip_quota,
            eip_used=eip_used,
            eip_available=eip_avail,
        )

    def ensure_origin_attachment(
        self, *, shard_id: str, origin_id: str, context: dict[str, Any]
    ) -> AllocationResult:
        """
        Allocate and configure dataplane resources for an origin.

        This method:
        1. Gets active and standby nodes for the shard
        2. Allocates secondary private IPv4 on each node's ENI (AWS auto-assigns)
        3. Configures OS interfaces via SSH (ip addr add)
        4. Returns allocation details for database persistence

        Args:
            shard_id: Shard to attach origin to
            origin_id: Origin identifier being attached
            context: Provider-specific context (unused for AWS, but kept for Protocol)

        Returns:
            AllocationResult with:
                - attachment_type: "aws_secondary_private_ipv4"
                - active: {"private_ip": str, "eni_id": str, "node_id": str}
                - standby: {"private_ip": str, "eni_id": str, "node_id": str}

        Raises:
            ValueError: If shard not found, missing nodes, or insufficient capacity
            Exception: If AWS API calls or SSH commands fail

        Note:
            This method is idempotent at the AWS level (assigning same IP twice
            is safe), but NOT at the OS level (ip addr add will fail if IP exists).
            Rollback is caller's responsibility.
        """
        state_manager = self._get_state_manager()
        provider = self._get_provider()

        # Get nodes for this shard
        nodes = state_manager.get_nodes_for_shard(shard_id)
        if not nodes or len(nodes) < 2:
            raise ValueError(
                f"Shard {shard_id} does not have active + standby nodes"
            )

        # Get region from shard for AWS API calls
        shard = state_manager.get_shard(shard_id)
        region = shard.get("region") if shard else None

        # Identify active and standby nodes
        active_node = next((n for n in nodes if n.get("role") == "active"), None)
        standby_node = next((n for n in nodes if n.get("role") == "standby"), None)

        if not active_node or not standby_node:
            raise ValueError(
                f"Shard {shard_id} missing active or standby node"
            )

        # Check capacity before allocating
        capacity = self.shard_hard_capacity(shard_id=shard_id)
        if capacity.origin_slots_available is not None and capacity.origin_slots_available < 1:
            raise ValueError(
                f"Shard {shard_id} has no available capacity "
                f"({capacity.origin_slots_used}/{capacity.origin_slots_total} used)"
            )

        logger.info(
            f"Allocating IPs for origin {origin_id} on shard {shard_id} "
            f"(active: {active_node['node_id']}, standby: {standby_node['node_id']})"
        )

        # Allocate secondary IP on active node ENI
        active_eni_id = active_node["eni_id"]
        active_ips = provider.assign_secondary_private_ipv4(active_eni_id, count=1, region=region)
        if not active_ips:
            raise Exception(
                f"Failed to allocate secondary IP on active ENI {active_eni_id}"
            )
        active_ip = active_ips[0]
        logger.info(f"  Active node IP allocated: {active_ip}")

        # Allocate secondary IP on standby node ENI
        standby_eni_id = standby_node["eni_id"]
        standby_ips = provider.assign_secondary_private_ipv4(standby_eni_id, count=1, region=region)
        if not standby_ips:
            # Rollback: release active IP
            try:
                provider.unassign_private_ip_addresses(active_eni_id, [active_ip], region=region)
            except Exception as rollback_err:
                logger.error(
                    f"Failed to rollback active IP {active_ip}: {rollback_err}"
                )
            raise Exception(
                f"Failed to allocate secondary IP on standby ENI {standby_eni_id}"
            )
        standby_ip = standby_ips[0]
        logger.info(f"  Standby node IP allocated: {standby_ip}")

        # Configure OS interfaces via SSH
        # AWS scrubbers use ens5 as primary interface
        interface = "ens5"
        subnet_mask = "24"  # AWS VPC subnets are typically /24

        # Configure active node
        active_host = active_node["public_ip"]
        active_cmd = f"sudo ip addr add {active_ip}/{subnet_mask} dev {interface}"
        logger.info(f"  Configuring active node: {active_cmd}")
        rc, stdout, stderr = ssh_exec(
            active_host,
            active_cmd,
            self.settings.ssh_key_path,
            nodes_db=state_manager.nodes_db,
        )
        if rc != 0:
            # Rollback: release both IPs
            try:
                provider.unassign_private_ip_addresses(active_eni_id, [active_ip], region=region)
                provider.unassign_private_ip_addresses(standby_eni_id, [standby_ip], region=region)
            except Exception as rollback_err:
                logger.error(f"Failed to rollback IPs: {rollback_err}")
            raise Exception(
                f"Failed to configure active node {active_host}: {stderr}"
            )
        logger.info("  Active node configured")

        # Configure standby node
        standby_host = standby_node["public_ip"]
        standby_cmd = f"sudo ip addr add {standby_ip}/{subnet_mask} dev {interface}"
        logger.info(f"  Configuring standby node: {standby_cmd}")
        rc, stdout, stderr = ssh_exec(
            standby_host,
            standby_cmd,
            self.settings.ssh_key_path,
            nodes_db=state_manager.nodes_db,
        )
        if rc != 0:
            # Rollback: remove active IP from OS, release both IPs from ENIs
            try:
                ssh_exec(
                    active_host,
                    f"sudo ip addr del {active_ip}/{subnet_mask} dev {interface}",
                    self.settings.ssh_key_path,
                    nodes_db=state_manager.nodes_db,
                )
                provider.unassign_private_ip_addresses(active_eni_id, [active_ip], region=region)
                provider.unassign_private_ip_addresses(standby_eni_id, [standby_ip], region=region)
            except Exception as rollback_err:
                logger.error(f"Failed to rollback after standby config failure: {rollback_err}")
            raise Exception(
                f"Failed to configure standby node {standby_host}: {stderr}"
            )
        logger.info("  Standby node configured")

        logger.info(
            f"Origin {origin_id} attached to shard {shard_id}: "
            f"active={active_ip}, standby={standby_ip}"
        )

        return AllocationResult(
            attachment_type="aws_secondary_private_ipv4",
            active={
                "private_ip": active_ip,
                "eni_id": active_eni_id,
                "node_id": active_node["node_id"],
            },
            standby={
                "private_ip": standby_ip,
                "eni_id": standby_eni_id,
                "node_id": standby_node["node_id"],
            },
        )

    def release_origin_attachment(
        self, *, shard_id: str, origin_id: str, allocation: AllocationResult
    ) -> None:
        """
        Release dataplane resources for an origin.

        This method:
        1. Removes secondary IPs from OS interfaces via SSH
        2. Releases secondary IPs from ENIs via AWS API

        Args:
            shard_id: Shard the origin was attached to
            origin_id: Origin identifier being released
            allocation: The AllocationResult returned from ensure_origin_attachment

        Note:
            This method is idempotent and logs errors but does not raise exceptions.
            Best-effort cleanup - if AWS API fails, the IPs remain allocated but
            unused, which is acceptable for cleanup operations.
        """
        state_manager = self._get_state_manager()
        provider = self._get_provider()

        # Get region from shard for AWS API calls
        shard = state_manager.get_shard(shard_id)
        region = shard.get("region") if shard else None

        logger.info(f"Releasing IPs for origin {origin_id} on shard {shard_id}")

        # Extract allocation details
        active_ip = allocation.active.get("private_ip")
        active_eni_id = allocation.active.get("eni_id")
        active_node_id = allocation.active.get("node_id")

        standby_ip = allocation.standby.get("private_ip")
        standby_eni_id = allocation.standby.get("eni_id")
        standby_node_id = allocation.standby.get("node_id")

        if not all([active_ip, active_eni_id, standby_ip, standby_eni_id]):
            logger.error(
                f"Incomplete allocation data for origin {origin_id}: "
                f"active_ip={active_ip}, active_eni_id={active_eni_id}, "
                f"standby_ip={standby_ip}, standby_eni_id={standby_eni_id}"
            )
            return

        interface = "ens5"
        subnet_mask = "24"

        # Remove IP from active node OS
        active_node = state_manager.nodes_db.get(active_node_id)
        if active_node:
            active_host = active_node.get("public_ip")
            if active_host:
                cmd = f"sudo ip addr del {active_ip}/{subnet_mask} dev {interface}"
                logger.info(f"  Removing IP from active node: {cmd}")
                try:
                    rc, stdout, stderr = ssh_exec(
                        active_host,
                        cmd,
                        self.settings.ssh_key_path,
                        nodes_db=state_manager.nodes_db,
                    )
                    if rc != 0:
                        logger.warning(
                            f"Failed to remove IP from active node OS: {stderr} "
                            f"(continuing cleanup)"
                        )
                except Exception as e:
                    logger.warning(
                        f"Exception removing IP from active node OS: {e} "
                        f"(continuing cleanup)"
                    )
            else:
                logger.warning(
                    f"Active node {active_node_id} has no public IP (continuing cleanup)"
                )
        else:
            logger.warning(
                f"Active node {active_node_id} not found in state manager "
                f"(continuing cleanup)"
            )

        # Remove IP from standby node OS
        standby_node = state_manager.nodes_db.get(standby_node_id)
        if standby_node:
            standby_host = standby_node.get("public_ip")
            if standby_host:
                cmd = f"sudo ip addr del {standby_ip}/{subnet_mask} dev {interface}"
                logger.info(f"  Removing IP from standby node: {cmd}")
                try:
                    rc, stdout, stderr = ssh_exec(
                        standby_host,
                        cmd,
                        self.settings.ssh_key_path,
                        nodes_db=state_manager.nodes_db,
                    )
                    if rc != 0:
                        logger.warning(
                            f"Failed to remove IP from standby node OS: {stderr} "
                            f"(continuing cleanup)"
                        )
                except Exception as e:
                    logger.warning(
                        f"Exception removing IP from standby node OS: {e} "
                        f"(continuing cleanup)"
                    )
            else:
                logger.warning(
                    f"Standby node {standby_node_id} has no public IP (continuing cleanup)"
                )
        else:
            logger.warning(
                f"Standby node {standby_node_id} not found in state manager "
                f"(continuing cleanup)"
            )

        # Release IPs from ENIs via AWS API
        logger.info("  Releasing IPs from ENIs")
        try:
            provider.unassign_private_ip_addresses(active_eni_id, [active_ip], region=region)
            logger.info(f"  Released {active_ip} from ENI {active_eni_id}")
        except Exception as e:
            logger.warning(
                f"Failed to release {active_ip} from ENI {active_eni_id}: {e} "
                f"(continuing cleanup)"
            )

        try:
            provider.unassign_private_ip_addresses(standby_eni_id, [standby_ip], region=region)
            logger.info(f"  Released {standby_ip} from ENI {standby_eni_id}")
        except Exception as e:
            logger.warning(
                f"Failed to release {standby_ip} from ENI {standby_eni_id}: {e} "
                f"(continuing cleanup)"
            )

        logger.info(f"Origin {origin_id} detached from shard {shard_id}")
