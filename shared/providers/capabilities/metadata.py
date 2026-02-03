"""Instance metadata capability interface."""

from abc import ABC, abstractmethod
from typing import Dict, List


class InstanceMetadataCapability(ABC):
    """Interface for querying instance type metadata."""

    capability_name = "metadata"

    @abstractmethod
    def describe_instance_types(
        self,
        instance_types: List[str],
    ) -> List[Dict]:
        """Get metadata for instance types.

        Returns:
            List[Dict] with keys:
            - 'instance_type': str
            - 'vcpu_info': Dict with 'default_vcpus'
            - 'memory_info': Dict with 'size_in_mib'
            - 'network_info': Dict with 'maximum_network_interfaces', 'ipv4_addresses_per_interface'
        """
        pass
