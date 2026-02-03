"""Secondary private IP capability interface.

Primarily AWS capability for ENI management.

IMPORTANT: All methods return Dict/List[Dict] for backward compatibility.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class SecondaryIPCapability(ABC):
    """Interface for managing secondary private IPs on network interfaces."""

    capability_name = "secondary_ip"

    @abstractmethod
    def describe_network_interfaces(
        self,
        instance_id: Optional[str] = None,
        network_interface_ids: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Get network interface details.

        Returns:
            List[Dict] with keys:
            - 'network_interface_id': str
            - 'instance_id': str (empty if not attached)
            - 'private_ip_address': str (primary)
            - 'private_ip_addresses': List[Dict] with keys:
                - 'private_ip_address': str  # NOTE: field name for backward compat
                - 'primary': bool
        """
        pass

    @abstractmethod
    def assign_private_ip_addresses(
        self,
        network_interface_id: str,
        private_ip_addresses: Optional[List[str]] = None,
        secondary_private_ip_address_count: Optional[int] = None,
    ) -> List[str]:
        """Assign private IPs to ENI.

        Returns:
            List of assigned private IP addresses
        """
        pass

    @abstractmethod
    def unassign_private_ip_addresses(
        self,
        network_interface_id: str,
        private_ip_addresses: List[str],
    ) -> bool:
        """Remove private IPs from ENI."""
        pass
