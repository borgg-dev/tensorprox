"""Public IP capability interface.

Maps to: AWS EIP, Linode Reserved IP, DO Floating IP

IMPORTANT: All methods return Dict/List[Dict] to preserve backward
compatibility with existing callers.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class PublicIPCapability(ABC):
    """Interface for managing public/elastic/floating IPs."""

    capability_name = "public_ip"

    @abstractmethod
    def allocate_address(self, domain: str = "vpc") -> Dict:
        """Allocate a new public IP.

        Returns:
            Dict with keys:
            - 'allocation_id': str (eipalloc-xxx)
            - 'public_ip': str
        """
        pass

    @abstractmethod
    def release_address(self, allocation_id: str) -> bool:
        """Release/delete a public IP."""
        pass

    @abstractmethod
    def associate_address(
        self,
        allocation_id: str,
        instance_id: Optional[str] = None,
        network_interface_id: Optional[str] = None,
        private_ip_address: Optional[str] = None,
    ) -> Dict:
        """Associate public IP with instance or ENI.

        Returns:
            Dict with key 'association_id': str
        """
        pass

    @abstractmethod
    def disassociate_address(self, association_id: str) -> bool:
        """Disassociate public IP."""
        pass

    @abstractmethod
    def describe_addresses(
        self,
        allocation_ids: Optional[List[str]] = None,
        public_ips: Optional[List[str]] = None,
    ) -> List[Dict]:
        """List public IPs.

        Returns:
            List[Dict] with keys:
            - 'allocation_id': str
            - 'public_ip': str
            - 'instance_id': str (empty if not attached)
            - 'association_id': str (empty if not attached)
            - 'network_interface_id': str (empty if not attached)
            - 'private_ip_address': str (empty if not attached)
        """
        pass
