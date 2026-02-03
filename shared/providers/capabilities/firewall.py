"""Firewall/Security Group capability interface.

Maps to: AWS SG, Linode Firewall, DO Firewall

IMPORTANT: All methods return Dict/List[Dict] for backward compatibility.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class FirewallCapability(ABC):
    """Interface for managing firewall/security group rules."""

    capability_name = "firewall"

    @abstractmethod
    def describe_security_groups(
        self,
        group_ids: Optional[List[str]] = None,
        filters: Optional[Dict] = None,
    ) -> List[Dict]:
        """Get security group details.

        Returns:
            List[Dict] with keys:
            - 'group_id': str
            - 'group_name': str
            - 'vpc_id': str
            - 'ip_permissions': List[Dict] (ingress rules)
        """
        pass

    @abstractmethod
    def authorize_security_group_ingress(
        self,
        group_id: str,
        ip_permissions: List[Dict],
    ) -> bool:
        """Add inbound rules."""
        pass

    @abstractmethod
    def revoke_security_group_ingress(
        self,
        group_id: str,
        ip_permissions: List[Dict],
    ) -> bool:
        """Remove inbound rules."""
        pass
