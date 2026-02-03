"""Base provider interface for all cloud providers.

Design Principles:
- Stateless: Region passed per-call, not stored
- Thread-safe: No mutable instance state
- Dict returns: All methods return Dict/List[Dict] for backward compatibility
- Minimal: Only methods ALL providers must implement

IMPORTANT: All methods return Dict or List[Dict], NOT dataclasses.
This preserves backward compatibility with existing callers.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class BaseProvider(ABC):
    """Abstract base class for cloud providers.

    All methods that operate on resources take `region` as an explicit
    parameter. This ensures thread-safety and clarity - no hidden state.

    RETURN TYPE CONTRACT:
    - create_instance() -> Dict with keys: instance_id, public_ip, private_ip, status
    - describe_instances() -> List[Dict] with same keys
    - wait_for_instance_running() -> Dict with same keys
    - All string values use empty string '' for missing, never None
    """

    # Required class attributes - override in subclass
    default_ssh_user: str = "ubuntu"
    default_home_dir: str = "/home/ubuntu"

    @property
    def capabilities(self) -> set[str]:
        """Declare which optional capabilities this provider supports.

        Known capabilities:
        - "public_ip": Elastic/Floating/Reserved IP management
        - "secondary_ip": Secondary private IPs on network interfaces
        - "firewall": Security group / firewall rule management
        - "metadata": Instance type details (vCPUs, memory, limits)

        Returns:
            Set of capability names this provider supports
        """
        return set()

    # =========================================================================
    # REQUIRED METHODS - Every provider must implement these
    # =========================================================================

    @abstractmethod
    def create_instance(
        self,
        region: str,
        instance_type: str,
        user_data: str,
        tags: Dict[str, str],
    ) -> Dict:
        """Create a new compute instance and wait until ready.

        This method blocks until the instance is running and has a public IP.

        Args:
            region: Cloud region (e.g., "eu-central-1", "us-east")
            instance_type: Instance size (e.g., "t3.medium", "g6-standard-1")
            user_data: Cloud-init script content
            tags: Key-value tags for the instance

        Returns:
            Dict with keys:
            - 'instance_id': str
            - 'public_ip': str (empty string if not assigned)
            - 'private_ip': str (empty string if not applicable)
            - 'status': str ('running', 'pending', etc.)

        Raises:
            Exception: If instance creation fails
        """
        pass

    @abstractmethod
    def delete_instance(self, instance_id: str, region: Optional[str] = None) -> bool:
        """Terminate/delete an instance.

        Args:
            instance_id: Provider-specific instance ID
            region: Cloud region (required for AWS, ignored for global APIs)

        Returns:
            True if instance was terminated (or already gone)

        Raises:
            ProviderError: If deletion fails
        """
        pass

    @abstractmethod
    def get_instance_status(self, instance_id: str) -> str:
        """Get current status of an instance.

        Args:
            instance_id: Provider-specific instance ID

        Returns:
            Status string: 'running', 'pending', 'stopped', 'terminated', 'not-found'
        """
        pass

    @abstractmethod
    def describe_instances(self, instance_ids: List[str]) -> List[Dict]:
        """Get details for one or more instances.

        Args:
            instance_ids: List of instance IDs to describe

        Returns:
            List of Dict, each with keys:
            - 'instance_id': str
            - 'public_ip': str (empty string if not assigned)
            - 'private_ip': str
            - 'status': str
            - 'vpc_id': str (empty string if not applicable, AWS-specific)
            - 'security_groups': List[Dict] (empty list if not applicable, AWS-specific)
        """
        pass

    @abstractmethod
    def wait_for_instance_running(
        self,
        instance_id: str,
        max_attempts: int = 60,
        interval: int = 5,
    ) -> Dict:
        """Wait for instance to reach running state with public IP.

        Args:
            instance_id: Provider-specific instance ID
            max_attempts: Maximum polling attempts
            interval: Seconds between attempts

        Returns:
            Dict with instance details (same structure as describe_instances)

        Raises:
            TimeoutError: If instance doesn't become ready
            Exception: If instance enters terminal state
        """
        pass

    @abstractmethod
    def list_regions(self) -> List[str]:
        """Get list of available regions for this provider.

        Returns:
            List of region identifiers (e.g., ["us-east-1", "eu-west-1"])
        """
        pass


class ProviderError(Exception):
    """Base exception for provider operations."""

    def __init__(self, message: str, provider: str = "unknown", region: Optional[str] = None):
        self.provider = provider
        self.region = region
        super().__init__(f"[{provider}:{region or 'global'}] {message}")
