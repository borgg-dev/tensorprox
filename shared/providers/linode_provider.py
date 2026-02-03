"""
Linode cloud provider implementation.

Uses Linode REST API for instance management.
"""

import time
from typing import Dict, List, Any, Optional

import requests
from loguru import logger

from shared.providers.base import BaseProvider
from shared.config import get_shared_settings


class LinodeProvider(BaseProvider):
    """
    Linode provider using REST API.
    """

    API_BASE = "https://api.linode.com/v4"

    def __init__(self):
        """Initialize Linode provider.

        Raises:
            ValueError: If Linode token is not configured.
        """
        self.settings = get_shared_settings()
        self.token = self.settings.linode_token
        self.default_region = self.settings.linode_region

        # Validate token at initialization to fail fast
        if not self.token:
            raise ValueError(
                "Linode token not configured. Set LINODE_TOKEN environment variable."
            )

    @property
    def name(self) -> str:
        return "linode"

    @property
    def default_ssh_user(self) -> str:
        return "root"

    @property
    def default_home_dir(self) -> str:
        return "/root"

    def _headers(self) -> Dict[str, str]:
        """Get API headers."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def create_instance(
        self,
        region: str,
        instance_type: str,
        user_data: str,
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Create a Linode instance.

        Args:
            region: Linode region.
            instance_type: Linode type (e.g., g6-nanode-1).
            user_data: Cloud-init user data.
            tags: Tags to apply.

        Returns:
            Instance details dictionary.
        """
        import base64

        # Encode user data as base64 for cloud-init
        user_data_b64 = base64.b64encode(user_data.encode()).decode()

        # Build create request
        label = tags.get("Name", f"tensorprox-{int(time.time())}")
        label = label[:32]  # Linode label limit

        payload = {
            "image": "linode/ubuntu22.04",
            "region": region,
            "type": instance_type,
            "label": label,
            "root_pass": self._generate_root_password(),
            "authorized_keys": self._get_ssh_keys(),
            "metadata": {
                "user_data": user_data_b64,
            },
        }

        # Add tags if provided (use key:value format for discovery)
        if tags:
            formatted_tags = [f"{k}:{v}" for k, v in tags.items()][:5]
            payload["tags"] = formatted_tags

        response = requests.post(
            f"{self.API_BASE}/linode/instances",
            json=payload,
            headers=self._headers()
        )
        response.raise_for_status()

        data = response.json()
        instance_id = str(data["id"])

        logger.info(f"Created Linode instance: {instance_id}")

        # Get public IP (may need to wait)
        public_ip = None
        if data.get("ipv4"):
            public_ip = data["ipv4"][0]

        return {
            "instance_id": instance_id,
            "public_ip": public_ip,
            "private_ip": None,  # Linode private IPs are optional
            "status": data.get("status", "provisioning"),
            "region": region,
            "instance_type": instance_type,
            "provider": "linode",
        }

    def delete_instance(
        self,
        instance_id: str,
        region: Optional[str] = None
    ) -> bool:
        """Delete a Linode instance."""
        try:
            response = requests.delete(
                f"{self.API_BASE}/linode/instances/{instance_id}",
                headers=self._headers()
            )
            response.raise_for_status()
            logger.info(f"Deleted Linode instance: {instance_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete Linode instance: {e}")
            return False

    def get_instance_status(
        self,
        instance_id: str,
        region: Optional[str] = None
    ) -> str:
        """Get Linode instance status."""
        try:
            response = requests.get(
                f"{self.API_BASE}/linode/instances/{instance_id}",
                headers=self._headers()
            )
            response.raise_for_status()
            data = response.json()
            return data.get("status", "unknown")
        except Exception as e:
            logger.error(f"Failed to get Linode status: {e}")
            return "unknown"

    def wait_for_instance(
        self,
        instance_id: str,
        target_status: str = "running",
        timeout: int = 300,
        poll_interval: int = 5,
        region: Optional[str] = None
    ) -> bool:
        """Wait for instance to reach target status."""
        start_time = time.time()

        while time.time() - start_time < timeout:
            status = self.get_instance_status(instance_id)
            if status == target_status:
                return True
            if status in ("deleting", "deleted"):
                return False
            time.sleep(poll_interval)

        return False

    def get_public_ip(
        self,
        instance_id: str,
        region: Optional[str] = None
    ) -> Optional[str]:
        """Get public IP of a Linode instance."""
        try:
            response = requests.get(
                f"{self.API_BASE}/linode/instances/{instance_id}",
                headers=self._headers()
            )
            response.raise_for_status()
            data = response.json()
            if data.get("ipv4"):
                return data["ipv4"][0]
            return None
        except Exception:
            return None

    def describe_instances(
        self,
        instance_ids: Optional[List[str]] = None,
        region: Optional[str] = None,
        filters: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Describe Linode instances with optional filtering.

        Args:
            instance_ids: List of specific instance IDs to describe.
            region: Filter by region.
            filters: Tag filters. For Linode, we check if tag values are in
                     the instance's tags list or match the label.

        Returns:
            List of instance details.
        """
        try:
            response = requests.get(
                f"{self.API_BASE}/linode/instances",
                headers=self._headers()
            )
            response.raise_for_status()
            data = response.json()

            instances = []
            for instance in data.get("data", []):
                # Filter by instance_ids
                if instance_ids and str(instance["id"]) not in instance_ids:
                    continue

                # Filter by region
                if region and instance.get("region") != region:
                    continue

                # Filter by status (only running)
                if instance.get("status") != "running":
                    continue

                # Filter by tags
                # Linode tags are a list of strings, we check if filter values are in tags
                if filters:
                    instance_tags = instance.get("tags", [])
                    instance_label = instance.get("label", "")

                    match = True
                    for key, value in filters.items():
                        # Check if value is in tags list or matches label
                        if value not in instance_tags and value != instance_label:
                            # Also check for key:value format in tags
                            kv_tag = f"{key}:{value}"
                            if kv_tag not in instance_tags:
                                match = False
                                break
                    if not match:
                        continue

                # Build tags dict from label and tags list
                tags = {"Name": instance.get("label", "")}
                for tag in instance.get("tags", []):
                    if ":" in tag:
                        k, v = tag.split(":", 1)
                        tags[k] = v
                    else:
                        tags[tag] = tag

                instances.append({
                    "instance_id": str(instance["id"]),
                    "public_ip": instance["ipv4"][0] if instance.get("ipv4") else None,
                    "private_ip": None,
                    "status": instance.get("status"),
                    "region": instance.get("region"),
                    "instance_type": instance.get("type"),
                    "provider": "linode",
                    "tags": tags,
                })

            if not instances:
                logger.debug(
                    f"No running Linode instances found "
                    f"(instance_ids={instance_ids}, region={region}, filters={filters})"
                )
            return instances
        except requests.exceptions.HTTPError as e:
            logger.error(
                f"Linode API error in describe_instances: {e} "
                f"(instance_ids={instance_ids}, region={region}, filters={filters})"
            )
            return []
        except Exception as e:
            logger.error(
                f"Failed to describe Linode instances: {e} "
                f"(instance_ids={instance_ids}, region={region}, filters={filters})"
            )
            return []

    def _generate_root_password(self) -> str:
        """Generate a random root password."""
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
        return "".join(secrets.choice(alphabet) for _ in range(32))

    def _get_ssh_keys(self) -> List[str]:
        """Get SSH public keys for authorized_keys."""
        import os

        ssh_key_path = os.path.expanduser(self.settings.ssh_key_path)
        pub_key_path = f"{ssh_key_path}.pub"

        if os.path.exists(pub_key_path):
            with open(pub_key_path, "r") as f:
                return [f.read().strip()]

        return []
