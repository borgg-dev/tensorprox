"""Linode provider using pure REST API"""
import base64
import re
import secrets
import string
from typing import Dict, List, Optional

import requests

from .base import BaseProvider
from shared.config import get_settings
from shared.utils.ssh import PROVIDER_SSH_USERS


class LinodeProvider(BaseProvider):
    """
    Linode provider using pure REST API calls.
    Docs: https://www.linode.com/docs/api/

    Uses Pydantic Settings for configuration (PROPER integration).
    """

    # Linode-specific defaults (imported from single source of truth)
    default_ssh_user = PROVIDER_SSH_USERS['linode']
    default_home_dir = '/root'

    def __init__(self, token: Optional[str] = None):
        super().__init__()
        self.settings = get_settings()
        self.token = token or self.settings.linode_token

        if not self.token:
            raise ValueError("LINODE_TOKEN required in tp.env")

        self.api_base = "https://api.linode.com/v4"
        self.session = requests.Session()  # Initialize HTTP session
        self.session.headers.update({
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        })

    def create_instance(
        self,
        region: str,
        instance_type: str,
        user_data: str,
        tags: Dict[str, str]
    ) -> Dict:
        """
        Create Linode instance via POST /linode/instances.
        https://www.linode.com/docs/api/linode-instances/#linode-create
        """
        payload = {
            'type': instance_type,
            'region': region,
            'image': 'linode/ubuntu22.04',
            'label': tags.get('Name', f'tensorprox-{tags.get("node_type", "node")}'),
            'root_pass': self._generate_root_password(),
            'authorized_keys': [self._get_ssh_public_key()],
            'metadata': {
                'user_data': base64.b64encode(user_data.encode()).decode()
            },
            'tags': self._format_tags(tags),
            'booted': True
        }

        response = self.session.post(
            f"{self.api_base}/linode/instances",
            json=payload
        )
        response.raise_for_status()

        data = response.json()

        return {
            'instance_id': str(data['id']),
            'public_ip': data['ipv4'][0] if data['ipv4'] else '',
            'private_ip': None,
            'status': data['status']
        }

    def delete_instance(self, instance_id: str, region: Optional[str] = None) -> bool:
        """
        Delete Linode via DELETE /linode/instances/{id}.
        https://www.linode.com/docs/api/linode-instances/#linode-delete

        Note: region is ignored for Linode (global API) but accepted for interface compatibility.
        """
        response = self.session.delete(
            f"{self.api_base}/linode/instances/{instance_id}"
        )
        return response.status_code in [200, 204]

    def get_instance_status(self, instance_id: str) -> str:
        """
        Get Linode status via GET /linode/instances/{id}.
        https://www.linode.com/docs/api/linode-instances/#linode-view
        """
        response = self.session.get(
            f"{self.api_base}/linode/instances/{instance_id}"
        )
        response.raise_for_status()

        data = response.json()
        return data['status']

    def describe_instances(self, instance_ids: List[str]) -> List[Dict]:
        """
        Get details for one or more Linode instances.
        https://www.linode.com/docs/api/linode-instances/#linode-view

        Returns:
            List of Dict with keys: instance_id, public_ip, private_ip, status,
            vpc_id (empty string), security_groups (empty list)
        """
        results = []
        for instance_id in instance_ids:
            try:
                response = self.session.get(
                    f"{self.api_base}/linode/instances/{instance_id}"
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        'instance_id': str(data['id']),
                        'public_ip': (data.get('ipv4') or [''])[0],
                        'private_ip': '',
                        'status': data.get('status', 'unknown'),
                        'vpc_id': '',
                        'security_groups': []
                    })
            except Exception:
                # Skip instances that can't be described
                pass
        return results

    def wait_for_instance_running(
        self,
        instance_id: str,
        max_attempts: int = 60,
        interval: int = 5,
        region: str = None,  # Ignored for Linode (instances are global)
    ) -> Dict:
        """
        Wait for Linode instance to reach running state with public IP.

        Args:
            instance_id: Linode instance ID
            max_attempts: Maximum polling attempts (default: 60)
            interval: Seconds between attempts (default: 5)

        Returns:
            Dict with instance details (same structure as describe_instances)

        Raises:
            TimeoutError: If instance doesn't become running within max_attempts
        """
        import time

        for attempt in range(max_attempts):
            instances = self.describe_instances([instance_id])
            if instances and instances[0].get('status') == 'running':
                return instances[0]
            time.sleep(interval)

        raise TimeoutError(
            f"Instance {instance_id} did not become running "
            f"after {max_attempts * interval} seconds"
        )

    def _get_ssh_public_key(self) -> str:
        """Read SSH public key from tp.env SSH_KEY_PATH (via Pydantic Settings)"""
        import os
        ssh_key_path = self.settings.ssh_key_path
        if not ssh_key_path:
            raise ValueError("SSH_KEY_PATH required in tp.env")

        # Expand ~ to home directory
        ssh_key_path = os.path.expanduser(ssh_key_path)
        public_key_path = f"{ssh_key_path}.pub"
        with open(public_key_path, 'r') as f:
            return f.read().strip()

    def _generate_root_password(self) -> str:
        """Generate secure random password for root"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(32))

    def _format_tags(self, tags: Dict[str, str]) -> List[str]:
        """Return Linode-friendly tags (alnum, '-', '_', max 50 chars)."""
        formatted = []
        for key, value in tags.items():
            raw = f"{key}-{value}" if value else key
            clean = re.sub(r'[^A-Za-z0-9_\-]', '-', raw)
            formatted.append(clean[:50])
        return formatted

    def list_regions(self) -> List[str]:
        """List available Linode regions."""
        response = self.session.get(f"{self.api_base}/regions")
        response.raise_for_status()
        data = response.json()
        return [region["id"] for region in data.get("data", []) if region.get("id")]
