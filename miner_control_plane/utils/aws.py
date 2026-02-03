"""AWS operations for Miner

Security groups, EIP allocation, ENI operations, instance queries.
Uses REST API via AWSProvider instead of boto3 for cloud-agnostic operations.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from shared.providers.aws_provider import AWSProvider

logger = logging.getLogger(__name__)


class AWSMinerOperations:
    """
    AWS operations specific to Miner scrubber management.

    Uses REST API via AWSProvider for cloud-agnostic resource management.
    """

    def __init__(self, region: str = 'eu-central-1'):
        """Initialize AWS operations using REST API provider"""
        self.region = region
        self._provider = None

    @property
    def provider(self):
        """Lazy-load AWS provider (for test mocking)"""
        if self._provider is None:
            self._provider = AWSProvider()
        return self._provider

    def fetch_public_ip_from_aws(
        self,
        instance_id: str,
        region: Optional[str] = None
    ) -> Optional[str]:
        """
        Fetch current public IP from AWS EC2 API.

        Uses REST API via AWSProvider for cloud-agnostic resource management.
        """
        try:
            instances = self.provider.describe_instances([instance_id], region=region)

            if not instances:
                logger.error(f"Instance {instance_id} not found in AWS")
                return None

            public_ip = instances[0].get('public_ip')
            logger.debug(f"Fetched IP for {instance_id}: {public_ip}")
            return public_ip

        except Exception as e:
            logger.error(f"Failed to fetch IP for {instance_id}: {e}")
            return None

    def refresh_public_ip_if_stale(
        self,
        node_id: str,
        instance_name: str,
        current_ip: str,
        updated_at,
        db_connection,
        region: Optional[str] = None
    ) -> str:
        """
        Return cached IP or refresh from AWS if stale (>5 min).

        Logic preserved - adapted to take db_connection parameter.
        """
        STALE_THRESHOLD = timedelta(minutes=5)

        # Use cached if fresh
        if current_ip and updated_at and (datetime.now() - updated_at) < STALE_THRESHOLD:
            return current_ip

        # Fetch from AWS
        logger.info(f"{instance_name}: Refreshing IP from AWS")
        fresh_ip = self.fetch_public_ip_from_aws(node_id, region=region)

        if not fresh_ip:
            return current_ip  # Fallback to stale

        # Update database
        try:
            conn = db_connection.conn if hasattr(db_connection, 'conn') else db_connection
            cur = conn.cursor()
            cur.execute("""
                UPDATE nodes SET current_public_ip=%s, current_public_ip_updated_at=NOW()
                WHERE node_id=%s
            """, (fresh_ip, node_id))
            conn.commit()
            cur.close()

            if fresh_ip != current_ip:
                logger.info(f"{instance_name}: IP updated {current_ip} -> {fresh_ip}")

        except Exception as e:
            logger.error(f"{instance_name}: DB update failed: {e}")

        return fresh_ip

    def get_scrubber_security_group_id(self, region: Optional[str] = None) -> str:
        """
        Get Security Group ID for Scrubbers.

        Queries AWS for tensorprox-scrubbers security group by group_name.
        """
        # Query by group_name (the actual SG name, not tag)
        sgs = self.provider.describe_security_groups(
            filters={'group-name': 'tensorprox-scrubbers'},
            region=region
        )
        if sgs:
            sg_id = sgs[0]['group_id']
            logger.info(f"Found security group by name: {sg_id}")
            return sg_id

        # Fallback: query by tag:Name
        sgs = self.provider.describe_security_groups(
            filters={'tag:Name': 'tensorprox-sg'},
            region=region
        )
        if sgs:
            sg_id = sgs[0]['group_id']
            logger.info(f"Found security group by tag: {sg_id}")
            return sg_id

        raise Exception("No tensorprox security group found (tried group-name and tag:Name)")

    def add_ports_to_security_group(self, ports: List[int], region: Optional[str] = None) -> None:
        """
        Add TCP/UDP ports to Scrubber Security Group.

        Uses REST API via AWSProvider for cloud-agnostic resource management.
        """
        try:
            sg_id = self.get_scrubber_security_group_id(region=region)

            # Build IP permissions list
            ip_permissions = []

            for port in ports:
                for protocol in ('tcp', 'udp'):
                    ip_permissions.append({
                        'protocol': protocol,
                        'from_port': port,
                        'to_port': port,
                        'cidr': '0.0.0.0/0'
                    })

            if ip_permissions:
                try:
                    self.provider.authorize_security_group_ingress(
                        sg_id, ip_permissions, region=region
                    )
                    logger.info(f"Added {len(ports)} ports (TCP+UDP) to Security Group {sg_id}")
                except Exception as e:
                    if 'already exists' in str(e).lower() or 'duplicate' in str(e).lower():
                        logger.info(f"Ports already exist in Security Group {sg_id}")
                    else:
                        raise

        except Exception as e:
            logger.error(f"Failed to add ports to Security Group: {e}")
            raise

    def remove_unused_ports_from_security_group(
        self,
        origin_id: str,
        ports: List[int],
        origins_db: Dict,
        region: Optional[str] = None
    ) -> None:
        """
        Remove ports from Security Group if no other Origin uses them (reference counting).

        Uses SSH-based approach; consider migrating to REST API RevokeSecurityGroupIngress.
        """
        try:
            # Get all OTHER Origins' ports
            other_ports: set[int] = set()
            for oid, origin in origins_db.items():
                if oid != origin_id and 'required_ports' in origin:
                    other_ports.update(origin.get('required_ports') or [])

            sg_id = self.get_scrubber_security_group_id(region=region)

            for port in ports:
                if port in other_ports:
                    logger.info(f"Keeping port {port} in Security Group (used by other Origins)")
                    continue
                for protocol in ('tcp', 'udp'):
                    try:
                        self.provider.revoke_security_group_ingress(
                            group_id=sg_id,
                            ip_permissions=[{
                                'protocol': protocol,
                                'from_port': port,
                                'to_port': port,
                                'cidr': '0.0.0.0/0'
                            }],
                            region=region
                        )
                        logger.info(f"Removed {protocol.upper()} port {port} from Security Group (unused)")
                    except Exception as e:
                        logger.warning(f"Could not remove {protocol.upper()} port {port}: {e}")

        except Exception as e:
            logger.error(f"Failed to remove ports from Security Group: {e}")

    def allocate_eip(self, region: Optional[str] = None) -> Tuple[str, str]:
        """
        Allocate AWS Elastic IP.

        Uses REST API via AWSProvider for cloud-agnostic resource management.
        """
        result = self.provider.allocate_address(domain='vpc', region=region)
        eip = result['public_ip']
        eip_alloc_id = result['allocation_id']
        logger.info(f"Allocated EIP: {eip} (allocation_id={eip_alloc_id})")
        return eip, eip_alloc_id

    def assign_private_ip_to_eni(
        self,
        eni_id: str,
        private_ip: str,
        region: Optional[str] = None
    ) -> None:
        """
        Assign private IP to ENI.

        Uses REST API via AWSProvider for cloud-agnostic resource management.
        """
        self.provider.assign_private_ip_addresses(
            network_interface_id=eni_id,
            private_ip_addresses=[private_ip],
            region=region
        )
        logger.info(f"Assigned private IP {private_ip} to ENI {eni_id}")

    def associate_eip_to_eni(
        self,
        eip_alloc_id: str,
        eni_id: str,
        private_ip: str,
        region: Optional[str] = None
    ) -> None:
        """
        Associate Elastic IP to ENI with specific private IP.

        Uses REST API via AWSProvider for cloud-agnostic resource management.
        """
        self.provider.associate_address(
            allocation_id=eip_alloc_id,
            network_interface_id=eni_id,
            private_ip_address=private_ip,
            region=region
        )
        logger.info(f"Associated EIP {eip_alloc_id} to ENI {eni_id} (private IP {private_ip})")

    def release_eip(self, eip_alloc_id: str, region: Optional[str] = None) -> None:
        """
        Release Elastic IP.

        Uses REST API via AWSProvider for cloud-agnostic resource management.
        """
        self.provider.release_address(allocation_id=eip_alloc_id, region=region)
        logger.info(f"Released EIP {eip_alloc_id}")

    def describe_addresses(
        self,
        allocation_ids: Optional[List[str]] = None,
        public_ips: Optional[List[str]] = None,
        region: Optional[str] = None
    ) -> List[Dict]:
        """
        Describe Elastic IP addresses.

        Uses REST API via AWSProvider for cloud-agnostic resource management.
        """
        return self.provider.describe_addresses(
            allocation_ids=allocation_ids,
            public_ips=public_ips,
            region=region
        )

    def disassociate_address(self, association_id: str, region: Optional[str] = None) -> None:
        """
        Disassociate Elastic IP from ENI.

        Uses REST API via AWSProvider for cloud-agnostic resource management.
        """
        self.provider.disassociate_address(association_id=association_id, region=region)
        logger.info(f"Disassociated EIP (association_id={association_id})")

    def unassign_private_ip_addresses(
        self,
        eni_id: str,
        private_ips: List[str],
        region: Optional[str] = None
    ) -> None:
        """
        Unassign private IPs from ENI.

        Uses REST API via AWSProvider for cloud-agnostic resource management.
        """
        self.provider.unassign_private_ip_addresses(
            network_interface_id=eni_id,
            private_ip_addresses=private_ips,
            region=region
        )
        logger.info(f"Unassigned private IPs {private_ips} from ENI {eni_id}")

    def describe_network_interfaces(
        self,
        network_interface_ids: List[str],
        region: Optional[str] = None,
    ) -> List[Dict]:
        """
        Describe ENIs with backward-compatible field names.

        Uses REST API via AWSProvider for cloud-agnostic resource management.

        Args:
            network_interface_ids: List of ENI IDs to describe
            region: Optional region (defaults to self.region)

        Returns:
            List[Dict] with keys:
            - 'network_interface_id': str
            - 'private_ip_addresses': List[Dict] with 'private_ip_address' and 'primary' keys
        """
        # Use provider's describe_network_interfaces method
        results = self.provider.describe_network_interfaces(
            network_interface_ids=network_interface_ids,
            region=region
        )

        # Results from provider already have correct field names ('private_ip_address')
        # after Task 5 refactoring
        return results


# Singleton instance
aws_operations = AWSMinerOperations()
