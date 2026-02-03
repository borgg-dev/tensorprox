"""AWS provider using pure REST API with Signature V4"""

import hmac
import hashlib
import base64
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import quote, urlencode
import xml.etree.ElementTree as ET
from requests import Response
from .base import BaseProvider
from .capabilities.public_ip import PublicIPCapability
from .capabilities.secondary_ip import SecondaryIPCapability
from .capabilities.firewall import FirewallCapability
from .capabilities.metadata import InstanceMetadataCapability
from shared.config import get_settings
from shared.utils.logging import get_logger
from shared.utils.ssh import PROVIDER_SSH_USERS

logger = get_logger(__name__)


class AWSProvider(
    BaseProvider,
    PublicIPCapability,
    SecondaryIPCapability,
    FirewallCapability,
    InstanceMetadataCapability,
):
    """
    AWS EC2 provider using pure REST API calls.
    Implements AWS Signature Version 4 authentication.

    Uses Pydantic Settings for configuration (PROPER integration).

    References:
    - EC2 API: https://docs.aws.amazon.com/ec2/
    - Signature V4: https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
    """

    # AWS-specific defaults (imported from single source of truth)
    default_ssh_user = PROVIDER_SSH_USERS["aws"]
    default_home_dir = "/home/ubuntu"

    def __init__(
        self,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        region: Optional[str] = None,
    ):
        super().__init__()
        import requests

        settings = get_settings()
        self.access_key = access_key_id or settings.aws_access_key_id
        self.secret_key = secret_access_key or settings.aws_secret_access_key
        self._default_region = region or settings.aws_region  # Default region, never mutated
        self._region_cache: list[str] = []
        self._ami_cache: dict[str, str] = {}
        self.session = requests.Session()  # HTTP session for API calls

        if not self.access_key or not self.secret_key:
            raise ValueError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY required in tp.env")

        self.service = "ec2"

    @property
    def capabilities(self) -> set[str]:
        """Declare supported capabilities."""
        return {"public_ip", "secondary_ip", "firewall", "metadata"}

    def _sign(self, key: bytes, msg: str) -> bytes:
        """Generate HMAC-SHA256 signature"""
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def _get_signature_key(self, date_stamp: str, region: str) -> bytes:
        """
        Derive signing key using AWS Signature Version 4 algorithm.
        Implements the key derivation chain: kSecret -> kDate -> kRegion -> kService -> kSigning

        Args:
            date_stamp: Date stamp in YYYYMMDD format
            region: AWS region for signing
        """
        k_date = self._sign(("AWS4" + self.secret_key).encode("utf-8"), date_stamp)
        k_region = self._sign(k_date, region)
        k_service = self._sign(k_region, self.service)
        k_signing = self._sign(k_service, "aws4_request")
        return k_signing

    def _create_canonical_request(
        self,
        method: str,
        canonical_uri: str,
        canonical_querystring: str,
        canonical_headers: str,
        signed_headers: str,
        payload_hash: str,
    ) -> str:
        """Create canonical request for AWS Signature V4"""
        return "\n".join(
            [
                method,
                canonical_uri,
                canonical_querystring,
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )

    def _sign_request(
        self, params: Dict[str, str], region: str, method: str = "POST"
    ) -> Dict[str, str]:
        """
        Sign AWS EC2 API request using Signature Version 4.

        Args:
            params: API request parameters
            region: AWS region for this request
            method: HTTP method (POST or GET)

        Returns:
            Dictionary of headers including Authorization

        Note:
            For POST requests, parameters must be sorted before encoding to ensure
            the signature matches the actual request body sent by _make_signed_request.
        """
        # Compute host for this region (stateless)
        host = f"ec2.{region}.amazonaws.com"

        # Create timestamp
        t = datetime.utcnow()
        amz_date = t.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = t.strftime("%Y%m%d")

        # Build canonical request
        canonical_uri = "/"

        # For POST requests, include Content-Type in signed headers
        if method == "POST":
            canonical_headers = (
                f"content-type:application/x-www-form-urlencoded; charset=utf-8\n"
                f"host:{host}\n"
                f"x-amz-date:{amz_date}\n"
            )
            signed_headers = "content-type;host;x-amz-date"
        else:
            canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
            signed_headers = "host;x-amz-date"

        # Sort parameters (required for consistent signature)
        sorted_params = sorted(params.items())

        # Build canonical query string
        # For GET: Use URL encoding for canonical query string
        # For POST: canonical query string is empty
        if method == "GET":
            canonical_querystring = "&".join(
                [f"{quote(k, safe='')}={quote(str(v), safe='')}" for k, v in sorted_params]
            )
        else:
            canonical_querystring = ""

        # Create payload hash
        # For POST: use form-encoded body (matches what _make_signed_request sends)
        # For GET: empty string
        if method == "POST":
            payload = urlencode(sorted_params)
        else:
            payload = ""
        payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        # Create canonical request
        canonical_request = self._create_canonical_request(
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash,
        )

        # Create string to sign
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{date_stamp}/{region}/{self.service}/aws4_request"
        string_to_sign = "\n".join(
            [
                algorithm,
                amz_date,
                credential_scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )

        # Calculate signature
        signing_key = self._get_signature_key(date_stamp, region)
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        # Build authorization header
        authorization_header = (
            f"{algorithm} "
            f"Credential={self.access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )

        headers = {"Authorization": authorization_header, "x-amz-date": amz_date, "Host": host}

        # Add Content-Type for POST requests
        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"

        return headers

    def _make_signed_request(
        self, params: Dict[str, str], region: str, method: str = "POST"
    ) -> Response:
        """
        Make signed HTTP request to EC2 API.

        Args:
            params: API request parameters
            region: AWS region for this request
            method: HTTP method (POST or GET)

        Returns:
            Response object

        Note:
            For POST requests, the body must be pre-encoded with sorted parameters
            to match the signature computed in _sign_request.
        """
        # Compute endpoint for this region (stateless)
        endpoint = f"https://ec2.{region}.amazonaws.com"

        # Sign request with region
        headers = self._sign_request(params, region, method)

        if method == "POST":
            # Pre-encode body with sorted params to match signature
            sorted_params = sorted(params.items())
            post_body = urlencode(sorted_params)

            response = self.session.post(endpoint, data=post_body, headers=headers)
        else:
            # GET with query string
            response = self.session.get(endpoint, params=params, headers=headers)

        return response

    def _parse_xml_response(self, xml_text: str) -> ET.Element:
        """Parse XML response and check for errors"""
        root = ET.fromstring(xml_text)

        # Check for error response
        error = root.find(".//{http://ec2.amazonaws.com/doc/2016-11-15/}Errors")
        if error is not None:
            error_code = error.find(".//{http://ec2.amazonaws.com/doc/2016-11-15/}Code")
            error_msg = error.find(".//{http://ec2.amazonaws.com/doc/2016-11-15/}Message")
            code = error_code.text if error_code is not None else "Unknown"
            msg = error_msg.text if error_msg is not None else "Unknown error"
            raise Exception(f"AWS API Error {code}: {msg}")

        return root

    def run_instances_in_region(
        self,
        region: str,
        ami_id: str,
        instance_type: str,
        subnet_id: str,
        security_group_ids: List[str],
        key_name: str,
        user_data: str,
        tags: Dict[str, str],
        source_dest_check: bool = True,
    ) -> Dict:
        """
        Launch EC2 instance in specific region via RunInstances API.

        Args:
            region: AWS region to launch instance in
            ami_id: AMI ID to launch
            instance_type: Instance type (e.g., t3.medium)
            subnet_id: Subnet ID for network interface
            security_group_ids: List of security group IDs
            key_name: SSH key pair name
            user_data: User data script (base64 encoded internally)
            tags: Instance tags
            source_dest_check: Enable/disable source/destination checks

        Returns:
            {
                'instance_id': str,
                'public_ip': str,
                'private_ip': str,
                'status': str
            }
        """
        # Encode user data
        user_data_b64 = base64.b64encode(user_data.encode("utf-8")).decode("utf-8")

        # Build parameters
        params = {
            "Action": "RunInstances",
            "Version": "2016-11-15",
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "MinCount": "1",
            "MaxCount": "1",
            "SubnetId": subnet_id,
            "KeyName": key_name,
            "UserData": user_data_b64,
        }

        # SourceDestinationCheck attribute must be set via ModifyInstanceAttribute after launch
        # Not supported as RunInstances parameter in this API version

        # Add security groups
        for idx, sg_id in enumerate(security_group_ids, start=1):
            params[f"SecurityGroupId.{idx}"] = sg_id

        # Add tags
        tag_idx = 1
        for key, value in tags.items():
            params["TagSpecification.1.ResourceType"] = "instance"
            params[f"TagSpecification.1.Tag.{tag_idx}.Key"] = key
            params[f"TagSpecification.1.Tag.{tag_idx}.Value"] = value
            tag_idx += 1

        # Make request with explicit region
        response = self._make_signed_request(params, region)

        if response.status_code != 200:
            raise Exception(f"RunInstances failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        instance = root.find(".//aws:instancesSet/aws:item", ns)
        if instance is None:
            raise Exception("No instance in RunInstances response")

        instance_id_elem = instance.find("aws:instanceId", ns)
        private_ip_elem = instance.find("aws:privateIpAddress", ns)
        state_elem = instance.find("aws:instanceState/aws:name", ns)

        instance_id = instance_id_elem.text if instance_id_elem is not None else None
        private_ip = private_ip_elem.text if private_ip_elem is not None else None
        state = state_elem.text if state_elem is not None else "unknown"

        if not instance_id:
            raise Exception("Instance ID not found in response")

        return {
            "instance_id": instance_id,
            "public_ip": "",  # Not assigned immediately
            "private_ip": private_ip or "",
            "status": state,
        }

    def run_instances(
        self,
        ami_id: str,
        instance_type: str,
        subnet_id: str,
        security_group_ids: List[str],
        key_name: str,
        user_data: str,
        tags: Dict[str, str],
        source_dest_check: bool = True,
    ) -> Dict:
        """
        Launch EC2 instance via RunInstances API.

        Args:
            ami_id: AMI ID to launch
            instance_type: Instance type (e.g., t3.medium)
            subnet_id: Subnet ID for network interface
            security_group_ids: List of security group IDs
            key_name: SSH key pair name
            user_data: User data script (base64 encoded internally)
            tags: Instance tags
            source_dest_check: Enable/disable source/destination checks

        Returns:
            {
                'instance_id': str,
                'public_ip': str,
                'private_ip': str,
                'status': str
            }
        """
        # Encode user data
        user_data_b64 = base64.b64encode(user_data.encode("utf-8")).decode("utf-8")

        # Build parameters
        params = {
            "Action": "RunInstances",
            "Version": "2016-11-15",
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "MinCount": "1",
            "MaxCount": "1",
            "SubnetId": subnet_id,
            "KeyName": key_name,
            "UserData": user_data_b64,
        }

        # SourceDestinationCheck attribute must be set via ModifyInstanceAttribute after launch
        # Not supported as RunInstances parameter in this API version

        # Add security groups
        for idx, sg_id in enumerate(security_group_ids, start=1):
            params[f"SecurityGroupId.{idx}"] = sg_id

        # Add tags
        tag_idx = 1
        for key, value in tags.items():
            params["TagSpecification.1.ResourceType"] = "instance"
            params[f"TagSpecification.1.Tag.{tag_idx}.Key"] = key
            params[f"TagSpecification.1.Tag.{tag_idx}.Value"] = value
            tag_idx += 1

        # Make request (use default region for this low-level method)
        response = self._make_signed_request(params, self._default_region)

        if response.status_code != 200:
            raise Exception(f"RunInstances failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        instance = root.find(".//aws:instancesSet/aws:item", ns)
        if instance is None:
            raise Exception("No instance in RunInstances response")

        instance_id_elem = instance.find("aws:instanceId", ns)
        private_ip_elem = instance.find("aws:privateIpAddress", ns)
        state_elem = instance.find("aws:instanceState/aws:name", ns)

        instance_id = instance_id_elem.text if instance_id_elem is not None else None
        private_ip = private_ip_elem.text if private_ip_elem is not None else None
        state = state_elem.text if state_elem is not None else "unknown"

        if not instance_id:
            raise Exception("Instance ID not found in response")

        return {
            "instance_id": instance_id,
            "public_ip": "",  # Not assigned immediately
            "private_ip": private_ip or "",
            "status": state,
        }

    def describe_instances_in_region(self, instance_ids: List[str], region: str) -> List[Dict]:
        """
        Query instance details in specific region via DescribeInstances API.

        Args:
            instance_ids: List of instance IDs to describe
            region: AWS region to query

        Returns:
            List of instance details
        """
        params = {"Action": "DescribeInstances", "Version": "2016-11-15"}

        # Add instance IDs
        for idx, instance_id in enumerate(instance_ids, start=1):
            params[f"InstanceId.{idx}"] = instance_id

        response = self._make_signed_request(params, region, method="GET")

        # AWS can return 400 InvalidInstanceID.NotFound briefly after launch; treat as empty
        if response.status_code == 400 and "InvalidInstanceID.NotFound" in response.text:
            return []
        if response.status_code != 200:
            raise Exception(f"DescribeInstances failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        instances = []
        for item in root.findall(".//aws:instancesSet/aws:item", ns):
            instance_id_elem = item.find("aws:instanceId", ns)
            public_ip_elem = item.find("aws:ipAddress", ns)
            private_ip_elem = item.find("aws:privateIpAddress", ns)
            state_elem = item.find("aws:instanceState/aws:name", ns)
            vpc_id_elem = item.find("aws:vpcId", ns)
            # Fallback for VPC public IP associations
            if public_ip_elem is None or not (public_ip_elem.text or "").strip():
                assoc_ip_elem = item.find(
                    "aws:networkInterfaceSet/aws:item/aws:association/aws:publicIp", ns
                )
                if assoc_ip_elem is not None:
                    public_ip_elem = assoc_ip_elem

            # Parse security groups
            security_groups = []
            for sg_item in item.findall(".//aws:groupSet/aws:item", ns):
                sg_id_elem = sg_item.find("aws:groupId", ns)
                sg_name_elem = sg_item.find("aws:groupName", ns)
                if sg_id_elem is not None:
                    security_groups.append(
                        {
                            "group_id": sg_id_elem.text,
                            "group_name": sg_name_elem.text if sg_name_elem is not None else "",
                        }
                    )

            instances.append(
                {
                    "instance_id": (
                        instance_id_elem.text if instance_id_elem is not None else None
                    ),
                    "public_ip": public_ip_elem.text if public_ip_elem is not None else "",
                    "private_ip": (private_ip_elem.text if private_ip_elem is not None else ""),
                    "status": state_elem.text if state_elem is not None else "unknown",
                    "vpc_id": vpc_id_elem.text if vpc_id_elem is not None else None,
                    "security_groups": security_groups,
                }
            )

        return instances

    def describe_instances_with_filters(
        self,
        region: str,
        filters: Dict[str, str],
    ) -> List[Dict]:
        """
        Query instances in a region using filters.

        Follows same pattern as describe_vpcs, describe_subnets, etc.

        Args:
            region: AWS region to query
            filters: Filter dict (e.g., {'tag:Name': 'exit_hub*', 'instance-state-name': 'running'})

        Returns:
            List of instance details with launch_time included for age checks
        """
        from datetime import datetime

        params = {"Action": "DescribeInstances", "Version": "2016-11-15"}

        # Add filters
        for idx, (name, value) in enumerate(filters.items(), start=1):
            params[f"Filter.{idx}.Name"] = name
            params[f"Filter.{idx}.Value.1"] = value

        response = self._make_signed_request(params, region, method="GET")

        if response.status_code != 200:
            raise Exception(f"DescribeInstances failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        instances = []
        for item in root.findall(".//aws:instancesSet/aws:item", ns):
            instance_id_elem = item.find("aws:instanceId", ns)
            public_ip_elem = item.find("aws:ipAddress", ns)
            private_ip_elem = item.find("aws:privateIpAddress", ns)
            state_elem = item.find("aws:instanceState/aws:name", ns)
            launch_time_elem = item.find("aws:launchTime", ns)

            # Fallback for VPC public IP associations
            if public_ip_elem is None or not (public_ip_elem.text or "").strip():
                assoc_ip_elem = item.find(
                    "aws:networkInterfaceSet/aws:item/aws:association/aws:publicIp", ns
                )
                if assoc_ip_elem is not None:
                    public_ip_elem = assoc_ip_elem

            # Parse launch time (ISO 8601 format: 2023-12-23T16:06:18.000Z)
            launch_time = None
            if launch_time_elem is not None and launch_time_elem.text:
                try:
                    launch_time = datetime.fromisoformat(
                        launch_time_elem.text.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            # Parse instance type
            instance_type_elem = item.find("aws:instanceType", ns)

            # Parse tags
            tags = {}
            tag_set = item.find("aws:tagSet", ns)
            if tag_set is not None:
                for tag_item in tag_set.findall("aws:item", ns):
                    tag_key_elem = tag_item.find("aws:key", ns)
                    tag_value_elem = tag_item.find("aws:value", ns)
                    if tag_key_elem is not None and tag_key_elem.text:
                        tags[tag_key_elem.text] = (
                            tag_value_elem.text if tag_value_elem is not None else ""
                        )

            instances.append(
                {
                    "instance_id": (
                        instance_id_elem.text if instance_id_elem is not None else None
                    ),
                    "public_ip": public_ip_elem.text if public_ip_elem is not None else "",
                    "private_ip": (private_ip_elem.text if private_ip_elem is not None else ""),
                    "status": state_elem.text if state_elem is not None else "unknown",
                    "launch_time": launch_time,
                    "instance_type": (
                        instance_type_elem.text if instance_type_elem is not None else ""
                    ),
                    "tags": tags,
                }
            )

        return instances

    def describe_instances(
        self,
        instance_ids: List[str],
        region: Optional[str] = None,
    ) -> List[Dict]:
        """
        Query instance details via DescribeInstances API.

        Args:
            instance_ids: List of instance IDs to describe
            region: AWS region (default: use default region)

        Returns:
            List of instance details
        """
        params = {"Action": "DescribeInstances", "Version": "2016-11-15"}

        # Add instance IDs
        for idx, instance_id in enumerate(instance_ids, start=1):
            params[f"InstanceId.{idx}"] = instance_id

        response = self._make_signed_request(params, region or self._default_region, method="GET")

        # AWS can return 400 InvalidInstanceID.NotFound briefly after launch; treat as empty
        if response.status_code == 400 and "InvalidInstanceID.NotFound" in response.text:
            return []
        if response.status_code != 200:
            raise Exception(f"DescribeInstances failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        instances = []
        for item in root.findall(".//aws:instancesSet/aws:item", ns):
            instance_id_elem = item.find("aws:instanceId", ns)
            public_ip_elem = item.find("aws:ipAddress", ns)
            private_ip_elem = item.find("aws:privateIpAddress", ns)
            state_elem = item.find("aws:instanceState/aws:name", ns)
            vpc_id_elem = item.find("aws:vpcId", ns)
            # Fallback for VPC public IP associations
            if public_ip_elem is None or not (public_ip_elem.text or "").strip():
                assoc_ip_elem = item.find(
                    "aws:networkInterfaceSet/aws:item/aws:association/aws:publicIp", ns
                )
                if assoc_ip_elem is not None:
                    public_ip_elem = assoc_ip_elem

            # Parse security groups
            security_groups = []
            for sg_item in item.findall(".//aws:groupSet/aws:item", ns):
                sg_id_elem = sg_item.find("aws:groupId", ns)
                sg_name_elem = sg_item.find("aws:groupName", ns)
                if sg_id_elem is not None:
                    security_groups.append(
                        {
                            "group_id": sg_id_elem.text,
                            "group_name": sg_name_elem.text if sg_name_elem is not None else "",
                        }
                    )

            instances.append(
                {
                    "instance_id": (
                        instance_id_elem.text if instance_id_elem is not None else None
                    ),
                    "public_ip": public_ip_elem.text if public_ip_elem is not None else "",
                    "private_ip": (private_ip_elem.text if private_ip_elem is not None else ""),
                    "status": state_elem.text if state_elem is not None else "unknown",
                    "vpc_id": vpc_id_elem.text if vpc_id_elem is not None else None,
                    "security_groups": security_groups,
                }
            )

        return instances

    def terminate_instances(
        self, instance_ids: List[str], region: Optional[str] = None
    ) -> bool:
        """
        Terminate EC2 instances via TerminateInstances API.

        Args:
            instance_ids: List of instance IDs to terminate
            region: AWS region (default: use default region)

        Returns:
            True if successful
        """
        params = {"Action": "TerminateInstances", "Version": "2016-11-15"}

        # Add instance IDs
        for idx, instance_id in enumerate(instance_ids, start=1):
            params[f"InstanceId.{idx}"] = instance_id

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"TerminateInstances failed: {response.status_code} {response.text}")

        self._parse_xml_response(response.text)  # Check for errors
        return True

    def allocate_address(self, domain: str = "vpc", region: Optional[str] = None) -> Dict[str, str]:
        """
        Allocate Elastic IP via AllocateAddress API.

        Args:
            domain: 'vpc' or 'standard'
            region: AWS region (default: use default region)

        Returns:
            {
                'allocation_id': str,
                'public_ip': str
            }
        """
        params = {"Action": "AllocateAddress", "Version": "2016-11-15", "Domain": domain}

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"AllocateAddress failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        allocation_id_elem = root.find(".//aws:allocationId", ns)
        public_ip_elem = root.find(".//aws:publicIp", ns)

        return {
            "allocation_id": (allocation_id_elem.text if allocation_id_elem is not None else ""),
            "public_ip": public_ip_elem.text if public_ip_elem is not None else "",
        }

    def associate_address(
        self,
        allocation_id: str,
        instance_id: Optional[str] = None,
        network_interface_id: Optional[str] = None,
        private_ip_address: Optional[str] = None,
        region: Optional[str] = None,
    ) -> str:
        """
        Associate Elastic IP via AssociateAddress API.

        Args:
            allocation_id: EIP allocation ID
            instance_id: Instance ID (for EC2-Classic or default VPC interface)
            network_interface_id: ENI ID (for VPC)
            private_ip_address: Private IP to associate with
            region: AWS region (default: use default region)

        Returns:
            Association ID
        """
        params = {
            "Action": "AssociateAddress",
            "Version": "2016-11-15",
            "AllocationId": allocation_id,
        }

        if instance_id:
            params["InstanceId"] = instance_id
        if network_interface_id:
            params["NetworkInterfaceId"] = network_interface_id
        if private_ip_address:
            params["PrivateIpAddress"] = private_ip_address

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"AssociateAddress failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        assoc_id_elem = root.find(".//aws:associationId", ns)
        return assoc_id_elem.text if assoc_id_elem is not None else ""

    def disassociate_address(self, association_id: str, region: Optional[str] = None) -> bool:
        """
        Disassociate Elastic IP via DisassociateAddress API.

        Args:
            association_id: Association ID from associate_address
            region: AWS region (default: use default region)

        Returns:
            True if successful
        """
        params = {
            "Action": "DisassociateAddress",
            "Version": "2016-11-15",
            "AssociationId": association_id,
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"DisassociateAddress failed: {response.status_code} {response.text}")

        self._parse_xml_response(response.text)  # Check for errors
        return True

    def release_address(self, allocation_id: str, region: Optional[str] = None) -> bool:
        """
        Release Elastic IP via ReleaseAddress API.

        Args:
            allocation_id: EIP allocation ID
            region: AWS region (default: use default region)

        Returns:
            True if successful
        """
        params = {
            "Action": "ReleaseAddress",
            "Version": "2016-11-15",
            "AllocationId": allocation_id,
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"ReleaseAddress failed: {response.status_code} {response.text}")

        self._parse_xml_response(response.text)  # Check for errors
        return True

    def describe_addresses(
        self,
        allocation_ids: Optional[List[str]] = None,
        public_ips: Optional[List[str]] = None,
        region: Optional[str] = None,
    ) -> List[Dict]:
        """
        Query Elastic IP details via DescribeAddresses API.

        Args:
            allocation_ids: Filter by allocation IDs
            public_ips: Filter by public IPs
            region: AWS region (default: use default region)

        Returns:
            List of EIP details
        """
        params = {"Action": "DescribeAddresses", "Version": "2016-11-15"}

        if allocation_ids:
            for idx, alloc_id in enumerate(allocation_ids, start=1):
                params[f"AllocationId.{idx}"] = alloc_id

        if public_ips:
            for idx, public_ip in enumerate(public_ips, start=1):
                params[f"PublicIp.{idx}"] = public_ip

        response = self._make_signed_request(params, region or self._default_region, method="GET")

        if response.status_code != 200:
            raise Exception(f"DescribeAddresses failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        addresses = []
        for item in root.findall(".//aws:addressesSet/aws:item", ns):
            allocation_id_elem = item.find("aws:allocationId", ns)
            public_ip_elem = item.find("aws:publicIp", ns)
            private_ip_elem = item.find("aws:privateIpAddress", ns)
            assoc_id_elem = item.find("aws:associationId", ns)
            instance_id_elem = item.find("aws:instanceId", ns)
            network_interface_id_elem = item.find("aws:networkInterfaceId", ns)

            addresses.append(
                {
                    "allocation_id": (
                        allocation_id_elem.text if allocation_id_elem is not None else ""
                    ),
                    "public_ip": public_ip_elem.text if public_ip_elem is not None else "",
                    "private_ip": (private_ip_elem.text if private_ip_elem is not None else ""),
                    "association_id": (assoc_id_elem.text if assoc_id_elem is not None else ""),
                    "instance_id": (instance_id_elem.text if instance_id_elem is not None else ""),
                    "network_interface_id": (
                        network_interface_id_elem.text
                        if network_interface_id_elem is not None
                        else ""
                    ),
                }
            )

        return addresses

    def describe_network_interfaces(
        self,
        instance_id: Optional[str] = None,
        network_interface_ids: Optional[List[str]] = None,
        region: Optional[str] = None,
    ) -> List[Dict]:
        """
        Query network interface details via DescribeNetworkInterfaces API.

        Implements SecondaryIPCapability interface with backward-compatible field names.

        Args:
            instance_id: Optional instance ID to filter by
            network_interface_ids: Optional list of ENI IDs to query
            region: AWS region (default: use default region)

        Returns:
            List of ENI details with structure:
            [
                {
                    'network_interface_id': str,
                    'instance_id': str (empty if not attached),
                    'private_ip_address': str (primary IP),
                    'private_ip_addresses': [
                        {'private_ip_address': str, 'primary': bool},
                        ...
                    ],
                    'device_index': int (if attached to instance)
                },
                ...
            ]

        Example:
            >>> provider.describe_network_interfaces(instance_id='i-abc123')
            >>> provider.describe_network_interfaces(network_interface_ids=['eni-abc123'])
        """
        params = {"Action": "DescribeNetworkInterfaces", "Version": "2016-11-15"}

        # Add filters based on provided parameters
        if instance_id:
            params["Filter.1.Name"] = "attachment.instance-id"
            params["Filter.1.Value.1"] = instance_id
        elif network_interface_ids:
            for idx, eni_id in enumerate(network_interface_ids, start=1):
                params[f"NetworkInterfaceId.{idx}"] = eni_id

        response = self._make_signed_request(params, region or self._default_region, method="GET")

        if response.status_code != 200:
            raise Exception(
                f"DescribeNetworkInterfaces failed: {response.status_code} {response.text}"
            )

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        interfaces = []
        for item in root.findall(".//aws:networkInterfaceSet/aws:item", ns):
            eni_id_elem = item.find("aws:networkInterfaceId", ns)
            if eni_id_elem is None:
                continue

            # Extract instance ID and device index from attachment
            instance_id_elem = item.find("aws:attachment/aws:instanceId", ns)
            device_index_elem = item.find("aws:attachment/aws:deviceIndex", ns)

            # Parse private IP addresses
            private_ip_addresses = []
            primary_ip = ""
            for ip_item in item.findall(".//aws:privateIpAddressesSet/aws:item", ns):
                ip_elem = ip_item.find("aws:privateIpAddress", ns)
                primary_elem = ip_item.find("aws:primary", ns)

                if ip_elem is not None and ip_elem.text:
                    # Parse primary flag (AWS returns 'true' or 'false' as string)
                    is_primary = False
                    if primary_elem is not None and primary_elem.text:
                        is_primary = primary_elem.text.lower() == "true"

                    # Use 'private_ip_address' for capability compatibility
                    private_ip_addresses.append(
                        {"private_ip_address": ip_elem.text, "primary": is_primary}
                    )

                    if is_primary:
                        primary_ip = ip_elem.text

            result = {
                "network_interface_id": eni_id_elem.text,
                "instance_id": (instance_id_elem.text if instance_id_elem is not None else ""),
                "private_ip_address": primary_ip,
                "private_ip_addresses": private_ip_addresses,
            }

            # Add device_index if available (for backward compatibility)
            if device_index_elem is not None:
                result["device_index"] = int(device_index_elem.text)

            interfaces.append(result)

        return interfaces

    def describe_network_interfaces_by_id(self, eni_ids: List[str], region: Optional[str] = None) -> List[Dict]:
        """
        Legacy method - use describe_network_interfaces(network_interface_ids=...) instead.

        DEPRECATED: This method is kept for backward compatibility.
        Use describe_network_interfaces(network_interface_ids=eni_ids) instead.

        Args:
            eni_ids: List of ENI IDs to query
            region: AWS region (default: use default region)

        Returns:
            List of ENI details with 'ip' field (legacy) and 'private_ip_address' (new)
        """
        # Call the unified method
        results = self.describe_network_interfaces(network_interface_ids=eni_ids, region=region)

        # Add legacy 'ip' field for backward compatibility
        for eni in results:
            if "private_ip_addresses" in eni:
                for addr in eni["private_ip_addresses"]:
                    if "private_ip_address" in addr:
                        # Add legacy 'ip' field
                        addr["ip"] = addr["private_ip_address"]

        return results

    # ----------------------------------------------------------------------
    # Discovery helpers
    # ----------------------------------------------------------------------

    def describe_regions(self) -> list[str]:
        """List available AWS regions."""
        params = {
            "Action": "DescribeRegions",
            "Version": "2016-11-15",
        }
        response = self._make_signed_request(params, self._default_region, method="GET")
        if response.status_code != 200:
            raise Exception(f"DescribeRegions failed: {response.status_code} {response.text}")

        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}
        regions = []
        for item in root.findall(".//aws:regionInfo/aws:item", ns):
            name_elem = item.find("aws:regionName", ns)
            if name_elem is not None and name_elem.text:
                regions.append(name_elem.text)
        self._region_cache = regions
        return regions

    def list_regions(self) -> List[str]:
        """Get list of available AWS regions (BaseProvider interface).

        Returns:
            List of AWS region identifiers (e.g., ["us-east-1", "eu-central-1"])
        """
        return self.describe_regions()

    def describe_availability_zones(self, region: Optional[str] = None) -> List[str]:
        """List available availability zones for a region.

        Args:
            region: AWS region to query. Defaults to _default_region.

        Returns:
            List of availability zone names (e.g., ["us-east-1a", "us-east-1b"])
        """
        region = region or self._default_region
        params = {
            "Action": "DescribeAvailabilityZones",
            "Version": "2016-11-15",
            "Filter.1.Name": "state",
            "Filter.1.Value.1": "available",
        }
        response = self._make_signed_request(params, region, method="GET")
        if response.status_code != 200:
            raise Exception(f"DescribeAvailabilityZones failed: {response.status_code} {response.text}")

        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}
        azs = []
        for item in root.findall(".//aws:availabilityZoneInfo/aws:item", ns):
            zone_elem = item.find("aws:zoneName", ns)
            if zone_elem is not None and zone_elem.text:
                azs.append(zone_elem.text)
        return sorted(azs)

    def describe_images(self, name_pattern: str, owner: str = "099720109477") -> list[dict]:
        """
        Query images matching name pattern and owner (used for Ubuntu LTS discovery).
        """
        params = {
            "Action": "DescribeImages",
            "Version": "2016-11-15",
            "Owner.1": owner,
            "Filter.1.Name": "name",
            "Filter.1.Value.1": name_pattern,
            "Filter.2.Name": "state",
            "Filter.2.Value.1": "available",
            "Filter.3.Name": "architecture",
            "Filter.3.Value.1": "x86_64",
        }

        response = self._make_signed_request(params, self._default_region, method="GET")
        if response.status_code != 200:
            raise Exception(f"DescribeImages failed: {response.status_code} {response.text}")

        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        images = []
        for item in root.findall(".//aws:imagesSet/aws:item", ns):
            image_id = item.find("aws:imageId", ns)
            name = item.find("aws:name", ns)
            creation = item.find("aws:creationDate", ns)
            if image_id is None or not image_id.text:
                continue
            images.append(
                {
                    "image_id": image_id.text,
                    "name": name.text if name is not None else "",
                    "creation_date": creation.text if creation is not None else "",
                }
            )
        return images

    def _describe_images_in_region(
        self, name_pattern: str, region: str, owner: str = "099720109477"
    ) -> list[dict]:
        """
        Query images matching name pattern in specific region.

        Args:
            name_pattern: Image name pattern to search for
            region: AWS region to query
            owner: AWS account ID (default: Canonical for Ubuntu)

        Returns:
            List of matching images
        """
        params = {
            "Action": "DescribeImages",
            "Version": "2016-11-15",
            "Owner.1": owner,
            "Filter.1.Name": "name",
            "Filter.1.Value.1": name_pattern,
            "Filter.2.Name": "state",
            "Filter.2.Value.1": "available",
            "Filter.3.Name": "architecture",
            "Filter.3.Value.1": "x86_64",
        }

        response = self._make_signed_request(params, region, method="GET")
        if response.status_code != 200:
            raise Exception(f"DescribeImages failed: {response.status_code} {response.text}")

        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        images = []
        for item in root.findall(".//aws:imagesSet/aws:item", ns):
            image_id = item.find("aws:imageId", ns)
            name = item.find("aws:name", ns)
            creation = item.find("aws:creationDate", ns)
            if image_id is None or not image_id.text:
                continue
            images.append(
                {
                    "image_id": image_id.text,
                    "name": name.text if name is not None else "",
                    "creation_date": creation.text if creation is not None else "",
                }
            )
        return images

    def _resolve_ami(self, region: str) -> str:
        """
        Resolve a recent Ubuntu 22.04 AMI for the target region (cached).

        Args:
            region: AWS region to query

        Returns:
            AMI ID for Ubuntu 22.04 in the specified region
        """
        if region in self._ami_cache:
            return self._ami_cache[region]

        # Query images in the specified region (stateless - describe_images_in_region handles region)
        images = self._describe_images_in_region(
            "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*", region
        )
        if not images:
            raise Exception(f"No Ubuntu 22.04 images found in region {region}")

        latest = sorted(images, key=lambda i: i.get("creation_date", ""), reverse=True)[0]
        self._ami_cache[region] = latest["image_id"]
        return latest["image_id"]

    def assign_private_ip_addresses(
        self, network_interface_id: str, private_ip_addresses: List[str], region: Optional[str] = None
    ) -> bool:
        """
        Assign private IP addresses to ENI via AssignPrivateIpAddresses API.

        Args:
            network_interface_id: ENI ID
            private_ip_addresses: List of private IPs to assign
            region: AWS region (default: use default region)

        Returns:
            True if successful
        """
        params = {
            "Action": "AssignPrivateIpAddresses",
            "Version": "2016-11-15",
            "NetworkInterfaceId": network_interface_id,
        }

        for idx, ip in enumerate(private_ip_addresses, start=1):
            params[f"PrivateIpAddress.{idx}"] = ip

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(
                f"AssignPrivateIpAddresses failed: {response.status_code} {response.text}"
            )

        self._parse_xml_response(response.text)  # Check for errors
        return True

    def assign_secondary_private_ipv4(self, eni_id: str, count: int = 1, region: Optional[str] = None) -> list[str]:
        """
        Auto-assign secondary private IPv4 addresses to ENI via AssignPrivateIpAddresses API.

        This method requests AWS to automatically assign secondary private IPv4 addresses
        from the subnet's available IP pool. Unlike assign_private_ip_addresses(), this
        method does NOT require explicit IP addresses - AWS selects available IPs automatically.

        Args:
            eni_id: Network interface ID (ENI)
            count: Number of secondary private IPv4 addresses to assign (default: 1)
            region: AWS region (default: use default region)

        Returns:
            List of newly assigned private IPv4 addresses

        Raises:
            Exception: If AWS API call fails or if assigned IPs cannot be parsed

        Example:
            >>> provider = AWSProvider()
            >>> assigned_ips = provider.assign_secondary_private_ipv4('eni-abc123', count=2)
            >>> print(assigned_ips)
            ['10.0.1.50', '10.0.1.51']

        Note:
            - This is used for provider-agnostic dynamic addressing (MINER-SPEC.md Section 3.1)
            - AWS selects IPs from the subnet's available pool
            - Primary IP is never changed (only secondary IPs are assigned)
        """
        params = {
            "Action": "AssignPrivateIpAddresses",
            "Version": "2016-11-15",
            "NetworkInterfaceId": eni_id,
            "SecondaryPrivateIpAddressCount": str(count),
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(
                f"AssignPrivateIpAddresses failed: {response.status_code} {response.text}"
            )

        # Parse response to extract assigned IPs
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        # AWS returns assigned IPs in assignedPrivateIpAddressesSet
        assigned_ips = []
        for item in root.findall(".//aws:assignedPrivateIpAddressesSet/aws:item", ns):
            ip_elem = item.find("aws:privateIpAddress", ns)
            if ip_elem is not None and ip_elem.text:
                assigned_ips.append(ip_elem.text)

        if not assigned_ips:
            raise Exception(
                f"AssignPrivateIpAddresses succeeded but no IPs found in response. "
                f"Requested {count} IPs for ENI {eni_id}"
            )

        return assigned_ips

    def unassign_private_ip_addresses(
        self, network_interface_id: str, private_ip_addresses: List[str], region: Optional[str] = None
    ) -> bool:
        """
        Remove private IP addresses from ENI via UnassignPrivateIpAddresses API.

        Args:
            network_interface_id: ENI ID
            private_ip_addresses: List of private IPs to remove
            region: AWS region (default: use default region)

        Returns:
            True if successful
        """
        params = {
            "Action": "UnassignPrivateIpAddresses",
            "Version": "2016-11-15",
            "NetworkInterfaceId": network_interface_id,
        }

        for idx, ip in enumerate(private_ip_addresses, start=1):
            params[f"PrivateIpAddress.{idx}"] = ip

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(
                f"UnassignPrivateIpAddresses failed: {response.status_code} {response.text}"
            )

        self._parse_xml_response(response.text)  # Check for errors
        return True

    # BaseProvider interface implementation

    def create_instance(
        self, region: str, instance_type: str, user_data: str, tags: Dict[str, str]
    ) -> Dict:
        """
        Launch EC2 instance via RunInstances API with AZ failover.

        This is a simplified wrapper that uses hardcoded defaults for AMI,
        subnet, security group, and key pair. For full control, use run_instances().

        Includes automatic failover across availability zones when encountering:
        - InsufficientInstanceCapacity: No capacity in the AZ
        - Unsupported: Instance type not supported in the AZ

        Args:
            region: AWS region for the instance
            instance_type: Instance type (e.g., t3.medium)
            user_data: User data script
            tags: Instance tags

        Returns:
            {
                'instance_id': str,
                'public_ip': str,
                'private_ip': str,
                'status': str
            }
        """
        # Get AWS configuration from Pydantic Settings
        settings = get_settings()
        key_name = settings.aws_ssh_key_name

        # Get or create VPC/subnet/SG infrastructure via REST API (replaces Terraform!)
        infra = self.get_or_create_scrubber_infrastructure(region)
        vpc_id = infra["vpc_id"]
        security_group_id = infra["security_group_id"]
        ami_id = self._resolve_ami(region)

        # Get available AZs and existing subnets for AZ failover
        available_azs = self.describe_availability_zones(region)
        existing_subnets = self.describe_subnets(
            filters={"vpc-id": vpc_id, "tag:Name": "tensorprox-subnet"}, region=region
        )

        # Build map of AZ -> subnet_id
        az_subnet_map = {s["availability_zone"]: s["subnet_id"] for s in existing_subnets}
        tried_azs: set = set()
        last_error = None

        # Track CIDR blocks to avoid conflicts
        used_cidrs = {s.get("cidr_block") for s in existing_subnets if s.get("cidr_block")}

        logger.info(
            f"Using infrastructure: VPC {vpc_id}, SG {security_group_id}, "
            f"available AZs: {available_azs}, existing subnets: {list(az_subnet_map.keys())}"
        )

        for attempt in range(len(available_azs)):
            # Pick an AZ: prefer existing subnets, then try new ones
            current_az = None
            subnet_id = None

            # First try existing subnets in untried AZs
            for az, sid in az_subnet_map.items():
                if az not in tried_azs:
                    current_az = az
                    subnet_id = sid
                    break

            # If no existing subnet available, create one in an untried AZ
            if not current_az:
                for az in available_azs:
                    if az not in tried_azs:
                        current_az = az
                        break

            if not current_az:
                break  # All AZs exhausted

            tried_azs.add(current_az)

            # Create subnet if needed
            if not subnet_id:
                # Generate unique CIDR
                for i in range(1, 256):
                    cidr = f"10.0.{i}.0/24"
                    if cidr not in used_cidrs:
                        used_cidrs.add(cidr)
                        break

                try:
                    logger.info(f"Creating subnet in {current_az} with CIDR {cidr}...")
                    subnet_result = self.create_subnet(
                        vpc_id=vpc_id,
                        cidr_block=cidr,
                        availability_zone=current_az,
                        name="tensorprox-subnet",
                        region=region
                    )
                    subnet_id = subnet_result["subnet_id"]
                    az_subnet_map[current_az] = subnet_id

                    # Enable auto-assign public IP
                    self.modify_subnet_attribute(subnet_id, map_public_ip_on_launch=True, region=region)

                    # Associate with route table
                    route_tables = self.describe_route_tables(
                        filters={"vpc-id": vpc_id, "tag:Name": "tensorprox-route-table"}, region=region
                    )
                    if route_tables:
                        self.associate_route_table(route_tables[0]["route_table_id"], subnet_id, region=region)
                except Exception as e:
                    logger.warning(f"Failed to create subnet in {current_az}: {e}")
                    continue

            # Try to launch instance
            try:
                logger.info(f"Launching {instance_type} in {current_az} (subnet {subnet_id})...")
                launched = self.run_instances_in_region(
                    region=region,
                    ami_id=ami_id,
                    instance_type=instance_type,
                    subnet_id=subnet_id,
                    security_group_ids=[security_group_id],
                    key_name=key_name,
                    user_data=user_data,
                    tags=tags,
                    source_dest_check=False,
                )
                instance_id = launched["instance_id"]

                # Poll until running with public IP
                ready = self.wait_for_instance_running(instance_id, region=region)
                launched["public_ip"] = ready.get("public_ip") or launched.get("public_ip")
                launched["private_ip"] = ready.get("private_ip") or launched.get("private_ip")
                launched["status"] = ready.get("status") or launched.get("status")
                if not launched.get("public_ip"):
                    raise Exception(
                        f"Instance {instance_id} did not receive a public IP in region {region}"
                    )

                logger.info(f"Instance {instance_id} launched successfully in {current_az}")
                return launched

            except Exception as e:
                error_str = str(e)
                last_error = e

                # Check if this is an AZ-specific error that we can retry
                if "InsufficientInstanceCapacity" in error_str:
                    logger.warning(
                        f"InsufficientInstanceCapacity in {current_az}, trying next AZ... "
                        f"(tried {len(tried_azs)}/{len(available_azs)} AZs)"
                    )
                    continue
                elif "Unsupported" in error_str and "Availability Zone" in error_str:
                    logger.warning(
                        f"Instance type {instance_type} not supported in {current_az}, trying next AZ... "
                        f"(tried {len(tried_azs)}/{len(available_azs)} AZs)"
                    )
                    continue
                else:
                    # Non-AZ-specific error, don't retry
                    raise

        # All AZs exhausted
        raise Exception(
            f"Failed to launch {instance_type} in any AZ in {region}. "
            f"Tried {len(tried_azs)} AZs: {sorted(tried_azs)}. "
            f"Last error: {last_error}"
        )

    def delete_instance(self, instance_id: str, region: Optional[str] = None) -> bool:
        """
        Terminate EC2 instance via TerminateInstances API.

        Args:
            instance_id: Instance ID to terminate
            region: AWS region (uses default if not specified)

        Returns:
            True if successful
        """
        return self.terminate_instances([instance_id], region=region)

    def get_instance_status(self, instance_id: str) -> str:
        """
        Get instance status via DescribeInstances API.

        Args:
            instance_id: Instance ID to query

        Returns:
            Instance status (running, stopped, terminated, etc.)
        """
        instances = self.describe_instances([instance_id])
        if not instances:
            return "not-found"
        return instances[0]["status"]

    def wait_for_instance_running(
        self,
        instance_id: str,
        max_attempts: int = 60,
        interval: int = 5,
        eventual_consistency_grace: int = 6,
        region: Optional[str] = None,
    ) -> Dict:
        """
        Poll instance status until 'running' state and public IP assigned.

        Args:
            instance_id: Instance ID to poll
            max_attempts: Maximum polling attempts (default: 60)
            interval: Seconds between attempts (default: 5)
            eventual_consistency_grace: Number of initial attempts to tolerate
                "not found" errors due to AWS eventual consistency (default: 6,
                which gives ~30 seconds grace period)
            region: AWS region where instance was launched (default: use default region)

        Returns:
            Instance details dict with status='running' and public_ip

        Raises:
            TimeoutError: If instance doesn't reach running state within max_attempts
            Exception: If instance not found after eventual consistency grace period
        """
        import time

        # Use provided region or default region
        target_region = region or self._default_region

        for attempt in range(1, max_attempts + 1):
            instances = self.describe_instances_in_region([instance_id], target_region)

            if not instances:
                # Handle AWS eventual consistency - newly created instances may not
                # be immediately visible to DescribeInstances API
                if attempt <= eventual_consistency_grace:
                    logger.debug(
                        f"Poll {attempt}/{max_attempts}: {instance_id} not yet visible "
                        f"(eventual consistency grace {attempt}/{eventual_consistency_grace})"
                    )
                    time.sleep(interval)
                    continue
                raise Exception(
                    f"Instance {instance_id} not found after {eventual_consistency_grace} "
                    f"attempts ({eventual_consistency_grace * interval}s grace period)"
                )

            instance = instances[0]
            status = instance["status"]
            public_ip = instance["public_ip"]

            logger.debug(
                f"Poll {attempt}/{max_attempts}: {instance_id} "
                f"status={status}, public_ip={public_ip}"
            )

            if status == "running" and public_ip:
                logger.info(f"Instance {instance_id} ready: {public_ip}")
                return instance

            if status in ["terminated", "terminating", "stopped", "stopping"]:
                raise Exception(f"Instance {instance_id} entered terminal state: {status}")

            time.sleep(interval)

        raise TimeoutError(
            f"Instance {instance_id} did not reach 'running' state with public IP after "
            f"{max_attempts * interval} seconds"
        )

    # VPC Management Methods

    def create_vpc(
        self,
        cidr_block: str = "10.0.0.0/16",
        name: str = "tensorprox-vpc",
        region: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Create VPC via CreateVpc REST API.

        Args:
            cidr_block: CIDR block for VPC (default: 10.0.0.0/16)
            name: Name tag for VPC (default: tensorprox-vpc)
            region: AWS region (default: use default region)

        Returns:
            {
                'vpc_id': str,
                'cidr_block': str,
                'state': str
            }
        """
        params = {
            "Action": "CreateVpc",
            "Version": "2016-11-15",
            "CidrBlock": cidr_block,
            "TagSpecification.1.ResourceType": "vpc",
            "TagSpecification.1.Tag.1.Key": "Name",
            "TagSpecification.1.Tag.1.Value": name,
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"CreateVpc failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        vpc = root.find(".//aws:vpc", ns)
        if vpc is None:
            raise Exception("No VPC in CreateVpc response")

        vpc_id_elem = vpc.find("aws:vpcId", ns)
        cidr_elem = vpc.find("aws:cidrBlock", ns)
        state_elem = vpc.find("aws:state", ns)

        vpc_id = vpc_id_elem.text if vpc_id_elem is not None else ""
        cidr = cidr_elem.text if cidr_elem is not None else cidr_block
        state = state_elem.text if state_elem is not None else "unknown"

        if not vpc_id:
            raise Exception("VPC ID not found in response")

        return {"vpc_id": vpc_id, "cidr_block": cidr, "state": state}

    def describe_vpcs_in_region(
        self,
        region: str,
        vpc_ids: Optional[List[str]] = None,
        filters: Optional[Dict[str, str]] = None,
    ) -> List[Dict]:
        """
        Query VPC details in specific region via DescribeVpcs API.

        Args:
            region: AWS region to query
            vpc_ids: Filter by VPC IDs
            filters: Additional filters (e.g., {'tag:Name': 'tensorprox-vpc'})

        Returns:
            List of VPC details
        """
        params = {"Action": "DescribeVpcs", "Version": "2016-11-15"}

        if vpc_ids:
            for idx, vpc_id in enumerate(vpc_ids, start=1):
                params[f"VpcId.{idx}"] = vpc_id

        if filters:
            for idx, (name, value) in enumerate(filters.items(), start=1):
                params[f"Filter.{idx}.Name"] = name
                params[f"Filter.{idx}.Value.1"] = value

        response = self._make_signed_request(params, region, method="GET")

        if response.status_code != 200:
            raise Exception(f"DescribeVpcs failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        vpcs = []
        for item in root.findall(".//aws:vpcSet/aws:item", ns):
            vpc_id_elem = item.find("aws:vpcId", ns)
            cidr_elem = item.find("aws:cidrBlock", ns)
            state_elem = item.find("aws:state", ns)

            # Extract Name tag
            name = ""
            for tag in item.findall(".//aws:tagSet/aws:item", ns):
                key_elem = tag.find("aws:key", ns)
                value_elem = tag.find("aws:value", ns)
                if key_elem is not None and key_elem.text == "Name":
                    name = value_elem.text if value_elem is not None else ""
                    break

            vpcs.append(
                {
                    "vpc_id": vpc_id_elem.text if vpc_id_elem is not None else "",
                    "cidr_block": cidr_elem.text if cidr_elem is not None else "",
                    "state": state_elem.text if state_elem is not None else "unknown",
                    "name": name,
                }
            )

        return vpcs

    def describe_vpcs(
        self, vpc_ids: Optional[List[str]] = None, filters: Optional[Dict[str, str]] = None
    ) -> List[Dict]:
        """
        Query VPC details via DescribeVpcs API (uses default region).

        Args:
            vpc_ids: Filter by VPC IDs
            filters: Additional filters (e.g., {'tag:Name': 'tensorprox-vpc'})

        Returns:
            List of VPC details
        """
        params = {"Action": "DescribeVpcs", "Version": "2016-11-15"}

        if vpc_ids:
            for idx, vpc_id in enumerate(vpc_ids, start=1):
                params[f"VpcId.{idx}"] = vpc_id

        if filters:
            for idx, (name, value) in enumerate(filters.items(), start=1):
                params[f"Filter.{idx}.Name"] = name
                params[f"Filter.{idx}.Value.1"] = value

        response = self._make_signed_request(params, self._default_region, method="GET")

        if response.status_code != 200:
            raise Exception(f"DescribeVpcs failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        vpcs = []
        for item in root.findall(".//aws:vpcSet/aws:item", ns):
            vpc_id_elem = item.find("aws:vpcId", ns)
            cidr_elem = item.find("aws:cidrBlock", ns)
            state_elem = item.find("aws:state", ns)

            # Extract Name tag
            name = ""
            for tag in item.findall(".//aws:tagSet/aws:item", ns):
                key_elem = tag.find("aws:key", ns)
                value_elem = tag.find("aws:value", ns)
                if key_elem is not None and key_elem.text == "Name":
                    name = value_elem.text if value_elem is not None else ""
                    break

            vpcs.append(
                {
                    "vpc_id": vpc_id_elem.text if vpc_id_elem is not None else "",
                    "cidr_block": cidr_elem.text if cidr_elem is not None else "",
                    "state": state_elem.text if state_elem is not None else "unknown",
                    "name": name,
                }
            )

        return vpcs

    def create_subnet(
        self,
        vpc_id: str,
        cidr_block: str = "10.0.1.0/24",
        availability_zone: Optional[str] = None,
        name: str = "tensorprox-subnet",
        region: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Create subnet via CreateSubnet REST API.

        Args:
            vpc_id: VPC ID to create subnet in
            cidr_block: CIDR block for subnet (default: 10.0.1.0/24)
            availability_zone: AZ for subnet (default: let AWS choose)
            name: Name tag for subnet (default: tensorprox-subnet)
            region: AWS region (default: use provider's default region)

        Returns:
            {
                'subnet_id': str,
                'vpc_id': str,
                'cidr_block': str,
                'availability_zone': str,
                'state': str
            }
        """
        params = {
            "Action": "CreateSubnet",
            "Version": "2016-11-15",
            "VpcId": vpc_id,
            "CidrBlock": cidr_block,
            "TagSpecification.1.ResourceType": "subnet",
            "TagSpecification.1.Tag.1.Key": "Name",
            "TagSpecification.1.Tag.1.Value": name,
        }

        if availability_zone:
            params["AvailabilityZone"] = availability_zone

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"CreateSubnet failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        subnet = root.find(".//aws:subnet", ns)
        if subnet is None:
            raise Exception("No subnet in CreateSubnet response")

        subnet_id_elem = subnet.find("aws:subnetId", ns)
        vpc_id_elem = subnet.find("aws:vpcId", ns)
        cidr_elem = subnet.find("aws:cidrBlock", ns)
        az_elem = subnet.find("aws:availabilityZone", ns)
        state_elem = subnet.find("aws:state", ns)

        subnet_id = subnet_id_elem.text if subnet_id_elem is not None else ""
        returned_vpc_id = vpc_id_elem.text if vpc_id_elem is not None else vpc_id
        cidr = cidr_elem.text if cidr_elem is not None else cidr_block
        az = az_elem.text if az_elem is not None else ""
        state = state_elem.text if state_elem is not None else "unknown"

        if not subnet_id:
            raise Exception("Subnet ID not found in response")

        return {
            "subnet_id": subnet_id,
            "vpc_id": returned_vpc_id,
            "cidr_block": cidr,
            "availability_zone": az,
            "state": state,
        }

    def describe_subnets(
        self,
        subnet_ids: Optional[List[str]] = None,
        filters: Optional[Dict[str, str]] = None,
        region: Optional[str] = None,
    ) -> List[Dict]:
        """
        Query subnet details via DescribeSubnets API.

        Args:
            subnet_ids: Filter by subnet IDs
            filters: Additional filters (e.g., {'vpc-id': 'vpc-xxx'})
            region: AWS region (default: use provider's default region)

        Returns:
            List of subnet details
        """
        params = {"Action": "DescribeSubnets", "Version": "2016-11-15"}

        if subnet_ids:
            for idx, subnet_id in enumerate(subnet_ids, start=1):
                params[f"SubnetId.{idx}"] = subnet_id

        if filters:
            for idx, (name, value) in enumerate(filters.items(), start=1):
                params[f"Filter.{idx}.Name"] = name
                params[f"Filter.{idx}.Value.1"] = value

        response = self._make_signed_request(params, region or self._default_region, method="GET")

        if response.status_code != 200:
            raise Exception(f"DescribeSubnets failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        subnets = []
        for item in root.findall(".//aws:subnetSet/aws:item", ns):
            subnet_id_elem = item.find("aws:subnetId", ns)
            vpc_id_elem = item.find("aws:vpcId", ns)
            cidr_elem = item.find("aws:cidrBlock", ns)
            az_elem = item.find("aws:availabilityZone", ns)
            state_elem = item.find("aws:state", ns)

            # Extract Name tag
            name = ""
            for tag in item.findall(".//aws:tagSet/aws:item", ns):
                key_elem = tag.find("aws:key", ns)
                value_elem = tag.find("aws:value", ns)
                if key_elem is not None and key_elem.text == "Name":
                    name = value_elem.text if value_elem is not None else ""
                    break

            subnets.append(
                {
                    "subnet_id": subnet_id_elem.text if subnet_id_elem is not None else "",
                    "vpc_id": vpc_id_elem.text if vpc_id_elem is not None else "",
                    "cidr_block": cidr_elem.text if cidr_elem is not None else "",
                    "availability_zone": az_elem.text if az_elem is not None else "",
                    "state": state_elem.text if state_elem is not None else "unknown",
                    "name": name,
                }
            )

        return subnets

    def create_security_group(
        self,
        vpc_id: str,
        group_name: str = "tensorprox-scrubbers",
        description: str = "TensorProx scrubbers security group",
        region: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Create security group via CreateSecurityGroup REST API.

        Args:
            vpc_id: VPC ID to create security group in
            group_name: Security group name (default: tensorprox-scrubbers)
            description: Security group description
            region: AWS region (default: use default region)

        Returns:
            {
                'group_id': str,
                'group_name': str
            }
        """
        params = {
            "Action": "CreateSecurityGroup",
            "Version": "2016-11-15",
            "VpcId": vpc_id,
            "GroupName": group_name,
            "GroupDescription": description,
            "TagSpecification.1.ResourceType": "security-group",
            "TagSpecification.1.Tag.1.Key": "Name",
            "TagSpecification.1.Tag.1.Value": group_name,
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"CreateSecurityGroup failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        group_id_elem = root.find(".//aws:groupId", ns)
        group_id = group_id_elem.text if group_id_elem is not None else ""

        if not group_id:
            raise Exception("Security group ID not found in response")

        return {"group_id": group_id, "group_name": group_name}

    def describe_security_groups(
        self,
        group_ids: Optional[List[str]] = None,
        group_names: Optional[List[str]] = None,
        filters: Optional[Dict[str, str]] = None,
        region: Optional[str] = None,
    ) -> List[Dict]:
        """
        Query security group details via DescribeSecurityGroups API.

        Args:
            group_ids: Filter by security group IDs
            group_names: Filter by security group names
            filters: Additional filters (e.g., {'vpc-id': 'vpc-xxx'})
            region: AWS region (default: use default region)

        Returns:
            List of security group details
        """
        params = {"Action": "DescribeSecurityGroups", "Version": "2016-11-15"}

        if group_ids:
            for idx, group_id in enumerate(group_ids, start=1):
                params[f"GroupId.{idx}"] = group_id

        if group_names:
            for idx, group_name in enumerate(group_names, start=1):
                params[f"GroupName.{idx}"] = group_name

        if filters:
            for idx, (name, value) in enumerate(filters.items(), start=1):
                params[f"Filter.{idx}.Name"] = name
                params[f"Filter.{idx}.Value.1"] = value

        response = self._make_signed_request(params, region or self._default_region, method="GET")

        if response.status_code != 200:
            raise Exception(
                f"DescribeSecurityGroups failed: {response.status_code} {response.text}"
            )

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        groups = []
        for item in root.findall(".//aws:securityGroupInfo/aws:item", ns):
            group_id_elem = item.find("aws:groupId", ns)
            group_name_elem = item.find("aws:groupName", ns)
            vpc_id_elem = item.find("aws:vpcId", ns)
            description_elem = item.find("aws:groupDescription", ns)

            groups.append(
                {
                    "group_id": group_id_elem.text if group_id_elem is not None else "",
                    "group_name": group_name_elem.text if group_name_elem is not None else "",
                    "vpc_id": vpc_id_elem.text if vpc_id_elem is not None else "",
                    "description": description_elem.text if description_elem is not None else "",
                }
            )

        return groups

    def authorize_security_group_ingress(
        self,
        group_id: str,
        ip_permissions: List[Dict],
        region: Optional[str] = None,
    ) -> bool:
        """
        Add ingress rules to security group via AuthorizeSecurityGroupIngress API.

        Args:
            group_id: Security group ID
            ip_permissions: List of permission dictionaries with keys:
                - protocol: 'tcp', 'udp', 'icmp', or '-1' for all
                - from_port: Starting port number (optional for protocol '-1')
                - to_port: Ending port number (optional for protocol '-1')
                - cidr: CIDR block to allow (e.g., '0.0.0.0/0')
            region: AWS region (default: use default region)

        Example:
            ip_permissions = [
                {'protocol': 'tcp', 'from_port': 22, 'to_port': 22, 'cidr': '0.0.0.0/0'},
                {'protocol': 'tcp', 'from_port': 80, 'to_port': 80, 'cidr': '0.0.0.0/0'},
                {'protocol': '-1', 'cidr': '10.0.0.0/16'}  # All traffic from VPC
            ]

        Returns:
            True if successful
        """
        params = {
            "Action": "AuthorizeSecurityGroupIngress",
            "Version": "2016-11-15",
            "GroupId": group_id,
        }

        # Add IP permissions
        for idx, perm in enumerate(ip_permissions, start=1):
            protocol = perm.get("protocol", "tcp")
            from_port = perm.get("from_port")
            to_port = perm.get("to_port")
            cidr = perm.get("cidr", "0.0.0.0/0")

            params[f"IpPermissions.{idx}.IpProtocol"] = protocol

            # Only add ports if not protocol -1 (all traffic)
            if protocol != "-1" and from_port is not None and to_port is not None:
                params[f"IpPermissions.{idx}.FromPort"] = str(from_port)
                params[f"IpPermissions.{idx}.ToPort"] = str(to_port)

            params[f"IpPermissions.{idx}.IpRanges.1.CidrIp"] = cidr

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(
                f"AuthorizeSecurityGroupIngress failed: {response.status_code} {response.text}"
            )

        self._parse_xml_response(response.text)  # Check for errors
        return True

    def revoke_security_group_ingress(
        self,
        group_id: str,
        ip_permissions: List[Dict],
        region: Optional[str] = None,
    ) -> bool:
        """
        Remove ingress rules from security group via RevokeSecurityGroupIngress API.

        Args:
            group_id: Security group ID
            ip_permissions: List of permission dictionaries with keys:
                - protocol: 'tcp', 'udp', 'icmp', or '-1' for all
                - from_port: Starting port number (optional for protocol '-1')
                - to_port: Ending port number (optional for protocol '-1')
                - cidr: CIDR block (e.g., '0.0.0.0/0')
            region: AWS region (default: use default region)

        Example:
            ip_permissions = [
                {'protocol': 'tcp', 'from_port': 7001, 'to_port': 7001, 'cidr': '0.0.0.0/0'},
                {'protocol': 'udp', 'from_port': 7111, 'to_port': 7111, 'cidr': '0.0.0.0/0'}
            ]

        Returns:
            True if successful, False if rule doesn't exist (idempotent)
        """
        params = {
            "Action": "RevokeSecurityGroupIngress",
            "Version": "2016-11-15",
            "GroupId": group_id,
        }

        # Add IP permissions (same format as authorize)
        for idx, perm in enumerate(ip_permissions, start=1):
            protocol = perm.get("protocol", "tcp")
            from_port = perm.get("from_port")
            to_port = perm.get("to_port")
            cidr = perm.get("cidr", "0.0.0.0/0")

            params[f"IpPermissions.{idx}.IpProtocol"] = protocol

            # Only add ports if not protocol -1 (all traffic)
            if protocol != "-1" and from_port is not None and to_port is not None:
                params[f"IpPermissions.{idx}.FromPort"] = str(from_port)
                params[f"IpPermissions.{idx}.ToPort"] = str(to_port)

            params[f"IpPermissions.{idx}.IpRanges.1.CidrIp"] = cidr

        response = self._make_signed_request(params, region or self._default_region)

        # Handle "rule does not exist" as success (idempotent)
        if response.status_code == 400:
            if "does not exist" in response.text or "InvalidPermission.NotFound" in response.text:
                return True  # Already removed, idempotent

        if response.status_code != 200:
            raise Exception(
                f"RevokeSecurityGroupIngress failed: {response.status_code} {response.text}"
            )

        self._parse_xml_response(response.text)  # Check for errors
        return True

    def create_internet_gateway(
        self, name: str = "tensorprox-igw", region: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Create Internet Gateway via CreateInternetGateway REST API.

        Args:
            name: Name tag for IGW (default: tensorprox-igw)
            region: AWS region (default: use default region)

        Returns:
            {
                'internet_gateway_id': str,
                'state': str
            }
        """
        params = {
            "Action": "CreateInternetGateway",
            "Version": "2016-11-15",
            "TagSpecification.1.ResourceType": "internet-gateway",
            "TagSpecification.1.Tag.1.Key": "Name",
            "TagSpecification.1.Tag.1.Value": name,
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"CreateInternetGateway failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        igw = root.find(".//aws:internetGateway", ns)
        if igw is None:
            raise Exception("No IGW in CreateInternetGateway response")

        igw_id_elem = igw.find("aws:internetGatewayId", ns)
        state_elem = igw.find("aws:attachmentSet/aws:item/aws:state", ns)

        igw_id = igw_id_elem.text if igw_id_elem is not None else ""
        state = state_elem.text if state_elem is not None else "detached"

        if not igw_id:
            raise Exception("IGW ID not found in response")

        return {"internet_gateway_id": igw_id, "state": state}

    def attach_internet_gateway(
        self, igw_id: str, vpc_id: str, region: Optional[str] = None
    ) -> bool:
        """
        Attach Internet Gateway to VPC via AttachInternetGateway REST API.

        Args:
            igw_id: Internet Gateway ID
            vpc_id: VPC ID to attach to
            region: AWS region (default: use default region)

        Returns:
            True if successful
        """
        params = {
            "Action": "AttachInternetGateway",
            "Version": "2016-11-15",
            "InternetGatewayId": igw_id,
            "VpcId": vpc_id,
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"AttachInternetGateway failed: {response.status_code} {response.text}")

        self._parse_xml_response(response.text)  # Check for errors
        return True

    def describe_internet_gateways(
        self,
        igw_ids: Optional[List[str]] = None,
        filters: Optional[Dict[str, str]] = None,
        region: Optional[str] = None,
    ) -> List[Dict]:
        """
        Query Internet Gateway details via DescribeInternetGateways API.

        Args:
            igw_ids: Filter by IGW IDs
            filters: Additional filters (e.g., {'attachment.vpc-id': 'vpc-xxx'})
            region: AWS region (default: use default region)

        Returns:
            List of IGW details
        """
        params = {"Action": "DescribeInternetGateways", "Version": "2016-11-15"}

        if igw_ids:
            for idx, igw_id in enumerate(igw_ids, start=1):
                params[f"InternetGatewayId.{idx}"] = igw_id

        if filters:
            for idx, (name, value) in enumerate(filters.items(), start=1):
                params[f"Filter.{idx}.Name"] = name
                params[f"Filter.{idx}.Value.1"] = value

        response = self._make_signed_request(params, region or self._default_region, method="GET")

        if response.status_code != 200:
            raise Exception(
                f"DescribeInternetGateways failed: {response.status_code} {response.text}"
            )

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        gateways = []
        for item in root.findall(".//aws:internetGatewaySet/aws:item", ns):
            igw_id_elem = item.find("aws:internetGatewayId", ns)

            # Get attachment info
            attachment = item.find("aws:attachmentSet/aws:item", ns)
            vpc_id = ""
            state = "detached"
            if attachment is not None:
                vpc_id_elem = attachment.find("aws:vpcId", ns)
                state_elem = attachment.find("aws:state", ns)
                vpc_id = vpc_id_elem.text if vpc_id_elem is not None else ""
                state = state_elem.text if state_elem is not None else "detached"

            # Extract Name tag
            name = ""
            for tag in item.findall(".//aws:tagSet/aws:item", ns):
                key_elem = tag.find("aws:key", ns)
                value_elem = tag.find("aws:value", ns)
                if key_elem is not None and key_elem.text == "Name":
                    name = value_elem.text if value_elem is not None else ""
                    break

            gateways.append(
                {
                    "internet_gateway_id": igw_id_elem.text if igw_id_elem is not None else "",
                    "vpc_id": vpc_id,
                    "state": state,
                    "name": name,
                }
            )

        return gateways

    def create_route_table(
        self, vpc_id: str, name: str = "tensorprox-route-table", region: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Create route table via CreateRouteTable REST API.

        Args:
            vpc_id: VPC ID to create route table in
            name: Name tag for route table
            region: AWS region (default: use default region)

        Returns:
            {
                'route_table_id': str,
                'vpc_id': str
            }
        """
        params = {
            "Action": "CreateRouteTable",
            "Version": "2016-11-15",
            "VpcId": vpc_id,
            "TagSpecification.1.ResourceType": "route-table",
            "TagSpecification.1.Tag.1.Key": "Name",
            "TagSpecification.1.Tag.1.Value": name,
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"CreateRouteTable failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        route_table = root.find(".//aws:routeTable", ns)
        if route_table is None:
            raise Exception("No route table in CreateRouteTable response")

        rt_id_elem = route_table.find("aws:routeTableId", ns)
        vpc_id_elem = route_table.find("aws:vpcId", ns)

        rt_id = rt_id_elem.text if rt_id_elem is not None else ""
        returned_vpc_id = vpc_id_elem.text if vpc_id_elem is not None else vpc_id

        if not rt_id:
            raise Exception("Route table ID not found in response")

        return {"route_table_id": rt_id, "vpc_id": returned_vpc_id}

    def create_route(
        self, route_table_id: str, destination: str, gateway_id: str, region: Optional[str] = None
    ) -> bool:
        """
        Create route in route table via CreateRoute REST API.

        Args:
            route_table_id: Route table ID
            destination: Destination CIDR (e.g., '0.0.0.0/0' for internet)
            gateway_id: Target gateway ID (Internet Gateway ID)
            region: AWS region (default: use default region)

        Returns:
            True if successful
        """
        params = {
            "Action": "CreateRoute",
            "Version": "2016-11-15",
            "RouteTableId": route_table_id,
            "DestinationCidrBlock": destination,
            "GatewayId": gateway_id,
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"CreateRoute failed: {response.status_code} {response.text}")

        self._parse_xml_response(response.text)  # Check for errors
        return True

    def describe_route_tables(
        self,
        route_table_ids: Optional[List[str]] = None,
        filters: Optional[Dict[str, str]] = None,
        region: Optional[str] = None,
    ) -> List[Dict]:
        """
        Query route table details via DescribeRouteTables API.

        Args:
            route_table_ids: Filter by route table IDs
            filters: Additional filters (e.g., {'vpc-id': 'vpc-xxx'})
            region: AWS region (default: use default region)

        Returns:
            List of route table details
        """
        params = {"Action": "DescribeRouteTables", "Version": "2016-11-15"}

        if route_table_ids:
            for idx, rt_id in enumerate(route_table_ids, start=1):
                params[f"RouteTableId.{idx}"] = rt_id

        if filters:
            for idx, (name, value) in enumerate(filters.items(), start=1):
                params[f"Filter.{idx}.Name"] = name
                params[f"Filter.{idx}.Value.1"] = value

        response = self._make_signed_request(params, region or self._default_region, method="GET")

        if response.status_code != 200:
            raise Exception(f"DescribeRouteTables failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        route_tables = []
        for item in root.findall(".//aws:routeTableSet/aws:item", ns):
            rt_id_elem = item.find("aws:routeTableId", ns)
            vpc_id_elem = item.find("aws:vpcId", ns)

            # Extract Name tag
            name = ""
            for tag in item.findall(".//aws:tagSet/aws:item", ns):
                key_elem = tag.find("aws:key", ns)
                value_elem = tag.find("aws:value", ns)
                if key_elem is not None and key_elem.text == "Name":
                    name = value_elem.text if value_elem is not None else ""
                    break

            route_tables.append(
                {
                    "route_table_id": rt_id_elem.text if rt_id_elem is not None else "",
                    "vpc_id": vpc_id_elem.text if vpc_id_elem is not None else "",
                    "name": name,
                }
            )

        return route_tables

    def associate_route_table(
        self, route_table_id: str, subnet_id: str, region: Optional[str] = None
    ) -> str:
        """
        Associate route table with subnet via AssociateRouteTable REST API.

        Args:
            route_table_id: Route table ID
            subnet_id: Subnet ID to associate with
            region: AWS region (default: use default region)

        Returns:
            Association ID
        """
        params = {
            "Action": "AssociateRouteTable",
            "Version": "2016-11-15",
            "RouteTableId": route_table_id,
            "SubnetId": subnet_id,
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"AssociateRouteTable failed: {response.status_code} {response.text}")

        # Parse response
        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        assoc_id_elem = root.find(".//aws:associationId", ns)
        return assoc_id_elem.text if assoc_id_elem is not None else ""

    def modify_subnet_attribute(
        self, subnet_id: str, map_public_ip_on_launch: bool = True, region: Optional[str] = None
    ) -> bool:
        """
        Modify subnet attributes via ModifySubnetAttribute REST API.

        Args:
            subnet_id: Subnet ID
            map_public_ip_on_launch: Auto-assign public IP to instances
            region: AWS region (default: use default region)

        Returns:
            True if successful
        """
        params = {
            "Action": "ModifySubnetAttribute",
            "Version": "2016-11-15",
            "SubnetId": subnet_id,
            "MapPublicIpOnLaunch.Value": "true" if map_public_ip_on_launch else "false",
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"ModifySubnetAttribute failed: {response.status_code} {response.text}")

        self._parse_xml_response(response.text)  # Check for errors
        return True

    def get_or_create_scrubber_infrastructure(self, region: str) -> Dict[str, str]:
        """
        Get existing or create new VPC/subnet/SG/IGW infrastructure for scrubbers in specific region.

        This method:
        1. Searches for existing tensorprox-vpc
        2. If not found, creates VPC, subnet, and security group
        3. If found, searches for existing subnet and security group
        4. Creates Internet Gateway and attaches to VPC
        5. Creates route table with internet route (0.0.0.0/0 -> IGW)
        6. Associates route table with subnet
        7. Enables auto-assign public IP on subnet
        8. Creates missing components as needed

        Args:
            region: AWS region to create/query infrastructure in

        Returns:
            {
                'vpc_id': str,
                'subnet_id': str,
                'security_group_id': str,
                'internet_gateway_id': str,
                'route_table_id': str,
                'created': bool  # True if new infrastructure was created
            }
        """
        created = False

        # Check for existing VPC (in the specified region)
        vpcs = self.describe_vpcs_in_region(region, filters={"tag:Name": "tensorprox-vpc"})

        if vpcs:
            vpc_id = vpcs[0]["vpc_id"]
            logger.debug(f"Found existing VPC: {vpc_id}")
        else:
            logger.debug("Creating new VPC...")
            vpc_result = self.create_vpc(cidr_block="10.0.0.0/16", name="tensorprox-vpc", region=region)
            vpc_id = vpc_result["vpc_id"]
            logger.info(f"Created VPC: {vpc_id}")
            created = True

        igws = self.describe_internet_gateways(filters={"attachment.vpc-id": vpc_id}, region=region)

        if igws:
            igw_id = igws[0]["internet_gateway_id"]
            logger.debug(f"Found existing Internet Gateway: {igw_id}")
        else:
            logger.debug("Creating Internet Gateway...")
            igw_result = self.create_internet_gateway(name="tensorprox-igw", region=region)
            igw_id = igw_result["internet_gateway_id"]
            logger.info(f"Created Internet Gateway: {igw_id}")
            self.attach_internet_gateway(igw_id, vpc_id, region=region)
            logger.debug("Internet Gateway attached")
            created = True

        subnets = self.describe_subnets(filters={"vpc-id": vpc_id, "tag:Name": "tensorprox-subnet"}, region=region)

        if subnets:
            subnet_id = subnets[0]["subnet_id"]
            logger.debug(f"Found existing subnet: {subnet_id}")
        else:
            first_az = f"{region}a"
            logger.debug(f"Creating new subnet in {first_az}...")
            subnet_result = self.create_subnet(
                vpc_id=vpc_id,
                cidr_block="10.0.1.0/24",
                availability_zone=first_az,
                name="tensorprox-subnet",
                region=region
            )
            subnet_id = subnet_result["subnet_id"]
            logger.info(f"Created subnet: {subnet_id}")
            created = True

        route_tables = self.describe_route_tables(
            filters={"vpc-id": vpc_id, "tag:Name": "tensorprox-route-table"}, region=region
        )

        if route_tables:
            route_table_id = route_tables[0]["route_table_id"]
            logger.debug(f"Found existing route table: {route_table_id}")
        else:
            logger.debug("Creating route table...")
            rt_result = self.create_route_table(vpc_id=vpc_id, name="tensorprox-route-table", region=region)
            route_table_id = rt_result["route_table_id"]
            logger.info(f"Created route table: {route_table_id}")
            self.create_route(
                route_table_id=route_table_id, destination="0.0.0.0/0", gateway_id=igw_id, region=region
            )
            logger.debug("Internet route added")
            created = True

        try:
            assoc_tables = self.describe_route_tables(
                filters={"association.subnet-id": subnet_id}, region=region
            )
            if not assoc_tables or assoc_tables[0]["route_table_id"] != route_table_id:
                assoc_id = self.associate_route_table(route_table_id, subnet_id, region=region)
                logger.debug(f"Route table associated (association ID: {assoc_id})")
        except Exception as e:
            logger.warning(f"Route table association check/creation failed: {e}")

        try:
            self.modify_subnet_attribute(subnet_id, map_public_ip_on_launch=True, region=region)
        except Exception as exc:
            logger.warning(f"Could not enforce auto-assign public IP on subnet {subnet_id}: {exc}")

        security_groups = self.describe_security_groups(
            filters={"vpc-id": vpc_id, "group-name": "tensorprox-scrubbers"}, region=region
        )

        if security_groups:
            security_group_id = security_groups[0]["group_id"]
            logger.debug(f"Found existing security group: {security_group_id}")
        else:
            logger.debug("Creating new security group...")
            sg_result = self.create_security_group(
                vpc_id=vpc_id,
                group_name="tensorprox-scrubbers",
                description="TensorProx scrubbers security group",
                region=region
            )
            security_group_id = sg_result["group_id"]
            logger.info(f"Created security group: {security_group_id}")
            ip_permissions = [
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"},
                {"protocol": "udp", "from_port": 51820, "to_port": 51820, "cidr": "0.0.0.0/0"},
                {"protocol": "-1", "cidr": "10.0.0.0/16"},
                {"protocol": "-1", "cidr": "0.0.0.0/0"},
            ]
            self.authorize_security_group_ingress(security_group_id, ip_permissions, region=region)
            logger.debug("Security group rules added")
            created = True

        settings = get_settings()
        key_name = settings.aws_ssh_key_name

        try:
            existing_keys = self.describe_key_pairs(key_names=[key_name], region=region)
            if existing_keys:
                logger.debug(f"Found existing SSH key: {key_name}")
            else:
                raise Exception("Key not found")
        except Exception:
            logger.debug(f"Importing SSH key: {key_name}")
            ssh_key_path = settings.ssh_key_path
            public_key_path = f"{ssh_key_path}.pub"

            with open(public_key_path, "r") as f:
                public_key_material = f.read().strip()

            self.import_key_pair(key_name=key_name, public_key_material=public_key_material, region=region)
            logger.info(f"SSH key imported: {key_name}")
            created = True

        return {
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "security_group_id": security_group_id,
            "internet_gateway_id": igw_id,
            "route_table_id": route_table_id,
            "ssh_key_name": key_name,
            "created": created,
        }

    def describe_key_pairs(
        self, key_names: Optional[List[str]] = None, region: Optional[str] = None
    ) -> List[Dict]:
        """
        Query SSH key pairs via DescribeKeyPairs API.

        Args:
            key_names: List of key names to filter (optional)
            region: AWS region (default: use default region)

        Returns:
            List of key pair dictionaries
        """
        params = {"Action": "DescribeKeyPairs", "Version": "2016-11-15"}

        if key_names:
            for idx, key_name in enumerate(key_names, start=1):
                params[f"KeyName.{idx}"] = key_name

        response = self._make_signed_request(params, region or self._default_region, method="GET")

        if response.status_code != 200:
            return []  # Key doesn't exist

        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        keys = []
        for item in root.findall(".//aws:keySet/aws:item", ns):
            key_name_elem = item.find("aws:keyName", ns)
            keys.append({"key_name": key_name_elem.text if key_name_elem is not None else ""})

        return keys

    def import_key_pair(
        self, key_name: str, public_key_material: str, region: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Import SSH public key via ImportKeyPair REST API.

        Args:
            key_name: Name for the SSH key
            public_key_material: Public key content
            region: AWS region (default: use default region)

        Returns:
            Dictionary with key_name and fingerprint
        """
        import base64

        params = {
            "Action": "ImportKeyPair",
            "Version": "2016-11-15",
            "KeyName": key_name,
            "PublicKeyMaterial": base64.b64encode(public_key_material.encode()).decode(),
        }

        response = self._make_signed_request(params, region or self._default_region)

        if response.status_code != 200:
            raise Exception(f"ImportKeyPair failed: {response.status_code} {response.text}")

        root = self._parse_xml_response(response.text)
        ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

        key_name_elem = root.find(".//aws:keyName", ns)
        fingerprint_elem = root.find(".//aws:keyFingerprint", ns)

        return {
            "key_name": key_name_elem.text if key_name_elem is not None else key_name,
            "fingerprint": fingerprint_elem.text if fingerprint_elem is not None else "",
        }

    def describe_instance_types(
        self, instance_types: List[str], region: Optional[str] = None
    ) -> List[Dict]:
        """
        Query instance type details via DescribeInstanceTypes API.

        Args:
            instance_types: List of instance types to describe (e.g., ['t3.medium', 'c5.large'])
            region: AWS region (default: use default region)

        Returns:
            List of instance type details with at minimum:
            [
                {
                    'instance_type': str,
                    'ipv4_addresses_per_interface': int,
                    'max_network_interfaces': int
                },
                ...
            ]

        Note:
            This method handles pagination automatically using NextToken
            if AWS returns partial results.
        """
        all_instance_types = []
        next_token = None

        while True:
            params = {"Action": "DescribeInstanceTypes", "Version": "2016-11-15"}

            # Add instance type filters
            for idx, instance_type in enumerate(instance_types, start=1):
                params[f"InstanceType.{idx}"] = instance_type

            # Add pagination token if present
            if next_token:
                params["NextToken"] = next_token

            response = self._make_signed_request(params, region or self._default_region, method="GET")

            if response.status_code != 200:
                raise Exception(
                    f"DescribeInstanceTypes failed: {response.status_code} {response.text}"
                )

            # Parse response
            root = self._parse_xml_response(response.text)
            ns = {"aws": "http://ec2.amazonaws.com/doc/2016-11-15/"}

            # Extract instance type details
            for item in root.findall(".//aws:instanceTypeSet/aws:item", ns):
                instance_type_elem = item.find("aws:instanceType", ns)

                # Navigate to network info
                network_info = item.find("aws:networkInfo", ns)
                if network_info is None:
                    # Skip if no network info available
                    continue

                ipv4_per_interface_elem = network_info.find("aws:ipv4AddressesPerInterface", ns)
                max_enis_elem = network_info.find("aws:maximumNetworkInterfaces", ns)

                # Extract bandwidth from networkCards
                baseline_bandwidth_gbps = 0.0
                peak_bandwidth_gbps = 0.0
                network_cards = network_info.find("aws:networkCards", ns)
                if network_cards is not None:
                    card = network_cards.find("aws:item", ns)
                    if card is not None:
                        baseline_elem = card.find("aws:baselineBandwidthInGbps", ns)
                        peak_elem = card.find("aws:peakBandwidthInGbps", ns)
                        if baseline_elem is not None and baseline_elem.text:
                            baseline_bandwidth_gbps = float(baseline_elem.text)
                        if peak_elem is not None and peak_elem.text:
                            peak_bandwidth_gbps = float(peak_elem.text)

                if instance_type_elem is None or ipv4_per_interface_elem is None:
                    # Skip incomplete entries
                    continue

                instance_data = {
                    "instance_type": instance_type_elem.text,
                    "ipv4_addresses_per_interface": int(ipv4_per_interface_elem.text),
                    "max_network_interfaces": (
                        int(max_enis_elem.text)
                        if max_enis_elem is not None and max_enis_elem.text
                        else 0
                    ),
                    "baseline_bandwidth_gbps": baseline_bandwidth_gbps,
                    "peak_bandwidth_gbps": peak_bandwidth_gbps,
                    "baseline_bandwidth_bps": int(baseline_bandwidth_gbps * 1_000_000_000),
                }

                all_instance_types.append(instance_data)

            # Check for pagination token
            next_token_elem = root.find(".//aws:nextToken", ns)
            if next_token_elem is not None and next_token_elem.text:
                next_token = next_token_elem.text
                # Continue to next page
            else:
                # No more pages
                break

        return all_instance_types
