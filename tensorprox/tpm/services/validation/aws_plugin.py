"""AWS Validation Plugin.

PURPOSE:
    This plugin implements AWS-specific validation workflows using the miner's
    own AWS credentials. Unlike shared/providers/aws_provider.py which uses
    TPM's credentials from settings, this plugin receives credentials per-call
    to validate miner-reported information against AWS APIs.

AUTHENTICATION:
    Uses AWS Signature Version 4 for REST API authentication. The signing
    algorithm is implemented inline (not using boto3) to maintain consistency
    with the existing AWS provider pattern and avoid SDK dependencies.

IMPLEMENTED WORKFLOWS:
    - discover_regions: Calls EC2 DescribeRegions API to list all regions
      available to the miner's AWS account. Used to determine where this
      miner can deploy scrubbers for client geographic matching.

FUTURE WORKFLOWS (examples):
    - verify_traffic_volume: Call CloudWatch or Cost Explorer to verify
      traffic metrics reported by miner for billing reconciliation
    - check_permissions: Verify IAM permissions for required EC2 operations
    - estimate_capacity: Query EC2 limits/quotas for capacity planning

CREDENTIAL FORMAT:
    Expects credentials dict with keys:
    - aws_access_key_id: AWS access key
    - aws_secret_access_key: AWS secret key
    - aws_region: Default region for API calls (used for signing)

API REFERENCE:
    - DescribeRegions: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html
    - Signature V4: https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
"""
from __future__ import annotations

import hashlib
import hmac
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import quote, urlencode

import requests

from shared.utils.logging import get_logger

from .base import (
    MinerValidationPlugin,
    ValidationPluginError,
    ValidationResult,
    ValidationStatus,
)

logger = get_logger(__name__)


class AWSValidationPlugin(MinerValidationPlugin):
    """AWS-specific validation using miner's credentials.

    Implements AWS Signature V4 signing for API calls without
    depending on shared provider settings.
    """

    SERVICE = "ec2"
    API_VERSION = "2016-11-15"

    @property
    def provider_name(self) -> str:
        return "aws"

    def discover_regions(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Call DescribeRegions API using miner's AWS credentials.

        Args:
            credentials: Dict with keys:
                - aws_access_key_id: str
                - aws_secret_access_key: str
                - aws_region: str (default region for signing)

        Returns:
            ValidationResult with list of region names on success
        """
        start_time = time.monotonic()

        access_key = credentials.get("aws_access_key_id")
        secret_key = credentials.get("aws_secret_access_key")
        region = credentials.get("aws_region", "us-east-1")

        if not access_key or not secret_key:
            return ValidationResult(
                workflow="discover_regions",
                status=ValidationStatus.FAILED,
                message="Missing required AWS credentials (access_key or secret_key)",
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

        try:
            regions = self._call_describe_regions(
                access_key=access_key,
                secret_key=secret_key,
                region=region,
            )

            duration_ms = int((time.monotonic() - start_time) * 1000)
            logger.info(
                "AWS region discovery succeeded: %d regions in %dms",
                len(regions),
                duration_ms,
            )

            return ValidationResult(
                workflow="discover_regions",
                status=ValidationStatus.SUCCESS,
                data=regions,
                message=f"Discovered {len(regions)} AWS regions",
                duration_ms=duration_ms,
            )

        except ValidationPluginError as exc:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            logger.warning("AWS region discovery failed: %s", exc)
            return ValidationResult(
                workflow="discover_regions",
                status=ValidationStatus.FAILED,
                message=str(exc),
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            logger.warning("AWS region discovery failed unexpectedly: %s", exc)
            return ValidationResult(
                workflow="discover_regions",
                status=ValidationStatus.FAILED,
                message=f"Unexpected error: {exc}",
                duration_ms=duration_ms,
            )

    def _call_describe_regions(
        self,
        access_key: str,
        secret_key: str,
        region: str,
    ) -> List[str]:
        """Execute DescribeRegions API call with Signature V4."""
        host = f"ec2.{region}.amazonaws.com"
        endpoint = f"https://{host}"

        params = {
            "Action": "DescribeRegions",
            "Version": self.API_VERSION,
        }

        headers = self._sign_request(
            params=params,
            access_key=access_key,
            secret_key=secret_key,
            region=region,
            host=host,
            method="GET",
        )

        response = requests.get(
            endpoint,
            params=params,
            headers=headers,
            timeout=30,
        )

        if response.status_code != 200:
            raise ValidationPluginError(
                message=f"DescribeRegions failed: {response.status_code} {response.text[:500]}",
                provider="aws",
                workflow="discover_regions",
            )

        return self._parse_regions_response(response.text)

    def _sign_request(
        self,
        params: Dict[str, str],
        access_key: str,
        secret_key: str,
        region: str,
        host: str,
        method: str = "GET",
    ) -> Dict[str, str]:
        """Generate AWS Signature V4 headers.

        Implements signing algorithm as per:
        https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
        """
        t = datetime.utcnow()
        amz_date = t.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = t.strftime("%Y%m%d")

        sorted_params = sorted(params.items())

        if method == "GET":
            canonical_querystring = "&".join(
                [f"{quote(k, safe='')}={quote(str(v), safe='')}" for k, v in sorted_params]
            )
            payload = ""
            canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
            signed_headers = "host;x-amz-date"
        else:
            canonical_querystring = ""
            payload = urlencode(sorted_params)
            canonical_headers = (
                f"content-type:application/x-www-form-urlencoded; charset=utf-8\n"
                f"host:{host}\n"
                f"x-amz-date:{amz_date}\n"
            )
            signed_headers = "content-type;host;x-amz-date"

        payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        canonical_request = "\n".join([
            method,
            "/",
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash,
        ])

        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{date_stamp}/{region}/{self.SERVICE}/aws4_request"
        string_to_sign = "\n".join([
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ])

        signing_key = self._get_signature_key(secret_key, date_stamp, region)
        signature = hmac.new(
            signing_key,
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        authorization = (
            f"{algorithm} "
            f"Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )

        headers = {
            "Host": host,
            "X-Amz-Date": amz_date,
            "Authorization": authorization,
        }

        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"

        return headers

    def _get_signature_key(
        self,
        secret_key: str,
        date_stamp: str,
        region: str,
    ) -> bytes:
        """Derive signing key per Signature V4 algorithm."""

        def sign(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        k_date = sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
        k_region = sign(k_date, region)
        k_service = sign(k_region, self.SERVICE)
        k_signing = sign(k_service, "aws4_request")
        return k_signing

    def _parse_regions_response(self, xml_text: str) -> List[str]:
        """Parse DescribeRegions XML response."""
        root = ET.fromstring(xml_text)
        ns = {"aws": f"http://ec2.amazonaws.com/doc/{self.API_VERSION}/"}

        regions = []
        for item in root.findall(".//aws:regionInfo/aws:item", ns):
            name_elem = item.find("aws:regionName", ns)
            if name_elem is not None and name_elem.text:
                regions.append(name_elem.text)

        return sorted(regions)


_aws_plugin: AWSValidationPlugin | None = None


def get_aws_plugin() -> AWSValidationPlugin:
    """Get singleton AWS validation plugin instance."""
    global _aws_plugin
    if _aws_plugin is None:
        _aws_plugin = AWSValidationPlugin()
    return _aws_plugin
