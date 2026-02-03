"""AWS Signature Version 4 authentication.

Extracted from aws_provider.py for reuse. Stateless - region per-call.
"""
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Dict
from urllib.parse import quote, urlencode
import xml.etree.ElementTree as ET

import requests

from shared.config import get_settings


class AWSAuth:
    """AWS Signature V4 authentication helper. Stateless and thread-safe."""

    def __init__(self):
        settings = get_settings()
        self.access_key = settings.aws_access_key_id
        self.secret_key = settings.aws_secret_access_key

        if not self.access_key or not self.secret_key:
            raise ValueError(
                "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY required"
            )

    def _sign(self, key: bytes, msg: str) -> bytes:
        """Generate HMAC-SHA256 signature."""
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def _get_signature_key(
        self,
        date_stamp: str,
        region: str,
        service: str
    ) -> bytes:
        """Derive signing key using AWS Signature Version 4 algorithm."""
        k_date = self._sign(
            ('AWS4' + self.secret_key).encode('utf-8'),
            date_stamp
        )
        k_region = self._sign(k_date, region)
        k_service = self._sign(k_region, service)
        return self._sign(k_service, 'aws4_request')

    def sign_request(
        self,
        params: Dict[str, str],
        region: str,
        service: str = 'ec2',
        method: str = 'POST',
    ) -> Dict[str, str]:
        """Sign AWS API request and return headers including Authorization.

        Args:
            params: API request parameters
            region: AWS region (e.g., 'us-east-1')
            service: AWS service (default: 'ec2')
            method: HTTP method (default: 'POST')

        Returns:
            Dictionary of headers including Authorization, x-amz-date, Host
        """
        host = f"{service}.{region}.amazonaws.com"
        t = datetime.now(timezone.utc)
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')

        # Build canonical request components
        canonical_uri = '/'

        # Sort parameters (required for consistent signature)
        sorted_params = sorted(params.items())

        # Build canonical query string
        if method == 'GET':
            canonical_querystring = '&'.join([
                f"{quote(k, safe='')}={quote(str(v), safe='')}"
                for k, v in sorted_params
            ])
        else:
            canonical_querystring = ''

        # Build canonical headers
        if method == 'POST':
            canonical_headers = (
                f'content-type:application/x-www-form-urlencoded; charset=utf-8\n'
                f'host:{host}\n'
                f'x-amz-date:{amz_date}\n'
            )
            signed_headers = 'content-type;host;x-amz-date'
        else:
            canonical_headers = f'host:{host}\nx-amz-date:{amz_date}\n'
            signed_headers = 'host;x-amz-date'

        # Create payload hash
        if method == 'POST':
            payload = urlencode(sorted_params)
        else:
            payload = ''
        payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()

        # Create canonical request
        canonical_request = '\n'.join([
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash
        ])

        # Create string to sign
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = '\n'.join([
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        ])

        # Calculate signature
        signing_key = self._get_signature_key(date_stamp, region, service)
        signature = hmac.new(
            signing_key,
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        # Build authorization header
        authorization_header = (
            f"{algorithm} "
            f"Credential={self.access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )

        headers = {
            'Authorization': authorization_header,
            'x-amz-date': amz_date,
            'Host': host
        }

        # Add Content-Type for POST requests
        if method == 'POST':
            headers['Content-Type'] = (
                'application/x-www-form-urlencoded; charset=utf-8'
            )

        return headers

    def make_request(
        self,
        params: Dict[str, str],
        region: str,
        service: str = 'ec2',
        method: str = 'POST',
    ) -> requests.Response:
        """Make signed request to AWS API.

        Args:
            params: API request parameters
            region: AWS region (e.g., 'us-east-1')
            service: AWS service (default: 'ec2')
            method: HTTP method (default: 'POST')

        Returns:
            Response object
        """
        endpoint = f"https://{service}.{region}.amazonaws.com"
        headers = self.sign_request(params, region, service, method)

        sorted_params = sorted(params.items())
        if method == 'GET':
            return requests.get(
                f"{endpoint}?{urlencode(sorted_params, quote_via=quote)}",
                headers=headers
            )
        else:
            return requests.post(
                endpoint,
                headers=headers,
                data=urlencode(sorted_params)
            )

    @staticmethod
    def parse_xml(response_text: str) -> ET.Element:
        """Parse XML response and return root element.

        Args:
            response_text: XML response text

        Returns:
            XML root element
        """
        return ET.fromstring(response_text)

    @staticmethod
    def get_xml_namespace() -> dict:
        """Get AWS EC2 XML namespace for XPath queries.

        Note:
            This namespace is specific to EC2 API responses. Other AWS services
            (S3, STS, etc.) use different namespaces and will require their own
            namespace definitions.

        Returns:
            Dictionary with 'aws' key mapping to EC2 XML namespace
        """
        return {'aws': 'http://ec2.amazonaws.com/doc/2016-11-15/'}
