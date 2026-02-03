"""
Multi-TPM Client for TPM-Lite Endpoint Communication.

Client for communicating with TPM-Lite endpoints running on validators.
Each TPM operates independently - this client helps route requests to
the appropriate TPM and provides resilience features:

1. Metagraph-based endpoint discovery
2. Per-endpoint circuit breakers
3. Deterministic secret derivation
4. Automatic failover on transient failures

Note: Each origin is exclusively owned by one TPM. The web app is
responsible for tracking which TPM owns which origin.

Usage:
    client = MultiTPMClient(metagraph=metagraph)
    client.discover_endpoints()
    result = client.report_scores(...)
"""

import asyncio
import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Set
from enum import Enum
import random

import requests

from loguru import logger


class EndpointState(Enum):
    """State of a TPM endpoint."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


@dataclass
class CircuitBreakerState:
    """Per-endpoint circuit breaker state."""
    state: str = "closed"  # closed, open, half_open
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    next_retry_time: float = 0.0


@dataclass
class TPMEndpoint:
    """Represents a single TPM-Lite endpoint on a validator."""

    # Endpoint identification
    validator_uid: int
    validator_hotkey: str
    api_url: str

    # State tracking
    state: EndpointState = EndpointState.UNKNOWN
    last_seen: float = 0.0
    last_success: float = 0.0
    latency_ms: float = 0.0

    # Circuit breaker
    circuit_breaker: CircuitBreakerState = field(default_factory=CircuitBreakerState)

    # Statistics
    total_requests: int = 0
    total_failures: int = 0


class MultiTPMClient:
    """
    Client for interacting with TPM-Lite endpoints.

    Provides resilience through:
    - Automatic endpoint discovery from metagraph
    - Per-endpoint circuit breakers
    - Automatic retry on transient failures

    Note: Each origin is exclusively owned by one TPM.
    This client helps communicate with the appropriate TPM.
    """

    # Default TPM port for validators
    DEFAULT_TPM_PORT = 5001

    # Circuit breaker configuration
    CIRCUIT_FAILURE_THRESHOLD = 3
    CIRCUIT_RESET_TIMEOUT = 60.0
    CIRCUIT_HALF_OPEN_REQUESTS = 2

    # Request configuration
    REQUEST_TIMEOUT = 30
    MAX_RETRIES = 2

    # Endpoint selection
    MIN_HEALTHY_ENDPOINTS = 2

    def __init__(
        self,
        metagraph: Any = None,
        fallback_url: Optional[str] = None,
        miner_hotkey: Optional[str] = None,
    ):
        """
        Initialize multi-TPM client.

        Args:
            metagraph: Bittensor metagraph for endpoint discovery
            fallback_url: Fallback TPM URL if no endpoints discovered
            miner_hotkey: Miner hotkey for deterministic secret derivation
        """
        self.metagraph = metagraph
        self.fallback_url = fallback_url
        self.miner_hotkey = miner_hotkey

        # Discovered endpoints: validator_uid -> TPMEndpoint
        self.endpoints: Dict[int, TPMEndpoint] = {}

        # Session for HTTP requests
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=0,
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        # Deterministic secret cache
        self._derived_secrets: Dict[int, str] = {}

        logger.info("MultiTPMClient initialized")

    def discover_endpoints(self) -> int:
        """
        Discover TPM-Lite endpoints from metagraph.

        Validators running TPM-Lite expose it on DEFAULT_TPM_PORT.
        We discover their IPs from the metagraph axon information.

        Returns:
            Number of endpoints discovered
        """
        if not self.metagraph:
            logger.warning("No metagraph available for endpoint discovery")
            return 0

        discovered = 0
        current_time = time.time()

        for uid in range(len(self.metagraph.hotkeys)):
            # Only consider validators (those with stake)
            stake = self.metagraph.S[uid].item() if hasattr(self.metagraph, 'S') else 0
            if stake <= 0:
                continue

            try:
                axon = self.metagraph.axons[uid]
                if not axon or not hasattr(axon, 'ip'):
                    continue

                # Construct TPM-Lite URL
                ip = axon.ip
                if not ip or ip == "0.0.0.0":
                    continue

                api_url = f"http://{ip}:{self.DEFAULT_TPM_PORT}"

                # Create or update endpoint
                if uid not in self.endpoints:
                    self.endpoints[uid] = TPMEndpoint(
                        validator_uid=uid,
                        validator_hotkey=self.metagraph.hotkeys[uid],
                        api_url=api_url,
                    )
                    discovered += 1
                else:
                    # Update URL if changed
                    self.endpoints[uid].api_url = api_url

            except Exception as e:
                logger.debug(f"Failed to discover endpoint for uid {uid}: {e}")

        logger.info(f"Discovered {discovered} new TPM-Lite endpoints (total: {len(self.endpoints)})")
        return discovered

    def get_healthy_endpoints(self) -> List[TPMEndpoint]:
        """Get list of healthy endpoints sorted by latency."""
        healthy = [
            ep for ep in self.endpoints.values()
            if ep.state == EndpointState.HEALTHY
            and self._circuit_breaker_allows(ep)
        ]

        # Sort by latency (fastest first)
        healthy.sort(key=lambda ep: ep.latency_ms)

        return healthy

    def select_endpoint(self, prefer_uid: Optional[int] = None) -> Optional[TPMEndpoint]:
        """
        Select the best available endpoint.

        Args:
            prefer_uid: Preferred validator UID (if available and healthy)

        Returns:
            Selected endpoint or None
        """
        healthy = self.get_healthy_endpoints()

        if not healthy:
            # Try degraded endpoints
            degraded = [
                ep for ep in self.endpoints.values()
                if ep.state == EndpointState.DEGRADED
                and self._circuit_breaker_allows(ep)
            ]
            if degraded:
                return degraded[0]

            # Fall back to unknown endpoints
            unknown = [
                ep for ep in self.endpoints.values()
                if ep.state == EndpointState.UNKNOWN
            ]
            if unknown:
                return random.choice(unknown)

            return None

        # Check preferred endpoint
        if prefer_uid and prefer_uid in self.endpoints:
            ep = self.endpoints[prefer_uid]
            if ep.state == EndpointState.HEALTHY and self._circuit_breaker_allows(ep):
                return ep

        # Return fastest healthy endpoint
        return healthy[0]

    def _circuit_breaker_allows(self, endpoint: TPMEndpoint) -> bool:
        """Check if circuit breaker allows request."""
        cb = endpoint.circuit_breaker
        current_time = time.time()

        if cb.state == "closed":
            return True

        if cb.state == "open":
            if current_time >= cb.next_retry_time:
                cb.state = "half_open"
                cb.success_count = 0
                return True
            return False

        # half_open - allow limited requests
        return True

    def _record_success(self, endpoint: TPMEndpoint, latency_ms: float):
        """Record successful request."""
        endpoint.last_success = time.time()
        endpoint.last_seen = time.time()
        endpoint.latency_ms = latency_ms
        endpoint.total_requests += 1

        cb = endpoint.circuit_breaker
        if cb.state == "half_open":
            cb.success_count += 1
            if cb.success_count >= self.CIRCUIT_HALF_OPEN_REQUESTS:
                cb.state = "closed"
                cb.failure_count = 0
                logger.info(f"Endpoint {endpoint.validator_uid} circuit breaker closed")
        elif cb.state == "closed":
            cb.failure_count = max(0, cb.failure_count - 1)

        # Update state
        if endpoint.state != EndpointState.HEALTHY:
            endpoint.state = EndpointState.HEALTHY
            logger.info(f"Endpoint {endpoint.validator_uid} now HEALTHY")

    def _record_failure(self, endpoint: TPMEndpoint):
        """Record failed request."""
        endpoint.total_failures += 1
        endpoint.total_requests += 1

        cb = endpoint.circuit_breaker
        cb.failure_count += 1
        cb.last_failure_time = time.time()

        if cb.state == "half_open":
            cb.state = "open"
            cb.next_retry_time = time.time() + self.CIRCUIT_RESET_TIMEOUT
            logger.warning(f"Endpoint {endpoint.validator_uid} circuit breaker OPEN (half-open failure)")
        elif cb.state == "closed":
            if cb.failure_count >= self.CIRCUIT_FAILURE_THRESHOLD:
                cb.state = "open"
                cb.next_retry_time = time.time() + self.CIRCUIT_RESET_TIMEOUT
                endpoint.state = EndpointState.OFFLINE
                logger.warning(f"Endpoint {endpoint.validator_uid} circuit breaker OPEN")
            else:
                endpoint.state = EndpointState.DEGRADED

    def derive_secret_for_validator(self, validator_uid: int) -> str:
        """
        Derive a deterministic secret for a validator.

        The secret is derived from the miner's hotkey and the validator UID,
        ensuring the same miner always presents the same secret to all validators.

        Args:
            validator_uid: Target validator UID

        Returns:
            Deterministic secret string
        """
        if validator_uid in self._derived_secrets:
            return self._derived_secrets[validator_uid]

        if not self.miner_hotkey:
            raise ValueError("Miner hotkey required for secret derivation")

        # Derive secret: HMAC-SHA256(miner_hotkey, "tpm-auth:{validator_uid}")
        message = f"tpm-auth:{validator_uid}".encode()
        secret = hmac.new(
            self.miner_hotkey.encode(),
            message,
            hashlib.sha256
        ).hexdigest()

        self._derived_secrets[validator_uid] = secret
        return secret

    async def health_check_all(self) -> Dict[int, bool]:
        """
        Health check all endpoints.

        Returns:
            Dict mapping validator_uid to health status
        """
        results = {}

        for uid, endpoint in self.endpoints.items():
            try:
                start_time = time.time()
                response = self.session.get(
                    f"{endpoint.api_url}/health",
                    timeout=5
                )
                latency_ms = (time.time() - start_time) * 1000

                if response.status_code == 200:
                    self._record_success(endpoint, latency_ms)
                    results[uid] = True
                else:
                    self._record_failure(endpoint)
                    results[uid] = False

            except Exception:
                self._record_failure(endpoint)
                results[uid] = False

        healthy_count = sum(results.values())
        logger.info(f"Health check: {healthy_count}/{len(results)} endpoints healthy")

        return results

    def _make_request(
        self,
        method: str,
        endpoint_path: str,
        json: Optional[Dict] = None,
        params: Optional[Dict] = None,
        endpoint: Optional[TPMEndpoint] = None,
    ) -> Optional[requests.Response]:
        """
        Make a request to a TPM endpoint with failover.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint_path: API path (e.g., /api/v1/miners/register)
            json: JSON body
            params: Query parameters
            endpoint: Specific endpoint to use (or auto-select)

        Returns:
            Response or None on failure
        """
        # Select endpoint if not specified
        if endpoint is None:
            endpoint = self.select_endpoint()

        if endpoint is None:
            # Try fallback URL
            if self.fallback_url:
                try:
                    url = f"{self.fallback_url}{endpoint_path}"
                    response = self.session.request(
                        method,
                        url,
                        json=json,
                        params=params,
                        timeout=self.REQUEST_TIMEOUT
                    )
                    return response
                except Exception as e:
                    logger.error(f"Fallback request failed: {e}")
            return None

        # Try selected endpoint
        for attempt in range(self.MAX_RETRIES + 1):
            try:
                url = f"{endpoint.api_url}{endpoint_path}"
                start_time = time.time()

                response = self.session.request(
                    method,
                    url,
                    json=json,
                    params=params,
                    timeout=self.REQUEST_TIMEOUT
                )

                latency_ms = (time.time() - start_time) * 1000

                if response.status_code < 500:
                    self._record_success(endpoint, latency_ms)
                    return response
                else:
                    self._record_failure(endpoint)

            except requests.Timeout:
                logger.warning(f"Request to {endpoint.validator_uid} timed out (attempt {attempt + 1})")
                self._record_failure(endpoint)
            except requests.ConnectionError:
                logger.warning(f"Connection error to {endpoint.validator_uid} (attempt {attempt + 1})")
                self._record_failure(endpoint)
            except Exception as e:
                logger.error(f"Request error: {e}")
                self._record_failure(endpoint)

            # Try another endpoint on next attempt
            if attempt < self.MAX_RETRIES:
                endpoint = self.select_endpoint()
                if endpoint is None:
                    break

        return None

    # =========================================================================
    # High-Level API Methods
    # =========================================================================

    def report_scores(
        self,
        validator_uid: int,
        validator_hotkey: str,
        scores: Dict[int, float],
        **kwargs
    ) -> bool:
        """
        Report miner scores to TPM (broadcasts to all healthy endpoints).

        Args:
            validator_uid: Reporting validator's UID
            validator_hotkey: Reporting validator's hotkey
            scores: Dict mapping miner UID to score

        Returns:
            True if at least one endpoint accepted the scores
        """
        payload = {
            "validator_uid": validator_uid,
            "validator_hotkey": validator_hotkey,
            "scores": scores,
            "timestamp": time.time(),
            **kwargs
        }

        # Broadcast to all healthy endpoints for consensus
        healthy = self.get_healthy_endpoints()
        if not healthy:
            # Try any endpoint
            endpoint = self.select_endpoint()
            if endpoint:
                healthy = [endpoint]

        success = False
        for endpoint in healthy:
            response = self._make_request(
                "POST",
                f"/api/v1/validators/{validator_uid}/scores",
                json=payload,
                endpoint=endpoint
            )
            if response and response.status_code == 200:
                success = True

        return success

    def get_miner_assignments(self, miner_uid: Optional[int] = None) -> List[Dict]:
        """
        Get origin assignments for miners.

        Queries all healthy endpoints and merges results.

        Args:
            miner_uid: Specific miner UID (or all if None)

        Returns:
            List of assignment dicts
        """
        if miner_uid is not None:
            path = f"/api/v1/miners/{miner_uid}/assignments"
        else:
            path = "/api/v1/assignments"

        # Query from any healthy endpoint
        response = self._make_request("GET", path)
        if response and response.status_code == 200:
            data = response.json()
            return data.get("assignments", [])

        return []

    def request_assignment(
        self,
        origin_id: str,
        origin_ip: str,
        exit_hub_ip: str,
        tunnel_name: str,
        **kwargs
    ) -> Optional[Dict]:
        """
        Request miner assignment for a new origin.

        The target TPM will exclusively own this origin.

        Args:
            origin_id: Origin identifier
            origin_ip: Origin IP address
            exit_hub_ip: Exit hub IP
            tunnel_name: WireGuard tunnel name

        Returns:
            Assignment dict or None
        """
        payload = {
            "origin_id": origin_id,
            "origin_ip": origin_ip,
            "exit_hub_ip": exit_hub_ip,
            "tunnel_name": tunnel_name,
            **kwargs
        }

        response = self._make_request(
            "POST",
            "/api/v1/origins/request-assignment",
            json=payload
        )

        if response and response.status_code == 200:
            data = response.json()
            return data.get("assignment")

        return None

    def sync_leaderboard(
        self,
        validator_uid: int,
        validator_hotkey: str,
        miners: List[Dict],
    ) -> Dict:
        """
        Sync miner leaderboard data to TPM.

        Broadcasts to all healthy endpoints for consistency.

        Args:
            validator_uid: Validator's UID
            validator_hotkey: Validator's hotkey
            miners: List of miner data dicts

        Returns:
            Sync result dict
        """
        payload = {
            "validator_uid": validator_uid,
            "validator_hotkey": validator_hotkey,
            "miners": miners,
            "timestamp": time.time(),
        }

        # Broadcast to all healthy endpoints
        healthy = self.get_healthy_endpoints()
        results = {"miners_updated": 0, "endpoints_synced": 0}

        for endpoint in healthy:
            response = self._make_request(
                "POST",
                "/api/v1/miners/leaderboard/sync",
                json=payload,
                endpoint=endpoint
            )
            if response and response.status_code == 200:
                data = response.json()
                results["miners_updated"] = max(
                    results["miners_updated"],
                    data.get("miners_updated", 0)
                )
                results["endpoints_synced"] += 1

        return results

    def get_status(self) -> Dict[str, Any]:
        """Get client status for monitoring."""
        state_counts: Dict[str, int] = {}
        for endpoint in self.endpoints.values():
            state = endpoint.state.value
            state_counts[state] = state_counts.get(state, 0) + 1

        return {
            "total_endpoints": len(self.endpoints),
            "endpoint_states": state_counts,
            "healthy_endpoints": len(self.get_healthy_endpoints()),
            "fallback_available": self.fallback_url is not None,
        }


# Global client instance
_multi_tpm_client: Optional[MultiTPMClient] = None


def get_multi_tpm_client() -> Optional[MultiTPMClient]:
    """Get the global multi-TPM client instance."""
    return _multi_tpm_client


def init_multi_tpm_client(
    metagraph: Any = None,
    fallback_url: Optional[str] = None,
    miner_hotkey: Optional[str] = None,
) -> MultiTPMClient:
    """Initialize the global multi-TPM client."""
    global _multi_tpm_client

    _multi_tpm_client = MultiTPMClient(
        metagraph=metagraph,
        fallback_url=fallback_url,
        miner_hotkey=miner_hotkey,
    )

    return _multi_tpm_client
