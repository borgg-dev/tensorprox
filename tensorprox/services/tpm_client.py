"""
TPM (TensorProx Manager) client for validator integration.

Provides interface for validators to query TPM for:
- Origin assignment information
- Exit hub access credentials
- Miner-to-origin mappings

SCALABILITY FEATURES:
- Retry logic with exponential backoff for transient failures
- Circuit breaker pattern to prevent cascading failures
- Partition detection for network issues
- Idempotent request support where applicable
"""

import requests
import time
import threading
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from functools import wraps
from enum import Enum

from loguru import logger


# === RETRY AND CIRCUIT BREAKER CONFIGURATION ===
MAX_RETRIES = 3                      # Maximum retry attempts
INITIAL_BACKOFF_SECONDS = 1.0        # Initial backoff delay
MAX_BACKOFF_SECONDS = 30.0           # Maximum backoff delay
BACKOFF_MULTIPLIER = 2.0             # Exponential backoff multiplier

# Circuit breaker settings
CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5    # Failures before opening circuit
CIRCUIT_BREAKER_RESET_TIMEOUT = 60       # Seconds before attempting to close circuit
CIRCUIT_BREAKER_HALF_OPEN_REQUESTS = 2   # Successful requests needed to close


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreaker:
    """
    Circuit breaker for protecting against cascading failures.

    When too many failures occur, the circuit opens and rejects requests
    immediately, giving the downstream service time to recover.
    """
    failure_threshold: int = CIRCUIT_BREAKER_FAILURE_THRESHOLD
    reset_timeout: float = CIRCUIT_BREAKER_RESET_TIMEOUT
    half_open_requests: int = CIRCUIT_BREAKER_HALF_OPEN_REQUESTS

    # State tracking
    state: CircuitState = field(default=CircuitState.CLOSED)
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        self._lock = threading.Lock()

    def can_execute(self) -> bool:
        """Check if request should be allowed through."""
        with self._lock:
            if self.state == CircuitState.CLOSED:
                return True

            if self.state == CircuitState.OPEN:
                # Check if enough time has passed to try again
                if time.time() - self.last_failure_time >= self.reset_timeout:
                    self.state = CircuitState.HALF_OPEN
                    self.success_count = 0
                    logger.debug("Circuit breaker entering HALF_OPEN state")
                    return True
                return False

            # HALF_OPEN - allow limited requests
            return True

    def record_success(self):
        """Record a successful request."""
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.half_open_requests:
                    self.state = CircuitState.CLOSED
                    self.failure_count = 0
                    logger.debug("Circuit breaker CLOSED (service recovered)")
            elif self.state == CircuitState.CLOSED:
                # Reset failure count on success
                self.failure_count = max(0, self.failure_count - 1)

    def record_failure(self):
        """Record a failed request."""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.state == CircuitState.HALF_OPEN:
                # Any failure in half-open returns to open
                self.state = CircuitState.OPEN
                logger.warning("Circuit breaker OPEN (failure during recovery)")
            elif self.state == CircuitState.CLOSED:
                if self.failure_count >= self.failure_threshold:
                    self.state = CircuitState.OPEN
                    logger.warning(
                        f"Circuit breaker OPEN after {self.failure_count} failures"
                    )

    def get_state(self) -> Dict[str, Any]:
        """Get circuit breaker state for monitoring."""
        with self._lock:
            return {
                "state": self.state.value,
                "failure_count": self.failure_count,
                "success_count": self.success_count,
                "last_failure_time": self.last_failure_time,
            }


def retry_with_backoff(
    max_retries: int = MAX_RETRIES,
    initial_backoff: float = INITIAL_BACKOFF_SECONDS,
    max_backoff: float = MAX_BACKOFF_SECONDS,
    backoff_multiplier: float = BACKOFF_MULTIPLIER,
    circuit_breaker: Optional[CircuitBreaker] = None,
):
    """
    Decorator for retry logic with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        initial_backoff: Initial delay between retries (seconds)
        max_backoff: Maximum delay between retries (seconds)
        backoff_multiplier: Multiplier for exponential backoff
        circuit_breaker: Optional circuit breaker instance
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check circuit breaker
            if circuit_breaker and not circuit_breaker.can_execute():
                logger.warning(f"Circuit breaker OPEN, skipping {func.__name__}")
                return None if func.__annotations__.get('return') != bool else False

            last_exception = None
            backoff = initial_backoff

            for attempt in range(max_retries + 1):
                try:
                    result = func(*args, **kwargs)
                    if circuit_breaker:
                        circuit_breaker.record_success()
                    return result

                except requests.exceptions.Timeout as e:
                    last_exception = e
                    # MULTI-MINER: Use debug for retries, only warn on final failure
                    logger.debug(f"{func.__name__} timeout ({attempt + 1}/{max_retries + 1})")
                except requests.exceptions.ConnectionError as e:
                    last_exception = e
                    logger.debug(f"{func.__name__} connection error ({attempt + 1}/{max_retries + 1})")
                except requests.exceptions.HTTPError as e:
                    # Don't retry 4xx errors (client errors)
                    if e.response is not None and 400 <= e.response.status_code < 500:
                        if circuit_breaker:
                            circuit_breaker.record_success()  # Server is responding
                        raise
                    last_exception = e
                    logger.debug(f"{func.__name__} HTTP {e.response.status_code if e.response else 'N/A'} ({attempt + 1}/{max_retries + 1})")
                except requests.RequestException as e:
                    last_exception = e
                    logger.debug(f"{func.__name__} request error ({attempt + 1}/{max_retries + 1})")

                # Record failure for circuit breaker
                if circuit_breaker:
                    circuit_breaker.record_failure()

                # Don't sleep after last attempt
                if attempt < max_retries:
                    sleep_time = min(backoff, max_backoff)
                    logger.trace(f"Retrying {func.__name__} in {sleep_time:.1f}s")
                    time.sleep(sleep_time)
                    backoff *= backoff_multiplier

            # All retries failed
            logger.error(
                f"{func.__name__} failed after {max_retries + 1} attempts: {last_exception}"
            )
            return None if func.__annotations__.get('return') != bool else False

        return wrapper
    return decorator


@dataclass
class OriginAssignment:
    """Represents an origin assigned to a miner."""

    origin_id: str
    origin_ip: str
    miner_uid: int
    exit_hub_ip: str
    exit_hub_tunnel_name: str
    assigned_at: float
    traffic_profile: Dict[str, Any]


@dataclass
class ExitHubAccess:
    """Exit hub access credentials for validator auditing."""

    exit_hub_ip: str
    ssh_host: str
    ssh_port: int
    ssh_user: str
    # SSH key should be pre-provisioned, not returned via API


@dataclass
class VerifiedVolume:
    """
    Volume for a miner (from TPM-managed exit hubs).

    Exit hubs are TPM-controlled infrastructure - this is ground truth
    for reward calculation and cannot be gamed by miners.
    """

    miner_uid: int
    total_verified_bytes: int
    origin_count: int
    origins: List[Dict[str, Any]]  # Per-origin breakdown


@dataclass
class ProductionMetrics:
    """
    Production XDP metrics from assigned scrubbers.

    These metrics come from real production traffic through xdp_wan.c
    (different from audit which uses xdp_wg_audit.c). This is ground truth
    for production performance that cannot be gamed.

    Key insight: Miners can optimize xdp_wg_audit.c for audits, but they
    MUST use xdp_wan.c in production. By scoring production metrics, we
    close the audit gap.
    """

    miner_uid: int
    timestamp: float

    # XDP drop stats (from production traffic)
    xdp_pass: int = 0
    xdp_drop_blacklist: int = 0
    xdp_drop_ratelimit: int = 0
    xdp_drop_temp_blacklist: int = 0
    xdp_drop_bogon: int = 0
    xdp_drop_invalid_ip: int = 0
    xdp_drop_invalid_tcp: int = 0

    # Connection metrics
    active_connections: int = 0
    syn_synack_ratio: float = 1.0  # Should be close to 1.0 for healthy traffic

    # SYN/SYN-ACK raw counts (for origin-down vs flood distinction)
    total_syn: int = 0
    total_synack: int = 0

    # Aggregate stats
    total_packets: int = 0
    total_bytes: int = 0

    # Origin-level breakdown
    origin_count: int = 0
    origins: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def total_drops(self) -> int:
        """Total packets dropped by XDP."""
        return (
            self.xdp_drop_blacklist +
            self.xdp_drop_ratelimit +
            self.xdp_drop_temp_blacklist +
            self.xdp_drop_bogon +
            self.xdp_drop_invalid_ip +
            self.xdp_drop_invalid_tcp
        )

    @property
    def drop_rate(self) -> float:
        """Fraction of packets dropped (0-1)."""
        total = self.xdp_pass + self.total_drops
        if total == 0:
            return 0.0
        return self.total_drops / total

    @property
    def is_healthy(self) -> bool:
        """
        Check if production metrics indicate healthy operation.

        Very lenient - only returns False for clear problems:
        - Extremely high SYN/SYN-ACK ratio (sustained SYN flood)

        Does NOT check traffic volume - small/quiet origins are fine.
        """
        # Only flag as unhealthy for severe SYN flood (ratio > 10)
        # Lower ratios might just be brief spikes during attacks
        if self.syn_synack_ratio > 10.0:
            return False

        return True


class TPMClient:
    """
    Client for interacting with TPM API.

    SCALABILITY FEATURES:
    - Retry logic with exponential backoff for transient failures
    - Circuit breaker to prevent cascading failures when TPM is down
    - Partition detection via health checks
    - Thread-safe for concurrent validator operations

    Validators use this to:
    1. Report miner scores for origin assignment decisions
    2. Query which miners are assigned to which origins
    3. Get exit hub access information for traffic inspection
    """

    def __init__(
        self,
        tpm_api_url: str,
        api_key: Optional[str] = None,
        timeout: int = 30,
        enable_circuit_breaker: bool = True,
    ):
        """
        Initialize TPM client.

        Args:
            tpm_api_url: Base URL for TPM API (e.g., https://tpm.tensorprox.com).
            api_key: Optional API key for authentication.
            timeout: Request timeout in seconds.
            enable_circuit_breaker: Whether to enable circuit breaker pattern.
        """
        self.api_url = tpm_api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()

        # Circuit breaker for resilience
        self.circuit_breaker = CircuitBreaker() if enable_circuit_breaker else None

        # Partition detection state
        self._last_successful_request = time.time()
        self._consecutive_failures = 0
        self._partition_detected = False
        self._partition_lock = threading.Lock()

        if api_key:
            self.session.headers.update({"X-API-Key": api_key})

        # Configure session for connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=0,  # We handle retries ourselves
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def _record_success(self):
        """Record successful request for partition detection."""
        with self._partition_lock:
            self._last_successful_request = time.time()
            self._consecutive_failures = 0
            if self._partition_detected:
                self._partition_detected = False
                logger.info("TPM connection restored after partition")

    def _record_failure(self):
        """Record failed request for partition detection."""
        with self._partition_lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= 5 and not self._partition_detected:
                self._partition_detected = True
                logger.warning(
                    f"Possible network partition detected: {self._consecutive_failures} "
                    f"consecutive TPM failures"
                )

    def is_partition_detected(self) -> bool:
        """Check if network partition to TPM is detected."""
        with self._partition_lock:
            return self._partition_detected

    def get_health_status(self) -> Dict[str, Any]:
        """Get TPM client health status for monitoring."""
        with self._partition_lock:
            status = {
                "last_successful_request": self._last_successful_request,
                "consecutive_failures": self._consecutive_failures,
                "partition_detected": self._partition_detected,
                "seconds_since_success": time.time() - self._last_successful_request,
            }
        if self.circuit_breaker:
            status["circuit_breaker"] = self.circuit_breaker.get_state()
        return status

    def report_scores(
        self,
        validator_uid: int,
        validator_hotkey: str,
        scores: Dict[int, float],
        score_components: Optional[Dict[int, Dict[str, float]]] = None,
        audit_type: str = "production",
        validator_version: Optional[str] = None,
        submission_nonce: Optional[str] = None,
    ) -> bool:
        """
        Report miner scores to TPM with retry logic and idempotency support.

        TPM uses these scores to make origin assignment decisions.
        This method implements retry with exponential backoff for resilience.

        IDEMPOTENCY: When submission_nonce is provided, TPM will deduplicate
        repeated submissions with the same nonce. This prevents double-counting
        scores when network issues cause retries.

        Args:
            validator_uid: This validator's UID.
            validator_hotkey: This validator's hotkey (SS58 address).
            scores: Dict mapping miner UID to score (0-1).
            score_components: Optional dict mapping miner UID to component breakdown.
            audit_type: Type of audit (default: "production").
            validator_version: Optional validator software version.
            submission_nonce: Optional unique nonce for idempotent submission.
                              If not provided, generates one from timestamp + uid.

        Returns:
            True if successful, False otherwise.
        """
        # Check circuit breaker
        if self.circuit_breaker and not self.circuit_breaker.can_execute():
            logger.warning("Circuit breaker OPEN, skipping report_scores")
            return False

        endpoint = f"{self.api_url}/api/v1/validators/{validator_uid}/scores"

        # Generate submission nonce for idempotency if not provided
        timestamp = self._get_timestamp()
        if not submission_nonce:
            submission_nonce = f"{validator_uid}-{int(timestamp * 1000)}"

        payload = {
            "validator_uid": validator_uid,
            "validator_hotkey": validator_hotkey,
            "scores": scores,
            "timestamp": timestamp,
            "submission_nonce": submission_nonce,
        }

        if score_components:
            payload["score_components"] = score_components
        if audit_type:
            payload["audit_type"] = audit_type
        if validator_version:
            payload["validator_version"] = validator_version

        # Retry with exponential backoff
        backoff = INITIAL_BACKOFF_SECONDS
        last_error = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.post(
                    endpoint,
                    json=payload,
                    timeout=self.timeout
                )
                response.raise_for_status()

                self._record_success()
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()

                logger.info(f"Reported {len(scores)} miner scores to TPM")
                return True

            except requests.exceptions.Timeout as e:
                last_error = e
                logger.warning(
                    f"report_scores timeout (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.exceptions.ConnectionError as e:
                last_error = e
                logger.warning(
                    f"report_scores connection error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.exceptions.HTTPError as e:
                # Don't retry 4xx errors
                if e.response is not None and 400 <= e.response.status_code < 500:
                    self._record_success()  # Server is up
                    logger.error(f"report_scores client error (no retry): {e}")
                    return False
                last_error = e
                logger.warning(
                    f"report_scores HTTP error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.RequestException as e:
                last_error = e
                logger.warning(
                    f"report_scores request error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )

            # Record failure
            self._record_failure()
            if self.circuit_breaker:
                self.circuit_breaker.record_failure()

            # Sleep before retry (except on last attempt)
            if attempt < MAX_RETRIES:
                sleep_time = min(backoff, MAX_BACKOFF_SECONDS)
                time.sleep(sleep_time)
                backoff *= BACKOFF_MULTIPLIER

        logger.error(f"Failed to report scores after {MAX_RETRIES + 1} attempts: {last_error}")
        return False

    def get_miner_assignments(
        self,
        miner_uid: Optional[int] = None
    ) -> List[OriginAssignment]:
        """
        Get origin assignments for miners.

        Args:
            miner_uid: Optional specific miner UID. If None, returns all assignments.

        Returns:
            List of OriginAssignment objects.
        """
        if miner_uid is not None:
            endpoint = f"{self.api_url}/api/v1/miners/{miner_uid}/assignments"
        else:
            endpoint = f"{self.api_url}/api/v1/assignments"

        try:
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            assignments = []

            for item in data.get("assignments", []):
                # Ensure miner_uid is int (API may return string)
                miner_uid = int(item["miner_uid"])
                assignment = OriginAssignment(
                    origin_id=item["origin_id"],
                    origin_ip=item["origin_ip"],
                    miner_uid=miner_uid,
                    exit_hub_ip=item["exit_hub_ip"],
                    exit_hub_tunnel_name=item.get("tunnel_name", f"wg-miner-{miner_uid}"),
                    assigned_at=item.get("assigned_at", 0.0),
                    traffic_profile=item.get("traffic_profile", {}),
                )
                assignments.append(assignment)

            logger.debug(f"Retrieved {len(assignments)} origin assignments")
            return assignments

        except requests.RequestException as e:
            logger.error(f"Failed to get assignments from TPM: {e}")
            return []

    def get_exit_hub_access(
        self,
        exit_hub_ip: str
    ) -> Optional[ExitHubAccess]:
        """
        Get exit hub access information.

        Returns connection details for SSH-based traffic inspection.
        Note: SSH private key must be pre-provisioned to validator,
        not returned via API for security.

        Args:
            exit_hub_ip: Exit hub IP address.

        Returns:
            ExitHubAccess object or None if not found.
        """
        endpoint = f"{self.api_url}/api/v1/exit-hubs/{exit_hub_ip}"

        try:
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()

            access = ExitHubAccess(
                exit_hub_ip=data["ip"],
                ssh_host=data.get("ssh_host", data["ip"]),
                ssh_port=data.get("ssh_port", 22),
                ssh_user=data.get("ssh_user", "ubuntu"),
            )

            return access

        except requests.RequestException as e:
            logger.error(f"Failed to get exit hub access info: {e}")
            return None

    def get_all_exit_hubs(self) -> List[ExitHubAccess]:
        """
        Get list of all exit hubs.

        Returns:
            List of ExitHubAccess objects.
        """
        endpoint = f"{self.api_url}/api/v1/exit-hubs"

        try:
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            exit_hubs = []

            for item in data.get("exit_hubs", []):
                access = ExitHubAccess(
                    exit_hub_ip=item["ip"],
                    ssh_host=item.get("ssh_host", item["ip"]),
                    ssh_port=item.get("ssh_port", 22),
                    ssh_user=item.get("ssh_user", "ubuntu"),
                )
                exit_hubs.append(access)

            logger.debug(f"Retrieved {len(exit_hubs)} exit hubs")
            return exit_hubs

        except requests.RequestException as e:
            logger.error(f"Failed to get exit hubs from TPM: {e}")
            return []

    def report_miner_failure(
        self,
        miner_uid: int,
        reason: str,
        severity: str = "warning"
    ) -> bool:
        """
        Report miner failure to TPM with retry logic.

        TPM may decide to trigger failover or reassignment.
        This is critical for failover system, so we retry aggressively.

        Args:
            miner_uid: Failed miner UID.
            reason: Failure reason description.
            severity: Severity level (info, warning, critical).

        Returns:
            True if report accepted, False otherwise.
        """
        # Check circuit breaker
        if self.circuit_breaker and not self.circuit_breaker.can_execute():
            logger.warning(f"Circuit breaker OPEN, skipping miner {miner_uid} failure report")
            return False

        endpoint = f"{self.api_url}/api/v1/miners/{miner_uid}/failure"

        payload = {
            "miner_uid": miner_uid,
            "reason": reason,
            "severity": severity,
            "timestamp": self._get_timestamp(),
        }

        # Retry with exponential backoff
        backoff = INITIAL_BACKOFF_SECONDS
        last_error = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.post(
                    endpoint,
                    json=payload,
                    timeout=self.timeout
                )
                response.raise_for_status()

                self._record_success()
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()

                logger.debug(f"Reported miner {miner_uid} failure to TPM: {reason}")
                return True

            except requests.exceptions.Timeout as e:
                last_error = e
                logger.warning(
                    f"report_miner_failure timeout (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.exceptions.ConnectionError as e:
                last_error = e
                logger.warning(
                    f"report_miner_failure connection error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.exceptions.HTTPError as e:
                if e.response is not None and 400 <= e.response.status_code < 500:
                    self._record_success()
                    logger.error(f"report_miner_failure client error (no retry): {e}")
                    return False
                last_error = e
                logger.warning(
                    f"report_miner_failure HTTP error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.RequestException as e:
                last_error = e
                logger.warning(
                    f"report_miner_failure request error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )

            self._record_failure()
            if self.circuit_breaker:
                self.circuit_breaker.record_failure()

            if attempt < MAX_RETRIES:
                sleep_time = min(backoff, MAX_BACKOFF_SECONDS)
                time.sleep(sleep_time)
                backoff *= BACKOFF_MULTIPLIER

        logger.error(f"Failed to report miner {miner_uid} failure after {MAX_RETRIES + 1} attempts: {last_error}")
        return False

    def _get_timestamp(self) -> float:
        """Get current timestamp."""
        import time
        return time.time()

    def health_check(self) -> bool:
        """
        Check TPM API health.

        Returns:
            True if TPM is reachable, False otherwise.
        """
        endpoint = f"{self.api_url}/health"

        try:
            response = self.session.get(endpoint, timeout=5)
            return response.status_code == 200

        except requests.RequestException:
            return False

    def get_verified_volume(self, miner_uid: int) -> Optional[VerifiedVolume]:
        """
        Get TPM-verified volume for a miner.

        This volume has been cross-validated against exit hub reports.
        Validators should use this for the volume component of rewards.

        Args:
            miner_uid: Miner UID to query.

        Returns:
            VerifiedVolume object or None if not available.
        """
        endpoint = f"{self.api_url}/api/v1/miners/{miner_uid}/verified-volume"

        try:
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()

            volume = VerifiedVolume(
                miner_uid=data["miner_uid"],
                total_verified_bytes=data["total_verified_bytes"],
                origin_count=data.get("origin_count", 0),
                origins=data.get("origins", []),
            )

            logger.debug(
                f"Retrieved verified volume for miner {miner_uid}: "
                f"{volume.total_verified_bytes} bytes"
            )
            return volume

        except requests.RequestException as e:
            logger.warning(f"Failed to get verified volume for miner {miner_uid}: {e}")
            return None

    def get_all_verified_volumes(self) -> Dict[int, VerifiedVolume]:
        """
        Get TPM-verified volumes for all miners.

        Returns:
            Dict mapping miner_uid -> VerifiedVolume
        """
        endpoint = f"{self.api_url}/api/v1/miners/verified-volumes"

        try:
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            miners_data = data.get("miners", {})

            result = {}
            for uid_str, vol_data in miners_data.items():
                miner_uid = int(uid_str)
                result[miner_uid] = VerifiedVolume(
                    miner_uid=miner_uid,
                    total_verified_bytes=vol_data["total_verified_bytes"],
                    origin_count=0,  # Not included in batch response
                    origins=[],
                )

            logger.debug(f"Retrieved verified volumes for {len(result)} miners")
            return result

        except requests.RequestException as e:
            logger.warning(f"Failed to get all verified volumes: {e}")
            return {}

    # =========================================================================
    # LEADERBOARD SYNC METHODS (Region, Availability, EMA)
    # =========================================================================

    def sync_leaderboard(
        self,
        validator_uid: int,
        validator_hotkey: str,
        miners: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Sync miner leaderboard data to TPM with retry logic.

        Called periodically to update TPM with:
        - EMA audit scores (from validator's real-time leaderboard)
        - Miner availability (online/offline status)
        - Miner region (AWS/cloud region)

        TPM uses this data for intelligent origin-to-miner assignment.
        This is critical for multi-validator consistency.

        Args:
            validator_uid: This validator's UID.
            validator_hotkey: This validator's hotkey.
            miners: List of miner data dicts with keys:
                - miner_uid: int
                - ema_score: float (0-1)
                - is_available: bool
                - region: str (optional, e.g., 'us-east-1' for AWS, 'us-east' for Linode)
                - provider: str (optional, cloud provider: 'aws', 'linode')
                - last_heartbeat: str (optional, ISO timestamp)

        Returns:
            Dict with sync results:
                - miners_updated: int
                - miners_not_found: List[int]

        Example:
            client.sync_leaderboard(
                validator_uid=7,
                validator_hotkey="5GrwvaEF...",
                miners=[
                    {"miner_uid": 42, "ema_score": 0.875, "is_available": True, "region": "us-east-1", "provider": "aws"},
                    {"miner_uid": 17, "ema_score": 0.723, "is_available": False, "region": "us-east", "provider": "linode"},
                ]
            )
        """
        # Check circuit breaker
        if self.circuit_breaker and not self.circuit_breaker.can_execute():
            logger.warning("Circuit breaker OPEN, skipping leaderboard sync")
            return {"miners_updated": 0, "miners_not_found": [], "error": "circuit_breaker_open"}

        endpoint = f"{self.api_url}/api/v1/miners/leaderboard/sync"

        payload = {
            "validator_uid": validator_uid,
            "validator_hotkey": validator_hotkey,
            "miners": miners,
            "timestamp": self._get_timestamp(),
        }

        # Retry with exponential backoff
        backoff = INITIAL_BACKOFF_SECONDS
        last_error = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.post(
                    endpoint,
                    json=payload,
                    timeout=self.timeout
                )
                response.raise_for_status()

                self._record_success()
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()

                data = response.json()
                logger.info(
                    f"Synced leaderboard to TPM: {data.get('miners_updated', 0)} miners updated"
                )
                return data

            except requests.exceptions.Timeout as e:
                last_error = e
                logger.warning(
                    f"sync_leaderboard timeout (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.exceptions.ConnectionError as e:
                last_error = e
                logger.warning(
                    f"sync_leaderboard connection error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.exceptions.HTTPError as e:
                if e.response is not None and 400 <= e.response.status_code < 500:
                    self._record_success()
                    logger.error(f"sync_leaderboard client error (no retry): {e}")
                    return {"miners_updated": 0, "miners_not_found": [], "error": str(e)}
                last_error = e
                logger.warning(
                    f"sync_leaderboard HTTP error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.RequestException as e:
                last_error = e
                logger.warning(
                    f"sync_leaderboard request error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )

            self._record_failure()
            if self.circuit_breaker:
                self.circuit_breaker.record_failure()

            if attempt < MAX_RETRIES:
                sleep_time = min(backoff, MAX_BACKOFF_SECONDS)
                time.sleep(sleep_time)
                backoff *= BACKOFF_MULTIPLIER

        logger.error(f"Failed to sync leaderboard after {MAX_RETRIES + 1} attempts: {last_error}")
        return {"miners_updated": 0, "miners_not_found": [], "error": str(last_error)}

    def get_leaderboard(
        self,
        min_score: float = 0.8,
        region: Optional[str] = None,
        available_only: bool = True,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Get miner leaderboard from TPM.

        Returns miners sorted by EMA score with availability and region info.
        Used for origin assignment decisions.

        Args:
            min_score: Minimum EMA score (default 0.8).
            region: Filter by region (optional).
            available_only: Only return available miners (default True).
            limit: Maximum miners to return (default 50).

        Returns:
            List of miner dicts with keys:
                - miner_uid: int
                - hotkey: str
                - aggregated_score: float
                - ema_score: float
                - is_available: bool
                - region: str or None
                - origins_assigned: int
                - max_origins: int
                - available_capacity: int
                - state: str
                - last_heartbeat: str or None
        """
        endpoint = f"{self.api_url}/api/v1/miners/leaderboard"

        params = {
            "min_score": min_score,
            "available_only": str(available_only).lower(),
            "limit": limit,
        }
        if region:
            params["region"] = region

        try:
            response = self.session.get(
                endpoint,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            miners = data.get("miners", [])

            logger.debug(
                f"Retrieved leaderboard from TPM: {len(miners)} miners "
                f"(total={data.get('total_count', 0)}, available={data.get('available_count', 0)})"
            )
            return miners

        except requests.RequestException as e:
            logger.error(f"Failed to get leaderboard from TPM: {e}")
            return []

    def update_miner_availability(
        self,
        miner_uid: int,
        is_available: bool,
        region: Optional[str] = None,
        scrubber_ip: Optional[str] = None,
    ) -> bool:
        """
        Update availability status for a specific miner.

        Called when validator detects a miner going online/offline.

        Args:
            miner_uid: Miner UID.
            is_available: Whether miner is currently online and responding.
            region: Optional AWS/cloud region.
            scrubber_ip: Optional scrubber IP address.

        Returns:
            True if update successful, False otherwise.
        """
        endpoint = f"{self.api_url}/api/v1/miners/{miner_uid}/availability"

        payload = {"is_available": is_available}
        if region:
            payload["region"] = region
        if scrubber_ip:
            payload["scrubber_ip"] = scrubber_ip

        try:
            response = self.session.put(
                endpoint,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            logger.debug(
                f"Updated miner {miner_uid} availability: {is_available} (region={region})"
            )
            return True

        except requests.RequestException as e:
            logger.warning(f"Failed to update miner {miner_uid} availability: {e}")
            return False

    def request_assignment(
        self,
        origin_id: str,
        origin_ip: str,
        exit_hub_ip: str,
        tunnel_name: str,
        expected_bandwidth_mbps: Optional[int] = None,
        traffic_type: Optional[str] = None,
        preferred_region: Optional[str] = None,
        request_nonce: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Request miner assignment for a new origin from TPM with idempotency support.

        IDEMPOTENCY: When request_nonce is provided, TPM will return the same
        assignment for repeated requests with the same nonce. This prevents
        duplicate assignments when network issues cause retries.

        TPM will select the best available miner based on:
        - EMA audit score (highest first)
        - Region match (preferred region first)
        - Available capacity (less loaded miners preferred)
        - Online status (only available miners)

        Args:
            origin_id: Origin identifier.
            origin_ip: Origin IP address.
            exit_hub_ip: Exit hub IP for this origin.
            tunnel_name: WireGuard tunnel name.
            expected_bandwidth_mbps: Expected bandwidth (optional).
            traffic_type: Traffic type (optional, e.g., 'web', 'video').
            preferred_region: Preferred AWS/cloud region (optional).
            request_nonce: Optional unique nonce for idempotent request.
                          If not provided, generates one from origin_id + timestamp.

        Returns:
            Assignment dict with keys:
                - assignment_id: int
                - origin_id: str
                - miner_uid: int
                - miner_hotkey: str
                - scrubber_ip: str
                - ema_score: float
                - region: str or None
                - idempotent: bool (True if this was a duplicate request)
            Or None if no suitable miner available.
        """
        # Check circuit breaker
        if self.circuit_breaker and not self.circuit_breaker.can_execute():
            logger.warning(f"Circuit breaker OPEN, skipping assignment request for {origin_id}")
            return None

        endpoint = f"{self.api_url}/api/v1/origins/request-assignment"

        # Generate request nonce for idempotency if not provided
        if not request_nonce:
            request_nonce = f"{origin_id}-{int(time.time() * 1000)}"

        payload = {
            "origin_id": origin_id,
            "origin_ip": origin_ip,
            "exit_hub_ip": exit_hub_ip,
            "tunnel_name": tunnel_name,
            "request_nonce": request_nonce,
        }
        if expected_bandwidth_mbps:
            payload["expected_bandwidth_mbps"] = expected_bandwidth_mbps
        if traffic_type:
            payload["traffic_type"] = traffic_type
        if preferred_region:
            payload["preferred_region"] = preferred_region

        # Retry with exponential backoff
        backoff = INITIAL_BACKOFF_SECONDS
        last_error = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.post(
                    endpoint,
                    json=payload,
                    timeout=self.timeout
                )

                if response.status_code == 503:
                    # No miner available - don't retry, this is a valid response
                    data = response.json()
                    logger.warning(
                        f"No miner available for origin {origin_id}: {data.get('message')}"
                    )
                    self._record_success()  # Server is responding
                    if self.circuit_breaker:
                        self.circuit_breaker.record_success()
                    return None

                response.raise_for_status()

                self._record_success()
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()

                data = response.json()
                assignment = data.get("assignment")

                if assignment:
                    is_idempotent = data.get("idempotent", False)
                    assignment["idempotent"] = is_idempotent

                    if is_idempotent:
                        logger.info(
                            f"Origin {origin_id} already assigned to miner {assignment['miner_uid']} "
                            f"(idempotent request with nonce={request_nonce})"
                        )
                    else:
                        logger.info(
                            f"Origin {origin_id} assigned to miner {assignment['miner_uid']} "
                            f"(ema={assignment.get('ema_score', 0):.3f}, region={assignment.get('region')})"
                        )

                return assignment

            except requests.exceptions.Timeout as e:
                last_error = e
                logger.warning(
                    f"request_assignment timeout (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.exceptions.ConnectionError as e:
                last_error = e
                logger.warning(
                    f"request_assignment connection error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.exceptions.HTTPError as e:
                # Don't retry 4xx errors (client errors)
                if e.response is not None and 400 <= e.response.status_code < 500:
                    self._record_success()  # Server is responding
                    if self.circuit_breaker:
                        self.circuit_breaker.record_success()
                    logger.error(f"request_assignment client error (no retry): {e}")
                    return None
                last_error = e
                logger.warning(
                    f"request_assignment HTTP error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )
            except requests.RequestException as e:
                last_error = e
                logger.warning(
                    f"request_assignment request error (attempt {attempt + 1}/{MAX_RETRIES + 1}): {e}"
                )

            # Record failure
            self._record_failure()
            if self.circuit_breaker:
                self.circuit_breaker.record_failure()

            # Sleep before retry (except on last attempt)
            if attempt < MAX_RETRIES:
                sleep_time = min(backoff, MAX_BACKOFF_SECONDS)
                time.sleep(sleep_time)
                backoff *= BACKOFF_MULTIPLIER

        logger.error(
            f"Failed to request assignment for origin {origin_id} "
            f"after {MAX_RETRIES + 1} attempts: {last_error}"
        )
        return None

    # =========================================================================
    # PRODUCTION METRICS (for dual EMA scoring)
    # =========================================================================

    def get_production_metrics(
        self,
        miner_uid: Optional[int] = None
    ) -> Dict[int, ProductionMetrics]:
        """
        Get production XDP metrics for assigned miners.

        These metrics come from real production traffic through xdp_wan.c,
        providing ground truth for production performance. This closes the
        audit gap where miners could optimize for xdp_wg_audit.c audits but
        use different configs in production.

        The metrics are collected from scrubbers via TPM (not directly from miners),
        making them ungameable.

        Args:
            miner_uid: Optional specific miner UID. If None, returns all assigned miners.

        Returns:
            Dict mapping miner_uid -> ProductionMetrics
        """
        if miner_uid is not None:
            endpoint = f"{self.api_url}/api/v1/miners/{miner_uid}/production-metrics"
        else:
            endpoint = f"{self.api_url}/api/v1/miners/production-metrics"

        try:
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            result = {}

            miners_data = data.get("miners", {})
            if miner_uid is not None and "metrics" in data:
                # Single miner response format
                miners_data = {str(miner_uid): data["metrics"]}

            for uid_str, metrics in miners_data.items():
                uid = int(uid_str)
                result[uid] = ProductionMetrics(
                    miner_uid=uid,
                    timestamp=metrics.get("timestamp", time.time()),
                    xdp_pass=metrics.get("xdp_pass", 0),
                    xdp_drop_blacklist=metrics.get("xdp_drop_blacklist", 0),
                    xdp_drop_ratelimit=metrics.get("xdp_drop_ratelimit", 0),
                    xdp_drop_temp_blacklist=metrics.get("xdp_drop_temp_blacklist", 0),
                    xdp_drop_bogon=metrics.get("xdp_drop_bogon", 0),
                    xdp_drop_invalid_ip=metrics.get("xdp_drop_invalid_ip", 0),
                    xdp_drop_invalid_tcp=metrics.get("xdp_drop_invalid_tcp", 0),
                    active_connections=metrics.get("active_connections", 0),
                    syn_synack_ratio=metrics.get("syn_synack_ratio", 1.0),
                    total_syn=metrics.get("total_syn", 0),
                    total_synack=metrics.get("total_synack", 0),
                    total_packets=metrics.get("total_packets", 0),
                    total_bytes=metrics.get("total_bytes", 0),
                    origin_count=metrics.get("origin_count", 0),
                    origins=metrics.get("origins", []),
                )

            logger.debug(f"Retrieved production metrics for {len(result)} miners")
            return result

        except requests.RequestException as e:
            logger.warning(f"Failed to get production metrics: {e}")
            return {}

    def get_origin_production_metrics(
        self,
        origin_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get production metrics for a specific origin.

        Returns XDP stats from the scrubber handling this origin's traffic.

        Args:
            origin_id: Origin identifier.

        Returns:
            Dict with XDP metrics or None if not available.
        """
        endpoint = f"{self.api_url}/api/v1/origins/{origin_id}/metrics"

        try:
            response = self.session.get(endpoint, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            return data.get("metrics")

        except requests.RequestException as e:
            logger.debug(f"Failed to get origin metrics for {origin_id}: {e}")
            return None

    # =========================================================================
    # BENIGN TEST PACKET TRACKING (for production audit verification)
    # =========================================================================

    def register_benign_test(
        self,
        test_id: str,
        miner_uid: int,
        packet_ids: List[str],
        scrubber_ip: Optional[str] = None,
        origin_id: Optional[str] = None,
    ) -> bool:
        """
        Register a benign test with TPM for packet tracking.

        Before sending test packets, the validator registers the expected packet IDs
        with TPM. The exit hub/scrubber will then track which of these packets are
        received, allowing the validator to verify traffic is flowing correctly.

        Packets are identified by unique hash IDs embedded in the TCP payload:
        "TPTEST:{test_id}:{packet_id}:{timestamp}"

        Args:
            test_id: Unique identifier for this test batch.
            miner_uid: Miner being tested.
            packet_ids: List of unique packet IDs that will be sent.
            scrubber_ip: Optional scrubber IP being tested.
            origin_id: Optional origin ID for the test traffic.

        Returns:
            True if registration successful, False otherwise.
        """
        endpoint = f"{self.api_url}/api/v1/benign-tests/register"

        payload = {
            "test_id": test_id,
            "miner_uid": miner_uid,
            "packet_ids": packet_ids,
            "timestamp": self._get_timestamp(),
        }
        if scrubber_ip:
            payload["scrubber_ip"] = scrubber_ip
        if origin_id:
            payload["origin_id"] = origin_id

        try:
            response = self.session.post(
                endpoint,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            self._record_success()
            logger.debug(
                f"Registered benign test {test_id} for miner {miner_uid} "
                f"with {len(packet_ids)} packet IDs"
            )
            return True

        except requests.RequestException as e:
            self._record_failure()
            logger.warning(f"Failed to register benign test {test_id}: {e}")
            return False

    def get_benign_test_results(
        self,
        test_id: str,
        miner_uid: int,
        timeout_seconds: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """
        Get results of a benign test from TPM.

        After sending test packets, the validator queries TPM to see which
        packets were received by the exit hub/scrubber. This verifies that
        legitimate traffic is flowing through the production scrubber.

        Args:
            test_id: Test identifier from register_benign_test().
            miner_uid: Miner that was tested.
            timeout_seconds: Max time to wait for results (default 10s).

        Returns:
            Dict with test results:
                - test_id: str
                - miner_uid: int
                - packets_sent: int (total registered)
                - packets_received: int (successfully passed through)
                - received_ids: List[str] (packet IDs that were received)
                - pass_rate: float (0-1)
                - completed: bool (whether test finished)
            Or None if test not found or error.

        Example response:
            {
                "test_id": "test-123",
                "miner_uid": 42,
                "packets_sent": 10,
                "packets_received": 9,
                "received_ids": ["pkt-1", "pkt-2", ...],
                "pass_rate": 0.9,
                "completed": True
            }
        """
        endpoint = f"{self.api_url}/api/v1/benign-tests/{test_id}/results"

        params = {
            "miner_uid": miner_uid,
            "timeout": timeout_seconds,
        }

        try:
            response = self.session.get(
                endpoint,
                params=params,
                timeout=max(self.timeout, timeout_seconds + 5)
            )
            response.raise_for_status()

            self._record_success()
            data = response.json()

            logger.debug(
                f"Benign test {test_id} results: "
                f"{data.get('packets_received', 0)}/{data.get('packets_sent', 0)} "
                f"packets received (pass_rate={data.get('pass_rate', 0):.2f})"
            )
            return data

        except requests.RequestException as e:
            self._record_failure()
            logger.warning(f"Failed to get benign test results for {test_id}: {e}")
            return None

    def cancel_benign_test(
        self,
        test_id: str,
        miner_uid: int,
    ) -> bool:
        """
        Cancel a pending benign test.

        Call this if the test cannot be completed (e.g., scrubber unreachable).

        Args:
            test_id: Test identifier to cancel.
            miner_uid: Miner UID for the test.

        Returns:
            True if cancellation successful, False otherwise.
        """
        endpoint = f"{self.api_url}/api/v1/benign-tests/{test_id}/cancel"

        payload = {
            "miner_uid": miner_uid,
        }

        try:
            response = self.session.post(
                endpoint,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            logger.debug(f"Cancelled benign test {test_id}")
            return True

        except requests.RequestException as e:
            logger.debug(f"Failed to cancel benign test {test_id}: {e}")
            return False
