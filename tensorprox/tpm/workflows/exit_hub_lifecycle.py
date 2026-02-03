"""Exit hub lifecycle workflow (registration + configuration)."""
from __future__ import annotations

import json
import os
import shlex
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

import requests

from shared.config import get_settings, get_tp_management_settings
from shared.models import ExitHubDeployRequest
from shared.utils.logging import get_logger
from shared.utils.ssh import sftp_upload, ssh_exec

from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository
from tensorprox.tpm.repositories.origin_repository import OriginRepository
from tensorprox.tpm.repositories.shard_repository import ShardRepository
from tensorprox.tpm.services.client_registry import ClientRegistry
from tensorprox.tpm.services.miner_registry import (
    MinerRegistry,
    MinerRegistryError,
)
from tensorprox.tpm.services.miner_operation_queue import (
    get_miner_operation_queue,
    OperationContext,
)
from tensorprox.tpm.services.geolocation import (
    infer_provider_from_region,
    get_default_region_for_provider,
)
from tensorprox.tpm.services.deployment_decision import get_miner_connection_info


class MinerRegistrationTimeoutError(Exception):
    """Raised when EMN registration request exhausts retries."""


class ShardNotFoundError(Exception):
    """
    Raised when Miner returns 404 with code='shard_not_found'.
    TPM should create the shard or reselect target.
    """

    def __init__(self, message: str, shard_id: Optional[str] = None):
        super().__init__(message)
        self.shard_id = shard_id


class ShardNotReadyError(Exception):
    """
    Raised when Miner returns 409 with code='shard_not_ready'.
    TPM should wait on job/shards then retry.
    """

    def __init__(self, message: str, shard_id: Optional[str] = None, job_id: Optional[str] = None):
        super().__init__(message)
        self.shard_id = shard_id
        self.job_id = job_id


class CapacityExhaustedError(Exception):
    """
    Raised when Miner returns 409 with code='capacity_exhausted'.
    TPM should reselect shard (not retry same shard).
    """

    def __init__(
        self,
        message: str,
        shard_id: Optional[str] = None,
        hard_capacity: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.shard_id = shard_id
        self.hard_capacity = hard_capacity


class RegionCapacityExhaustedError(Exception):
    """
    Raised when a cloud region has no capacity for new instances.
    TPM should try a fallback region.

    This can happen due to:
    - AWS InsufficientInstanceCapacity in all AZs
    - vCPU quota exceeded
    - EIP quota exceeded
    """

    def __init__(
        self,
        message: str,
        region: str,
        provider: str = "aws",
    ):
        super().__init__(message)
        self.region = region
        self.provider = provider


class ExitHubLifecycle:
    """Coordinate Miner registration and exit-hub configuration."""

    def __init__(
        self,
        repository: ExitHubRepository,
        client_registry: ClientRegistry,
        origin_repository: OriginRepository,
        miner_registry: Optional[MinerRegistry] = None,
        settings=None,
        state_change_hook=None
    ):
        self.repository = repository
        self.client_registry = client_registry
        self.origin_repository = origin_repository
        self.miner_registry = miner_registry
        self.settings = settings or get_settings()
        self.tpm_settings = get_tp_management_settings()
        self.logger = get_logger(__name__)
        self._state_change_hook = state_change_hook

    def _reraise_structured_error(self, error_msg: str) -> None:
        """Re-raise structured exceptions preserved through the miner queue.

        The miner queue serializes specific exception types as JSON to preserve
        their type and attributes. This method parses that JSON and re-raises
        the appropriate exception, enabling proper error handling in deploy_queue.

        Args:
            error_msg: Error message from completed operation (may be JSON)

        Raises:
            ShardNotReadyError: If error was shard_not_ready
            ShardNotFoundError: If error was shard_not_found
            CapacityExhaustedError: If error was capacity_exhausted
        """
        try:
            error_data = json.loads(error_msg)
            if not isinstance(error_data, dict) or not error_data.get("_structured"):
                return  # Not a structured error, fall through to RuntimeError

            error_type = error_data.get("type")
            message = error_data.get("message", "Unknown error")

            if error_type == "ShardNotReadyError":
                raise ShardNotReadyError(
                    message,
                    shard_id=error_data.get("shard_id"),
                    job_id=error_data.get("job_id"),
                )
            elif error_type == "ShardNotFoundError":
                raise ShardNotFoundError(
                    message,
                    shard_id=error_data.get("shard_id"),
                )
            elif error_type == "CapacityExhaustedError":
                raise CapacityExhaustedError(
                    message,
                    shard_id=error_data.get("shard_id"),
                    hard_capacity=error_data.get("hard_capacity"),
                )
            # Unknown structured type, fall through to RuntimeError
        except json.JSONDecodeError:
            pass  # Not JSON, fall through to RuntimeError

    def register_exit_hub(
        self,
        *,
        exit_hub_id: UUID,
        request: ExitHubDeployRequest,
        exit_hub_ip: str,
        instance_id: str,
        ssh_username: str
    ) -> Dict[str, Any]:
        """
        Register exit hub with Miner/EMN and configure remote host.

        NOTE: SSE notifications are handled by miner_operation_queue:
        - "queued_for_miner" emitted when submit() is called (with queue position)
        - "registering_origin" emitted when operation starts processing
        This ensures correct notification order for parallel deployments.
        """
        # Update DB status only - SSE handled by miner_operation_queue
        self.repository.update_exit_hub(
            exit_hub_id,
            status='queued_for_miner',
            instance_id=instance_id,
            exit_hub_ip=exit_hub_ip,
        )

        self.logger.info(
            "Exit hub %s: submitting origin registration to miner queue (miner_ip=%s)",
            exit_hub_id,
            request.emn_ip,
        )

        # Submit origin registration to miner operation queue (FIFO per miner)
        miner_queue = get_miner_operation_queue()

        # Determine shard_id with provider-aware fallback
        if request.shard_id:
            shard_id = request.shard_id
        elif request.region:
            shard_id = request.region
        else:
            provider = request.cloud_provider or "aws"
            shard_id = get_default_region_for_provider(provider)
        miner_op = miner_queue.submit(
            miner_id=request.miner_id,
            operation_type="register_origin",
            payload={
                "emn_ip": request.emn_ip,
                "emn_port": request.emn_port,
                "origin_id": request.origin_id,
                "exit_hub_ip": exit_hub_ip,
                "origin_ip": request.origin_ip,
                "ports": request.ports,
                "shard_id": shard_id,
            },
            exit_hub_id=str(exit_hub_id),
            origin_id=request.origin_id,
            shard_id=shard_id,
            context=OperationContext(
                exit_hub_id=str(exit_hub_id),
                origin_id=request.origin_id,
                client_id=request.client_id,
                miner_id=request.miner_id,
                miner_ip=request.emn_ip,
            ),
        )

        # Wait for queue completion
        try:
            completed_op = miner_queue.wait_for_completion(
                str(miner_op.operation_id),
                timeout=120,
            )
        except TimeoutError as e:
            self.logger.error(
                "Exit hub %s: origin registration timed out",
                exit_hub_id,
            )
            raise MinerRegistrationTimeoutError(
                f"Origin registration timed out: {e}"
            ) from e

        if completed_op.status == "cancelled":
            raise RuntimeError("Origin registration cancelled")

        if completed_op.status == "failed":
            self.logger.error(
                "Exit hub %s: origin registration failed: %s",
                exit_hub_id,
                completed_op.error,
            )
            # Re-raise structured exceptions preserved through the queue
            self._reraise_structured_error(completed_op.error)
            raise RuntimeError(f"Origin registration failed: {completed_op.error}")

        registration = completed_op.result or {}
        self._apply_registration_to_exit_hub(
            host=exit_hub_ip,
            ssh_username=ssh_username,
            request=request,
            registration=registration
        )
        self._verify_exit_hub_ready(
            host=exit_hub_ip,
            ssh_username=ssh_username,
            interface=registration.get('wg_interface') or f"wg-{request.origin_id}",
        )
        self.logger.info(
            "Exit hub %s: Miner registration applied",
            exit_hub_id
        )

        # Intermediate stage to surface Step 5/6 before activation.
        self.repository.update_exit_hub(
            exit_hub_id,
            status='stabilizing',
            last_error=None,
        )
        self._emit_state_change(
            exit_hub_id=exit_hub_id,
            status='stabilizing',
            request=request,
            metadata={
                'instance_id': instance_id,
                'exit_hub_ip': exit_hub_ip,
            },
        )

        wg_interface = registration.get('wg_interface') or f"wg-{request.origin_id}"
        secret = registration.get('secret')
        tensorprox_ip = registration.get('eip')

        metadata = {
            'client_id': request.client_id,
            'requested_region': request.region,
            'requested_instance_type': request.instance_type,
            'ports': request.ports,
            'emn_ip': request.emn_ip,
            'miner_id': request.miner_id,
            'miner_ip': request.emn_ip,
            'tensorprox_ip': tensorprox_ip,
            'registration': {
                'status': registration.get('status'),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'transparent_mode_commands': registration.get('transparent_mode_commands', []),
            }
        }

        self.repository.update_metadata(exit_hub_id, metadata)
        self.repository.update_exit_hub(
            exit_hub_id,
            status='active',
            secret=secret,
            wg_interface=wg_interface,
            tensorprox_ip=tensorprox_ip,
            last_error=None
        )

        # Persist deployment result to origin (canonical location)
        if request.client_id and request.origin_id and tensorprox_ip:
            shard_id = request.shard_id or registration.get('shard_id') or request.region
            self.origin_repository.set_deployment_result(
                client_id=request.client_id,
                origin_id=request.origin_id,
                shard_id=shard_id,
                tensorprox_ip=tensorprox_ip,
            )
            self.logger.info(
                "Persisted deployment result to origin %s (shard_id=%s, tensorprox_ip=%s)",
                request.origin_id,
                shard_id,
                tensorprox_ip,
            )

            # Increment shard origin count (cancels any pending sweep)
            if request.miner_id and shard_id:
                try:
                    from tensorprox.tpm.repositories.shard_repository import ShardRepository
                    shard_repo = ShardRepository()
                    shard_repo.increment_origin_count(UUID(request.miner_id), shard_id)
                except Exception as exc:
                    self.logger.warning("Failed to update shard origin count: %s", exc)

            # Sync shard to tensorprox_miner_shards (ensures TPM tracks all shards)
            if request.miner_id and shard_id:
                try:
                    # Derive region from shard_id (e.g., "eu-central-1-2" -> "eu-central-1")
                    region = registration.get('region') or request.region or shard_id
                    if shard_id != region and shard_id.startswith(region):
                        # shard_id has suffix (e.g., eu-central-1-2), region is base
                        pass
                    elif '-' in shard_id:
                        # Extract base region: "eu-central-1-2" -> "eu-central-1"
                        # Handle AWS region format: {area}-{direction}-{num}[-{suffix}]
                        parts = shard_id.rsplit('-', 1)
                        if parts[-1].isdigit() and len(parts) > 1:
                            # Check if it's a suffix or part of region name
                            potential_region = parts[0]
                            if potential_region.count('-') >= 2:
                                region = potential_region
                            else:
                                region = shard_id  # shard_id IS the region

                    shard_repo = ShardRepository()
                    shard_repo.upsert_shard(
                        miner_id=UUID(request.miner_id),
                        shard_id=shard_id,
                        region=region,
                        status="active",
                    )
                    self.logger.info(
                        "Synced shard %s to TPM database (miner=%s, region=%s)",
                        shard_id,
                        request.miner_id,
                        region,
                    )
                except Exception as exc:  # noqa: BLE001
                    # Non-fatal: shard sync failure shouldn't block deployment
                    self.logger.warning(
                        "Failed to sync shard %s to TPM database: %s",
                        shard_id,
                        exc,
                    )

        if request.client_id and request.origin_id:
            self.client_registry.mark_origin_active(request.client_id, request.origin_id)

        return {
            'secret': secret,
            'wg_interface': wg_interface,
            'registration': registration,
            'metadata': metadata
        }

    def _emit_state_change(
        self,
        *,
        exit_hub_id: UUID,
        status: str,
        request: ExitHubDeployRequest,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        if not self._state_change_hook:
            return
        self._state_change_hook(
            exit_hub_id=str(exit_hub_id),
            status=status,
            client_id=request.client_id,
            origin_id=request.origin_id,
            miner_id=request.miner_id,
            miner_ip=request.emn_ip,
            metadata=metadata,
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _call_origin_registration(
        self,
        request: ExitHubDeployRequest,
        exit_hub_ip: str
    ) -> Dict[str, Any]:
        """
        Call Miner/EMN origin registration endpoint.

        Raises:
            ShardNotFoundError: 404 with code='shard_not_found'
            ShardNotReadyError: 409 with code='shard_not_ready'
            CapacityExhaustedError: 409 with code='capacity_exhausted'
            MinerRegistrationTimeoutError: network timeout or exhausted retries
            RuntimeError: other errors
        """
        emn_ip = request.emn_ip
        if not emn_ip:
            raise RuntimeError("EMN IP missing on deploy request; cannot register origin")
        emn_port = request.emn_port
        url = f"http://{emn_ip}:{emn_port}/api/v1/origins"

        # Derive shard_id: explicit > region > provider-aware default
        if request.shard_id:
            shard_id = request.shard_id
        elif request.region:
            shard_id = request.region
        else:
            provider = request.cloud_provider or "aws"
            shard_id = get_default_region_for_provider(provider)
        payload = {
            'origin_id': request.origin_id,
            'exit_hub_ip': exit_hub_ip,
            'origin_ip': request.origin_ip,
            'required_ports': request.ports,
            'shard_id': shard_id,
        }
        headers = self._build_miner_headers(request.miner_id)

        # Use configurable timeout from TPM settings
        timeout_seconds = self.tpm_settings.tp_request_timeout_seconds
        timeout_tuple = (5, timeout_seconds)  # (connect timeout, read timeout)

        self.logger.info(
            "Registering origin %s with EMN %s (timeout=%ss)",
            request.origin_id,
            url,
            timeout_seconds
        )

        attempts = 3
        delay = 2
        last_error: Optional[str] = None

        for attempt in range(1, attempts + 1):
            try:
                self.logger.info(
                    "EMN registration attempt %s/%s for origin %s",
                    attempt,
                    attempts,
                    request.origin_id,
                )
                response = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=timeout_tuple
                )
            except requests.RequestException as exc:
                last_error = str(exc)
                self.logger.warning(
                    "EMN registration attempt %s/%s hit transport error: %s",
                    attempt,
                    attempts,
                    exc,
                )
                # Continue to retry logic for network errors
            else:
                self.logger.info(
                    "EMN registration attempt %s/%s returned %s",
                    attempt,
                    attempts,
                    response.status_code,
                )

                # Success case
                if response.status_code < 400:
                    break

                # Parse error response body
                try:
                    error_body = response.json()
                except Exception:  # noqa: BLE001
                    error_body = {}

                error_code = error_body.get("code")
                error_message = error_body.get("message") or response.text
                error_shard_id = error_body.get("shard_id")

                # Raise context-sensitive exceptions for structured error codes
                if response.status_code == 404 and error_code == "shard_not_found":
                    self.logger.warning(
                        "Miner returned shard_not_found for shard %s",
                        error_shard_id
                    )
                    raise ShardNotFoundError(error_message, shard_id=error_shard_id)

                if response.status_code == 409:
                    if error_code == "shard_not_ready":
                        job_id = error_body.get("job_id")
                        self.logger.warning(
                            "Miner returned shard_not_ready for shard %s (job_id=%s)",
                            error_shard_id,
                            job_id
                        )
                        raise ShardNotReadyError(
                            error_message,
                            shard_id=error_shard_id,
                            job_id=job_id
                        )

                    if error_code == "capacity_exhausted":
                        hard_capacity = error_body.get("hard_capacity")
                        self.logger.warning(
                            "Miner returned capacity_exhausted for shard %s",
                            error_shard_id
                        )
                        raise CapacityExhaustedError(
                            error_message,
                            shard_id=error_shard_id,
                            hard_capacity=hard_capacity
                        )

                # Generic error for non-specific codes
                last_error = f"{response.status_code}: {error_message}"

            # Retry logic
            if attempt < attempts:
                self.logger.warning(
                    "EMN registration attempt %s failed (%s); retrying in %ss",
                    attempt,
                    last_error,
                    delay,
                )
                time.sleep(delay)
                delay *= 2
        else:
            # Exhausted all retries
            raise MinerRegistrationTimeoutError(
                f"EMN registration request failed after {attempts} attempts: {last_error}"
            )

        # Parse successful response
        try:
            data = response.json()
        except json.JSONDecodeError as exc:
            raise RuntimeError("Invalid JSON response from EMN") from exc

        if data.get('status') != 'success':
            message = data.get('message') or 'unknown error'
            raise RuntimeError(f"EMN registration returned error: {message}")

        return data

    def _apply_registration_to_exit_hub(
        self,
        *,
        host: str,
        ssh_username: str,
        request: ExitHubDeployRequest,
        registration: Dict[str, Any]
    ) -> None:
        """Write secrets, WireGuard config, and routing rules on the exit hub."""
        secret = registration.get('secret')
        if secret:
            self._write_secret(host, ssh_username, secret)
        else:
            self.logger.warning(
                "No secret received for exit hub %s",
                request.origin_id
            )

        wg_interface = registration.get('wg_interface') or f"wg-{request.origin_id}"
        wg_config = registration.get('hub_wg_config')
        if wg_config:
            self._upload_wireguard_config(host, ssh_username, wg_interface, wg_config)
            self.logger.info(
                "WireGuard config for %s uploaded (interface=%s)",
                request.origin_id,
                wg_interface,
            )
        else:
            self.logger.warning(
                "No WireGuard config provided for origin %s",
                request.origin_id
            )

        # Always try to start/restart WireGuard to ensure config is applied.
        self._run_remote(
            host,
            f"sudo systemctl enable --now wg-quick@{shlex.quote(wg_interface)}",
            ssh_username
        )

        self._ensure_forwarding_rules(host, ssh_username, wg_interface)
        self._apply_transparent_mode_commands(
            host,
            ssh_username,
            registration.get('transparent_mode_commands', [])
        )

    def _write_secret(self, host: str, ssh_username: str, secret: str) -> None:
        """Persist shared secret so Miner can authenticate to exit hub."""
        self.logger.info("Writing shared secret on %s", host)
        command = (
            "sudo mkdir -p /etc/exit-hub && "
            f"echo {shlex.quote(secret)} | sudo tee /etc/exit-hub/secret >/dev/null && "
            "sudo chmod 600 /etc/exit-hub/secret"
        )
        self._run_remote_with_retry(host, command, ssh_username, attempts=3, delay=5)

    def _upload_wireguard_config(
        self,
        host: str,
        ssh_username: str,
        interface: str,
        config_text: str
    ) -> None:
        """Upload WireGuard configuration and set permissions."""
        self.logger.info(
            "Uploading WireGuard configuration for interface %s on %s",
            interface,
            host,
        )
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".conf") as tmp:
            tmp.write(config_text)
            tmp_path = tmp.name

        try:
            uploaded, upload_error = sftp_upload(
                host=host,
                username=ssh_username,
                key_filename=self.settings.ssh_key_path,
                local_path=tmp_path,
                remote_path=f"/tmp/{interface}.conf",
                timeout=30
            )
            if not uploaded:
                raise RuntimeError(upload_error or "Failed to upload WireGuard config via SFTP")

            commands = [
                f"sudo mv /tmp/{interface}.conf /etc/wireguard/{interface}.conf",
                f"sudo chown root:root /etc/wireguard/{interface}.conf",
                f"sudo chmod 600 /etc/wireguard/{interface}.conf",
            ]
            for cmd in commands:
                self._run_remote(host, cmd, ssh_username)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _ensure_forwarding_rules(self, host: str, ssh_username: str, interface: str) -> None:
        """Ensure nft forward rules exist between WireGuard interface and primary NIC."""
        self.logger.info(
            "Ensuring nft forwarding rules exist for interface %s on %s",
            interface,
            host,
        )
        # Detect primary interface dynamically (eth0 on Linode, ens5 on AWS)
        iface_detect = "$(ip route get 1.1.1.1 | grep -oP 'dev \\K\\S+' | head -1)"
        commands = [
            (
                f"IFACE={iface_detect}; sudo nft add rule ip filter forward "
                f"iifname {shlex.quote(interface)} oifname \"$IFACE\" accept"
            ),
            (
                f"IFACE={iface_detect}; sudo nft add rule ip filter forward "
                f"iifname \"$IFACE\" oifname {shlex.quote(interface)} accept"
            ),
        ]
        for cmd in commands:
            self._run_remote(host, f"{cmd} 2>/dev/null || true", ssh_username, required=False)

    def _apply_transparent_mode_commands(
        self,
        host: str,
        ssh_username: str,
        commands: Optional[Any]
    ) -> None:
        """Run Miner-supplied commands to finish transparent routing setup."""
        if not commands:
            self.logger.warning("No transparent_mode_commands provided by Miner")
            return

        for raw_cmd in commands:
            if not raw_cmd:
                continue
            self.logger.info(
                "Applying transparent-mode command on %s: %s",
                host,
                raw_cmd,
            )
            quoted = shlex.quote(str(raw_cmd))
            self._run_remote(
                host,
                f"sudo bash -c {quoted}",
                ssh_username,
                required=False
            )

    def _run_remote(
        self,
        host: str,
        command: str,
        ssh_username: str,
        required: bool = True
    ) -> None:
        """Execute a remote command via SSH."""
        rc, stdout, stderr = ssh_exec(
            host,
            command,
            self.settings.ssh_key_path,
            user=ssh_username
        )

        if rc != 0:
            message = (
                f"Remote command failed on {host}: {command} "
                f"(rc={rc}, stderr={stderr.strip()})"
            )
            if required:
                raise RuntimeError(message)
            self.logger.warning(message)
        else:
            if stdout:
                self.logger.debug("Remote command output: %s", stdout.strip())

    def _run_remote_with_retry(
        self,
        host: str,
        command: str,
        ssh_username: str,
        *,
        attempts: int = 3,
        delay: int = 5,
        required: bool = True,
    ) -> None:
        """Execute a remote command with limited retries for transient SSH errors."""
        last_error: Optional[Exception] = None
        for attempt in range(1, attempts + 1):
            try:
                self._run_remote(host, command, ssh_username, required=required)
                return
            except RuntimeError as exc:
                last_error = exc
                if attempt == attempts:
                    raise
                self.logger.warning(
                    "Retrying remote command on %s (attempt %s/%s): %s",
                    host,
                    attempt,
                    attempts,
                    exc,
                )
                time.sleep(delay)
        if last_error:
            raise last_error

    def _build_miner_headers(self, miner_id: Optional[str]) -> Optional[Dict[str, str]]:
        """Build Authorization headers for Miner requests if available."""
        if not miner_id or not self.miner_registry:
            if not miner_id:
                self.logger.warning("Unable to build miner headers: missing miner_id")
            return None
        try:
            secret = self.miner_registry.get_plaintext_secret(miner_id)
        except MinerRegistryError as exc:
            self.logger.warning(
                "Unable to load secret for miner %s: %s",
                miner_id,
                exc,
            )
            return None
        return {"Authorization": f"Bearer {secret}"}

    def _verify_exit_hub_ready(
        self,
        *,
        host: str,
        ssh_username: str,
        interface: str,
    ) -> None:
        """Run lightweight checks to ensure the exit hub is ready before activation."""
        checks = {
            "wireguard_interface": f"sudo wg show {shlex.quote(interface)}",
            "wireguard_service": f"sudo systemctl is-active --quiet wg-quick@{shlex.quote(interface)}",
            "nft_forward_rules": (
                "sudo nft list ruleset | grep -q "
                f"{shlex.quote(interface)}"
            ),
        }
        for check_name, command in checks.items():
            self.logger.info(
                "Verifying %s on %s via SSH command: %s",
                check_name,
                host,
                command,
            )
            rc, stdout, stderr = ssh_exec(
                host,
                command,
                self.settings.ssh_key_path,
                user=ssh_username
            )
            if rc != 0:
                message = stderr.strip() or stdout.strip() or "no output"
                raise RuntimeError(
                    f"Exit hub verification '{check_name}' failed on {host}: {message}"
                )

    def decommission_origin(
        self,
        origin_id: str,
        emn_ip: Optional[str] = None,
        miner_id: Optional[str] = None,
        shard_id: Optional[str] = None,
        emn_port: Optional[int] = None,
        fire_and_forget: bool = False,
    ) -> Dict[str, Any]:
        """Notify Miner/EMN to tear down origin state via miner operation queue.

        Args:
            origin_id: Origin to decommission
            emn_ip: Miner IP address
            miner_id: Miner UUID
            shard_id: Shard ID for tracking and sweep scheduling
            emn_port: Miner port (optional - will look up from registry if not provided)
            fire_and_forget: If True, submit to queue and return immediately
                             without waiting for completion. Use for user-initiated
                             deletions where fast feedback is important.
        """
        target_ip = emn_ip
        target_port = emn_port or self.settings.miner_port
        if not target_ip:
            raise RuntimeError("EMN IP missing for origin teardown")
        if not miner_id:
            raise RuntimeError("Miner ID missing for origin teardown")

        # Try to get port from miner registry if not provided
        if not emn_port:
            try:
                miner = self.miner_registry.get_miner(miner_id)
                if miner:
                    _, target_port = get_miner_connection_info(miner)
            except Exception:
                pass  # Fall back to default

        self.logger.info(
            "Submitting origin teardown for %s to miner %s via queue (fire_and_forget=%s)",
            origin_id,
            miner_id,
            fire_and_forget,
        )

        # Submit origin deletion to miner operation queue (FIFO per miner)
        miner_queue = get_miner_operation_queue()

        miner_op = miner_queue.submit(
            miner_id=miner_id,
            operation_type="delete_origin",
            payload={
                "emn_ip": target_ip,
                "emn_port": target_port,
                "origin_id": origin_id,
                "shard_id": shard_id,
            },
            origin_id=origin_id,
            shard_id=shard_id,
            context=OperationContext(
                origin_id=origin_id,
                miner_id=miner_id,
                miner_ip=target_ip,
            ),
        )

        # Fire-and-forget: return immediately for fast user feedback
        # The queue worker will process the deletion in background
        if fire_and_forget:
            self.logger.info(
                "Origin teardown queued for %s (fire-and-forget mode, op=%s)",
                origin_id,
                miner_op.operation_id,
            )
            return {"status": "queued", "operation_id": str(miner_op.operation_id)}

        # Wait for queue completion (20 min: Japan ops can take 15+ min)
        try:
            completed_op = miner_queue.wait_for_completion(
                str(miner_op.operation_id),
                timeout=1200,  # 20 minutes for slow cross-region ops
            )
        except TimeoutError as e:
            self.logger.error(
                "Origin teardown timed out for %s",
                origin_id,
            )
            raise RuntimeError(f"Origin teardown timed out: {e}") from e

        if completed_op.status == "failed":
            self.logger.error(
                "Origin teardown failed for %s: %s",
                origin_id,
                completed_op.error,
            )
            raise RuntimeError(f"Origin teardown failed: {completed_op.error}")

        return completed_op.result or {"status": "success"}

    # ------------------------------------------------------------------ #
    # Egress routing methods (GRE tunnel for origin egress)
    # ------------------------------------------------------------------ #

    def activate_egress(
        self,
        *,
        origin_id: str,
        origin_ip: str,
        exit_hub_ip: str,
        ssh_username: str,
    ) -> Dict[str, Any]:
        """
        Activate egress routing via GRE tunnel on the exit hub.

        Sets up a GRE tunnel from the exit hub to the origin, allowing
        the origin to route egress traffic through the exit hub.

        Args:
            origin_id: Unique identifier for the origin
            origin_ip: IP address of the origin server
            exit_hub_ip: IP address of the exit hub
            ssh_username: SSH username for remote commands

        Returns:
            Dict with status='activated' on success
        """
        self.logger.info(
            "Activating egress routing for origin %s (origin_ip=%s, exit_hub=%s)",
            origin_id,
            origin_ip,
            exit_hub_ip,
        )
        self._configure_gre_tunnel(exit_hub_ip, ssh_username, origin_ip)
        self._add_egress_forwarding_rules(exit_hub_ip, ssh_username)
        self._add_egress_policy_routing(exit_hub_ip, ssh_username, origin_ip, origin_id)
        self.logger.info(
            "Egress routing activated for origin %s",
            origin_id,
        )
        return {"status": "activated"}

    def deactivate_egress(
        self,
        *,
        origin_id: str,
        origin_ip: str,
        exit_hub_ip: str,
        ssh_username: str,
    ) -> Dict[str, Any]:
        """
        Deactivate egress routing by tearing down the GRE tunnel.

        Args:
            origin_id: Unique identifier for the origin
            origin_ip: IP address of the origin server (for policy routing cleanup)
            exit_hub_ip: IP address of the exit hub
            ssh_username: SSH username for remote commands

        Returns:
            Dict with status='deactivated' on success
        """
        self.logger.info(
            "Deactivating egress routing for origin %s (exit_hub=%s)",
            origin_id,
            exit_hub_ip,
        )
        self._remove_egress_policy_routing(exit_hub_ip, ssh_username, origin_ip, origin_id)
        self._remove_egress_forwarding_rules(exit_hub_ip, ssh_username)
        self._remove_gre_tunnel(exit_hub_ip, ssh_username)
        self.logger.info(
            "Egress routing deactivated for origin %s",
            origin_id,
        )
        return {"status": "deactivated"}

    def _configure_gre_tunnel(
        self,
        host: str,
        ssh_username: str,
        origin_ip: str,
    ) -> None:
        """
        Configure GRE tunnel on exit hub to origin.

        Creates a GRE tunnel interface with:
        - Remote endpoint: origin_ip
        - Local endpoint: exit hub's primary IP (auto-detected)
        - Tunnel IP: 10.99.0.1/30 (exit hub side)

        Args:
            host: Exit hub IP address
            ssh_username: SSH username for remote commands
            origin_ip: Origin server IP (GRE remote endpoint)
        """
        self.logger.info(
            "Configuring GRE tunnel on %s to origin %s",
            host,
            origin_ip,
        )
        # Get local IP dynamically using hostname -I
        local_ip_cmd = "$(hostname -I | awk '{print $1}')"
        # Delete existing tunnel first for idempotency
        self._run_remote(
            host,
            "sudo ip tunnel del gre-origin 2>/dev/null || true",
            ssh_username,
            required=False,
        )
        # MTU 1400 is safe for GRE over internet paths (1500 - IP/GRE headers - cloud overhead)
        # Without this, AWS jumbo frames (MTU 9001) cause TLS handshake timeouts
        commands = [
            (
                f"sudo ip tunnel add gre-origin mode gre "
                f"remote {shlex.quote(origin_ip)} local {local_ip_cmd} ttl 64"
            ),
            "sudo ip link set gre-origin up",
            "sudo ip link set gre-origin mtu 1400",
            "sudo ip addr add 10.99.0.1/30 dev gre-origin",
        ]
        for cmd in commands:
            self._run_remote(host, cmd, ssh_username)

    def _remove_gre_tunnel(self, host: str, ssh_username: str) -> None:
        """
        Remove GRE tunnel from exit hub.

        Gracefully tears down the gre-origin interface, ignoring errors
        if the tunnel doesn't exist.

        Args:
            host: Exit hub IP address
            ssh_username: SSH username for remote commands
        """
        self.logger.info("Removing GRE tunnel on %s", host)
        commands = [
            "sudo ip link set gre-origin down 2>/dev/null || true",
            "sudo ip tunnel del gre-origin 2>/dev/null || true",
        ]
        for cmd in commands:
            self._run_remote(host, cmd, ssh_username, required=False)

    def _add_egress_forwarding_rules(self, host: str, ssh_username: str) -> None:
        """
        Add nftables forwarding rules for GRE tunnel traffic.

        Allows:
        - Inbound traffic from gre-origin interface
        - Outbound related/established traffic to gre-origin

        Args:
            host: Exit hub IP address
            ssh_username: SSH username for remote commands
        """
        self.logger.info("Adding egress forwarding rules on %s", host)
        commands = [
            'sudo nft add rule ip filter forward iifname "gre-origin" accept',
            (
                'sudo nft add rule ip filter forward oifname "gre-origin" '
                'ct state related,established accept'
            ),
        ]
        for cmd in commands:
            self._run_remote(host, cmd, ssh_username, required=False)

    def _add_egress_policy_routing(
        self,
        host: str,
        ssh_username: str,
        origin_ip: str,
        origin_id: str,
    ) -> None:
        """
        Add policy routing rules for bidirectional GRE↔WireGuard traffic.

        Creates routing rules to:
        1. Route traffic arriving on gre-origin to WireGuard (table 60001)
        2. Route return traffic from WireGuard to gre-origin (table 200)

        Args:
            host: Exit hub IP address
            ssh_username: SSH username for remote commands
            origin_ip: Origin server IP for return path routing
            origin_id: Origin ID (e.g., "O19") to derive WireGuard interface name
        """
        # Derive WireGuard interface name from origin_id (e.g., "O19" -> "wgO19")
        wg_iface = f"wg{origin_id}"

        self.logger.info(
            "Adding egress policy routing on %s for origin %s (wg_iface=%s)",
            host,
            origin_ip,
            wg_iface,
        )
        commands = [
            # Outbound: traffic from GRE goes to WireGuard (table 60001)
            "sudo ip rule del iif gre-origin table 60001 2>/dev/null || true",
            "sudo ip rule add iif gre-origin lookup 60001 priority 20000",
            f"sudo ip route replace default dev {shlex.quote(wg_iface)} table 60001",
            # Return: traffic from WireGuard to origin goes to GRE (table 200)
            f"sudo ip rule del to {shlex.quote(origin_ip)} iif {shlex.quote(wg_iface)} table 200 2>/dev/null || true",
            f"sudo ip rule add to {shlex.quote(origin_ip)} iif {shlex.quote(wg_iface)} lookup 200 priority 100",
            f"sudo ip route replace {shlex.quote(origin_ip)} dev gre-origin table 200",
        ]
        for cmd in commands:
            self._run_remote(host, cmd, ssh_username, required=False)

    def _remove_egress_policy_routing(
        self,
        host: str,
        ssh_username: str,
        origin_ip: str,
        origin_id: str,
    ) -> None:
        """
        Remove policy routing rules for GRE↔WireGuard traffic.

        Args:
            host: Exit hub IP address
            ssh_username: SSH username for remote commands
            origin_ip: Origin server IP for cleanup
            origin_id: Origin ID (e.g., "O19") to derive WireGuard interface name
        """
        # Derive WireGuard interface name from origin_id (e.g., "O19" -> "wgO19")
        wg_iface = f"wg{origin_id}"

        self.logger.info(
            "Removing egress policy routing on %s for origin %s (wg_iface=%s)",
            host,
            origin_ip,
            wg_iface,
        )
        commands = [
            "sudo ip rule del iif gre-origin table 60001 2>/dev/null || true",
            f"sudo ip route del default dev {shlex.quote(wg_iface)} table 60001 2>/dev/null || true",
            f"sudo ip rule del to {shlex.quote(origin_ip)} iif {shlex.quote(wg_iface)} table 200 2>/dev/null || true",
            f"sudo ip route del {shlex.quote(origin_ip)} dev gre-origin table 200 2>/dev/null || true",
        ]
        for cmd in commands:
            self._run_remote(host, cmd, ssh_username, required=False)

    def _remove_egress_forwarding_rules(self, host: str, ssh_username: str) -> None:
        """
        Remove nftables forwarding rules for GRE tunnel traffic.

        Removes any rules referencing gre-origin from the filter forward chain.
        Uses grep/awk to find rule handles and delete them individually.

        Args:
            host: Exit hub IP address
            ssh_username: SSH username for remote commands
        """
        self.logger.info("Removing egress forwarding rules on %s", host)
        # Delete rules matching gre-origin - find handles and delete each
        delete_cmd = (
            'for handle in $(sudo nft -a list chain ip filter forward 2>/dev/null | '
            'grep gre-origin | awk \'{print $NF}\'); do '
            'sudo nft delete rule ip filter forward handle $handle 2>/dev/null || true; done'
        )
        self._run_remote(host, delete_cmd, ssh_username, required=False)
