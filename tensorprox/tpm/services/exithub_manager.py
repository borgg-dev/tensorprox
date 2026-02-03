"""Exit Hub Manager - Deployment + registration orchestration."""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import UUID, uuid4, uuid5, NAMESPACE_URL

import requests
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from shared.config import get_settings, get_tp_management_settings
from shared.models import ExitHubDeployRequest, ExitHubResponse, InstanceCreateResult
from shared.node import Node
from shared.providers import SCRUBBER_SUPPORTED_PROVIDERS
from shared.utils.logging import get_logger
from shared.utils.ssh import create_ssh_client

from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository
from tensorprox.tpm.repositories.origin_repository import OriginRepository
from tensorprox.tpm.repositories.shard_repository import ShardRepository
from tensorprox.tpm.services.client_registry import ClientRegistry
from tensorprox.tpm.services.miner_registry import (
    MinerRegistry,
    MinerSecretInvalidError,
    normalize_miner_id,
)
from tensorprox.tpm.services.geolocation import find_best_region_for_ip, infer_provider_from_region, get_all_regions
from tensorprox.tpm.services.deployment_decision import get_miner_connection_info
from tensorprox.tpm.services.placement import select_exit_hub_location
from tensorprox.tpm.services.operation_tracker import get_operation_tracker
from tensorprox.tpm.services.metrics_gateway_client import MetricsGatewayClient
from tensorprox.tpm.workflows.exit_hub_lifecycle import (
    ExitHubLifecycle,
    MinerRegistrationTimeoutError,
    RegionCapacityExhaustedError,
)
from tensorprox.tpm.services.notifier import ExitHubNotifier
from tensorprox.tpm.utils.cleanup import cleanup_failed_exit_hub
from tensorprox.tpm.services.provider_registry import ProviderRegistry
from tensorprox.tpm.services.node_factory import NodeFactory
from tensorprox.tpm.services.assignment_engine import AssignmentEngine, AssignmentRequest
from shared.database import get_tp_db_connection

logger = get_logger(__name__)


class ExitHubNotFoundError(Exception):
    """Raised when an exit hub record cannot be found."""


class DeploymentTimeoutError(Exception):
    """Raised when the overall deployment exceeds a safe duration."""


class ExitHubManager:
    """Exit hub deployment and lifecycle management."""

    def __init__(self):
        self.repository = ExitHubRepository()
        self.origin_repository = OriginRepository()
        self.shard_repository = ShardRepository()
        self.client_registry = ClientRegistry()
        self.miner_registry = MinerRegistry()
        self.lifecycle = ExitHubLifecycle(
            self.repository,
            self.client_registry,
            miner_registry=self.miner_registry,
            origin_repository=self.origin_repository,
            state_change_hook=self._notify_state_change
        )
        self.settings = get_settings()
        self.provider_registry = ProviderRegistry(self.settings)
        self.node_factory = NodeFactory(self.settings, self.provider_registry)
        self.notifier = ExitHubNotifier()
        # Wire operation tracker singleton
        get_operation_tracker().set_notifier(self.notifier)
        self.metrics_client = MetricsGatewayClient()
        management_settings = get_tp_management_settings()
        self._deploy_timeout = max(30, management_settings.cloud_deploy_timeout_seconds)
        self._ssh_wait_timeout = max(60, management_settings.exit_hub_ssh_timeout_seconds)
        self._post_provision_timeout = min(300, self._deploy_timeout + 120)
        self._bootstrap_grace_seconds = max(0, management_settings.exit_hub_bootstrap_grace_seconds)

    def handle_worker_timeout(
        self,
        exit_hub_id: UUID,
        req: ExitHubDeployRequest,
        *,
        timeout_seconds: int,
    ) -> None:
        """Called when an async worker exceeds its allotted time."""
        reason = f"Deployment timed out after {timeout_seconds}s"
        record = self.repository.get_exit_hub(str(exit_hub_id)) or {}
        metadata = record.get('metadata') or {}
        instance_id = record.get('instance_id')
        node = None
        if metadata:
            try:
                node = self._node_from_record(metadata)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Unable to reconstruct node for %s: %s", exit_hub_id, exc)
        if node is None:
            try:
                node = self._create_node(req)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Unable to recreate node config for %s: %s", exit_hub_id, exc)
        cleanup_failed_exit_hub(
            node=node,
            instance_id=instance_id,
            origin_id=req.origin_id,
            emn_ip=req.emn_ip,
            miner_id=req.miner_id,
            shard_id=req.shard_id,
            lifecycle=self.lifecycle,
        )
        # Cleanup TPM-created shard if applicable
        self._cleanup_tpm_created_shard(
            exit_hub_id=exit_hub_id,
            metadata=metadata,
            miner_id=record.get('miner_id') or req.miner_id,
            miner_ip=record.get('miner_ip') or req.emn_ip,
        )
        self.repository.update_exit_hub(
            exit_hub_id,
            status='failed',
            instance_id=None,
            exit_hub_ip=None,
            last_error=reason
        )
        if req.client_id and req.origin_id:
            self.client_registry.mark_origin_failed(req.client_id, req.origin_id)
        self._notify_state_change(
            exit_hub_id=str(exit_hub_id),
            status='failed',
            client_id=req.client_id,
            origin_id=req.origin_id,
            miner_id=record.get('miner_id') or req.miner_id,
            miner_ip=record.get('miner_ip') or req.emn_ip,
            error=reason,
        )
        self._publish_metrics_snapshot(
            origin_id=req.origin_id,
            exit_hub_ip=record.get('exit_hub_ip'),
            status='failed',
            metadata={**metadata, 'error': reason},
        )
        logger.error(
            "Deployment %s aborted after exceeding %ss timeout",
            exit_hub_id,
            timeout_seconds,
        )

    def handle_worker_failure(
        self,
        exit_hub_id: UUID,
        req: ExitHubDeployRequest,
        error: Exception,
    ) -> None:
        """Shared failure handler for worker exceptions."""
        message = str(error)
        record = self.repository.get_exit_hub(str(exit_hub_id)) or {}
        metadata = record.get('metadata') or {}
        instance_id = record.get('instance_id')
        node = None
        if instance_id:
            try:
                node = self._node_from_record(metadata)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Unable to reconstruct node for %s: %s", exit_hub_id, exc)
            if node is None:
                try:
                    node = self._create_node(req)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Unable to recreate node for %s: %s", exit_hub_id, exc)
        if node and instance_id:
            self._safe_destroy_node(node, instance_id)

        # Cleanup TPM-created shard if applicable
        self._cleanup_tpm_created_shard(
            exit_hub_id=exit_hub_id,
            metadata=metadata,
            miner_id=record.get('miner_id') or req.miner_id,
            miner_ip=record.get('miner_ip') or req.emn_ip,
        )

        self.repository.update_exit_hub(
            exit_hub_id,
            status='failed',
            instance_id=None if instance_id else record.get('instance_id'),
            exit_hub_ip=None if instance_id else record.get('exit_hub_ip'),
            last_error=message,
        )

        if req.client_id and req.origin_id:
            self.client_registry.mark_origin_failed(req.client_id, req.origin_id)
            # Clear deployment fields to release shard slot
            self.origin_repository.clear_deployment(req.client_id, req.origin_id)

        # Wait for miner cleanup to complete - prevents orphaned AWS resources
        # Even during failure handling, we must wait to ensure EIPs are released
        miner_id = record.get('miner_id') or req.miner_id
        miner_ip = record.get('miner_ip') or req.emn_ip
        shard_id = record.get('shard_id') or req.shard_id
        if req.origin_id and miner_ip and miner_id:
            try:
                self.lifecycle.decommission_origin(
                    origin_id=req.origin_id,
                    emn_ip=miner_ip,
                    miner_id=miner_id,
                    shard_id=shard_id,
                    fire_and_forget=False,
                )
                logger.info("Miner cleanup completed for failed origin %s (shard_id=%s)", req.origin_id, shard_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not queue miner cleanup for %s: %s", req.origin_id, exc)

        self._notify_state_change(
            exit_hub_id=str(exit_hub_id),
            status='failed',
            client_id=req.client_id,
            origin_id=req.origin_id,
            miner_id=record.get('miner_id') or req.miner_id,
            miner_ip=record.get('miner_ip') or req.emn_ip,
            error=message,
        )
        self._publish_metrics_snapshot(
            origin_id=req.origin_id,
            exit_hub_ip=record.get('exit_hub_ip'),
            status='failed',
            metadata={**metadata, 'error': message},
        )
        logger.error("Deployment %s failed in worker: %s", exit_hub_id, message)

    @staticmethod
    def _build_exit_hub_ebpf() -> None:
        """Ensure SNAT eBPF object is compiled before bundling."""
        ebpf_dir = Path("configs/assets/exit_hub/ebpf")
        if not ebpf_dir.exists():
            return

        result = subprocess.run(
            ["make", "-C", str(ebpf_dir)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            error_output = (result.stderr or result.stdout or "unknown error")[:500]
            error_msg = f"eBPF build failed (exit {result.returncode}): {error_output}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

    def prepare_deploy(
        self,
        req: ExitHubDeployRequest
    ) -> tuple[UUID, ExitHubDeployRequest, Optional[int]]:
        """Assign identifiers and persist the initial exit-hub request."""
        client_id, origin_id, origin_num = self.client_registry.assign_client_and_origin(
            req.client_id,
            req.client_name,
            req.origin_id
        )
        req = self._resolve_miner_assignment(req, client_id, origin_id)
        self.client_registry.set_miner_assignment(client_id, origin_id, req.miner_id, req.emn_ip)

        placement_provider, placement_region, placement_reason = self._select_exit_hub_location(req)
        resolved_instance_type = self.provider_registry.resolve_instance_type(
            placement_provider,
            req.instance_type,
        )
        # Capture original requested region BEFORE model_copy overwrites it
        original_requested_region = req.region
        req = req.model_copy(
            update={
                "cloud_provider": placement_provider,
                "region": placement_region,
                "instance_type": resolved_instance_type,
            }
        )

        exit_hub_id = uuid4()
        logger.info(
            "Queued exit hub %s for origin %s (client=%s, requested_region=%s, placement_region=%s)",
            exit_hub_id,
            req.origin_id,
            req.client_id or "unknown",
            original_requested_region,
            placement_region,
        )
        self._record_initial_request(
            exit_hub_id,
            req,
            origin_num,
            placement_provider,
            placement_region,
            placement_reason,
            requested_region=original_requested_region,
        )
        self._notify_state_change(
            exit_hub_id=str(exit_hub_id),
            status='requested',
            client_id=req.client_id,
            origin_id=req.origin_id,
            miner_id=req.miner_id,
            miner_ip=req.emn_ip,
            metadata={
                **self._initial_metadata(req, origin_num, placement_provider, placement_region, placement_reason, requested_region=original_requested_region),
                "action": "deploy",
            },
        )
        return exit_hub_id, req, origin_num

    def deploy_exit_hub(
        self,
        req: ExitHubDeployRequest,
        *,
        exit_hub_id: Optional[UUID] = None,
        origin_num: Optional[int] = None,
        prepared: bool = False,
        cancel_checker: Optional[callable] = None,
    ) -> ExitHubResponse:
        """
        Deploy an exit hub and register it with Miner.

        Pattern: deploy → wait for SSH → upload assets → bootstrap → register.
        """
        if not req.miner_id or not req.emn_ip:
            raise ValueError("Miner assignment missing; cannot deploy without a registered miner")
        if prepared:
            if exit_hub_id is None:
                raise ValueError("Prepared deploy requires exit_hub_id")
        else:
            exit_hub_id, req, origin_num = self.prepare_deploy(req)

        self._build_exit_hub_ebpf()
        logger.info(
            "Deploying exit hub %s for origin %s (client=%s)",
            exit_hub_id,
            req.origin_id,
            req.client_id or "unknown",
        )

        # Helper to check cancellation if checker provided
        def _check_cancel():
            if cancel_checker:
                cancel_checker()

        node = self._create_node(req)
        try:
            result = self._deploy_with_timeout(node, exit_hub_id)
            logger.info("Exit hub instance %s created at %s", result.instance_id, result.public_ip)
            _check_cancel()  # Check after cloud deploy
        except DeploymentTimeoutError as exc:
            self._handle_initial_failure(exit_hub_id, req, origin_num, exc)
            raise
        except Exception as exc:  # noqa: BLE001
            self._handle_initial_failure(exit_hub_id, req, origin_num, exc)
            raise

        if not result.public_ip:
            message = (
                f"Exit hub {exit_hub_id} launched without public IP "
                f"(instance_id={result.instance_id})"
            )
            self._handle_initial_failure(exit_hub_id, req, origin_num, RuntimeError(message))
            raise RuntimeError(message)

        self.repository.update_exit_hub(
            exit_hub_id,
            status='deploying',
            instance_id=result.instance_id,
            exit_hub_ip=result.public_ip,
            miner_id=req.miner_id,
            miner_ip=req.emn_ip,
        )
        self.repository.update_metadata(
            exit_hub_id,
            {
                'cloud_provider': node.cloud_provider,
                'region': node.region,
                'instance_type': node.instance_type,
                'emn_ip': req.emn_ip,
                'miner_id': req.miner_id,
                'miner_ip': req.emn_ip,
                'action': 'deploy',
            }
        )
        self._notify_state_change(
            exit_hub_id=str(exit_hub_id),
            status='deploying',
            client_id=req.client_id,
            origin_id=req.origin_id,
            miner_id=req.miner_id,
            miner_ip=req.emn_ip,
            metadata={
                'instance_id': result.instance_id,
                'exit_hub_ip': result.public_ip,
                'cloud_provider': node.cloud_provider,
                'region': node.region,
                'instance_type': node.instance_type,
                'action': 'deploy',
            }
        )

        _check_cancel()  # Check before SSH provisioning

        try:
            self._provision_exit_hub(exit_hub_id, node, result.public_ip, req)
            _check_cancel()  # Check after SSH provisioning
            if self._bootstrap_grace_seconds:
                logger.info(
                    "Deployment %s: waiting %ss for exit hub services to stabilize",
                    exit_hub_id,
                    self._bootstrap_grace_seconds,
                )
                time.sleep(self._bootstrap_grace_seconds)
            _check_cancel()  # Check before miner registration
            lifecycle_result = self.lifecycle.register_exit_hub(
                exit_hub_id=exit_hub_id,
                request=req,
                exit_hub_ip=result.public_ip,
                instance_id=result.instance_id,
                ssh_username=node.provider.default_ssh_user
            )
        except MinerRegistrationTimeoutError as exc:
            self._handle_post_provision_failure(
                exit_hub_id,
                req,
                node,
                result,
                exc
            )
            raise DeploymentTimeoutError(str(exc)) from exc
        except DeploymentTimeoutError as exc:
            self._handle_post_provision_failure(
                exit_hub_id,
                req,
                node,
                result,
                exc
            )
            raise
        except Exception as exc:  # noqa: BLE001
            self._handle_post_provision_failure(
                exit_hub_id,
                req,
                node,
                result,
                exc
            )
            raise

        wg_interface = lifecycle_result.get('wg_interface') or f"wg-{req.origin_id}"
        secret = lifecycle_result.get('secret')
        response_metadata = lifecycle_result.get('metadata') or {}
        response_metadata['action'] = 'deploy'

        # Configure volume reporting agent on the exit hub
        self._configure_volume_agent(
            exit_hub_id=exit_hub_id,
            exit_hub_ip=result.public_ip,
            origin_id=req.origin_id,
            ssh_username=node.provider.default_ssh_user,
        )

        response = ExitHubResponse(
            exit_hub_id=exit_hub_id,
            client_id=req.client_id,
            instance_id=result.instance_id,
            exit_hub_ip=result.public_ip,
            origin_ip=req.origin_ip,
            origin_id=req.origin_id,
            wg_interface=wg_interface,
            region=node.region,
            instance_type=node.instance_type,
            status='active',
            secret=secret,
            miner_id=req.miner_id,
            miner_ip=req.emn_ip,
            metadata=response_metadata
        )
        self._ensure_response_identifiers(response)
        self._notify_state_change(
            exit_hub_id=str(exit_hub_id),
            status=response.status,
            client_id=response.client_id,
            origin_id=response.origin_id,
            miner_id=response.miner_id,
            miner_ip=response.miner_ip,
            metadata=response.metadata,
        )
        self._publish_metrics_snapshot(
            origin_id=response.origin_id,
            exit_hub_ip=response.exit_hub_ip,
            status=response.status,
            metadata=response.metadata,
        )
        return response

    def cancel_exit_hub(self, exit_hub_id: str) -> Dict[str, Any]:
        """Cancel an in-progress deployment and perform complete cleanup.

        This method:
        1. Registers cancellation with the worker pool (signals worker to abort)
        2. Sets status to 'cancelling' (prevents worker from overwriting)
        3. Destroys cloud instance if provisioned
        4. Decommissions origin from miner (removes from miner DB, BPF maps, WireGuard)
        5. Marks origin as terminated in client registry
        6. Deletes the exit_hub record from TPM database completely

        Returns:
            Dict with exit_hub_id, status, and action taken.
        """
        record = self.repository.get_exit_hub(exit_hub_id)
        if not record:
            raise ExitHubNotFoundError(exit_hub_id)

        current_status = record.get('status')
        client_id = record.get('client_id')
        origin_id = record.get('origin_id')
        miner_id = record.get('miner_id')
        metadata = record.get('metadata') or {}
        miner_ip = record.get('miner_ip') or metadata.get('emn_ip') or metadata.get('miner_ip')
        shard_id = record.get('shard_id') or metadata.get('shard_id')

        # Already in a terminal state? Still allow purge
        if current_status in {'cancelled', 'terminated', 'failed'}:
            # Purge the record completely
            self.repository.delete_exit_hub(exit_hub_id)
            logger.info("Purged already-terminal exit hub %s (was %s)", exit_hub_id, current_status)
            return {
                'exit_hub_id': exit_hub_id,
                'status': current_status,
                'action': 'purged',
                'message': f'Purged terminal record (was {current_status})'
            }

        logger.info(
            "Cancelling exit hub %s (status=%s, origin=%s, instance=%s)",
            exit_hub_id, current_status, origin_id, record.get('instance_id')
        )

        # 1. Register cancellation with worker pool to abort in-progress work
        from tensorprox.tpm.services.deploy_queue import deploy_queue
        deploy_queue.cancel_job(exit_hub_id)

        # 1b. Cancel any queued miner operations for this exit hub
        from tensorprox.tpm.services.miner_operation_queue import (
            get_miner_operation_queue,
        )
        miner_queue = get_miner_operation_queue()
        cancelled_ops = miner_queue.cancel_by_exit_hub(exit_hub_id)
        if cancelled_ops:
            logger.info(
                "Cancelled %d queued miner operations for exit hub %s",
                cancelled_ops,
                exit_hub_id,
            )

        # 2. Set status to 'cancelling' (use force=True to ensure it sticks)
        self.repository.update_exit_hub(exit_hub_id, status='cancelling', force=True)
        self._notify_state_change(
            exit_hub_id=exit_hub_id,
            status='cancelling',
            client_id=client_id,
            origin_id=origin_id,
            miner_id=miner_id,
            miner_ip=miner_ip,
            metadata={'action': 'cancel', 'previous_status': current_status},
        )

        errors: list[str] = []

        # 3. Destroy cloud instance if it exists
        instance_id = record.get('instance_id')
        if instance_id:
            logger.info("Destroying cloud instance %s for cancelled exit hub %s", instance_id, exit_hub_id)
            try:
                node = self._node_from_record(metadata)
                destroyed = node.destroy(instance_id)
                if destroyed:
                    logger.info("Cloud instance %s destroyed successfully", instance_id)
                else:
                    logger.warning("Destroy returned false for instance %s (may already be gone)", instance_id)
            except Exception as exc:  # noqa: BLE001
                message = str(exc)
                if "not found" in message.lower() or "invalidinstanceid" in message.lower():
                    logger.info("Instance %s already gone: %s", instance_id, message)
                else:
                    logger.error("Failed to destroy instance %s: %s", instance_id, exc)
                    errors.append(f"cloud_destroy:{exc}")

        # 4. Decommission origin from miner (always attempt if we have origin_id and miner_ip)
        if origin_id and miner_ip:
            logger.info("Decommissioning origin %s from miner %s (shard_id=%s)", origin_id, miner_ip, shard_id)
            try:
                miner_result = self.lifecycle.decommission_origin(
                    origin_id=origin_id,
                    emn_ip=miner_ip,
                    miner_id=miner_id,
                    shard_id=shard_id,
                )
                logger.info("Miner decommission for origin %s: %s", origin_id, miner_result)
            except Exception as exc:  # noqa: BLE001
                # Log but don't fail cancel - origin may not have been registered yet
                message = str(exc)
                if "not found" in message.lower() or "404" in message:
                    logger.info("Origin %s not found in miner (not yet registered): %s", origin_id, message)
                else:
                    logger.warning("Miner decommission failed for origin %s: %s", origin_id, exc)
                    errors.append(f"miner_cleanup:{exc}")

        # 5. Mark origin as terminated in client registry
        if client_id and origin_id:
            try:
                self.client_registry.mark_origin_terminated(client_id, origin_id)
                logger.info("Marked origin %s as terminated in client registry", origin_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to mark origin %s terminated: %s", origin_id, exc)

        # 6. Emit cancelled status before deleting record
        self._notify_state_change(
            exit_hub_id=exit_hub_id,
            status='cancelled',
            client_id=client_id,
            origin_id=origin_id,
            miner_id=miner_id,
            miner_ip=miner_ip,
            metadata={'action': 'cancel', 'cleanup_errors': errors if errors else None},
            error="; ".join(errors) if errors else None,
        )

        # 7. Mark exit_hub for deferred deletion (allows webapp to receive notification)
        try:
            purge_time = datetime.now(timezone.utc) + timedelta(hours=1)
            self.repository.mark_for_purge(exit_hub_id, purge_time)
            logger.info(
                "Exit hub %s marked for purge after %s",
                exit_hub_id, purge_time.isoformat()
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to mark exit hub %s for purge: %s", exit_hub_id, exc)
            errors.append(f"db_purge_mark:{exc}")

        # Clear from cancellation registry
        deploy_queue.clear_cancelled(exit_hub_id)

        logger.info(
            "Exit hub %s cancel complete: instance=%s, origin=%s, errors=%s",
            exit_hub_id, instance_id or "none", origin_id, errors or "none"
        )

        return {
            'exit_hub_id': exit_hub_id,
            'status': 'cancelled',
            'action': 'cancelled',
            'cleanup_errors': errors if errors else None
        }

    def terminate_exit_hub(self, exit_hub_id: str, purge: bool = False) -> Dict[str, Any]:
        """Destroy exit hub instance, notify Miner, and archive/purge DB record."""
        record = self.repository.get_exit_hub(exit_hub_id)
        if not record:
            raise ExitHubNotFoundError(exit_hub_id)

        client_id = record.get('client_id')
        origin_id = record.get('origin_id')

        if record.get('status') == 'terminated':
            # Ensure origin is also terminated (idempotent cleanup)
            if client_id and origin_id:
                self.client_registry.mark_origin_terminated(client_id, origin_id)
                self.origin_repository.clear_deployment(client_id, origin_id)
            if purge:
                self.repository.delete_exit_hub(exit_hub_id)
                return {'exit_hub_id': exit_hub_id, 'status': 'terminated', 'purged': True}
            return {'exit_hub_id': exit_hub_id, 'status': 'terminated', 'purged': False}

        metadata = record.get('metadata') or {}
        logger.info("Terminating exit hub %s (purge=%s)", exit_hub_id, purge)
        miner_id = record.get('miner_id')
        miner_ip = record.get('miner_ip') or metadata.get('emn_ip') or metadata.get('miner_ip')
        shard_id = record.get('shard_id') or metadata.get('shard_id')
        base_meta = {**metadata, "action": "terminate"}

        def _emit(status: str, meta: Optional[Dict[str, Any]] = None, error: Optional[str] = None) -> None:
            merged_meta = {**base_meta, **(meta or {})}
            # force=True bypasses terminal status protection (needed for re-terminating failed exit_hubs)
            self.repository.update_exit_hub(exit_hub_id, status=status, last_error=error, force=True)
            self._notify_state_change(
                exit_hub_id=exit_hub_id,
                status=status,
                client_id=client_id,
                origin_id=origin_id,
                miner_id=miner_id,
                miner_ip=miner_ip,
                metadata=merged_meta,
                error=error,
            )

        _emit("teardown_requested")
        _emit("draining")

        errors: list[str] = []
        status = 'failed'
        last_error = None
        purged = False

        try:
            instance_id = record.get('instance_id')
            if instance_id:
                _emit("cloud_destroy")
                try:
                    node = self._node_from_record(metadata)
                    destroyed = node.destroy(instance_id)
                    if destroyed:
                        logger.info("Exit hub %s cloud instance %s destroyed", exit_hub_id, instance_id)
                    else:
                        logger.warning(
                            "Destroy returned false for exit hub %s (instance %s); assuming already gone",
                            exit_hub_id,
                            instance_id,
                        )
                except Exception as exc:  # noqa: BLE001
                    message = str(exc)
                    if "not found" in message.lower() or "invalidinstanceid" in message.lower():
                        logger.warning(
                            "Instance %s already absent during destroy for exit hub %s: %s",
                            instance_id,
                            exit_hub_id,
                            message,
                        )
                    else:
                        logger.error("Failed to destroy exit hub %s: %s", exit_hub_id, exc, exc_info=True)
                        errors.append(f"cloud_destroy_exception:{exc}")
                finally:
                    # clear instance_id/exit_hub_ip to avoid retry overlap
                    self.repository.update_exit_hub(exit_hub_id, instance_id=None, exit_hub_ip=None)
            else:
                logger.warning("No instance_id recorded for exit hub %s", exit_hub_id)

            _emit("miner_cleanup")
            try:
                # CRITICAL: Wait for miner cleanup to complete (includes EIP release)
                # fire_and_forget=False prevents orphaned AWS resources (EIPs, BPF entries)
                # The 20-minute timeout in decommission_origin handles slow cross-region ops
                miner_result = self.lifecycle.decommission_origin(
                    origin_id=record['origin_id'],
                    emn_ip=miner_ip,
                    miner_id=miner_id,
                    shard_id=shard_id,
                    fire_and_forget=False,
                )
                logger.info(
                    "Miner teardown queued for origin %s via %s (shard_id=%s, result=%s)",
                    record['origin_id'],
                    miner_ip,
                    shard_id,
                    miner_result,
                )
            except Exception as exc:  # noqa: BLE001
                message = str(exc)
                # "not found" or 404 means origin was already deleted from miner - not an error
                if "not found" in message.lower() or "404" in message:
                    logger.info(
                        "Origin %s already gone from miner (not found): %s",
                        record['origin_id'], message
                    )
                else:
                    logger.error("Failed to queue miner teardown for origin %s: %s", record['origin_id'], exc)
                    errors.append(f"miner_cleanup:{exc}")

            metadata_updates = {
                'terminated_at': datetime.now(timezone.utc).isoformat(),
                'action': 'terminate',
            }
            if errors:
                metadata_updates['termination_errors'] = errors

            self.repository.update_metadata(exit_hub_id, metadata_updates)

            status = 'terminated' if not errors else 'failed'
            last_error = "; ".join(errors) if errors else None
            self.repository.update_exit_hub(
                exit_hub_id,
                status=status,
                secret=None,
                wg_interface=None,
                last_error=last_error,
                force=True  # Bypass terminal status protection for re-terminating failed exit_hubs
            )

            if client_id and origin_id:
                if status == 'terminated':
                    self.client_registry.mark_origin_terminated(client_id, origin_id)
                    # Clear deployment fields from origin
                    self.origin_repository.clear_deployment(client_id, origin_id)
                else:
                    self.client_registry.mark_origin_failed(client_id, origin_id)

            self._publish_metrics_snapshot(
                origin_id=origin_id,
                exit_hub_ip=record.get('exit_hub_ip'),
                status=status,
                metadata={**(record.get('metadata') or {}), **metadata_updates},
            )

            if purge and not errors:
                # Deferred purge: mark for deletion after 1 hour
                # This ensures webapp has time to receive the notification
                purge_time = datetime.now(timezone.utc) + timedelta(hours=1)
                self.repository.mark_for_purge(exit_hub_id, purge_time)
                purged = True  # Will be purged by background sweeper
                logger.info(
                    "Exit hub %s marked for purge after %s",
                    exit_hub_id, purge_time.isoformat()
                )
        finally:
            # Emit final status (use the computed status variable, not a hardcoded "terminating")
            _emit(status, error=last_error)
            # Always emit final notifier so subscribers see terminal state
            self._notify_state_change(
                exit_hub_id=exit_hub_id,
                status=status,
                client_id=client_id,
                origin_id=origin_id,
                miner_id=miner_id,
                miner_ip=miner_ip,
                metadata={**metadata, "action": "terminate"},
                error=last_error,
            )
            logger.info(
                "Terminate exit hub %s completed with status=%s errors=%s",
                exit_hub_id,
                status,
                errors,
            )

        return {
            'exit_hub_id': exit_hub_id,
            'status': status,
            'purged': purged,
            'errors': errors,
        }

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _deploy_with_timeout(self, node: Node, exit_hub_id: UUID) -> InstanceCreateResult:
        """Execute node.deploy with a bounded timeout."""
        logger.info(
            "Exit hub %s: starting cloud provision (timeout=%ss, provider=%s, region=%s, size=%s)",
            exit_hub_id,
            self._deploy_timeout,
            node.cloud_provider,
            node.region,
            node.instance_type,
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                node.deploy,
                skip_asset_embedding=True,
                tags={'exit_hub_id': str(exit_hub_id)},
            )
            try:
                return future.result(timeout=self._deploy_timeout)
            except FutureTimeoutError as exc:
                future.cancel()
                logger.error(
                    "Exit hub %s: cloud provisioning timed out after %ss",
                    exit_hub_id,
                    self._deploy_timeout,
                )
                raise DeploymentTimeoutError(
                    f"Cloud provisioning timed out after {self._deploy_timeout} seconds"
                ) from exc
            except Exception as exc:
                error_str = str(exc)
                # Check for region capacity exhaustion errors
                # AWS: "Failed to launch instance in any AZ in {region}"
                # Also check for vCPU/EIP quota errors
                if any(pattern in error_str for pattern in [
                    "Failed to launch instance in any AZ",
                    "InsufficientInstanceCapacity",
                    "VcpuLimitExceeded",
                    "AddressLimitExceeded",
                ]):
                    logger.warning(
                        "Exit hub %s: region %s capacity exhausted: %s",
                        exit_hub_id,
                        node.region,
                        error_str,
                    )
                    raise RegionCapacityExhaustedError(
                        f"Region {node.region} capacity exhausted: {error_str}",
                        region=node.region,
                        provider=node.cloud_provider,
                    ) from exc
                # Re-raise other errors
                raise

    def _record_initial_request(
        self,
        exit_hub_id: UUID,
        req: ExitHubDeployRequest,
        origin_num: Optional[int],
        exit_provider: Optional[str],
        exit_region: Optional[str],
        placement_reason: Optional[str],
        requested_region: Optional[str] = None,
    ) -> None:
        """Persist an initial record so state exists even if deploy fails early."""
        self.repository.create_exit_hub(
            exit_hub_id=exit_hub_id,
            client_id=req.client_id,
            origin_id=req.origin_id,
            origin_ip=req.origin_ip,
            status='requested',
            miner_id=req.miner_id,
            miner_ip=req.emn_ip,
            metadata=self._initial_metadata(req, origin_num, exit_provider, exit_region, placement_reason, requested_region)
        )
        # Store exit_hub_id in origin for reliable termination notification
        if req.origin_id:
            try:
                self.origin_repository.set_last_exit_hub_id(req.origin_id, str(exit_hub_id))
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to store last_exit_hub_id for origin %s: %s",
                    req.origin_id, exc
                )

    @staticmethod
    def _initial_metadata(
        req: ExitHubDeployRequest,
        origin_num: Optional[int],
        exit_provider: Optional[str] = None,
        exit_region: Optional[str] = None,
        placement_reason: Optional[str] = None,
        requested_region: Optional[str] = None,
    ) -> Dict[str, Any]:
        provider = exit_provider or req.cloud_provider
        region = exit_region or req.region
        reason = placement_reason or (f"requested:{provider}/{region}" if provider and region else "unspecified")
        # Use explicit requested_region if provided, otherwise fall back to req.region
        # This is needed because req.region may be overwritten with placement_region
        original_requested_region = requested_region if requested_region is not None else req.region
        return {
            'client_id': req.client_id,
            'emn_ip': req.emn_ip,
            'requested_region': original_requested_region,
            'requested_instance_type': req.instance_type,
            'requested_cloud_provider': req.cloud_provider,
            'ports': req.ports,
            'origin_num': origin_num,
            'miner_id': req.miner_id,
            'miner_ip': req.emn_ip,
            'exit_provider': provider,
            'exit_region': region,
            'placement_reason': reason,
        }

    def _create_node(self, req: ExitHubDeployRequest) -> Node:
        """Create Node instance with template variables for bootstrap."""
        return self.node_factory.build_exit_hub_node(req)

    def _select_exit_hub_location(self, req: ExitHubDeployRequest) -> tuple[str, str, str]:
        """Determine exit hub provider/region. Exit hub MUST use same provider as miner's scrubbers."""
        miner_record = None
        if req.miner_id:
            try:
                miner_record = self.miner_registry.repository.get_miner(req.miner_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Unable to load miner %s for placement: %s", req.miner_id, exc)

        miner_provider = (miner_record or {}).get("metadata", {}).get("provider")
        miner_region = (miner_record or {}).get("metadata", {}).get("region")

        # CRITICAL: Exit hub MUST use same provider as miner's scrubbers.
        # Miner's provider is authoritative - request's cloud_provider is ignored if miner is assigned.
        # NOTE: Only AWS is currently supported for scrubbers (Linode not implemented).
        if miner_provider:
            resolved_provider = miner_provider.lower()
            if resolved_provider not in SCRUBBER_SUPPORTED_PROVIDERS:
                raise ValueError(
                    f"Miner {req.miner_id} has unsupported scrubber provider '{resolved_provider}'. "
                    f"Only AWS is currently supported. Supported: {list(SCRUBBER_SUPPORTED_PROVIDERS)}"
                )
            if req.cloud_provider and req.cloud_provider.lower() != resolved_provider:
                logger.info(
                    "Ignoring requested provider %s - enforcing miner's scrubber provider %s",
                    req.cloud_provider,
                    resolved_provider,
                )
        else:
            # No miner assigned yet (edge case), fall back to request or default
            resolved_provider = self.provider_registry.resolve_provider(req.cloud_provider, None)

        default_region = self.provider_registry.resolve_region(resolved_provider, None, None)

        # Geolocate origin IP to find best region if not explicitly specified
        geolocated_region = None
        if not req.region and req.origin_ip:
            available_regions = self.miner_registry.get_all_available_regions()
            # Fallback to all known provider regions if miners have no validation data
            if not available_regions:
                available_regions = get_all_regions(resolved_provider)
                logger.info(
                    "No miner validation regions available, using all known %s regions (%d)",
                    resolved_provider,
                    len(available_regions),
                )
            if available_regions:
                geolocated_region = find_best_region_for_ip(
                    req.origin_ip,
                    available_regions,
                    provider=resolved_provider,
                    fallback_region=default_region,
                )
                logger.info(
                    "Geolocated origin %s to region %s (from %d available)",
                    req.origin_ip,
                    geolocated_region,
                    len(available_regions),
                )

        # Region priority: explicit request > geolocation > miner metadata > default
        # Provider is always from miner (scrubber provider matching)
        effective_region = req.region or geolocated_region
        resolved_region = self.provider_registry.resolve_region(
            resolved_provider, effective_region, miner_region
        )

        # Build reason string - provider always follows miner's scrubber provider
        if miner_provider:
            if req.region:
                reason = f"scrubber_match:{resolved_provider}/requested_region:{req.region}"
            elif geolocated_region:
                reason = f"scrubber_match:{resolved_provider}/geolocated:{geolocated_region}"
            elif miner_region:
                reason = f"scrubber_match:{miner_provider}/{miner_region}"
            else:
                reason = f"scrubber_match:{resolved_provider}/{default_region}"
        elif geolocated_region:
            reason = f"geolocated:{resolved_provider}/{geolocated_region}"
        else:
            reason = f"default:{resolved_provider}/{default_region}"

        return select_exit_hub_location(
            miner_record=miner_record,
            requested_provider=resolved_provider,
            requested_region=resolved_region,
            default_provider=resolved_provider,
            default_region=default_region,
        )


    def _handle_initial_failure(
        self,
        exit_hub_id: UUID,
        req: ExitHubDeployRequest,
        origin_num: Optional[int],
        error: Exception
    ) -> None:
        logger.error("Exit hub %s provisioning failed: %s", exit_hub_id, error, exc_info=True)
        self.repository.update_exit_hub(
            exit_hub_id,
            status='failed',
            last_error=str(error)
        )
        if req.client_id and req.origin_id:
            self.client_registry.mark_origin_failed(req.client_id, req.origin_id)
        metadata = self._initial_metadata(req, origin_num, req.cloud_provider, req.region, None)
        self._notify_state_change(
            exit_hub_id=str(exit_hub_id),
            status='failed',
            client_id=req.client_id,
            origin_id=req.origin_id,
            miner_id=req.miner_id,
            miner_ip=req.emn_ip,
            metadata=metadata,
            error=str(error),
        )
        self._publish_metrics_snapshot(
            origin_id=req.origin_id,
            exit_hub_ip=None,
            status='failed',
            metadata={**metadata, 'error': str(error)},
        )
        cleanup_failed_exit_hub(
            node=None,
            instance_id=None,
            origin_id=req.origin_id,
            emn_ip=req.emn_ip,
            miner_id=req.miner_id,
            shard_id=req.shard_id,
            lifecycle=self.lifecycle,
        )

    def _handle_post_provision_failure(
        self,
        exit_hub_id: UUID,
        req: ExitHubDeployRequest,
        node: Node,
        result: InstanceCreateResult,
        error: Exception
    ) -> None:
        logger.error("Exit hub %s deployment failed: %s", exit_hub_id, error, exc_info=True)
        self.repository.update_exit_hub(
            exit_hub_id,
            status='failed',
            last_error=str(error)
        )
        if req.client_id and req.origin_id:
            self.client_registry.mark_origin_failed(req.client_id, req.origin_id)
        cleanup_failed_exit_hub(
            node=node,
            instance_id=result.instance_id,
            origin_id=req.origin_id,
            emn_ip=req.emn_ip,
            miner_id=req.miner_id,
            shard_id=req.shard_id,
            lifecycle=self.lifecycle,
        )
        self._notify_state_change(
            exit_hub_id=str(exit_hub_id),
            status='failed',
            client_id=req.client_id,
            origin_id=req.origin_id,
            miner_id=req.miner_id,
            miner_ip=req.emn_ip,
            error=str(error),
        )
        self._publish_metrics_snapshot(
            origin_id=req.origin_id,
            exit_hub_ip=result.public_ip,
            status='failed',
            metadata={'emn_ip': req.emn_ip, 'error': str(error)},
        )
        # Cleanup TPM-created shard if applicable (before deleting record)
        current_record = self.repository.get_exit_hub(str(exit_hub_id))
        if current_record:
            current_metadata = current_record.get('metadata') or {}
            self._cleanup_tpm_created_shard(
                exit_hub_id=exit_hub_id,
                metadata=current_metadata,
                miner_id=req.miner_id,
                miner_ip=req.emn_ip,
            )
        # Mark for deferred purge (allows webapp to receive failure notification)
        try:
            purge_time = datetime.now(timezone.utc) + timedelta(hours=1)
            self.repository.mark_for_purge(str(exit_hub_id), purge_time)
            logger.info(
                "Failed exit hub %s marked for purge after %s",
                exit_hub_id, purge_time.isoformat()
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unable to mark failed exit hub %s for purge: %s", exit_hub_id, exc)

    def _provision_exit_hub(
        self,
        exit_hub_id: UUID,
        node: Node,
        public_ip: str,
        req: ExitHubDeployRequest
    ) -> None:
        """Upload assets and execute bootstrap script."""
        try:
            logger.info(
                "Deployment %s: waiting for SSH on %s",
                exit_hub_id,
                public_ip
            )
            node.wait_for_ssh(
                host=public_ip,
                max_attempts=24,
                interval=5,
                timeout=10,
                deadline_seconds=self._ssh_wait_timeout,
            )
            logger.info("Deployment %s: SSH ready for %s", exit_hub_id, public_ip)

            bundle = node.create_asset_bundle()
            if bundle:
                try:
                    logger.info(
                        "Deployment %s: uploading bootstrap assets to %s",
                        exit_hub_id,
                        public_ip
                    )
                    provision_success, provision_error = node.post_provision(
                        public_ip,
                        bundle,
                        command_timeout=self._post_provision_timeout,
                    )
                    if not provision_success:
                        raise RuntimeError(provision_error or "Post-provision failed")
                    logger.info("Deployment %s: asset upload complete", exit_hub_id)
                finally:
                    os.unlink(bundle)
            else:
                logger.info("Deployment %s: no asset bundle required", exit_hub_id)

            env_vars = {
                'ORIGIN_IP': req.origin_ip,
                'ORIGIN_ID': req.origin_id,
                'EMN_IP': req.emn_ip,
                'PORTS_JSON': json.dumps(req.ports),
            }

            logger.info("Deployment %s: executing bootstrap on %s", exit_hub_id, public_ip)
            success, output = node.execute_bootstrap(
                instance_ip=public_ip,
                env_vars=env_vars,
                timeout=self._post_provision_timeout,
            )
            if not success:
                raise RuntimeError(f"Bootstrap failed for exit hub {public_ip}: {output}")

            logger.info("Deployment %s: bootstrap complete on %s", exit_hub_id, public_ip)
        except TimeoutError as exc:
            raise DeploymentTimeoutError(str(exc)) from exc
        except Exception:
            raise

    def _node_from_record(self, metadata: Dict[str, Any]) -> Node:
        """Recreate a Node object using stored metadata for termination."""
        return Node(
            node_type="exit_hub",
            region=metadata.get('region') or metadata.get('requested_region'),
            instance_type=metadata.get('instance_type') or metadata.get('requested_instance_type'),
            cloud_provider=metadata.get('cloud_provider') or metadata.get('requested_cloud_provider'),
        )

    def _resolve_miner_assignment(
        self,
        req: ExitHubDeployRequest,
        client_id: Optional[str],
        origin_id: Optional[str],
    ) -> ExitHubDeployRequest:
        """Select a miner for deployment using validator-based scoring.

        Selection Strategy:
        1) If miner_id provided → validate and use it (explicit override)
        2) If emn_ip provided → map to registered miner
        3) Use AssignmentEngine for smart selection:
           - EMA scores from validators
           - Region proximity (nearest region fallback)
           - Availability status
           - Load balancing
        4) Fallback to simple last_seen if no subnet_miners data

        The AssignmentEngine queries the subnet_miners table which is populated
        by validators syncing their leaderboard data via /miners/leaderboard/sync.
        """
        miner_id = req.miner_id
        miner_ip = req.emn_ip

        def apply_record(record: Dict[str, object]):
            nonlocal miner_id, miner_ip
            if record.get("miner_id"):
                miner_id = str(record["miner_id"])
            # Use get_miner_connection_info to properly extract emn_ip from metadata
            ip, _ = get_miner_connection_info(record)
            if ip:
                miner_ip = ip

        # If miner_id explicitly provided, validate and hydrate IP
        if miner_id:
            normalized = normalize_miner_id(miner_id)
            record = self.miner_registry.repository.get_miner(normalized)
            if not record:
                raise ValueError(f"miner_id {normalized} not found")
            miner_id = normalized
            if not miner_ip:
                apply_record(record)
            logger.info("Using explicitly provided miner_id: %s", miner_id)

        # If IP provided, try matching active miner
        if not miner_id and miner_ip:
            for record in self.miner_registry.list_active_miners():
                # Check both current_ip and emn_ip from metadata
                record_ip, _ = get_miner_connection_info(record)
                if record_ip == miner_ip or str(record.get("current_ip")) == miner_ip:
                    apply_record(record)
                    logger.info("Resolved miner_id from IP: %s -> %s", miner_ip, miner_id)
                    break

        # Auto-select using AssignmentEngine (validator scores, region, availability)
        if not miner_id or not miner_ip:
            selected_miner = self._select_miner_with_assignment_engine(
                origin_ip=req.origin_ip,
                preferred_region=req.region,
                cloud_provider=req.cloud_provider,
            )

            if selected_miner:
                # AssignmentEngine found a miner
                if selected_miner.miner_id:
                    miner_id = selected_miner.miner_id
                if selected_miner.scrubber_ip:
                    miner_ip = selected_miner.scrubber_ip

                logger.info(
                    "AssignmentEngine selected miner UID %d (miner_id=%s, ema=%.3f, region=%s)",
                    selected_miner.miner_uid,
                    miner_id,
                    selected_miner.ema_score,
                    selected_miner.region or 'any',
                )

        # Fallback: simple last_seen selection from miner_registry
        if not miner_id or not miner_ip:
            logger.warning(
                "AssignmentEngine unavailable or returned no miner, "
                "falling back to simple miner_registry selection"
            )
            active = self.miner_registry.list_active_miners()
            if active:
                apply_record(active[0])
                logger.info("Fallback selected miner_id: %s (from miner_registry)", miner_id)

        # Validate selected miner has active shards (deployed infrastructure)
        # If not, select a miner that DOES have shards to avoid assignment to unavailable miners
        if miner_id:
            shard_repo = ShardRepository()
            miners_with_shards = set(shard_repo.get_miners_with_active_shards())

            if miner_id not in miners_with_shards:
                logger.warning(
                    "Selected miner %s has no active shards, looking for alternative",
                    miner_id[:8] if miner_id else "None"
                )
                # Find first active miner that HAS shards
                for record in self.miner_registry.list_active_miners():
                    candidate_id = str(record.get("miner_id", ""))
                    if candidate_id in miners_with_shards:
                        logger.info(
                            "Re-assigning from miner %s (no shards) to %s (has shards)",
                            miner_id[:8] if miner_id else "None",
                            candidate_id[:8],
                        )
                        apply_record(record)
                        break
                else:
                    # No miners with shards - let deployment proceed (will create new shard)
                    logger.warning(
                        "No miners have active shards. Deployment will create new shard on %s",
                        miner_id[:8] if miner_id else "None"
                    )

        # Final validation
        if miner_id:
            try:
                miner_id = normalize_miner_id(miner_id)
            except MinerSecretInvalidError as exc:
                raise ValueError(f"Invalid miner_id provided: {exc}") from exc

        if not miner_ip:
            raise ValueError("No reachable miner available (emn_ip not resolved)")

        return req.model_copy(
            update={
                'client_id': client_id,
                'origin_id': origin_id,
                'miner_id': miner_id,
                'emn_ip': miner_ip,
            }
        )

    def _select_miner_with_assignment_engine(
        self,
        origin_ip: Optional[str],
        preferred_region: Optional[str],
        cloud_provider: Optional[str] = None,
    ) -> Optional[Any]:
        """Use AssignmentEngine to select best miner based on validator data.

        Args:
            origin_ip: Origin server IP (for geolocation-based region selection)
            preferred_region: Explicitly requested region (overrides geolocation)
            cloud_provider: Cloud provider hint (aws, linode, etc.) - auto-detected if not specified

        Returns:
            MinerCandidate if found, None if no suitable miner or engine unavailable
        """
        try:
            # Determine cloud provider (from hint, region, or default)
            provider = cloud_provider
            if not provider and preferred_region:
                provider = infer_provider_from_region(preferred_region)
            if not provider:
                provider = "aws"  # Default fallback

            # Determine preferred region
            region = preferred_region
            if not region and origin_ip:
                # Geolocate origin IP to find best region using all known regions for provider
                all_regions = get_all_regions(provider)
                region = find_best_region_for_ip(
                    ip=origin_ip,
                    available_regions=all_regions,
                    provider=provider,
                    fallback_region="us-west-2" if provider == "aws" else "us-west",
                )
                logger.debug("Geolocated origin IP %s to region: %s (provider: %s, %d regions)", origin_ip, region, provider, len(all_regions))

            # Create assignment request
            assignment_request = AssignmentRequest(
                origin_id="pending",  # Will be set later
                origin_ip=origin_ip or "0.0.0.0",
                preferred_region=region,
            )

            # Get database connection and create engine
            db_conn = get_tp_db_connection()
            engine = AssignmentEngine(db_conn)

            # Select best miner
            miner = engine.select_best_miner(
                request=assignment_request,
                provider=provider,
            )

            return miner

        except Exception as e:
            logger.warning(
                "AssignmentEngine selection failed (will use fallback): %s",
                str(e),
            )
            return None

    @staticmethod
    def _ensure_response_identifiers(response: ExitHubResponse) -> None:
        """Guard against returning partial mappings to callers."""
        required_fields = {
            'client_id': response.client_id,
            'origin_id': response.origin_id,
            'miner_id': response.miner_id,
            'miner_ip': response.miner_ip,
            'exit_hub_id': response.exit_hub_id,
            'instance_id': response.instance_id,
            'exit_hub_ip': response.exit_hub_ip,
        }
        missing = [name for name, value in required_fields.items() if value in (None, "")]
        if missing:
            logger.error(
                "Exit hub response missing required identifiers: %s (exit_hub_id=%s)",
                ', '.join(missing),
                response.exit_hub_id
            )
            raise RuntimeError(f"Incomplete exit hub response: missing {', '.join(missing)}")

    @staticmethod
    def _safe_destroy_node(node: Node, instance_id: Optional[str]) -> None:
        if not instance_id:
            return
        try:
            logger.info("Attempting to destroy cloud instance %s", instance_id)
            destroyed = node.destroy(instance_id)
            if destroyed:
                logger.info("Cloud instance %s destroyed", instance_id)
            else:
                logger.warning("Cloud instance %s could not be destroyed cleanly", instance_id)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Exception while destroying instance %s: %s",
                instance_id,
                exc,
                exc_info=True,
            )

    def _cleanup_tpm_created_shard(
        self,
        exit_hub_id: UUID,
        metadata: Dict[str, Any],
        miner_id: Optional[str],
        miner_ip: Optional[str],
    ) -> None:
        """Clean up TPM-created shards that have no origins after deployment failure.

        If TPM created a shard for this deployment and the origin registration
        ultimately failed, attempt to delete the empty shard from the miner.

        Policy:
        - Only cleanup shards created by TPM (metadata flag: shard_created_by_tpm=True)
        - Only cleanup if shard has origins_count=0 and deploy.state in {succeeded, none}
        - DELETE call is defensive: 404/501 are logged but not fatal

        Args:
            exit_hub_id: The exit hub that failed
            metadata: Exit hub metadata (may contain shard info)
            miner_id: Miner ID for authentication
            miner_ip: Miner IP address
        """
        if not metadata.get('shard_created_by_tpm'):
            logger.debug(
                "Exit hub %s: shard cleanup skipped (not created by TPM)",
                exit_hub_id
            )
            return

        shard_id = metadata.get('shard_id')
        if not shard_id:
            logger.debug(
                "Exit hub %s: shard cleanup skipped (no shard_id in metadata)",
                exit_hub_id
            )
            return

        if not miner_ip:
            logger.warning(
                "Exit hub %s: cannot cleanup shard %s (no miner_ip available)",
                exit_hub_id,
                shard_id
            )
            return

        logger.info(
            "Exit hub %s: checking if TPM-created shard %s should be cleaned up",
            exit_hub_id,
            shard_id
        )

        # Get authentication headers
        headers = None
        if miner_id:
            try:
                secret = self.miner_registry.get_plaintext_secret(miner_id)
                headers = {"Authorization": f"Bearer {secret}"}
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Exit hub %s: unable to get miner secret for shard cleanup: %s",
                    exit_hub_id,
                    exc
                )

        # Query miner shards to check if our shard is empty
        shards_url = f"http://{miner_ip}:{self.settings.miner_port}/api/v1/admin/shards"
        try:
            logger.debug(
                "Exit hub %s: querying miner shards at %s",
                exit_hub_id,
                shards_url
            )
            response = requests.get(shards_url, headers=headers, timeout=(5, 10))

            if response.status_code == 404:
                logger.info(
                    "Exit hub %s: miner shards endpoint not found (404) - "
                    "skipping shard cleanup",
                    exit_hub_id
                )
                return

            if response.status_code >= 400:
                logger.warning(
                    "Exit hub %s: failed to query miner shards (%s): %s",
                    exit_hub_id,
                    response.status_code,
                    response.text[:200]
                )
                return

            shards_data = response.json()
            shards = shards_data.get('shards', [])

            # Find our shard
            target_shard = None
            for shard in shards:
                if shard.get('shard_id') == shard_id:
                    target_shard = shard
                    break

            if not target_shard:
                logger.info(
                    "Exit hub %s: shard %s not found in miner "
                    "(may have been cleaned up already)",
                    exit_hub_id,
                    shard_id
                )
                return

            origins_count = target_shard.get('origins_count', -1)
            deploy_state = target_shard.get('deploy', {}).get('state', 'unknown')

            logger.info(
                "Exit hub %s: shard %s status: origins_count=%s, deploy.state=%s",
                exit_hub_id,
                shard_id,
                origins_count,
                deploy_state
            )

            # Check cleanup conditions
            if origins_count != 0:
                logger.info(
                    "Exit hub %s: shard %s has origins_count=%s, "
                    "not cleaning up (shard is in use)",
                    exit_hub_id,
                    shard_id,
                    origins_count
                )
                return

            if deploy_state not in ('succeeded', 'none'):
                logger.info(
                    "Exit hub %s: shard %s deploy.state=%s, "
                    "not cleaning up (deploy not stable)",
                    exit_hub_id,
                    shard_id,
                    deploy_state
                )
                return

            # Shard is empty and stable - delete it
            delete_url = (
                f"http://{miner_ip}:{self.settings.miner_port}/api/v1/admin/shards/{shard_id}"
            )
            logger.info(
                "Exit hub %s: deleting empty TPM-created shard %s via %s",
                exit_hub_id,
                shard_id,
                delete_url
            )

            delete_response = requests.delete(delete_url, headers=headers, timeout=(5, 30))

            if delete_response.status_code == 404:
                logger.info(
                    "Exit hub %s: shard %s already deleted (404)",
                    exit_hub_id,
                    shard_id
                )
                return

            if delete_response.status_code == 501:
                logger.info(
                    "Exit hub %s: shard DELETE endpoint not implemented yet (501) - "
                    "skipping cleanup",
                    exit_hub_id
                )
                return

            if delete_response.status_code >= 400:
                logger.warning(
                    "Exit hub %s: failed to delete shard %s (%s): %s",
                    exit_hub_id,
                    shard_id,
                    delete_response.status_code,
                    delete_response.text[:200]
                )
                return

            logger.info(
                "Exit hub %s: successfully deleted empty TPM-created shard %s",
                exit_hub_id,
                shard_id
            )

            # Also remove from TPM's tensorprox_miner_shards table
            if miner_id:
                try:
                    self.shard_repository.delete_shard(
                        miner_id=UUID(miner_id),
                        shard_id=shard_id,
                    )
                    logger.info(
                        "Exit hub %s: removed shard %s from TPM database",
                        exit_hub_id,
                        shard_id
                    )
                except Exception as del_exc:  # noqa: BLE001
                    logger.warning(
                        "Exit hub %s: failed to remove shard %s from TPM database: %s",
                        exit_hub_id,
                        shard_id,
                        del_exc
                    )

        except requests.RequestException as exc:
            logger.warning(
                "Exit hub %s: network error during shard cleanup for %s: %s",
                exit_hub_id,
                shard_id,
                exc
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Exit hub %s: unexpected error during shard cleanup for %s: %s",
                exit_hub_id,
                shard_id,
                exc,
                exc_info=True
            )

    def _notify_state_change(
        self,
        *,
        exit_hub_id: str,
        status: str,
        client_id: Optional[str],
        origin_id: Optional[str],
        miner_id: Optional[str],
        miner_ip: Optional[str],
        metadata: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Route state changes through unified operation tracker."""
        queue_position = (metadata or {}).get("queue_position", 0)
        get_operation_tracker().track(
            exit_hub_id=exit_hub_id,
            status=status,
            client_id=client_id,
            origin_id=origin_id,
            miner_id=miner_id,
            miner_ip=miner_ip,
            queue_position=queue_position,
            metadata=metadata,
            error=error,
        )

    def _configure_volume_agent(
        self,
        exit_hub_id: str,
        exit_hub_ip: str,
        origin_id: str,
        ssh_username: str,
    ) -> None:
        """Configure the volume reporting agent on an exit hub.

        Updates /opt/tensorprox/agent.env with TPM connection details
        and restarts the agent service.
        """
        try:
            management_settings = get_tp_management_settings()
            global_settings = get_settings()

            # Use tp_redis_external_host/port for exit hub -> TPM Redis connection
            tpm_redis_host = management_settings.tp_redis_external_host or "tpm.tensorprox.com"
            tpm_redis_port = management_settings.tp_redis_external_port or 6379
            tpm_redis_password = management_settings.tp_redis_password or ""

            # Get SSH key path from global settings (TensorProxSettings)
            ssh_key_path = str(Path(global_settings.ssh_key_path).expanduser()) if global_settings.ssh_key_path else None

            if not ssh_key_path or not Path(ssh_key_path).exists():
                logger.warning(
                    "Exit hub %s: SSH key not found, skipping agent configuration",
                    exit_hub_id
                )
                return

            logger.info(
                "Exit hub %s: configuring volume agent (TPM=%s:%s)",
                exit_hub_id, tpm_redis_host, tpm_redis_port
            )

            # Create SSH connection
            ssh = create_ssh_client(exit_hub_ip, ssh_username, ssh_key_path, timeout=30)

            # Update agent environment file using printf (heredocs don't work well with paramiko)
            env_lines = [
                "# TPM Redis connection - configured by TPM",
                f"TPM_HOST={tpm_redis_host}",
                f"TPM_PORT={tpm_redis_port}",
                f"TPM_PASSWORD={tpm_redis_password}",
                "REPORT_INTERVAL=60",
                f"EXIT_HUB_ID={exit_hub_id}",
                f"ORIGIN_ID={origin_id}",
            ]
            env_content_escaped = "\\n".join(env_lines)

            # Write env file using printf (works reliably over SSH)
            write_cmd = f"printf '{env_content_escaped}\\n' | sudo tee /opt/tensorprox/agent.env > /dev/null"
            restart_cmd = "sudo systemctl restart exithub-agent.service || true"

            commands = [write_cmd, restart_cmd]

            for cmd in commands:
                logger.debug("Exit hub %s: executing SSH command: %s", exit_hub_id, cmd[:100])
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
                exit_code = stdout.channel.recv_exit_status()
                stdout_text = stdout.read().decode()
                stderr_text = stderr.read().decode()
                if exit_code != 0:
                    logger.warning(
                        "Exit hub %s: agent config command failed (exit %d): stderr=%s stdout=%s",
                        exit_hub_id, exit_code, stderr_text, stdout_text
                    )
                else:
                    logger.debug("Exit hub %s: command succeeded (exit %d)", exit_hub_id, exit_code)

            ssh.close()
            logger.info("Exit hub %s: volume agent configured", exit_hub_id)

        except Exception as e:
            # Non-fatal - don't fail deployment if agent config fails
            logger.warning(
                "Exit hub %s: failed to configure volume agent: %s",
                exit_hub_id, e
            )

    def _publish_metrics_snapshot(
        self,
        *,
        origin_id: Optional[str],
        exit_hub_ip: Optional[str],
        status: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Send a payload to the metrics gateway, if configured."""
        if not origin_id or not self.metrics_client.is_enabled():
            return
        body = self.metrics_client.build_snapshot_body(
            origin_id=origin_id,
            exit_hub_ip=exit_hub_ip,
            status=status,
            metadata=metadata,
        )
        self.metrics_client.publish_snapshot(body)

    def reconfigure_volume_agent(self, exit_hub_id: str) -> Dict[str, Any]:
        """Reconfigure the volume reporting agent on an existing exit hub.

        This is useful when:
        - The initial configuration failed during deployment
        - Redis connection details have changed
        - The agent needs to be restarted with updated settings

        Args:
            exit_hub_id: The exit hub to reconfigure

        Returns:
            Dict with status and details of the reconfiguration

        Raises:
            ExitHubNotFoundError: If exit hub doesn't exist
            ValueError: If exit hub is not in 'active' status
        """
        record = self.repository.get_exit_hub(exit_hub_id)
        if not record:
            raise ExitHubNotFoundError(exit_hub_id)

        status = record.get('status')
        if status != 'active':
            raise ValueError(f"Cannot reconfigure exit hub in '{status}' status (must be 'active')")

        exit_hub_ip = record.get('exit_hub_ip')
        origin_id = record.get('origin_id')
        metadata = record.get('metadata') or {}

        if not exit_hub_ip:
            raise ValueError(f"Exit hub {exit_hub_id} has no exit_hub_ip")
        if not origin_id:
            raise ValueError(f"Exit hub {exit_hub_id} has no origin_id")

        # Determine SSH username from metadata or default
        cloud_provider = metadata.get('cloud_provider', 'aws')
        ssh_username = 'ubuntu' if cloud_provider == 'aws' else 'root'

        logger.info(
            "Reconfiguring volume agent for exit hub %s (ip=%s, origin=%s)",
            exit_hub_id, exit_hub_ip, origin_id
        )

        # Call the internal configuration method
        self._configure_volume_agent(
            exit_hub_id=exit_hub_id,
            exit_hub_ip=exit_hub_ip,
            origin_id=origin_id,
            ssh_username=ssh_username,
        )

        return {
            'exit_hub_id': exit_hub_id,
            'exit_hub_ip': exit_hub_ip,
            'origin_id': origin_id,
            'status': 'reconfigured',
            'message': 'Volume agent reconfiguration initiated'
        }


# Singleton exported for API usage
exithub_manager = ExitHubManager()

# Wire notifier to miner operation queue for SSE notifications
try:
    from tensorprox.tpm.services.miner_operation_queue import (
        get_miner_operation_queue,
    )
    get_miner_operation_queue().set_notifier(exithub_manager.notifier)
except Exception as _exc:  # noqa: BLE001
    logger.warning("Failed to wire notifier to miner operation queue: %s", _exc)
