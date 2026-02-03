"""Origins API Blueprint for TensorProx Management."""
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request

from shared.config import get_settings, get_tp_management_settings
from shared.utils.logging import get_logger
from shared.utils.ssh import get_ssh_user_for_provider
from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository
from tensorprox.tpm.repositories.origin_repository import OriginRepository
from tensorprox.tpm.services.client_registry import ClientRegistry
from tensorprox.tpm.services.egress_script_generator import generate_egress_installer
from tensorprox.tpm.services.exithub_manager import (
    ExitHubNotFoundError,
    exithub_manager,
)

bp = Blueprint("tp_origins", __name__, url_prefix="/api/v1/origins")

exit_hub_repository = ExitHubRepository()
origin_repository = OriginRepository()
client_registry = ClientRegistry()
logger = get_logger(__name__)
settings = get_settings()
tpm_settings = get_tp_management_settings()


@bp.delete("/<origin_id>")
def delete_origin(origin_id: str):
    """Delete origin with guaranteed SSE notification to webapp.

    This endpoint ALWAYS signals termination to the webapp, regardless of
    internal state. Errors are stored internally but never exposed to clients.
    TPM is the source of truth - the webapp must receive a clean signal.
    """
    # Collect context for notification
    param_exit_hub_id = (request.args.get("exit_hub_id") or "").strip() or None

    # CRITICAL: Log all termination requests with full context for audit trail
    logger.warning(
        "ORIGIN_TERMINATE_REQUEST | origin_id=%s | exit_hub_id=%s | "
        "caller_ip=%s | user_agent=%s | api_key=%s | "
        "x_forwarded_for=%s | referer=%s",
        origin_id,
        param_exit_hub_id,
        request.remote_addr,
        request.headers.get("User-Agent", "unknown"),
        request.headers.get("X-API-Key", "none")[:8] + "..." if request.headers.get("X-API-Key") else "none",
        request.headers.get("X-Forwarded-For", "none"),
        request.headers.get("Referer", "none"),
    )

    logger.info("DELETE origin requested origin_id=%s exit_hub_id=%s", origin_id, param_exit_hub_id)

    # Try to get exit_hub record (may be already deleted)
    record = exit_hub_repository.get_exit_hub_by_origin(origin_id)
    origin_row = origin_repository.find_by_origin_id(origin_id)

    # Determine exit_hub_id for notification (priority: record > stored > param)
    effective_exit_hub_id = None
    if record and record.get("exit_hub_id"):
        effective_exit_hub_id = record["exit_hub_id"]
    elif origin_row and origin_row.get("last_exit_hub_id"):
        effective_exit_hub_id = str(origin_row["last_exit_hub_id"])
    elif param_exit_hub_id:
        effective_exit_hub_id = param_exit_hub_id

    # Collect context for notification
    client_id = None
    miner_id = None
    miner_ip = None

    if origin_row:
        client_id = origin_row.get("client_id")
        miner_id = origin_row.get("miner_id")
        miner_ip = origin_row.get("miner_ip")
    if record:
        client_id = client_id or record.get("client_id")
        miner_id = miner_id or record.get("miner_id")
        miner_ip = miner_ip or record.get("miner_ip")

    # Track internal errors (never exposed to webapp)
    internal_errors: list[str] = []

    # --- Path 1: Exit hub record exists - use terminate_exit_hub ---
    if record and record.get("exit_hub_id"):
        try:
            result = exithub_manager.terminate_exit_hub(record["exit_hub_id"], purge=True)
            # terminate_exit_hub handles all SSE notifications
            return jsonify({"status": "success", "result": result}), 200
        except ExitHubNotFoundError:
            # Record was deleted between lookup and terminate - continue with direct path
            logger.warning("Exit hub %s disappeared during terminate", record["exit_hub_id"])
        except Exception as exc:  # noqa: BLE001
            logger.error("Exit hub termination failed for origin %s: %s", origin_id, exc, exc_info=True)
            internal_errors.append(f"terminate_exit_hub:{exc}")
            # Continue - we still need to notify webapp

    # --- Path 2: No exit_hub record but origin exists ---
    if origin_row:
        # CRITICAL: Wait for miner cleanup to complete (includes EIP release)
        # fire_and_forget=False prevents orphaned AWS resources (EIPs, BPF entries)
        shard_id = origin_row.get("shard_id")
        try:
            exithub_manager.lifecycle.decommission_origin(
                origin_id=origin_id,
                emn_ip=miner_ip,
                miner_id=miner_id,
                shard_id=shard_id,
                fire_and_forget=False,
            )
            logger.info("Miner cleanup completed for origin %s (shard_id=%s)", origin_id, shard_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to queue miner cleanup for origin %s: %s", origin_id, exc, exc_info=True)
            internal_errors.append(f"miner_cleanup:{exc}")
            # Continue - we still mark as terminated and notify webapp

        # Update internal state - store errors but mark as terminated
        error_str = "; ".join(internal_errors) if internal_errors else None
        origin_repository.mark_terminated_with_error(client_id, origin_id, error_str)

    # --- ALWAYS emit SSE notification chain ---
    if effective_exit_hub_id:
        _emit_termination_chain(
            exit_hub_id=effective_exit_hub_id,
            origin_id=origin_id,
            client_id=client_id,
            miner_id=miner_id,
            miner_ip=miner_ip,
        )
    else:
        logger.warning(
            "No exit_hub_id available for origin %s notification. "
            "Webapp may show stale state until refresh.",
            origin_id,
        )

    # Always return success - internal errors are logged and stored
    return jsonify({
        "status": "success",
        "result": {
            "origin_id": origin_id,
            "miner_ip": miner_ip,
            "exit_hub_id": effective_exit_hub_id,
        }
    }), 200


def _emit_termination_chain(
    *,
    exit_hub_id: str,
    origin_id: str,
    client_id: str | None,
    miner_id: str | None,
    miner_ip: str | None,
) -> None:
    """Emit complete termination SSE chain to webapp.

    This ensures the webapp receives a clean, complete termination signal
    regardless of what happened internally.
    """
    termination_chain = [
        "teardown_requested",
        "draining",
        "miner_cleanup",
        "terminated",
    ]
    for status in termination_chain:
        exithub_manager._notify_state_change(
            exit_hub_id=exit_hub_id,
            status=status,
            client_id=client_id,
            origin_id=origin_id,
            miner_id=miner_id,
            miner_ip=miner_ip,
            metadata={"action": "terminate"},
        )


# ------------------------------------------------------------------ #
# Egress Routing Endpoints
# ------------------------------------------------------------------ #


@bp.put("/<origin_id>/egress")
def put_egress_config(origin_id: str):
    """Store egress questionnaire configuration for an origin.

    Called by Webapp after user completes egress setup questionnaire.
    Stores questionnaire responses for later use when generating installer script.

    Request body:
        {
            "cloud_provider": "aws|linode|gcp|digitalocean|other",
            "route_system_updates": true|false,
            "os_type": "ubuntu|debian|centos|rhel|other",
            "backup_providers": ["s3", "gcs", "backblaze"],
            "nic_name": "" (empty for auto-detect),
            "custom_blacklist_ports": ["8443"],
            "custom_blacklist_cidrs": ["203.0.113.0/24"],
            "custom_blacklist_ips": ["198.51.100.50"]
        }

    Returns:
        {
            "status": "configured",
            "origin_id": "...",
            "install_command": "curl -sL https://.../egress/installer | sudo sh"
        }
    """
    logger.info("PUT egress config for origin %s", origin_id)

    # Verify origin exists
    origin_row = origin_repository.find_by_origin_id(origin_id)
    if not origin_row:
        return jsonify({"error": "origin_not_found", "origin_id": origin_id}), 404

    # Verify exit hub exists and is active
    exit_hub = exit_hub_repository.get_exit_hub_by_origin(origin_id)
    if not exit_hub or exit_hub.get("status") != "active":
        return jsonify({
            "error": "exit_hub_not_ready",
            "message": "Origin must have an active exit hub before configuring egress"
        }), 400

    # Store questionnaire
    questionnaire = request.json or {}
    origin_repository.set_egress_config(origin_id, questionnaire)

    # Generate install command
    base_url = getattr(tpm_settings, "tpm_external_url", None) or f"http://localhost:{settings.tensorprox_port}"
    install_url = f"{base_url}/api/v1/origins/{origin_id}/egress/installer"
    install_command = f"curl -4 -sL {install_url} | sudo sh"

    logger.info("Egress configured for origin %s", origin_id)
    return jsonify({
        "status": "configured",
        "origin_id": origin_id,
        "install_command": install_command,
    }), 200


@bp.get("/<origin_id>/egress")
def get_egress_status(origin_id: str):
    """Get egress routing status and configuration summary.

    Returns:
        {
            "origin_id": "...",
            "egress_enabled": true|false,
            "egress_activated_at": "2024-12-22T10:30:00Z" or null,
            "questionnaire_configured": true|false
        }
    """
    logger.info("GET egress status for origin %s", origin_id)

    egress_config = origin_repository.get_egress_config(origin_id)
    if not egress_config:
        return jsonify({"error": "origin_not_found", "origin_id": origin_id}), 404

    activated_at = egress_config.get("egress_activated_at")
    if activated_at and hasattr(activated_at, "isoformat"):
        activated_at = activated_at.isoformat()

    return jsonify({
        "origin_id": origin_id,
        "egress_enabled": egress_config.get("egress_enabled", False),
        "egress_activated_at": activated_at,
        "questionnaire_configured": egress_config.get("egress_questionnaire") is not None,
    }), 200


@bp.get("/<origin_id>/egress/installer")
def get_egress_installer(origin_id: str):
    """Generate and return the egress installer script.

    Called by origin server via: curl -sL <url> | sudo sh

    Returns:
        Shell script (Content-Type: text/x-shellscript)
    """
    logger.info("GET egress installer for origin %s", origin_id)

    # Verify origin exists
    origin_row = origin_repository.find_by_origin_id(origin_id)
    if not origin_row:
        return jsonify({"error": "origin_not_found", "origin_id": origin_id}), 404

    # Get exit hub info
    exit_hub = exit_hub_repository.get_exit_hub_by_origin(origin_id)
    if not exit_hub or not exit_hub.get("exit_hub_ip"):
        return jsonify({
            "error": "exit_hub_not_found",
            "message": "No active exit hub found for this origin"
        }), 404

    # Get questionnaire (may be None if not configured via PUT)
    egress_config = origin_repository.get_egress_config(origin_id)
    questionnaire = (egress_config or {}).get("egress_questionnaire") or {}

    # Generate callback URL
    callback_url = getattr(tpm_settings, "tpm_external_url", None) or f"http://localhost:{settings.tensorprox_port}"
    callback_url = f"{callback_url}/api/v1"

    # Generate installer script
    script = generate_egress_installer(
        origin_id=origin_id,
        exit_hub_ip=exit_hub["exit_hub_ip"],
        callback_url=callback_url,
        questionnaire=questionnaire,
    )

    return Response(script, mimetype="text/x-shellscript")


@bp.post("/<origin_id>/egress/activate")
def activate_egress(origin_id: str):
    """Activate egress routing on the exit hub.

    Called by origin installer (tp-reload) after local GRE tunnel is created.
    This endpoint SSHes into the exit hub to create the matching GRE endpoint.

    Returns:
        {"status": "activated"} or error
    """
    logger.info("POST egress activate for origin %s", origin_id)

    # Verify origin exists
    origin_row = origin_repository.find_by_origin_id(origin_id)
    if not origin_row:
        return jsonify({"error": "origin_not_found", "origin_id": origin_id}), 404

    # Get exit hub info
    exit_hub = exit_hub_repository.get_exit_hub_by_origin(origin_id)
    if not exit_hub or not exit_hub.get("exit_hub_ip"):
        return jsonify({
            "error": "exit_hub_not_found",
            "message": "No active exit hub found for this origin"
        }), 404

    # Determine SSH user from provider metadata
    cloud_provider = (exit_hub.get("metadata") or {}).get("cloud_provider", "linode")
    ssh_username = get_ssh_user_for_provider(cloud_provider)

    # Get origin IP from exit hub record
    origin_ip = exit_hub.get("origin_ip")
    if not origin_ip:
        return jsonify({
            "error": "origin_ip_missing",
            "message": "Origin IP not found in exit hub record"
        }), 400

    try:
        # Activate egress on exit hub via SSH
        result = exithub_manager.lifecycle.activate_egress(
            origin_id=origin_id,
            origin_ip=origin_ip,
            exit_hub_ip=exit_hub["exit_hub_ip"],
            ssh_username=ssh_username,
        )

        # Update database
        origin_repository.set_egress_enabled(
            origin_id,
            enabled=True,
            activated_at=datetime.now(timezone.utc),
        )

        logger.info("Egress activated for origin %s", origin_id)
        return jsonify(result), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Egress activation failed for origin %s: %s", origin_id, exc, exc_info=True)
        return jsonify({
            "error": "activation_failed",
            "message": str(exc)
        }), 500


@bp.delete("/<origin_id>/egress")
def deactivate_egress(origin_id: str):
    """Deactivate egress routing and remove configuration.

    Called by origin server via tp-delete script.
    SSHes into exit hub to remove GRE tunnel and firewall rules.

    Returns:
        {"status": "deactivated"} or error
    """
    logger.info("DELETE egress for origin %s", origin_id)

    # Verify origin exists (but allow cleanup even if not)
    origin_row = origin_repository.find_by_origin_id(origin_id)

    # Get exit hub info
    exit_hub = exit_hub_repository.get_exit_hub_by_origin(origin_id)
    if not exit_hub or not exit_hub.get("exit_hub_ip"):
        # If no exit hub, just clear database state
        if origin_row:
            origin_repository.set_egress_enabled(origin_id, enabled=False)
        return jsonify({"status": "deactivated", "note": "no_exit_hub"}), 200

    # Determine SSH user from provider metadata
    cloud_provider = (exit_hub.get("metadata") or {}).get("cloud_provider", "linode")
    ssh_username = get_ssh_user_for_provider(cloud_provider)

    try:
        # Get origin IP from exit hub data or origin row
        origin_ip = exit_hub.get("origin_ip") or (origin_row.get("tensorprox_ip") if origin_row else None)
        if not origin_ip:
            logger.warning("No origin_ip found for deactivate_egress, policy routing may not be cleaned up")
            origin_ip = ""  # Allow cleanup to proceed with empty IP

        # Deactivate egress on exit hub via SSH
        result = exithub_manager.lifecycle.deactivate_egress(
            origin_id=origin_id,
            origin_ip=origin_ip,
            exit_hub_ip=exit_hub["exit_hub_ip"],
            ssh_username=ssh_username,
        )

        # Update database
        if origin_row:
            origin_repository.set_egress_enabled(origin_id, enabled=False)

        logger.info("Egress deactivated for origin %s", origin_id)
        return jsonify(result), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Egress deactivation failed for origin %s: %s", origin_id, exc, exc_info=True)
        return jsonify({
            "error": "deactivation_failed",
            "message": str(exc)
        }), 500
