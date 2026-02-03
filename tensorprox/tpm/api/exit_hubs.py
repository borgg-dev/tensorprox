"""Exit Hubs API Blueprint"""
from flask import Blueprint, request, jsonify
from pydantic import ValidationError
from shared.models import ExitHubDeployRequest
from shared.utils.logging import get_logger
from uuid import UUID
from tensorprox.tpm.services.deploy_queue import (
    DeployQueueFullError,
    deploy_queue,
)
from tensorprox.tpm.services.exithub_manager import (
    ExitHubNotFoundError,
    exithub_manager
)
from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository
from tensorprox.tpm.repositories.system_error_repository import SystemErrorRepository
from tensorprox.tpm.utils.api_security import validate_api_request

bp = Blueprint('exit_hubs', __name__, url_prefix='/api/v1/exit-hubs')
exit_hub_repository = ExitHubRepository()
system_error_repository = SystemErrorRepository()
logger = get_logger(__name__)


@bp.before_request
def _enforce_api_security():
    ok, message = validate_api_request()
    if not ok:
        return jsonify({'error': message}), 403


@bp.post('', strict_slashes=False)
def deploy_exit_hub():
    """Queue a new exit hub deployment"""
    try:
        req = ExitHubDeployRequest(**request.json)
        logger.info(
            "API deploy request received: origin_ip=%s emn_ip=%s client_id=%s origin_id=%s miner_id=%s",
            req.origin_ip,
            req.emn_ip,
            req.client_id,
            req.origin_id,
            req.miner_id,
        )
        exit_hub_id, prepared_req = deploy_queue.enqueue(req)
        return jsonify({
            'exit_hub_id': str(exit_hub_id),
            'client_id': prepared_req.client_id,
            'origin_id': prepared_req.origin_id,
            'miner_id': prepared_req.miner_id,
            'status': 'queued'
        }), 202
    except ValidationError as e:
        logger.warning("Deploy validation failed: %s", e)
        system_error_repository.log_error(
            error_source='api_validation',
            error_code='invalid_request',
            error_message=str(e),
            context={
                "endpoint": "/api/v1/exit-hubs",
                "method": "POST",
                "client_ip": request.remote_addr,
            },
        )
        return jsonify({'error': str(e)}), 400
    except ValueError as e:
        logger.warning("Deploy request invalid: %s", e)
        system_error_repository.log_error(
            error_source='api_validation',
            error_code='invalid_request',
            error_message=str(e),
            context={
                "endpoint": "/api/v1/exit-hubs",
                "method": "POST",
                "client_ip": request.remote_addr,
            },
        )
        return jsonify({'error': str(e)}), 400
    except DeployQueueFullError:
        logger.error("Deployment queue full; rejecting request", exc_info=True)
        return jsonify({'error': 'deployment_queue_full'}), 503
    except Exception as e:
        logger.error("Unexpected deploy error: %s", e, exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp.get('', strict_slashes=False)
def list_exit_hubs():
    """List all exit hubs"""
    statuses = _parse_status_filters(request.args.getlist('status'))
    client_id = request.args.get('client_id')
    origin_id = request.args.get('origin_id')
    miner_id = request.args.get('miner_id')

    hubs = exit_hub_repository.list_exit_hubs(
        statuses=statuses,
        client_id=client_id,
        origin_id=origin_id,
        miner_id=miner_id
    )
    return jsonify({
        'exit_hubs': hubs,
        'filters': {
            'status': statuses,
            'client_id': client_id,
            'origin_id': origin_id,
            'miner_id': miner_id,
        }
    })


@bp.get('/<exit_hub_id>')
def get_exit_hub(exit_hub_id):
    """Get exit hub details"""
    record = exit_hub_repository.get_exit_hub(exit_hub_id)
    if not record:
        return jsonify({'error': 'Exit hub not found'}), 404
    return jsonify(record)


@bp.post('/<exit_hub_id>/cancel')
def cancel_exit_hub(exit_hub_id: str):
    """Cancel an in-progress deployment.

    This endpoint cancels a deployment at any stage, cleaning up any
    provisioned resources. It signals workers to abort and prevents
    further status updates.
    """
    try:
        UUID(exit_hub_id)
    except Exception:
        return jsonify({'error': 'invalid_exit_hub_id'}), 400
    try:
        logger.info("API cancel request: exit_hub_id=%s", exit_hub_id)
        result = exithub_manager.cancel_exit_hub(exit_hub_id)
        return jsonify({'status': 'success', **result})
    except ExitHubNotFoundError:
        return jsonify({'error': 'not_found', 'exit_hub_id': exit_hub_id}), 404
    except Exception as e:  # noqa: BLE001
        logger.error("Exit hub cancel failed: %s", e, exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp.delete('/<exit_hub_id>')
def delete_exit_hub(exit_hub_id):
    """Terminate exit hub"""
    purge = request.args.get('purge', 'false').lower() in {'1', 'true', 'yes'}

    # CRITICAL: Log all termination requests with full context for audit trail
    logger.warning(
        "EXIT_HUB_TERMINATE_REQUEST | exit_hub_id=%s | purge=%s | "
        "caller_ip=%s | user_agent=%s | api_key=%s | "
        "x_forwarded_for=%s | referer=%s",
        exit_hub_id,
        purge,
        request.remote_addr,
        request.headers.get("User-Agent", "unknown"),
        request.headers.get("X-API-Key", "none")[:8] + "..." if request.headers.get("X-API-Key") else "none",
        request.headers.get("X-Forwarded-For", "none"),
        request.headers.get("Referer", "none"),
    )

    try:
        UUID(exit_hub_id)
    except Exception:
        return jsonify({'status': 'not_found', 'exit_hub_id': exit_hub_id}), 200
    try:
        logger.info("API terminate request: exit_hub_id=%s purge=%s", exit_hub_id, purge)
        result = exithub_manager.terminate_exit_hub(exit_hub_id, purge=purge)
        return jsonify({'status': 'success', **result})
    except ExitHubNotFoundError:
        # Idempotent delete: return success even if already removed.
        return jsonify({'status': 'not_found', 'exit_hub_id': exit_hub_id}), 200
    except Exception as e:  # noqa: BLE001
        logger.error("Exit hub terminate failed: %s", e, exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp.post('/<exit_hub_id>/reconfigure-agent')
def reconfigure_exit_hub_agent(exit_hub_id: str):
    """Reconfigure the volume reporting agent on an existing exit hub.

    This endpoint is useful when:
    - The initial agent configuration failed during deployment
    - Redis connection details have changed in the environment
    - The agent needs to be restarted with updated settings

    The agent will be configured with current TP_REDIS_EXTERNAL_HOST and
    TP_REDIS_EXTERNAL_PORT values from the environment.
    """
    try:
        UUID(exit_hub_id)
    except Exception:
        return jsonify({'error': 'invalid_exit_hub_id'}), 400
    try:
        logger.info("API reconfigure-agent request: exit_hub_id=%s", exit_hub_id)
        result = exithub_manager.reconfigure_volume_agent(exit_hub_id)
        return jsonify({'status': 'success', **result})
    except ExitHubNotFoundError:
        return jsonify({'error': 'not_found', 'exit_hub_id': exit_hub_id}), 404
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:  # noqa: BLE001
        logger.error("Exit hub reconfigure-agent failed: %s", e, exc_info=True)
        return jsonify({'error': str(e)}), 500


def _parse_status_filters(raw_statuses):
    """Normalize repeated/comma-separated status query params."""
    if not raw_statuses:
        return None
    statuses = []
    for value in raw_statuses:
        statuses.extend([part.strip() for part in value.split(',') if part.strip()])
    return statuses or None
