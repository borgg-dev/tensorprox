"""
TensorProx Management (TPM-Lite) - Embedded in validator for independent operation.

This is the Flask application factory for TPM-Lite, a lightweight version of TPM
that runs embedded within each validator. Each TPM operates independently:

1. Once an origin is assigned to a TPM, that TPM exclusively owns it
2. No inter-TPM communication or failover
3. Each TPM handles its origins from deployment to deletion independently

Usage:
    # Standalone (for testing):
    python -m tensorprox.tpm.app

    # Embedded in validator (production):
    Validator starts TPM via --enable-tpm flag
"""
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from loguru import logger


# Global state for embedded mode
_app_instance: Optional[Flask] = None
_validator_uid: Optional[int] = None
_validator_hotkey: Optional[str] = None  # SS58 address of the hosting validator


def create_app(
    validator_uid: Optional[int] = None,
    validator_hotkey: Optional[str] = None,
    log_dir: Optional[Path] = None,
) -> Flask:
    """
    Create TPM-Lite Flask application.

    Args:
        validator_uid: The hosting validator's UID
        validator_hotkey: The hosting validator's SS58 hotkey address
        log_dir: Directory for TPM logs (default: /tmp/tpm-lite)

    Returns:
        Configured Flask application
    """
    global _app_instance, _validator_uid, _validator_hotkey

    # Store validator UID and hotkey
    _validator_uid = validator_uid
    _validator_hotkey = validator_hotkey

    # Configure logging
    log_dir = log_dir or Path("/tmp/tpm-lite")
    log_dir.mkdir(parents=True, exist_ok=True)

    # Setup audit logger
    audit_logger = logging.getLogger("tensorprox.tpm.audit")
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

    if not audit_logger.handlers:
        audit_handler = RotatingFileHandler(
            log_dir / "tpm_requests.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8",
        )
        audit_handler.setFormatter(logging.Formatter(
            fmt='[%(asctime)s] %(levelname)-7s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        audit_logger.addHandler(audit_handler)

    # Create Flask app
    app = Flask(__name__)
    app.config['JSON_SORT_KEYS'] = False

    # Store config
    app.config['TPM_VALIDATOR_UID'] = validator_uid

    @app.before_request
    def _inject_validator_context():
        """Inject validator_uid into Flask request context for use by services."""
        try:
            from flask import g
            g.validator_uid = validator_uid
        except Exception:
            pass

    @app.before_request
    def _log_request():
        """Log all incoming requests for audit trail."""
        try:
            from flask import request
            request_id = request.headers.get("X-Request-Id", "")
            line = (
                f"HTTP {request.method} {request.path} "
                f"args={dict(request.args)} remote={request.remote_addr}"
            )
            if request_id:
                line = f"{line} request_id={request_id}"
            if validator_uid is not None:
                line = f"{line} validator_uid={validator_uid}"
            logger.debug(line)
            audit_logger.info(line)
        except Exception:
            pass

    @app.errorhandler(Exception)
    def _handle_exception(exc: Exception):
        """Global exception handler."""
        status_code = 500
        error_type = "internal_error"
        message = str(exc) or "internal error"

        if isinstance(exc, HTTPException):
            status_code = exc.code or 500
            error_type = exc.name or "http_error"
            message = exc.description or message

        logger.error(f"Request failed: {exc}", exc_info=True)
        return jsonify({"error": error_type, "message": message}), status_code

    @app.route('/health', methods=['GET'])
    def health():
        """Health check endpoint."""
        return jsonify({
            'status': 'healthy',
            'service': 'tpm-lite',
            'validator_uid': validator_uid,
        })

    @app.route('/status', methods=['GET'])
    def status():
        """Get TPM status (for monitoring)."""
        return jsonify({
            'validator_uid': validator_uid,
            'mode': 'independent',
        })

    # Register API blueprints
    try:
        from tensorprox.tpm.api import (
            exit_hubs_bp, origins_bp, miners_bp, streams_bp, subnet_bp,
            validators_bp, tpm_keys_bp, miner_events_bp, miner_ports_bp, admin_cleanup_bp,
            benign_tests_bp,
        )
        app.register_blueprint(exit_hubs_bp)
        app.register_blueprint(origins_bp)
        app.register_blueprint(miners_bp)
        app.register_blueprint(streams_bp)
        app.register_blueprint(subnet_bp)
        app.register_blueprint(validators_bp)
        app.register_blueprint(tpm_keys_bp)
        app.register_blueprint(miner_events_bp)
        app.register_blueprint(miner_ports_bp)
        app.register_blueprint(admin_cleanup_bp)
        app.register_blueprint(benign_tests_bp)
        logger.info("TPM-Lite API blueprints registered")
    except ImportError as e:
        logger.warning(f"Some TPM blueprints not available: {e}")

    _app_instance = app
    return app


def get_app() -> Optional[Flask]:
    """Get the current TPM-Lite app instance."""
    return _app_instance


def get_validator_uid() -> Optional[int]:
    """Get the hosting validator's UID."""
    return _validator_uid


def get_validator_hotkey() -> Optional[str]:
    """Get the hosting validator's SS58 hotkey address."""
    return _validator_hotkey


def run_startup_tasks():
    """
    Run TPM startup tasks (migrations, recovery, etc.)

    Called when TPM starts, either standalone or embedded.
    """
    logger.info("Running TPM startup tasks...")

    # Run database migrations
    try:
        from tensorprox.tpm.utils.db_setup import run_db_migrations
        run_db_migrations()
        logger.info("Database migrations complete")
    except ImportError:
        logger.debug("db_setup not available, skipping migrations")
    except Exception as e:
        logger.error(f"Migration failed: {e}")

    # Recover orphaned operations
    try:
        from tensorprox.tpm.services.miner_operation_queue import get_miner_operation_queue
        queue = get_miner_operation_queue()
        orphaned = queue.recover_on_startup(max_age_seconds=300)
        if orphaned:
            logger.warning(f"Recovered {orphaned} orphaned miner operations")
    except ImportError:
        logger.debug("miner_operation_queue not available")
    except Exception as e:
        logger.error(f"Operation recovery failed: {e}")

    # Recover stuck terminations
    try:
        from tensorprox.tpm.services.termination_recovery import recover_stuck_terminations
        results = recover_stuck_terminations()
        if results.get("recovered") or results.get("still_stuck"):
            logger.info(
                f"Termination recovery: {results.get('recovered', 0)} recovered, "
                f"{results.get('still_stuck', 0)} still stuck"
            )
    except ImportError:
        logger.debug("termination_recovery not available")
    except Exception as e:
        logger.error(f"Termination recovery failed: {e}")

    # Recover stuck deployments
    try:
        from tensorprox.tpm.services.deployment_recovery import recover_stuck_deployments
        results = recover_stuck_deployments()
        if results.get("recovered") or results.get("errors"):
            logger.info(
                f"Deployment recovery: {results.get('recovered', 0)} recovered, "
                f"{results.get('errors', 0)} errors"
            )
    except ImportError:
        logger.debug("deployment_recovery not available")
    except Exception as e:
        logger.error(f"Deployment recovery failed: {e}")

    # Sync shards from all miners (cleans up stale shard records)
    try:
        from tensorprox.tpm.services.shard_sync import sync_all_miner_shards
        results = sync_all_miner_shards()
        if results.get("synced") or results.get("stale_removed"):
            logger.info(
                f"Shard sync: {results.get('synced', 0)} miners synced, "
                f"{results.get('stale_removed', 0)} stale shards removed"
            )
    except ImportError:
        logger.debug("shard_sync not available")
    except Exception as e:
        logger.error(f"Shard sync failed: {e}")

    # Sync deletions from webapp (cleanup origins deleted while TPM was offline)
    try:
        from tensorprox.tpm.services.webapp_sync import run_webapp_sync
        results = run_webapp_sync()
        if results.get("synced") or results.get("errors"):
            logger.info(
                f"Webapp sync: {results.get('synced', 0)} origins cleaned up, "
                f"{results.get('errors', 0)} errors"
            )
    except ImportError:
        logger.debug("webapp_sync not available")
    except Exception as e:
        logger.warning(f"Webapp sync failed (non-critical): {e}")

    logger.info("TPM startup tasks complete")


def start_background_services():
    """
    Start TPM background services (sweepers, forwarders, etc.)

    Called after app creation to start background workers.
    """
    logger.info("Starting TPM background services...")

    # Initialize SSE notifier and set it on OperationTracker
    try:
        from tensorprox.tpm.services.notifier import ExitHubNotifier
        from tensorprox.tpm.services.operation_tracker import get_operation_tracker

        # Get validator_uid from module-level variable set during create_app
        validator_uid_val = get_validator_uid()
        notifier = ExitHubNotifier(validator_uid=validator_uid_val)
        get_operation_tracker().set_notifier(notifier)
        logger.info(f"SSE notifier initialized and set on OperationTracker (validator_uid={validator_uid_val})")
    except ImportError:
        logger.debug("notifier not available")
    except Exception as e:
        logger.warning(f"SSE notifier init failed: {e}", exc_info=True)

    # Start metrics forwarder
    try:
        from tensorprox.tpm.services.metrics_forwarder import start_metrics_forwarder
        start_metrics_forwarder()
        logger.info("Metrics forwarder started")
    except ImportError:
        logger.debug("metrics_forwarder not available")
    except Exception as e:
        logger.warning(f"Metrics forwarder failed: {e}")

    # Start orphan sweeper
    try:
        from tensorprox.tpm.services.orphan_sweeper import start_orphan_sweeper
        start_orphan_sweeper()
        logger.info("Orphan sweeper started")
    except ImportError:
        logger.debug("orphan_sweeper not available")
    except Exception as e:
        logger.warning(f"Orphan sweeper failed: {e}")

    # Start purge sweeper
    try:
        from tensorprox.tpm.services.purge_sweeper import start_purge_sweeper
        start_purge_sweeper()
        logger.info("Purge sweeper started")
    except ImportError:
        logger.debug("purge_sweeper not available")
    except Exception as e:
        logger.warning(f"Purge sweeper failed: {e}")

    # Start shard sweeper (cleans up empty PRODUCTION shards after 10 min grace period)
    # Note: Audit shards are NEVER swept - they must remain active for validator scoring
    try:
        from tensorprox.tpm.services.shard_sweeper import start_shard_sweeper
        start_shard_sweeper()
        logger.info("Shard sweeper started (production shards only, audit shards excluded)")
    except ImportError:
        logger.debug("shard_sweeper not available")
    except Exception as e:
        logger.warning(f"Shard sweeper failed: {e}")

    # Initialize deployment queue (workers auto-start on import)
    try:
        from tensorprox.tpm.services.deploy_queue import get_deploy_queue
        queue = get_deploy_queue()
        logger.info(f"Deployment queue initialized: {queue.queue.qsize()} jobs pending, workers already running")
    except ImportError:
        logger.debug("deploy_queue not available")
    except Exception as e:
        logger.warning(f"Deployment queue failed: {e}")

    # Initialize TPM keypair
    try:
        from tensorprox.tpm.services import tpm_keypair
        key_id = tpm_keypair.load_or_generate_keypair()
        logger.info(f"TPM keypair initialized (key_id: {key_id})")
    except ImportError:
        logger.debug("tpm_keypair not available")
    except Exception as e:
        logger.warning(f"TPM keypair init failed: {e}")

    # Initialize validation queue
    try:
        from tensorprox.tpm.services.validation.queue import get_validation_queue
        get_validation_queue()
        logger.info("Validation queue initialized")
    except ImportError:
        logger.debug("validation queue not available")
    except Exception as e:
        logger.warning(f"Validation queue failed: {e}")

    # Initialize geolocation service
    try:
        from tensorprox.tpm.services.geolocation import initialize_geolocation
        if initialize_geolocation():
            logger.info("Geolocation service initialized")
        else:
            logger.warning("Geolocation service unavailable")
    except ImportError:
        logger.debug("geolocation not available")
    except Exception as e:
        logger.warning(f"Geolocation init failed: {e}")

    # Start heartbeat pusher (sends load metrics to webapp for load balancing)
    try:
        from tensorprox.tpm.services.heartbeat_pusher import start_heartbeat_pusher
        start_heartbeat_pusher()
        logger.info("Heartbeat pusher started")
    except ImportError:
        logger.debug("heartbeat_pusher not available")
    except Exception as e:
        logger.warning(f"Heartbeat pusher failed: {e}")

    logger.info("TPM background services started")


if __name__ == '__main__':
    """Standalone mode for testing."""
    import argparse

    parser = argparse.ArgumentParser(description="TPM-Lite Standalone Server")
    parser.add_argument("--port", type=int, default=5001, help="Port to listen on")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--validator-uid", type=int, default=None, help="Validator UID")
    args = parser.parse_args()

    # Run startup tasks
    run_startup_tasks()

    # Create and configure app
    app = create_app(
        validator_uid=args.validator_uid,
    )

    # Start background services
    start_background_services()

    # Run Flask app
    logger.info(f"Starting TPM-Lite on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
