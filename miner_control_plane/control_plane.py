"""Miner service - Control plane for scrubber management and attack detection"""
import threading
from flask import Flask, jsonify
from shared.config import get_settings
from shared.utils.logging import setup_logging, get_logger
from miner_control_plane.api import (
    admin,
    health as health_bp,
    origins,
    reputation,
    origin_reputation,
    layer4,
    metrics,
    baselines,
    challenge_levels,
    attack_events,
    anomaly_detection,
    machine_limits,
    mitigation,
    protocol,
    web_app,
    capacity,
    l7_audit
)
from miner_control_plane.services.state_manager import state_manager
from miner_control_plane.services import (
    syncookie_controller,
    anomaly_detector,
    attack_detection,
    baseline_learner,
    automated_mitigation,
    adaptive_scaling,
    db_maintenance
)
from miner_control_plane.services.data_aggregation_service import start_data_aggregation_thread
from miner_control_plane.services.health_monitor import start_health_monitor_thread
from miner_control_plane.services.job_worker import start_job_worker_thread
from miner_control_plane.services.miner_identity import miner_identity

logger = get_logger(__name__)


def create_app() -> Flask:
    """
    Create Miner Flask application.
    Preserves ALL EMN functionality including background detection services.
    """
    settings = get_settings()

    # Initialize logging system FIRST (before any other operations)
    setup_logging(
        service_name="miner",
        log_level=getattr(settings, 'log_level', 'INFO'),
        console=True,
        file_logging=True,
        rate_limit=True
    )

    logger.info("=" * 80)
    logger.info(f"Starting Miner Service v1.0")
    logger.info(f"Port: {settings.emn_port}")
    logger.info(f"Database: {settings.db_name}@{settings.db_host}")
    logger.info("=" * 80)

    app = Flask(__name__)
    app.config['JSON_SORT_KEYS'] = False

    # Suppress werkzeug request logging (too verbose for production)
    import logging
    logging.getLogger('werkzeug').setLevel(logging.WARNING)

    # Try to register with TensorProx Management, but don't block Flask startup.
    # If TPM is unavailable, the Flask server should still start and serve health checks.
    # Registration will be retried when validators provide bootstrap tokens.
    try:
        miner_identity.ensure_registered(settings)
    except RuntimeError as e:
        logger.warning(f"TPM registration failed during startup: {e}")
        logger.warning("Control plane will start without TPM registration - API auth may be limited")
        logger.info("Registration will be retried when validators provide bootstrap tokens")

    # CRITICAL: Bittensor's default logging sets ALL non-bittensor loggers to CRITICAL level.
    # We must reset our loggers' levels after bittensor initialization.
    # This affects ALL child loggers (e.g., miner_control_plane.services.data_aggregation_service)
    import logging as stdlogging
    for logger_name, logger_obj in stdlogging.Logger.manager.loggerDict.items():
        if isinstance(logger_obj, stdlogging.Logger):
            if (logger_name.startswith('miner_control_plane') or
                logger_name.startswith('shared') or
                logger_name == '__main__'):
                logger_obj.setLevel(stdlogging.DEBUG)
    # Also reset parent loggers and root
    stdlogging.getLogger('miner_control_plane').setLevel(stdlogging.DEBUG)
    stdlogging.getLogger('shared').setLevel(stdlogging.DEBUG)
    stdlogging.getLogger().setLevel(stdlogging.DEBUG)

    # Initialize state on app creation (load shards, nodes, origins from database)
    logger.info("Loading state from database...")
    state_manager.load_state()
    logger.info(
        f"State loaded: {len(state_manager.shards_db)} shards, "
        f"{len(state_manager.nodes_db)} nodes, "
        f"{len(state_manager.origins_db)} origins"
    )

    # Start background state sync thread (keeps cache in sync with database)
    state_manager.start_sync_thread()

    # Run all startup cleanup routines (BPF maps, wg2priv_map, expected_tunnels.json)
    # See miner/services/startup_cleanup.py for implementation details
    # NOTE: Run in background thread to avoid blocking Flask startup.
    # Database operations in cleanup can timeout (30s each) which would delay Flask startup.
    from miner_control_plane.services.startup_cleanup import run_all_startup_cleanup

    def _background_cleanup():
        try:
            run_all_startup_cleanup()
        except Exception as e:
            logger.warning(f"Startup cleanup failed (non-fatal): {e}")
            logger.warning("Some cleanup operations may need to be retried")

    cleanup_thread = threading.Thread(target=_background_cleanup, daemon=True, name="StartupCleanup")
    cleanup_thread.start()
    logger.info("Startup cleanup started in background thread")

    # Health endpoint
    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'healthy',
            'service': 'miner',
            'port': settings.emn_port
        })

    # Register API blueprints (ALL EMN endpoints organized into blueprints)
    logger.info("Registering 17 API blueprints...")
    app.register_blueprint(admin.bp)
    app.register_blueprint(health_bp.bp)
    app.register_blueprint(origins.bp)
    app.register_blueprint(reputation.bp)
    app.register_blueprint(origin_reputation.bp)
    logger.info("  - origin_reputation (per-origin whitelist/blacklist)")
    app.register_blueprint(layer4.bp)
    app.register_blueprint(metrics.bp)
    app.register_blueprint(baselines.bp)
    app.register_blueprint(challenge_levels.bp)
    app.register_blueprint(attack_events.bp)
    app.register_blueprint(anomaly_detection.bp)
    app.register_blueprint(machine_limits.bp)
    app.register_blueprint(mitigation.bp)
    app.register_blueprint(protocol.bp)
    app.register_blueprint(web_app.bp)
    app.register_blueprint(capacity.capacity_bp)
    app.register_blueprint(l7_audit.bp)
    logger.info("  - l7_audit (Layer 7 attack detection audit)")
    logger.info("API blueprints registered")

    # Start ALL EMN background services (preserve EMN behavior)
    # Each service manages its own thread via start_*_thread() function
    logger.info("Starting 10 background services...")
    logger.info("  - db_maintenance (1h interval)")
    db_maintenance.start_maintenance_thread(interval_seconds=3600, retention_hours=24, metrics_retention_days=90)
    logger.info("  - automated_mitigation (60s interval)")
    automated_mitigation.start_automated_mitigation_thread(interval_seconds=60)
    logger.info("  - syncookie_controller (5s interval)")
    syncookie_controller.start_syncookie_controller_thread(interval_seconds=5)
    logger.info("  - adaptive_scaling (60s interval)")
    adaptive_scaling.start_adaptive_scaling_thread()
    logger.info("  - baseline_learner (1h interval)")
    baseline_learner.start_baseline_learner_thread(interval_seconds=3600)
    logger.info("  - anomaly_detector (30s interval)")
    anomaly_detector.start_anomaly_detector_thread()
    logger.info("  - data_aggregation_service (30s interval) - ORCHESTRATOR")
    start_data_aggregation_thread(interval_seconds=30)
    logger.info("  - health_monitor (10s interval) - AUTOMATED FAILOVER")
    start_health_monitor_thread()
    logger.info("  - job_worker (5s poll) - ASYNC SHARD DEPLOYMENT")
    start_job_worker_thread(poll_interval=5)
    logger.info("Background services started")
    # attack_detection has no auto-start function (on-demand threat scoring)

    logger.info("Miner initialization complete")
    return app


if __name__ == '__main__':
    settings = get_settings()
    app = create_app()
    app.run(
        host='0.0.0.0',
        port=settings.emn_port,
        debug=False
    )
