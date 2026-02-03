"""Redis→tp-webapp + tp_data metrics forwarder."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from shared.config import get_tp_management_settings
from shared.utils.logging import get_logger
from tensorprox.tpm.repositories import SystemErrorRepository
from tensorprox.tpm.repositories.origin_repository import OriginRepository
from tensorprox.tpm.services.miner_registry import MinerRegistry
from tensorprox.tpm.services.volume_verifier import get_volume_verifier

try:
    import redis  # type: ignore
except ImportError:  # pragma: no cover
    redis = None

try:
    import psycopg2
    import psycopg2.pool
except ImportError:  # pragma: no cover
    psycopg2 = None


logger = get_logger(__name__)
_forwarder_instance: Optional["MetricsForwarder"] = None
_forwarder_started = False

# Module-level repository for system error logging
_system_error_repo = SystemErrorRepository()


class MetricsForwarder:
    """Subscribe to Redis channel and forward metrics to tp-webapp APIs and tp_data DB."""

    def __init__(self) -> None:
        self.settings = get_tp_management_settings()
        raw_base = (os.environ.get("TP_WEBAPP_URL") or "").rstrip("/")
        self.base_url = raw_base
        self.api_key = os.environ.get("TP_WEBAPP_API_KEY", "")
        self.channel = getattr(self.settings, "metrics_channel", "metrics.aggregated")
        self.exithub_volume_channel = "exithub.volume"
        self._stop = False
        self._thread: Optional[threading.Thread] = None
        self._exithub_thread: Optional[threading.Thread] = None
        self._volume_verifier = get_volume_verifier()
        self._redis_client = None
        self._miner_registry = MinerRegistry()
        self._origin_repository = OriginRepository()
        self._seen_miners: set[str] = set()
        self._terminated_origins: set[str] = set()  # Cache of recently terminated origins
        self._enabled = True

        # tp_data PostgreSQL connection pool
        self._tp_data_pool = None
        self._tp_data_enabled = False

        if not redis:
            logger.info("Metrics forwarder disabled: redis library not available")
            self._enabled = False
            return
        if not self.settings.tp_redis_url:
            logger.info("Metrics forwarder disabled: tp_redis_url not configured")
            self._enabled = False
            return

        # Webapp forwarding is optional now (tp_data can work alone)
        if not self.base_url:
            logger.info("Metrics forwarder: TP_WEBAPP_URL not configured (tp_data only)")

        try:
            self._redis_client = redis.Redis.from_url(self.settings.tp_redis_url)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Metrics forwarder cannot connect to Redis %s: %s",
                self.settings.tp_redis_url,
                exc,
            )
            try:
                _system_error_repo.log_error(
                    error_source="metrics",
                    error_code="pool_init_failed",
                    error_message=f"Metrics forwarder cannot connect to Redis: {exc}",
                    context={"component": "metrics_forwarder", "phase": "init", "redis_url": self.settings.tp_redis_url},
                )
            except Exception:
                pass  # Don't break main flow
            self._redis_client = None

        # Initialize tp_data PostgreSQL connection pool
        self._init_tp_data_pool()

    def _init_tp_data_pool(self) -> None:
        """Initialize connection pool for tp_data database."""
        if not psycopg2:
            logger.info("Metrics forwarder: psycopg2 not available, tp_data disabled")
            return

        host = self.settings.tp_data_db_host
        if not host:
            logger.info("Metrics forwarder: tp_data_db_host not configured, tp_data disabled")
            return

        password = self.settings.tp_data_db_password
        if not password:
            logger.info("Metrics forwarder: tp_data_db_password not configured, tp_data disabled")
            return

        # Resolve SSL cert path
        ssl_cert = self.settings.tp_data_db_sslrootcert
        if ssl_cert:
            cert_path = Path(ssl_cert)
            if not cert_path.is_absolute():
                # Try relative to project root directory first
                project_dir = Path(__file__).parent.parent.parent
                candidate = project_dir / ssl_cert
                if candidate.exists():
                    ssl_cert = str(candidate)
                else:
                    # Try relative to tensorprox_management directory
                    tpm_dir = Path(__file__).parent.parent
                    candidate = tpm_dir / Path(ssl_cert).name
                    ssl_cert = str(candidate)
            logger.debug("SSL cert path resolved to: %s", ssl_cert)

        try:
            self._tp_data_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=5,
                host=host,
                port=self.settings.tp_data_db_port,
                dbname=self.settings.tp_data_db_name,
                user=self.settings.tp_data_db_user,
                password=password,
                sslmode=self.settings.tp_data_db_sslmode,
                sslrootcert=ssl_cert,
                connect_timeout=10,
            )
            self._tp_data_enabled = True
            logger.info(
                "Metrics forwarder: tp_data PostgreSQL pool initialized (host=%s, db=%s)",
                host,
                self.settings.tp_data_db_name,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Metrics forwarder: failed to init tp_data pool: %s", exc)
            try:
                _system_error_repo.log_error(
                    error_source="metrics",
                    error_code="pool_init_failed",
                    error_message=f"Metrics forwarder failed to init tp_data pool: {exc}",
                    context={"component": "metrics_forwarder", "phase": "init", "host": host},
                )
            except Exception:
                pass  # Don't break main flow
            self._tp_data_pool = None

    def start(self) -> None:
        if not self._enabled or not self._redis_client:
            logger.info(
                "Metrics forwarder not started (enabled=%s, redis_client=%s)",
                self._enabled,
                bool(self._redis_client),
            )
            return
        if self._thread:
            return
        self._thread = threading.Thread(target=self._run, name="metrics-forwarder", daemon=True)
        self._thread.start()

        # Start exit hub volume subscriber
        self._exithub_thread = threading.Thread(
            target=self._run_exithub_volume, name="exithub-volume-forwarder", daemon=True
        )
        self._exithub_thread.start()

        logger.info(
            "Metrics forwarder started (channel=%s, exithub_channel=%s, redis=%s, webapp=%s, tp_data=%s)",
            self.channel,
            self.exithub_volume_channel,
            self.settings.tp_redis_url,
            self.base_url or "disabled",
            self._tp_data_enabled,
        )

    def _run(self) -> None:
        while not self._stop:
            try:
                pubsub = self._redis_client.pubsub(ignore_subscribe_messages=True)
                pubsub.subscribe(self.channel)
                logger.info("Metrics forwarder subscribed to channel %s", self.channel)
                while not self._stop:
                    message = pubsub.get_message(timeout=1.0)
                    if not message:
                        continue
                    if message.get("type") != "message":
                        continue
                    logger.info("Metrics forwarder received raw message on %s", self.channel)
                    try:
                        payload = json.loads(message.get("data"))
                    except Exception:
                        logger.warning("Metrics forwarder received non-JSON payload")
                        continue
                    self._forward(payload)
            except Exception as exc:  # noqa: BLE001
                logger.error("Metrics forwarder loop error: %s", exc, exc_info=True)
                try:
                    _system_error_repo.log_error(
                        error_source="metrics",
                        error_code="collection_failed",
                        error_message=f"Metrics forwarder loop error: {exc}",
                        context={"component": "metrics_forwarder", "phase": "collection"},
                    )
                except Exception:
                    pass  # Don't break main flow
                time.sleep(5)

    def _run_exithub_volume(self) -> None:
        """Subscribe to exit hub volume channel and update VolumeVerifier."""
        while not self._stop:
            try:
                pubsub = self._redis_client.pubsub(ignore_subscribe_messages=True)
                pubsub.subscribe(self.exithub_volume_channel)
                logger.info("Exit hub volume forwarder subscribed to channel %s", self.exithub_volume_channel)
                while not self._stop:
                    message = pubsub.get_message(timeout=1.0)
                    if not message:
                        continue
                    if message.get("type") != "message":
                        continue
                    try:
                        payload = json.loads(message.get("data"))
                    except Exception:
                        logger.warning("Exit hub volume forwarder received non-JSON payload")
                        continue
                    self._process_exithub_volume(payload)
            except Exception as exc:  # noqa: BLE001
                logger.error("Exit hub volume forwarder loop error: %s", exc, exc_info=True)
                time.sleep(5)

    def _process_exithub_volume(self, payload: Dict[str, Any]) -> None:
        """Process exit hub volume report and update VolumeVerifier."""
        try:
            self._volume_verifier.process_exit_hub_report(payload)
            logger.debug(
                "Exit hub volume processed: exit_hub=%s miners=%d",
                payload.get("exit_hub_id") or payload.get("exit_hub_ip"),
                len(payload.get("miners", {})),
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to process exit hub volume: %s", exc)

    def _forward(self, payload: Dict[str, Any]) -> None:
        # Validate miner auth if present
        miner_id = payload.get("miner_id")
        auth_token = payload.get("auth_token")
        if miner_id and auth_token:
            try:
                secret = self._miner_registry.get_plaintext_secret(str(miner_id))
                if secret != auth_token:
                    logger.warning("Metrics payload auth failed for miner %s", miner_id)
                    return
            except Exception as exc:  # noqa: BLE001
                logger.warning("Metrics payload auth lookup failed for miner %s: %s", miner_id, exc)
                return

        registered_count = len(self._miner_registry.repository.list_miners())
        if miner_id:
            self._seen_miners.add(str(miner_id))
        try:
            with open("/tmp/tensorprox/metrics_forwarder.log", "a", encoding="utf-8") as fh:
                fh.write(f"payload origin={payload.get('origin_id')} miner={miner_id}\n")
        except Exception:
            pass
        logger.info(
            "Metrics payload received origin=%s miner=%s (registered=%s, publishers_seen=%s)",
            payload.get("origin_id"),
            miner_id,
            registered_count,
            len(self._seen_miners),
        )

        # Forward to tp_data PostgreSQL (time-series storage)
        if self._tp_data_enabled:
            self._store_to_tp_data(payload)

        # Forward to webapp (if configured)
        if self.base_url:
            self._forward_to_webapp(payload, miner_id, registered_count)

    def _store_to_tp_data(self, payload: Dict[str, Any]) -> None:
        """Store metrics in tp_data PostgreSQL for dashboard queries."""
        origin_id = payload.get("origin_id")
        miner_id = payload.get("miner_id")

        if not origin_id:
            logger.warning("Metrics payload missing origin_id, skipping tp_data store")
            return

        conn = None
        try:
            conn = self._tp_data_pool.getconn()
            with conn.cursor() as cur:
                # Insert metrics using the upsert function
                cur.execute(
                    "SELECT upsert_origin_metric(%s, %s, %s)",
                    (origin_id, miner_id, json.dumps(payload)),
                )

                # Extract security events if present
                events = payload.get("events")
                if events and isinstance(events, list):
                    cur.execute(
                        "SELECT extract_security_events(%s, %s)",
                        (origin_id, json.dumps(payload)),
                    )

            conn.commit()
            logger.debug(
                "Metrics stored in tp_data for origin=%s (miner=%s)",
                origin_id,
                miner_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to store metrics in tp_data for origin=%s: %s",
                origin_id,
                exc,
            )
            try:
                _system_error_repo.log_error(
                    error_source="metrics",
                    error_code="submission_failed",
                    error_message=f"Failed to store metrics in tp_data: {exc}",
                    context={"component": "metrics_forwarder", "phase": "submission", "origin_id": origin_id, "miner_id": miner_id},
                )
            except Exception:
                pass  # Don't break main flow
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
        finally:
            if conn:
                try:
                    self._tp_data_pool.putconn(conn)
                except Exception:
                    pass

    def _forward_to_webapp(
        self, payload: Dict[str, Any], miner_id: Optional[str], registered_count: int
    ) -> None:
        """Forward metrics to tp-webapp REST API."""
        origin_id = payload.get("origin_id")

        # Skip forwarding for terminated origins to avoid 404 errors
        if origin_id:
            # Check cache first
            if origin_id in self._terminated_origins:
                logger.debug("Skipping metrics forward for terminated origin %s", origin_id)
                return
            # Check database if not in cache
            try:
                origin = self._origin_repository.find_by_origin_id(origin_id)
                if origin and origin.get("status") == "terminated":
                    self._terminated_origins.add(origin_id)
                    logger.debug("Skipping metrics forward for terminated origin %s", origin_id)
                    return
            except Exception:
                pass  # If check fails, continue with forwarding

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        # Normalize base URL and endpoints to avoid double /api prefixes.
        base = self.base_url.rstrip("/")
        has_api_prefix = base.lower().endswith("/api")
        base_api = base if has_api_prefix else f"{base}/api"
        instances_url = f"{base_api}/instances"
        metrics_url = f"{base_api}/metrics/"

        instance_id = payload.get("instance_id") or origin_id
        if instance_id:
            try:
                resp = requests.put(
                    f"{instances_url}/{instance_id}/",
                    json=payload,
                    headers=headers,
                    timeout=10,
                )
                if resp.status_code >= 400:
                    logger.warning(
                        "Metrics forwarder PUT /instances/%s returned %s (body=%s)",
                        instance_id,
                        resp.status_code,
                        resp.text[:200],
                    )
                else:
                    logger.info(
                        "Metrics forwarder updated instance %s (origin=%s, miner=%s)",
                        instance_id,
                        payload.get("origin_id"),
                        miner_id,
                    )
                try:
                    with open("/tmp/tensorprox/metrics_forwarder.log", "a", encoding="utf-8") as fh:
                        fh.write(
                            f"put status={resp.status_code} instance={instance_id} "
                            f"origin={payload.get('origin_id')} miner={miner_id}\n"
                        )
                except Exception:
                    pass
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Metrics forwarder failed instance update for %s: %s",
                    instance_id,
                    exc,
                )
                try:
                    _system_error_repo.log_error(
                        error_source="metrics",
                        error_code="submission_failed",
                        error_message=f"Metrics forwarder failed instance update: {exc}",
                        context={"component": "metrics_forwarder", "phase": "submission", "instance_id": instance_id},
                    )
                except Exception:
                    pass  # Don't break main flow

        try:
            resp = requests.post(
                metrics_url,
                json=payload,
                headers=headers,
                timeout=10,
            )
            if resp.status_code >= 400:
                logger.warning(
                    "Metrics forwarder POST /metrics returned %s (body=%s)",
                    resp.status_code,
                    resp.text[:200],
                )
            else:
                logger.info(
                    "Metrics forwarded for origin=%s (miner=%s, registered=%s, seen=%s)",
                    payload.get("origin_id"),
                    miner_id,
                    registered_count,
                    len(self._seen_miners),
                )
            try:
                with open("/tmp/tensorprox/metrics_forwarder.log", "a", encoding="utf-8") as fh:
                    fh.write(
                        f"post status={resp.status_code} origin={payload.get('origin_id')} "
                        f"miner={miner_id} body={resp.text.strip()}\n"
                    )
            except Exception:
                pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("Metrics forwarder failed to POST metrics: %s", exc)
            try:
                _system_error_repo.log_error(
                    error_source="metrics",
                    error_code="submission_failed",
                    error_message=f"Metrics forwarder failed to POST metrics: {exc}",
                    context={"component": "metrics_forwarder", "phase": "submission", "origin_id": payload.get("origin_id")},
                )
            except Exception:
                pass  # Don't break main flow


def start_metrics_forwarder() -> None:
    """Helper to start the forwarder if configured."""
    global _forwarder_instance, _forwarder_started  # noqa: PLW0603
    if _forwarder_started:
        logger.info("Metrics forwarder already running; skipping start")
        return

    logger.info("Metrics forwarder bootstrap begin")
    _forwarder_instance = MetricsForwarder()
    if _forwarder_instance._enabled is False:
        logger.info("Metrics forwarder disabled by configuration or missing deps")
        return
    logger.info(
        "Metrics forwarder constructed (redis=%s, webapp=%s, tp_data=%s)",
        bool(_forwarder_instance._redis_client),
        _forwarder_instance.base_url or "disabled",
        _forwarder_instance._tp_data_enabled,
    )
    _forwarder_instance.start()
    _forwarder_started = True
    logger.info("Metrics forwarder bootstrap end")
