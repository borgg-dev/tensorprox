"""
Heartbeat Pusher - Pushes TPM load metrics to webapp for load balancing.

This service runs every 30s and sends:
- Validator UID and hotkey
- TPM public URL
- Load metrics: queue depth, origins assigned, max origins
- System metrics: CPU and memory usage

The webapp uses this information for weighted-random TPM selection.
"""
import os
import threading
import time
from typing import Optional

import psutil
import requests
from loguru import logger

from tensorprox.tpm.app import get_validator_uid, get_validator_hotkey


# Configuration from environment
HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get('TPM_HEARTBEAT_INTERVAL_SECONDS', '30'))
TP_WEBAPP_URL = os.environ.get('TP_WEBAPP_URL', '')
TPM_PUBLIC_URL = os.environ.get('TPM_PUBLIC_URL', '')
TPM_INTERNAL_SECRET = os.environ.get('TPM_INTERNAL_SECRET', '')

_heartbeat_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()


def _get_queue_depth() -> int:
    """Get current deployment queue depth."""
    try:
        from tensorprox.tpm.services.deploy_queue import get_deploy_queue
        queue = get_deploy_queue()
        return queue.queue.qsize()
    except Exception as e:
        logger.debug(f"Failed to get queue depth: {e}")
        return 0


def _get_origins_count() -> int:
    """Get current number of assigned origins for this validator."""
    try:
        from shared.database import get_tp_db_connection

        validator_uid = get_validator_uid()
        if validator_uid is None:
            return 0

        conn = get_tp_db_connection()
        try:
            result = conn.query_one(
                "SELECT COUNT(*) as count FROM tensorprox_origins WHERE status = 'active' AND validator_uid = %s",
                (validator_uid,)
            )
            return result['count'] if result else 0
        finally:
            conn.close()
    except Exception as e:
        logger.debug(f"Failed to get origins count: {e}")
        return 0


def _get_system_metrics() -> tuple[float, float]:
    """Get CPU and memory usage percentages."""
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory().percent
        return cpu, memory
    except Exception as e:
        logger.debug(f"Failed to get system metrics: {e}")
        return 0.0, 0.0


def _send_heartbeat():
    """Send a single heartbeat to the webapp."""
    if not TP_WEBAPP_URL:
        logger.debug("TP_WEBAPP_URL not configured, skipping heartbeat")
        return

    if not TPM_PUBLIC_URL:
        logger.debug("TPM_PUBLIC_URL not configured, skipping heartbeat")
        return

    validator_uid = get_validator_uid()
    if validator_uid is None:
        logger.debug("Validator UID not set, skipping heartbeat")
        return

    cpu_percent, memory_percent = _get_system_metrics()

    # Get SS58 hotkey address (set by tpm_integration from wallet)
    validator_hotkey = get_validator_hotkey() or ''

    payload = {
        'validator_uid': validator_uid,
        'hotkey': validator_hotkey,
        'url': TPM_PUBLIC_URL,
        'queue_depth': _get_queue_depth(),
        'origins_assigned': _get_origins_count(),
        'cpu_percent': round(cpu_percent, 2),
        'memory_percent': round(memory_percent, 2),
    }

    try:
        url = f"{TP_WEBAPP_URL.rstrip('/')}/api/tpm/heartbeat"
        headers = {'Content-Type': 'application/json'}
        if TPM_INTERNAL_SECRET:
            headers['X-TPM-Secret'] = TPM_INTERNAL_SECRET

        response = requests.post(
            url,
            json=payload,
            timeout=10,
            headers=headers
        )

        if response.status_code == 200:
            logger.debug(f"Heartbeat sent successfully: uid={validator_uid}, origins={payload['origins_assigned']}")
        else:
            logger.warning(f"Heartbeat failed: status={response.status_code}, body={response.text[:200]}")
    except requests.exceptions.Timeout:
        logger.warning("Heartbeat request timed out")
    except requests.exceptions.RequestException as e:
        logger.warning(f"Heartbeat request failed: {e}")


def _heartbeat_loop():
    """Background loop that sends heartbeats every interval."""
    logger.info(f"Heartbeat pusher started (interval={HEARTBEAT_INTERVAL_SECONDS}s)")

    # Wait a bit before first heartbeat to let services initialize
    time.sleep(5)

    while not _stop_event.is_set():
        try:
            _send_heartbeat()
        except Exception as e:
            logger.error(f"Heartbeat error: {e}", exc_info=True)

        # Wait for next interval, but check stop event periodically
        for _ in range(HEARTBEAT_INTERVAL_SECONDS):
            if _stop_event.is_set():
                break
            time.sleep(1)

    logger.info("Heartbeat pusher stopped")


def start_heartbeat_pusher():
    """Start the heartbeat pusher background thread."""
    global _heartbeat_thread

    if _heartbeat_thread is not None and _heartbeat_thread.is_alive():
        logger.debug("Heartbeat pusher already running")
        return

    if not TP_WEBAPP_URL:
        logger.info("TP_WEBAPP_URL not configured, heartbeat pusher disabled")
        return

    _stop_event.clear()
    _heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        name="tpm-heartbeat-pusher",
        daemon=True
    )
    _heartbeat_thread.start()
    logger.info(f"Heartbeat pusher started: url={TP_WEBAPP_URL}, interval={HEARTBEAT_INTERVAL_SECONDS}s")


def stop_heartbeat_pusher():
    """Stop the heartbeat pusher background thread."""
    global _heartbeat_thread

    if _heartbeat_thread is None:
        return

    _stop_event.set()
    _heartbeat_thread.join(timeout=5)
    _heartbeat_thread = None
    logger.info("Heartbeat pusher stopped")


def is_heartbeat_pusher_running() -> bool:
    """Check if heartbeat pusher is running."""
    return _heartbeat_thread is not None and _heartbeat_thread.is_alive()
