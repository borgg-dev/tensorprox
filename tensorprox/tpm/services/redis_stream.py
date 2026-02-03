"""Redis-backed streaming helpers for TPM SSE endpoints."""
from __future__ import annotations

import json
import time
from typing import Dict, Generator, Iterable, Optional, Set

from shared.config import get_tp_management_settings
from shared.utils.logging import get_logger

try:
    import redis  # type: ignore
except ImportError:  # pragma: no cover
    redis = None

logger = get_logger(__name__)


class RedisUnavailableError(Exception):
    """Raised when Redis is not installed or cannot be reached."""


def _get_client():
    if not redis:
        raise RedisUnavailableError("redis library is not installed")
    settings = get_tp_management_settings()
    try:
        client = redis.Redis.from_url(settings.tp_redis_url, socket_timeout=5)
        # Ping to validate connectivity early
        client.ping()
        return client
    except Exception as exc:  # noqa: BLE001
        raise RedisUnavailableError(str(exc)) from exc


def stream_exit_hub_events(
    *,
    exit_hub_id: str,
    channel: str,
    stop_statuses: Optional[Iterable[str]] = None,
    heartbeat_seconds: int = 15,
) -> Generator[Dict[str, object], None, None]:
    """Yield exit-hub events from Redis pub/sub filtered by exit_hub_id."""
    stop_set: Set[str] = set(stop_statuses or {"active", "failed", "terminated"})
    client = _get_client()
    pubsub = client.pubsub(ignore_subscribe_messages=True)
    try:
        pubsub.subscribe(channel)
        last_heartbeat = time.time()
        while True:
            message = pubsub.get_message(timeout=1)
            now = time.time()
            if not message:
                if now - last_heartbeat >= heartbeat_seconds:
                    yield {"event": "heartbeat", "ts": now}
                    last_heartbeat = now
                continue

            data = message.get("data")
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            if not data:
                continue

            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                logger.warning("Skipping non-JSON event on %s: %s", channel, data)
                continue

            if payload.get("exit_hub_id") != exit_hub_id:
                continue

            yield payload
            status = (payload.get("status") or "").lower()
            if status in stop_set:
                break
    finally:
        try:
            pubsub.close()
        except Exception:  # pragma: no cover - best effort
            pass


def stream_filtered_events(
    *,
    channel: str,
    filter_key: str,
    filter_value: str,
    stop_statuses: Optional[Iterable[str]] = None,
    heartbeat_seconds: int = 15,
) -> Generator[Dict[str, object], None, None]:
    """Generic pub/sub stream filtered by key/value."""
    stop_set: Set[str] = set(stop_statuses or {"applied", "failed", "terminated"})
    client = _get_client()
    pubsub = client.pubsub(ignore_subscribe_messages=True)
    try:
        pubsub.subscribe(channel)
        last_heartbeat = time.time()
        while True:
            message = pubsub.get_message(timeout=1)
            now = time.time()
            if not message:
                if now - last_heartbeat >= heartbeat_seconds:
                    yield {"event": "heartbeat", "ts": now}
                    last_heartbeat = now
                continue

            data = message.get("data")
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            if not data:
                continue

            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                logger.warning("Skipping non-JSON event on %s: %s", channel, data)
                continue

            if payload.get(filter_key) != filter_value:
                continue

            yield payload
            status = (payload.get("status") or "").lower()
            if status in stop_set:
                break
    finally:
        try:
            pubsub.close()
        except Exception:  # pragma: no cover - best effort
            pass
