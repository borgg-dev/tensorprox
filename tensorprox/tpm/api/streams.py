"""Authenticated streaming endpoints backed by Redis."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

from flask import Blueprint, Response, jsonify, stream_with_context

from tensorprox.tpm.services.redis_stream import (
    RedisUnavailableError,
    stream_exit_hub_events,
    stream_filtered_events,
)
from tensorprox.tpm.services.operation_tracker import PROGRESS_EXIT_HUB, progress_hint
from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository
from tensorprox.tpm.services.notifier import ExitHubNotifier
from tensorprox.tpm.utils.api_security import validate_api_request
from shared.utils.logging import get_logger

bp = Blueprint("streams", __name__, url_prefix="/api/v1/streams")
logger = get_logger(__name__)


@bp.before_request
def _enforce_api_security():
    ok, message = validate_api_request()
    if not ok:
        return jsonify({"error": message}), 403


@bp.get("/exit-hubs/<exit_hub_id>")
def stream_exit_hub(exit_hub_id: str):
    """Server-Sent Events stream for exit-hub lifecycle events."""
    channel = ExitHubNotifier.CHANNEL
    stop_statuses: Iterable[str] = {"failed", "terminated", "cancelled"}
    repo = ExitHubRepository()

    def event_stream():
        logger.info("SSE start exit_hub_id=%s", exit_hub_id)
        # Emit a snapshot of current state if available, otherwise synthetic terminal events
        try:
            record = repo.get_exit_hub(exit_hub_id)
        except Exception as exc:
            logger.error("SSE lookup failed for exit_hub_id=%s: %s", exit_hub_id, exc, exc_info=True)
            error_body = {"error": "sse_stream_error", "message": str(exc)}
            yield _format_sse(error_body, event="error")
            return

        if record:
            current_status = (record.get("status") or "").lower()
            progress = progress_hint(current_status, PROGRESS_EXIT_HUB)
            payload = {
                "exit_hub_id": exit_hub_id,
                "status": current_status,
                "metadata": record.get("metadata") or {},
            }
            if progress:
                payload["metadata"] = {**payload["metadata"], "progress": progress}
            yield _format_sse(payload)

            # If already in terminal state, don't wait for more events
            if current_status in stop_statuses:
                logger.info("SSE exit_hub_id=%s already terminal=%s, closing stream", exit_hub_id, current_status)
                return
        else:
            # No record exists (clean slate) – emit synthetic terminating->terminated to unblock clients.
            for status in ("terminating", "terminated"):
                progress = progress_hint(status, PROGRESS_EXIT_HUB)
                payload = {
                    "exit_hub_id": exit_hub_id,
                    "status": status,
                    "metadata": {
                        "action": "terminate",
                        "synthetic": True,
                    },
                }
                if progress:
                    payload["metadata"]["progress"] = progress
                yield _format_sse(payload)
            logger.info("SSE exit_hub_id=%s synthetic terminate emitted", exit_hub_id)
            return

        while True:
            try:
                for payload in stream_exit_hub_events(
                    exit_hub_id=exit_hub_id,
                    channel=channel,
                    stop_statuses=stop_statuses,
                ):
                    if payload.get("event") == "heartbeat":
                        yield ": heartbeat\n\n"
                        continue
                    yield _format_sse(payload)
                    # Stop after terminal states
                    if (payload.get("status") or "").lower() in stop_statuses:
                        logger.info("SSE exit_hub_id=%s terminal=%s", exit_hub_id, payload.get("status"))
                        return
            except RedisUnavailableError as exc:
                logger.error("SSE exit_hub_id=%s redis unavailable: %s", exit_hub_id, exc, exc_info=True)
                error_body = {"error": "redis_unavailable", "message": str(exc)}
                yield _format_sse(error_body, event="error")
                return
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("SSE exit_hub_id=%s stream error: %s", exit_hub_id, exc, exc_info=True)
                error_body = {"error": "sse_stream_error", "message": str(exc)}
                yield _format_sse(error_body, event="error")
                return

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }
    return Response(
        stream_with_context(event_stream()),
        status=200,
        headers=headers,
    )


@bp.get("/miner-ports/<origin_id>")
def stream_miner_ports(origin_id: str):
    """SSE stream for miner port update events."""
    channel = "tensorprox.miner_ports"
    stop_statuses: Iterable[str] = {"applied", "failed"}

    def event_stream():
        logger.info("SSE start miner_ports origin_id=%s", origin_id)
        try:
            for payload in stream_filtered_events(
                channel=channel,
                filter_key="origin_id",
                filter_value=origin_id,
                stop_statuses=stop_statuses,
            ):
                if payload.get("event") == "heartbeat":
                    yield ": heartbeat\n\n"
                    continue
                yield _format_sse(payload)
                status = (payload.get("status") or "").lower()
                if status in stop_statuses:
                    logger.info("SSE miner_ports origin_id=%s terminal=%s", origin_id, status)
                    return
        except RedisUnavailableError as exc:
            logger.error("SSE miner_ports origin_id=%s redis unavailable: %s", origin_id, exc, exc_info=True)
            error_body = {"error": "redis_unavailable", "message": str(exc)}
            yield _format_sse(error_body, event="error")
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("SSE miner_ports origin_id=%s stream error: %s", origin_id, exc, exc_info=True)
            error_body = {"error": "sse_stream_error", "message": str(exc)}
            yield _format_sse(error_body, event="error")

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }
    return Response(
        stream_with_context(event_stream()),
        status=200,
        headers=headers,
    )


def _format_sse(payload: dict, event: str | None = None) -> str:
    """Format dict payload as SSE line(s)."""
    body = {
        **payload,
        "server_ts": datetime.now(timezone.utc).isoformat(),
    }
    lines = []
    if event:
        lines.append(f"event: {event}")
    lines.append(f"data: {json.dumps(body)}")
    return "\n".join(lines) + "\n\n"
