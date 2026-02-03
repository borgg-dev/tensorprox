"""Placeholder blueprint for miner-generated lifecycle events."""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from shared.utils.logging import get_logger

logger = get_logger(__name__)

bp = Blueprint("miner_events", __name__, url_prefix="/api/v1/miner-events")


@bp.post('', strict_slashes=False)
def ingest_event():
    """
    Accept miner-side lifecycle events (heartbeat/ack/etc.).

    Currently acts as a stub so integrations can POST payloads and receive a 202
    while the asynchronous ingestion workflow is finalized.
    """
    payload = request.get_json(silent=True) or {}
    event_type = payload.get("event_type") or "unknown"
    # Log event type only - payload may contain sensitive data
    logger.info("Received miner event stub: type=%s", event_type)
    return jsonify({
        "status": "accepted",
        "message": "Miner events endpoint is scaffolded; payload recorded for future processing.",
        "event_type": event_type,
    }), 202
