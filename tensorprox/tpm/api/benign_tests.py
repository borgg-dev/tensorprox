"""Flask blueprint for benign test packet tracking.

The validator sends TPTEST packets through the production path (scrubber → exit hub)
to verify traffic is flowing correctly. This blueprint provides endpoints for:

1. Registering expected packet IDs before sending test traffic
2. Exit hub reporting which packets it received
3. Validator querying test results (pass rate)
4. Cancelling/cleaning up tests

All state is kept in-memory (dict with TTL cleanup) — tests are short-lived (~30s)
and only relevant during audit cycles.
"""

from __future__ import annotations

import time
import threading
from typing import Any, Dict, Set

from flask import Blueprint, jsonify, request

from shared.utils.logging import get_logger

bp = Blueprint("benign_tests", __name__, url_prefix="/api/v1/benign-tests")
logger = get_logger(__name__)

# In-memory store: test_id → test record
_tests: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()

# Tests older than this are purged automatically
_TTL_SECONDS = 120


def _cleanup_expired() -> None:
    """Remove tests older than _TTL_SECONDS. Called under _lock."""
    now = time.time()
    expired = [
        tid for tid, t in _tests.items()
        if now - t["created_at"] > _TTL_SECONDS
    ]
    for tid in expired:
        del _tests[tid]
    if expired:
        logger.debug("Purged %d expired benign tests", len(expired))


@bp.post("/register")
def register_test():
    """
    Register expected packet IDs for a benign test.

    Body JSON:
        test_id: str          — unique test identifier
        miner_uid: int        — miner being tested
        packet_ids: list[str] — packet IDs that will be sent
        timestamp: str        — (optional) caller timestamp
        scrubber_ip: str      — (optional) scrubber being tested
        origin_id: str        — (optional) origin for the test traffic

    Returns 200 on success.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "bad_request", "message": "JSON body required"}), 400

    test_id = data.get("test_id")
    miner_uid = data.get("miner_uid")
    packet_ids = data.get("packet_ids")

    if not test_id or miner_uid is None or not packet_ids:
        return jsonify({
            "error": "bad_request",
            "message": "test_id, miner_uid, and packet_ids are required",
        }), 400

    with _lock:
        _cleanup_expired()
        _tests[test_id] = {
            "miner_uid": miner_uid,
            "packet_ids": set(packet_ids),
            "received_ids": set(),
            "created_at": time.time(),
            "status": "active",
            "scrubber_ip": data.get("scrubber_ip"),
            "origin_id": data.get("origin_id"),
        }

    logger.debug(
        "Registered benign test %s for miner %s with %d packets",
        test_id, miner_uid, len(packet_ids),
    )

    return jsonify({
        "test_id": test_id,
        "status": "registered",
        "packets_registered": len(packet_ids),
    }), 200


@bp.get("/<test_id>/results")
def get_results(test_id: str):
    """
    Return pass rate and received IDs for a benign test.

    Query params:
        miner_uid: int  — miner UID (for validation)
        timeout: int    — (unused server-side, included for client compat)

    Returns 200 with test results, or 404 if test not found.
    """
    with _lock:
        _cleanup_expired()
        test = _tests.get(test_id)

    if test is None:
        return jsonify({
            "error": "not_found",
            "message": f"Test {test_id} not found or expired",
        }), 404

    packets_sent = len(test["packet_ids"])
    received_ids = list(test["received_ids"])
    packets_received = len(received_ids)
    pass_rate = packets_received / packets_sent if packets_sent > 0 else 0.0

    return jsonify({
        "test_id": test_id,
        "miner_uid": test["miner_uid"],
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "received_ids": received_ids,
        "pass_rate": pass_rate,
        "completed": test["status"] != "active",
    }), 200


@bp.post("/<test_id>/cancel")
def cancel_test(test_id: str):
    """
    Cancel and remove a benign test.

    Body JSON (optional):
        miner_uid: int — for logging/validation

    Returns 200 on success, 404 if test not found.
    """
    with _lock:
        _cleanup_expired()
        test = _tests.pop(test_id, None)

    if test is None:
        return jsonify({
            "error": "not_found",
            "message": f"Test {test_id} not found or expired",
        }), 404

    logger.debug("Cancelled benign test %s for miner %s", test_id, test["miner_uid"])

    return jsonify({
        "test_id": test_id,
        "status": "cancelled",
    }), 200


@bp.post("/<test_id>/report-received")
def report_received(test_id: str):
    """
    Exit hub reports which packet IDs it received for a test.

    Body JSON:
        packet_ids: list[str] — packet IDs that were received

    Returns 200 with updated counts, 404 if test not found.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "bad_request", "message": "JSON body required"}), 400

    received = data.get("packet_ids")
    if not received or not isinstance(received, list):
        return jsonify({
            "error": "bad_request",
            "message": "packet_ids list is required",
        }), 400

    with _lock:
        _cleanup_expired()
        test = _tests.get(test_id)
        if test is None:
            return jsonify({
                "error": "not_found",
                "message": f"Test {test_id} not found or expired",
            }), 404

        # Only accept IDs that were registered
        valid_ids = set(received) & test["packet_ids"]
        test["received_ids"].update(valid_ids)
        matched = len(valid_ids)
        total_received = len(test["received_ids"])

    logger.debug(
        "Test %s: received %d packet IDs (%d matched, %d total received)",
        test_id, len(received), matched, total_received,
    )

    return jsonify({
        "test_id": test_id,
        "matched": matched,
        "total_received": total_received,
    }), 200
