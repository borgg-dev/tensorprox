"""API to proxy port updates to Miner and emit SSE-friendly events."""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from shared.utils.logging import get_logger
from tensorprox.tpm.services.miner_ports import miner_port_proxy
from tensorprox.tpm.utils.api_security import validate_api_request

bp = Blueprint("miner_ports", __name__, url_prefix="/api/v1/miner-ports")
logger = get_logger(__name__)


@bp.before_request
def _enforce_api_security():
    ok, message = validate_api_request()
    if not ok:
        return jsonify({"error": message}), 403


@bp.post("", strict_slashes=False)
def update_ports():
    payload = request.get_json(silent=True) or {}
    origin_id = payload.get("origin_id")
    miner_id = payload.get("miner_id")
    ports = payload.get("ports")
    miner_ip = payload.get("miner_ip")

    if not origin_id or not miner_id:
        return jsonify({"error": "origin_id and miner_id are required"}), 400
    if ports is None:
        return jsonify({"error": "ports are required"}), 400
    logger.info(
        "Port update requested origin_id=%s miner_id=%s ports_count=%s miner_ip=%s",
        origin_id,
        miner_id,
        len(ports) if isinstance(ports, list) else "n/a",
        miner_ip or "auto",
    )

    try:
        body, status = miner_port_proxy.update_ports(
            origin_id=origin_id,
            miner_id=miner_id,
            ports=ports,
            miner_ip=miner_ip,
        )
        return jsonify(body), status
    except ValueError as exc:
        logger.warning(
            "Port update validation failed origin_id=%s miner_id=%s: %s",
            origin_id,
            miner_id,
            exc,
        )
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Port update failed origin_id=%s miner_id=%s: %s",
            origin_id,
            miner_id,
            exc,
            exc_info=True,
        )
        return jsonify({"error": str(exc)}), 502
