"""Port update proxy between webapp and Miner."""
from __future__ import annotations

import json
from typing import Dict, List, Optional, Tuple

import requests

from shared.config import get_settings
from shared.utils.logging import get_logger

from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository
from tensorprox.tpm.repositories.miner_repository import MinerRepository
from tensorprox.tpm.repositories.origin_repository import OriginRepository
from tensorprox.tpm.services.miner_registry import MinerRegistry, MinerRegistryError
from tensorprox.tpm.services.operation_tracker import PROGRESS_PORT_UPDATE, progress_hint

logger = get_logger(__name__)

PORT_EVENTS_CHANNEL = "tensorprox.miner_ports"


def _publish_event(payload: Dict[str, object]) -> None:
    try:
        import redis  # type: ignore
    except ImportError:  # pragma: no cover
        return
    from shared.config import get_tp_management_settings

    settings = get_tp_management_settings()
    try:
        client = redis.Redis.from_url(settings.tp_redis_url)
        client.publish(PORT_EVENTS_CHANNEL, json.dumps(payload))
    except Exception as exc:  # noqa: BLE001
        logger.debug("Failed to publish port event: %s", exc)


def _normalize_ports(raw_ports) -> List[int]:
    if raw_ports is None:
        return []
    if isinstance(raw_ports, str):
        parts = [p.strip() for p in raw_ports.split(",") if p.strip()]
        ports = [int(p) for p in parts]
    elif isinstance(raw_ports, list):
        ports = [int(p) for p in raw_ports]
    else:
        raise ValueError("ports must be a list of integers or a comma-separated string")
    # Deduplicate while preserving order
    seen = set()
    normalized = []
    for p in ports:
        if p not in seen:
            seen.add(p)
            normalized.append(p)
    return normalized


class MinerPortProxy:
    """Forward port updates to Miner and emit events for SSE subscribers."""

    def __init__(self):
        self.settings = get_settings()
        self.miner_registry = MinerRegistry()
        self.miner_repository = MinerRepository()
        self.origin_repository = OriginRepository()
        self.exit_hub_repository = ExitHubRepository()

    def update_ports(
        self,
        *,
        origin_id: str,
        miner_id: str,
        ports,
        miner_ip: Optional[str] = None,
    ) -> Tuple[Dict[str, object], int]:
        normalized_ports = _normalize_ports(ports)

        received_payload = {
            "status": "received",
            "origin_id": origin_id,
            "miner_id": miner_id,
            "requested_ports": normalized_ports,
        }
        received_progress = self._progress_hint("received")
        if received_progress:
            received_payload["progress"] = received_progress
        _publish_event(received_payload)

        processing_payload = {
            "status": "processing",
            "origin_id": origin_id,
            "miner_id": miner_id,
            "requested_ports": normalized_ports,
        }
        processing_progress = self._progress_hint("processing")
        if processing_progress:
            processing_payload["progress"] = processing_progress
        _publish_event(processing_payload)

        try:
            response_data = self._call_miner(
                origin_id=origin_id,
                miner_id=miner_id,
                ports=normalized_ports,
                miner_ip=miner_ip,
            )

            # Sync ports to TPM database (TPM is source of truth)
            self._sync_ports_to_tpm(origin_id, normalized_ports)

            applied_payload = {
                **response_data,
                "origin_id": origin_id,
                "miner_id": miner_id,
                "status": response_data.get("status") or "applied",
            }
            applied_progress = self._progress_hint(applied_payload["status"])
            if applied_progress:
                applied_payload["progress"] = applied_progress
            _publish_event(applied_payload)
            return applied_payload, 200
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Port update failed origin_id=%s miner_id=%s: %s",
                origin_id,
                miner_id,
                exc,
                exc_info=True,
            )
            error_payload = {
                "status": "failed",
                "origin_id": origin_id,
                "miner_id": miner_id,
                "error": str(exc),
            }
            failed_progress = self._progress_hint("failed")
            if failed_progress:
                error_payload["progress"] = failed_progress
            _publish_event(error_payload)
            raise

    def _call_miner(
        self,
        *,
        origin_id: str,
        miner_id: str,
        ports: List[int],
        miner_ip: Optional[str],
    ) -> Dict[str, object]:
        # Origin-centric miner IP resolution for multi-miner scalability
        base_ip = self._resolve_miner_ip(origin_id, miner_id, miner_ip)

        url = f"http://{base_ip}:{self.settings.miner_port}/api/v1/origins/{origin_id}/ports"
        headers = self._build_headers(miner_id)
        payload = {
            "origin_id": origin_id,
            "ports": ports,
        }
        logger.info(
            "Forwarding port update to miner %s (%s): origin=%s ports=%s",
            miner_id,
            base_ip,
            origin_id,
            ports,
        )
        resp = requests.patch(url, json=payload, headers=headers, timeout=(5, 30))
        if resp.status_code >= 400:
            raise RuntimeError(f"Miner port update failed {resp.status_code}: {resp.text}")
        try:
            return resp.json()
        except ValueError as exc:
            raise RuntimeError("Invalid JSON response from Miner") from exc

    def _resolve_miner_ip(
        self,
        origin_id: str,
        miner_id: str,
        miner_ip_override: Optional[str],
    ) -> str:
        """Resolve the miner IP for a given origin.

        Resolution priority:
        1. Explicit miner_ip override (for emergency/testing)
        2. Origin's assigned miner's current_ip (canonical, origin-centric)
        3. Provided miner_id's current_ip (fallback if origin not found)
        4. Config fallback (last resort, logs warning)
        """
        # 1. Explicit override takes precedence
        if miner_ip_override:
            logger.debug(
                "Using explicit miner_ip override for origin=%s: %s",
                origin_id, miner_ip_override
            )
            return miner_ip_override

        # 2. Origin-centric lookup: which miner serves THIS origin?
        origin = self.origin_repository.find_by_origin_id(origin_id)
        if origin and origin.get("miner_id"):
            origin_miner_id = origin["miner_id"]
            miner = self.miner_repository.get_miner(origin_miner_id)
            if miner and miner.get("current_ip"):
                logger.debug(
                    "Resolved miner IP from origin=%s -> miner=%s -> ip=%s",
                    origin_id, origin_miner_id, miner["current_ip"]
                )
                return miner["current_ip"]

        # 3. Fallback: use provided miner_id directly
        if miner_id:
            miner = self.miner_repository.get_miner(miner_id)
            if miner and miner.get("current_ip"):
                logger.debug(
                    "Resolved miner IP from miner_id=%s -> ip=%s",
                    miner_id, miner["current_ip"]
                )
                return miner["current_ip"]

        # 4. Last resort: localhost fallback (should not happen in production)
        logger.warning(
            "Could not resolve miner IP for origin=%s miner_id=%s, using fallback=127.0.0.1",
            origin_id, miner_id
        )
        return "127.0.0.1"

    def _build_headers(self, miner_id: str) -> Dict[str, str]:
        try:
            secret = self.miner_registry.get_plaintext_secret(miner_id)
        except MinerRegistryError:
            return {}
        return {"Authorization": f"Bearer {secret}"}

    def _sync_ports_to_tpm(self, origin_id: str, ports: List[int]) -> None:
        """
        Sync port configuration to TPM database.

        TPM is the source of truth - after successful Miner update,
        persist the ports in the exit hub metadata.
        """
        try:
            updated = self.exit_hub_repository.update_metadata_by_origin(
                origin_id, {"ports": ports}
            )
            if updated:
                logger.info(
                    "Synced ports to TPM for origin=%s ports=%s",
                    origin_id, ports
                )
            else:
                logger.warning(
                    "No active exit hub found in TPM for origin=%s to sync ports",
                    origin_id
                )
        except Exception as exc:  # noqa: BLE001
            # Log but don't fail the request - Miner update succeeded
            logger.error(
                "Failed to sync ports to TPM for origin=%s: %s",
                origin_id, exc, exc_info=True
            )

    @staticmethod
    def _progress_hint(status: str) -> Optional[Dict[str, object]]:
        """Progress labels for port updates."""
        return progress_hint(status, PROGRESS_PORT_UPDATE)


miner_port_proxy = MinerPortProxy()
