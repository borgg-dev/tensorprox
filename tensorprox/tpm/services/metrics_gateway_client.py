"""Client for pushing origin snapshots into the Metrics Gateway ingestion API."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

from shared.config import get_tp_management_settings
from shared.utils.logging import get_logger


class MetricsGatewayClient:
    """Best-effort publisher for miner/exit-hub metrics snapshots."""

    def __init__(self):
        self.settings = get_tp_management_settings()
        self.ingest_url: Optional[str] = self.settings.tp_metrics_ingest_url
        self.api_key: Optional[str] = self.settings.tp_metrics_api_key
        self.logger = get_logger(__name__)
        self.enabled = bool(self.ingest_url)
        if not self.enabled:
            self.logger.debug("Metrics gateway client disabled (no TP_METRICS_INGEST_URL).")

    def is_enabled(self) -> bool:
        return self.enabled

    def publish_snapshot(self, payload: Dict[str, Any]) -> bool:
        """Send a snapshot payload to the ingestion API."""
        if not self.enabled or not self.ingest_url:
            return False

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            response = requests.post(self.ingest_url, json=payload, timeout=10, headers=headers)
            response.raise_for_status()
            self.logger.debug("Pushed metrics snapshot for origin %s", payload.get("origin_id"))
            return True
        except requests.RequestException as exc:  # noqa: BLE001
            self.logger.warning(
                "Failed to push metrics snapshot for origin %s: %s",
                payload.get("origin_id"),
                exc,
            )
            return False

    @staticmethod
    def build_snapshot_body(
        *,
        origin_id: str,
        exit_hub_ip: Optional[str],
        status: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Translate TensorProx metadata into the Metrics Gateway schema."""
        metadata = metadata or {}
        metrics = metadata.get("metrics") or {}

        def _metric_value(key: str, default: float = 0.0) -> float:
            try:
                return float(metrics.get(key, default))
            except (TypeError, ValueError):
                return default

        def _int_value(key: str, default: int = 0) -> int:
            try:
                return int(metrics.get(key, default))
            except (TypeError, ValueError):
                return default

        return {
            "origin_id": origin_id,
            "eip": exit_hub_ip or metadata.get("emn_ip") or "",
            "status": status,
            "uptime_days": _int_value("uptime_days", 0),
            "bandwidth_usage": _metric_value("bandwidth_usage"),
            "volume_processed": _metric_value("volume_processed"),
            "latency": _metric_value("latency"),
            "cpu_usage": _metric_value("cpu_usage"),
            "memory_usage": metrics.get("memory_usage"),
            "active_connections": metrics.get("active_connections"),
            "anomalies_count": _int_value("anomalies_count", 0),
            "anomalies": metrics.get("anomalies"),
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
