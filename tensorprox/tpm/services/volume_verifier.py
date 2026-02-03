"""
Volume Service

Tracks volume processed by miners via exit hub reports.

Architecture:
- Exit hubs report volume via Redis channel "exithub.volume"
- Exit hubs are TPM-managed infrastructure (trusted source)
- Volume is used for 70% of reward calculation

Security Properties:
- Miners cannot manipulate exit hub data (they don't control exit hubs)
- Only assigned miners can have volume > 0
- Validators receive attested volume from TPM-controlled infrastructure
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class VolumeReport:
    """Volume report from exit hub."""
    origin_id: str
    origin_ip: str
    miner_id: str
    miner_uid: Optional[int] = None
    bytes: int = 0
    packets: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    exit_hub_id: Optional[str] = None


@dataclass
class VerifiedVolume:
    """Volume for a miner/origin combination (from exit hub)."""
    miner_uid: int
    miner_id: str
    origin_id: str
    origin_ip: str

    # Volume from exit hub (ground truth)
    exit_hub_bytes: int = 0
    exit_hub_packets: int = 0

    # Timestamps
    last_report: Optional[datetime] = None
    recorded_at: Optional[datetime] = None


class VolumeVerifier:
    """
    Volume Service.

    Collects volume reports from exit hubs and provides
    verified volume for reward calculation.
    """

    def __init__(self, db_conn=None):
        """
        Initialize the volume verifier.

        Args:
            db_conn: Optional database connection for persistence
        """
        self.db_conn = db_conn
        self._lock = threading.Lock()

        # In-memory caches (per-origin)
        self._exit_hub_volumes: Dict[str, VolumeReport] = {}  # origin_id -> latest
        self._verified_volumes: Dict[str, VerifiedVolume] = {}  # origin_id -> verified

        # Miner UID mapping (miner_id -> miner_uid)
        self._miner_uid_map: Dict[str, int] = {}
        # Cache: origin_id -> miner_uid (populated from DB on first lookup)
        self._origin_uid_cache: Dict[str, int] = {}

    def set_miner_uid(self, miner_id: str, miner_uid: int) -> None:
        """Map miner_id to miner_uid for reward calculation."""
        self._miner_uid_map[miner_id] = miner_uid

    def _resolve_miner_uid(self, origin_id: str) -> Optional[int]:
        """Resolve origin_id to miner_uid via tensorprox_origins + subnet_miners."""
        # Check in-memory cache first (origin_id -> miner_uid)
        cached = self._origin_uid_cache.get(origin_id)
        if cached is not None:
            return cached

        try:
            from shared.database import get_connection
            conn = get_connection()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT sm.miner_uid "
                        "FROM tensorprox_origins o "
                        "JOIN subnet_miners sm ON o.miner_id = sm.miner_id "
                        "WHERE o.origin_id = %s AND o.status = 'active' "
                        "AND sm.miner_uid IS NOT NULL "
                        "LIMIT 1",
                        (origin_id,)
                    )
                    row = cur.fetchone()
                    if row:
                        self._origin_uid_cache[origin_id] = row[0]
                        logger.info("Resolved origin %s -> miner_uid %d", origin_id, row[0])
                        return row[0]
            finally:
                conn.close()
        except Exception as e:
            logger.warning("Failed to resolve miner_uid for origin %s: %s", origin_id, e)
        return None

    def process_exit_hub_volume(
        self,
        origin_id: str,
        origin_ip: str,
        miner_id: str,
        exit_hub_id: str,
        bytes_processed: int,
        packets: int = 0,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """
        Process volume report from an exit hub.

        Called when exit-hub-agent reports volume to TPM.
        """
        report = VolumeReport(
            origin_id=origin_id,
            origin_ip=origin_ip,
            miner_id=miner_id,
            miner_uid=self._miner_uid_map.get(miner_id),
            bytes=bytes_processed,
            packets=packets,
            timestamp=timestamp or datetime.now(timezone.utc),
            exit_hub_id=exit_hub_id,
        )

        with self._lock:
            self._exit_hub_volumes[origin_id] = report
            self._update_volume(origin_id)

        logger.debug(
            "Exit hub volume for origin %s: %d bytes via %s",
            origin_id, bytes_processed, exit_hub_id
        )

    def _update_volume(self, origin_id: str) -> None:
        """
        Update volume record for an origin.

        Called internally when exit hub reports.
        """
        exit_hub = self._exit_hub_volumes.get(origin_id)

        if not exit_hub:
            return

        miner_id = exit_hub.miner_id
        origin_ip = exit_hub.origin_ip

        self._verified_volumes[origin_id] = VerifiedVolume(
            miner_uid=self._miner_uid_map.get(miner_id, 0),
            miner_id=miner_id,
            origin_id=origin_id,
            origin_ip=origin_ip,
            exit_hub_bytes=exit_hub.bytes,
            exit_hub_packets=exit_hub.packets,
            last_report=exit_hub.timestamp,
            recorded_at=datetime.now(timezone.utc),
        )

    def get_verified_volume(self, origin_id: str) -> Optional[VerifiedVolume]:
        """Get volume for an origin."""
        with self._lock:
            return self._verified_volumes.get(origin_id)

    def get_miner_verified_volume(self, miner_uid: int) -> Dict[str, VerifiedVolume]:
        """
        Get all volumes for a miner.

        Returns dict of origin_id -> VerifiedVolume
        """
        result = {}
        with self._lock:
            for origin_id, verified in self._verified_volumes.items():
                if verified.miner_uid == miner_uid:
                    result[origin_id] = verified
        return result

    def get_miner_total_verified_bytes(self, miner_uid: int) -> int:
        """
        Get total bytes for a miner across all origins.

        Returns:
            Total bytes processed
        """
        total_bytes = 0

        with self._lock:
            for verified in self._verified_volumes.values():
                if verified.miner_uid == miner_uid:
                    total_bytes += verified.exit_hub_bytes

        return total_bytes

    def get_all_miner_volumes(self) -> Dict[int, int]:
        """
        Get volume for all miners.

        Returns:
            Dict of miner_uid -> total_bytes
        """
        result: Dict[int, int] = {}

        with self._lock:
            for verified in self._verified_volumes.values():
                uid = verified.miner_uid
                if uid not in result:
                    result[uid] = 0
                result[uid] += verified.exit_hub_bytes

        return result

    def get_stats(self) -> Dict:
        """Get overall volume statistics."""
        with self._lock:
            total_origins = len(self._verified_volumes)
            total_bytes = sum(
                v.exit_hub_bytes for v in self._verified_volumes.values()
            )
            total_packets = sum(
                v.exit_hub_packets for v in self._verified_volumes.values()
            )
            unique_miners = len(set(
                v.miner_uid for v in self._verified_volumes.values()
            ))

        return {
            "total_origins": total_origins,
            "unique_miners": unique_miners,
            "total_bytes": total_bytes,
            "total_packets": total_packets,
        }

    def process_exit_hub_report(self, report: Dict) -> None:
        """
        Process full exit hub volume report (from exit-hub-agent).

        The report format is:
        {
            "type": "exit_hub_volume",
            "exit_hub_id": "...",
            "exit_hub_ip": "...",
            "miners": {
                "57": {"rx_bytes": ..., "rx_packets": ..., ...},
                ...
            },
            "totals": {...},
            "deltas": {...},
        }
        """
        if report.get("type") != "exit_hub_volume":
            return

        exit_hub_id = report.get("exit_hub_id", "")
        exit_hub_ip = report.get("exit_hub_ip", "")
        miners_data = report.get("miners", {})
        timestamp_str = report.get("timestamp")

        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        # Get origin_id from report (exit hub knows its assigned origin)
        report_origin_id = report.get("origin_id")

        for key, miner_data in miners_data.items():
            # Key can be either:
            # - An integer miner UID (legacy format from scrubber)
            # - An origin_id like "O91" (from exit hub agent)
            try:
                miner_uid = int(key)
                origin_id = f"miner_{miner_uid}"
            except ValueError:
                # Key is an origin_id — resolve miner_uid from DB
                origin_id = key if key.startswith("O") else (report_origin_id or key)
                miner_uid = self._resolve_miner_uid(origin_id)
                if miner_uid is None:
                    logger.warning(
                        "Could not resolve miner_uid for origin %s, skipping volume",
                        origin_id
                    )
                    continue

            rx_bytes = miner_data.get("rx_bytes", 0)
            rx_packets = miner_data.get("rx_packets", 0)

            with self._lock:
                # Update miner UID map
                self._miner_uid_map[f"miner-{miner_uid}"] = miner_uid

                report_obj = VolumeReport(
                    origin_id=origin_id,
                    origin_ip="",  # Not available in this report
                    miner_id=f"miner-{miner_uid}",
                    miner_uid=miner_uid,
                    bytes=rx_bytes,
                    packets=rx_packets,
                    timestamp=timestamp,
                    exit_hub_id=exit_hub_id,
                )

                self._exit_hub_volumes[origin_id] = report_obj
                self._update_volume(origin_id)

        logger.debug(
            "Processed exit hub report from %s: %d miners",
            exit_hub_id or exit_hub_ip, len(miners_data)
        )

    def to_dict_for_api(self, miner_uid: int) -> Dict:
        """
        Get volume data formatted for API response.

        This is what validators receive when querying TPM.
        """
        total_bytes = self.get_miner_total_verified_bytes(miner_uid)
        origins = self.get_miner_verified_volume(miner_uid)

        origin_details = []
        for origin_id, v in origins.items():
            origin_details.append({
                "origin_id": v.origin_id,
                "origin_ip": v.origin_ip,
                "exit_hub_bytes": v.exit_hub_bytes,
                "exit_hub_packets": v.exit_hub_packets,
                "last_report": v.last_report.isoformat() if v.last_report else None,
            })

        return {
            "miner_uid": miner_uid,
            "total_verified_bytes": total_bytes,
            "origin_count": len(origins),
            "origins": origin_details,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# Singleton instance
_volume_verifier: Optional[VolumeVerifier] = None


def get_volume_verifier() -> VolumeVerifier:
    """Get the singleton volume verifier instance."""
    global _volume_verifier
    if _volume_verifier is None:
        _volume_verifier = VolumeVerifier()
    return _volume_verifier
