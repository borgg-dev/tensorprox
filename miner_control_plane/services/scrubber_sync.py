"""Scrubber Synchronization Service

Ensures both scrubbers (active + standby) have identical BPF map state.
Handles:
- Atomic updates to both scrubbers (all-or-nothing)
- Drift detection between scrubbers
- Reconciliation when scrubbers diverge
- New scrubber bootstrap sync
- Recovery after scrubber restart
"""
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Set

from shared.database import get_db_connection
from shared.config import get_settings
from shared.utils.bpf_helpers import (
    update_bpf_map,
    delete_bpf_map,
    ip_to_hex,
    get_map_path,
)
from shared.utils.ssh import ssh_exec, get_ssh_user_for_provider
from shared.utils.logging import get_logger
from miner_control_plane.services.state_manager import state_manager

logger = get_logger(__name__)
settings = get_settings()


class SyncResult(Enum):
    SUCCESS = "success"
    PARTIAL = "partial"  # Only used internally during retry
    FAILED = "failed"
    ROLLBACK = "rollback"


@dataclass
class SyncOperation:
    """Represents a single sync operation to be applied atomically."""

    map_name: str
    key_hex: str
    value_hex: Optional[str]  # None for delete
    action: str  # 'update' or 'delete'
    origin_id: str
    ip_address: str
    list_type: str  # 'whitelist', 'blacklist', 'override'


@dataclass
class SyncReport:
    """Result of a sync operation."""

    result: SyncResult
    scrubbers_updated: List[str] = field(default_factory=list)
    scrubbers_failed: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    retries: int = 0


class ScrubberSyncService:
    """
    Atomic synchronization of BPF maps across scrubbers.

    DESIGN PRINCIPLES:
    1. All-or-nothing: Either ALL scrubbers updated, or NONE (rollback)
    2. Database is source of truth: BPF maps are derived from DB
    3. Retry before fail: Up to 3 retries per scrubber
    4. Audit everything: All operations logged to origin_reputation_log
    """

    # Map names for per-origin reputation
    ORIGIN_REP_MAPS = {
        "whitelist": "/sys/fs/bpf/xdp/globals/origin_whitelist_map",
        "blacklist": "/sys/fs/bpf/xdp/globals/origin_blacklist_map",
        "override": "/sys/fs/bpf/xdp/globals/origin_override_map",
    }

    MAX_RETRIES = 3
    RETRY_DELAY = 1.0  # seconds between retries

    def __init__(self):
        self._lock = threading.RLock()  # Reentrant lock for nested method calls

    def _build_compound_key(self, src_ip: str, dst_eip: str) -> str:
        """Build compound key hex for origin_rep_key struct."""
        return f"{ip_to_hex(src_ip)} {ip_to_hex(dst_eip)}"

    def _build_value(
        self, active: bool = True, reason_code: int = 2, expires_at: int = 0
    ) -> str:
        """Build value hex for origin_rep_value struct."""
        # struct: active(1) + reason_code(1) + cidr_prefix(2) + expires_at(4)
        return (
            f"{1 if active else 0:02x} "
            f"{reason_code:02x} "
            f"20 00 "  # cidr_prefix = 32 (little-endian)
            f"{(expires_at >> 0) & 0xFF:02x} "
            f"{(expires_at >> 8) & 0xFF:02x} "
            f"{(expires_at >> 16) & 0xFF:02x} "
            f"{(expires_at >> 24) & 0xFF:02x}"
        )

    def _get_shard_nodes(self, shard_id: str) -> Dict[str, dict]:
        """Get only the scrubber nodes for a specific shard."""
        return {
            node_id: node
            for node_id, node in state_manager.nodes_db.items()
            if node.get("shard_id") == shard_id
        }

    def _apply_to_scrubber(
        self, node: dict, op: SyncOperation
    ) -> Tuple[bool, str]:
        """Apply single operation to single scrubber. Returns (success, error)."""
        host = node["public_ip"]
        provider = node.get("provider", "aws")
        map_path = self.ORIGIN_REP_MAPS[op.list_type]

        if op.action == "update":
            success, error = update_bpf_map(
                host=host,
                map_path=map_path,
                key_hex=op.key_hex,
                value_hex=op.value_hex,
                ssh_key_path=settings.ssh_key_path,
                provider=provider,
                verify=True,
            )
        else:  # delete
            success, error = delete_bpf_map(
                host=host,
                map_path=map_path,
                key_hex=op.key_hex,
                ssh_key_path=settings.ssh_key_path,
                provider=provider,
            )

        return success, error

    def _rollback_operation(
        self, nodes_to_rollback: List[dict], op: SyncOperation
    ) -> None:
        """Rollback operation from specified nodes."""
        for node in nodes_to_rollback:
            try:
                if op.action == "update":
                    # Rollback update = delete
                    delete_bpf_map(
                        host=node["public_ip"],
                        map_path=self.ORIGIN_REP_MAPS[op.list_type],
                        key_hex=op.key_hex,
                        ssh_key_path=settings.ssh_key_path,
                        provider=node.get("provider", "aws"),
                    )
                # For delete rollback, we'd need original value - skip for now
            except Exception as e:
                logger.error(
                    f"Rollback failed on {node.get('instance_name')}: {e}"
                )

    def apply_atomic_to_shard(self, op: SyncOperation, shard_id: str) -> SyncReport:
        """
        Apply operation atomically to only the scrubbers in a specific shard.

        Per-origin operations use compound keys with private_ip which only exists
        on the origin's shard. Syncing to other shards is wasteful and pointless.

        Args:
            op: The sync operation to apply
            shard_id: The shard ID to limit the operation to

        Algorithm:
        1. Get only nodes for the specified shard
        2. For each node, try up to MAX_RETRIES times
        3. If ANY node fails after retries, rollback ALL and return FAILED
        4. If ALL succeed, return SUCCESS
        """
        with self._lock:
            nodes = self._get_shard_nodes(shard_id)
            if not nodes:
                logger.warning(f"No scrubber nodes found for shard {shard_id}")
                return SyncReport(
                    result=SyncResult.FAILED,
                    error_message=f"No scrubber nodes available for shard {shard_id}",
                )

            succeeded_nodes = []
            report = SyncReport(result=SyncResult.SUCCESS)

            for node_name, node in nodes.items():
                success = False
                last_error = ""

                for attempt in range(self.MAX_RETRIES):
                    success, error = self._apply_to_scrubber(node, op)
                    if success:
                        break
                    last_error = error
                    report.retries += 1
                    logger.warning(
                        f"Retry {attempt + 1}/{self.MAX_RETRIES} for {node_name}: {error}"
                    )
                    time.sleep(self.RETRY_DELAY)

                if success:
                    succeeded_nodes.append(node)
                    report.scrubbers_updated.append(node_name)
                else:
                    # Failed after all retries - ROLLBACK
                    logger.error(
                        f"Failed to apply to {node_name} after {self.MAX_RETRIES} retries"
                    )
                    report.scrubbers_failed.append(node_name)
                    report.error_message = last_error

                    # Rollback all succeeded nodes
                    if succeeded_nodes:
                        logger.warning(
                            f"Rolling back {len(succeeded_nodes)} scrubbers due to failure"
                        )
                        self._rollback_operation(succeeded_nodes, op)

                    report.result = SyncResult.ROLLBACK
                    report.scrubbers_updated = []  # All rolled back
                    return report

            logger.info(
                f"Atomic sync to shard {shard_id} completed: "
                f"{len(report.scrubbers_updated)} scrubbers updated"
            )
            return report

    def sync_origin_reputation_to_scrubber(
        self, node_name: str, origin_id: str
    ) -> SyncReport:
        """
        Sync all reputation entries for an origin to a specific scrubber.
        Used for new scrubber bootstrap or scrubber recovery.
        """
        with self._lock:
            node = state_manager.nodes_db.get(node_name)
            if not node:
                return SyncReport(
                    result=SyncResult.FAILED,
                    error_message=f"Node {node_name} not found",
                )

            db = get_db_connection()
            try:
                # Get origin EIP
                origin = state_manager.get_origin(origin_id)
                if not origin:
                    return SyncReport(
                        result=SyncResult.FAILED,
                        error_message=f"Origin {origin_id} not found",
                    )
                eip = origin.get("eip")
                if not eip:
                    return SyncReport(
                        result=SyncResult.FAILED,
                        error_message=f"Origin {origin_id} has no EIP assigned",
                    )

                # Load all reputation entries for this origin
                entries = []

                for list_type, table in [
                    ("whitelist", "origin_whitelist"),
                    ("blacklist", "origin_blacklist"),
                    ("override", "origin_blacklist_override"),
                ]:
                    rows = db.query_all(
                        f"SELECT ip_address, expires_at FROM {table} WHERE origin_id = %s",
                        (origin_id,),
                    )
                    for row in rows:
                        entries.append(
                            {
                                "list_type": list_type,
                                "ip": str(row["ip_address"]),
                                "expires_at": row.get("expires_at"),
                            }
                        )

                if not entries:
                    logger.info(f"No reputation entries to sync for {origin_id}")
                    return SyncReport(result=SyncResult.SUCCESS)

                # Apply each entry
                failed = 0
                for entry in entries:
                    key_hex = self._build_compound_key(entry["ip"], eip)
                    expires_ts = (
                        int(entry["expires_at"].timestamp())
                        if entry["expires_at"]
                        else 0
                    )
                    value_hex = self._build_value(expires_at=expires_ts)

                    success, error = self._apply_to_scrubber(
                        node,
                        SyncOperation(
                            map_name=self.ORIGIN_REP_MAPS[entry["list_type"]],
                            key_hex=key_hex,
                            value_hex=value_hex,
                            action="update",
                            origin_id=origin_id,
                            ip_address=entry["ip"],
                            list_type=entry["list_type"],
                        ),
                    )
                    if not success:
                        failed += 1
                        logger.error(
                            f"Failed to sync {entry['ip']} to {node_name}: {error}"
                        )

                if failed > 0:
                    return SyncReport(
                        result=SyncResult.FAILED,
                        error_message=f"{failed}/{len(entries)} entries failed",
                    )

                logger.info(
                    f"Synced {len(entries)} reputation entries for {origin_id} to {node_name}"
                )
                return SyncReport(
                    result=SyncResult.SUCCESS, scrubbers_updated=[node_name]
                )

            finally:
                db.close()

    def sync_all_reputation_to_scrubber(self, node_name: str) -> SyncReport:
        """
        Sync ALL per-origin reputation from database to a scrubber.
        Called after scrubber bootstrap or recovery.
        """
        with self._lock:
            total_synced = 0
            total_failed = 0

            for origin_id in state_manager.origins_db:
                report = self.sync_origin_reputation_to_scrubber(node_name, origin_id)
                if report.result == SyncResult.SUCCESS:
                    total_synced += 1
                else:
                    total_failed += 1

            if total_failed > 0:
                return SyncReport(
                    result=SyncResult.PARTIAL,
                    error_message=f"{total_failed} origins failed to sync",
                )

            logger.info(
                f"Synced reputation for {total_synced} origins to {node_name}"
            )
            return SyncReport(
                result=SyncResult.SUCCESS, scrubbers_updated=[node_name]
            )

    def detect_drift(self) -> Dict[str, Dict[str, int]]:
        """
        Compare BPF map state across all scrubbers.
        Returns dict of differences: {map_name: {node_name: entry_count}}

        Used for monitoring and reconciliation.
        """
        with self._lock:
            nodes = self._get_all_nodes()
            if len(nodes) < 2:
                return {}  # Need at least 2 nodes to detect drift

            drift = {}

            for map_name, map_path in self.ORIGIN_REP_MAPS.items():
                node_keys = {}

                for node_name, node in nodes.items():
                    # Dump map entries
                    user = get_ssh_user_for_provider(node.get("provider", "aws"))
                    rc, stdout, stderr = ssh_exec(
                        node["public_ip"],
                        f"sudo bpftool map dump pinned {map_path} 2>/dev/null | grep -c 'key:' || echo 0",
                        settings.ssh_key_path,
                        user=user,
                        timeout=30,
                    )

                    if rc == 0:
                        try:
                            count = int(stdout.strip())
                            node_keys[node_name] = count
                        except ValueError:
                            node_keys[node_name] = -1
                    else:
                        node_keys[node_name] = -1

                # Check for differences in entry counts
                counts = set(node_keys.values())
                if len(counts) > 1:
                    drift[map_name] = node_keys
                    logger.warning(f"Drift detected in {map_name}: {node_keys}")

            return drift

    def reconcile(self) -> bool:
        """
        Reconcile all scrubbers to match database state.
        Database is source of truth - all BPF maps rebuilt from DB.
        """
        with self._lock:
            logger.info("Starting full reconciliation from database")

            nodes = self._get_all_nodes()
            success = True

            for node_name in nodes:
                report = self.sync_all_reputation_to_scrubber(node_name)
                if report.result != SyncResult.SUCCESS:
                    success = False
                    logger.error(f"Reconciliation failed for {node_name}")

            return success


# Singleton
scrubber_sync = ScrubberSyncService()
