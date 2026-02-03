"""
Scrubber management service for miners.

Handles deployment, configuration, and lifecycle management
of scrubber nodes for the TensorProx subnet.
"""

import json
import os
import time
import socket
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

import requests
from loguru import logger


def get_miner_public_ip() -> Optional[str]:
    """Get the miner's public IP address for whitelist."""
    services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    for service in services:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                ip = response.text.strip()
                # Validate it's IPv4
                socket.inet_aton(ip)
                return ip
        except Exception:
            continue
    return None

from shared.node import Node
from shared.models import InstanceCreateResult, ScrubberStats
from shared.config import get_shared_settings, SharedSettings
from shared.utils.ssh import ssh_check_service_running
from shared.utils.bpf_helpers import bpf_read_xdp_stats
from shared.providers import get_provider


@dataclass
class ScrubberNode:
    """Represents a deployed scrubber node."""

    node_id: str
    instance_id: str
    public_ip: str
    private_ip: Optional[str] = None
    region: str = ""
    instance_type: str = ""
    status: str = "pending"
    health_status: str = "unknown"
    role: str = "unknown"  # "active", "standby", or "unknown"
    last_health_check: Optional[datetime] = None
    deployed_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "node_id": self.node_id,
            "instance_id": self.instance_id,
            "public_ip": self.public_ip,
            "private_ip": self.private_ip,
            "region": self.region,
            "instance_type": self.instance_type,
            "status": self.status,
            "health_status": self.health_status,
            "role": self.role,
            "last_health_check": (
                self.last_health_check.isoformat()
                if self.last_health_check else None
            ),
            "deployed_at": self.deployed_at.isoformat(),
        }


# Default state directory
DEFAULT_STATE_DIR = Path.home() / ".tensorprox" / "scrubbers"


def get_state_file_for_miner(miner_id: str) -> Path:
    """Get the state file path for a specific miner instance."""
    # Sanitize miner_id for use as filename
    safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in miner_id)
    return DEFAULT_STATE_DIR / f"{safe_id}.json"


class ScrubberManager:
    """
    Manages scrubber node lifecycle for a miner.

    Handles deployment, health monitoring, and teardown of
    scrubber infrastructure used for DDoS protection.

    Features:
    - Instance-specific state persistence (per miner_id)
    - Discovery of existing cloud instances for this miner only
    - Health verification before reuse
    - Support for multiple miner instances on same machine
    """

    def __init__(
        self,
        settings: Optional[SharedSettings] = None,
        max_scrubbers: int = 8,
        miner_id: Optional[str] = None,
        state_file: Optional[Path] = None
    ):
        """
        Initialize the scrubber manager.

        Args:
            settings: Optional settings override.
            max_scrubbers: Maximum number of scrubbers to manage.
            miner_id: Unique identifier for this miner instance (e.g., wallet hotkey).
                      Required for multi-miner support on same machine.
            state_file: Path to state file for persistence (auto-generated if miner_id provided).
        """
        self.settings = settings or get_shared_settings()
        self.max_scrubbers = max_scrubbers
        self.scrubbers: Dict[str, ScrubberNode] = {}
        self._node_counter = 0

        # Miner identity for instance-specific management
        self.miner_id = miner_id or self._generate_default_miner_id()

        # Track active/standby pair explicitly
        self.active_node_id: Optional[str] = None
        self.standby_node_id: Optional[str] = None

        # State file is specific to this miner instance
        if state_file:
            self.state_file = state_file
        else:
            self.state_file = get_state_file_for_miner(self.miner_id)

        # Ensure state directory exists
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        # Create initial empty state file if it doesn't exist
        if not self.state_file.exists():
            self._create_initial_state_file()

        logger.info(f"ScrubberManager initialized for miner_id={self.miner_id}")

    def _generate_default_miner_id(self) -> str:
        """Generate a default miner_id from settings."""
        # Use wallet name + hotkey as unique identifier
        wallet_name = getattr(self.settings, 'wallet_name', 'default')
        wallet_hotkey = getattr(self.settings, 'wallet_hotkey', 'default')
        return f"{wallet_name}_{wallet_hotkey}"

    def _create_initial_state_file(self) -> None:
        """Create an initial empty state file for this miner instance."""
        try:
            initial_state = {
                "miner_id": self.miner_id,
                "active_node_id": None,
                "standby_node_id": None,
                "scrubbers": {},
                "node_counter": 0,
                "saved_at": datetime.utcnow().isoformat(),
            }
            with open(self.state_file, "w") as f:
                json.dump(initial_state, f, indent=2)
            logger.debug(f"Created initial state file for miner_id={self.miner_id}")
        except Exception as e:
            logger.warning(f"Failed to create initial state file: {e}")

    @property
    def ssh_user(self) -> str:
        """Get the SSH username based on the configured cloud provider."""
        provider_name = getattr(self.settings, 'scrubber_provider', 'aws')
        provider = get_provider(provider_name)
        return provider.default_ssh_user

    @property
    def active_scrubber(self) -> Optional[ScrubberNode]:
        """Get the active scrubber."""
        if self.active_node_id and self.active_node_id in self.scrubbers:
            return self.scrubbers[self.active_node_id]
        return None

    @property
    def standby_scrubber(self) -> Optional[ScrubberNode]:
        """Get the standby scrubber."""
        if self.standby_node_id and self.standby_node_id in self.scrubbers:
            return self.scrubbers[self.standby_node_id]
        return None

    @property
    def healthy_scrubbers(self) -> List[ScrubberNode]:
        """Get list of healthy scrubbers."""
        return [
            s for s in self.scrubbers.values()
            if s.status == "running" and s.health_status == "healthy"
        ]

    @property
    def scrubber_count(self) -> int:
        """Get count of deployed scrubbers."""
        return len(self.scrubbers)

    def _get_next_node_number(self) -> int:
        """
        Calculate the next node number dynamically based on existing scrubbers.

        Finds the highest existing scrubber number and returns max + 1.
        If no scrubbers exist, returns 1.

        Returns:
            Next available node number.
        """
        if not self.scrubbers:
            return 1

        max_num = 0
        for node_id in self.scrubbers.keys():
            # Parse number from node_id like "scrubber-001"
            if node_id.startswith("scrubber-"):
                try:
                    num = int(node_id.split("-")[1])
                    max_num = max(max_num, num)
                except (IndexError, ValueError):
                    continue

        return max_num + 1

    def set_active(self, node_id: str) -> bool:
        """Set a scrubber as active."""
        if node_id not in self.scrubbers:
            return False
        self.active_node_id = node_id
        self.scrubbers[node_id].role = "active"
        logger.info(f"Set {node_id} as active scrubber")
        return True

    def set_standby(self, node_id: str) -> bool:
        """Set a scrubber as standby."""
        if node_id not in self.scrubbers:
            return False
        self.standby_node_id = node_id
        self.scrubbers[node_id].role = "standby"
        logger.info(f"Set {node_id} as standby scrubber")
        return True

    def clear_role(self, node_id: str) -> None:
        """Clear a scrubber's role."""
        if node_id in self.scrubbers:
            self.scrubbers[node_id].role = "unknown"
        if self.active_node_id == node_id:
            self.active_node_id = None
        if self.standby_node_id == node_id:
            self.standby_node_id = None

    # ========================================================================
    # State Persistence
    # ========================================================================

    def save_state(self) -> bool:
        """
        Save current scrubber state to disk.

        State is saved to a miner-specific file to support multiple
        miner instances on the same machine. Includes active/standby
        role assignments.

        Returns:
            True if successful.
        """
        try:
            state = {
                "miner_id": self.miner_id,
                "active_node_id": self.active_node_id,
                "standby_node_id": self.standby_node_id,
                "scrubbers": {
                    node_id: scrubber.to_dict()
                    for node_id, scrubber in self.scrubbers.items()
                },
                "node_counter": self._node_counter,
                "saved_at": datetime.utcnow().isoformat(),
            }

            with open(self.state_file, "w") as f:
                json.dump(state, f, indent=2)

            logger.debug(
                f"Saved scrubber state for miner_id={self.miner_id}: "
                f"active={self.active_node_id}, standby={self.standby_node_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to save scrubber state: {e}")
            return False

    def load_state(self) -> bool:
        """
        Load scrubber state from disk for this miner instance.

        Restores scrubber records and active/standby role assignments.

        Returns:
            True if state was loaded successfully.
        """
        if not self.state_file.exists():
            logger.debug(f"No scrubber state file found for miner_id={self.miner_id}")
            return False

        try:
            with open(self.state_file, "r") as f:
                state = json.load(f)

            # Verify miner_id matches (safety check)
            saved_miner_id = state.get("miner_id")
            if saved_miner_id and saved_miner_id != self.miner_id:
                logger.warning(
                    f"State file miner_id mismatch: saved={saved_miner_id}, "
                    f"current={self.miner_id}. Ignoring state file."
                )
                return False

            # Restore node counter
            self._node_counter = state.get("node_counter", 0)

            # Restore scrubber records
            for node_id, data in state.get("scrubbers", {}).items():
                deployed_at = data.get("deployed_at")
                if deployed_at:
                    deployed_at = datetime.fromisoformat(deployed_at)
                else:
                    deployed_at = datetime.utcnow()

                last_health = data.get("last_health_check")
                if last_health:
                    last_health = datetime.fromisoformat(last_health)

                scrubber = ScrubberNode(
                    node_id=data["node_id"],
                    instance_id=data["instance_id"],
                    public_ip=data["public_ip"],
                    private_ip=data.get("private_ip"),
                    region=data.get("region", ""),
                    instance_type=data.get("instance_type", ""),
                    status=data.get("status", "unknown"),
                    health_status=data.get("health_status", "unknown"),
                    role=data.get("role", "unknown"),
                    last_health_check=last_health,
                    deployed_at=deployed_at,
                )
                self.scrubbers[node_id] = scrubber

            # Restore active/standby assignments
            self.active_node_id = state.get("active_node_id")
            self.standby_node_id = state.get("standby_node_id")

            logger.info(
                f"Loaded {len(self.scrubbers)} scrubbers from state for miner_id={self.miner_id}: "
                f"active={self.active_node_id}, standby={self.standby_node_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to load scrubber state: {e}")
            return False

    def clear_state(self) -> bool:
        """
        Clear the saved state file and in-memory state.

        Returns:
            True if successful.
        """
        try:
            if self.state_file.exists():
                self.state_file.unlink()
                logger.debug(f"Cleared scrubber state file")

            # Clear in-memory state
            self.scrubbers.clear()
            self.active_node_id = None
            self.standby_node_id = None
            logger.info("Cleared scrubber state")

            return True
        except Exception as e:
            logger.error(f"Failed to clear state file: {e}")
            return False

    # ========================================================================
    # Discovery and Recovery
    # ========================================================================

    def discover_existing_scrubbers(
        self,
        region: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Discover existing scrubber instances in the cloud for THIS miner instance.

        Looks for running instances with:
        - node_type=scrubber
        - miner_id=<this miner's id>

        Args:
            region: Cloud region to search in.

        Returns:
            List of discovered instance details belonging to this miner.
        """
        region = region or self.settings.scrubber_region
        provider_name = self.settings.scrubber_provider

        logger.info(
            f"Discovering existing scrubbers for miner_id={self.miner_id} "
            f"in {region} ({provider_name})..."
        )

        try:
            provider = get_provider(provider_name)

            # Look for instances tagged with THIS miner's id
            # AWS requires 'tag:' prefix for tag-based filtering
            filters = {
                "tag:node_type": "scrubber",
                "tag:miner_id": self.miner_id,
                "instance-state-name": "running",
            }

            # Use describe_instances_with_filters for AWS tag-based filtering
            if hasattr(provider, 'describe_instances_with_filters'):
                instances = provider.describe_instances_with_filters(
                    region=region,
                    filters=filters
                )
            else:
                # Fallback for providers without filter support
                instances = []

            logger.info(
                f"Discovered {len(instances)} scrubber(s) for miner_id={self.miner_id}"
            )
            return instances

        except Exception as e:
            logger.error(f"Failed to discover scrubbers: {e}")
            return []

    def discover_all_scrubbers_in_region(
        self,
        region: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Discover ALL scrubber instances in the region (without miner_id filter).

        This is a fallback mechanism to find orphaned scrubbers that may have
        missing or incorrect miner_id tags. Use this to detect:
        - Orphans from failed deployments
        - Instances with corrupted tags
        - Scrubbers that may belong to a different miner

        Args:
            region: Cloud region to search in.

        Returns:
            List of ALL scrubber instances in the region.
        """
        region = region or self.settings.scrubber_region
        provider_name = self.settings.scrubber_provider

        logger.info(
            f"Discovering ALL scrubbers (no miner_id filter) in {region} ({provider_name})..."
        )

        try:
            provider = get_provider(provider_name)

            # Query ALL scrubbers, not filtered by miner_id
            filters = {
                "tag:node_type": "scrubber",
                "instance-state-name": "running",
            }

            if hasattr(provider, 'describe_instances_with_filters'):
                instances = provider.describe_instances_with_filters(
                    region=region,
                    filters=filters
                )
            else:
                instances = []

            logger.info(
                f"Discovered {len(instances)} total scrubber(s) in region {region}"
            )
            return instances

        except Exception as e:
            logger.error(f"Failed to discover all scrubbers: {e}")
            return []

    def find_orphan_scrubbers(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find orphan scrubbers in AWS that are not tracked by ANY miner.

        Compares ALL scrubbers in region against those tagged with this miner's ID.
        Returns instances that exist but don't have proper miner_id tags.

        This helps identify:
        - Instances from failed deployments
        - Instances with corrupted/missing tags
        - Leaked resources that should be cleaned up

        Args:
            region: Cloud region to search in.

        Returns:
            List of orphan instances (have node_type=scrubber but no/wrong miner_id).
        """
        region = region or self.settings.scrubber_region

        # Get all scrubbers in region
        all_scrubbers = self.discover_all_scrubbers_in_region(region=region)

        # Get scrubbers tagged for this miner
        my_scrubbers = self.discover_existing_scrubbers(region=region)
        my_instance_ids = {s.get("instance_id") for s in my_scrubbers if s.get("instance_id")}

        # Also check what we have in local state
        local_instance_ids = {s.instance_id for s in self.scrubbers.values()}

        orphans = []
        for scrubber in all_scrubbers:
            iid = scrubber.get("instance_id")
            if iid and iid not in my_instance_ids and iid not in local_instance_ids:
                # This is an orphan - not tagged for this miner AND not in our local state
                tags = scrubber.get("tags", {})
                miner_tag = tags.get("miner_id", "NONE")
                logger.warning(
                    f"Found potential orphan: {iid} (miner_id tag={miner_tag}, "
                    f"ip={scrubber.get('public_ip')})"
                )
                orphans.append(scrubber)

        if orphans:
            logger.warning(f"Found {len(orphans)} potential orphan scrubber(s) in {region}")
        else:
            logger.info(f"No orphan scrubbers found in {region}")

        return orphans

    def recover_scrubber(
        self,
        instance_data: Dict[str, Any]
    ) -> Optional[ScrubberNode]:
        """
        Recover a scrubber from discovered cloud instance.

        Verifies the scrubber is healthy and properly configured
        before adding it to the managed set.

        Args:
            instance_data: Instance details from discover_existing_scrubbers().

        Returns:
            ScrubberNode if recovery successful, None otherwise.
        """
        instance_id = instance_data.get("instance_id")
        public_ip = instance_data.get("public_ip")

        if not instance_id or not public_ip:
            logger.warning(f"Invalid instance data for recovery: {instance_data}")
            return None

        # Check if already managed
        for scrubber in self.scrubbers.values():
            if scrubber.instance_id == instance_id:
                logger.debug(f"Instance {instance_id} already managed")
                return scrubber

        logger.info(f"Attempting to recover scrubber: {instance_id} ({public_ip})")

        # Verify the scrubber is responsive and properly configured
        if not self._verify_scrubber(public_ip):
            logger.warning(
                f"Scrubber {instance_id} failed verification - may need redeployment"
            )
            return None

        # Generate node_id from tags or create new one
        tags = instance_data.get("tags", {})
        node_id = tags.get("Name", f"recovered-{instance_id[:8]}")

        # Ensure unique node_id using dynamic calculation
        if node_id in self.scrubbers:
            next_num = self._get_next_node_number()
            node_id = f"scrubber-{next_num:03d}"

        # Create scrubber record
        scrubber = ScrubberNode(
            node_id=node_id,
            instance_id=instance_id,
            public_ip=public_ip,
            private_ip=instance_data.get("private_ip"),
            region=instance_data.get("region", self.settings.scrubber_region),
            instance_type=instance_data.get("instance_type", ""),
            status="running",
            health_status="healthy",
            last_health_check=datetime.utcnow(),
        )

        self.scrubbers[node_id] = scrubber
        logger.info(f"Recovered scrubber: {node_id} ({public_ip})")

        # Save state after recovery
        self.save_state()

        return scrubber

    def recover_scrubber_pair(
        self,
        region: Optional[str] = None,
        check_orphans: bool = True
    ) -> tuple[Optional[ScrubberNode], Optional[ScrubberNode]]:
        """
        Recover the active/standby scrubber pair for this miner instance.

        Handles all scenarios:
        1. Fresh start (no state) - Returns (None, None)
        2. Both scrubbers healthy - Returns (active, standby)
        3. Only active healthy - Returns (active, None)
        4. Only standby healthy - Promotes standby to active, returns (promoted, None)
        5. Neither healthy - Cleans up state, returns (None, None)

        Args:
            region: Cloud region to search in.
            check_orphans: If True, also check for orphan scrubbers and log warnings.

        Returns:
            Tuple of (active_scrubber, standby_scrubber). Either may be None.
        """
        active = None
        standby = None

        # Step 0: Load state file first (to get any persisted data)
        self.load_state()

        # Step 1: CRITICAL - Sync with AWS to ensure state matches reality
        # This prevents orphans and ensures we know about all our scrubbers
        logger.info("Syncing state file with AWS before recovery...")
        sync_result = self.sync_with_cloud(region=region)
        logger.info(
            f"Cloud sync complete: {sync_result['final_count']} scrubber(s) in state, "
            f"added={len(sync_result['added_to_state'])}, "
            f"removed={len(sync_result['removed_from_state'])}"
        )

        # Step 1.5: Clean up failed instances from previous deployments
        # These are instances we tracked but failed during provisioning
        failed_nodes = [
            node_id for node_id, scrubber in self.scrubbers.items()
            if scrubber.status == "failed" or scrubber.status == "provisioning"
        ]
        if failed_nodes:
            logger.info(f"Found {len(failed_nodes)} failed/stuck instance(s) from previous deployments")
            for node_id in failed_nodes:
                scrubber = self.scrubbers[node_id]
                logger.info(f"Cleaning up failed instance: {node_id} ({scrubber.instance_id})")
                try:
                    node = Node(node_type="scrubber", region=region)
                    node.destroy(scrubber.instance_id)
                    logger.info(f"Terminated failed instance {scrubber.instance_id}")
                except Exception as e:
                    logger.warning(f"Could not terminate {scrubber.instance_id} (may already be gone): {e}")
                # Remove from tracking regardless of whether termination succeeded
                del self.scrubbers[node_id]
            self.save_state()
            logger.info(f"Cleaned up {len(failed_nodes)} failed instance(s)")

        # Step 1.6: Check for and clean up orphans (scrubbers without proper tags)
        if check_orphans:
            try:
                orphans = self.find_orphan_scrubbers(region=region)
                if orphans:
                    logger.warning(
                        f"⚠️ Found {len(orphans)} orphan scrubber(s) in {region or self.settings.scrubber_region}! "
                        f"Attempting automatic cleanup..."
                    )
                    # Auto-cleanup orphans (they have no valid miner_id, so safe to terminate)
                    cleaned = self.cleanup_orphan_scrubbers(region=region, dry_run=False)
                    if cleaned:
                        logger.info(f"Successfully cleaned up {len(cleaned)} orphan scrubber(s)")
            except Exception as e:
                logger.warning(f"Failed to check/cleanup orphans: {e}")

        if not self.scrubbers:
            logger.info("No scrubbers found after cloud sync, will need fresh deployment")
            return (None, None)

        # Step 2: Get active/standby from sync results (sync_with_cloud already assigned roles)
        if self.active_node_id and self.active_node_id in self.scrubbers:
            active = self.scrubbers[self.active_node_id]
            if active.health_status != "healthy":
                logger.warning(f"Active scrubber {self.active_node_id} is not healthy")
                active = None

        if self.standby_node_id and self.standby_node_id in self.scrubbers:
            standby = self.scrubbers[self.standby_node_id]
            if standby.health_status != "healthy":
                logger.warning(f"Standby scrubber {self.standby_node_id} is not healthy")
                standby = None

        # Step 3: Handle promotion if active failed but standby is healthy
        if active is None and standby is not None:
            logger.info(
                f"Active scrubber unavailable, promoting standby {standby.node_id} to active"
            )
            self.set_active(standby.node_id)
            active = standby
            standby = None
            self.standby_node_id = None
            self.save_state()

        # Log final status
        active_str = f"{active.node_id} ({active.public_ip})" if active else "None"
        standby_str = f"{standby.node_id} ({standby.public_ip})" if standby else "None"
        logger.info(
            f"Recovery complete: active={active_str}, standby={standby_str}"
        )

        return (active, standby)

    def cleanup_orphan_scrubbers(self, region: Optional[str] = None, dry_run: bool = True) -> List[str]:
        """
        Find and optionally terminate orphan scrubbers in the region.

        Orphans are scrubbers that:
        - Have node_type=scrubber tag
        - But don't have a valid miner_id tag matching any known miner
        - And are not tracked in any miner's local state

        WARNING: This is destructive! Use dry_run=True first to see what would be terminated.

        Args:
            region: Cloud region to search in.
            dry_run: If True, only log what would be terminated. If False, actually terminate.

        Returns:
            List of instance IDs that were (or would be) terminated.
        """
        region = region or self.settings.scrubber_region
        orphans = self.find_orphan_scrubbers(region=region)

        terminated = []
        for orphan in orphans:
            iid = orphan.get("instance_id")
            if not iid:
                continue

            if dry_run:
                logger.info(f"[DRY RUN] Would terminate orphan: {iid} ({orphan.get('public_ip')})")
            else:
                try:
                    node = Node(
                        node_type="scrubber",
                        region=region,
                    )
                    node.destroy(iid)
                    logger.info(f"Terminated orphan scrubber: {iid}")
                    terminated.append(iid)
                except Exception as e:
                    logger.error(f"Failed to terminate orphan {iid}: {e}")

        if dry_run and orphans:
            logger.info(f"[DRY RUN] Would terminate {len(orphans)} orphan(s). Set dry_run=False to actually terminate.")

        return terminated

    def sync_with_cloud(self, region: Optional[str] = None) -> Dict[str, Any]:
        """
        Synchronize state file with actual AWS state.

        This is the AUTHORITATIVE sync mechanism that:
        1. Queries AWS for ALL scrubbers tagged with this miner's ID
        2. Updates state file to match AWS reality
        3. Terminates any unhealthy/orphaned instances
        4. Ensures exactly the expected number of scrubbers exist

        RELIABILITY: Uses try/finally to ensure state is ALWAYS saved, even on crash.
        This prevents state drift where local state doesn't match AWS reality.

        Args:
            region: Cloud region to sync (defaults to scrubber_region)

        Returns:
            Dict with sync results: added, removed, terminated, final_count
        """
        region = region or self.settings.scrubber_region

        logger.info(f"=== Starting cloud sync for miner_id={self.miner_id} in {region} ===")

        results = {
            "added_to_state": [],
            "removed_from_state": [],
            "terminated": [],
            "verified_healthy": [],
            "final_count": 0,
            "error": None,
        }

        state_modified = False

        try:
            # Step 1: Discover ALL scrubbers on AWS for this miner
            discovered = self.discover_existing_scrubbers(region=region)
            discovered_ids = {d.get("instance_id") for d in discovered if d.get("instance_id")}

            logger.info(f"AWS discovery found {len(discovered)} scrubber(s) for this miner")

            # Step 2: Build mapping of discovered instances
            aws_instances = {}
            for inst_data in discovered:
                iid = inst_data.get("instance_id")
                if iid:
                    aws_instances[iid] = inst_data

            # Step 3: Check state file scrubbers against AWS reality
            stale_nodes = []
            for node_id, scrubber in list(self.scrubbers.items()):
                if scrubber.instance_id not in discovered_ids:
                    # Instance not on AWS - remove from state
                    logger.warning(
                        f"Scrubber {node_id} (instance={scrubber.instance_id}) "
                        f"not found on AWS - removing from state"
                    )
                    stale_nodes.append(node_id)
                    results["removed_from_state"].append(node_id)

            # Remove stale nodes from state
            for node_id in stale_nodes:
                if node_id == self.active_node_id:
                    self.active_node_id = None
                if node_id == self.standby_node_id:
                    self.standby_node_id = None
                del self.scrubbers[node_id]
                state_modified = True

            # CRITICAL: Save state after removing stale nodes to prevent orphans
            if stale_nodes:
                self.save_state()
                logger.info(f"Persisted state after removing {len(stale_nodes)} stale node(s)")

            # Step 4: Verify existing scrubbers and add newly discovered ones
            state_instance_ids = {s.instance_id for s in self.scrubbers.values()}

            for inst_data in discovered:
                iid = inst_data.get("instance_id")
                public_ip = inst_data.get("public_ip")

                if not iid or not public_ip:
                    continue

                # Check if already in state
                if iid in state_instance_ids:
                    # Verify it's still healthy
                    for node_id, scrubber in list(self.scrubbers.items()):
                        if scrubber.instance_id == iid:
                            try:
                                if self._verify_scrubber(public_ip):
                                    scrubber.health_status = "healthy"
                                    scrubber.status = "running"
                                    results["verified_healthy"].append(node_id)
                                    state_modified = True
                                    logger.info(f"✓ Verified {node_id} ({public_ip}) is healthy")
                                else:
                                    logger.warning(f"✗ {node_id} failed verification - will terminate")
                                    # persist=True since this is a critical state change
                                    self._handle_failed_scrubber(node_id, persist=True)
                                    results["terminated"].append(iid)
                                    state_modified = True
                            except Exception as e:
                                logger.warning(f"Error verifying {node_id}: {e}")
                            break
                else:
                    # New instance discovered on AWS - try to recover it
                    logger.info(f"Found untracked instance {iid} ({public_ip}) - attempting recovery")
                    recovered = self.recover_scrubber(inst_data)
                    if recovered:
                        results["added_to_state"].append(recovered.node_id)
                        state_modified = True
                        logger.info(f"✓ Recovered {recovered.node_id} from AWS")
                    else:
                        # Failed to recover - terminate orphan
                        logger.warning(f"Failed to recover {iid} - terminating orphan")
                        try:
                            node = Node(
                                node_type="scrubber",
                                region=region,
                            )
                            node.destroy(iid)
                            results["terminated"].append(iid)
                            logger.info(f"Terminated orphan instance: {iid}")
                        except Exception as e:
                            logger.error(f"Failed to terminate orphan {iid}: {e}")

            # Step 5: Assign active/standby roles if not set
            healthy_scrubbers = [
                s for s in self.scrubbers.values()
                if s.health_status == "healthy"
            ]

            if healthy_scrubbers and not self.active_node_id:
                self.set_active(healthy_scrubbers[0].node_id)
                state_modified = True
                logger.info(f"Assigned {healthy_scrubbers[0].node_id} as active")

            # Clear standby if it matches active (can happen after failover + removal of old active)
            if self.standby_node_id and self.standby_node_id == self.active_node_id:
                logger.warning(
                    f"Standby {self.standby_node_id} same as active - clearing standby"
                )
                self.standby_node_id = None
                state_modified = True

            # Clear standby if it's no longer a valid/healthy scrubber
            if self.standby_node_id and self.standby_node_id not in self.scrubbers:
                logger.warning(
                    f"Standby {self.standby_node_id} no longer exists - clearing standby"
                )
                self.standby_node_id = None
                state_modified = True

            if len(healthy_scrubbers) > 1 and not self.standby_node_id:
                for s in healthy_scrubbers:
                    if s.node_id != self.active_node_id:
                        self.set_standby(s.node_id)
                        state_modified = True
                        logger.info(f"Assigned {s.node_id} as standby")
                        break

        except Exception as e:
            logger.error(f"Error during cloud sync: {e}")
            results["error"] = str(e)
            # Don't re-raise - we want to save state in finally block

        finally:
            # CRITICAL: Always save state, even on error, to persist any changes made
            if state_modified:
                try:
                    self.save_state()
                    logger.debug("Final state save completed in sync_with_cloud")
                except Exception as save_error:
                    logger.error(f"CRITICAL: Failed to save state in sync_with_cloud: {save_error}")

        results["final_count"] = len(self.scrubbers)

        logger.info(
            f"=== Cloud sync complete: "
            f"added={len(results['added_to_state'])}, "
            f"removed={len(results['removed_from_state'])}, "
            f"terminated={len(results['terminated'])}, "
            f"healthy={len(results['verified_healthy'])}, "
            f"final_count={results['final_count']} ==="
        )

        return results

    def _handle_failed_scrubber(self, node_id: str, persist: bool = True) -> None:
        """
        Handle a scrubber that failed verification.

        Args:
            node_id: The node to handle.
            persist: If True, save state after deletion. Set to False if caller
                     will save state later (e.g., in sync_with_cloud's finally block).
        """
        if node_id not in self.scrubbers:
            return

        scrubber = self.scrubbers[node_id]
        instance_id = scrubber.instance_id
        scrubber.health_status = "unhealthy"
        scrubber.status = "failed"

        # Clear role assignments
        self.clear_role(node_id)

        # Try to terminate the cloud instance
        logger.info(f"Attempting to terminate failed scrubber: {node_id}")
        try:
            node = Node(
                node_type="scrubber",
                region=scrubber.region or self.settings.scrubber_region,
            )
            node.destroy(instance_id)
            logger.info(f"Terminated failed instance: {instance_id}")
        except Exception as e:
            logger.warning(f"Failed to terminate instance {instance_id}: {e}")

        # Remove from tracking
        del self.scrubbers[node_id]

        # CRITICAL: Persist state immediately to prevent orphans on crash
        if persist:
            self.save_state()
            logger.debug(f"Persisted state after removing failed scrubber {node_id}")

    def deploy_scrubber(
        self,
        region: Optional[str] = None,
        instance_type: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None
    ) -> Optional[ScrubberNode]:
        """
        Deploy a new scrubber node.

        Args:
            region: Cloud region (defaults from settings).
            instance_type: Instance type (defaults from settings).
            tags: Additional tags.

        Returns:
            ScrubberNode if successful, None otherwise.

        Note:
            This method tracks instances immediately after creation to prevent orphans.
            If provisioning fails, the instance is marked as "failed" and cleanup is
            attempted. If cleanup fails, the instance remains tracked so recovery
            can handle it on next startup.
        """
        if self.scrubber_count >= self.max_scrubbers:
            logger.warning(
                f"Max scrubbers reached ({self.max_scrubbers}), "
                "cannot deploy more"
            )
            return None

        # Calculate next node number dynamically based on existing scrubbers
        next_num = self._get_next_node_number()
        node_id = f"scrubber-{next_num:03d}"
        effective_region = region or self.settings.scrubber_region
        effective_instance_type = instance_type or self.settings.scrubber_instance_type

        logger.info(f"Deploying scrubber: {node_id} (based on {self.scrubber_count} existing)")

        node = None
        scrubber = None
        instance_id = None

        def _cleanup_failed_instance(reason: str) -> None:
            """Helper to clean up failed instance and update state."""
            nonlocal scrubber
            if scrubber:
                scrubber.status = "failed"
                scrubber.health_status = "unhealthy"
                self.save_state()
                logger.warning(f"Marked {node_id} as failed: {reason}")

            if instance_id and node:
                try:
                    logger.info(f"Attempting to terminate failed instance {instance_id}...")
                    node.destroy(instance_id)
                    # Remove from tracking after successful termination
                    if node_id in self.scrubbers:
                        del self.scrubbers[node_id]
                        self.save_state()
                    logger.info(f"Successfully terminated {instance_id}")
                except Exception as destroy_error:
                    # CRITICAL: If destroy fails, keep the instance tracked as "failed"
                    # so recovery can clean it up later
                    logger.error(
                        f"FAILED to terminate instance {instance_id}: {destroy_error}. "
                        f"Instance remains tracked as 'failed' for recovery."
                    )

        try:
            # Create node deployer
            node = Node(
                node_type="scrubber",
                region=region,
                instance_type=instance_type,
            )

            # Deploy instance (skip asset embedding for post-provision)
            if tags is None:
                tags = {}
            tags["Name"] = node_id
            tags["node_type"] = "scrubber"
            tags["miner_id"] = self.miner_id  # Instance-specific tag for discovery

            result = node.deploy(tags=tags, skip_asset_embedding=True)
            instance_id = result.instance_id

            # CRITICAL: Track instance immediately after creation to prevent orphans
            # Even if subsequent steps fail, we'll know about this instance
            scrubber = ScrubberNode(
                node_id=node_id,
                instance_id=instance_id,
                public_ip="",  # Not yet assigned
                private_ip=result.private_ip or "",
                region=effective_region,
                instance_type=effective_instance_type,
                status="provisioning",  # Mark as provisioning until complete
                health_status="unknown",
                last_health_check=datetime.utcnow(),
            )
            self.scrubbers[node_id] = scrubber
            self.save_state()  # CRITICAL: Save immediately to prevent orphans
            logger.info(f"Instance {instance_id} created and tracked (status=provisioning)")

            # Wait for instance to be running and get public IP
            logger.info(f"Waiting for instance {instance_id} to start...")

            try:
                instance_info = node.provider.wait_for_instance_running(
                    instance_id,
                    region=node.region,
                    max_attempts=60,
                    interval=5
                )
                public_ip = instance_info.get("public_ip")
                if not public_ip:
                    _cleanup_failed_instance("No public IP assigned")
                    return None
            except Exception as e:
                _cleanup_failed_instance(f"Failed to start: {e}")
                return None

            logger.info(f"Instance {instance_id} running with IP {public_ip}")
            scrubber.public_ip = public_ip
            self.save_state()  # Save updated IP

            node.wait_for_ssh(
                public_ip,
                max_attempts=60,
                interval=5
            )

            # Create and upload asset bundle
            bundle_path = node.create_asset_bundle()
            if bundle_path:
                success, error = node.post_provision(
                    instance_ip=public_ip,
                    bundle_path=bundle_path
                )
                if not success:
                    _cleanup_failed_instance(f"Post-provision failed: {error}")
                    return None

            # Execute bootstrap with miner IP for whitelist
            miner_ip = get_miner_public_ip()
            if miner_ip:
                logger.info("Miner public IP detected for whitelist")
            else:
                logger.warning("Could not detect miner public IP - SSH may be blocked after XDP loads")

            success, output = node.execute_bootstrap(
                instance_ip=public_ip,
                env_vars={
                    "INSTANCE_ID": instance_id,
                    "NODE_ID": node_id,
                    "MINER_IP": miner_ip or "",
                    "EMN_IP": miner_ip or "",  # ECP agent needs this to report metrics
                    "EMN_PORT": str(self.settings.emn_port),
                }
            )

            if not success:
                _cleanup_failed_instance(f"Bootstrap failed: {output}")
                return None

            # Bootstrap output may contain IPs/credentials - only log success/failure
            logger.info(f"Bootstrap completed successfully (output: {len(output) if output else 0} chars)")

            # XDP is now attached during bootstrap (as root, no sudo needed)
            # This avoids the sudo permission issues when SSHing as ubuntu user
            logger.info("XDP attached during bootstrap - verifying...")

            # Verify XDP and services
            if not self._verify_scrubber(public_ip):
                _cleanup_failed_instance("Scrubber verification failed")
                return None

            # Update scrubber status to running (deployment complete)
            scrubber.status = "running"
            scrubber.health_status = "healthy"
            scrubber.last_health_check = datetime.utcnow()
            self.save_state()

            logger.info(f"Scrubber deployed successfully: {node_id}")
            return scrubber

        except Exception as e:
            logger.error(f"Failed to deploy scrubber: {e}")
            _cleanup_failed_instance(f"Unexpected error: {e}")
            return None

    def destroy_scrubber(self, node_id: str) -> bool:
        """
        Destroy a scrubber node.

        Args:
            node_id: Node identifier.

        Returns:
            True if successful.
        """
        if node_id not in self.scrubbers:
            logger.warning(f"Scrubber not found: {node_id}")
            return False

        scrubber = self.scrubbers[node_id]
        logger.info(f"Destroying scrubber: {node_id}")

        try:
            node = Node(
                node_type="scrubber",
                region=scrubber.region,
            )
            success = node.destroy(scrubber.instance_id)

            if success:
                # Clear active/standby reference before deletion
                self.clear_role(node_id)
                del self.scrubbers[node_id]
                logger.info(f"Scrubber destroyed: {node_id}")

                # Save state after destruction
                self.save_state()
                return True
            else:
                logger.error(f"Failed to destroy instance: {scrubber.instance_id}")
                return False

        except Exception as e:
            logger.error(f"Failed to destroy scrubber: {e}")
            return False

    def destroy_all_scrubbers(self) -> int:
        """
        Destroy all scrubber nodes.

        Returns:
            Number of scrubbers destroyed.
        """
        destroyed = 0
        node_ids = list(self.scrubbers.keys())

        for node_id in node_ids:
            if self.destroy_scrubber(node_id):
                destroyed += 1

        return destroyed

    def check_health(self, node_id: str, persist: bool = False) -> bool:
        """
        Check health of a specific scrubber.

        Args:
            node_id: Node identifier.
            persist: If True, save state after health check (use sparingly for performance).

        Returns:
            True if healthy.
        """
        if node_id not in self.scrubbers:
            return False

        scrubber = self.scrubbers[node_id]
        old_status = scrubber.health_status

        try:
            # Check if ecp-agent service is running
            is_healthy = ssh_check_service_running(
                host=scrubber.public_ip,
                username=self.ssh_user,
                key_filename=self.settings.ssh_key_path,
                service_name="ecp-agent"
            )

            scrubber.last_health_check = datetime.utcnow()
            scrubber.health_status = "healthy" if is_healthy else "unhealthy"

            # Persist state if explicitly requested OR if health status changed
            if persist or (old_status != scrubber.health_status):
                self.save_state()
                if old_status != scrubber.health_status:
                    logger.info(f"Health status changed for {node_id}: {old_status} -> {scrubber.health_status}")

            return is_healthy

        except Exception as e:
            logger.warning(f"Health check failed for {node_id}: {e}")
            scrubber.health_status = "unknown"
            # Persist if status changed
            if old_status != "unknown":
                self.save_state()
            return False

    def check_all_health(self, persist: bool = True) -> Dict[str, bool]:
        """
        Check health of all scrubbers.

        Args:
            persist: If True, save state after all health checks.

        Returns:
            Dict mapping node_id to health status.
        """
        results = {}
        any_changed = False
        for node_id in list(self.scrubbers.keys()):
            scrubber = self.scrubbers.get(node_id)
            if scrubber:
                old_status = scrubber.health_status
                # Don't persist individual checks, we'll do one save at the end
                results[node_id] = self.check_health(node_id, persist=False)
                if scrubber.health_status != old_status:
                    any_changed = True

        # Single save at the end if anything changed or persist requested
        if persist and any_changed:
            self.save_state()
            logger.debug(f"Persisted health check results for {len(results)} scrubbers")

        return results

    def get_scrubber_stats(self, node_id: str) -> Optional[ScrubberStats]:
        """
        Get XDP statistics from a scrubber.

        Args:
            node_id: Node identifier.

        Returns:
            ScrubberStats if successful.
        """
        if node_id not in self.scrubbers:
            return None

        scrubber = self.scrubbers[node_id]

        try:
            stats_dict = bpf_read_xdp_stats(
                host=scrubber.public_ip,
                ssh_key_path=self.settings.ssh_key_path,
                user=self.ssh_user
            )

            return ScrubberStats(
                node_id=node_id,
                xdp_pass=stats_dict.get("xdp_pass", 0),
                xdp_drop_blacklist=stats_dict.get("xdp_drop_blacklist", 0),
                xdp_drop_ratelimit=stats_dict.get("xdp_drop_ratelimit", 0),
                xdp_drop_quarantine=stats_dict.get("xdp_drop_quarantine", 0),
                xdp_drop_bogon=stats_dict.get("xdp_drop_bogon", 0),
                xdp_syncookie_challenge=stats_dict.get("xdp_syncookie_challenge", 0),
                whitelist_bypass=stats_dict.get("whitelist_bypass", 0),
            )

        except Exception as e:
            logger.warning(f"Failed to get stats for {node_id}: {e}")
            return None

    def get_all_stats(self) -> Dict[str, ScrubberStats]:
        """
        Get stats from all scrubbers.

        Returns:
            Dict mapping node_id to ScrubberStats.
        """
        results = {}
        for node_id in self.scrubbers:
            stats = self.get_scrubber_stats(node_id)
            if stats:
                results[node_id] = stats
        return results

    def _verify_scrubber(self, host: str) -> bool:
        """
        Verify scrubber is properly configured.

        Checks:
        - XDP program loaded
        - ecp-agent service running
        - BPF maps exist

        Args:
            host: Scrubber IP address.

        Returns:
            True if all checks pass.
        """
        from shared.utils.ssh import ssh_exec

        # Check XDP loaded (detect interface dynamically)
        exit_code, stdout, _ = ssh_exec(
            host=host,
            command="WAN_IF=$(ip route get 1.1.1.1 | grep -oP 'dev \\K\\S+' | head -1) && ip link show $WAN_IF | grep -q xdp",
            ssh_key_path=self.settings.ssh_key_path,
            user=self.ssh_user,
            timeout=30
        )

        if exit_code != 0:
            logger.warning(f"XDP not loaded on {host}")
            return False

        # Check ecp-agent service
        is_running = ssh_check_service_running(
            host=host,
            username=self.ssh_user,
            key_filename=self.settings.ssh_key_path,
            service_name="ecp-agent"
        )

        if not is_running:
            logger.warning(f"ecp-agent not running on {host}")
            return False

        # Check BPF maps exist
        exit_code, stdout, _ = ssh_exec(
            host=host,
            command="sudo bpftool map show | grep -q blacklist_map",
            ssh_key_path=self.settings.ssh_key_path,
            user=self.ssh_user,
            timeout=30
        )

        if exit_code != 0:
            logger.warning(f"BPF maps not found on {host}")
            return False

        logger.info(f"Scrubber verification passed: {host}")
        return True

    def get_status(self) -> Dict[str, Any]:
        """Get overall manager status."""
        return {
            "total_scrubbers": self.scrubber_count,
            "max_scrubbers": self.max_scrubbers,
            "active_count": len(self.active_scrubbers),
            "scrubbers": {
                node_id: scrubber.to_dict()
                for node_id, scrubber in self.scrubbers.items()
            },
        }
