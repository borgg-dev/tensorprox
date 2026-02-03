"""Automatic orphan instance sweeper.

Periodically scans cloud providers for exit_hub instances that TPM has lost track of
and terminates them automatically. Scans ALL regions where TPM deploys.

Supports multiple cloud providers (AWS, Linode).
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from shared.node import Node
from shared.utils.logging import get_logger

from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository
from tensorprox.tpm.services.geolocation import infer_provider_from_region

logger = get_logger(__name__)

# Instances younger than this are not considered orphans (still deploying)
MIN_AGE_SECONDS = 600  # 10 minutes


class OrphanSweeper:
    """Background service that finds and terminates orphaned exit_hub instances."""

    def __init__(
        self,
        repository: ExitHubRepository,
        interval_seconds: int = 300,  # 5 minutes
        regions: Optional[List[str]] = None,
        provider_registry: Any = None,
        enabled: bool = True,
    ):
        self.repository = repository
        self.interval = interval_seconds
        self.regions = regions or []
        self.provider_registry = provider_registry
        self.enabled = enabled
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the background sweeper thread."""
        if not self.enabled:
            logger.info("Orphan sweeper disabled")
            return
        if self._thread and self._thread.is_alive():
            logger.warning("Orphan sweeper already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="orphan-sweeper",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Orphan sweeper started (interval=%ds, regions=%d)",
            self.interval,
            len(self.regions),
        )

    def stop(self) -> None:
        """Stop the background sweeper thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Orphan sweeper stopped")

    def sweep_now(self) -> Dict[str, Any]:
        """Run a sweep immediately. Returns summary of actions taken."""
        return self._sweep()

    def _run_loop(self) -> None:
        """Main loop that runs sweeps periodically."""
        while not self._stop_event.is_set():
            try:
                self._sweep()
            except Exception as exc:
                logger.error("Orphan sweeper error: %s", exc, exc_info=True)
            self._stop_event.wait(timeout=self.interval)

    def _sweep(self) -> Dict[str, Any]:
        """Find and terminate orphaned instances across all regions."""
        logger.info("Orphan sweeper: starting scan across %d regions", len(self.regions))

        # Get tracked instance_ids from TPM database
        tracked_ids = self._get_tracked_instance_ids()

        total_scanned = 0
        total_orphans = 0
        total_terminated: List[str] = []

        for region in self.regions:
            result = self._sweep_region(region, tracked_ids)
            total_scanned += result["scanned"]
            total_orphans += result["orphans"]
            total_terminated.extend(result["terminated"])

        logger.info(
            "Orphan sweeper: total scanned=%d, orphans=%d, terminated=%d",
            total_scanned, total_orphans, len(total_terminated)
        )
        return {
            "scanned": total_scanned,
            "orphans": total_orphans,
            "terminated": total_terminated,
        }

    def _sweep_region(self, region: str, tracked_ids: Dict[str, str]) -> Dict[str, Any]:
        """Sweep a single region for orphans."""
        # Detect provider from region format (aws: us-east-1, linode: us-east)
        provider_name = infer_provider_from_region(region)
        logger.debug("Orphan sweeper: scanning region %s (provider: %s)", region, provider_name)

        # Get all exit_hub instances from this provider/region
        instances = self._get_exit_hub_instances(region, provider_name)
        if not instances:
            return {"scanned": 0, "orphans": 0, "terminated": []}

        # Find orphans: in cloud but not tracked (or tracked as terminated/failed)
        orphans = []
        now = datetime.now(timezone.utc)

        for instance in instances:
            instance_id = instance["instance_id"]
            launch_time = instance.get("launch_time")

            if launch_time:
                age_seconds = (now - launch_time).total_seconds()
            else:
                age_seconds = MIN_AGE_SECONDS + 1  # Unknown age, assume old

            # Skip young instances (might still be deploying)
            if age_seconds < MIN_AGE_SECONDS:
                logger.debug(
                    "Orphan sweeper: skipping %s in %s (age=%ds < %ds)",
                    instance_id, region, age_seconds, MIN_AGE_SECONDS
                )
                continue

            # Check if tracked
            if instance_id not in tracked_ids:
                orphans.append({
                    **instance,
                    "region": region,
                    "provider": provider_name,
                    "reason": "not_in_database",
                    "age_seconds": age_seconds,
                })
            elif tracked_ids[instance_id] in ("terminated", "failed", "cancelled"):
                orphans.append({
                    **instance,
                    "region": region,
                    "provider": provider_name,
                    "reason": f"status_{tracked_ids[instance_id]}",
                    "age_seconds": age_seconds,
                })

        if not orphans:
            logger.debug(
                "Orphan sweeper: scanned %d instances in %s (%s), no orphans",
                len(instances), region, provider_name
            )
            return {"scanned": len(instances), "orphans": 0, "terminated": []}

        # Terminate orphans
        terminated = []
        for orphan in orphans:
            instance_id = orphan["instance_id"]
            orphan_region = orphan.get("region", region)
            logger.warning(
                "Orphan sweeper: terminating orphan %s in %s (ip=%s, reason=%s, age=%ds)",
                instance_id,
                orphan_region,
                orphan.get("public_ip"),
                orphan["reason"],
                orphan["age_seconds"],
            )
            try:
                orphan_provider = orphan.get("provider", provider_name)
                node = Node(
                    node_type="exit_hub",
                    region=orphan_region,
                    cloud_provider=orphan_provider,
                )
                destroyed = node.destroy(instance_id)
                if destroyed:
                    terminated.append(instance_id)
                    logger.info("Orphan sweeper: terminated %s in %s", instance_id, orphan_region)
                else:
                    logger.warning(
                        "Orphan sweeper: destroy returned false for %s in %s",
                        instance_id, orphan_region
                    )
            except Exception as exc:
                logger.error(
                    "Orphan sweeper: failed to terminate %s in %s: %s",
                    instance_id, orphan_region, exc
                )

        logger.info(
            "Orphan sweeper: region %s (%s) scanned=%d, orphans=%d, terminated=%d",
            region, provider_name, len(instances), len(orphans), len(terminated)
        )
        return {
            "scanned": len(instances),
            "orphans": len(orphans),
            "terminated": terminated,
        }

    def _get_exit_hub_instances(self, region: str, provider_name: str) -> List[Dict]:
        """Query cloud provider for running exit_hub instances via REST API.

        Args:
            region: Cloud region to scan
            provider_name: Cloud provider name (aws, linode)

        Returns:
            List of instance dictionaries with instance_id, public_ip, launch_time, etc.
        """
        if not self.provider_registry:
            logger.warning("Orphan sweeper: no provider_registry, cannot scan %s", region)
            return []

        try:
            provider = self.provider_registry.get_provider(provider_name)

            # Build provider-appropriate filters
            if provider_name == "aws":
                filters = {
                    "instance-state-name": "running",
                    "tag:Name": "exit_hub*",
                }
            elif provider_name == "linode":
                # Linode uses label filtering
                filters = {
                    "status": "running",
                    "label": "exit_hub",  # Linode filter by label prefix
                }
            else:
                filters = {"status": "running"}

            instances = provider.describe_instances_with_filters(
                region=region,
                filters=filters
            )
            return instances
        except Exception as exc:
            logger.error("Orphan sweeper: %s query failed for %s: %s", provider_name, region, exc)
            return []

    def _get_tracked_instance_ids(self) -> Dict[str, str]:
        """Get instance_id -> status mapping from TPM database."""
        try:
            # Get all exit_hubs (we need to check terminated/failed ones too)
            all_hubs = self.repository.list_exit_hubs()
            return {
                hub["instance_id"]: hub["status"]
                for hub in all_hubs
                if hub.get("instance_id")
            }
        except Exception as exc:
            logger.error("Orphan sweeper: database query failed: %s", exc)
            return {}


# Singleton for use by the application
_sweeper: Optional[OrphanSweeper] = None


def get_orphan_sweeper() -> OrphanSweeper:
    """Get or create the singleton orphan sweeper."""
    global _sweeper
    if _sweeper is None:
        from shared.config import get_settings
        from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository
        from tensorprox.tpm.services.provider_registry import ProviderRegistry

        settings = get_settings()
        registry = ProviderRegistry(settings)
        regions = registry.available_regions("aws") or []

        _sweeper = OrphanSweeper(
            repository=ExitHubRepository(),
            interval_seconds=300,
            regions=regions,
            provider_registry=registry,
        )
    return _sweeper


def start_orphan_sweeper() -> None:
    """Start the orphan sweeper background service."""
    get_orphan_sweeper().start()


def sweep_orphans_now() -> Dict[str, Any]:
    """Run an immediate orphan sweep. Returns summary."""
    return get_orphan_sweeper().sweep_now()
