"""
Health monitoring service for TensorProx miners.

Periodically checks scrubber health and collects XDP statistics.
"""

import asyncio
from typing import Dict, Any, Optional, Callable
from datetime import datetime

from pydantic import Field
from loguru import logger

from tensorprox.base.loop_runner import AsyncLoopRunner
from tensorprox.services.scrubber_manager import ScrubberManager
from shared.models import ScrubberStats


class HealthMonitor(AsyncLoopRunner):
    """
    Async health monitor for scrubber nodes.

    Periodically checks scrubber health and collects statistics.
    Alerts on unhealthy nodes and can trigger recovery actions.
    """

    # Scrubber manager reference
    scrubber_manager: Optional[ScrubberManager] = Field(default=None)

    # Health state
    last_health_check: Dict[str, datetime] = Field(default_factory=dict)
    health_status: Dict[str, bool] = Field(default_factory=dict)
    consecutive_failures: Dict[str, int] = Field(default_factory=dict)

    # Statistics collection
    latest_stats: Dict[str, ScrubberStats] = Field(default_factory=dict)

    # Configuration
    failure_threshold: int = Field(
        default=3,
        description="Consecutive failures before node is marked unhealthy"
    )

    # Callbacks
    on_unhealthy_callback: Optional[Callable] = Field(default=None)
    on_stats_callback: Optional[Callable] = Field(default=None)

    def __init__(
        self,
        scrubber_manager: ScrubberManager,
        interval: int = 30,
        **kwargs
    ):
        """
        Initialize the health monitor.

        Args:
            scrubber_manager: Manager for scrubber nodes.
            interval: Health check interval in seconds.
        """
        super().__init__(
            interval=interval,
            name="HealthMonitor",
            **kwargs
        )
        self.scrubber_manager = scrubber_manager

    async def run_step(self) -> None:
        """Run one health check cycle."""
        if not self.scrubber_manager:
            return

        logger.debug(f"Running health check (step {self.step})")

        # Check health of all scrubbers
        for node_id in list(self.scrubber_manager.scrubbers.keys()):
            await self._check_node_health(node_id)

        # Collect statistics
        await self._collect_stats()

    async def _check_node_health(self, node_id: str) -> None:
        """
        Check health of a specific node.

        Args:
            node_id: Node identifier.
        """
        try:
            # Run health check in executor to avoid blocking
            loop = asyncio.get_event_loop()
            is_healthy = await loop.run_in_executor(
                None,
                self.scrubber_manager.check_health,
                node_id
            )

            self.last_health_check[node_id] = datetime.utcnow()

            if is_healthy:
                self.health_status[node_id] = True
                self.consecutive_failures[node_id] = 0
            else:
                self.consecutive_failures[node_id] = (
                    self.consecutive_failures.get(node_id, 0) + 1
                )

                if self.consecutive_failures[node_id] >= self.failure_threshold:
                    self.health_status[node_id] = False
                    await self._handle_unhealthy_node(node_id)

        except Exception as e:
            logger.warning(f"Health check error for {node_id}: {e}")
            self.consecutive_failures[node_id] = (
                self.consecutive_failures.get(node_id, 0) + 1
            )

    async def _collect_stats(self) -> None:
        """Collect XDP statistics from all scrubbers."""
        try:
            loop = asyncio.get_event_loop()
            stats = await loop.run_in_executor(
                None,
                self.scrubber_manager.get_all_stats
            )

            self.latest_stats = stats

            # Call stats callback if set
            if self.on_stats_callback:
                await self._call_stats_callback(stats)

        except Exception as e:
            logger.warning(f"Stats collection error: {e}")

    async def _handle_unhealthy_node(self, node_id: str) -> None:
        """
        Handle an unhealthy node.

        Args:
            node_id: Node identifier.
        """
        logger.warning(
            f"Node {node_id} marked unhealthy after "
            f"{self.failure_threshold} consecutive failures"
        )

        # Call unhealthy callback if set
        if self.on_unhealthy_callback:
            try:
                if asyncio.iscoroutinefunction(self.on_unhealthy_callback):
                    await self.on_unhealthy_callback(node_id)
                else:
                    self.on_unhealthy_callback(node_id)
            except Exception as e:
                logger.error(f"Error in unhealthy callback: {e}")

    async def _call_stats_callback(
        self,
        stats: Dict[str, ScrubberStats]
    ) -> None:
        """Call the stats collection callback."""
        try:
            if asyncio.iscoroutinefunction(self.on_stats_callback):
                await self.on_stats_callback(stats)
            else:
                self.on_stats_callback(stats)
        except Exception as e:
            logger.error(f"Error in stats callback: {e}")

    def get_aggregated_stats(self) -> Dict[str, int]:
        """
        Get aggregated statistics across all scrubbers.

        Returns:
            Dictionary with summed counters.
        """
        aggregated = {
            "xdp_pass": 0,
            "xdp_drop_blacklist": 0,
            "xdp_drop_ratelimit": 0,
            "xdp_drop_quarantine": 0,
            "xdp_drop_bogon": 0,
            "xdp_syncookie_challenge": 0,
            "whitelist_bypass": 0,
            "total_dropped": 0,
            "total_processed": 0,
        }

        for stats in self.latest_stats.values():
            aggregated["xdp_pass"] += stats.xdp_pass
            aggregated["xdp_drop_blacklist"] += stats.xdp_drop_blacklist
            aggregated["xdp_drop_ratelimit"] += stats.xdp_drop_ratelimit
            aggregated["xdp_drop_quarantine"] += stats.xdp_drop_quarantine
            aggregated["xdp_drop_bogon"] += stats.xdp_drop_bogon
            aggregated["xdp_syncookie_challenge"] += stats.xdp_syncookie_challenge
            aggregated["whitelist_bypass"] += stats.whitelist_bypass
            aggregated["total_dropped"] += stats.total_dropped
            aggregated["total_processed"] += stats.total_processed

        return aggregated

    def get_healthy_node_count(self) -> int:
        """Get count of healthy nodes."""
        return sum(1 for h in self.health_status.values() if h)

    def get_status(self) -> Dict[str, Any]:
        """Get monitor status."""
        return {
            "step": self.step,
            "running": self.running,
            "total_nodes": len(self.health_status),
            "healthy_nodes": self.get_healthy_node_count(),
            "health_status": self.health_status.copy(),
            "aggregated_stats": self.get_aggregated_stats(),
        }
