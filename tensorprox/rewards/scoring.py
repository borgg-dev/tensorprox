"""
Task scoring module for TensorProx subnet.

Manages the scoring queue and processes validation results
using the ChallengeRewardModel.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from queue import Queue

from pydantic import Field
from loguru import logger

from tensorprox.base.loop_runner import AsyncLoopRunner
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.rewards.reward import (
    ProductionRewardModel,
    RewardEvent,
    MinerMetrics,
)

# Aliases for backwards compatibility
ChallengeRewardModel = ProductionRewardModel
ChallengeRewardEvent = RewardEvent


@dataclass
class ScoringConfig:
    """Configuration for a scoring task."""

    # Response data
    response: DendriteResponseEvent

    # UIDs involved
    uids: List[int] = field(default_factory=list)

    # Additional metadata
    block: int = 0
    step: int = 0

    # Labels for traffic identification (optional)
    label_hashes: Dict[str, str] = field(default_factory=dict)


class TaskScorer(AsyncLoopRunner):
    """
    Async task scorer that processes validation results.

    Maintains a queue of ScoringConfig objects and processes
    them one at a time, computing rewards using ChallengeRewardModel.
    """

    # Queue configuration
    queue: Queue = Field(default_factory=Queue)
    max_queue_size: int = Field(default=100)

    # Reward model
    reward_model: ChallengeRewardModel = Field(
        default_factory=ChallengeRewardModel
    )

    # Results storage
    latest_event: Optional[ChallengeRewardEvent] = Field(default=None)
    results_history: List[ChallengeRewardEvent] = Field(default_factory=list)
    max_history: int = Field(default=100)

    # Callbacks
    on_score_callback: Optional[callable] = Field(default=None)

    def __init__(self, **kwargs):
        """Initialize the task scorer."""
        super().__init__(
            interval=1,  # Process queue every second
            name="TaskScorer",
            **kwargs
        )

    def add_scoring_task(self, config: ScoringConfig) -> bool:
        """
        Add a scoring task to the queue.

        Args:
            config: The scoring configuration.

        Returns:
            True if added, False if queue is full.
        """
        if self.queue.qsize() >= self.max_queue_size:
            logger.warning("Scoring queue is full, dropping task")
            return False

        self.queue.put(config)
        logger.debug(f"Added scoring task, queue size: {self.queue.qsize()}")
        return True

    async def run_step(self) -> None:
        """Process one scoring task from the queue."""
        if self.queue.empty():
            return

        try:
            config = self.queue.get_nowait()
            event = await self._process_scoring_config(config)

            if event:
                self.latest_event = event
                self.results_history.append(event)

                # Trim history
                if len(self.results_history) > self.max_history:
                    self.results_history.pop(0)

                # Call callback if set
                if self.on_score_callback:
                    await self._call_callback(config, event)

        except Exception as e:
            logger.error(f"Error processing scoring task: {e}")

    async def _process_scoring_config(
        self,
        config: ScoringConfig
    ) -> Optional[ChallengeRewardEvent]:
        """
        Process a single scoring configuration.

        Args:
            config: The scoring config to process.

        Returns:
            ChallengeRewardEvent with computed rewards.
        """
        logger.info(
            f"Processing scoring for round {config.response.round_id}, "
            f"block {config.block}, {len(config.uids)} miners"
        )

        # Extract metrics from response
        metrics_list = self._extract_metrics(config)

        if not metrics_list:
            logger.warning("No metrics to score")
            return None

        # Compute rewards
        event = self.reward_model.compute_rewards(metrics_list)

        logger.info(
            f"Scoring complete. Best score: {event.best_miner_score:.4f}, "
            f"Avg: {sum(event.rewards) / len(event.rewards) if event.rewards else 0:.4f}"
        )

        return event

    def _extract_metrics(
        self,
        config: ScoringConfig
    ) -> List[MinerMetrics]:
        """
        Extract MinerMetrics from a scoring config.

        Args:
            config: The scoring configuration.

        Returns:
            List of MinerMetrics objects.
        """
        metrics_list = []
        response = config.response

        for uid in config.uids:
            # Get metrics for this UID
            metrics_dict = response.get_metrics(uid)

            if not metrics_dict:
                # No metrics = zero scores
                metrics_list.append(MinerMetrics(uid=uid))
                continue

            # Convert to MinerMetrics
            metrics = MinerMetrics(
                uid=uid,
                total_packets_sent=metrics_dict.get("total_packets_sent", 0),
                total_benign_sent=metrics_dict.get("total_benign_sent", 0),
                total_attack_sent=metrics_dict.get("total_attack_sent", 0),
                total_reaching_packets=metrics_dict.get("total_reaching_packets", 0),
                total_reaching_benign=metrics_dict.get("total_reaching_benign", 0),
                total_reaching_attack=metrics_dict.get("total_reaching_attack", 0),
                avg_rtt_ms=metrics_dict.get("avg_rtt_ms", 0.0),
                min_rtt_ms=metrics_dict.get("min_rtt_ms", 0.0),
                p95_rtt_ms=metrics_dict.get("p95_rtt_ms", 0.0),
                p99_rtt_ms=metrics_dict.get("p99_rtt_ms", 0.0),
                xdp_drop_blacklist=metrics_dict.get("xdp_drop_blacklist", 0),
                xdp_drop_ratelimit=metrics_dict.get("xdp_drop_ratelimit", 0),
                xdp_drop_quarantine=metrics_dict.get("xdp_drop_quarantine", 0),
                xdp_drop_bogon=metrics_dict.get("xdp_drop_bogon", 0),
                xdp_syncookie_challenge=metrics_dict.get("xdp_syncookie_challenge", 0),
                whitelist_bypass=metrics_dict.get("whitelist_bypass", 0),
            )
            metrics_list.append(metrics)

        return metrics_list

    async def _call_callback(
        self,
        config: ScoringConfig,
        event: ChallengeRewardEvent
    ) -> None:
        """Call the scoring callback."""
        try:
            if asyncio.iscoroutinefunction(self.on_score_callback):
                await self.on_score_callback(config, event)
            else:
                self.on_score_callback(config, event)
        except Exception as e:
            logger.error(f"Error in score callback: {e}")

    def get_latest_rewards(self) -> Optional[Dict[int, float]]:
        """
        Get the latest rewards by UID.

        Returns:
            Dict mapping UID to reward, or None if no results.
        """
        if not self.latest_event:
            return None

        # Note: This requires UIDs to be tracked with rewards
        # For now, return rewards list indexed by position
        return {
            i: reward
            for i, reward in enumerate(self.latest_event.rewards)
        }

    def get_average_scores(self) -> Dict[str, float]:
        """
        Get average scores across recent history.

        Returns:
            Dict with average values for each metric.
        """
        if not self.results_history:
            return {}

        n = len(self.results_history)

        return {
            "avg_reward": sum(
                sum(e.rewards) / len(e.rewards) if e.rewards else 0
                for e in self.results_history
            ) / n,
            "avg_bdr": sum(
                sum(e.bdr) / len(e.bdr) if e.bdr else 0
                for e in self.results_history
            ) / n,
            "avg_ama": sum(
                sum(e.ama) / len(e.ama) if e.ama else 0
                for e in self.results_history
            ) / n,
            "avg_sps": sum(
                sum(e.sps) / len(e.sps) if e.sps else 0
                for e in self.results_history
            ) / n,
            "best_score": max(e.best_miner_score for e in self.results_history),
        }
