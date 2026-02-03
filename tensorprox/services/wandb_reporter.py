"""
W&B (Weights & Biases) Reporter for TensorProx Validators.

Reports comprehensive audit metrics to W&B for miner transparency:
- Per-miner audit scores (attack coverage, false positives, latency, availability)
- Per-miner EMA scores and leaderboard rankings
- Attack category breakdowns
- Weight distribution and volume metrics
- System-wide statistics

Miners can view their scores at: https://wandb.ai/shugo-labs/tensorprox
"""

import os
import threading
import time
from dataclasses import asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from loguru import logger

try:
    import tensorprox
    TENSORPROX_VERSION = tensorprox.__version__
except (ImportError, AttributeError):
    TENSORPROX_VERSION = "unknown"

if TYPE_CHECKING:
    from tensorprox.rewards.reward import RewardEvent, MinerMetrics
    from tensorprox.rewards.leaderboard import MinerLeaderboard, LeaderboardEntry


class WandbReporter:
    """
    Comprehensive W&B reporter for validator audit metrics.

    Reports metrics in a structured way that allows miners to:
    - Track their individual scores over time
    - Compare against network averages
    - Identify areas for improvement
    - Monitor their ranking and weight allocation
    """

    def __init__(
        self,
        project: str = "tensorprox",
        entity: str = "shugo-labs",
        api_key: Optional[str] = None,
        validator_uid: Optional[int] = None,
        validator_hotkey: Optional[str] = None,
        enabled: bool = True,
        wallet: Optional[Any] = None,
        netuid: Optional[int] = None,
    ):
        """
        Initialize W&B reporter.

        Args:
            project: W&B project name
            entity: W&B entity/team
            api_key: W&B API key (can also use WANDB_API_KEY env var)
            validator_uid: This validator's UID for run naming
            validator_hotkey: This validator's hotkey
            enabled: Whether W&B reporting is enabled
            wallet: Bittensor wallet for signing
            netuid: Network UID
        """
        self.project = project
        self.entity = entity
        self.validator_uid = validator_uid
        self.validator_hotkey = validator_hotkey
        self.enabled = enabled
        self.wallet = wallet
        self.netuid = netuid
        self._initialized = False
        self._step = 0
        self._lock = threading.Lock()

        if api_key:
            os.environ["WANDB_API_KEY"] = api_key

        if enabled:
            self._initialize()

    def _initialize(self) -> bool:
        """Initialize W&B connection."""
        if self._initialized:
            return True

        try:
            import wandb

            # Build run name
            run_name = f"validator-{self.validator_uid}"
            if self.validator_hotkey:
                run_name = f"{run_name}-{self.validator_hotkey[:8]}"

            # Build tags
            tags = [
                f"Time: {datetime.now().strftime('%Y_%m_%d_%H_%M_%S')}",
                f"Version: {TENSORPROX_VERSION}",
            ]
            if self.validator_hotkey:
                tags.append(f"Wallet: {self.validator_hotkey}")
            if self.validator_uid is not None:
                tags.append(f"Neuron UID: {self.validator_uid}")
            if self.netuid is not None:
                tags.append(f"Netuid: {self.netuid}")

            # Build config
            config = {
                "validator_uid": self.validator_uid,
                "validator_hotkey": self.validator_hotkey,
                "role": "validator",
                "wandb_start_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "version": TENSORPROX_VERSION,
            }
            if self.validator_hotkey:
                config["HOTKEY_SS58"] = self.validator_hotkey
            if self.netuid is not None:
                config["NETUID"] = self.netuid

            # Initialize W&B
            run = wandb.init(
                project=self.project,
                entity=self.entity,
                name=run_name,
                config=config,
                tags=tags,
                reinit=True,
            )

            # Add signature if wallet available
            if self.wallet and hasattr(self.wallet, 'hotkey') and run:
                try:
                    signature = self.wallet.hotkey.sign(run.id.encode()).hex()
                    run.config.update({"SIGNATURE": signature}, allow_val_change=True)
                except Exception as e:
                    logger.debug(f"Failed to add W&B signature: {e}")

            self._initialized = True
            logger.info(
                f"W&B initialized: {self.entity}/{self.project} as {run_name}"
            )
            return True

        except ImportError:
            logger.warning("wandb not installed, W&B reporting disabled")
            self.enabled = False
            return False
        except Exception as e:
            logger.error(f"Failed to initialize W&B: {e}")
            self.enabled = False
            return False

    def log_audit_results(
        self,
        reward_event: "RewardEvent",
        miner_metrics: Dict[int, "MinerMetrics"],
        leaderboard: "MinerLeaderboard",
        uid_to_hotkey: Dict[int, str],
    ) -> None:
        """
        Log comprehensive audit results to W&B.

        This is the main entry point called after each audit cycle.

        Args:
            reward_event: Complete reward calculation results
            miner_metrics: Raw metrics per miner UID
            leaderboard: Current leaderboard state
            uid_to_hotkey: Mapping of UID to hotkey
        """
        if not self.enabled:
            return

        with self._lock:
            self._step += 1
            step = self._step

        try:
            import wandb
            if wandb.run is None:
                if not self._initialize():
                    return

            # Prepare data for logging
            data: Dict[str, Any] = {}

            # 1. System-wide metrics
            data.update(self._build_system_metrics(reward_event, miner_metrics))

            # 2. Per-miner metrics (as tables for easy viewing)
            miner_table = self._build_miner_table(
                reward_event, miner_metrics, leaderboard, uid_to_hotkey
            )
            if miner_table:
                data["miners"] = miner_table

            # 3. Attack category summary
            data.update(self._build_category_summary(reward_event))

            # 4. Leaderboard rankings
            data.update(self._build_leaderboard_metrics(leaderboard))

            # Log to W&B
            wandb.log(data, step=step)

            logger.debug(f"W&B logged audit results at step {step}")

        except Exception as e:
            logger.error(f"W&B logging error: {e}")

    def log_weight_update(
        self,
        weights: List[float],
        uids: List[int],
        uid_to_hotkey: Dict[int, str],
        volume_scores: Optional[List[float]] = None,
        ema_scores: Optional[List[float]] = None,
    ) -> None:
        """
        Log weight setting to W&B.

        Args:
            weights: Final weights being set on chain
            uids: UIDs receiving weights
            uid_to_hotkey: Mapping of UID to hotkey
            volume_scores: Volume component of weights
            ema_scores: EMA score component of weights
        """
        if not self.enabled:
            return

        try:
            import wandb
            if wandb.run is None:
                return

            with self._lock:
                step = self._step

            data = {
                "weights/total_miners": len(weights),
                "weights/sum": sum(weights),
                "weights/max": max(weights) if weights else 0,
                "weights/min": min(weights) if weights else 0,
                "weights/avg": sum(weights) / len(weights) if weights else 0,
            }

            # Weight distribution histogram
            if weights:
                data["weights/distribution"] = wandb.Histogram(weights)

            # Top miners by weight
            if uids and weights:
                sorted_miners = sorted(
                    zip(uids, weights),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]

                for rank, (uid, weight) in enumerate(sorted_miners, 1):
                    hotkey = uid_to_hotkey.get(uid, "unknown")[:8]
                    data[f"weights/top_{rank}_uid"] = uid
                    data[f"weights/top_{rank}_weight"] = weight

            wandb.log(data, step=step)

        except Exception as e:
            logger.error(f"W&B weight logging error: {e}")

    def log_miner_score(
        self,
        uid: int,
        hotkey: str,
        audit_score: float,
        attack_score: float,
        fp_score: float,
        latency_score: float,
        availability_score: float,
        ema_score: float,
        volume: int = 0,
        category_scores: Optional[Dict[str, float]] = None,
    ) -> None:
        """
        Log individual miner score update.

        Called after each individual miner audit for real-time tracking.
        """
        if not self.enabled:
            return

        try:
            import wandb
            if wandb.run is None:
                return

            with self._lock:
                step = self._step

            hotkey_short = hotkey[:8] if hotkey else "unknown"
            prefix = f"miner/{uid}_{hotkey_short}"

            data = {
                f"{prefix}/audit_score": audit_score,
                f"{prefix}/attack_coverage": attack_score,
                f"{prefix}/benign_pass_rate": fp_score,  # 1 = all benign traffic passed correctly
                f"{prefix}/latency": latency_score,
                f"{prefix}/availability": availability_score,
                f"{prefix}/ema_score": ema_score,
                f"{prefix}/volume_bytes": volume,
            }

            # Add category breakdown if available
            if category_scores:
                for cat, score in category_scores.items():
                    data[f"{prefix}/cat_{cat}"] = score

            wandb.log(data, step=step)

        except Exception as e:
            logger.debug(f"W&B miner score logging error: {e}")

    def _build_system_metrics(
        self,
        reward_event: "RewardEvent",
        miner_metrics: Dict[int, "MinerMetrics"],
    ) -> Dict[str, Any]:
        """Build system-wide aggregate metrics."""
        data = {
            # Audit cycle stats
            "system/miners_audited": len(miner_metrics),
            "system/avg_reward": reward_event.avg_reward,
            "system/best_miner_uid": reward_event.best_miner_uid,
            "system/best_miner_score": reward_event.best_miner_score,
            "system/miners_with_full_coverage": reward_event.miners_with_full_coverage,

            # Benchmarks
            "system/max_bytes_processed": reward_event.max_bytes,
            "system/max_connections": reward_event.max_connections,
            "system/max_origins_served": reward_event.max_origins,
            "system/min_rtt_ms": reward_event.min_rtt if reward_event.min_rtt != float("inf") else 0,
            "system/max_uptime_percent": reward_event.max_uptime,
        }

        # Calculate averages across all miners
        if miner_metrics:
            total_volume = sum(m.total_bytes_processed for m in miner_metrics.values())
            avg_fp_rate = sum(m.false_positive_rate for m in miner_metrics.values()) / len(miner_metrics)
            avg_rtt = sum(m.avg_rtt_ms for m in miner_metrics.values()) / len(miner_metrics)
            avg_uptime = sum(m.uptime_percent for m in miner_metrics.values()) / len(miner_metrics)

            data.update({
                "system/total_volume_bytes": total_volume,
                "system/avg_false_positive_rate": avg_fp_rate,
                "system/avg_rtt_ms": avg_rtt,
                "system/avg_uptime_percent": avg_uptime,
            })

        return data

    def _build_miner_table(
        self,
        reward_event: "RewardEvent",
        miner_metrics: Dict[int, "MinerMetrics"],
        leaderboard: "MinerLeaderboard",
        uid_to_hotkey: Dict[int, str],
    ) -> Optional[Any]:
        """Build W&B table with per-miner metrics."""
        try:
            import wandb

            columns = [
                "uid", "audit_score", "ema_score",
                "attack_coverage", "benign_pass_rate", "latency", "availability",
                "volume_bytes", "uptime_percent", "avg_rtt_ms", "rank"
            ]

            data = []

            # Get rankings from leaderboard
            rankings = leaderboard.get_rankings()
            uid_to_rank = {uid: rank for rank, uid in enumerate(rankings, 1)}

            for idx, (uid, metrics) in enumerate(miner_metrics.items()):
                if idx >= len(reward_event.rewards):
                    continue

                entry = leaderboard.get_entry(uid)
                ema_score = entry.ema_score if entry else 0.0
                rank = uid_to_rank.get(uid, 999)

                row = [
                    uid,
                    reward_event.rewards[idx] if idx < len(reward_event.rewards) else 0,
                    ema_score,
                    reward_event.attack_coverage_scores[idx] if idx < len(reward_event.attack_coverage_scores) else 0,
                    reward_event.false_positive_scores[idx] if idx < len(reward_event.false_positive_scores) else 0,  # benign_pass_rate: 1 = all benign passed
                    reward_event.latency_scores[idx] if idx < len(reward_event.latency_scores) else 0,
                    reward_event.availability_scores[idx] if idx < len(reward_event.availability_scores) else 0,
                    metrics.total_bytes_processed,
                    metrics.uptime_percent,
                    metrics.avg_rtt_ms,
                    rank,
                ]
                data.append(row)

            if data:
                return wandb.Table(columns=columns, data=data)
            return None

        except Exception as e:
            logger.debug(f"Error building miner table: {e}")
            return None

    def _build_category_summary(
        self,
        reward_event: "RewardEvent",
    ) -> Dict[str, Any]:
        """Build attack category coverage summary."""
        data = {}

        # Average coverage per category across all miners
        for cat_name, avg_coverage in reward_event.avg_category_coverage.items():
            data[f"category/{cat_name}_avg_coverage"] = avg_coverage

        return data

    def _build_leaderboard_metrics(
        self,
        leaderboard: "MinerLeaderboard",
    ) -> Dict[str, Any]:
        """Build leaderboard ranking metrics."""
        data = {}

        try:
            rankings = leaderboard.get_rankings()
            eligible_count = sum(
                1 for uid in rankings
                if leaderboard.is_eligible(uid)
            )

            data["leaderboard/total_ranked"] = len(rankings)
            data["leaderboard/eligible_miners"] = eligible_count

            # Top 10 miners
            for rank, uid in enumerate(rankings[:10], 1):
                entry = leaderboard.get_entry(uid)
                if entry:
                    data[f"leaderboard/rank_{rank}_uid"] = uid
                    data[f"leaderboard/rank_{rank}_ema"] = entry.ema_score
                    data[f"leaderboard/rank_{rank}_variance"] = entry.ema_variance

            # EMA distribution
            all_emas = [
                leaderboard.get_entry(uid).ema_score
                for uid in rankings
                if leaderboard.get_entry(uid)
            ]
            if all_emas:
                import wandb
                data["leaderboard/ema_distribution"] = wandb.Histogram(all_emas)
                data["leaderboard/avg_ema"] = sum(all_emas) / len(all_emas)
                data["leaderboard/max_ema"] = max(all_emas)
                data["leaderboard/min_ema"] = min(all_emas)

        except Exception as e:
            logger.debug(f"Error building leaderboard metrics: {e}")

        return data

    def finish(self) -> None:
        """Finish W&B run."""
        if not self._initialized:
            return

        try:
            import wandb
            if wandb.run is not None:
                wandb.finish()
            self._initialized = False
            logger.info("W&B run finished")
        except Exception as e:
            logger.error(f"Error finishing W&B run: {e}")


# Singleton instance for easy access
_reporter: Optional[WandbReporter] = None


def get_wandb_reporter() -> Optional[WandbReporter]:
    """Get the global W&B reporter instance."""
    return _reporter


def init_wandb_reporter(
    project: str = "tensorprox",
    entity: str = "shugo-labs",
    api_key: Optional[str] = None,
    validator_uid: Optional[int] = None,
    validator_hotkey: Optional[str] = None,
    enabled: bool = True,
    wallet: Optional[Any] = None,
    netuid: Optional[int] = None,
) -> WandbReporter:
    """
    Initialize the global W&B reporter.

    Call this once during validator startup.

    Args:
        project: W&B project name
        entity: W&B entity/team
        api_key: W&B API key
        validator_uid: This validator's UID
        validator_hotkey: This validator's hotkey
        enabled: Whether W&B reporting is enabled
        wallet: Bittensor wallet for signing
        netuid: Network UID
    """
    global _reporter
    _reporter = WandbReporter(
        project=project,
        entity=entity,
        api_key=api_key,
        validator_uid=validator_uid,
        validator_hotkey=validator_hotkey,
        enabled=enabled,
        wallet=wallet,
        netuid=netuid,
    )
    return _reporter
