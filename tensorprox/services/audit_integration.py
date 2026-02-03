"""
Audit Integration Module.

Provides a unified interface for running cryptographic audits
and computing rewards. This is the main entry point for validators.

Usage:
    from tensorprox.services.audit_integration import AuditIntegration

    # Initialize
    audit = AuditIntegration(
        dendrite=dendrite,
        wallet=wallet,
        metagraph=metagraph,
    )

    # Run audit round
    weights = await audit.run_audit_round_and_compute_weights()

    # Set weights on chain
    subtensor.set_weights(
        wallet=wallet,
        netuid=netuid,
        uids=list(weights.keys()),
        weights=list(weights.values()),
    )
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

from loguru import logger
import bittensor as bt

from tensorprox.services.validator_audit_service import (
    ValidatorAuditService,
    AuditTarget,
    AuditRoundResult,
)
from tensorprox.services.audit import (
    AuditSender,
    ATTACK_PROFILES,
)
from tensorprox.services.l7_audit import (
    L7AuditSender,
    L7AuditChallenge,
    L7AuditResult,
    L7AttackType,
)
from tensorprox.rewards.leaderboard import (
    MinerLeaderboard,
    compute_bittensor_weights,
    ELIGIBILITY_THRESHOLD,
)
from tensorprox.rewards.reward import (
    compute_rewards_from_audit,
    AuditResultData,
    convert_audit_result_to_data,
)
from tensorprox.base.protocol import PingSynapse

# Try to import aiohttp for L7 metrics fetching
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    logger.warning("aiohttp not available - L7 metrics fetching disabled")


@dataclass
class AuditConfig:
    """Configuration for audit rounds."""
    # Audit frequency
    audit_interval_seconds: int = 300  # 5 minutes

    # Throughput levels to test
    default_throughput_level: int = 1  # Normal
    graduated_audit_probability: float = 0.2  # 20% chance of graduated test

    # Selection parameters
    miners_per_round: int = 10  # How many miners to audit per round
    min_eligible_miners: int = 3  # Minimum to proceed with round

    # Timeouts
    synapse_timeout: float = 30.0
    graduated_timeout: float = 120.0

    # Eligibility
    eligibility_threshold: float = ELIGIBILITY_THRESHOLD

    # L7 Audit Configuration
    enable_l7_audit: bool = True  # Enable Layer 7 auditing
    l7_audit_probability: float = 0.5  # 50% of audits include L7
    l7_weight: float = 0.20  # L7 contributes 20% to final score
    l34_weight: float = 0.80  # L3/L4 contributes 80% to final score
    # Note: Throughput scoring removed - lightweight audits focus on
    # filtering correctness, not capacity (validator audits 200+ miners)


class AuditIntegration:
    """
    Main integration class for cryptographic audits.

    Combines:
    - ValidatorAuditService: Runs crypto audits
    - MinerLeaderboard: Tracks variance-penalized scores
    - Reward computation: Converts audit results to weights

    Typical validator loop:

        audit = AuditIntegration(dendrite, wallet, metagraph)

        while True:
            # Run audit round
            weights = await audit.run_audit_round_and_compute_weights()

            # Set weights on chain
            subtensor.set_weights(...)

            # Wait for next round
            await asyncio.sleep(audit.config.audit_interval_seconds)
    """

    def __init__(
        self,
        dendrite: "bt.Dendrite",
        wallet: "bt.Wallet",
        metagraph: "bt.Metagraph",
        config: Optional[AuditConfig] = None,
        tunnel_interface: Optional[str] = None,
    ):
        """
        Initialize the audit integration.

        Args:
            dendrite: Bittensor dendrite for communication
            wallet: Validator wallet
            metagraph: Network metagraph
            config: Optional configuration
            tunnel_interface: Optional network interface for traffic
        """
        self.dendrite = dendrite
        self.wallet = wallet
        self.metagraph = metagraph
        self.config = config or AuditConfig()
        self.tunnel_interface = tunnel_interface

        # Initialize components
        self.leaderboard = MinerLeaderboard()
        self.audit_service = ValidatorAuditService(
            dendrite=dendrite,
            wallet=wallet,
            leaderboard=self.leaderboard,
            tunnel_interface=tunnel_interface,
        )

        # Initialize L7 audit sender if available
        self._l7_available = False
        self._l7_sender = None
        if self.config.enable_l7_audit:
            try:
                self._l7_sender = L7AuditSender()
                self._l7_available = True
                logger.info("L7 audit sender initialized")
            except Exception as e:
                logger.warning(f"L7 audit not available: {e}")

        # Track audit history
        self._last_audit_time: float = 0
        self._audit_count: int = 0
        self._volume_by_uid: Dict[int, int] = {}

        # Track L7 scores separately
        self._l7_scores: Dict[int, float] = {}

        logger.info(f"AuditIntegration initialized (L7 enabled: {self._l7_available})")

    async def run_audit_round_and_compute_weights(
        self,
        force_graduated: bool = False,
    ) -> Dict[int, float]:
        """
        Run a complete audit round and return Bittensor weights.

        This is the main entry point for validators. It:
        1. Selects miners to audit
        2. Runs cryptographic audits (possibly graduated)
        3. Updates leaderboard with variance-penalized scores
        4. Computes final Bittensor weights

        Args:
            force_graduated: Force graduated throughput testing

        Returns:
            Dict mapping UID to weight (normalized to sum to 1.0)
        """
        start_time = time.time()
        logger.info("Starting audit round")

        # Step 1: Select miners to audit
        targets = await self._select_audit_targets()
        if len(targets) < self.config.min_eligible_miners:
            logger.warning(
                f"Only {len(targets)} miners available, "
                f"need {self.config.min_eligible_miners}"
            )
            # Return existing weights if insufficient miners
            return self._get_current_weights()

        logger.info(f"Selected {len(targets)} miners for audit")

        # Step 2: Decide audit type
        import random
        use_graduated = (
            force_graduated or
            random.random() < self.config.graduated_audit_probability
        )

        # Step 3: Run audits (with L7 if enabled)
        combined_results = []
        if use_graduated:
            logger.info("Running graduated throughput audit")
            l34_results = await self._run_graduated_audits(targets)
            # Add L7 to graduated audits
            for i, target in enumerate(targets):
                l7_result = None
                if self._l7_available and random.random() < self.config.l7_audit_probability:
                    l7_result = await self._run_l7_audit_for_target(target)
                    if l7_result:
                        self._l7_scores[target.uid] = l7_result.overall_score
                combined_results.append((l34_results[i] if i < len(l34_results) else None, l7_result))
        else:
            logger.info(f"Running combined L3/L4 + L7 audit (L7 enabled: {self._l7_available})")
            combined_results = await self._run_combined_audits(targets)

        # Extract L3/L4 results for backwards compatibility
        results = [r[0] for r in combined_results if r[0] is not None]

        # Compute combined scores and update leaderboard
        for l34_result, l7_result in combined_results:
            if l34_result and l34_result.success:
                combined_score = self._compute_combined_score(l34_result, l7_result)
                # Update leaderboard with combined score
                self.leaderboard.update_score(
                    uid=l34_result.uid,
                    audit_score=combined_score,
                    hotkey=l34_result.hotkey,
                    throughput_level=l34_result.max_throughput_achieved,
                )

        # Step 4: Process results
        successful_results = [r for r in results if r.success]
        logger.info(
            f"Audit complete: {len(successful_results)}/{len(results)} successful"
        )

        if not successful_results:
            logger.warning("No successful audits, returning existing weights")
            return self._get_current_weights()

        # Step 5: Compute weights
        weights = self._compute_weights_from_results(successful_results)

        # Update state
        self._last_audit_time = time.time()
        self._audit_count += 1

        duration = time.time() - start_time
        logger.info(
            f"Audit round {self._audit_count} complete in {duration:.1f}s, "
            f"computed weights for {len(weights)} miners"
        )

        return weights

    async def _select_audit_targets(self) -> List[AuditTarget]:
        """Select miners to audit based on availability and rotation."""
        targets = []

        # Get all available miners
        for uid in range(self.metagraph.n):
            axon = self.metagraph.axons[uid]
            hotkey = self.metagraph.hotkeys[uid]

            # Skip inactive axons
            if axon.ip == "0.0.0.0" or axon.port == 0:
                continue

            # Ping to check availability and get scrubber IP
            try:
                ping_response = await self._ping_miner(axon)
                if ping_response and ping_response.is_available:
                    # Get scrubber IP from ping response
                    scrubber_ip = self._get_scrubber_ip(ping_response, axon)
                    if scrubber_ip:
                        targets.append(AuditTarget(
                            uid=uid,
                            hotkey=hotkey,
                            scrubber_ip=scrubber_ip,
                            axon=axon,
                        ))
            except Exception as e:
                logger.trace(f"Ping failed UID {uid}: {e}")
                continue

        # Limit to configured number
        if len(targets) > self.config.miners_per_round:
            # Prioritize miners with fewer recent audits
            # (rotation for fairness)
            import random
            random.shuffle(targets)
            targets = targets[:self.config.miners_per_round]

        return targets

    async def _ping_miner(self, axon: bt.AxonInfo) -> Optional[PingSynapse]:
        """Ping miner to check availability."""
        try:
            synapse = PingSynapse()
            response = await self.dendrite.call(
                target_axon=axon,
                synapse=synapse,
                timeout=5.0,
            )
            return response
        except Exception:
            return None

    def _get_scrubber_ip(
        self,
        ping_response: PingSynapse,
        axon: bt.AxonInfo,
    ) -> Optional[str]:
        """Extract scrubber IP from ping response."""
        # Try scrubber config first
        if ping_response.scrubber_config:
            config = ping_response.scrubber_config
            if hasattr(config, 'active_nodes') and config.active_nodes:
                # Return first active node IP
                return config.active_nodes[0]

        # Fall back to axon IP
        return axon.ip if axon.ip != "0.0.0.0" else None

    async def _run_standard_audits(
        self,
        targets: List[AuditTarget],
    ) -> List[AuditRoundResult]:
        """Run standard crypto audits for all targets."""
        return await self.audit_service.run_audit_round(
            targets=targets,
            throughput_level=self.config.default_throughput_level,
            parallel=True,
            timeout=self.config.synapse_timeout,
        )

    async def _run_graduated_audits(
        self,
        targets: List[AuditTarget],
        max_concurrent: int = 64,
    ) -> List[AuditRoundResult]:
        """
        Run graduated throughput audits for all targets in parallel.

        Args:
            targets: List of audit targets
            max_concurrent: Maximum concurrent graduated audits (default 64 to
                           balance parallelism with network load - graduated
                           audits send more traffic than standard)

        Returns:
            List of AuditRoundResult in same order as targets
        """
        if not targets:
            return []

        # Use semaphore to limit concurrent graduated audits
        # Graduated audits are heavier (4 levels each), so we limit concurrency
        semaphore = asyncio.Semaphore(max_concurrent)

        async def audit_with_semaphore(target: AuditTarget) -> AuditRoundResult:
            async with semaphore:
                try:
                    return await self.audit_service.graduated_audit_miner(
                        target=target,
                        max_level=3,
                        timeout=self.config.graduated_timeout,
                    )
                except Exception as e:
                    logger.warning(f"Graduated audit failed for UID {target.uid}: {e}")
                    return AuditRoundResult(
                        uid=target.uid,
                        hotkey=target.hotkey,
                        challenge_id="",
                        error_message=str(e),
                    )

        # Run all graduated audits in parallel (semaphore-limited)
        results = await asyncio.gather(
            *[audit_with_semaphore(t) for t in targets],
            return_exceptions=False  # Exceptions handled in wrapper
        )

        logger.info(f"Graduated audits complete: {len(results)} miners processed in parallel")
        return list(results)

    async def _run_l7_audit_for_target(
        self,
        target: AuditTarget,
        tunnel_interface: Optional[str] = None,
    ) -> Optional[L7AuditResult]:
        """
        Run L7 audit for a single target.

        Sends L7 attack patterns through the WireGuard tunnel and
        verifies the miner's detection/blocking response.

        Args:
            target: Audit target with scrubber IP
            tunnel_interface: WireGuard tunnel interface

        Returns:
            L7AuditResult or None if audit failed
        """
        if not self._l7_available or not self._l7_sender:
            return None

        try:
            # Generate L7 challenge
            challenge = await self._l7_sender.generate_challenge(
                dest_ip=target.scrubber_ip,
                include_slowloris=True,
                include_http_flood=True,
                include_state_exhaustion=True,
                benign_patterns=3,
            )

            # Send L7 traffic through tunnel
            challenge = await self._l7_sender.send_challenge(
                challenge=challenge,
                tunnel_interface=tunnel_interface or self.tunnel_interface,
            )

            # Wait for miner to process
            await asyncio.sleep(2.0)

            # Fetch L7 metrics from miner
            l7_metrics = await self._fetch_l7_metrics_from_miner(target)

            if not l7_metrics:
                logger.trace(f"No L7 metrics from UID {target.uid}")
                return None

            # Verify L7 results
            result = self._l7_sender.verify_results(challenge, l7_metrics)

            # MULTI-MINER: Per-miner L7 results at TRACE level
            logger.trace(
                f"L7 UID {target.uid}: detect={result.detection_score:.1%} "
                f"block={result.blocking_score:.1%}"
            )

            return result

        except Exception as e:
            logger.trace(f"L7 audit exception UID {target.uid}: {e}")
            return None

    async def _fetch_l7_metrics_from_miner(
        self,
        target: AuditTarget,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        """
        Fetch L7 detection metrics from miner's API.

        Args:
            target: Audit target
            timeout: Request timeout

        Returns:
            L7 metrics dict or empty dict on failure
        """
        if not AIOHTTP_AVAILABLE:
            return {}

        # Build miner API URL using axon info
        if not target.axon:
            return {}

        miner_api_base = f"http://{target.axon.ip}:{target.axon.port}"

        try:
            url = f"{miner_api_base}/api/v1/l7/detection-metrics"
            params = {"window_seconds": 120}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=timeout) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logger.trace(f"L7 metrics fetch failed UID {target.uid}: {response.status}")
                        return {}
        except Exception as e:
            logger.trace(f"L7 metrics fetch exception UID {target.uid}: {e}")
            return {}

    async def _run_combined_audits(
        self,
        targets: List[AuditTarget],
        max_concurrent_l7: int = 64,
    ) -> List[Tuple[AuditRoundResult, Optional[L7AuditResult]]]:
        """
        Run combined L3/L4 + L7 audits for all targets in parallel.

        Args:
            targets: List of audit targets
            max_concurrent_l7: Maximum concurrent L7 audits (default 64)

        Returns:
            List of (L34_result, L7_result) tuples.
            L7_result may be None if L7 audit was skipped or failed.
        """
        import random

        if not targets:
            return []

        # Run L3/L4 audits (parallel) - this is already parallelized
        l34_results = await self.audit_service.run_audit_round(
            targets=targets,
            throughput_level=self.config.default_throughput_level,
            parallel=True,
            timeout=self.config.synapse_timeout,
        )

        # Pad L34 results if needed
        l34_results_padded = list(l34_results) + [None] * (len(targets) - len(l34_results))

        # Determine which targets get L7 audits (pre-compute for determinism)
        l7_target_indices = []
        if self._l7_available:
            for i, target in enumerate(targets):
                if random.random() < self.config.l7_audit_probability:
                    l7_target_indices.append(i)

        # Run L7 audits in parallel for selected targets
        semaphore = asyncio.Semaphore(max_concurrent_l7)

        async def run_l7_with_semaphore(target: AuditTarget) -> Optional[L7AuditResult]:
            async with semaphore:
                try:
                    result = await self._run_l7_audit_for_target(target)
                    if result:
                        self._l7_scores[target.uid] = result.overall_score
                    return result
                except Exception as e:
                    logger.trace(f"L7 audit exception UID {target.uid}: {e}")
                    return None

        # Create L7 tasks only for selected targets
        l7_tasks = []
        l7_task_to_index = {}  # Map task index to target index
        for task_idx, target_idx in enumerate(l7_target_indices):
            l7_tasks.append(run_l7_with_semaphore(targets[target_idx]))
            l7_task_to_index[task_idx] = target_idx

        # Run all L7 audits in parallel
        l7_results_raw = []
        if l7_tasks:
            l7_results_raw = await asyncio.gather(*l7_tasks, return_exceptions=True)
            logger.info(f"L7 audits complete: {len(l7_tasks)} miners processed in parallel")

        # Build L7 results map (target_index -> result)
        l7_results_map: Dict[int, Optional[L7AuditResult]] = {}
        for task_idx, result in enumerate(l7_results_raw):
            target_idx = l7_task_to_index[task_idx]
            if isinstance(result, Exception):
                logger.trace(f"L7 audit exception for target {target_idx}: {result}")
                l7_results_map[target_idx] = None
            else:
                l7_results_map[target_idx] = result

        # Combine L3/L4 and L7 results
        results = []
        for i, target in enumerate(targets):
            l34_result = l34_results_padded[i]
            if l34_result is None:
                l34_result = AuditRoundResult(
                    uid=target.uid,
                    hotkey=target.hotkey,
                    challenge_id="",
                    error_message="L3/L4 audit not run",
                )

            l7_result = l7_results_map.get(i, None)
            results.append((l34_result, l7_result))

        return results

    def _compute_combined_score(
        self,
        l34_result: AuditRoundResult,
        l7_result: Optional[L7AuditResult],
    ) -> float:
        """
        Compute combined L3/L4 + L7 score.

        Score breakdown:
        - L3/L4: 80% (packet filtering accuracy)
        - L7: 20% (connection pattern protection)

        If L7 is not available, L3/L4 gets 100% weight.

        Note: Throughput scoring was removed because lightweight audits
        (needed to audit 200+ miners) cannot meaningfully stress-test
        scrubber capacity. Focus is on filtering correctness instead.
        """
        # L3/L4 score
        l34_score = 0.0
        if l34_result.success:
            l34_score = l34_result.accuracy_score

        # L7 score
        l7_score = 0.0
        if l7_result:
            l7_score = l7_result.overall_score

        # Compute weights
        l34_weight = self.config.l34_weight
        l7_weight = self.config.l7_weight

        # If L7 audit not available, L3/L4 gets full weight
        if not l7_result:
            l34_weight = 1.0
            l7_weight = 0.0

        # Compute final score
        final_score = (
            l34_score * l34_weight +
            l7_score * l7_weight
        )

        return max(0.0, min(1.0, final_score))

    def _compute_weights_from_results(
        self,
        results: List[AuditRoundResult],
    ) -> Dict[int, float]:
        """
        Compute Bittensor weights from audit results.

        Formula: weight = 0.7 * normalized_volume + 0.3 * ema_audit_score

        Where ema_audit_score includes:
        - Base accuracy from verified proofs
        - Variance penalty for inconsistent performance
        - Verification rate bonus
        """
        # Get all UIDs
        all_uids = list(range(self.metagraph.n))

        # Volumes (from TPM or tracking)
        volumes = self._volume_by_uid.copy()

        # Compute weights using leaderboard
        weights = compute_bittensor_weights(
            leaderboard=self.leaderboard,
            active_miners=volumes,
            all_uids=all_uids,
        )

        return weights

    def _get_current_weights(self) -> Dict[int, float]:
        """Get current weights based on leaderboard state."""
        all_uids = list(range(self.metagraph.n))
        return compute_bittensor_weights(
            leaderboard=self.leaderboard,
            active_miners=self._volume_by_uid,
            all_uids=all_uids,
        )

    def update_volume(self, uid: int, volume: int) -> None:
        """Update volume tracking for a miner."""
        self._volume_by_uid[uid] = volume

    def get_leaderboard_stats(self) -> Dict[str, Any]:
        """Get leaderboard statistics for monitoring."""
        ranking = self.leaderboard.get_ranking()

        return {
            "total_miners": len(ranking),
            "eligible_miners": self.leaderboard.count_eligible(),
            "audit_count": self._audit_count,
            "last_audit_time": self._last_audit_time,
            "l7_enabled": self._l7_available,
            "l7_scores_tracked": len(self._l7_scores),
            "top_5": [
                {
                    "uid": e.uid,
                    "final_score": e.final_score,
                    "ema_score": e.ema_score,
                    "variance": e.ema_variance,
                    "stability": e.get_stability_factor(),
                    "throughput_level": e.max_throughput_level,
                    "audit_count": e.audit_count,
                    "l7_score": self._l7_scores.get(e.uid, None),
                }
                for e in ranking[:5]
            ],
        }

    def get_miner_details(self, uid: int) -> Dict[str, Any]:
        """Get detailed stats for a specific miner."""
        return self.leaderboard.get_detailed_stats(uid)


# Convenience factory
def create_audit_integration(
    dendrite: "bt.Dendrite",
    wallet: "bt.Wallet",
    metagraph: "bt.Metagraph",
    audit_interval: int = 300,
    miners_per_round: int = 10,
) -> AuditIntegration:
    """
    Create an AuditIntegration instance with common settings.

    Args:
        dendrite: Bittensor dendrite
        wallet: Validator wallet
        metagraph: Network metagraph
        audit_interval: Seconds between audit rounds
        miners_per_round: Miners to audit per round

    Returns:
        Configured AuditIntegration instance
    """
    config = AuditConfig(
        audit_interval_seconds=audit_interval,
        miners_per_round=miners_per_round,
    )

    return AuditIntegration(
        dendrite=dendrite,
        wallet=wallet,
        metagraph=metagraph,
        config=config,
    )


__all__ = [
    "AuditIntegration",
    "AuditConfig",
    "create_audit_integration",
]
