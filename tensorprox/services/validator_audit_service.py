"""
Validator Audit Service.

Orchestrates the audit flow:
1. Generate test traffic packets
2. Send traffic to scrubber via WireGuard tunnel
3. Query miner for XDP stats
4. Compute accuracy based on stats delta
5. Update leaderboard with scores
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from loguru import logger
import bittensor as bt

from tensorprox.base.protocol import (
    AuditSynapse,
    GraduatedAuditSynapse,
)
from tensorprox.services.audit import (
    AuditSender,
    AuditChallenge,
    AuditResult,
    GraduatedThroughputAuditor,
    AttackCategory,
    ExpectedAction,
)
from tensorprox.rewards.leaderboard import MinerLeaderboard


@dataclass
class AuditTarget:
    """Information about a miner being audited."""
    uid: int
    hotkey: str
    scrubber_ip: str
    axon: Optional[bt.AxonInfo] = None


@dataclass
class AuditRoundResult:
    """Complete result of an audit round for one miner."""
    uid: int
    hotkey: str
    challenge_id: str

    # Packet counts
    total_packets_sent: int = 0

    # Correctness scores
    accuracy_score: float = 0.0
    false_positive_rate: float = 0.0

    # Per-category results
    category_coverage: Dict[str, float] = field(default_factory=dict)

    # Throughput metrics
    throughput_level: int = 0
    max_throughput_achieved: int = 0
    throughput_score: float = 0.0

    # Timing
    audit_duration_seconds: float = 0.0

    # Status
    success: bool = False
    error_message: Optional[str] = None

    def get_final_audit_score(self) -> float:
        """
        Compute final audit score for leaderboard update.

        Simple formula: score = accuracy_score

        Just the accuracy score from the audit - no bonuses or multipliers.
        """
        if not self.success:
            return 0.0

        return min(1.0, max(0.0, self.accuracy_score))


class ValidatorAuditService:
    """
    Orchestrates cryptographic audits for validators.

    Usage:
        service = ValidatorAuditService(dendrite, wallet)

        # Run audit for single miner
        result = await service.audit_miner(target)

        # Run graduated throughput test
        result = await service.graduated_audit_miner(target, max_level=3)

        # Run audit round for multiple miners
        results = await service.run_audit_round(targets)
    """

    def __init__(
        self,
        dendrite: "bt.Dendrite",
        wallet: "bt.Wallet",
        leaderboard: Optional[MinerLeaderboard] = None,
        tunnel_interface: Optional[str] = None,
    ):
        """
        Initialize the audit service.

        Args:
            dendrite: Bittensor dendrite for communication
            wallet: Validator wallet
            leaderboard: Optional leaderboard for score updates
            tunnel_interface: Optional network interface for traffic
        """
        self.dendrite = dendrite
        self.wallet = wallet
        self.leaderboard = leaderboard
        self.tunnel_interface = tunnel_interface

        # Initialize crypto audit components
        self.audit_sender = AuditSender()
        self.throughput_auditor = GraduatedThroughputAuditor()

        # Track active audits
        self._active_audits: Dict[str, AuditChallenge] = {}

    async def audit_miner(
        self,
        target: AuditTarget,
        throughput_level: int = 1,
        timeout: float = 60.0,
    ) -> AuditRoundResult:
        """
        Run a single cryptographic audit for one miner.

        Args:
            target: Miner to audit
            throughput_level: Traffic intensity (0-3)
            timeout: Synapse timeout in seconds

        Returns:
            AuditRoundResult with verification data
        """
        result = AuditRoundResult(
            uid=target.uid,
            hotkey=target.hotkey,
            challenge_id="",
        )

        try:
            # Generate challenge with test packets
            logger.trace(f"Audit starting for UID {target.uid}")
            start_time = time.time()

            challenge = await self.audit_sender.generate_challenge(
                dest_ip=target.scrubber_ip,
                throughput_level=throughput_level,
            )

            result.challenge_id = challenge.challenge_id
            result.total_packets_sent = len(challenge.packets)
            result.throughput_level = throughput_level

            # Store for tracking
            self._active_audits[challenge.challenge_id] = challenge

            # Notify miner that audit is starting
            logger.trace(f"Notifying UID {target.uid} of audit start")
            start_response = await self._send_audit_start(
                target, challenge, timeout
            )

            if not start_response or not start_response.success:
                result.error_message = "Miner failed to acknowledge audit start"
                logger.trace(f"UID {target.uid} failed to acknowledge audit")
                return result

            # Send traffic through tunnel
            logger.trace(f"Sending {len(challenge.packets)} packets to UID {target.uid}")
            challenge = await self.audit_sender.send_challenge(
                challenge,
                tunnel_interface=self.tunnel_interface,
            )

            # Brief wait for XDP processing
            await asyncio.sleep(0.5)

            # Collect XDP stats from miner
            logger.trace(f"Collecting stats from UID {target.uid}")
            stats_response = await self._send_audit_collect(
                target, challenge, timeout
            )

            if not stats_response or not stats_response.success:
                result.error_message = "Miner failed to return stats"
                logger.trace(f"UID {target.uid} failed to return stats")
                return result

            # ANTI-GAMING: Check if miner reported counter reset
            # This is in addition to our own detection in _compute_accuracy_from_stats
            miner_reported_reset = stats_response.reported_blocked.get("counter_reset_detected", 0)
            if miner_reported_reset:
                logger.warning(
                    f"UID {target.uid}: miner self-reported counter reset, "
                    f"this indicates XDP program was reloaded during audit"
                )

            # Compute accuracy based on XDP stats delta
            accuracy = self._compute_accuracy_from_stats(
                challenge, stats_response.stats_delta
            )

            # Populate result
            result.accuracy_score = accuracy
            result.false_positive_rate = 0.0  # Computed from stats if available
            result.max_throughput_achieved = throughput_level
            result.audit_duration_seconds = time.time() - start_time
            result.success = True

            logger.trace(f"UID {target.uid} audit: acc={result.accuracy_score:.1%}")

            # Update leaderboard if available
            if self.leaderboard:
                final_score = result.get_final_audit_score()
                self.leaderboard.update_score(
                    uid=target.uid,
                    audit_score=final_score,
                    hotkey=target.hotkey,
                    throughput_level=result.max_throughput_achieved,
                )

        except Exception as e:
            result.error_message = str(e)
            logger.trace(f"Audit exception UID {target.uid}: {e}")

        finally:
            # Cleanup
            if result.challenge_id in self._active_audits:
                del self._active_audits[result.challenge_id]

        return result

    async def graduated_audit_miner(
        self,
        target: AuditTarget,
        max_level: int = 3,
        timeout: float = 120.0,
    ) -> AuditRoundResult:
        """
        Run graduated throughput audit for one miner.

        Tests progressively higher traffic levels to find:
        - Maximum sustainable throughput
        - Accuracy degradation curve
        - Breaking point

        Args:
            target: Miner to audit
            max_level: Maximum throughput level to test (0-3)
            timeout: Total timeout for all levels

        Returns:
            AuditRoundResult with throughput metrics
        """
        result = AuditRoundResult(
            uid=target.uid,
            hotkey=target.hotkey,
            challenge_id=f"graduated-{int(time.time())}",
        )

        try:
            logger.info(
                f"Starting graduated audit for UID {target.uid}, max_level={max_level}"
            )
            start_time = time.time()

            level_results = []
            max_achieved = 0

            for level in range(max_level + 1):
                # Run single audit at this level
                level_result = await self.audit_miner(
                    target,
                    throughput_level=level,
                    timeout=timeout / (max_level + 1),
                )

                level_results.append({
                    "level": level,
                    "accuracy": level_result.accuracy_score,
                    "packets_sent": level_result.total_packets_sent,
                })

                if level_result.accuracy_score >= 0.5:
                    max_achieved = level
                else:
                    # Accuracy dropped below threshold, stop
                    logger.info(
                        f"UID {target.uid} accuracy dropped at level {level}, stopping"
                    )
                    break

                # Brief pause between levels
                await asyncio.sleep(1.0)

            # Compute throughput score
            result.throughput_score = self._compute_throughput_score(level_results)
            result.max_throughput_achieved = max_achieved
            result.audit_duration_seconds = time.time() - start_time

            # Use last successful level's metrics
            if level_results:
                last_good = level_results[max_achieved]
                result.accuracy_score = last_good["accuracy"]
                result.total_packets_sent = sum(r["packets_sent"] for r in level_results)

            result.success = True

            logger.info(
                f"UID {target.uid} graduated audit complete: "
                f"max_level={max_achieved}, throughput_score={result.throughput_score:.3f}"
            )

            # Update leaderboard
            if self.leaderboard:
                final_score = result.get_final_audit_score()
                self.leaderboard.update_score(
                    uid=target.uid,
                    audit_score=final_score,
                    hotkey=target.hotkey,
                    throughput_level=max_achieved,
                )

        except Exception as e:
            result.error_message = str(e)
            logger.error(f"Graduated audit failed for UID {target.uid}: {e}")

        return result

    async def run_audit_round(
        self,
        targets: List[AuditTarget],
        throughput_level: int = 1,
        parallel: bool = True,
        timeout: float = 60.0,
    ) -> List[AuditRoundResult]:
        """
        Run audit round for multiple miners.

        Args:
            targets: List of miners to audit
            throughput_level: Traffic intensity (0-3)
            parallel: Run audits in parallel (vs sequential)
            timeout: Per-miner timeout

        Returns:
            List of AuditRoundResult for each miner
        """
        target_uids = [t.uid for t in targets]
        logger.info(f"Starting crypto audit round: {len(targets)} miners UIDs={target_uids[:10]}{'...' if len(target_uids) > 10 else ''}")

        if parallel:
            # Run all audits concurrently
            tasks = [
                self.audit_miner(target, throughput_level, timeout)
                for target in targets
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Convert exceptions to failed results
            final_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    final_results.append(AuditRoundResult(
                        uid=targets[i].uid,
                        hotkey=targets[i].hotkey,
                        challenge_id="",
                        error_message=str(result),
                    ))
                else:
                    final_results.append(result)
        else:
            # Run sequentially
            final_results = []
            for target in targets:
                result = await self.audit_miner(target, throughput_level, timeout)
                final_results.append(result)

        # MULTI-MINER: Aggregated summary logging
        successful = [r for r in final_results if r.success]
        failed = [r for r in final_results if not r.success]
        if successful:
            avg_accuracy = sum(r.accuracy_score for r in successful) / len(successful)
            logger.info(
                f"Crypto audit complete: {len(successful)}/{len(final_results)} success, "
                f"avg_accuracy={avg_accuracy:.1%}"
            )
        if failed:
            failed_uids = [r.uid for r in failed]
            logger.warning(f"Crypto audit failures ({len(failed)}): UIDs={failed_uids[:10]}{'...' if len(failed_uids) > 10 else ''}")

        return final_results

    async def _send_audit_start(
        self,
        target: AuditTarget,
        challenge: AuditChallenge,
        timeout: float,
    ) -> Optional[AuditSynapse]:
        """Notify miner that audit is starting."""
        try:
            synapse = AuditSynapse(
                challenge_id=challenge.challenge_id,
                phase="start",
                scrubber_ip=target.scrubber_ip,
                expected_duration_seconds=30,
                throughput_level=challenge.throughput_level,
            )

            response = await self.dendrite.call(
                target_axon=target.axon,
                synapse=synapse,
                timeout=timeout,
            )

            return response

        except Exception as e:
            logger.trace(f"Audit start exception UID {target.uid}: {e}")
            return None

    async def _send_audit_collect(
        self,
        target: AuditTarget,
        challenge: AuditChallenge,
        timeout: float,
    ) -> Optional[AuditSynapse]:
        """Collect XDP stats from miner after traffic sent."""
        try:
            synapse = AuditSynapse(
                challenge_id=challenge.challenge_id,
                phase="collect",
                scrubber_ip=target.scrubber_ip,
            )

            response = await self.dendrite.call(
                target_axon=target.axon,
                synapse=synapse,
                timeout=timeout,
            )

            return response

        except Exception as e:
            logger.error(f"Stats collection failed for UID {target.uid}: {e}")
            return None

    # === CATEGORY WEIGHTS FOR SCORING (must sum to 1.0) ===
    # Split into SIGNATURE-BASED (percentage scoring) and RATE-LIMIT (binary scoring)
    #
    # Signature-based (60%): All matching packets should be blocked - score by % blocked
    # Rate-limit (40%): Only excess traffic blocked - binary (did it trigger?)
    CATEGORY_WEIGHTS = {
        # Signature-based categories (60% total)
        AttackCategory.BOGON: 0.10,           # Bogon source IPs
        AttackCategory.BLACKLIST: 0.05,       # Known malicious IPs
        AttackCategory.TCP_FLAG_ANOMALY: 0.15, # XMAS, NULL, SYN+FIN, etc.
        AttackCategory.UDP_AMPLIFICATION: 0.12, # DNS, NTP, SSDP, etc.
        AttackCategory.FRAGMENTATION: 0.08,    # Fragment attacks
        AttackCategory.MALFORMED: 0.05,        # Invalid headers
        AttackCategory.LAND_ATTACK: 0.05,      # Source == Dest IP

        # Rate-limit categories (40% total) - binary scoring
        AttackCategory.SYN_FLOOD: 0.15,        # SYN flood rate limiting
        AttackCategory.UDP_FLOOD: 0.10,        # UDP flood rate limiting
        AttackCategory.ICMP_FLOOD: 0.05,       # ICMP flood rate limiting
        AttackCategory.L7_APPLICATION: 0.10,   # Slowloris, HTTP flood
    }

    # Categories that use rate-limit (binary) scoring instead of percentage
    RATELIMIT_CATEGORIES = {
        AttackCategory.SYN_FLOOD,
        AttackCategory.UDP_FLOOD,
        AttackCategory.ICMP_FLOOD,
        AttackCategory.L7_APPLICATION,
    }

    # Minimum block rate to consider rate limiting "triggered"
    # Prevents gaming by blocking just 1-2 packets
    # 25% means: if we send 100 flood packets, miner must block at least 25
    RATE_LIMIT_MIN_BLOCK_RATE = 0.25

    def _compute_accuracy_from_stats(
        self,
        challenge: AuditChallenge,
        stats_delta: Dict[str, int],
    ) -> float:
        """
        Compute accuracy score from XDP stats delta using PER-CATEGORY WEIGHTED SCORING.

        Simple and fair scoring:
        1. Map XDP stats to attack categories
        2. For each category the validator sent packets for:
           - Signature-based: score = blocked / sent (percentage)
           - Rate-limit: score = 1.0 if triggered (≥25% blocked), else 0.0
        3. Apply category weights and sum
        4. Add false positive scoring (don't block benign traffic)

        Category Weights (sum to 1.0):
        - Signature-based (60%): BOGON, BLACKLIST, TCP_FLAG, UDP_AMP, FRAG, MALFORMED, LAND
        - Rate-limit (40%): SYN_FLOOD, UDP_FLOOD, ICMP_FLOOD, L7_APPLICATION

        Anti-gaming measures:
        - Detects negative counter deltas (indicates counter reset = cheating)
        - Validates tunnel was actually receiving traffic
        """
        if not stats_delta:
            return 0.0

        # ANTI-GAMING: Check for counter resets (negative deltas indicate tampering)
        counter_reset_detected = False
        for key, value in stats_delta.items():
            if isinstance(value, int) and value < 0:
                logger.warning(
                    f"Counter reset detected: {key}={value} (negative delta indicates tampering)"
                )
                counter_reset_detected = True
                break

        if counter_reset_detected:
            logger.warning(
                f"Audit challenge={challenge.challenge_id}: counter reset detected, "
                f"penalizing miner with 0.0 score"
            )
            return 0.0

        # === STEP 1: Count packets sent per category from challenge ===
        category_sent: Dict[AttackCategory, int] = {}
        benign_sent = 0

        for pkt in challenge.packets:
            if pkt.category == AttackCategory.BENIGN:
                benign_sent += 1
            elif pkt.category == AttackCategory.SPOOFED_PUBLIC:
                pass  # Undetectable, don't score
            else:
                category_sent[pkt.category] = category_sent.get(pkt.category, 0) + 1

        # === STEP 2: Map XDP stats to category blocked counts ===
        category_blocked: Dict[AttackCategory, int] = {}

        # BOGON - bogon source IPs
        category_blocked[AttackCategory.BOGON] = (
            stats_delta.get("xdp_drop_bogon", 0) +
            stats_delta.get("xdp_drop_invalid_ip", 0)
        )

        # BLACKLIST - known malicious IPs
        category_blocked[AttackCategory.BLACKLIST] = (
            stats_delta.get("xdp_drop_blacklist", 0) +
            stats_delta.get("xdp_drop_temp_blacklist", 0) +
            stats_delta.get("xdp_drop_quarantine", 0)
        )

        # TCP_FLAG_ANOMALY - invalid TCP flag combinations
        category_blocked[AttackCategory.TCP_FLAG_ANOMALY] = (
            stats_delta.get("xdp_drop_tcp_xmas", 0) +
            stats_delta.get("xdp_drop_tcp_null", 0) +
            stats_delta.get("xdp_drop_tcp_synfin", 0) +
            stats_delta.get("xdp_drop_tcp_synrst", 0) +
            stats_delta.get("xdp_drop_tcp_fin", 0) +
            stats_delta.get("xdp_drop_tcp_rst", 0) +
            stats_delta.get("xdp_drop_tcp_ack", 0) +
            stats_delta.get("xdp_drop_invalid_tcp", 0)
        )

        # UDP_AMPLIFICATION - DNS, NTP, SSDP, etc.
        category_blocked[AttackCategory.UDP_AMPLIFICATION] = (
            stats_delta.get("xdp_drop_udp_amp", 0)
        )

        # FRAGMENTATION - fragment attacks
        category_blocked[AttackCategory.FRAGMENTATION] = (
            stats_delta.get("xdp_drop_frag", 0)
        )

        # MALFORMED - invalid headers
        category_blocked[AttackCategory.MALFORMED] = (
            stats_delta.get("xdp_drop_malformed", 0)
        )

        # LAND_ATTACK - source == dest IP
        category_blocked[AttackCategory.LAND_ATTACK] = (
            stats_delta.get("xdp_drop_land", 0)
        )

        # SYN_FLOOD - rate-limited SYN packets
        category_blocked[AttackCategory.SYN_FLOOD] = (
            stats_delta.get("xdp_drop_syn_flood", 0) +
            stats_delta.get("xdp_syncookie_challenge", 0)  # SYN cookies count
        )

        # UDP_FLOOD - rate-limited UDP packets
        category_blocked[AttackCategory.UDP_FLOOD] = (
            stats_delta.get("xdp_drop_udp_flood", 0)
        )

        # ICMP_FLOOD - rate-limited ICMP packets
        category_blocked[AttackCategory.ICMP_FLOOD] = (
            stats_delta.get("xdp_drop_icmp_flood", 0)
        )

        # L7_APPLICATION - Slowloris + HTTP flood
        category_blocked[AttackCategory.L7_APPLICATION] = (
            stats_delta.get("xdp_drop_slowloris", 0) +
            stats_delta.get("xdp_drop_http_flood", 0)
        )

        # === STEP 3: Compute per-category scores (simple weighted average) ===
        total_weighted_score = 0.0
        total_weight_used = 0.0

        for category, weight in self.CATEGORY_WEIGHTS.items():
            sent = category_sent.get(category, 0)
            blocked = category_blocked.get(category, 0)

            if sent == 0:
                # Validator didn't send packets for this category - skip it
                # Don't penalize miner for categories not tested
                continue

            if category in self.RATELIMIT_CATEGORIES:
                # === RATE-LIMIT SCORING (binary with threshold) ===
                # Rate limiting allows some traffic through, blocks excess.
                # To prevent gaming (block 1 packet, pass 99), require minimum block rate.
                # BINARY: >= 25% blocked = 1.0, < 25% blocked = 0.0
                block_rate = blocked / sent
                if block_rate >= self.RATE_LIMIT_MIN_BLOCK_RATE:
                    category_score = 1.0  # Rate limiting working - full credit
                else:
                    category_score = 0.0  # Rate limiting not effective - no credit
            else:
                # === SIGNATURE-BASED SCORING (percentage of attacks blocked) ===
                # All matching packets should be blocked
                category_score = min(1.0, blocked / sent)

            total_weighted_score += category_score * weight
            total_weight_used += weight

            logger.debug(
                f"  {category.value}: {blocked}/{sent} ({category_score*100:.1f}%) "
                f"weight={weight:.2f}"
            )

        # Normalize by weights actually used (in case some categories weren't tested)
        if total_weight_used > 0:
            attack_coverage_score = total_weighted_score / total_weight_used
        else:
            attack_coverage_score = 0.0

        # === STEP 4: Compute false positive score ===
        reported_passes = stats_delta.get("xdp_pass", 0)
        if benign_sent > 0:
            # How many benign packets passed through?
            benign_passed = min(reported_passes, benign_sent)
            pass_rate = benign_passed / benign_sent
            fp_score = pass_rate  # Simple: 100% pass = 1.0, 0% pass = 0.0
        else:
            fp_score = 1.0  # No benign traffic sent, no FP penalty

        # === STEP 5: Compute final score ===
        # Attack blocking (70%) + Don't block benign (30%)
        final_accuracy = 0.7 * attack_coverage_score + 0.3 * fp_score

        # === STEP 6: Apply anti-gaming penalty for tunnel liveness ===
        total_drops = sum(category_blocked.values())
        total_reported = total_drops + reported_passes
        total_sent = sum(category_sent.values()) + benign_sent

        if total_reported == 0:
            logger.warning(
                f"Audit challenge={challenge.challenge_id}: miner reported 0 packets "
                f"(expected {total_sent}), tunnel may not be active"
            )
            return 0.0

        traffic_ratio = total_reported / max(1, total_sent)
        if traffic_ratio < 0.3:
            logger.warning(
                f"Audit challenge={challenge.challenge_id}: low traffic ratio "
                f"({traffic_ratio:.1%}), expected {total_sent}, got {total_reported}"
            )
            traffic_penalty = traffic_ratio / 0.3
            final_accuracy *= traffic_penalty

        logger.info(
            f"Audit score: attack={attack_coverage_score:.3f}, fp={fp_score:.3f}, "
            f"final={final_accuracy:.3f}"
        )

        return min(1.0, max(0.0, final_accuracy))

    def _compute_throughput_score(
        self,
        level_results: List[Dict],
    ) -> float:
        """
        Compute throughput score from graduated results.

        Weights higher levels more heavily:
        - Level 0: 10%
        - Level 1: 20%
        - Level 2: 30%
        - Level 3: 40%
        """
        if not level_results:
            return 0.0

        weights = [0.1, 0.2, 0.3, 0.4]
        total_weight = 0.0
        weighted_score = 0.0

        for result in level_results:
            level = result.get("level", 0)
            accuracy = result.get("accuracy", 0.0)

            if level < len(weights):
                weight = weights[level]
                total_weight += weight
                weighted_score += weight * accuracy

        if total_weight > 0:
            return weighted_score / total_weight

        return 0.0


# Factory function for easy instantiation
def create_audit_service(
    dendrite: "bt.Dendrite",
    wallet: "bt.Wallet",
    leaderboard: Optional[MinerLeaderboard] = None,
) -> ValidatorAuditService:
    """Create a new ValidatorAuditService instance."""
    return ValidatorAuditService(
        dendrite=dendrite,
        wallet=wallet,
        leaderboard=leaderboard,
    )


__all__ = [
    "ValidatorAuditService",
    "AuditTarget",
    "AuditRoundResult",
    "create_audit_service",
]
