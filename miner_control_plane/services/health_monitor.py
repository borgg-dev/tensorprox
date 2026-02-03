"""
Health Monitor Service - Context-Aware Automated Failover Detection

Monitors scrubber health via heartbeat tracking and triggers failover when
a scrubber is confirmed dead. Uses pattern-based detection with active probing
to minimize false positives.

DETECTION FLOW
================================================================================
The monitor runs a continuous loop (1s interval) checking each shard:

    1. HEARTBEAT CHECK (continuous)
        - ecp-agent on scrubber sends heartbeat every 5 seconds
        - Stored in-memory: _heartbeat_tracker[node_id] = timestamp
        - Expected max delay: 6 seconds (5s interval + 1s tolerance)

    2. SUSPICIOUS STATE (heartbeat > 6s late)
        - Triggers rapid probing sequence
        - Does NOT immediately failover

    3. RAPID PROBING (3 attempts, 0.5s each)
        - TCP connection to scrubber port 22
        - If ANY probe succeeds → node alive, no failover
        - If ALL 3 fail → CONFIRMED DEAD

    4. FAILOVER TRIGGER
        - Calls POST /api/v1/admin/shards/<shard_id>/failover
        - Only if standby is available
        - Respects cooldown period (30s between failovers)

DETECTION TIMELINE
================================================================================
    t=0.0s    Scrubber dies
    t=5.0s    Expected heartbeat missing
    t=6.0s    Monitor detects late heartbeat (>6s) → SUSPICIOUS
    t=6.5s    Rapid probe #1 fails
    t=7.0s    Rapid probe #2 fails
    t=7.5s    Rapid probe #3 fails → CONFIRMED DEAD
    t=7.5s    Failover triggered (calls admin.py)
    ─────────────────────────────────────────────────
    Total detection time: ~7.5 seconds

TIMING PARAMETERS
================================================================================
    HEARTBEAT_INTERVAL = 5        ecp-agent report frequency (seconds)
    HEARTBEAT_TOLERANCE = 1       Grace period before suspicious (seconds)
    MONITOR_INTERVAL = 1          Health check loop frequency (seconds)
    RAPID_PROBE_INTERVAL = 0.5    Probe attempt interval (seconds)
    RAPID_PROBE_TIMEOUT = 0.5     TCP connection timeout (seconds)
    PROBES_BEFORE_FAILOVER = 3    Required consecutive failures
    FAILOVER_COOLDOWN = 30        Min time between failovers (seconds)
    BOOTSTRAP_GRACE_PERIOD = 45   Extra tolerance for new nodes (seconds)

CLASSES
================================================================================
    NodeState (Enum)
        HEALTHY, DEGRADED, UNRESPONSIVE, NO_HEALTH_DATA, PROBING

    NodeHealth (dataclass)
        Per-node health tracking with heartbeat history
        Methods: record_heartbeat(), record_miss(), get_heartbeat_rate()

    HealthMonitor
        Main monitoring class, singleton instance

KEY METHODS
================================================================================
    HealthMonitor.monitor_loop()
        Background thread entry point, runs every MONITOR_INTERVAL

    HealthMonitor.check_active_scrubber_health()
        Main health check: iterates shards, checks heartbeats, triggers probes

    HealthMonitor._check_shard_health(row, cur, db)
        Per-shard health evaluation:
        - Get active node's last heartbeat
        - Check critical conditions (memory > 90%, BPF not loaded)
        - Trigger rapid probing if suspicious

    HealthMonitor.perform_rapid_probing(node_ip, node_id)
        Execute 3 TCP probes to confirm node death
        Returns: True if all probes fail (node dead)

    HealthMonitor.rapid_probe(node_ip, node_id)
        Single TCP probe attempt to port 22
        Returns: True if connection succeeds

    HealthMonitor.execute_failover(reason, shard_id, metrics)
        HTTP POST to /api/v1/admin/shards/<shard_id>/failover
        Called when node confirmed dead and standby available

    HealthMonitor.attempt_bpf_recovery(scrubber_ip)
        Try to reload XDP program via SSH before failing over
        Returns: True if recovery succeeded

THREAD SAFETY
================================================================================
    - _heartbeat_tracker protected by _heartbeat_lock
    - State reads are eventually consistent (30s sync interval)
    - Failover endpoint is idempotent (cooldown prevents thrashing)

FAILURE CONDITIONS (no failover triggered)
================================================================================
    - No standby node available
    - Within bootstrap grace period (new deployment)
    - Failover cooldown active (recent failover)
    - Probe succeeds (node alive, just heartbeat delayed)
    - No origins configured (nothing to protect)

RELATED FILES
================================================================================
    - admin.py: Failover execution (called via HTTP POST)
    - health.py: Heartbeat ingestion endpoint (updates _heartbeat_tracker)
    - state_manager.py: Shard state and node registry
    - ecp-agent.py: Scrubber-side heartbeat sender
"""
import logging
import threading
import time
import subprocess
import requests
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

import psycopg2.extras
from shared.database import get_db_connection
from shared.utils.ssh import ssh_exec
from shared.utils.logging import log_rate_limited
from shared.config import get_settings
from shared.utils.failover_protection import get_failover_protection, CascadeState
from miner_control_plane.services.miner_identity import miner_identity
from miner_control_plane.services.state_manager import state_manager
from miner_control_plane.api.health import get_last_heartbeat

logger = logging.getLogger('health-monitor')


class NodeState(Enum):
    """Scrubber health states for context-aware monitoring."""
    UNKNOWN = "unknown"          # No data yet
    HEALTHY = "healthy"          # Regular heartbeats arriving
    DEGRADED = "degraded"        # Missed some heartbeats
    PROBING = "probing"          # Actively probing to confirm status
    UNRESPONSIVE = "unresponsive"  # Confirmed dead


@dataclass
class NodeHealth:
    """Track health state for a single node."""
    node_id: str
    state: NodeState = NodeState.UNKNOWN
    consecutive_misses: int = 0
    last_heartbeat: float = 0.0
    heartbeat_history: List[float] = field(default_factory=list)
    last_probe_time: float = 0.0
    last_probe_result: Optional[bool] = None
    state_changed_at: float = field(default_factory=time.time)

    def record_heartbeat(self):
        """Record a successful heartbeat arrival."""
        now = time.time()
        self.last_heartbeat = now
        self.consecutive_misses = 0
        self.heartbeat_history.append(now)
        # Keep only last 60 seconds of history
        cutoff = now - 60
        self.heartbeat_history = [t for t in self.heartbeat_history if t > cutoff]

        if self.state != NodeState.HEALTHY:
            logger.info(f"Node {self.node_id} transitioned to HEALTHY (was {self.state.value})")
            self.state = NodeState.HEALTHY
            self.state_changed_at = now

    def record_miss(self):
        """Record a missed heartbeat interval."""
        self.consecutive_misses += 1

    def get_heartbeat_rate(self, window_seconds: int = 30) -> float:
        """Calculate heartbeat rate (heartbeats per second) over window."""
        now = time.time()
        cutoff = now - window_seconds
        recent = [t for t in self.heartbeat_history if t > cutoff]
        if len(recent) < 2:
            return 0.0
        return len(recent) / window_seconds


class HealthMonitor:
    """
    Context-aware health monitor with FAST failover logic.

    Key features:
    - Monitors every 1s for rapid detection
    - On suspicious (heartbeat late by >1s tolerance): rapid SSH probing
    - 3 consecutive probe failures at 0.5s interval → FAILOVER
    - Total detection time: ~5-7.5 seconds

    Timeline for actual node death:
    - t=0s:   Last heartbeat, node dies
    - t=5s:   Expected heartbeat doesn't arrive
    - t=6s:   Monitor detects late heartbeat → SUSPICIOUS
    - t=6.5s: Rapid probe #1 fails
    - t=7.0s: Rapid probe #2 fails
    - t=7.5s: Rapid probe #3 fails → FAILOVER
    """

    # Configuration - Fast failover detection
    HEARTBEAT_INTERVAL = 5          # Expected interval between heartbeats (seconds)
    MONITOR_INTERVAL = 1            # Check every 1 second (faster than heartbeat)
    HEARTBEAT_TOLERANCE = 1         # Seconds of tolerance before suspicious

    # Rapid probing (when heartbeat is late)
    RAPID_PROBE_INTERVAL = 0.5      # Probe every 0.5s when suspicious
    RAPID_PROBE_TIMEOUT = 0.5       # Short timeout for rapid probes
    RAPID_PROBES_BEFORE_FAILOVER = 3  # 3 consecutive failures = failover

    # Bootstrap grace period
    BOOTSTRAP_GRACE_PERIOD = 45     # Extra tolerance for newly deployed nodes

    # Failover settings
    FAILOVER_COOLDOWN = 30          # 30 seconds between failovers (fast recovery)

    def __init__(self):
        self.settings = get_settings()
        self.last_failover = 0
        self.node_health: Dict[str, NodeHealth] = {}
        self.issue_history = defaultdict(list)
        self.rapid_probe_failures: Dict[str, int] = {}  # Track rapid probe failures per node

    def get_or_create_node_health(self, node_id: str) -> NodeHealth:
        """Get or create health tracking for a node."""
        if node_id not in self.node_health:
            self.node_health[node_id] = NodeHealth(node_id=node_id)
        return self.node_health[node_id]

    def update_heartbeat_tracking(self, active_node_id: str, last_seen: float) -> NodeHealth:
        """
        Update heartbeat tracking for the active node.

        Args:
            active_node_id: Instance ID of the active scrubber
            last_seen: Timestamp of last health report

        Returns:
            Updated NodeHealth object
        """
        node = self.get_or_create_node_health(active_node_id)
        now = time.time()

        # Check if we received a new heartbeat since last check
        if last_seen > node.last_heartbeat:
            node.record_heartbeat()
        else:
            # No new heartbeat - check if we should count this as a miss
            time_since_last = now - node.last_heartbeat
            expected_heartbeats = int(time_since_last / self.HEARTBEAT_INTERVAL)

            if expected_heartbeats > node.consecutive_misses:
                # We've missed more heartbeats than we've counted
                missed_count = expected_heartbeats - node.consecutive_misses
                for _ in range(missed_count):
                    node.record_miss()

        return node

    def rapid_probe(self, node_ip: str, node_id: str) -> bool:
        """
        Fast probe for rapid failover detection.

        Uses TCP connection to SSH port (22) with short timeout.
        TCP is more reliable than ICMP for detecting instance shutdown
        (SSH service stops before ICMP becomes unresponsive).

        Returns:
            True if node is responsive, False if unresponsive
        """
        import socket
        try:
            # TCP probe to SSH port - fails faster than ICMP when instance is dying
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.RAPID_PROBE_TIMEOUT)  # 0.5s timeout
            result = sock.connect_ex((node_ip, 22))
            sock.close()
            return result == 0  # 0 means connection successful
        except socket.timeout:
            return False
        except Exception:
            return False

    def perform_rapid_probing(self, node_ip: str, node_id: str) -> bool:
        """
        Perform rapid probing sequence to confirm node death.

        Probes every RAPID_PROBE_INTERVAL (0.5s) up to RAPID_PROBES_BEFORE_FAILOVER times.

        Returns:
            True if failover should be triggered (all probes failed)
            False if node recovered (any probe succeeded)
        """
        logger.warning(f"Starting rapid probe sequence for {node_id} at {node_ip}")

        consecutive_failures = 0

        for i in range(self.RAPID_PROBES_BEFORE_FAILOVER):
            probe_result = self.rapid_probe(node_ip, node_id)

            if probe_result:
                # Node responded - it's alive
                logger.info(f"Rapid probe #{i+1} succeeded for {node_id} - node is alive")
                self.rapid_probe_failures[node_id] = 0
                return False  # Don't failover

            consecutive_failures += 1
            logger.warning(f"Rapid probe #{i+1} failed for {node_id} ({consecutive_failures}/{self.RAPID_PROBES_BEFORE_FAILOVER})")

            if consecutive_failures < self.RAPID_PROBES_BEFORE_FAILOVER:
                time.sleep(self.RAPID_PROBE_INTERVAL)

        # All probes failed
        logger.critical(f"All {self.RAPID_PROBES_BEFORE_FAILOVER} rapid probes failed for {node_id} - CONFIRMED DEAD")
        return True  # Trigger failover

    def check_active_scrubber_health(self) -> Dict:
        """
        Context-aware health check for the active scrubber.

        Uses consecutive miss tracking and active probing to make
        intelligent failover decisions.

        Returns:
            {
                'severity': 'ok'|'warning'|'critical',
                'reason': str,
                'failover': bool,
                'node_state': NodeState,
                ...
            }
        """
        try:
            # NOTE: Removed global deployment_in_progress check.
            # Async deployment now uses per-shard locking in job_worker.
            # Deploying shards have no nodes yet, so won't be checked here.

            # === PRE-CHECK: Within grace period after deployment? ===
            grace_remaining = (
                state_manager.deployment_completed_at +
                state_manager.deployment_grace_period -
                time.time()
            )
            if grace_remaining > 0:
                log_rate_limited(
                    "health_grace_period",
                    logger.debug,
                    f"Deployment grace period active ({grace_remaining:.0f}s remaining) - skipping failover checks",
                    interval_seconds=60
                )
                return {
                    'severity': 'ok',
                    'reason': 'DEPLOYMENT_GRACE_PERIOD',
                    'failover': False,
                    'node_state': NodeState.UNKNOWN
                }

            # === PRE-CHECK: Are scrubbers even deployed? ===
            if not state_manager.nodes_db:
                log_rate_limited(
                    "health_no_scrubbers",
                    logger.debug,
                    "No scrubbers deployed - skipping health check"
                )
                return {
                    'severity': 'ok',
                    'reason': 'NO_SCRUBBERS_DEPLOYED',
                    'failover': False,
                    'node_state': NodeState.UNKNOWN
                }

            # === PRE-CHECK: Any origins to protect? ===
            # If no origins configured, there's nothing to protect - don't trigger failover
            # This synchronizes with ecp-agent behavior (skips reporting when no traffic)
            # and matches the deployment flow: scrubbers → exit hub → origin → traffic
            if not state_manager.origins_db:
                log_rate_limited(
                    "health_no_origins",
                    logger.debug,
                    "No origins configured - skipping health check (nothing to protect)"
                )
                return {
                    'severity': 'ok',
                    'reason': 'NO_ORIGINS_CONFIGURED',
                    'failover': False,
                    'node_state': NodeState.UNKNOWN
                }

            # Get shard state - check ALL shards, not just eu-central-1
            db = get_db_connection()
            cur = db.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Multi-region support: Query all shards with active nodes
            cur.execute("SELECT shard_id, active_node, standby_node FROM shard_state WHERE active_node IS NOT NULL")
            all_shards = cur.fetchall()

            # Filter to only check shards that have origins assigned
            # This prevents failover on newly deployed shards before origin creation completes
            # (ecp-agent skips reporting when no origins → no health data → false failover)
            shards_with_origins = {o.get('shard_id') for o in state_manager.origins_db.values()}
            shards_to_check = [s for s in all_shards if s['shard_id'] in shards_with_origins]

            skipped_shards = [s['shard_id'] for s in all_shards if s['shard_id'] not in shards_with_origins]
            if skipped_shards:
                log_rate_limited(
                    "health_skip_empty_shards",
                    logger.debug,
                    f"Skipping health check for shards without origins: {skipped_shards}"
                )

            if not shards_to_check:
                cur.close()
                db.close()
                logger.debug("No shard state configured - skipping health check")
                return {
                    'severity': 'ok',
                    'reason': 'NO_SHARD_STATE',
                    'failover': False,
                    'node_state': NodeState.UNKNOWN
                }

            # Check each shard and return worst result
            worst_result = None
            for row in shards_to_check:
                shard_result = self._check_shard_health(row, cur, db)
                if worst_result is None or shard_result['severity'] == 'critical':
                    worst_result = shard_result
                    if shard_result['severity'] == 'critical':
                        break  # Stop on first critical - trigger failover immediately

            cur.close()
            db.close()
            return worst_result if worst_result else {
                'severity': 'ok',
                'reason': 'NO_ACTIVE_SHARDS',
                'failover': False,
                'node_state': NodeState.UNKNOWN
            }

        except Exception as e:
            logger.error(f"Health check failed: {e}", exc_info=True)
            return {
                'severity': 'ok',
                'reason': 'HEALTH_CHECK_ERROR',
                'failover': False,
                'node_state': NodeState.UNKNOWN
            }

    def _check_shard_health(self, row, cur, db):
        """Check health of a single shard. Returns health status dict."""
        try:
            shard_id = row['shard_id']

            active_node_id = row['active_node']
            standby_node_id = row['standby_node']

            # Find active node in registry by instance_id
            active_node_data = None
            for node_name, node_data in state_manager.nodes_db.items():
                if node_data.get('instance_id') == active_node_id:
                    active_node_data = node_data
                    break

            if not active_node_data:
                logger.debug(f"Active node {active_node_id} not in nodes_db for shard {shard_id}")
                return {
                    'severity': 'ok',
                    'reason': 'ACTIVE_NODE_NOT_REGISTERED',
                    'failover': False,
                    'node_state': NodeState.UNKNOWN,
                    'shard_id': shard_id
                }

            active_node_ip = active_node_data.get('public_ip')
            active_node_name = active_node_data.get('instance_name')

            # Check standby availability
            standby_node_data = None
            if standby_node_id:
                for node_name, node_data in state_manager.nodes_db.items():
                    if node_data.get('instance_id') == standby_node_id:
                        standby_node_data = node_data
                        break
            has_standby = standby_node_data is not None

            # Get health data from database (cursor shared, don't close here)
            cur.execute("""
                SELECT h.*, n.instance_name, n.current_public_ip, n.conntrack_max,
                       EXTRACT(EPOCH FROM h.last_seen) as last_seen_epoch,
                       EXTRACT(EPOCH FROM (NOW() - h.last_seen)) as staleness_seconds
                FROM health_node h
                JOIN nodes n ON h.node_id = n.node_id
                WHERE h.node_id = %s
            """, (active_node_id,))

            health = cur.fetchone()

            # No health data yet
            if not health:
                if not has_standby:
                    logger.warning(
                        f"No health data for {active_node_name} ({active_node_id}) but no standby available - "
                        "waiting for health reports"
                    )
                    return {
                        'severity': 'warning',
                        'reason': 'NO_HEALTH_DATA_NO_STANDBY',
                        'failover': False,
                        'node_state': NodeState.UNKNOWN
                    }

                # Have standby, but give new nodes time to report
                node = self.get_or_create_node_health(active_node_id)
                time_in_state = time.time() - node.state_changed_at

                if time_in_state < self.BOOTSTRAP_GRACE_PERIOD:
                    logger.debug(
                        f"No health data for {active_node_name} ({active_node_id}) but within bootstrap grace "
                        f"({self.BOOTSTRAP_GRACE_PERIOD - time_in_state:.0f}s remaining)"
                    )
                    return {
                        'severity': 'warning',
                        'reason': 'BOOTSTRAP_GRACE_PERIOD',
                        'failover': False,
                        'node_state': NodeState.UNKNOWN
                    }

                return {
                    'severity': 'critical',
                    'reason': 'NO_HEALTH_DATA',
                    'failover': True,
                    'node_state': NodeState.UNRESPONSIVE,
                    'shard_id': shard_id
                }

            # === Update heartbeat tracking (from in-memory tracker, NOT database) ===
            # The heartbeat tracker is updated by the lightweight /health/heartbeat endpoint
            # which is called every 5s by ecp-agent (separate from heavy 30s metrics)
            last_heartbeat = get_last_heartbeat(active_node_id)
            node = self.update_heartbeat_tracking(active_node_id, last_heartbeat)

            # === CRITICAL CHECKS (Immediate) ===

            # Memory exhausted
            if health['memory_pct'] and health['memory_pct'] > 90:
                return {
                    'severity': 'critical',
                    'reason': 'MEMORY_EXHAUSTED',
                    'failover': True,
                    'node_state': NodeState.UNRESPONSIVE,
                    'metrics': {'memory_pct': health['memory_pct']},
                    'shard_id': shard_id
                }

            # BPF not loaded
            if not health['bpf_loaded']:
                # Try recovery first
                if self.attempt_bpf_recovery(active_node_ip):
                    logger.info("BPF recovered successfully")
                    node.state = NodeState.HEALTHY
                    return {
                        'severity': 'warning',
                        'reason': 'BPF_RECOVERED',
                        'failover': False,
                        'node_state': NodeState.HEALTHY
                    }
                else:
                    return {
                        'severity': 'critical',
                        'reason': 'BPF_UNRECOVERABLE',
                        'failover': True,
                        'node_state': NodeState.UNRESPONSIVE,
                        'recovery_attempted': True,
                        'recovery_result': 'XDP reload failed',
                        'shard_id': shard_id
                    }

            # === FAST HEARTBEAT-BASED DETECTION ===
            # Check if heartbeat is late (beyond tolerance)
            now = time.time()
            time_since_heartbeat = now - last_heartbeat
            expected_max_delay = self.HEARTBEAT_INTERVAL + self.HEARTBEAT_TOLERANCE  # 6s

            # Healthy: heartbeat arrived within expected window
            if time_since_heartbeat <= expected_max_delay:
                if node.state != NodeState.HEALTHY:
                    logger.info(f"{active_node_name} is HEALTHY (heartbeat {time_since_heartbeat:.1f}s ago)")
                    node.state = NodeState.HEALTHY
                    node.state_changed_at = now
                    self.rapid_probe_failures[active_node_id] = 0

                return {
                    'severity': 'ok',
                    'reason': 'HEALTHY',
                    'failover': False,
                    'node_state': NodeState.HEALTHY,
                    'time_since_heartbeat': time_since_heartbeat
                }

            # === SUSPICIOUS: Heartbeat is late - start rapid probing ===
            logger.warning(
                f"{active_node_name} SUSPICIOUS: Heartbeat {time_since_heartbeat:.1f}s ago "
                f"(expected <{expected_max_delay}s) - starting rapid probe"
            )
            node.state = NodeState.PROBING
            node.state_changed_at = now

            # Perform rapid probing sequence (3 probes at 0.5s interval)
            should_failover = self.perform_rapid_probing(active_node_ip, active_node_id)

            if not should_failover:
                # Node responded to probes - it's alive but heartbeat is late
                logger.warning(
                    f"{active_node_name} probe succeeded but heartbeat is {time_since_heartbeat:.1f}s late - "
                    "possible ecp-agent issue, NOT triggering failover"
                )
                node.state = NodeState.DEGRADED
                return {
                    'severity': 'warning',
                    'reason': 'PROBE_OK_HEARTBEAT_LATE',
                    'failover': False,
                    'node_state': NodeState.DEGRADED,
                    'time_since_heartbeat': time_since_heartbeat,
                    'probe_result': 'responsive'
                }

            # All rapid probes failed - node is confirmed dead
            # Check if we have a standby
            if not has_standby:
                logger.error(
                    f"{active_node_name} is CONFIRMED DEAD but no standby available - "
                    "cannot failover"
                )
                node.state = NodeState.UNRESPONSIVE
                return {
                    'severity': 'critical',
                    'reason': 'UNRESPONSIVE_NO_STANDBY',
                    'failover': False,
                    'node_state': NodeState.UNRESPONSIVE,
                    'time_since_heartbeat': time_since_heartbeat
                }

            # Confirmed dead with standby available - trigger failover
            logger.critical(
                f"{active_node_name} CONFIRMED DEAD: Heartbeat {time_since_heartbeat:.1f}s late "
                f"AND all {self.RAPID_PROBES_BEFORE_FAILOVER} rapid probes failed - "
                f"TRIGGERING FAILOVER (total detection time: ~{time_since_heartbeat:.1f}s)"
            )
            node.state = NodeState.UNRESPONSIVE
            node.state_changed_at = time.time()

            return {
                'severity': 'critical',
                'reason': 'SCRUBBER_UNRESPONSIVE',
                'failover': True,
                'node_state': NodeState.UNRESPONSIVE,
                'time_since_heartbeat': time_since_heartbeat,
                'probe_result': 'all_failed',
                'shard_id': shard_id
            }

        except Exception as e:
            logger.error(f"Health check for shard failed: {e}")
            return {
                'severity': 'error',
                'reason': f'HEALTH_CHECK_FAILED: {e}',
                'failover': False,
                'node_state': NodeState.UNKNOWN,
                'shard_id': row.get('shard_id', 'unknown') if row else 'unknown'
            }

    def attempt_bpf_recovery(self, scrubber_ip: str) -> bool:
        """Attempt to reload BPF/XDP program."""
        logger.warning(f"Attempting BPF recovery on {scrubber_ip}")

        try:
            rc, stdout, stderr = ssh_exec(
                scrubber_ip,
                "cd /opt/tensorprox/ebpf && sudo bash -c '"
                "ip link set dev ens5 xdp off && "
                "ip -force link set dev ens5 xdpgeneric obj build/xdp_wan.o sec xdp"
                "'",
                self.settings.ssh_key_path,
                nodes_db=state_manager.nodes_db,
                timeout=15
            )

            if rc != 0:
                logger.error(f"XDP reload failed (rc={rc}): {stderr}")
                return False

            time.sleep(2)
            rc, _, _ = ssh_exec(
                scrubber_ip,
                "bpftool net show dev ens5 | grep -q xdp",
                self.settings.ssh_key_path,
                nodes_db=state_manager.nodes_db,
                timeout=5
            )

            if rc == 0:
                logger.info("BPF recovery successful")
                return True

            logger.error("BPF reload verification failed")
            return False

        except Exception as e:
            logger.error(f"BPF recovery exception: {e}")
            return False

    def execute_failover(self, reason: str, shard_id: str = 'eu-central-1', metrics: Dict = None):
        """Trigger failover endpoint with authentication and cascade protection."""
        # Get cascade protection singleton
        protection = get_failover_protection()

        # Record this failure for cascade detection (use shard_id as identifier)
        protection.record_failure(hash(shard_id) % 1000, reason)

        # Check cascade state before proceeding
        cascade_state = protection.get_cascade_state()
        if cascade_state == CascadeState.EMERGENCY:
            logger.critical(
                f"FAILOVER BLOCKED (EMERGENCY MODE): {shard_id} - {reason}. "
                "Too many failures detected, halting failovers to prevent cascade."
            )
            return

        if cascade_state == CascadeState.CASCADE:
            logger.warning(
                f"CASCADE DETECTED: Proceeding with failover for {shard_id} with caution"
            )

        # ALWAYS update last_failover to prevent infinite retry loop on failure
        self.last_failover = time.time()

        try:
            payload = {
                'reason': reason,
                'automated': True,
                'metrics': metrics or {},
                'cascade_state': cascade_state.value
            }

            # Correct endpoint: /api/v1/admin/shards/<shard_id>/failover
            emn_port = getattr(self.settings, 'emn_port', 8000)
            failover_url = f'http://localhost:{emn_port}/api/v1/admin/shards/{shard_id}/failover'
            response = requests.post(
                failover_url,
                headers={'Authorization': f'Bearer {miner_identity._miner_secret}'},
                json=payload,
                timeout=120
            )

            if response.status_code == 200:
                logger.critical(f"AUTOMATED FAILOVER COMPLETED: {reason}")
                # Reset node health tracking after successful failover
                self.node_health.clear()
            else:
                logger.error(f"Failover request failed: {response.status_code} {response.text}")

        except Exception as e:
            logger.error(f"Failover execution failed: {e}")

    def monitor_loop(self):
        """Main monitoring loop with cascade protection."""
        logger.info(
            f"Health monitor started: "
            f"interval={self.MONITOR_INTERVAL}s, "
            f"heartbeat_interval={self.HEARTBEAT_INTERVAL}s, "
            f"tolerance={self.HEARTBEAT_TOLERANCE}s, "
            f"rapid_probes_before_failover={self.RAPID_PROBES_BEFORE_FAILOVER}"
        )

        # Get cascade protection singleton
        protection = get_failover_protection()

        while True:
            try:
                health_status = self.check_active_scrubber_health()

                if health_status['severity'] == 'critical' and health_status.get('failover'):
                    # Check cascade state first
                    cascade_state = protection.get_cascade_state()
                    protection_status = protection.get_status()

                    if cascade_state == CascadeState.EMERGENCY:
                        logger.critical(
                            f"FAILOVER SUPPRESSED (EMERGENCY): {health_status['reason']} | "
                            f"recent_failures={protection_status['recent_failures']}, "
                            f"cascade_state={cascade_state.value}"
                        )
                        # Sleep longer during emergency to let things stabilize
                        time.sleep(self.MONITOR_INTERVAL * 5)
                        continue

                    # Check cooldown
                    time_since_failover = time.time() - self.last_failover

                    if time_since_failover > self.FAILOVER_COOLDOWN:
                        shard_id = health_status.get('shard_id', 'eu-central-1')
                        logger.critical(
                            f"AUTOMATIC FAILOVER TRIGGERED for {shard_id}: {health_status['reason']} "
                            f"(misses: {health_status.get('consecutive_misses', 'N/A')}, "
                            f"cascade_state={cascade_state.value})"
                        )
                        self.execute_failover(
                            reason=health_status['reason'],
                            shard_id=shard_id,
                            metrics=health_status.get('metrics')
                        )
                    else:
                        logger.warning(
                            f"Failover needed ({health_status['reason']}) but in cooldown "
                            f"({self.FAILOVER_COOLDOWN - time_since_failover:.0f}s remaining)"
                        )

                elif health_status['severity'] == 'warning':
                    logger.warning(
                        f"Scrubber degraded: {health_status['reason']} "
                        f"(state: {health_status.get('node_state', 'unknown').value if hasattr(health_status.get('node_state'), 'value') else 'unknown'})"
                    )

            except Exception as e:
                logger.error(f"Monitor loop iteration failed: {e}")

            time.sleep(self.MONITOR_INTERVAL)


def start_health_monitor_thread():
    """Start health monitor service in background thread."""
    monitor = HealthMonitor()

    def monitor_thread():
        monitor.monitor_loop()

    thread = threading.Thread(target=monitor_thread, daemon=True)
    thread.start()

    logger.info("Health monitor thread started")
