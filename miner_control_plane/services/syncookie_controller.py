#!/usr/bin/env python3
"""
PART 6: Adaptive SYN Cookie Controller
Runs at 5-second cadence (resident decision loop) following commercial pattern

LAYER 5 Enhancement: Dynamic thresholds from baseline statistics (optional)
"""

import logging
import threading
import time
import os
import socket
import psycopg2
from psycopg2.extras import RealDictCursor
import subprocess
from shared.database import get_db_connection as get_db
from shared.utils.ssh import ssh_exec, get_ssh_user_for_provider
from shared.utils.bpf_helpers import get_map_path, update_bpf_map
from shared.config import get_settings
from miner_control_plane.services.layer4_state import set_cookie_flag
from miner_control_plane.services.state_manager import state_manager
from miner_control_plane.services.scrubber_utils import get_scrubber_nodes

logger = logging.getLogger('emn-syncookie')

# Hysteresis parameters (anti-flapping)
ACTIVATION_THRESHOLD_RATIO = 15.0       # SYN/SYN-ACK ratio to activate (STATIC FALLBACK)
DEACTIVATION_THRESHOLD_RATIO = 10.0     # Ratio to deactivate (STATIC FALLBACK)
CONSECUTIVE_CHECKS_TO_ACTIVATE = 3      # Must breach 3 times (15s) to activate
CONSECUTIVE_CHECKS_TO_DEACTIVATE = 6    # Must be normal 6 times (30s) to deactivate

# LAYER 5: Dynamic threshold configuration
ENABLE_DYNAMIC_THRESHOLDS = False  # Disabled by default (requires Layer 6 baselines)
# When enabled, thresholds calculated per-origin from baseline_calculator.py

# Import Layer 5 baseline calculator (for dynamic thresholds)
try:
    from baseline_calculator import get_dynamic_syn_threshold
    BASELINE_CALC_AVAILABLE = True
except ImportError:
    BASELINE_CALC_AVAILABLE = False
    logger.warning("baseline_calculator not available, using static thresholds")

# Quarantine parameters (dev-plan section 6.5)
COOKIE_FAILURE_THRESHOLD = 3            # Failures before quarantine
QUARANTINE_BASE_TTL = 60                # Base TTL in seconds
QUARANTINE_MAX_TTL = 3600               # Max TTL (1 hour)
BYPASS_TTL = 60                         # Bypass map TTL per dev-plan section 6.6
MIN_SYN_DELTA_FOR_HISTORY = 50000       # Minimum new SYNs during the control interval

# Database connection imported from shared.database

def set_syncookie_mode_for_origin(eip, origin_ip, enabled):
    """
    Part 6: Enable/disable SYN cookie mode for specific origin (per-VIP isolation)

    Args:
        eip: Elastic IP address (for logging)
        origin_ip: Origin IP (key in syncookie_mode_map)
        enabled: 1=enable, 0=disable
    """
    settings = get_settings()
    nodes = get_scrubber_nodes()
    if not nodes:
        logger.warning("SYN cookie toggle skipped: no scrubber nodes available")
        return False

    try:
        origin_bytes = socket.inet_aton(origin_ip)
    except OSError:
        logger.error(f"Invalid origin IP for syncookie mode: {origin_ip}")
        return False

    origin_hex = ' '.join(f"{b:02x}" for b in origin_bytes)
    mode_hex = "01 00 00 00" if enabled else "00 00 00 00"

    map_path = get_map_path('syncookie_mode')
    updated = []
    errors = []
    for node in nodes:
        host_ip = node.get('host_ip')
        if not host_ip:
            continue
        success, error = update_bpf_map(
            host=host_ip,
            map_path=map_path,
            key_hex=origin_hex,
            value_hex=mode_hex,
            ssh_key_path=settings.ssh_key_path,
            provider=node.get('provider', 'aws'),
            user=node.get('ssh_user'),
            verify=True
        )
        if success:
            updated.append(node['node_id'])
        else:
            errors.append(f"{node['node_id']}: {error or 'unknown error'}")

    if len(updated) > 0:
        action = 'ENABLED' if enabled else 'DISABLED'
        logger.critical(f"SYN COOKIE {action} for EIP {eip} (origin {origin_ip}) on {len(updated)} scrubbers")

        # Log to mitigation_actions
        db = None
        try:
            db = get_db()
            conn = db.conn
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO mitigation_actions (
                    ip_address, action_type, severity, auto_triggered
                )
                VALUES (%s, %s, 'critical', true)
            """, (eip, 'syncookie_enable' if enabled else 'syncookie_disable'))
            conn.commit()
            cur.close()
        except Exception as e:
            logger.debug(f"Failed to log SYN cookie action: {e}")
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass

    else:
        logger.error(f"Failed to update syncookie_mode_map for {origin_ip}: {'; '.join(errors) if errors else 'no scrubbers succeeded'}")

    return len(updated) > 0

def get_activation_threshold(origin_id):
    """
    LAYER 6: Get activation threshold for an origin (dynamic or static)

    Returns: (activation_threshold, deactivation_threshold)

    If baseline_config.dynamic_thresholds_enabled = True and baseline available:
        activation = max(baseline_p95_ratio × multiplier, 10.0)
        deactivation = activation × 0.67 (maintains hysteresis gap)
    Else:
        Use static defaults (15.0, 10.0)
    """
    if not BASELINE_CALC_AVAILABLE:
        return ACTIVATION_THRESHOLD_RATIO, DEACTIVATION_THRESHOLD_RATIO

    db = None
    try:
        # LAYER 6: Check per-origin dynamic threshold flag
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT dynamic_thresholds_enabled FROM baseline_config WHERE origin_id = %s", (origin_id,))
        config = cur.fetchone()
        cur.close()

        if not config or not config['dynamic_thresholds_enabled']:
            return ACTIVATION_THRESHOLD_RATIO, DEACTIVATION_THRESHOLD_RATIO

        # Get dynamic threshold from Layer 6 baseline calculator
        dynamic_activation = get_dynamic_syn_threshold(origin_id, lookback_days=7)

        # Deactivation threshold = 67% of activation (maintains hysteresis gap)
        dynamic_deactivation = dynamic_activation * 0.67

        logger.debug(f"Dynamic thresholds for {origin_id}: activate={dynamic_activation:.1f}, deactivate={dynamic_deactivation:.1f}")

        return dynamic_activation, dynamic_deactivation

    except Exception as e:
        logger.warning(f"Failed to get dynamic threshold for {origin_id}: {e}, using static")
        return ACTIVATION_THRESHOLD_RATIO, DEACTIVATION_THRESHOLD_RATIO
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def syncookie_control_loop():
    """
    Part 6: Resident SYN cookie controller - runs every 5 seconds
    Local decisions with hysteresis to avoid flapping

    LAYER 5: Now supports dynamic thresholds from baseline statistics
    """
    # Persistent state for hysteresis (function attribute pattern)
    if not hasattr(syncookie_control_loop, 'origin_state'):
        syncookie_control_loop.origin_state = {}

    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get recent SYN/SYN-ACK ratios (last 30 seconds for fast response)
        cur.execute("""
            SELECT o.origin_id, o.eip, o.origin_ip, m.syn_synack_ratio, m.ingress_syn_count, m.pps
            FROM origins o
            LEFT JOIN LATERAL (
                SELECT syn_synack_ratio, ingress_syn_count, pps
                FROM origin_metrics
                WHERE origin_id = o.origin_id
                ORDER BY timestamp DESC
                LIMIT 1
            ) m ON true
            WHERE o.state = 'IN_SERVICE'
        """)
        origins = cur.fetchall()

        # Resource SLO check (don't activate if CPU overloaded)
        cur.execute("SELECT MAX(cpu_pct) as max_cpu FROM health_node WHERE last_seen > NOW() - INTERVAL '1 minute'")
        cpu_row = cur.fetchone()
        max_cpu = float(cpu_row['max_cpu']) if cpu_row and cpu_row['max_cpu'] else 0

        if max_cpu > 80:
            logger.warning(f"CPU at {max_cpu:.1f}% - SKIPPING SYN cookie checks (SLO protection)")
            cur.close()
            return

        for origin in origins:
            origin_id = origin['origin_id']
            eip = origin['eip']
            origin_ip = origin['origin_ip']
            ratio = float(origin['syn_synack_ratio']) if origin['syn_synack_ratio'] else 0
            syn_count = origin['ingress_syn_count'] or 0

            # Initialize state if new
            if origin_id not in syncookie_control_loop.origin_state:
                syncookie_control_loop.origin_state[origin_id] = {
                    'mode': 0,
                    'consecutive_normal': 0,
                    'consecutive_attack': 0,
                    'last_syn_total': syn_count
                }

            state = syncookie_control_loop.origin_state[origin_id]
            last_syn_total = state.get('last_syn_total', syn_count)
            syn_delta = max(syn_count - last_syn_total, 0)
            state['last_syn_total'] = syn_count

            # LAYER 5: Get thresholds (dynamic or static)
            activation_threshold, deactivation_threshold = get_activation_threshold(origin_id)

            # Get PPS for additional validation (prevent bootstrap false positives)
            pps = origin.get('pps', 0) or 0
            min_pps_for_ratio_trigger = 100  # Minimum PPS to trust high SYN ratio

            # ACTIVATION LOGIC (with hysteresis)
            # Require ALL three conditions (AND logic):
            #   1. High ratio (attack signature)
            #   2. Sufficient PPS (not bootstrap noise)
            #   3. Enough traffic history (reliable ratio calculation)
            # This PREVENTS bootstrap false positives from small sample sizes
            ratio_trigger = ratio > activation_threshold
            sufficient_pps = pps >= min_pps_for_ratio_trigger
            enough_history = syn_delta >= MIN_SYN_DELTA_FOR_HISTORY

            # Debug logging for condition failures
            if ratio_trigger and not enough_history and ratio > 5:  # High ratio but not enough data yet
                logger.debug(
                    "%s: High ratio=%.1f but only %s new SYNs in interval (need >= %s)",
                    origin_id,
                    ratio,
                    syn_delta,
                    MIN_SYN_DELTA_FOR_HISTORY
                )

            if ratio_trigger and sufficient_pps and enough_history:
                state['consecutive_attack'] += 1
                state['consecutive_normal'] = 0

                # Activate after 3 consecutive attack checks (15 seconds)
                if state['consecutive_attack'] >= CONSECUTIVE_CHECKS_TO_ACTIVATE and state['mode'] == 0:
                    logger.critical(f"ACTIVATING SYN COOKIES: {origin_id} EIP {eip} - ratio={ratio:.2f} (threshold={activation_threshold:.1f}), pps={pps}, syn_count={syn_count}")
                    if set_syncookie_mode_for_origin(eip, origin_ip, enabled=1):
                        set_cookie_flag(origin_ip, True, "syncookie_controller.activate")
                    state['mode'] = 1
                    state['consecutive_attack'] = 0

                    # Log event
                    try:
                        cur.execute("""
                            INSERT INTO syncookie_events (eip, origin_id, event_type, syn_synack_ratio, consecutive_checks)
                            VALUES (%s, %s, 'activated', %s, %s)
                        """, (eip, origin_id, ratio, CONSECUTIVE_CHECKS_TO_ACTIVATE))
                        conn.commit()
                    except Exception as e:
                        logger.debug(f"Failed to log syncookie event: {e}")

            # DEACTIVATION LOGIC (with stronger hysteresis - 30s)
            elif ratio < deactivation_threshold:
                state['consecutive_normal'] += 1
                state['consecutive_attack'] = 0

                # Deactivate after 6 consecutive normal checks (30 seconds)
                if state['consecutive_normal'] >= CONSECUTIVE_CHECKS_TO_DEACTIVATE and state['mode'] == 1:
                    logger.info(f"DEACTIVATING SYN COOKIES: {origin_id} EIP {eip} - ratio={ratio:.2f} (threshold={deactivation_threshold:.1f})")
                    if set_syncookie_mode_for_origin(eip, origin_ip, enabled=0):
                        set_cookie_flag(origin_ip, False, "syncookie_controller.deactivate")
                    state['mode'] = 0
                    state['consecutive_normal'] = 0

                    # Log event
                    try:
                        cur.execute("""
                            INSERT INTO syncookie_events (eip, origin_id, event_type, syn_synack_ratio, consecutive_checks)
                            VALUES (%s, %s, 'deactivated', %s, %s)
                        """, (eip, origin_id, ratio, CONSECUTIVE_CHECKS_TO_DEACTIVATE))
                        conn.commit()
                    except Exception as e:
                        logger.debug(f"Failed to log syncookie event: {e}")

            else:
                # In between thresholds - maintain current state, reset counters
                state['consecutive_normal'] = 0
                state['consecutive_attack'] = 0

        cur.close()

    except Exception as e:
        logger.error(f"SYN cookie control loop failed: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def monitor_cookie_failures_and_apply_quarantine():
    """
    Layer 4: Monitor cookie failures from cookie_failure_map and auto-quarantine

    Per dev-plan section 6.5:
    - Read cookie_failure_map from scrubbers (per-source tracking)
    - After 3 failures → quarantine with exponential TTL backoff
    - Update source_state table for audit trail
    """
    # NOTE: Removed global deployment_in_progress check.
    # Async deployment uses per-shard locking in job_worker.
    # Only shards with active nodes will be processed here.

    settings = get_settings()
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get active scrubber for reading cookie_failure_map
        nodes = get_scrubber_nodes()
        if not nodes:
            cur.close()
            return

        # Read from first scrubber
        primary = nodes[0]
        scrubber_host = primary.get('host_ip')
        if not scrubber_host:
            cur.close()
            return

        ssh_user = primary.get('ssh_user') or get_ssh_user_for_provider(primary.get('provider', 'aws'))

        # Dump cookie_failure_map to get all sources with failures
        rc, stdout, stderr = ssh_exec(
            scrubber_host,
            "sudo bpftool map dump pinned /sys/fs/bpf/tc/globals/cookie_failure_map",
            settings.ssh_key_path,
            user=ssh_user
        )

        if rc != 0:
            cur.close()
            return  # Map not populated yet

        # Parse JSON output
        try:
            import json
            import socket
            import struct

            map_data = json.loads(stdout)

            for entry in map_data:
                try:
                    # Parse key: {src_ip (u32), vip_ip (u32)}
                    key_data = entry.get('key', {})
                    src_ip_int = key_data.get('src_ip', 0)
                    vip_ip_int = key_data.get('vip_ip', 0)

                    # Convert network byte order ints to IP strings
                    src_ip = socket.inet_ntoa(struct.pack('<I', src_ip_int))
                    vip_ip = socket.inet_ntoa(struct.pack('<I', vip_ip_int))

                    # Parse value: {failure_count, success_count, first_seen_ts, last_failure_ts}
                    value_data = entry.get('value', {})
                    failure_count = value_data.get('failure_count', 0)
                    success_count = value_data.get('success_count', 0)

                    # Auto-quarantine if failures >= threshold
                    if failure_count >= COOKIE_FAILURE_THRESHOLD:
                        # Get current score from source_state or default to 0
                        cur.execute("""
                            SELECT score, quarantine_expiry
                            FROM source_state
                            WHERE src_ip = %s AND vip_ip = %s
                        """, (src_ip, vip_ip))

                        row = cur.fetchone()
                        if row:
                            score = row.get('score') or 0
                            expiry = row.get('quarantine_expiry')
                            # Skip if already quarantined
                            if expiry and expiry > int(time.time()):
                                continue
                        else:
                            score = 0

                        # Calculate TTL with exponential backoff (60s → 120s → 240s → ... → 3600s max)
                        ttl = min(QUARANTINE_BASE_TTL * (2 ** score), QUARANTINE_MAX_TTL)

                        logger.warning(f"Auto-quarantine: {src_ip} → {vip_ip} ({failure_count} failures, score={score}, TTL={ttl}s)")

                        # Quarantine the IP
                        quarantine_ip_internal(src_ip, vip_ip, ttl, reason=1, score=score+1)

                        # Upsert source_state
                        expires_ts = int(time.time()) + ttl
                        cur.execute("""
                            INSERT INTO source_state (src_ip, vip_ip, score, quarantine_expiry, cookie_failures, cookie_successes)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (src_ip, vip_ip) DO UPDATE SET
                                score = source_state.score + 1,
                                quarantine_expiry = EXCLUDED.quarantine_expiry,
                                cookie_failures = 0,
                                last_seen = NOW()
                        """, (src_ip, vip_ip, score + 1, expires_ts, 0, success_count))
                        conn.commit()

                except Exception as e:
                    logger.debug(f"Failed to parse cookie_failure entry: {e}")
                    continue

        except Exception as e:
            logger.error(f"Failed to parse cookie_failure_map: {e}")

        cur.close()

    except Exception as e:
        logger.error(f"Cookie failure monitoring failed: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def quarantine_ip_internal(src_ip, vip_ip, ttl, reason=1, score=1):
    """Internal helper to quarantine IP without HTTP request"""
    settings = get_settings()
    try:
        import ipaddress
        import struct

        expires_ns = (int(time.time()) + ttl) * 1_000_000_000
        key = ipaddress.IPv4Address(src_ip).packed + ipaddress.IPv4Address(vip_ip).packed
        value = struct.pack('<QBBBBBBBB', expires_ns, score, reason, 0, 0, 0, 0, 0, 0)

        def hex_bytes(data):
            return [f"{b:02x}" for b in data]

        hex_key = ' '.join(hex_bytes(key))
        hex_value = ' '.join(hex_bytes(value))

        nodes = get_scrubber_nodes()
        map_path = get_map_path('quarantine')
        for node in nodes:
            host = node.get('host_ip')
            if not host:
                continue
            ssh_user = node.get('ssh_user') or get_ssh_user_for_provider(node.get('provider', 'aws'))
            update_bpf_map(
                host=host,
                map_path=map_path,
                key_hex=hex_key,
                value_hex=hex_value,
                ssh_key_path=settings.ssh_key_path,
                provider=node.get('provider', 'aws'),
                user=ssh_user,
                verify=True
            )

        # Log to database
        db = None
        try:
            db = get_db()
            conn = db.conn
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                INSERT INTO quarantine_log (src_ip, vip_ip, reason, ttl, score, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (src_ip, vip_ip, reason, ttl, score, int(time.time()), int(time.time()) + ttl))
            conn.commit()
            cur.close()
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass

    except Exception as e:
        logger.error(f"Internal quarantine failed: {e}")

def start_syncookie_controller_thread(interval_seconds=5):
    """
    Start Part 6 SYN cookie controller thread (5s cadence, resident decisions)
    """
    def control_loop():
        syncookie_control_loop()
        monitor_cookie_failures_and_apply_quarantine()  # Layer 4: Auto-quarantine
        threading.Timer(interval_seconds, control_loop).start()

    # Start first cycle after 10 seconds (let system stabilize)
    threading.Timer(10, control_loop).start()
    logger.info(f"SYN cookie controller started: checking every {interval_seconds}s (resident loop)")
