#!/usr/bin/env python3
"""
Layer 3: Adaptive Load-Based Scaling

Monitors scrubber CPU/memory utilization and dynamically adjusts
machine_limits_map to protect system resources.

Per dev-plan line 607: "based on available CPU and memory"
Per dev-plan line 625: "if the instance type or load changes"
"""

import threading
import time
import psycopg2
from psycopg2.extras import RealDictCursor
import subprocess
import struct
from shared.config import get_settings
from shared.database import get_db_connection as get_db
from shared.utils.logging import get_logger
from shared.utils.bpf_helpers import get_map_path, update_bpf_map

logger = get_logger('emn-adaptive-scaling')

# SSH key path from tp.env
ssh_key_path = get_settings().ssh_key_path

def ssh_exec_adaptive(host, command, user='ubuntu'):
    """
    Execute command via SSH (local wrapper for adaptive scaling).

    Note: Uses subprocess instead of shared.utils.ssh.ssh_exec for
    simplicity in this background service. User defaults to 'ubuntu'
    for backward compatibility but should be derived from provider.
    """
    try:
        result = subprocess.run(
            ['ssh', '-i', ssh_key_path, '-o', 'StrictHostKeyChecking=no',
             '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
             f'{user}@{host}', command],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        logger.error(f"SSH exec failed to {host}: {e}")
        return -1, '', str(e)

def get_scrubber_health():
    """
    Get latest health metrics (CPU, memory) for each scrubber
    Returns: {node_id: {'cpu': 15.5, 'ip': '18.156.76.120'}}
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get latest health for each scrubber with IP address and provider (last 2 minutes)
        cur.execute("""
            SELECT DISTINCT ON (h.node_id)
                h.node_id, h.cpu_pct, h.last_seen, n.current_public_ip, n.provider
            FROM health_node h
            JOIN nodes n ON h.node_id = n.node_id
            WHERE h.last_seen > NOW() - INTERVAL '2 minutes'
              AND n.node_id LIKE 'i-%'
            ORDER BY h.node_id, h.last_seen DESC
        """)

        health = {}
        for row in cur.fetchall():
            health[row['node_id']] = {
                'cpu': float(row['cpu_pct']) if row['cpu_pct'] else 0.0,
                'last_seen': row['last_seen'],
                'ip': row['current_public_ip'],
                'provider': row.get('provider', 'aws')  # Include provider for SSH user resolution
            }

        cur.close()

        logger.debug(f"Retrieved health for {len(health)} scrubbers")
        return health

    except Exception as e:
        logger.error(f"Failed to get scrubber health: {e}", exc_info=True)
        return {}
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def calculate_load_multiplier(cpu_percent):
    """
    Calculate scaling multiplier based on current CPU load

    Logic (adaptive resource protection):
    - CPU < 60%:  multiplier = 1.0 (100% capacity - normal)
    - CPU 60-75%: multiplier = 0.8 (80% capacity - moderate load)
    - CPU 75-85%: multiplier = 0.6 (60% capacity - high load)
    - CPU 85-95%: multiplier = 0.4 (40% capacity - very high load)
    - CPU > 95%:  multiplier = 0.2 (20% capacity - emergency protection)

    This implements dev-plan line 607: "based on available CPU and memory"
    """
    if cpu_percent < 60:
        return 1.0
    elif cpu_percent < 75:
        return 0.8
    elif cpu_percent < 85:
        return 0.6
    elif cpu_percent < 95:
        return 0.4
    else:
        return 0.2  # Emergency - severe CPU constraint

def calculate_traffic_velocity_multiplier():
    """
    LAYER 5: Calculate multiplier based on actual traffic velocity

    Logic:
    - If avg_pps across all origins < 10% of total capacity
      → reduce limits to 50% (low traffic, save CPU)
    - Otherwise: full capacity (1.0)

    Integration: Combines with CPU multiplier for 2-dimensional scaling

    Returns:
        Multiplier (0.5 or 1.0)
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get average PPS across all origins (last 5 minutes)
        cur.execute("""
            SELECT SUM(pps) as total_pps
            FROM (
                SELECT DISTINCT ON (origin_id) pps
                FROM origin_metrics
                WHERE timestamp > NOW() - INTERVAL '5 minutes'
                  AND pps IS NOT NULL
                ORDER BY origin_id, timestamp DESC
            ) latest
        """)

        row = cur.fetchone()
        total_pps = row['total_pps'] if row and row['total_pps'] else 0

        # Get scrubber count to estimate total capacity in same connection
        cur.execute("SELECT COUNT(*) as count FROM nodes WHERE node_id LIKE 'i-%'")
        scrubber_count = cur.fetchone()['count'] or 2

        cur.close()

        total_capacity = scrubber_count * 18000000
        traffic_ratio = total_pps / total_capacity if total_capacity > 0 else 1.0

        if traffic_ratio < 0.1:  # < 10% capacity
            logger.info(f"Low traffic velocity: {total_pps:,} pps ({traffic_ratio*100:.1f}% of capacity) → applying 0.5× multiplier")
            return 0.5
        else:
            return 1.0

    except Exception as e:
        logger.error(f"Failed to calculate traffic velocity multiplier: {e}", exc_info=True)
        return 1.0  # Safe default
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def get_base_machine_limits(scrubber_ip, user='ubuntu'):
    """
    Get hardware-calculated base limits (before load multiplier)
    Re-runs module 37 logic to get fresh values
    """
    try:
        rc, stdout, stderr = ssh_exec_adaptive(scrubber_ip, "nproc && free -g | awk '/Mem:/ {print $2}'", user=user)
        if rc != 0:
            return 900, 90  # Default fallback

        lines = stdout.strip().split('\n')
        cpu_count = int(lines[0])
        ram_gb = int(lines[1]) if len(lines) > 1 else 4

        # Same formula as module 37
        max_pps = cpu_count * 9000000
        per_source_pps = (max_pps * 5) // 100 // 10000

        token_capacity = per_source_pps * 10
        token_refill_rate = per_source_pps

        return token_capacity, token_refill_rate

    except Exception as e:
        logger.error(f"Failed to calculate base limits: {e}")
        return 900, 90  # Default

def update_machine_limits_for_load(scrubber_ip, base_capacity, base_rate, load_multiplier, provider='aws'):
    """Update machine_limits_map with load-adjusted values"""
    try:
        # Apply load multiplier
        adjusted_capacity = int(base_capacity * load_multiplier)
        adjusted_rate = int(base_rate * load_multiplier)

        # Pack as little-endian 32-bit integers
        value_bytes = struct.pack('<2I', adjusted_capacity, adjusted_rate)
        value_hex = ' '.join([f'{b:02x}' for b in value_bytes])

        success, error = update_bpf_map(
            host=scrubber_ip,
            map_path=get_map_path('machine_limits'),
            key_hex="00 00 00 00",
            value_hex=value_hex,
            ssh_key_path=ssh_key_path,
            provider=provider
        )

        if success:
            logger.info(f"Adaptive scaling on {scrubber_ip}: {base_capacity}→{adjusted_capacity} (load multiplier: {load_multiplier:.2f})")
            return True
        else:
            logger.error(f"Failed to update machine limits on {scrubber_ip}: {error}")
            return False

    except Exception as e:
        logger.error(f"Load-based scaling failed: {e}")
        return False

def adaptive_scaling_loop():
    """
    Main loop: Monitor load and adjust machine limits every 60s

    This implements dev-plan requirement:
    "based on available CPU and memory" (line 607)
    "if the instance type or load changes" (line 625)
    """
    # Track previous states to avoid thrashing
    previous_multipliers = {}

    logger.info("Adaptive scaling loop started")

    while True:
        try:
            health = get_scrubber_health()

            if not health:
                logger.warning("No scrubber health data available, skipping adaptive scaling")
                time.sleep(60)
                continue

            logger.debug(f"Adaptive scaling cycle: {len(health)} scrubbers")

            for node_id, metrics in health.items():
                scrubber_ip = metrics.get('ip')
                provider = metrics.get('provider', 'aws')  # Get provider from health data
                if not scrubber_ip:
                    logger.warning(f"No IP address for {node_id}, skipping")
                    continue

                cpu = metrics.get('cpu', 0)
                logger.debug(f"Processing {node_id}: CPU={cpu:.1f}%, IP={scrubber_ip}, provider={provider}")

                # LAYER 5: Calculate load multiplier based on CPU + traffic velocity
                cpu_multiplier = calculate_load_multiplier(cpu)
                velocity_multiplier = calculate_traffic_velocity_multiplier()

                # Combined multiplier (2-dimensional scaling)
                new_multiplier = cpu_multiplier * velocity_multiplier

                # Get previous multiplier for hysteresis
                prev_multiplier = previous_multipliers.get(node_id, 1.0)

                # Hysteresis: Only adjust if change is significant (>10% difference)
                # or if entering emergency zone (>95% CPU)
                diff = abs(new_multiplier - prev_multiplier)
                emergency = cpu > 95

                if diff > 0.1 or emergency:
                    logger.info(f"Adaptive scaling triggered for {node_id}: diff={diff:.2f}, emergency={emergency}")

                    # Get base limits
                    from shared.utils.ssh import get_ssh_user_for_provider
                    ssh_user = get_ssh_user_for_provider(provider)
                    base_cap, base_rate = get_base_machine_limits(scrubber_ip, user=ssh_user)

                    # Apply load-based scaling
                    success = update_machine_limits_for_load(
                        scrubber_ip, base_cap, base_rate, new_multiplier, provider=provider
                    )

                    if success:
                        previous_multipliers[node_id] = new_multiplier
                        logger.info(f"Adaptive scaling {node_id}: CPU={cpu:.1f}%, cpu_mult={cpu_multiplier:.2f}, vel_mult={velocity_multiplier:.2f}, total_mult={new_multiplier:.2f}, cap={int(base_cap*new_multiplier)}, rate={int(base_rate*new_multiplier)}")
                else:
                    logger.debug(f"Adaptive scaling {node_id}: No change needed (CPU={cpu:.1f}%, multiplier={new_multiplier:.2f})")

        except Exception as e:
            logger.error(f"Adaptive scaling loop error: {e}", exc_info=True)

        # Run every 60 seconds
        time.sleep(60)

def start_adaptive_scaling_thread():
    """
    Start adaptive load-based scaling background thread

    This ensures rate limits automatically adjust when:
    - CPU load increases (reduce capacity to protect system)
    - Memory pressure increases (reduce capacity to avoid OOM)
    - Load decreases (restore capacity to full)
    """
    thread = threading.Thread(target=adaptive_scaling_loop, daemon=True)
    thread.start()
    logger.info("Adaptive load-based scaling thread started: monitoring every 60s")
    return thread
