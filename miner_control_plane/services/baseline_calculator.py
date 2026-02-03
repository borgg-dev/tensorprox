#!/usr/bin/env python3
from shared.database import get_db_connection as get_db
"""
Layer 6 Preparation: Baseline Statistics Calculator

Computes baseline traffic patterns from Layer 5 lifetime counters.
Used by Layer 6 (Baseline Learning) and Layer 7 (Anomaly Detection).

Key concepts:
- Baseline = normal traffic pattern for an origin
- Statistics: mean, stddev, percentiles (p50, p95, p99)
- Computed over lookback period (default: 7 days)
- Uses pre-aggregated hourly data for performance

Integration:
- Input: origin_metrics_hourly table (Layer 5)
- Output: traffic_baselines table (Layer 6, not yet created)
- Consumers: Layer 7 anomaly detection, Layer 4 dynamic thresholds

Note: This file defines interfaces for Layer 6 but is not yet active.
      Layer 6 will implement the complete baseline learning system.
"""

import logging
from typing import Dict, Optional
import statistics
from psycopg2.extras import RealDictCursor

logger = logging.getLogger('emn-baseline-calculator')

def calculate_baseline_for_origin(origin_id: str, lookback_days: int = 7) -> Optional[Dict]:
    """
    Calculate baseline traffic statistics for an origin

    Args:
        origin_id: Origin identifier
        lookback_days: Number of days to analyze (default: 7)

    Returns:
        Dictionary with baseline statistics:
        {
            'origin_id': 'O1',
            'lookback_days': 7,
            'sample_count': 168,  # Hours in lookback period
            'pps': {
                'mean': 125000,
                'stddev': 25000,
                'p50': 120000,
                'p95': 180000,
                'p99': 220000
            },
            'cps': {'mean': 450, 'stddev': 90, 'p95': 650},
            'bps': {'mean': 625000000, 'p95': 900000000},
            'syn_synack_ratio': {
                'mean': 1.08,
                'stddev': 0.15,
                'p95': 1.35,
                'max': 2.5
            },
            'active_connections': {
                'mean': 3200,
                'p95': 5000
            }
        }

    Usage (Layer 6):
        baseline = calculate_baseline_for_origin('O1', lookback_days=7)
        if baseline:
            # Store in traffic_baselines table
            # Use for anomaly detection (z-score)
            # Use for dynamic threshold calculation
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get min_samples from baseline_config (configurable per origin)
        cur.execute("""
            SELECT min_samples
            FROM baseline_config
            WHERE origin_id = %s
        """, (origin_id,))
        config_row = cur.fetchone()
        min_samples = config_row['min_samples'] if config_row and config_row['min_samples'] else 24

        # Query pre-aggregated hourly data (fast: ~168 rows for 7 days)
        cur.execute("""
            SELECT
                avg_pps, p95_pps, p99_pps,
                avg_cps, p95_cps,
                avg_bps, p95_bps,
                avg_syn_synack_ratio, max_syn_synack_ratio,
                avg_active_connections, max_active_connections
            FROM origin_metrics_hourly
            WHERE origin_id = %s
              AND hour_start > NOW() - INTERVAL '%s days'
            ORDER BY hour_start
        """, (origin_id, lookback_days))

        hourly_data = cur.fetchall()

        if len(hourly_data) < min_samples:
            logger.warning(f"Insufficient data for baseline (origin={origin_id}, samples={len(hourly_data)}, need={min_samples})")
            cur.close()
            return None

        # Extract time-series for each metric
        pps_values = [row['avg_pps'] for row in hourly_data if row['avg_pps'] is not None]
        cps_values = [row['avg_cps'] for row in hourly_data if row['avg_cps'] is not None]
        bps_values = [row['avg_bps'] for row in hourly_data if row['avg_bps'] is not None]
        ratio_values = [row['avg_syn_synack_ratio'] for row in hourly_data if row['avg_syn_synack_ratio'] is not None]
        conn_values = [row['avg_active_connections'] for row in hourly_data if row['avg_active_connections'] is not None]

        # Calculate statistics
        baseline = {
            'origin_id': origin_id,
            'lookback_days': lookback_days,
            'sample_count': len(hourly_data),
            'pps': compute_stats(pps_values),
            'cps': compute_stats(cps_values),
            'bps': compute_stats(bps_values),
            'syn_synack_ratio': compute_stats(ratio_values),
            'active_connections': compute_stats(conn_values)
        }

        cur.close()

        logger.info(f"Baseline calculated for {origin_id}: {baseline['sample_count']} samples, mean_pps={baseline['pps']['mean']}")

        return baseline

    except Exception as e:
        logger.error(f"Failed to calculate baseline for {origin_id}: {e}")
        return None
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def compute_stats(values: list) -> Dict:
    """
    Compute statistical measures for a list of values

    Args:
        values: List of numeric values

    Returns:
        Dictionary with mean, stddev, percentiles
    """
    if not values:
        return {
            'mean': None,
            'stddev': None,
            'p50': None,
            'p95': None,
            'p99': None,
            'min': None,
            'max': None
        }

    # Remove None values and convert to float (handles Decimal from database)
    clean_values = [float(v) for v in values if v is not None]

    if not clean_values:
        return {
            'mean': None,
            'stddev': None,
            'p50': None,
            'p95': None,
            'p99': None,
            'min': None,
            'max': None
        }

    # Calculate statistics
    mean_val = statistics.mean(clean_values)
    stddev_val = statistics.stdev(clean_values) if len(clean_values) > 1 else 0

    # Percentiles
    sorted_vals = sorted(clean_values)
    n = len(sorted_vals)

    p50 = sorted_vals[int(n * 0.50)] if n > 0 else None
    p95 = sorted_vals[int(n * 0.95)] if n > 0 else None
    p99 = sorted_vals[int(n * 0.99)] if n > 0 else None

    return {
        'mean': int(mean_val) if isinstance(mean_val, float) else mean_val,
        'stddev': int(stddev_val) if isinstance(stddev_val, float) else stddev_val,
        'p50': p50,
        'p95': p95,
        'p99': p99,
        'min': min(clean_values),
        'max': max(clean_values)
    }

def get_dynamic_syn_threshold(origin_id: str, lookback_days: int = 7) -> float:
    """
    Calculate dynamic SYN flood threshold based on baseline

    Args:
        origin_id: Origin identifier
        lookback_days: Baseline period (default: 7 days)

    Returns:
        Dynamic threshold (minimum: 10.0)

    Formula:
        threshold = max(baseline_p95 * 3, 10.0)

    Example:
        Normal ratio baseline: p95=1.5
        Threshold: 1.5 × 3 = 4.5 → use 10.0 (minimum)

        Asymmetric CDN: p95=3.5
        Threshold: 3.5 × 3 = 10.5 (adapt to traffic pattern)

    Usage (syncookie_controller.py):
        threshold = get_dynamic_syn_threshold(origin_id)
        if current_ratio > threshold:
            engage_syncookie_mode(vip_ip)
    """
    try:
        baseline = calculate_baseline_for_origin(origin_id, lookback_days)

        if not baseline or not baseline.get('syn_synack_ratio'):
            logger.warning(f"No baseline for {origin_id}, using default threshold 10.0")
            return 10.0

        p95_ratio = baseline['syn_synack_ratio'].get('p95')

        if not p95_ratio or p95_ratio <= 0:
            return 10.0

        # Threshold = 3× baseline p95, minimum 10.0
        # Convert to float to handle Decimal types from database
        dynamic_threshold = max(float(p95_ratio) * 3.0, 10.0)

        logger.info(f"Dynamic SYN threshold for {origin_id}: {dynamic_threshold:.1f} (baseline p95: {p95_ratio:.2f})")

        return dynamic_threshold

    except Exception as e:
        logger.error(f"Failed to get dynamic threshold for {origin_id}: {e}")
        return 10.0  # Safe fallback

def calculate_traffic_velocity_multiplier(origin_id: str) -> float:
    """
    Calculate traffic velocity multiplier for adaptive scaling

    Args:
        origin_id: Origin identifier

    Returns:
        Multiplier (0.5-1.0)

    Logic:
        If avg_pps < 10% of machine capacity → reduce limits to 50%
        (Low traffic = can throttle more aggressively to save CPU)

    Usage (adaptive_scaling.py):
        velocity_mult = calculate_traffic_velocity_multiplier(origin_id)
        total_mult = cpu_mult * velocity_mult
        adjusted_limits = base_limits * total_mult
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get average PPS over last 5 minutes
        cur.execute("""
            SELECT AVG(pps) as avg_pps
            FROM origin_metrics
            WHERE origin_id = %s
              AND timestamp > NOW() - INTERVAL '5 minutes'
              AND pps IS NOT NULL
        """, (origin_id,))

        row = cur.fetchone()
        avg_pps = row['avg_pps'] if row and row['avg_pps'] else 0

        cur.close()

        # Base capacity ~18M pps (2 CPU × 9M)
        estimated_capacity = 18000000

        traffic_ratio = avg_pps / estimated_capacity if estimated_capacity > 0 else 1.0

        if traffic_ratio < 0.1:  # < 10% capacity
            return 0.5  # Reduce to 50% (save resources)
        else:
            return 1.0  # Full capacity

    except Exception as e:
        logger.error(f"Failed to calculate velocity multiplier: {e}")
        return 1.0  # Safe default (no reduction)
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def aggregate_hourly_metrics(hour_start):
    """
    Aggregate raw metrics into hourly table (cron job for Layer 6)

    Args:
        hour_start: Start of hour to aggregate (TIMESTAMPTZ)

    This function is called by hourly cron job to pre-compute aggregates.
    Layer 6 will use these for fast baseline queries.

    Example cron: 5 * * * * python3 -c "from baseline_calculator import aggregate_hourly_metrics; from datetime import datetime, timedelta; aggregate_hourly_metrics(datetime.now() - timedelta(hours=1))"
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get all origins
        cur.execute("SELECT origin_id FROM origins")
        origins = [row['origin_id'] for row in cur.fetchall()]

        for origin_id in origins:
            # Aggregate last hour's data
            cur.execute("""
                INSERT INTO origin_metrics_hourly (
                    origin_id, hour_start,
                    avg_pps, min_pps, max_pps,
                    p50_pps, p95_pps, p99_pps,
                    avg_cps, min_cps, max_cps, p95_cps,
                    avg_bps, p95_bps,
                    avg_syn_synack_ratio, max_syn_synack_ratio,
                    avg_active_connections, max_active_connections,
                    sample_count
                )
                SELECT
                    origin_id,
                    date_trunc('hour', %s),
                    AVG(pps), MIN(pps), MAX(pps),
                    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY pps),
                    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY pps),
                    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY pps),
                    AVG(cps), MIN(cps), MAX(cps),
                    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY cps),
                    AVG(bps),
                    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY bps),
                    AVG(syn_synack_ratio), MAX(syn_synack_ratio),
                    AVG(active_connections), MAX(active_connections),
                    COUNT(*)
                FROM origin_metrics
                WHERE origin_id = %s
                  AND timestamp >= %s
                  AND timestamp < %s + INTERVAL '1 hour'
                  AND pps IS NOT NULL
                GROUP BY origin_id
                ON CONFLICT (origin_id, hour_start) DO UPDATE SET
                    avg_pps = EXCLUDED.avg_pps,
                    p95_pps = EXCLUDED.p95_pps,
                    sample_count = EXCLUDED.sample_count,
                    computed_at = NOW()
            """, (hour_start, origin_id, hour_start, hour_start))

            rows_inserted = cur.rowcount

            if rows_inserted > 0:
                logger.info(f"Aggregated hourly metrics for {origin_id} at {hour_start}")

        conn.commit()
        cur.close()

    except Exception as e:
        logger.error(f"Failed to aggregate hourly metrics: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

