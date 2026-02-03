#!/usr/bin/env python3
from shared.database import get_db_connection as get_db
"""
Layer 6: Baseline Learner Service
Calculates statistical baselines from hourly aggregated metrics

Runs daily (default 02:00) to compute baseline traffic patterns for each origin.
Uses outlier removal and confidence scoring to ensure quality baselines.

Usage:
    python3 baseline_learner.py                    # Run main loop (daemon)
    python3 baseline_learner.py --test-origin O1   # Test with specific origin
    python3 baseline_learner.py --force-all        # Force recalc all origins

Background Thread:
    Started via start_baseline_learner_thread()
"""

import logging
import psycopg2
from psycopg2.extras import RealDictCursor
import threading
import time
import sys
import argparse
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger('emn-baseline-learner')

def remove_outliers(values: List[float], removal_pct: float = 1.0) -> List[float]:
    """
    Remove top and bottom outliers from a list of values

    Args:
        values: List of numeric values
        removal_pct: Percentage to remove from top and bottom (default: 1.0%)

    Returns:
        Trimmed list with outliers removed

    Example:
        Input: 100 values, removal_pct=1.0
        Output: 98 values (top 1 and bottom 1 removed)
    """
    if not values or len(values) < 10:
        return values  # Too few samples to remove outliers

    sorted_vals = sorted(values)
    n = len(sorted_vals)
    # Convert removal_pct to float to handle Decimal from database
    remove_count = max(1, int(n * (float(removal_pct) / 100.0)))

    # Remove top and bottom outliers
    trimmed = sorted_vals[remove_count:-remove_count] if remove_count > 0 else sorted_vals

    logger.debug(f"Outlier removal: {n} samples → {len(trimmed)} samples ({remove_count} removed from each end)")

    return trimmed

def calculate_confidence_score(sample_count: int, stddev: float, mean: float, min_samples: int = 100) -> float:
    """
    Calculate confidence score for baseline (0.0 - 1.0)

    Factors:
    - Sample count (more samples = higher confidence)
    - Variance (low variance = higher confidence)

    Args:
        sample_count: Number of hourly samples used
        stddev: Standard deviation
        mean: Mean value
        min_samples: Minimum samples required for confidence

    Returns:
        Confidence score 0.0-1.0
    """
    if sample_count < min_samples:
        return 0.0  # Insufficient data

    if mean == 0:
        return 0.5  # Can't calculate coefficient of variation, moderate confidence

    # Coefficient of variation (CV) = stddev / mean
    cv = stddev / mean if mean > 0 else 0

    # Sample confidence (0.0-1.0 based on sample count)
    sample_conf = min(sample_count / (min_samples * 2), 1.0)

    # Variance confidence (lower CV = higher confidence)
    if cv < 0.2:
        variance_conf = 1.0  # Low variance, excellent
    elif cv < 0.5:
        variance_conf = 0.8  # Moderate variance, good
    elif cv < 1.0:
        variance_conf = 0.5  # High variance, fair
    else:
        variance_conf = 0.3  # Very high variance, poor

    # Combined confidence (weighted average)
    confidence = (sample_conf * 0.6) + (variance_conf * 0.4)

    return round(confidence, 2)

def compute_baseline_for_origin(origin_id: str) -> Optional[Dict]:
    """
    Compute baseline statistics for a specific origin

    Process:
    1. Read baseline_config for parameters
    2. Query origin_metrics_hourly for lookback period
    3. Remove outliers
    4. Calculate statistics (mean, stddev, percentiles)
    5. Calculate confidence score
    6. Mark old baseline as is_current=FALSE
    7. Insert new baseline as is_current=TRUE
    8. Update baseline_config (last_recalc_at, next_recalc_at)

    Args:
        origin_id: Origin identifier (e.g., "O1")

    Returns:
        Baseline dictionary or None if failed
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get baseline configuration for this origin
        cur.execute("SELECT * FROM baseline_config WHERE origin_id = %s", (origin_id,))
        config = cur.fetchone()

        if not config:
            logger.warning(f"No baseline_config found for {origin_id}, using defaults")
            lookback_days = 7
            min_samples = 100
            outlier_pct = 1.0
        else:
            lookback_days = config['lookback_days']
            min_samples = config['min_samples']
            outlier_pct = config['outlier_removal_pct']

        # Calculate observation period
        observation_end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        observation_start = observation_end - timedelta(days=lookback_days)

        # Query hourly aggregated data
        cur.execute("""
            SELECT
                avg_pps, avg_cps, avg_bps,
                avg_syn_synack_ratio, avg_active_connections,
                p95_pps, p95_cps,
                min_pps, max_pps
            FROM origin_metrics_hourly
            WHERE origin_id = %s
              AND hour_start >= %s
              AND hour_start < %s
            ORDER BY hour_start
        """, (origin_id, observation_start, observation_end))

        hourly_data = cur.fetchall()
        sample_count = len(hourly_data)

        if sample_count < min_samples:
            logger.warning(f"Insufficient data for {origin_id}: {sample_count} samples (min: {min_samples})")
            cur.close()
            return None

        # Extract time-series for each metric
        pps_values = [row['avg_pps'] for row in hourly_data if row['avg_pps'] is not None]
        cps_values = [row['avg_cps'] for row in hourly_data if row['avg_cps'] is not None]
        bps_values = [row['avg_bps'] for row in hourly_data if row['avg_bps'] is not None]
        ratio_values = [row['avg_syn_synack_ratio'] for row in hourly_data if row['avg_syn_synack_ratio'] is not None]
        conn_values = [row['avg_active_connections'] for row in hourly_data if row['avg_active_connections'] is not None]

        # Remove outliers
        pps_clean = remove_outliers(pps_values, outlier_pct)
        cps_clean = remove_outliers(cps_values, outlier_pct)
        bps_clean = remove_outliers(bps_values, outlier_pct)
        ratio_clean = remove_outliers(ratio_values, outlier_pct)
        conn_clean = remove_outliers(conn_values, outlier_pct)

        outliers_removed = len(pps_values) - len(pps_clean)

        # Calculate statistics
        import statistics

        def calc_stats(vals):
            if not vals:
                return None, None, None, None, None, None, None
            mean = statistics.mean(vals)
            stddev = statistics.stdev(vals) if len(vals) > 1 else 0
            sorted_vals = sorted(vals)
            n = len(sorted_vals)
            p50 = sorted_vals[int(n * 0.50)] if n > 0 else None
            p95 = sorted_vals[int(n * 0.95)] if n > 0 else None
            p99 = sorted_vals[int(n * 0.99)] if n > 0 else None
            min_val = min(vals)
            max_val = max(vals)
            return int(mean), int(stddev), p50, p95, p99, min_val, max_val

        pps_mean, pps_stddev, pps_p50, pps_p95, pps_p99, pps_min, pps_max = calc_stats(pps_clean)
        cps_mean, cps_stddev, cps_p50, cps_p95, cps_p99, cps_min, cps_max = calc_stats(cps_clean)
        bps_mean, bps_stddev, bps_p50, bps_p95, bps_p99, bps_min, bps_max = calc_stats(bps_clean)
        ratio_mean, ratio_stddev, ratio_p50, ratio_p95, ratio_p99, ratio_min, ratio_max = calc_stats(ratio_clean)
        conn_mean, conn_stddev, conn_p50, conn_p95, conn_p99, conn_min, conn_max = calc_stats(conn_clean)

        # Calculate confidence score
        confidence = calculate_confidence_score(
            sample_count=len(pps_clean),
            stddev=pps_stddev if pps_stddev else 0,
            mean=pps_mean if pps_mean else 1,
            min_samples=min_samples
        )

        # Mark old baseline as not current
        cur.execute("""
            UPDATE traffic_baselines
            SET is_current = FALSE
            WHERE origin_id = %s AND is_current = TRUE
        """, (origin_id,))

        # Insert new baseline
        cur.execute("""
            INSERT INTO traffic_baselines (
                origin_id, lookback_days, observation_start, observation_end, sample_count,
                pps_mean, pps_stddev, pps_p50, pps_p95, pps_p99, pps_min, pps_max,
                cps_mean, cps_stddev, cps_p95,
                bps_mean, bps_p95,
                syn_ratio_mean, syn_ratio_stddev, syn_ratio_p95, syn_ratio_max,
                active_conn_mean, active_conn_p95, active_conn_max,
                outliers_removed, confidence_score, is_current
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, TRUE
            ) RETURNING baseline_id
        """, (
            origin_id, lookback_days, observation_start, observation_end, len(pps_clean),
            pps_mean, pps_stddev, pps_p50, pps_p95, pps_p99, pps_min, pps_max,
            cps_mean, cps_stddev, cps_p95,
            bps_mean, bps_p95,
            ratio_mean, ratio_stddev, ratio_p95, ratio_max,
            conn_mean, conn_p95, conn_max,
            outliers_removed, confidence
        ))

        baseline_id = cur.fetchone()['baseline_id']

        # Update baseline_config (last_recalc_at, next_recalc_at)
        if config:
            next_recalc = datetime.now(timezone.utc) + timedelta(days=1)
            cur.execute("""
                UPDATE baseline_config
                SET last_recalc_at = NOW(),
                    next_recalc_at = %s,
                    updated_at = NOW()
                WHERE origin_id = %s
            """, (next_recalc, origin_id))

        conn.commit()

        logger.info(f"Baseline {baseline_id} computed for {origin_id}: {len(pps_clean)} samples, confidence={confidence}, pps_mean={pps_mean}, pps_p95={pps_p95}")

        cur.close()

        return {
            'baseline_id': baseline_id,
            'origin_id': origin_id,
            'sample_count': len(pps_clean),
            'confidence_score': confidence,
            'pps_mean': pps_mean,
            'pps_p95': pps_p95,
            'syn_ratio_mean': ratio_mean,
            'syn_ratio_p95': ratio_p95
        }

    except Exception as e:
        logger.error(f"Failed to compute baseline for {origin_id}: {e}", exc_info=True)
        return None
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def should_recalculate(origin_id: str) -> bool:
    """
    Check if baseline should be recalculated for an origin

    Criteria:
    - auto_recalc_enabled = TRUE
    - next_recalc_at <= NOW() OR next_recalc_at is NULL
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT auto_recalc_enabled, next_recalc_at
            FROM baseline_config
            WHERE origin_id = %s
        """, (origin_id,))

        config = cur.fetchone()
        cur.close()

        if not config:
            return False  # No config, don't recalculate

        if not config['auto_recalc_enabled']:
            return False  # Auto recalc disabled

        if config['next_recalc_at'] is None:
            return True  # Never calculated, do it now

        return config['next_recalc_at'] <= datetime.now(timezone.utc)

    except Exception as e:
        logger.error(f"Failed to check recalculation status for {origin_id}: {e}")
        return False
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def baseline_learner_loop(interval_seconds=3600):
    """
    Main baseline learner loop

    Runs every hour (or specified interval):
    1. Get all origins from baseline_config
    2. For each origin, check if should_recalculate()
    3. If yes, compute_baseline_for_origin()
    4. Sleep interval_seconds

    Args:
        interval_seconds: Seconds between checks (default: 3600 = 1 hour)
    """
    logger.info(f"Baseline learner loop started (checking every {interval_seconds}s)")

    while True:
        try:
            # Get all origins with baseline config
            origins = []
            db = None
            try:
                db = get_db()
                conn = db.conn
                cur = conn.cursor(cursor_factory=RealDictCursor)

                cur.execute("SELECT origin_id FROM baseline_config ORDER BY origin_id")
                origins = [row['origin_id'] for row in cur.fetchall()]

                cur.close()
            finally:
                if db:
                    try:
                        db.close()
                    except Exception:
                        pass

            logger.debug(f"Checking {len(origins)} origins for baseline recalculation")

            for origin_id in origins:
                if should_recalculate(origin_id):
                    logger.info(f"Recalculating baseline for {origin_id}")
                    result = compute_baseline_for_origin(origin_id)
                    if result:
                        logger.info(f"Baseline updated for {origin_id}: confidence={result['confidence_score']}")
                    else:
                        logger.warning(f"Baseline calculation failed for {origin_id}")
                else:
                    logger.debug(f"Skipping {origin_id} (not scheduled for recalculation)")

        except Exception as e:
            logger.error(f"Baseline learner loop error: {e}", exc_info=True)

        # Sleep until next check
        logger.debug(f"Baseline learner sleeping for {interval_seconds}s")
        time.sleep(interval_seconds)

def start_baseline_learner_thread(interval_seconds=3600):
    """
    Start baseline learner as background thread

    Args:
        interval_seconds: Seconds between checks (default: 3600 = 1 hour)
    """
    thread = threading.Thread(
        target=baseline_learner_loop,
        args=(interval_seconds,),
        daemon=True,
        name='baseline-learner'
    )
    thread.start()
    logger.info("Baseline learner thread started")
    return thread

def main():
    """CLI entry point for standalone testing"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='Baseline learner service')
    parser.add_argument('--test-origin', type=str, help='Test with specific origin')
    parser.add_argument('--force-all', action='store_true', help='Force recalc all origins')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.test_origin:
        # Test mode: calculate baseline for specific origin
        logger.info(f"Testing baseline calculation for {args.test_origin}")
        result = compute_baseline_for_origin(args.test_origin)
        if result:
            logger.info(
                f"Baseline calculated: ID={result['baseline_id']} "
                f"samples={result['sample_count']} confidence={result['confidence_score']} "
                f"pps_mean={result['pps_mean']:,} pps_p95={result['pps_p95']:,} "
                f"syn_ratio_mean={result['syn_ratio_mean']:.2f} syn_ratio_p95={result['syn_ratio_p95']:.2f}"
            )
            return 0
        else:
            logger.error(f"Baseline calculation failed for {args.test_origin}")
            return 1

    elif args.force_all:
        # Force mode: recalculate all origins
        logger.info("Force recalculating all origins")
        origins = []
        db = None
        try:
            db = get_db()
            conn = db.conn
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT origin_id FROM origins")
            origins = [row['origin_id'] for row in cur.fetchall()]
            cur.close()
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass

        success_count = 0
        for origin_id in origins:
            logger.info(f"Calculating baseline for {origin_id}")
            result = compute_baseline_for_origin(origin_id)
            if result:
                success_count += 1

        logger.info(f"Baseline recalculation complete: {success_count}/{len(origins)} succeeded")
        return 0 if success_count == len(origins) else 1

    else:
        # Daemon mode: run continuous loop
        logger.info("Starting baseline learner in daemon mode")
        baseline_learner_loop()

if __name__ == '__main__':
    sys.exit(main())
