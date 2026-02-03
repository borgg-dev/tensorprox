#!/usr/bin/env python3
from shared.database import get_db_connection as get_db
"""
Layer 7: Anomaly Detection and Challenge Level Escalation

Runs every 30s, analyzes latest metrics against Layer 6 baselines,
detects anomalies using Z-score analysis, and automatically escalates/
de-escalates challenge levels with hysteresis.

Architecture:
- Pure Python in EMN (userspace)
- Updates BPF maps via bpftool/SSH (reuses existing functions)
- XDP enforces rate limiting (kernel space - no changes needed)
- Coordinates with Layers 3-6

Integration:
- Layer 6: Calls calculate_baseline_for_origin() for Z-score inputs
- Layer 5: Reads origin_metrics table for real-time data
- Layer 4: Updates syncookie_mode_map for SYN cookie engagement
- Layer 3: Updates origin_challenge_map for rate limiting

27 runtime-configurable parameters with hot-reload (no restart required)
"""

import logging
import threading
import time
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, Optional, List, Tuple
import json
from datetime import datetime

# Import baseline calculator (Layer 6)
from miner_control_plane.services.baseline_calculator import calculate_baseline_for_origin

# Import BPF map update functions (existing in automated_mitigation.py)
from miner_control_plane.services.automated_mitigation import (
    set_origin_challenge_via_bpf,
    set_global_challenge_via_bpf
)
from shared.utils.bpf_helpers import lookup_bpf_map, get_map_path
from shared.config import get_settings
from miner_control_plane.services.scrubber_utils import get_scrubber_nodes

logger = logging.getLogger('emn-anomaly-detector')

# Conntrack limit (for state exhaustion detection)
CONNTRACK_MAX = 262144
NS_PER_SEC = 1000000000

# Incident thresholds
BLACKLIST_SPIKE_THRESHOLD = 500  # drops per 30s interval


class AnomalyDetectorConfig:
    """
    Configuration manager with automatic hot-reload
    No restart required for config changes
    """
    def __init__(self):
        self.global_cache = {}
        self.last_reload = 0
        self.reload_interval = 60  # Seconds

    def get_global_config(self, force_reload=False) -> Dict:
        """Get global config with automatic cache refresh"""
        now = time.time()

        if force_reload or (now - self.last_reload) > self.reload_interval:
            db = None
            try:
                db = get_db()
                conn = db.conn
                cur = conn.cursor(cursor_factory=RealDictCursor)
                cur.execute("SELECT * FROM anomaly_detection_config WHERE config_id = 1")
                row = cur.fetchone()
                cur.close()

                if row:
                    self.global_cache = dict(row)
                    # Update reload interval from config
                    self.reload_interval = self.global_cache.get('config_reload_interval', 60)
                    self.last_reload = now
                    logger.debug(f"Anomaly detector config reloaded: {len(self.global_cache)} parameters")
                else:
                    logger.error("No config found in anomaly_detection_config table")
                    self.global_cache = {}

            except Exception as e:
                logger.error(f"Failed to reload config: {e}")
                self.global_cache = {}
            finally:
                if db:
                    try:
                        db.close()
                    except Exception:
                        pass

        defaults = {
            'fallback_pps_multiplier': 5.0,
            'fallback_pps_min': 20000,
            'fallback_cps_multiplier': 5.0,
            'fallback_cps_min': 2000,
            'fallback_syn_ratio_delta': 4.0,
            'min_pps_for_syn_flood': 100.0
        }
        for key, value in defaults.items():
            self.global_cache.setdefault(key, value)

        return self.global_cache

    def get_origin_config(self, origin_id: str) -> Dict:
        """
        Get effective config for origin (global + per-origin overrides)

        Returns merged configuration:
        - Starts with global defaults
        - Applies per-origin overrides (if not NULL)
        - Result: Effective config for this specific origin
        """
        global_config = self.get_global_config()
        db = None

        try:
            # Fetch per-origin overrides from baseline_config
            db = get_db()
            conn = db.conn
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                SELECT z_score_threshold, pps_multiplier_threshold,
                       cps_multiplier_threshold, syn_ratio_threshold,
                       level_3_to_2_delay, level_2_to_1_delay, level_1_to_0_delay
                FROM baseline_config
                WHERE origin_id = %s
            """, (origin_id,))
            overrides = cur.fetchone()
            cur.close()

            # Merge: override if not NULL, else use global
            merged = global_config.copy()
            if overrides:
                for key, value in dict(overrides).items():
                    if value is not None:
                        merged[key] = value
                        logger.debug(f"Origin {origin_id}: {key} overridden to {value}")

            return merged

        except Exception as e:
            logger.error(f"Failed to get origin config for {origin_id}: {e}")
            return global_config
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass


# Global config instance
config = AnomalyDetectorConfig()


def calculate_z_score(current_value: float, baseline_mean: float, baseline_stddev: float) -> float:
    """
    Calculate Z-score (standard deviations from mean)

    Args:
        current_value: Current metric value
        baseline_mean: Baseline mean from Layer 6
        baseline_stddev: Baseline standard deviation

    Returns:
        Z-score (float)
    """
    if baseline_stddev == 0:
        return 0.0
    return (current_value - baseline_mean) / baseline_stddev


def analyze_origin_metrics(origin_id: str, cfg: Dict) -> Tuple[Optional[str], float, Dict]:
    """
    Analyze origin metrics against baseline for anomaly detection

    Args:
        origin_id: Origin identifier
        cfg: Effective configuration for this origin

    Returns:
        (attack_type, confidence, details) or (None, 0.0, {}) if no anomaly
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get latest metrics (last 3 samples for consecutive breach tracking)
        cur.execute("""
            SELECT pps, cps, syn_synack_ratio, active_connections, timestamp,
                   drop_blacklist, drop_temp_blacklist, drop_ratelimit,
                   drop_quarantine, drop_bogon
            FROM origin_metrics
            WHERE origin_id = %s
              AND timestamp > NOW() - INTERVAL '2 minutes'
            ORDER BY timestamp DESC
            LIMIT 3
        """, (origin_id,))
        metrics_samples = cur.fetchall()

        if not metrics_samples:
            logger.debug(f"No recent metrics for {origin_id}")
            cur.close()
            return None, 0.0, {}

        latest_metric = metrics_samples[0]
        current_pps = float(latest_metric['pps']) if latest_metric['pps'] else 0
        current_cps = float(latest_metric['cps']) if latest_metric['cps'] else 0
        current_ratio = float(latest_metric['syn_synack_ratio']) if latest_metric['syn_synack_ratio'] else 0
        current_active_conns = latest_metric['active_connections'] or 0

        # Extract security drops
        drop_blacklist = latest_metric.get('drop_blacklist', 0) or 0
        drop_temp_blacklist = latest_metric.get('drop_temp_blacklist', 0) or 0
        total_blacklist_drops = drop_blacklist + drop_temp_blacklist

        # Calculate rate if we have previous sample
        blacklist_rate = 0
        if len(metrics_samples) >= 2:
            prev_metric = metrics_samples[1]
            prev_blacklist = (prev_metric.get('drop_blacklist', 0) or 0) + \
                            (prev_metric.get('drop_temp_blacklist', 0) or 0)
            dt = (latest_metric['timestamp'] - prev_metric['timestamp']).total_seconds()
            if dt > 0:
                blacklist_rate = (total_blacklist_drops - prev_blacklist) / dt * 30  # normalize to 30s

        # NEW: Check for blacklist spike FIRST (highest value visibility)
        blacklist_threshold = cfg.get('blacklist_spike_threshold', BLACKLIST_SPIKE_THRESHOLD)
        if blacklist_rate > blacklist_threshold:
            confidence = min(0.95, 0.7 + (blacklist_rate / blacklist_threshold) * 0.1)
            cur.close()
            return 'BLACKLIST_SPIKE', confidence, {
                'drop_blacklist': drop_blacklist,
                'drop_temp_blacklist': drop_temp_blacklist,
                'blacklist_rate_per_30s': round(blacklist_rate, 0),
                'threshold': blacklist_threshold,
                'trigger': 'blacklist_spike'
            }

        cur.close()

        # Get baseline from Layer 6
        baseline = calculate_baseline_for_origin(origin_id, lookback_days=7)

        # Use short-term deltas if no baseline and fallback enabled
        if not baseline and cfg.get('static_threshold_fallback', True):
            result = _evaluate_short_term_delta(metrics_samples, cfg, origin_id)
            if result:
                return result
            return None, 0.0, {}

        if not baseline:
            logger.warning(
                f"No baseline for {origin_id} and static_threshold_fallback=false, skipping detection"
            )
            return None, 0.0, {}

        # Calculate Z-scores
        pps_z = calculate_z_score(current_pps, baseline.get('pps_mean', 0), baseline.get('pps_stddev', 1))
        cps_z = calculate_z_score(current_cps, baseline.get('cps_mean', 0), baseline.get('cps_stddev', 1))

        # Check thresholds
        z_threshold = cfg.get('z_score_threshold', 3.0)
        pps_mult_threshold = cfg.get('pps_multiplier_threshold', 2.0)
        cps_mult_threshold = cfg.get('cps_multiplier_threshold', 3.0)
        ratio_threshold = cfg.get('syn_ratio_threshold', 10.0)
        active_conn_threshold = cfg.get('active_conn_threshold', 0.9)

        details = {
            'current_pps': current_pps,
            'baseline_pps_mean': baseline.get('pps_mean'),
            'pps_z_score': round(pps_z, 2),
            'current_ratio': round(current_ratio, 2),
            'current_cps': current_cps,
            'current_active_conns': current_active_conns
        }

        # Detection logic (ordered by severity)

        # 1. SYN Flood: ratio > threshold AND pps > minimum
        if current_ratio > ratio_threshold:
            # Require minimum PPS to avoid bootstrap false positives
            min_pps = cfg.get('min_pps_for_syn_flood', 100.0)
            if current_pps >= min_pps:
                confidence = min(0.95, 0.7 + (current_ratio / ratio_threshold) * 0.1)
                return 'SYN_FLOOD', confidence, {**details, 'trigger': 'syn_ratio'}
            else:
                logger.debug(f"{origin_id}: High SYN ratio ({current_ratio:.1f}) but low PPS ({current_pps}), likely bootstrap noise")

        # 2. State Exhaustion: active_connections > 90% of conntrack_max
        if current_active_conns > (CONNTRACK_MAX * active_conn_threshold):
            confidence = 0.95
            return 'STATE_EXHAUSTION', confidence, {**details, 'trigger': 'active_connections', 'conntrack_max': CONNTRACK_MAX}

        # 3. PPS Spike: Z > threshold AND pps > multiplier × mean
        if pps_z > z_threshold and current_pps > (baseline.get('pps_mean', 0) * pps_mult_threshold):
            confidence = min(0.9, 0.7 + (pps_z / z_threshold) * 0.1)
            return 'PPS_SPIKE', confidence, {**details, 'trigger': 'pps_z_score'}

        # 4. CPS Spike: current_cps > multiplier × mean
        if current_cps > (baseline.get('cps_mean', 0) * cps_mult_threshold):
            # Calculate CPS z-score for confidence
            cps_confidence = min(0.9, 0.7 + (cps_z / 3.0) * 0.1) if cps_z > 0 else 0.8
            return 'CPS_SPIKE', cps_confidence, {**details, 'trigger': 'cps_spike'}

        # No anomaly detected
        return None, 0.0, details

    except Exception as e:
        logger.error(f"Failed to analyze metrics for {origin_id}: {e}")
        return None, 0.0, {}
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def _evaluate_short_term_delta(
    samples: List[Dict],
    cfg: Dict,
    origin_id: str
) -> Optional[Tuple[str, float, Dict]]:
    """
    Derive attack signals from short-term deltas when no long-term baseline exists.

    Compares the latest sample to the oldest sample in the recent window (normally
    the last 2 minutes) and checks whether PPS/CPS/SYN ratios spiked relative to
    that short history.
    """
    if len(samples) < 2:
        return None

    latest = samples[0]
    reference = samples[-1]

    current_pps = float(latest['pps']) if latest['pps'] else 0.0
    reference_pps = float(reference['pps']) if reference['pps'] else 0.0
    current_cps = float(latest['cps']) if latest['cps'] else 0.0
    reference_cps = float(reference['cps']) if reference['cps'] else 0.0
    current_ratio = float(latest['syn_synack_ratio']) if latest['syn_synack_ratio'] else 0.0
    reference_ratio = float(reference['syn_synack_ratio']) if reference['syn_synack_ratio'] else 0.0

    # PPS delta
    fallback_pps_min = cfg.get('fallback_pps_min', 20000)
    fallback_pps_multiplier = cfg.get('fallback_pps_multiplier', 5.0)
    if reference_pps > 0 and current_pps >= fallback_pps_min:
        ratio = current_pps / max(reference_pps, 1.0)
        if ratio >= fallback_pps_multiplier:
            confidence = min(ratio / fallback_pps_multiplier, 1.0)
            logger.info(
                "Short-term PPS spike detected for %s (current=%.0f, reference=%.0f, ratio=%.2f)",
                origin_id, current_pps, reference_pps, ratio
            )
            return (
                'PPS_SPIKE_SHORT_TERM',
                confidence,
                {
                    'current_pps': current_pps,
                    'reference_pps': reference_pps,
                    'ratio': ratio,
                    'method': 'short_term_delta'
                }
            )

    # CPS delta
    fallback_cps_min = cfg.get('fallback_cps_min', 2000)
    fallback_cps_multiplier = cfg.get('fallback_cps_multiplier', 5.0)
    if reference_cps > 0 and current_cps >= fallback_cps_min:
        ratio = current_cps / max(reference_cps, 1.0)
        if ratio >= fallback_cps_multiplier:
            confidence = min(ratio / fallback_cps_multiplier, 1.0)
            logger.info(
                "Short-term CPS spike detected for %s (current=%.0f, reference=%.0f, ratio=%.2f)",
                origin_id, current_cps, reference_cps, ratio
            )
            return (
                'CPS_SPIKE_SHORT_TERM',
                confidence,
                {
                    'current_cps': current_cps,
                    'reference_cps': reference_cps,
                    'ratio': ratio,
                    'method': 'short_term_delta'
                }
            )

    # SYN ratio delta
    fallback_ratio_delta = cfg.get('fallback_syn_ratio_delta', 4.0)
    ratio_delta = current_ratio - reference_ratio
    if current_ratio >= cfg.get('syn_ratio_threshold', 10.0) and ratio_delta >= fallback_ratio_delta:
        logger.info(
            "Short-term SYN ratio delta detected for %s (current=%.1f, reference=%.1f, delta=%.1f)",
            origin_id, current_ratio, reference_ratio, ratio_delta
        )
        return (
            'SYN_RATIO_SPIKE_SHORT_TERM',
            0.8,
            {
                'current_ratio': current_ratio,
                'reference_ratio': reference_ratio,
                'delta': ratio_delta,
                'method': 'short_term_delta'
            }
        )

    return None


def update_anomaly_state(origin_id: str, metric_type: str, is_breach: bool) -> int:
    """
    Update consecutive breach counter

    Args:
        origin_id: Origin identifier
        metric_type: 'pps', 'cps', 'ratio', or 'state_exhaust'
        is_breach: True if threshold breached, False to reset

    Returns:
        Current breach_count after update
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        field_name = f"{metric_type}_breach_count"

        if is_breach:
            # Increment breach count
            cur.execute(f"""
                INSERT INTO anomaly_detection_state (origin_id, {field_name}, last_breach_timestamp)
                VALUES (%s, 1, NOW())
                ON CONFLICT (origin_id) DO UPDATE SET
                    {field_name} = anomaly_detection_state.{field_name} + 1,
                    last_breach_timestamp = NOW(),
                    last_check_timestamp = NOW()
                RETURNING {field_name}
            """, (origin_id,))
        else:
            # Reset breach count
            cur.execute(f"""
                INSERT INTO anomaly_detection_state (origin_id, {field_name})
                VALUES (%s, 0)
                ON CONFLICT (origin_id) DO UPDATE SET
                    {field_name} = 0,
                    last_check_timestamp = NOW()
                RETURNING {field_name}
            """, (origin_id,))

        result = cur.fetchone()
        breach_count = result[field_name] if result else 0

        conn.commit()
        cur.close()

        return breach_count

    except Exception as e:
        logger.error(f"Failed to update anomaly state for {origin_id}.{metric_type}: {e}")
        return 0
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def calculate_attack_confidence(attack_type: str, z_score: float, cfg: Dict) -> float:
    """
    Calculate detection confidence based on conditions met

    Args:
        attack_type: Type of attack detected
        z_score: Z-score value
        cfg: Configuration

    Returns:
        Confidence 0.7-0.99
    """
    base_confidence = 0.7

    # Z-score contribution (higher z-score = higher confidence)
    if z_score > cfg.get('z_score_threshold', 3.0):
        z_contribution = min(0.15, (z_score / cfg.get('z_score_threshold', 3.0)) * 0.05)
        base_confidence += z_contribution

    # Attack type confidence
    type_confidence = {
        'SYN_FLOOD': 0.15,
        'STATE_EXHAUSTION': 0.10,
        'PPS_SPIKE': 0.10,
        'CPS_SPIKE': 0.08
    }
    base_confidence += type_confidence.get(attack_type, 0.05)

    # Cap at 0.99
    return min(0.99, base_confidence)


def create_attack_event(origin_id: str, attack_type: str, confidence: float, details: Dict, cfg: Dict) -> Optional[int]:
    """
    Create attack_events row in database

    Args:
        origin_id: Origin identifier
        attack_type: Attack type (PPS_SPIKE, SYN_FLOOD, etc.)
        confidence: Detection confidence 0.7-0.99
        details: Additional metadata
        cfg: Configuration

    Returns:
        event_id if created, None on error
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Check if there's already an active event of this type
        cur.execute("""
            SELECT event_id
            FROM attack_events
            WHERE origin_id = %s
              AND attack_type = %s
              AND mitigation_active = true
            LIMIT 1
        """, (origin_id, attack_type))
        existing_event = cur.fetchone()

        if existing_event:
            # Update existing event (peak values)
            event_id = existing_event['event_id']
            cur.execute("""
                UPDATE attack_events
                SET peak_pps = GREATEST(COALESCE(peak_pps, 0), %s),
                    peak_cps = GREATEST(COALESCE(peak_cps, 0), %s),
                    peak_active_connections = GREATEST(COALESCE(peak_active_connections, 0), %s),
                    samples_breached = COALESCE(samples_breached, 0) + 1,
                    updated_at = NOW()
                WHERE event_id = %s
            """, (
                int(details.get('current_pps', 0)),
                int(details.get('current_cps', 0)),
                details.get('current_active_conns', 0),
                event_id
            ))
            conn.commit()
            logger.debug(f"Updated existing attack event {event_id} for {origin_id}")

        else:
            # Create new attack event
            cur.execute("""
                INSERT INTO attack_events (
                    origin_id, detected_at, attack_type, peak_pps, peak_cps,
                    peak_active_connections, confidence, mitigation_active,
                    baseline_deviation_zscore, samples_breached, details
                )
                VALUES (%s, NOW(), %s, %s, %s, %s, %s, true, %s, %s, %s)
                RETURNING event_id
            """, (
                origin_id,
                attack_type,
                int(details.get('current_pps', 0)),
                int(details.get('current_cps', 0)),
                details.get('current_active_conns', 0),
                confidence,
                details.get('pps_z_score', 0),
                cfg.get('consecutive_samples_to_activate', 3),
                json.dumps(details)
            ))
            result = cur.fetchone()
            event_id = result['event_id'] if result else None
            conn.commit()
            logger.info(f"Created attack event {event_id} for {origin_id}: {attack_type} (confidence={confidence:.2f})")

        cur.close()
        return event_id

    except Exception as e:
        logger.error(f"Failed to create attack event for {origin_id}: {e}")
        return None
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def escalate_challenge_level(origin_id: str, new_level: int, attack_type: str, event_id: int) -> bool:
    """
    Escalate challenge level with database update and BPF map synchronization

    Args:
        origin_id: Origin identifier
        new_level: New challenge level (0-4)
        attack_type: Attack type that triggered escalation
        event_id: Associated attack event ID

    Returns:
        True if successful
    """
    db = None
    origin_ip = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get origin IP for BPF map update
        cur.execute("SELECT origin_ip FROM origins WHERE origin_id = %s", (origin_id,))
        row = cur.fetchone()
        if not row:
            logger.error(f"Origin {origin_id} not found")
            cur.close()
            return False

        origin_ip = row['origin_ip']

        # Update anomaly_detection_state
        cur.execute("""
            UPDATE anomaly_detection_state
            SET current_challenge_level = %s,
                escalation_timestamp = NOW(),
                active_attack_event_id = %s,
                updated_at = NOW()
            WHERE origin_id = %s
        """, (new_level, event_id, origin_id))

        # Update attack event with peak level
        cur.execute("""
            UPDATE attack_events
            SET challenge_level_peak = GREATEST(COALESCE(challenge_level_peak, 0), %s),
                updated_at = NOW()
            WHERE event_id = %s
        """, (new_level, event_id))

        conn.commit()
        cur.close()

    except Exception as e:
        logger.error(f"Failed to escalate challenge level for {origin_id}: {e}")
        return False
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

    # Update BPF maps (reuses existing function from automated_mitigation.py)
    # Done outside the DB block to release the connection first
    if origin_ip:
        success = set_origin_challenge_via_bpf(origin_ip, new_level)

        if success:
            logger.info(f"Challenge level escalated: {origin_id} → level {new_level} ({attack_type})")
        else:
            logger.error(f"Failed to update BPF maps for {origin_id}")

        return success

    return False


def deescalate_challenge_level(origin_id: str, cfg: Dict) -> bool:
    """
    Gradual de-escalation with hysteresis

    Checks if de-escalation is eligible based on:
    - Metrics below threshold
    - Sufficient time elapsed (hysteresis delay)
    - Only drops 1 level at a time

    Args:
        origin_id: Origin identifier
        cfg: Effective configuration

    Returns:
        True if de-escalation occurred
    """
    db = None
    origin_ip = None
    new_level = None
    current_level = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get current state
        cur.execute("""
            SELECT current_challenge_level, deescalation_eligible_at, active_attack_event_id
            FROM anomaly_detection_state
            WHERE origin_id = %s
        """, (origin_id,))
        state = cur.fetchone()

        if not state or state['current_challenge_level'] == 0:
            cur.close()
            return False  # Already at level 0

        current_level = state['current_challenge_level']
        eligible_at = state['deescalation_eligible_at']
        event_id = state['active_attack_event_id']

        # Check if de-escalation is eligible
        now = datetime.now()
        if eligible_at and now < eligible_at:
            # Not yet eligible (hysteresis timer)
            cur.close()
            return False

        # De-escalate one level
        new_level = current_level - 1

        # Get origin IP
        cur.execute("SELECT origin_ip FROM origins WHERE origin_id = %s", (origin_id,))
        row = cur.fetchone()
        origin_ip = row['origin_ip'] if row else None

        if not origin_ip:
            cur.close()
            return False

        # Calculate next de-escalation eligibility time
        delay_map = {
            2: cfg.get('level_3_to_2_delay', 300),   # 5 min
            1: cfg.get('level_2_to_1_delay', 600),   # 10 min
            0: cfg.get('level_1_to_0_delay', 1200)   # 20 min
        }
        next_delay = delay_map.get(new_level, 600)

        # Update state
        if new_level == 0:
            # Returning to normal - end attack event
            cur.execute("""
                UPDATE anomaly_detection_state
                SET current_challenge_level = 0,
                    deescalation_eligible_at = NULL,
                    active_attack_event_id = NULL,
                    updated_at = NOW()
                WHERE origin_id = %s
            """, (origin_id,))

            if event_id:
                cur.execute("""
                    UPDATE attack_events
                    SET ended_at = NOW(),
                        mitigation_active = false,
                        updated_at = NOW()
                    WHERE event_id = %s
                """, (event_id,))
        else:
            # Intermediate de-escalation
            cur.execute("""
                UPDATE anomaly_detection_state
                SET current_challenge_level = %s,
                    deescalation_eligible_at = NOW() + INTERVAL '%s seconds',
                    updated_at = NOW()
                WHERE origin_id = %s
            """, (new_level, next_delay, origin_id))

        conn.commit()
        cur.close()

    except Exception as e:
        logger.error(f"Failed to de-escalate challenge level for {origin_id}: {e}")
        return False
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

    # Update BPF maps (done outside DB block to release connection first)
    if origin_ip is not None and new_level is not None:
        set_origin_challenge_via_bpf(origin_ip, new_level)
        logger.info(f"Challenge level de-escalated: {origin_id} {current_level}→{new_level}")
        return True

    return False


def get_global_challenge_level() -> int:
    """
    Read current global challenge level from BPF map on first available scrubber.

    Returns:
        Current global challenge level (0-4), or 0 if unable to read
    """
    try:
        nodes = get_scrubber_nodes()
        if not nodes:
            logger.debug("No scrubbers available to read global challenge level")
            return 0

        settings = get_settings()
        map_path = get_map_path('challenge_level')
        key_hex = "00 00 00 00"

        # Try first available node
        for node in nodes:
            host_ip = node.get('host_ip')
            if not host_ip:
                continue

            provider = node.get('provider', 'aws')
            success, payload, error = lookup_bpf_map(
                host=host_ip,
                map_path=map_path,
                key_hex=key_hex,
                ssh_key_path=settings.ssh_key_path,
                provider=provider
            )

            if success and payload:
                # Parse the value - it's a 32-bit little-endian integer
                # bpftool -j returns: {"key": [...], "value": [...]}
                # Note: bpftool may return hex strings ("0x00") or integers (0)
                value_bytes = payload.get('value', [])
                if value_bytes and len(value_bytes) >= 1:
                    # First byte is the challenge level in little-endian u32
                    level = value_bytes[0]
                    # Handle hex strings from bpftool (e.g., "0x00" -> 0)
                    if isinstance(level, str):
                        level = int(level, 16)
                    logger.debug(f"Global challenge level read from {node['node_id']}: {level}")
                    return level

            logger.debug(f"Could not read global challenge level from {node['node_id']}: {error}")

        return 0  # Default to NORMAL if cannot read

    except Exception as e:
        logger.error(f"Failed to get global challenge level: {e}")
        return 0


def check_global_escalation(cfg: Dict) -> bool:
    """
    Check if multi-origin attack requires global challenge level 4

    Args:
        cfg: Configuration

    Returns:
        True if global escalation occurred
    """
    if not cfg.get('enable_global_escalation', True):
        return False

    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Count origins with active attacks (challenge_level >= 2)
        cur.execute("""
            SELECT COUNT(*) as count
            FROM anomaly_detection_state
            WHERE current_challenge_level >= 2
        """)
        row = cur.fetchone()
        origins_under_attack = row['count'] if row else 0

        multi_origin_threshold = cfg.get('multi_origin_threshold', 3)

        if origins_under_attack >= multi_origin_threshold:
            # Platform-wide attack detected
            logger.warning(f"Multi-origin attack detected: {origins_under_attack} origins breached (threshold={multi_origin_threshold})")

            # Set global challenge level to 4
            set_global_challenge_via_bpf(4)

            # Update all origins to level 4
            cur.execute("""
                UPDATE anomaly_detection_state
                SET current_challenge_level = 4,
                    escalation_timestamp = NOW()
            """)

            # Create attack events for multi-origin attack
            cur.execute("""
                INSERT INTO attack_events (origin_id, attack_type, confidence, details)
                SELECT origin_id, 'MULTI_ORIGIN_ATTACK', 0.99,
                       json_build_object('origins_affected', %s)::jsonb
                FROM origins
                WHERE origin_id NOT IN (
                    SELECT origin_id FROM attack_events WHERE mitigation_active = true
                )
            """, (origins_under_attack,))

            conn.commit()
            cur.close()

            logger.critical(f"GLOBAL CHALLENGE LEVEL 4 (EMERGENCY) activated: {origins_under_attack} origins under attack")
            return True

        cur.close()
        return False

    except Exception as e:
        logger.error(f"Failed to check global escalation: {e}")
        return False
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def deescalate_global_challenge(cfg: Dict) -> bool:
    """
    De-escalate global challenge level when multi-origin attack subsides.

    Called every 30s during anomaly detection loop.
    Uses hysteresis to prevent oscillation.

    Args:
        cfg: Configuration dict with thresholds

    Returns:
        True if de-escalation occurred
    """
    # Get current global level from challenge_level_map
    global_level = get_global_challenge_level()

    if global_level == 0:
        return False  # Already at NORMAL, nothing to do

    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Count origins still under attack (level >= 2)
        cur.execute("""
            SELECT COUNT(*) as count FROM anomaly_detection_state
            WHERE current_challenge_level >= 2
        """)
        row = cur.fetchone()
        origins_under_attack = row['count'] if row else 0
        cur.close()

        # Threshold for de-escalation (hysteresis)
        deescalate_threshold = cfg.get('global_deescalate_threshold', 1)

        if origins_under_attack <= deescalate_threshold:
            # Safe to de-escalate one level
            new_level = max(0, global_level - 1)

            set_global_challenge_via_bpf(new_level)

            logger.info(
                f"Global challenge de-escalated: {global_level} -> {new_level} "
                f"(only {origins_under_attack} origins still under attack)"
            )
            return True

        return False

    except Exception as e:
        logger.error(f"Global de-escalation error: {e}")
        return False
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def anomaly_detection_loop():
    """
    Main anomaly detection loop (runs every 30s)

    For each origin:
    1. Fetch latest metrics
    2. Fetch baseline (Layer 6)
    3. Calculate Z-scores
    4. Check breach thresholds
    5. Track consecutive breaches
    6. Escalate/de-escalate challenge levels
    7. Create/update attack events
    """
    logger.info("Anomaly detection loop started")

    while True:
        try:
            # Get global config (auto-reloads every 60s)
            global_cfg = config.get_global_config()

            # Check if auto-escalation is enabled
            if not global_cfg.get('enable_auto_escalation', True):
                logger.debug("Auto-escalation disabled, skipping detection")
                time.sleep(global_cfg.get('loop_interval', 30))
                continue

            # Get active origins
            origins = []
            db = None
            try:
                db = get_db()
                conn = db.conn
                cur = conn.cursor(cursor_factory=RealDictCursor)
                cur.execute("SELECT origin_id, state FROM origins WHERE state = 'IN_SERVICE'")
                origins = cur.fetchall()
                cur.close()
            finally:
                if db:
                    try:
                        db.close()
                    except Exception:
                        pass

            for origin in origins:
                origin_id = origin['origin_id']

                # Get effective config for this origin (global + overrides)
                cfg = config.get_origin_config(origin_id)

                # Analyze metrics
                attack_type, confidence, details = analyze_origin_metrics(origin_id, cfg)

                if attack_type:
                    # Anomaly detected - update breach counter
                    metric_type_map = {
                        'PPS_SPIKE': 'pps',
                        'CPS_SPIKE': 'cps',
                        'SYN_FLOOD': 'ratio',
                        'STATE_EXHAUSTION': 'state_exhaust',
                        'BLACKLIST_SPIKE': 'blacklist'
                    }
                    metric_type = metric_type_map.get(attack_type, 'pps')
                    breach_count = update_anomaly_state(origin_id, metric_type, is_breach=True)

                    logger.info(f"{origin_id}: {attack_type} detected (confidence={confidence:.2f}, breach_count={breach_count})")

                    # Check if consecutive threshold reached
                    consecutive_threshold = cfg.get('consecutive_samples_to_activate', 3)
                    if breach_count >= consecutive_threshold:
                        # Create or update attack event
                        event_id = create_attack_event(origin_id, attack_type, confidence, details, cfg)

                        if event_id:
                            # Escalate challenge level
                            escalation_map = {
                                'PPS_SPIKE': cfg.get('pps_spike_level', 2),
                                'SYN_FLOOD': cfg.get('syn_flood_level', 3),
                                'CPS_SPIKE': cfg.get('cps_spike_level', 2),
                                'STATE_EXHAUSTION': cfg.get('state_exhaustion_level', 3),
                                'BLACKLIST_SPIKE': cfg.get('blacklist_spike_level', 2)
                            }
                            target_level = escalation_map.get(attack_type, 2)

                            escalate_challenge_level(origin_id, target_level, attack_type, event_id)

                else:
                    # No anomaly - reset breach counters and check for de-escalation
                    for metric in ['pps', 'cps', 'ratio', 'state_exhaust']:
                        update_anomaly_state(origin_id, metric, is_breach=False)

                    # Attempt de-escalation if enabled
                    if global_cfg.get('enable_auto_deescalation', True):
                        deescalate_challenge_level(origin_id, cfg)

            # Check for multi-origin attack (global escalation)
            check_global_escalation(global_cfg)

            # Check for global de-escalation
            if global_cfg.get('enable_global_deescalation', True):
                deescalate_global_challenge(global_cfg)

        except Exception as e:
            logger.error(f"Anomaly detection loop error: {e}")

        # Sleep until next iteration
        loop_interval = global_cfg.get('loop_interval', 30)
        time.sleep(loop_interval)


def start_anomaly_detector_thread():
    """
    Start anomaly detection background thread

    This thread runs continuously, analyzing metrics every 30s and
    automatically escalating/de-escalating challenge levels based on
    detected anomalies.
    """
    thread = threading.Thread(target=anomaly_detection_loop, daemon=True)
    thread.start()
    logger.info("Anomaly detector thread started: analyzing metrics every 30s")
    return thread
