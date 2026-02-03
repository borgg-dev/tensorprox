"""
Layer 7 Audit API - Endpoints for L7 attack detection verification.

Provides endpoints for validators to:
1. Query L7 detection metrics (rate-limited IPs, blocked connections)
2. Get connection pattern analysis
3. Verify L7 protection capabilities

This integrates with the anomaly detector's existing L7 detection:
- SYN flood detection (high SYN/SYN-ACK ratio)
- State exhaustion detection (high active connections)
- Connection rate spike detection (CPS anomalies)
"""

import logging
import time
import json
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
import psycopg2.extras
from shared.database import get_db_connection
from shared.config import get_settings
from miner_control_plane.services.state_manager import state_manager

bp = Blueprint('l7_audit', __name__, url_prefix='/api/v1')
logger = logging.getLogger(__name__)
settings = get_settings()


@bp.route('/l7/detection-metrics', methods=['GET'])
def get_l7_detection_metrics():
    """
    Get Layer 7 detection metrics for audit verification.

    Returns metrics that indicate L7 attack detection and response:
    - rate_limited_ips: Source IPs that triggered rate limiting
    - blocked_connection_ips: IPs blocked for connection patterns
    - high_syn_rate_ips: IPs with suspicious SYN rates
    - connection_completion_rate: Overall connection completion rate
    - current_challenge_levels: Per-origin challenge levels

    Query params:
        window_seconds: Time window for metrics (default: 120)
        origin_id: Filter to specific origin (optional)

    Returns:
        {
            "rate_limited_ips": ["1.2.3.4", "5.6.7.8"],
            "blocked_connection_ips": ["1.2.3.4"],
            "high_syn_rate_ips": ["1.2.3.4", "5.6.7.8"],
            "connection_metrics": {
                "syn_count": 1000,
                "synack_count": 800,
                "completion_rate": 0.8,
                "active_connections": 5000
            },
            "challenge_levels": {
                "O1": 2,
                "O2": 0
            },
            "attack_events": [...],
            "timestamp": 1699999999.123
        }
    """
    try:
        window_seconds = int(request.args.get('window_seconds', 120))
        origin_id = request.args.get('origin_id')

        db = get_db_connection()
        cur = db.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        result = {
            "rate_limited_ips": [],
            "blocked_connection_ips": [],
            "high_syn_rate_ips": [],
            "connection_metrics": {},
            "challenge_levels": {},
            "attack_events": [],
            "l7_detection_capabilities": {
                "slowloris": True,
                "http_flood": True,
                "state_exhaustion": True,
            },
            "timestamp": time.time()
        }

        # Get rate-limited IPs from temp_blacklist (auto-mitigation)
        cur.execute("""
            SELECT DISTINCT ip_address
            FROM temp_blacklist
            WHERE created_at > NOW() - INTERVAL '%s seconds'
              AND expires_at > NOW()
        """, (window_seconds,))
        result["rate_limited_ips"] = [row['ip_address'] for row in cur.fetchall()]

        # Get IPs from mitigation_actions (rate limit penalties)
        cur.execute("""
            SELECT DISTINCT ip_address
            FROM mitigation_actions
            WHERE timestamp > NOW() - INTERVAL '%s seconds'
              AND action_type IN ('ratelimit_penalty', 'temp_blacklist')
        """, (window_seconds,))
        blocked_ips = [row['ip_address'] for row in cur.fetchall()]
        result["blocked_connection_ips"] = blocked_ips

        # Get IPs flagged for high SYN rate from ip_attack_signatures
        cur.execute("""
            SELECT DISTINCT ip_address
            FROM ip_attack_signatures
            WHERE timestamp > NOW() - INTERVAL '%s seconds'
              AND attack_score >= 30
              AND (
                  attack_types && ARRAY['syn_flood', 'cps_spike', 'http_flood']
                  OR attack_types && ARRAY['slowloris', 'state_exhaustion']
              )
        """, (window_seconds,))
        result["high_syn_rate_ips"] = [row['ip_address'] for row in cur.fetchall()]

        # Get connection metrics from latest origin_metrics
        origin_filter = "AND origin_id = %s" if origin_id else ""
        params = [window_seconds]
        if origin_id:
            params.append(origin_id)

        cur.execute(f"""
            SELECT
                SUM(ingress_syn_count) as total_syn,
                SUM(egress_synack_count) as total_synack,
                SUM(active_connections) as total_active,
                AVG(syn_synack_ratio) as avg_ratio,
                AVG(cps) as avg_cps,
                AVG(pps) as avg_pps
            FROM origin_metrics
            WHERE timestamp > NOW() - INTERVAL '%s seconds'
            {origin_filter}
        """, params)
        metrics = cur.fetchone()

        if metrics:
            syn_count = int(metrics['total_syn'] or 0)
            synack_count = int(metrics['total_synack'] or 0)
            completion_rate = synack_count / syn_count if syn_count > 0 else 1.0

            result["connection_metrics"] = {
                "syn_count": syn_count,
                "synack_count": synack_count,
                "completion_rate": round(completion_rate, 3),
                "active_connections": int(metrics['total_active'] or 0),
                "avg_syn_synack_ratio": round(float(metrics['avg_ratio'] or 1.0), 2),
                "avg_cps": round(float(metrics['avg_cps'] or 0), 2),
                "avg_pps": round(float(metrics['avg_pps'] or 0), 2),
            }

        # Get current challenge levels per origin
        cur.execute("""
            SELECT origin_id, current_challenge_level
            FROM anomaly_detection_state
        """)
        for row in cur.fetchall():
            result["challenge_levels"][row['origin_id']] = row['current_challenge_level']

        # Get recent attack events
        cur.execute("""
            SELECT origin_id, attack_type, confidence, detected_at,
                   peak_pps, peak_cps, peak_active_connections,
                   challenge_level_peak, mitigation_active
            FROM attack_events
            WHERE detected_at > NOW() - INTERVAL '%s seconds'
            ORDER BY detected_at DESC
            LIMIT 20
        """, (window_seconds,))

        for row in cur.fetchall():
            result["attack_events"].append({
                "origin_id": row['origin_id'],
                "attack_type": row['attack_type'],
                "confidence": float(row['confidence']) if row['confidence'] else 0,
                "detected_at": row['detected_at'].isoformat() if row['detected_at'] else None,
                "peak_pps": row['peak_pps'],
                "peak_cps": row['peak_cps'],
                "peak_active_connections": row['peak_active_connections'],
                "challenge_level": row['challenge_level_peak'],
                "active": row['mitigation_active'],
            })

        cur.close()
        db.conn.close()

        return jsonify(result)

    except Exception as e:
        logger.error(f"L7 detection metrics error: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route('/l7/connection-patterns', methods=['GET'])
def get_connection_patterns():
    """
    Get connection pattern analysis for L7 audit.

    Returns patterns that indicate L7 attacks:
    - Slowloris: High SYN/low completion, long connection times
    - HTTP Flood: High CPS from single IPs
    - State Exhaustion: Many half-open connections

    Query params:
        window_seconds: Time window (default: 300)
        limit: Max IPs to return (default: 50)

    Returns:
        {
            "slowloris_indicators": {
                "detected": true,
                "ips": ["1.2.3.4"],
                "avg_completion_rate": 0.3
            },
            "http_flood_indicators": {
                "detected": true,
                "high_rate_ips": ["5.6.7.8"],
                "peak_cps": 500
            },
            "state_exhaustion_indicators": {
                "detected": false,
                "half_open_ratio": 0.1,
                "active_connections": 5000
            }
        }
    """
    try:
        window_seconds = int(request.args.get('window_seconds', 300))
        limit = int(request.args.get('limit', 50))

        db = get_db_connection()
        cur = db.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        result = {
            "slowloris_indicators": {
                "detected": False,
                "ips": [],
                "avg_completion_rate": 1.0,
                "evidence": []
            },
            "http_flood_indicators": {
                "detected": False,
                "high_rate_ips": [],
                "peak_cps": 0,
                "evidence": []
            },
            "state_exhaustion_indicators": {
                "detected": False,
                "half_open_ratio": 0.0,
                "active_connections": 0,
                "evidence": []
            },
            "timestamp": time.time()
        }

        # Check for Slowloris pattern: high SYN/SYN-ACK ratio (low completion)
        cur.execute("""
            SELECT origin_id, syn_synack_ratio, ingress_syn_count, egress_synack_count
            FROM origin_metrics
            WHERE timestamp > NOW() - INTERVAL '%s seconds'
              AND syn_synack_ratio > 5
            ORDER BY syn_synack_ratio DESC
            LIMIT 10
        """, (window_seconds,))
        slowloris_data = cur.fetchall()

        if slowloris_data:
            result["slowloris_indicators"]["detected"] = True
            avg_ratio = sum(float(r['syn_synack_ratio']) for r in slowloris_data) / len(slowloris_data)
            result["slowloris_indicators"]["avg_completion_rate"] = round(1.0 / avg_ratio if avg_ratio > 0 else 0, 3)
            result["slowloris_indicators"]["evidence"] = [
                f"High SYN/SYN-ACK ratio ({r['syn_synack_ratio']:.1f}) on {r['origin_id']}"
                for r in slowloris_data[:3]
            ]

        # Get IPs associated with Slowloris-like patterns
        cur.execute("""
            SELECT DISTINCT ip_address
            FROM ip_attack_signatures
            WHERE timestamp > NOW() - INTERVAL '%s seconds'
              AND (attack_types && ARRAY['slowloris', 'http_slow'] OR attack_score >= 40)
            LIMIT %s
        """, (window_seconds, limit))
        result["slowloris_indicators"]["ips"] = [r['ip_address'] for r in cur.fetchall()]

        # Check for HTTP Flood pattern: high CPS
        cur.execute("""
            SELECT origin_id, cps, pps
            FROM origin_metrics
            WHERE timestamp > NOW() - INTERVAL '%s seconds'
              AND cps > 100
            ORDER BY cps DESC
            LIMIT 10
        """, (window_seconds,))
        flood_data = cur.fetchall()

        if flood_data:
            result["http_flood_indicators"]["detected"] = True
            result["http_flood_indicators"]["peak_cps"] = int(max(r['cps'] for r in flood_data))
            result["http_flood_indicators"]["evidence"] = [
                f"High CPS ({r['cps']:.0f}) on {r['origin_id']}"
                for r in flood_data[:3]
            ]

        # Get IPs with high connection rates
        cur.execute("""
            SELECT DISTINCT ip_address
            FROM ip_attack_signatures
            WHERE timestamp > NOW() - INTERVAL '%s seconds'
              AND (attack_types && ARRAY['http_flood', 'cps_spike'] OR attack_score >= 50)
            LIMIT %s
        """, (window_seconds, limit))
        result["http_flood_indicators"]["high_rate_ips"] = [r['ip_address'] for r in cur.fetchall()]

        # Check for State Exhaustion: high active connections
        CONNTRACK_MAX = 262144  # Standard Linux conntrack limit

        cur.execute("""
            SELECT origin_id, active_connections, ingress_syn_count, egress_synack_count
            FROM origin_metrics
            WHERE timestamp > NOW() - INTERVAL '%s seconds'
            ORDER BY active_connections DESC
            LIMIT 5
        """, (window_seconds,))
        state_data = cur.fetchall()

        if state_data:
            max_active = max(int(r['active_connections'] or 0) for r in state_data)
            result["state_exhaustion_indicators"]["active_connections"] = max_active

            # Calculate half-open ratio
            total_syn = sum(int(r['ingress_syn_count'] or 0) for r in state_data)
            total_synack = sum(int(r['egress_synack_count'] or 0) for r in state_data)
            if total_syn > 0:
                result["state_exhaustion_indicators"]["half_open_ratio"] = round(
                    1.0 - (total_synack / total_syn), 3
                )

            if max_active > CONNTRACK_MAX * 0.7:  # 70% of limit
                result["state_exhaustion_indicators"]["detected"] = True
                result["state_exhaustion_indicators"]["evidence"] = [
                    f"Active connections ({max_active}) approaching limit ({CONNTRACK_MAX})"
                ]

        cur.close()
        db.conn.close()

        return jsonify(result)

    except Exception as e:
        logger.error(f"Connection patterns error: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route('/l7/audit-proof', methods=['POST'])
def submit_l7_audit_proof():
    """
    Submit L7 audit stats for validator verification.

    Called by the miner's audit handler when a validator requests L7 stats.
    Returns connection-level decisions made during the audit window.

    Request body:
    {
        "challenge_id": "l7-abc123-1699999999",
        "window_start": 1699999900.0,
        "window_end": 1699999999.0
    }

    Returns:
    {
        "challenge_id": "...",
        "stats": {
            "rate_limited_ips": ["1.2.3.4"],
            "blocked_ips": ["1.2.3.4"],
            "detection_events": [...]
        },
        "connection_metrics": {...}
    }
    """
    try:
        data = request.json
        challenge_id = data.get('challenge_id')
        window_start = data.get('window_start', time.time() - 120)
        window_end = data.get('window_end', time.time())

        if not challenge_id:
            return jsonify({"error": "challenge_id required"}), 400

        # Convert timestamps to datetime
        start_dt = datetime.fromtimestamp(window_start)
        end_dt = datetime.fromtimestamp(window_end)

        db = get_db_connection()
        cur = db.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        proofs = {
            "rate_limited_ips": [],
            "blocked_ips": [],
            "detection_events": [],
        }

        # Get IPs that were rate-limited during the audit window
        cur.execute("""
            SELECT ip_address, action_type, attack_score, timestamp
            FROM mitigation_actions
            WHERE timestamp BETWEEN %s AND %s
            ORDER BY timestamp
        """, (start_dt, end_dt))

        for row in cur.fetchall():
            if row['action_type'] == 'ratelimit_penalty':
                proofs["rate_limited_ips"].append(row['ip_address'])
            elif row['action_type'] in ('temp_blacklist', 'perm_blacklist'):
                proofs["blocked_ips"].append(row['ip_address'])

        # Get attack detection events during window
        cur.execute("""
            SELECT origin_id, attack_type, confidence, detected_at,
                   peak_cps, peak_pps, challenge_level_peak
            FROM attack_events
            WHERE detected_at BETWEEN %s AND %s
        """, (start_dt, end_dt))

        for row in cur.fetchall():
            proofs["detection_events"].append({
                "origin_id": row['origin_id'],
                "attack_type": row['attack_type'],
                "confidence": float(row['confidence']) if row['confidence'] else 0,
                "detected_at": row['detected_at'].isoformat() if row['detected_at'] else None,
                "peak_cps": row['peak_cps'],
                "peak_pps": row['peak_pps'],
                "challenge_level": row['challenge_level_peak'],
            })

        # Get connection metrics for the window
        cur.execute("""
            SELECT
                SUM(ingress_syn_count) as total_syn,
                SUM(egress_synack_count) as total_synack,
                MAX(active_connections) as max_active,
                AVG(cps) as avg_cps,
                MAX(cps) as peak_cps
            FROM origin_metrics
            WHERE timestamp BETWEEN %s AND %s
        """, (start_dt, end_dt))
        metrics = cur.fetchone()

        connection_metrics = {}
        if metrics:
            connection_metrics = {
                "total_syn": int(metrics['total_syn'] or 0),
                "total_synack": int(metrics['total_synack'] or 0),
                "max_active_connections": int(metrics['max_active'] or 0),
                "avg_cps": round(float(metrics['avg_cps'] or 0), 2),
                "peak_cps": round(float(metrics['peak_cps'] or 0), 2),
            }

        cur.close()
        db.conn.close()

        # Deduplicate IP lists
        proofs["rate_limited_ips"] = list(set(proofs["rate_limited_ips"]))
        proofs["blocked_ips"] = list(set(proofs["blocked_ips"]))

        return jsonify({
            "challenge_id": challenge_id,
            "proofs": proofs,
            "connection_metrics": connection_metrics,
            "window": {
                "start": window_start,
                "end": window_end,
            },
            "timestamp": time.time()
        })

    except Exception as e:
        logger.error(f"L7 audit proof error: {e}")
        return jsonify({"error": str(e)}), 500
