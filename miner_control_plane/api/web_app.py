"""Web App API - Historical data endpoints (summary at destination)

SCALABILITY FEATURES:
- Query timeouts to prevent long-running queries from blocking
- Pagination for large result sets
- Maximum limits on query parameters to prevent abuse
- Proper connection handling with context managers
"""
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
import psycopg2.extras
from shared.database import get_db_connection
from miner_control_plane.services.state_manager import state_manager

bp = Blueprint('web_app', __name__, url_prefix='/api/v1/webapp')
logger = logging.getLogger(__name__)

# === QUERY LIMITS FOR SCALABILITY ===
MAX_HOURS_QUERY = 168  # Maximum 7 days of historical data
DEFAULT_HOURS = 24
MAX_RESULTS_PER_PAGE = 500  # Maximum results per query
QUERY_TIMEOUT_MS = 10000  # 10 second query timeout


@bp.get('/origins/<origin_id>/metrics')
def get_origin_metrics_history(origin_id: str):
    """
    Get time-series metrics for charts with pagination and timeouts.

    Query params:
        hours: Time range (default 24, max 168)
        limit: Max results (default 500, max 500)
        offset: Pagination offset (default 0)

    Returns: {origin_id, period_hours, total_count, data: [{timestamp, cpu_pct, bandwidth_mbps, latency_ms}]}
    """
    try:
        if origin_id not in state_manager.origins_db:
            return jsonify({'error': 'Origin not found'}), 404

        # Parse and validate query parameters
        hours = min(int(request.args.get('hours', DEFAULT_HOURS)), MAX_HOURS_QUERY)
        limit = min(int(request.args.get('limit', MAX_RESULTS_PER_PAGE)), MAX_RESULTS_PER_PAGE)
        offset = max(int(request.args.get('offset', 0)), 0)

        # Use context manager for automatic connection cleanup
        with get_db_connection() as db:
            conn = db.conn
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Set query timeout to prevent long-running queries
            cur.execute(f"SET statement_timeout = {QUERY_TIMEOUT_MS}")

            # Get total count first (for pagination info)
            cur.execute("""
                SELECT COUNT(*) FROM origin_metrics
                WHERE origin_id = %s AND timestamp > NOW() - INTERVAL '%s hours'
            """, (origin_id, hours))
            total_count = cur.fetchone()['count']

            # Query historical data from origin_metrics with pagination
            cur.execute("""
                SELECT timestamp, cpu_pct, memory_pct, bps, active_connections
                FROM origin_metrics
                WHERE origin_id = %s AND timestamp > NOW() - INTERVAL '%s hours'
                ORDER BY timestamp DESC
                LIMIT %s OFFSET %s
            """, (origin_id, hours, limit, offset))

            metrics = []
            timestamps = []
            for row in cur.fetchall():
                ts = row['timestamp']
                timestamps.append(ts)
                metrics.append({
                    'timestamp': ts.isoformat(),
                    'cpu_pct': row['cpu_pct'],
                    'memory_pct': row['memory_pct'],
                    'bandwidth_mbps': round(row['bps'] * 8 / 1_000_000, 2) if row['bps'] else 0,
                    'active_connections': row['active_connections'],
                    'latency_ms': None  # Will be filled below
                })

            # Get latency history for matching timestamps (batch query)
            if timestamps:
                cur.execute("""
                    SELECT timestamp, latency_ms FROM latency_measurements
                    WHERE origin_id = %s AND timestamp = ANY(%s)
                """, (origin_id, timestamps))

                latency_map = {row['timestamp']: row['latency_ms'] for row in cur.fetchall()}

                # Merge latency into metrics
                for metric in metrics:
                    ts = datetime.fromisoformat(metric['timestamp'])
                    metric['latency_ms'] = latency_map.get(ts)

            cur.close()

        return jsonify({
            'origin_id': origin_id,
            'period_hours': hours,
            'total_count': total_count,
            'limit': limit,
            'offset': offset,
            'data': metrics
        })

    except psycopg2.errors.QueryCanceled:
        logger.warning(f"Query timeout getting metrics for {origin_id}")
        return jsonify({'error': 'Query timeout - try reducing time range'}), 504
    except Exception as e:
        logger.error(f"Failed to get metrics history: {e}")
        return jsonify({'error': str(e)}), 500


def format_anomaly_description(attack_type: str, confidence: float, details: dict) -> str:
    """Create human-readable anomaly description"""
    if attack_type == 'SYN_FLOOD':
        ratio = details.get('current_ratio', 0)
        current_pps = details.get('current_pps', 0)
        return f"SYN flood attack - {ratio:.1f}x more SYNs than SYN-ACKs, {current_pps:,} packets/sec (confidence: {confidence:.0%})"

    elif attack_type == 'PPS_SPIKE':
        current_pps = details.get('current_pps', 0)
        baseline = details.get('baseline_pps_mean', 0)
        if baseline > 0:
            multiplier = current_pps / baseline
            return f"Traffic spike - {current_pps:,} packets/sec ({multiplier:.1f}x normal baseline, confidence: {confidence:.0%})"
        else:
            return f"Traffic spike - {current_pps:,} packets/sec (confidence: {confidence:.0%})"

    elif attack_type == 'STATE_EXHAUSTION':
        conns = details.get('current_active_conns', 0)
        max_conns = details.get('conntrack_max', 262144)
        pct = (conns / max_conns) * 100 if max_conns > 0 else 0
        return f"Connection exhaustion - {conns:,} active connections ({pct:.0f}% capacity, confidence: {confidence:.0%})"

    elif attack_type == 'CPS_SPIKE':
        cps = details.get('current_cps', 0)
        baseline_cps = details.get('baseline_cps_mean', 0)
        if baseline_cps > 0:
            multiplier = cps / baseline_cps
            return f"Connection rate spike - {cps:,} connections/sec ({multiplier:.1f}x baseline, confidence: {confidence:.0%})"
        else:
            return f"Connection rate spike - {cps:,} connections/sec (confidence: {confidence:.0%})"

    elif attack_type == 'APPLICATION_ATTACK':
        return f"Application-layer attack detected (confidence: {confidence:.0%})"

    else:
        return f"{attack_type.replace('_', ' ').title()} detected (confidence: {confidence:.0%})"


@bp.get('/origins/<origin_id>/anomalies')
def get_origin_anomalies(origin_id: str):
    """
    Get anomalies for origin (from EXISTING attack_events) with pagination.

    Query params:
        limit: Max results (default 100, max 500)
        offset: Pagination offset (default 0)
        hours: Time range filter (optional, max 168)

    Returns: {origin_id, total, limit, offset, anomalies: [{type, severity, detected_at, ended_at, description}]}
    """
    try:
        if origin_id not in state_manager.origins_db:
            return jsonify({'error': 'Origin not found'}), 404

        # Parse and validate query parameters
        limit = min(int(request.args.get('limit', 100)), MAX_RESULTS_PER_PAGE)
        offset = max(int(request.args.get('offset', 0)), 0)
        hours = request.args.get('hours')

        # Use context manager for automatic connection cleanup
        with get_db_connection() as db:
            conn = db.conn
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Set query timeout
            cur.execute(f"SET statement_timeout = {QUERY_TIMEOUT_MS}")

            # Build query with optional time filter
            if hours:
                hours = min(int(hours), MAX_HOURS_QUERY)
                cur.execute("""
                    SELECT event_id, attack_type, confidence, detected_at, ended_at, details
                    FROM attack_events
                    WHERE origin_id = %s AND detected_at > NOW() - INTERVAL '%s hours'
                    ORDER BY detected_at DESC
                    LIMIT %s OFFSET %s
                """, (origin_id, hours, limit, offset))
            else:
                cur.execute("""
                    SELECT event_id, attack_type, confidence, detected_at, ended_at, details
                    FROM attack_events
                    WHERE origin_id = %s
                    ORDER BY detected_at DESC
                    LIMIT %s OFFSET %s
                """, (origin_id, limit, offset))

            anomalies = []
            for row in cur.fetchall():
                # Parse JSONB details
                details = row['details'] if row['details'] else {}

                # Create human-readable description
                description = format_anomaly_description(
                    row['attack_type'],
                    row['confidence'],
                    details
                )

                anomalies.append({
                    'id': row['event_id'],
                    'type': row['attack_type'],
                    'severity': 'high' if row['confidence'] > 0.9 else 'medium',
                    'detected_at': row['detected_at'].isoformat(),
                    'ended_at': row['ended_at'].isoformat() if row['ended_at'] else None,
                    'description': description
                })

            cur.close()

        return jsonify({
            'origin_id': origin_id,
            'total': len(anomalies),
            'limit': limit,
            'offset': offset,
            'anomalies': anomalies
        })

    except psycopg2.errors.QueryCanceled:
        logger.warning(f"Query timeout getting anomalies for {origin_id}")
        return jsonify({'error': 'Query timeout - try reducing time range'}), 504
    except Exception as e:
        logger.error(f"Failed to get anomalies: {e}")
        return jsonify({'error': str(e)}), 500
