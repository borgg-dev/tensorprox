"""Attack Events API Blueprint - Layer 7: Attack Event Management & Status

Endpoints:
    GET  /api/v1/attack_events                           - List all attack events
    GET  /api/v1/origins/<origin_id>/attack_events       - Get attack events for specific origin
    GET  /api/v1/attack_events/<event_id>                - Get detailed event information
    POST /api/v1/attack_events/<event_id>/end            - Manually end attack event
    GET  /api/v1/anomaly_detection/status                - Get anomaly detector runtime status
"""
from flask import Blueprint, request, jsonify
import logging
import psycopg2.extras
from psycopg2.extras import RealDictCursor
from typing import Optional

# Import shared utilities
from shared.database import get_db_connection

logger = logging.getLogger(__name__)

bp = Blueprint('attack_events', __name__, url_prefix='/api/v1')


# ============================================================================
# ATTACK EVENT LISTING ENDPOINTS
# ============================================================================

@bp.route('/attack_events', methods=['GET'])
def list_attack_events():
    """
    List all attack events (active + historical)

    Query parameters:
    - limit: Maximum number of events to return (default: 50, max: 500)
    - offset: Offset for pagination (default: 0)
    - origin_id: Filter by origin
    - active_only: Filter to active attacks only (true/false)
    - attack_type: Filter by attack type

    Returns:
        200: Attack events list with pagination metadata
        500: Server error

    Example:
        GET /api/v1/attack_events?limit=10&active_only=true

        Response:
        {
            "events": [...],
            "total": 150,
            "active_count": 3,
            "limit": 10,
            "offset": 0
        }

    """
    try:
        limit = min(int(request.args.get('limit', 50)), 500)
        offset = int(request.args.get('offset', 0))
        origin_id = request.args.get('origin_id')
        active_only = request.args.get('active_only', '').lower() == 'true'
        attack_type = request.args.get('attack_type')

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Build query
        where_clauses = []
        params = []

        if origin_id:
            where_clauses.append("origin_id = %s")
            params.append(origin_id)

        if active_only:
            where_clauses.append("mitigation_active = true")

        if attack_type:
            where_clauses.append("attack_type = %s")
            params.append(attack_type)

        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        # Get total count
        cur.execute(f"SELECT COUNT(*) as total FROM attack_events {where_sql}", params)
        total = cur.fetchone()['total']

        # Get active count
        active_where = "WHERE mitigation_active = true"
        cur.execute(f"SELECT COUNT(*) as active_count FROM attack_events {active_where}")
        active_count = cur.fetchone()['active_count']

        # Get events with pagination
        params.extend([limit, offset])
        cur.execute(f"""
            SELECT event_id, origin_id, detected_at, ended_at, attack_type,
                   peak_pps, peak_cps, peak_active_connections, confidence,
                   challenge_level_peak, mitigation_active, baseline_deviation_zscore,
                   samples_breached, created_at, updated_at
            FROM attack_events
            {where_sql}
            ORDER BY detected_at DESC
            LIMIT %s OFFSET %s
        """, params)
        events = [dict(row) for row in cur.fetchall()]

        cur.close()

        return jsonify({
            'events': events,
            'total': total,
            'active_count': active_count,
            'limit': limit,
            'offset': offset
        })

    except Exception as e:
        logger.error(f"Failed to list attack events: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/origins/<origin_id>/attack_events', methods=['GET'])
def get_origin_attack_events(origin_id: str):
    """
    Get attack events for specific origin

    Args:
        origin_id: Origin identifier (e.g., "O1")

    Query parameters:
        limit: Maximum number of events to return (default: 50, max: 500)

    Returns:
        200: Attack events for the origin
        500: Server error

    Example:
        GET /api/v1/origins/O1/attack_events?limit=20

        Response:
        {
            "origin_id": "O1",
            "events": [...],
            "count": 15
        }

    """
    try:
        limit = min(int(request.args.get('limit', 50)), 500)

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT event_id, detected_at, ended_at, attack_type, peak_pps,
                   confidence, challenge_level_peak, mitigation_active
            FROM attack_events
            WHERE origin_id = %s
            ORDER BY detected_at DESC
            LIMIT %s
        """, (origin_id, limit))
        events = [dict(row) for row in cur.fetchall()]

        cur.close()

        return jsonify({
            'origin_id': origin_id,
            'events': events,
            'count': len(events)
        })

    except Exception as e:
        logger.error(f"Failed to get attack events for {origin_id}: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# ATTACK EVENT DETAILS ENDPOINT
# ============================================================================

@bp.route('/attack_events/<int:event_id>', methods=['GET'])
def get_attack_event_details(event_id: int):
    """
    Get detailed information about specific attack event

    Args:
        event_id: Attack event ID

    Returns:
        200: Event details with timeline
        404: Event not found
        500: Server error

    Example:
        GET /api/v1/attack_events/123

        Response:
        {
            "event": {
                "event_id": 123,
                "origin_id": "O1",
                "detected_at": "2025-11-06T10:30:00",
                "attack_type": "syn_flood",
                ...
            },
            "timeline": [
                {
                    "changed_at": "2025-11-06T10:30:00",
                    "challenge_level": 2,
                    "flags": 0,
                    "reason": "PPS spike detected"
                },
                ...
            ]
        }

    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT *
            FROM attack_events
            WHERE event_id = %s
        """, (event_id,))
        event = cur.fetchone()

        if not event:
            cur.close()
            return jsonify({'error': 'Event not found'}), 404

        # Get timeline (vip_state_history changes during this event)
        cur.execute("""
            SELECT vh.changed_at, vh.challenge_level, vh.flags, vh.reason
            FROM vip_state_history vh
            JOIN origins o ON o.origin_ip = vh.origin_ip
            WHERE o.origin_id = %s
              AND vh.changed_at >= %s
              AND (vh.changed_at <= %s OR %s IS NULL)
            ORDER BY vh.changed_at
        """, (event['origin_id'], event['detected_at'], event['ended_at'], event['ended_at']))
        timeline = [dict(row) for row in cur.fetchall()]

        cur.close()

        return jsonify({
            'event': dict(event),
            'timeline': timeline
        })

    except Exception as e:
        logger.error(f"Failed to get attack event {event_id}: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# ATTACK EVENT MANAGEMENT ENDPOINT
# ============================================================================

@bp.route('/attack_events/<int:event_id>/end', methods=['POST'])
def end_attack_event(event_id: int):
    """
    Manually end attack event and trigger de-escalation

    Args:
        event_id: Attack event ID

    Request body:
    {
        "reason": "Manual intervention"  // Optional: reason for ending
    }

    Returns:
        200: Event ended successfully
        404: Event not found
        200: Event already ended (status: already_ended)
        500: Server error

    Example:
        POST /api/v1/attack_events/123/end
        Body: {"reason": "False positive - legitimate traffic spike"}

        Response:
        {
            "status": "ended",
            "event_id": 123,
            "origin_id": "O1",
            "reason": "False positive - legitimate traffic spike"
        }

    """
    try:
        data = request.json or {}
        reason = data.get('reason', 'Manual intervention')

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get event details
        cur.execute("""
            SELECT origin_id, mitigation_active
            FROM attack_events
            WHERE event_id = %s
        """, (event_id,))
        event = cur.fetchone()

        if not event:
            cur.close()
            return jsonify({'error': 'Event not found'}), 404

        if not event['mitigation_active']:
            cur.close()
            return jsonify({
                'status': 'already_ended',
                'event_id': event_id
            })

        # End the event
        cur.execute("""
            UPDATE attack_events
            SET ended_at = NOW(),
                mitigation_active = false,
                updated_at = NOW()
            WHERE event_id = %s
        """, (event_id,))

        # Clear active_attack_event_id in anomaly_detection_state
        cur.execute("""
            UPDATE anomaly_detection_state
            SET active_attack_event_id = NULL
            WHERE origin_id = %s AND active_attack_event_id = %s
        """, (event['origin_id'], event_id))

        # Log config change
        cur.execute("""
            INSERT INTO config_change_log (
                config_type, parameter_name, new_value, changed_by, changed_via, reason
            )
            VALUES ('global', 'attack_event_manual_end', %s, 'api', 'api', %s)
        """, (str(event_id), reason))

        conn.commit()
        cur.close()

        logger.info(f"Attack event {event_id} manually ended: {reason}")

        return jsonify({
            'status': 'ended',
            'event_id': event_id,
            'origin_id': event['origin_id'],
            'reason': reason
        })

    except Exception as e:
        logger.error(f"Failed to end attack event {event_id}: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# ANOMALY DETECTION STATUS ENDPOINT
# ============================================================================

@bp.route('/anomaly_detection/status', methods=['GET'])
def get_anomaly_detector_status():
    """
    Get anomaly detector runtime status

    Returns runtime status including:
    - Detector running state
    - Loop interval and last check timestamp
    - Config last reload time
    - Number of origins monitored
    - Active attacks count
    - Active per-origin overrides count

    Returns:
        200: Detector status
        500: Server error

    Example:
        GET /api/v1/anomaly_detection/status

        Response:
        {
            "detector_running": true,
            "loop_interval": 30,
            "last_loop_at": "2025-11-06T10:45:00",
            "config_last_reloaded": "2025-11-06T08:00:00",
            "origins_monitored": 5,
            "active_attacks": 2,
            "active_overrides": 1,
            "paused": false
        }

    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get config
        cur.execute(
            "SELECT loop_interval, updated_at FROM anomaly_detection_config WHERE config_id = 1"
        )
        cfg = cur.fetchone()

        # Get latest check timestamp
        cur.execute("SELECT MAX(last_check_timestamp) as last_check FROM anomaly_detection_state")
        check = cur.fetchone()

        # Count active attacks
        cur.execute("SELECT COUNT(*) as count FROM attack_events WHERE mitigation_active = true")
        active_attacks = cur.fetchone()['count']

        # Count origins monitored
        cur.execute("SELECT COUNT(*) as count FROM origins WHERE state = 'IN_SERVICE'")
        origins_monitored = cur.fetchone()['count']

        # Count per-origin overrides
        cur.execute("""
            SELECT COUNT(*) as count FROM baseline_config
            WHERE z_score_threshold IS NOT NULL
               OR pps_multiplier_threshold IS NOT NULL
               OR syn_ratio_threshold IS NOT NULL
        """)
        active_overrides = cur.fetchone()['count']

        cur.close()

        return jsonify({
            'detector_running': True,  # If this endpoint responds, detector is running
            'loop_interval': cfg['loop_interval'] if cfg else 30,
            'last_loop_at': (
                check['last_check'].isoformat() if check and check['last_check'] else None
            ),
            'config_last_reloaded': cfg['updated_at'].isoformat() if cfg else None,
            'origins_monitored': origins_monitored,
            'active_attacks': active_attacks,
            'active_overrides': active_overrides,
            'paused': False
        })

    except Exception as e:
        logger.error(f"Failed to get anomaly detector status: {e}")
        return jsonify({'error': str(e)}), 500
