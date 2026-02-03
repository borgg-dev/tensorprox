"""Challenge Levels API Blueprint

Per-origin challenge level management (adaptive rate limiting).
"""
import json
import socket
import logging
import psycopg2.extras
from flask import Blueprint, request, jsonify
from shared.database import get_db_connection
from shared.utils.ssh import ssh_exec
from shared.utils.bpf_helpers import apply_bpf_map_all, get_map_path, lookup_bpf_map
from shared.config import get_settings
from miner_control_plane.services.state_manager import state_manager

bp = Blueprint('challenge_levels', __name__, url_prefix='/api/v1')
logger = logging.getLogger(__name__)
settings = get_settings()


@bp.route('/origins/<origin_id>/challenge_level', methods=['POST'])
def set_origin_challenge_level(origin_id: str):
    """
    Set per-origin challenge level (adaptive rate limiting per VIP)

    Request body:
    {
        "level": 0-4,           // 0=NORMAL, 1=SOFT(80%), 2=ACTIVE(50%), 3=STRICT(20%), 4=EMERGENCY(10%)
        "reason": "string",     // Optional: reason for change
        "duration_minutes": 60  // Optional: auto-reset after N minutes (0 = permanent)
    }

    """
    try:
        if origin_id not in state_manager.origins_db:
            return jsonify({'status': 'error', 'message': 'Origin not found'}), 404

        data = request.json
        level = data.get('level', 0)
        reason = data.get('reason', 'API request')
        duration_minutes = data.get('duration_minutes', 0)

        # Validate level
        if not isinstance(level, int) or level < 0 or level > 4:
            return jsonify({'status': 'error', 'message': 'Level must be 0-4'}), 400

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        origin = state_manager.origins_db[origin_id]
        origin_ip = origin['origin_ip']

        logger.info(
            f"=== Setting challenge level for origin {origin_id} ({origin_ip}) to {level} ==="
        )

        level_names = ['NORMAL', 'SOFT', 'ACTIVE', 'STRICT', 'EMERGENCY']
        level_name = level_names[level] if level < len(level_names) else f'UNKNOWN({level})'

        # Convert origin_ip to network byte order (big-endian) for BPF map key
        origin_ip_bytes = socket.inet_aton(origin_ip)
        origin_ip_hex = ' '.join([f'{b:02x}' for b in origin_ip_bytes])

        # Pack level as little-endian 32-bit integer
        level_hex = f"{level:02x} 00 00 00"

        results = apply_bpf_map_all(
            nodes=state_manager.nodes_db,
            map_path=get_map_path('origin_challenge'),
            key_hex=origin_ip_hex,
            value_hex=level_hex,
            ssh_key_path=settings.ssh_key_path,
            verify=True
        )

        updated = [edge for edge, res in results.items() if res.success]
        if len(updated) == 0:
            return jsonify({'status': 'error', 'message': 'Failed to update any scrubbers'}), 500

        # Log to audit_log
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO audit_log (action, origin_id, details)
                VALUES (%s, %s, %s)
                """,
                (
                    'origin_challenge_level_set',
                    origin_id,
                    json.dumps({
                        'origin_ip': origin_ip,
                        'level': level,
                        'level_name': level_name,
                        'reason': reason,
                        'duration_minutes': duration_minutes
                    })
                )
            )
            conn.commit()
        finally:
            cur.close()

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'origin_ip': origin_ip,
            'level': level,
            'level_name': level_name,
            'updated_scrubbers': updated,
            'duration_minutes': duration_minutes
        })

    except Exception as e:
        logger.error(f"Failed to set origin challenge level: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/origins/<origin_id>/challenge_level', methods=['GET'])
def get_origin_challenge_level(origin_id: str):
    """
    Query current challenge level for a specific origin

    """
    try:
        if origin_id not in state_manager.origins_db:
            return jsonify({'status': 'error', 'message': 'Origin not found'}), 404

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        origin = state_manager.origins_db[origin_id]
        origin_ip = origin['origin_ip']

        level_names = ['NORMAL', 'SOFT', 'ACTIVE', 'STRICT', 'EMERGENCY']

        # Convert origin_ip to network byte order for BPF map key
        origin_ip_bytes = socket.inet_aton(origin_ip)
        origin_ip_hex = ' '.join([f'{b:02x}' for b in origin_ip_bytes])

        # Query from active scrubber
        active_edge = state_manager.get_active_edge()
        active_ip = state_manager.nodes_db[active_edge]['public_ip']

        success, payload, error = lookup_bpf_map(
            active_ip,
            get_map_path('origin_challenge'),
            origin_ip_hex,
            settings.ssh_key_path,
            provider=state_manager.nodes_db[active_edge].get('provider', 'aws')
        )

        if not success:
            # No entry in map = using global challenge level
            return jsonify({
                'status': 'success',
                'origin_id': origin_id,
                'origin_ip': origin_ip,
                'level': None,  # No per-origin override
                'level_name': 'USING_GLOBAL',
                'scrubber': active_edge
            })

        try:
            value_obj = payload.get('value')
            if isinstance(value_obj, dict):
                level = next((v for v in value_obj.values() if isinstance(v, int)), 0)
            else:
                level = int(value_obj)
        except Exception as e:
            logger.error(f"Failed to parse origin challenge level: {e}, payload: {payload}")
            return jsonify({'status': 'error', 'message': f'Parse error: {str(e)}'}), 500

        level_name = level_names[level] if level < len(level_names) else f'UNKNOWN({level})'

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'origin_ip': origin_ip,
            'level': level,
            'level_name': level_name,
            'scrubber': active_edge
        })

    except Exception as e:
        logger.error(f"Failed to get origin challenge level: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/origins/<origin_id>/challenge_level', methods=['DELETE'])
def reset_origin_challenge_level(origin_id: str):
    """
    Reset origin to use global challenge level (remove per-origin override)

    """
    try:
        if origin_id not in state_manager.origins_db:
            return jsonify({'status': 'error', 'message': 'Origin not found'}), 404

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        origin = state_manager.origins_db[origin_id]
        origin_ip = origin['origin_ip']

        logger.info(
            f"=== Resetting challenge level for origin {origin_id} ({origin_ip}) to global ==="
        )

        # Convert origin_ip to network byte order for BPF map key
        origin_ip_bytes = socket.inet_aton(origin_ip)
        origin_ip_hex = ' '.join([f'{b:02x}' for b in origin_ip_bytes])

        results = apply_bpf_map_all(
            nodes=state_manager.nodes_db,
            map_path=get_map_path('origin_challenge'),
            key_hex=origin_ip_hex,
            ssh_key_path=settings.ssh_key_path,
            action="delete",
            verify=False
        )
        updated = list(results.keys())

        # Log to audit_log
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO audit_log (action, origin_id, details)
                VALUES (%s, %s, %s)
                """,
                (
                    'origin_challenge_level_reset',
                    origin_id,
                    json.dumps({'origin_ip': origin_ip})
                )
            )
            conn.commit()
        finally:
            cur.close()

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'origin_ip': origin_ip,
            'level_name': 'RESET_TO_GLOBAL',
            'updated_scrubbers': updated
        })

    except Exception as e:
        logger.error(f"Failed to reset origin challenge level: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/challenge_level', methods=['POST'])
def set_challenge_level():
    """
    Set DDoS challenge level (adaptive rate limiting)

    """
    try:
        data = request.json
        level = data.get('level', 0)
        # 0=NORMAL, 1=SOFT(80%), 2=ACTIVE(50%), 3=STRICT(20%), 4=EMERGENCY(10%)

        # Validate level
        if not isinstance(level, int) or level < 0 or level > 4:
            return jsonify({'status': 'error', 'message': 'Level must be 0-4'}), 400

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        logger.info(f"=== Setting challenge level to {level} ===")

        level_names = ['NORMAL', 'SOFT', 'ACTIVE', 'STRICT', 'EMERGENCY']
        level_name = (
            level_names[level] if level < len(level_names) else f'UNKNOWN({level})'
        )

        # Pack level as little-endian 32-bit integer
        level_hex = f"{level:02x} 00 00 00"

        results = apply_bpf_map_all(
            nodes=state_manager.nodes_db,
            map_path=get_map_path('challenge_level'),
            key_hex="00 00 00 00",
            value_hex=level_hex,
            ssh_key_path=settings.ssh_key_path,
            verify=True
        )

        updated = [edge for edge, res in results.items() if res.success]
        if len(updated) == 0:
            return jsonify(
                {'status': 'error', 'message': 'Failed to update any scrubbers'}
            ), 500

        return jsonify({
            'status': 'success',
            'level': level,
            'level_name': level_name,
            'updated_scrubbers': updated
        })

    except Exception as e:
        logger.error(f"Failed to set challenge level: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/challenge_level', methods=['GET'])
def get_challenge_level():
    """
    Query current DDoS challenge level from scrubbers

    """
    try:
        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        level_names = ['NORMAL', 'SOFT', 'ACTIVE', 'STRICT', 'EMERGENCY']

        # Query from active scrubber
        active_edge = state_manager.get_active_edge()
        active_ip = state_manager.nodes_db[active_edge]['public_ip']

        # NOTE: challenge_level_map is an XDP map (defined in xdp_wan.c)
        # so it's pinned at /sys/fs/bpf/xdp/globals/ (NOT tc/globals/)
        rc, stdout, stderr = ssh_exec(
            active_ip,
            "sudo bpftool map dump pinned /sys/fs/bpf/xdp/globals/challenge_level_map --json",
            settings.ssh_key_path,
            nodes_db=state_manager.nodes_db
        )

        if rc != 0:
            return jsonify(
                {'status': 'error', 'message': 'Failed to query challenge level'}
            ), 500

        # Parse bpftool output
        try:
            map_data = json.loads(stdout)
            if map_data and len(map_data) > 0:
                entry = map_data[0]
                # Parse value (u32 little-endian)
                if 'formatted' in entry and 'value' in entry['formatted']:
                    level = entry['formatted']['value']
                else:
                    value_hex = entry.get('value', [])
                    if isinstance(value_hex, list) and len(value_hex) > 0:
                        level = (
                            int(value_hex[0], 16)
                            if isinstance(value_hex[0], str)
                            else value_hex[0]
                        )
                    else:
                        level = 0

                level_name = (
                    level_names[level] if level < len(level_names) else f'UNKNOWN({level})'
                )

                return jsonify({
                    'status': 'success',
                    'level': level,
                    'level_name': level_name,
                    'scrubber': active_edge
                })
            else:
                return jsonify({
                    'status': 'success',
                    'level': 0,
                    'level_name': 'NORMAL',
                    'scrubber': active_edge
                })
        except Exception as e:
            logger.error(f"Failed to parse challenge level: {e}")
            return jsonify(
                {'status': 'error', 'message': f'Parse error: {str(e)}'}
            ), 500

    except Exception as e:
        logger.error(f"Failed to get challenge level: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/challenge_levels', methods=['GET'])
def get_all_challenge_levels():
    """
    Get all current challenge levels (global + all origins)

    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        try:
            # Get global challenge level from anomaly_detection_config
            cur.execute(
                """
                SELECT updated_at
                FROM anomaly_detection_config
                WHERE config_id = 1
                """
            )
            config = cur.fetchone()

            # Get per-origin challenge levels
            cur.execute(
                """
                SELECT ads.origin_id, ads.current_challenge_level,
                       ads.escalation_timestamp, ads.active_attack_event_id,
                       ae.attack_type
                FROM anomaly_detection_state ads
                LEFT JOIN attack_events ae ON ae.event_id = ads.active_attack_event_id
                """
            )
            origin_states = cur.fetchall()

        finally:
            cur.close()

        origins = {}
        for state in origin_states:
            origins[state['origin_id']] = {
                'level': state['current_challenge_level'],
                'last_updated': (
                    state['escalation_timestamp'].isoformat()
                    if state['escalation_timestamp']
                    else None
                ),
                'active_attack_event_id': state['active_attack_event_id'],
                'attack_type': state['attack_type']
            }

        return jsonify({
            'global': {
                'level': 0,
                'last_updated': config['updated_at'].isoformat() if config else None
            },
            'origins': origins
        })

    except Exception as e:
        logger.error(f"Failed to get challenge levels: {e}")
        return jsonify({'error': str(e)}), 500
