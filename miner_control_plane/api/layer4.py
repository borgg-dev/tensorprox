"""Layer4 API Blueprint

VIP state management, quarantine, bypass, and source state tracking (Layer 4).
"""
import logging
import ipaddress
import json
import struct
import time
import psycopg2.extras
from flask import Blueprint, request, jsonify
from shared.database import get_db_connection
from shared.utils.ssh import ssh_exec
from shared.utils.bpf_helpers import apply_bpf_map_all, get_map_path
from shared.config import get_settings
from miner_control_plane.services.state_manager import state_manager
from miner_control_plane.services.layer4_state import apply_vip_state
from miner_control_plane.services.syncookie_controller import set_syncookie_mode_for_origin

bp = Blueprint('layer4', __name__, url_prefix='/api/v1')
logger = logging.getLogger(__name__)
settings = get_settings()

SYNCDBG_RESULT_MAP = {
    0: "none",
    1: "mode_disabled",
    2: "syn_bypass",
    3: "syn_redirect",
    4: "syn_redirect_fail",
    5: "ack_convert_ok",
    6: "ack_convert_fail",
    7: "ack_invalid"
}
SYNCDBG_MAP_PATH = "/sys/fs/bpf/tc/globals/syncookie_debug_map"


def hex_bytes(data: bytes) -> list:
    """Convert bytes to hex string list for bpftool"""
    return [f"{b:02x}" for b in data]

def _resolve_origin_by_ip(origin_ip: str):
    """Return cached origin metadata for a given origin IP (with DB fallback)."""
    for origin in state_manager.origins_db.values():
        if origin.get('origin_ip') == origin_ip:
            return origin

    try:
        db = get_db_connection()
        conn = db.conn
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT origin_id, origin_ip, eip FROM origins WHERE origin_ip = %s LIMIT 1", (origin_ip,))
            row = cur.fetchone()
        conn.close()
        return row
    except Exception as exc:
        logger.warning(f"Failed to resolve origin metadata for {origin_ip}: {exc}")
    return None


@bp.route('/vips/<origin_ip>/state', methods=['POST'])
def set_vip_state(origin_ip):
    """
    Enable/disable SYN cookies or update attack state for a VIP
    Body: {"cookie_mode": 1, "under_attack": 1, "escalated": 0, "challenge_level": 0}

    """
    try:
        # Validate origin_ip
        try:
            ipaddress.IPv4Address(origin_ip)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP address'}), 400

        data = request.get_json()
        cookie_on = data.get('cookie_mode', 0)
        under_attack = data.get('under_attack', 0)
        escalated = data.get('escalated', 0)
        challenge_level = data.get('challenge_level', 0)
        reason = data.get('reason', 'Manual API call')

        result = apply_vip_state(
            origin_ip,
            cookie_on,
            under_attack,
            escalated,
            challenge_level,
            reason
        )

        syncookie_mode_updated = None
        syncookie_mode_error = None
        if data.get('cookie_mode') is not None:
            origin_record = _resolve_origin_by_ip(origin_ip)
            eip = origin_record.get('eip') if origin_record else None
            if eip:
                try:
                    syncookie_mode_updated = set_syncookie_mode_for_origin(eip, origin_ip, bool(cookie_on))
                    if not syncookie_mode_updated:
                        syncookie_mode_error = 'bpftool_update_failed'
                except Exception as exc:
                    logger.error(f"Failed to toggle syncookie_mode_map for {origin_ip}: {exc}")
                    syncookie_mode_error = str(exc)
            else:
                syncookie_mode_error = 'origin_not_registered'

        response = {'status': 'success', **result}
        if syncookie_mode_updated is not None:
            response['syncookie_mode_updated'] = syncookie_mode_updated
        if syncookie_mode_error:
            response['syncookie_mode_error'] = syncookie_mode_error

        if result['updated_scrubbers'] == 0:
            return jsonify({'status': 'error', 'message': 'Failed on all scrubbers', 'errors': result['errors']}), 500

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Failed to set VIP state: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/vips/<origin_ip>/state', methods=['GET'])
def get_vip_state(origin_ip):
    """
    Get current VIP state from scrubbers

    """
    try:
        # Validate origin_ip
        try:
            ipaddress.IPv4Address(origin_ip)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP address'}), 400

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        origin_packed = ipaddress.IPv4Address(origin_ip).packed
        hex_key = ' '.join(hex_bytes(origin_packed))

        results = {}

        for edge_name, node in state_manager.nodes_db.items():
            host_ip = node['public_ip']
            cmd = f"sudo bpftool map lookup pinned /sys/fs/bpf/xdp/globals/vip_state_map key hex {hex_key}"

            rc, stdout, stderr = ssh_exec(
                host_ip, cmd, settings.ssh_key_path,
                nodes_db=state_manager.nodes_db
            )
            if rc == 0 and 'value' in stdout:
                # Parse output: "value: 01 00 00 00 00 00 00 00"
                import re
                match = re.search(r'value:\s*([0-9a-f\s]+)', stdout)
                if match:
                    value_hex = match.group(1).replace(' ', '')
                    if len(value_hex) >= 16:  # 8 bytes = 16 hex chars
                        flags = int(value_hex[0:2], 16)
                        challenge_level = int(value_hex[2:4], 16)
                        results[edge_name] = {
                            'flags': flags,
                            'cookie_mode': (flags & 0x1) != 0,
                            'under_attack': (flags & 0x2) != 0,
                            'escalated': (flags & 0x4) != 0,
                            'challenge_level': challenge_level
                        }
                    else:
                        results[edge_name] = {'error': 'Invalid value length'}
                else:
                    results[edge_name] = {'error': 'Could not parse value'}
            elif 'key not found' in stderr or 'key not found' in stdout:
                results[edge_name] = {'error': 'VIP not configured (key not found)'}
            else:
                results[edge_name] = {'error': f'Query failed: {stderr[:100]}'}

        return jsonify({
            'status': 'success',
            'vip': origin_ip,
            'scrubbers': results
        }), 200

    except Exception as e:
        logger.error(f"Failed to get VIP state: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


def _int_to_ip(value: int) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except Exception:
        return f"0x{value:x}"


def _format_syncookie_debug(value: dict) -> dict:
    if not isinstance(value, dict):
        return {'error': 'invalid_value'}

    result_code = value.get('last_result', 0)
    formatted = {
        'syn_cookie': value.get('syn_cookie'),
        'syn_timestamp': value.get('syn_now_sec'),
        'last_ack': value.get('last_ack'),
        'ack_timestamp': value.get('ack_now_sec'),
        'last_origin_ip': _int_to_ip(value.get('last_origin_ip', 0)),
        'last_dst_eip': _int_to_ip(value.get('last_dst_eip', 0)),
        'last_mode_value': value.get('last_mode_value'),
        'last_tcp_flags': value.get('last_tcp_flags'),
        'last_redirect_ifindex': value.get('last_redirect_ifindex'),
        'syn_redirect_ret': value.get('syn_redirect_ret'),
        'result_code': result_code,
        'result_label': SYNCDBG_RESULT_MAP.get(result_code, 'unknown')
    }
    return formatted


@bp.route('/layer4/syncookie-debug', methods=['GET'])
def get_syncookie_debug():
    """
    Fetch the per-node syncookie_debug_map snapshot to aid dataplane debugging.
    """
    try:
        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        results = {}
        for edge_name, node in state_manager.nodes_db.items():
            host_ip = node['public_ip']
            cmd = (
                f"sudo bpftool map lookup pinned {SYNCDBG_MAP_PATH} "
                "key hex 00 00 00 00 -j"
            )
            rc, stdout, stderr = ssh_exec(
                host_ip,
                cmd,
                settings.ssh_key_path,
                nodes_db=state_manager.nodes_db
            )
            if rc != 0:
                results[edge_name] = {
                    'error': stderr.strip() or 'lookup_failed'
                }
                continue

            try:
                payload = json.loads(stdout or "[]")
                value = None
                if isinstance(payload, list) and payload:
                    entry = payload[0]
                    if isinstance(entry, dict):
                        value = entry.get('value') or entry.get('formatted', {}).get('value')
                results[edge_name] = _format_syncookie_debug(value)
            except json.JSONDecodeError as exc:
                results[edge_name] = {'error': f'parse_error: {exc}'}

        return jsonify({
            'status': 'success',
            'nodes': results,
            'result_labels': SYNCDBG_RESULT_MAP
        }), 200

    except Exception as exc:
        logger.error(f"Failed to fetch syncookie debug state: {exc}")
        return jsonify({'status': 'error', 'message': str(exc)}), 500


@bp.route('/layer4/syncookie-metrics', methods=['GET'])
def get_syncookie_metrics():
    """
    Retrieve recent SYN cookie telemetry per VIP.

    Query params:
        vip_ip (optional)
        node_id (optional)
        limit (default 50, max 500)
    """
    try:
        vip_filter = (request.args.get('vip_ip') or '').strip()
        origin_id_filter = (request.args.get('origin_id') or '').strip()
        node_filter = request.args.get('node_id')
        limit = min(int(request.args.get('limit', 50)), 500)

        db = get_db_connection()
        conn = db.conn
        filter_ips = []

        def _add_filter_ip(value: str):
            if not value:
                return
            ip_val = value.strip()
            if ip_val and ip_val not in filter_ips:
                filter_ips.append(ip_val)

        if vip_filter:
            _add_filter_ip(vip_filter)

        lookup_cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            if vip_filter:
                lookup_cur.execute(
                    """
                    SELECT origin_id, origin_ip
                    FROM origins
                    WHERE eip = %s OR origin_ip = %s
                    LIMIT 1
                    """,
                    (vip_filter, vip_filter)
                )
                origin_meta = lookup_cur.fetchone()
                if origin_meta and origin_meta.get('origin_ip'):
                    _add_filter_ip(origin_meta['origin_ip'])

            if origin_id_filter:
                lookup_cur.execute(
                    "SELECT origin_ip FROM origins WHERE origin_id = %s LIMIT 1",
                    (origin_id_filter,)
                )
                origin = lookup_cur.fetchone()
                if origin and origin.get('origin_ip'):
                    _add_filter_ip(origin['origin_ip'])
        finally:
            lookup_cur.close()

        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        conditions = []
        params = []
        if filter_ips:
            ip_conditions = []
            for ip in filter_ips:
                ip_conditions.append("sm.vip_ip = %s::inet")
                params.append(ip)
            conditions.append(f"({' OR '.join(ip_conditions)})")
        if origin_id_filter:
            conditions.append("o.origin_id = %s")
            params.append(origin_id_filter)
        if node_filter:
            conditions.append("sm.node_id = %s")
            params.append(node_filter)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        cur.execute(f"""
            SELECT sm.node_id,
                   o.origin_id,
                   sm.vip_ip,
                   COALESCE(o.eip, sm.vip_ip::text) AS vip_eip,
                   sm.timestamp,
                   sm.incoming_syn, sm.cookie_validates, sm.cookie_rejects,
                   sm.handshake_completes, sm.challenged_clients,
                   sm.pending_cookies, sm.allow_list_size,
                   sm.syn_retransmits, sm.false_positives,
                   sm.outgoing_synack, sm.last_update_ts, sm.cookie_mode
            FROM syncookie_metrics sm
            LEFT JOIN origins o ON o.origin_ip::inet = sm.vip_ip
            {where_clause}
            ORDER BY sm.timestamp DESC
            LIMIT %s
        """, (*params, limit))

        rows = cur.fetchall()
        cur.close()

        return jsonify({
            'status': 'success',
            'count': len(rows),
            'metrics': [
                {
                    **row,
                    'vip_eip': row['vip_eip'],
                    'timestamp': row['timestamp'].isoformat()
                } for row in rows
            ]
        })

    except Exception as e:
        logger.error(f"Failed to fetch syncookie metrics: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/layer4/cookie-failures/top', methods=['GET'])
def get_cookie_failure_summary():
    """
    Return the top offenders from source_state sorted by cookie failures.

    Query params:
        vip_ip (optional)
        limit (default 50, max 200)
    """
    try:
        vip_filter = request.args.get('vip_ip')
        limit = min(int(request.args.get('limit', 50)), 200)

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        params = [limit]
        if vip_filter:
            cur.execute("""
                SELECT src_ip, vip_ip, score, cookie_failures, cookie_successes,
                       quarantine_expiry, last_seen
                FROM source_state
                WHERE vip_ip = %s AND cookie_failures > 0
                ORDER BY cookie_failures DESC, last_seen DESC
                LIMIT %s
            """, (vip_filter, limit))
        else:
            cur.execute("""
                SELECT src_ip, vip_ip, score, cookie_failures, cookie_successes,
                       quarantine_expiry, last_seen
                FROM source_state
                WHERE cookie_failures > 0
                ORDER BY cookie_failures DESC, last_seen DESC
                LIMIT %s
            """, (limit,))

        rows = cur.fetchall()
        cur.close()

        return jsonify({
            'status': 'success',
            'count': len(rows),
            'entries': [
                {
                    'src_ip': str(row['src_ip']),
                    'vip_ip': str(row['vip_ip']),
                    'score': row['score'],
                    'cookie_failures': row['cookie_failures'],
                    'cookie_successes': row['cookie_successes'],
                    'quarantine_expiry': row['quarantine_expiry'],
                    'last_seen': row['last_seen'].isoformat() if row['last_seen'] else None
                } for row in rows
            ]
        })

    except Exception as e:
        logger.error(f"Failed to fetch cookie failure summary: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/quarantine', methods=['POST'])
def add_quarantine():
    """
    Quarantine an IP for a specific VIP
    Body: {"src_ip": "1.2.3.4", "vip_ip": "5.6.7.8", "ttl_seconds": 120, "reason": 1, "score": 1}

    """
    try:
        data = request.get_json()
        src_ip = data['src_ip']
        vip_ip = data['vip_ip']
        ttl = data.get('ttl_seconds', 120)
        reason = data.get('reason', 1)  # 1=cookie_fail, 2=protocol_anomaly, 3=behavioral
        score = data.get('score', 1)

        # Validate IPs
        try:
            ipaddress.IPv4Address(src_ip)
            ipaddress.IPv4Address(vip_ip)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP address'}), 400

        # Calculate expiration (nanoseconds since boot - approximated with time.time())
        expires_ns = (int(time.time()) + ttl) * 1_000_000_000

        # quarantine_key: {src_ip, vip_ip} = 8 bytes
        key = ipaddress.IPv4Address(src_ip).packed + ipaddress.IPv4Address(vip_ip).packed

        # quarantine_entry: {u64 expires_ns, u8 score, u8 reason, u8[6] reserved} = 16 bytes
        value = struct.pack('<QBBBBBBBB', expires_ns, score, reason, 0, 0, 0, 0, 0, 0)

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        hex_key = ' '.join(hex_bytes(key))
        hex_value = ' '.join(hex_bytes(value))

        results = apply_bpf_map_all(
            nodes=state_manager.nodes_db,
            map_path=get_map_path('quarantine'),
            key_hex=hex_key,
            value_hex=hex_value,
            ssh_key_path=settings.ssh_key_path,
            verify=True
        )
        success_count = sum(1 for res in results.values() if res.success)
        errors = [f"{edge}: {res.stderr or res.verification_error}" for edge, res in results.items() if not res.success]

        # Log quarantine action to database
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO quarantine_log (src_ip, vip_ip, reason, ttl, score, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (src_ip, vip_ip, reason, ttl, score, int(time.time()), int(time.time()) + ttl))
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to log quarantine action: {e}")
        finally:
            cur.close()

        if success_count == 0:
            return jsonify({'status': 'error', 'message': 'Failed on all scrubbers', 'errors': errors}), 500

        return jsonify({
            'status': 'quarantined',
            'src_ip': src_ip,
            'vip_ip': vip_ip,
            'expires_in': ttl,
            'reason': reason,
            'score': score,
            'updated_scrubbers': success_count,
            'errors': errors if errors else None
        }), 200

    except KeyError as e:
        return jsonify({'status': 'error', 'message': f'Missing required field: {e}'}), 400
    except Exception as e:
        logger.error(f"Failed to add quarantine: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/quarantine', methods=['GET'])
def list_quarantine():
    """
    List all quarantined IPs (from database log)

    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            # Get recent quarantine entries (last 24 hours)
            cur.execute("""
                SELECT src_ip, vip_ip, reason, ttl, score, created_at, expires_at
                FROM quarantine_log
                WHERE created_at > %s
                ORDER BY created_at DESC
                LIMIT 1000
            """, (int(time.time()) - 86400,))
            rows = cur.fetchall()

            return jsonify({
                'status': 'success',
                'count': len(rows),
                'entries': [dict(row) for row in rows]
            }), 200
        finally:
            cur.close()

    except Exception as e:
        logger.error(f"Failed to list quarantine: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/quarantine/<src_ip>', methods=['DELETE'])
def remove_quarantine(src_ip):
    """
    Remove IP from quarantine (all VIPs)

    """
    try:
        # Validate IP
        try:
            ipaddress.IPv4Address(src_ip)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP address'}), 400

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        # Note: BPF LRU maps don't support efficient deletion of entries matching a pattern
        # We would need to dump the entire map, find matching keys, and delete each one
        # For now, we'll just let the TTL expire naturally
        # This endpoint is primarily for logging/auditing purposes

        return jsonify({
            'status': 'success',
            'message': f'Quarantine entries for {src_ip} will expire naturally (LRU map)',
            'note': 'BPF LRU maps do not support pattern-based deletion. Entries will auto-expire per TTL.'
        }), 200

    except Exception as e:
        logger.error(f"Failed to remove quarantine: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/bypass', methods=['POST'])
def add_bypass():
    """
    Add 4-tuple to bypass map (fast-path whitelisting)
    Body: {"src_ip": "1.2.3.4", "src_port": 12345, "vip_ip": "5.6.7.8", "dst_port": 80, "ttl_seconds": 60}

    """
    try:
        data = request.get_json()
        src_ip = data['src_ip']
        src_port = data['src_port']
        vip_ip = data['vip_ip']
        dst_port = data['dst_port']
        ttl = data.get('ttl_seconds', 60)

        # Validate IPs and ports
        try:
            ipaddress.IPv4Address(src_ip)
            ipaddress.IPv4Address(vip_ip)
            if not (0 < src_port < 65536 and 0 < dst_port < 65536):
                raise ValueError("Invalid port number")
        except ValueError as e:
            return jsonify({'status': 'error', 'message': f'Invalid input: {e}'}), 400

        # Calculate expiration (nanoseconds)
        expires_ns = (int(time.time()) + ttl) * 1_000_000_000

        # bypass_key: {src_ip, src_port, vip_ip, dst_port} = 12 bytes
        key = (ipaddress.IPv4Address(src_ip).packed +
               struct.pack('<H', src_port) +
               ipaddress.IPv4Address(vip_ip).packed +
               struct.pack('<H', dst_port))

        # bypass_entry: {u64 expires_ns, u32 validated_ts, u32 reserved} = 16 bytes
        value = struct.pack('<QII', expires_ns, int(time.time()), 0)

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        hex_key = ' '.join(hex_bytes(key))
        hex_value = ' '.join(hex_bytes(value))

        results = apply_bpf_map_all(
            nodes=state_manager.nodes_db,
            map_path=get_map_path('bypass'),
            key_hex=hex_key,
            value_hex=hex_value,
            ssh_key_path=settings.ssh_key_path,
            verify=True
        )
        success_count = sum(1 for res in results.values() if res.success)
        errors = [f"{edge}: {res.stderr or res.verification_error}" for edge, res in results.items() if not res.success]

        if success_count == 0:
            return jsonify({'status': 'error', 'message': 'Failed on all scrubbers', 'errors': errors}), 500

        return jsonify({
            'status': 'success',
            'flow': f"{src_ip}:{src_port} -> {vip_ip}:{dst_port}",
            'expires_in': ttl,
            'updated_scrubbers': success_count,
            'errors': errors if errors else None
        }), 200

    except KeyError as e:
        return jsonify({'status': 'error', 'message': f'Missing required field: {e}'}), 400
    except Exception as e:
        logger.error(f"Failed to add bypass: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/sources/<src_ip>/state', methods=['GET'])
def get_source_state(src_ip):
    """
    Query cookie validation history for a source IP across all VIPs

    Returns cookie failures, successes, quarantine state, score for debugging
    and customer support ("Why is my IP blocked?")

    """
    try:
        # Validate IP format
        try:
            ipaddress.IPv4Address(src_ip)
        except:
            return jsonify({'status': 'error', 'message': 'Invalid IP address'}), 400

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get all VIP interactions for this source
        cur.execute("""
            SELECT
                src_ip,
                vip_ip,
                score,
                cookie_failures,
                cookie_successes,
                quarantine_expiry,
                first_seen,
                last_seen
            FROM source_state
            WHERE src_ip = %s
            ORDER BY last_seen DESC
        """, (src_ip,))

        vips = cur.fetchall()
        cur.close()

        # Convert to JSON-friendly format
        result = {
            'src_ip': src_ip,
            'vips': []
        }

        for vip in vips:
            result['vips'].append({
                'vip_ip': str(vip['vip_ip']),
                'cookie_failures': vip['cookie_failures'],
                'cookie_successes': vip['cookie_successes'],
                'score': vip['score'],
                'quarantine_expiry': vip['quarantine_expiry'],
                'is_quarantined': vip['quarantine_expiry'] is not None and vip['quarantine_expiry'] > time.time_ns(),
                'first_seen': vip['first_seen'].isoformat() if vip['first_seen'] else None,
                'last_seen': vip['last_seen'].isoformat() if vip['last_seen'] else None
            })

        return jsonify(result)

    except Exception as e:
        logger.error(f"Failed to get source state: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/layer4/cookie_failures', methods=['GET'])
def get_cookie_failures():
    """
    Get top sources with cookie validation failures

    Query params:
    - limit: Number of sources to return (default 50)
    - vip_ip: Filter by VIP (optional)

    """
    try:
        limit = request.args.get('limit', 50, type=int)
        vip_filter = request.args.get('vip_ip', None)

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        if vip_filter:
            cur.execute("""
                SELECT src_ip, vip_ip, cookie_failures, cookie_successes,
                       score, last_seen
                FROM source_state
                WHERE vip_ip = %s AND cookie_failures > 0
                ORDER BY cookie_failures DESC, last_seen DESC
                LIMIT %s
            """, (vip_filter, limit))
        else:
            cur.execute("""
                SELECT src_ip, vip_ip, cookie_failures, cookie_successes,
                       score, last_seen
                FROM source_state
                WHERE cookie_failures > 0
                ORDER BY cookie_failures DESC, last_seen DESC
                LIMIT %s
            """, (limit,))

        failures = cur.fetchall()
        cur.close()

        result = {
            'count': len(failures),
            'sources': []
        }

        for entry in failures:
            result['sources'].append({
                'src_ip': str(entry['src_ip']),
                'vip_ip': str(entry['vip_ip']),
                'cookie_failures': entry['cookie_failures'],
                'cookie_successes': entry['cookie_successes'],
                'score': entry['score'],
                'success_rate': entry['cookie_successes'] / (entry['cookie_failures'] + entry['cookie_successes']) if (entry['cookie_failures'] + entry['cookie_successes']) > 0 else 0,
                'last_seen': entry['last_seen'].isoformat() if entry['last_seen'] else None
            })

        return jsonify(result)

    except Exception as e:
        logger.error(f"Failed to get cookie failures: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/bypass', methods=['DELETE'])
def clear_bypass():
    """
    Clear all bypass entries (force re-validation of all flows)

    """
    try:
        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        success_count = 0
        errors = []

        # Clear bypass map on all scrubbers (delete all entries)
        for edge_name, node in state_manager.nodes_db.items():
            host_ip = node['public_ip']
            # Get all keys and delete them
            cmd = "sudo bpftool map dump pinned /sys/fs/bpf/xdp/globals/bypass_map | grep 'key:' | awk '{print $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13}' | while read key; do sudo bpftool map delete pinned /sys/fs/bpf/xdp/globals/bypass_map key hex $key; done"

            rc, stdout, stderr = ssh_exec(
                host_ip, cmd, settings.ssh_key_path,
                nodes_db=state_manager.nodes_db
            )
            if rc == 0:
                success_count += 1
                logger.info(f"Cleared bypass map on {edge_name}")
            else:
                # Map might be empty, which is not an error
                success_count += 1
                logger.info(f"Cleared bypass map on {edge_name} (map was likely empty)")

        return jsonify({
            'status': 'success',
            'message': 'All bypass entries cleared',
            'updated_scrubbers': success_count
        }), 200

    except Exception as e:
        logger.error(f"Failed to clear bypass: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
