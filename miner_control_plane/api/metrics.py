"""Metrics API Blueprint

Layer 5: Metrics & Observability Endpoints
"""
import json
import socket
import struct
import logging
import psycopg2.extras
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from shared.database import get_db_connection
from shared.utils.ssh import ssh_exec
from shared.config import get_settings
from miner_control_plane.services.state_manager import state_manager

bp = Blueprint('metrics', __name__, url_prefix='/api/v1')
logger = logging.getLogger(__name__)
settings = get_settings()


@bp.get('/origins/<origin_id>/metrics')
def get_origin_metrics(origin_id: str):
    """
    Get time-series metrics for an origin

    Query parameters:
    - period: Time period (1h, 6h, 24h, 7d, 30d) - default: 1h
    - limit: Max number of data points - default: 100

    Returns: Time-series data (pps, cps, bps, syn_synack_ratio, active_connections)
    Use case: Grafana dashboards, forensics, anomaly investigation

    """
    try:
        if origin_id not in state_manager.origins_db:
            return jsonify({'status': 'error', 'message': 'Origin not found'}), 404

        # Parse query parameters
        period = request.args.get('period', '1h')
        limit = int(request.args.get('limit', 100))

        # Convert period to SQL interval
        period_map = {
            '1h': '1 hour',
            '6h': '6 hours',
            '24h': '24 hours',
            '7d': '7 days',
            '30d': '30 days'
        }
        interval = period_map.get(period, '1 hour')

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Query time-series metrics
        cur.execute("""
            SELECT
                timestamp,
                pps, cps, bps,
                active_connections,
                syn_synack_ratio,
                conn_opened_total, conn_closed_total,
                packets_total, bytes_total,
                ingress_syn_count, egress_synack_count,
                fin_count, rst_count,
                volume_ingress, volume_egress
            FROM origin_metrics
            WHERE origin_id = %s
              AND timestamp > NOW() - INTERVAL %s
            ORDER BY timestamp DESC
            LIMIT %s
        """, (origin_id, interval, limit))

        metrics = []
        for row in cur.fetchall():
            metrics.append({
                'timestamp': row['timestamp'].isoformat(),
                'pps': row['pps'],
                'cps': row['cps'],
                'bps': row['bps'],
                'active_connections': row['active_connections'],
                'syn_synack_ratio': float(row['syn_synack_ratio']) if row['syn_synack_ratio'] else None,
                'counters': {
                    'conn_opened_total': row['conn_opened_total'],
                    'conn_closed_total': row['conn_closed_total'],
                    'packets_total': row['packets_total'],
                    'bytes_total': row['bytes_total'] or (row.get('volume_ingress', 0) + row.get('volume_egress', 0)),
                    'ingress_syn_count': row['ingress_syn_count'],
                    'egress_synack_count': row['egress_synack_count'],
                    'fin_count': row['fin_count'],
                    'rst_count': row['rst_count']
                }
            })

        cur.close()

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'period': period,
            'data_points': len(metrics),
            'metrics': metrics
        })

    except Exception as e:
        logger.error(f"Failed to get metrics for origin {origin_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.get('/origins/<origin_id>/metrics/latest')
def get_origin_metrics_latest(origin_id: str):
    """
    Get most recent metric snapshot (last 30s)

    Returns: Latest metric values
    Use case: Real-time monitoring, health checks

    """
    try:
        if origin_id not in state_manager.origins_db:
            return jsonify({'status': 'error', 'message': 'Origin not found'}), 404

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get latest metric
        cur.execute("""
            SELECT
                timestamp,
                pps, cps, bps,
                active_connections,
                syn_synack_ratio,
                conn_opened_total, conn_closed_total,
                packets_total, bytes_total,
                ingress_syn_count, egress_synack_count,
                fin_count, rst_count,
                volume_ingress, volume_egress
            FROM origin_metrics
            WHERE origin_id = %s
            ORDER BY timestamp DESC
            LIMIT 1
        """, (origin_id,))

        row = cur.fetchone()

        if not row:
            cur.close()
            return jsonify({
                'status': 'success',
                'origin_id': origin_id,
                'message': 'No metrics available yet'
            })

        metric = {
            'timestamp': row['timestamp'].isoformat(),
            'age_seconds': (datetime.now(timezone.utc) - row['timestamp']).total_seconds(),
            'pps': row['pps'],
            'cps': row['cps'],
            'bps': row['bps'],
            'active_connections': row['active_connections'],
            'syn_synack_ratio': float(row['syn_synack_ratio']) if row['syn_synack_ratio'] else None,
            'counters': {
                'conn_opened_total': row['conn_opened_total'],
                'conn_closed_total': row['conn_closed_total'],
                'packets_total': row['packets_total'],
                'bytes_total': row['bytes_total'] or (row.get('volume_ingress', 0) + row.get('volume_egress', 0)),
                'ingress_syn_count': row['ingress_syn_count'],
                'egress_synack_count': row['egress_synack_count'],
                'fin_count': row['fin_count'],
                'rst_count': row['rst_count']
            }
        }

        cur.close()

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'metric': metric
        })

    except Exception as e:
        logger.error(f"Failed to get latest metrics for origin {origin_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.get('/origins/<origin_id>/metrics/summary')
def get_origin_metrics_summary(origin_id: str):
    """
    Get aggregated statistics for a time period

    Query parameters:
    - period: Time period (1h, 6h, 24h, 7d, 30d) - default: 24h

    Returns: Min, max, avg, p95, p99 for pps/cps/bps/syn_synack_ratio
    Use case: Performance baselines, SLA reporting

    """
    try:
        if origin_id not in state_manager.origins_db:
            return jsonify({'status': 'error', 'message': 'Origin not found'}), 404

        period = request.args.get('period', '24h')
        period_map = {
            '1h': '1 hour',
            '6h': '6 hours',
            '24h': '24 hours',
            '7d': '7 days',
            '30d': '30 days'
        }
        interval = period_map.get(period, '24 hours')

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Calculate aggregates
        cur.execute("""
            SELECT
                COUNT(*) as sample_count,
                -- PPS stats
                MIN(pps) as min_pps,
                MAX(pps) as max_pps,
                AVG(pps) as avg_pps,
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY pps) as p95_pps,
                PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY pps) as p99_pps,
                -- CPS stats
                MIN(cps) as min_cps,
                MAX(cps) as max_cps,
                AVG(cps) as avg_cps,
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY cps) as p95_cps,
                -- BPS stats
                MIN(bps) as min_bps,
                MAX(bps) as max_bps,
                AVG(bps) as avg_bps,
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY bps) as p95_bps,
                -- SYN/SYN-ACK ratio stats
                MIN(syn_synack_ratio) as min_ratio,
                MAX(syn_synack_ratio) as max_ratio,
                AVG(syn_synack_ratio) as avg_ratio,
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY syn_synack_ratio) as p95_ratio,
                -- Active connections
                MAX(active_connections) as peak_connections,
                AVG(active_connections) as avg_connections
            FROM origin_metrics
            WHERE origin_id = %s
              AND timestamp > NOW() - INTERVAL %s
              AND pps IS NOT NULL
        """, (origin_id, interval))

        row = cur.fetchone()

        if row['sample_count'] == 0:
            cur.close()
            return jsonify({
                'status': 'success',
                'origin_id': origin_id,
                'message': 'No metrics available for period'
            })

        summary = {
            'period': period,
            'sample_count': row['sample_count'],
            'pps': {
                'min': row['min_pps'],
                'max': row['max_pps'],
                'avg': int(row['avg_pps']) if row['avg_pps'] else None,
                'p95': int(row['p95_pps']) if row['p95_pps'] else None,
                'p99': int(row['p99_pps']) if row['p99_pps'] else None
            },
            'cps': {
                'min': row['min_cps'],
                'max': row['max_cps'],
                'avg': int(row['avg_cps']) if row['avg_cps'] else None,
                'p95': int(row['p95_cps']) if row['p95_cps'] else None
            },
            'bps': {
                'min': row['min_bps'],
                'max': row['max_bps'],
                'avg': int(row['avg_bps']) if row['avg_bps'] else None,
                'p95': int(row['p95_bps']) if row['p95_bps'] else None
            },
            'syn_synack_ratio': {
                'min': float(row['min_ratio']) if row['min_ratio'] else None,
                'max': float(row['max_ratio']) if row['max_ratio'] else None,
                'avg': float(row['avg_ratio']) if row['avg_ratio'] else None,
                'p95': float(row['p95_ratio']) if row['p95_ratio'] else None
            },
            'active_connections': {
                'peak': row['peak_connections'],
                'avg': int(row['avg_connections']) if row['avg_connections'] else None
            }
        }

        cur.close()

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'summary': summary
        })

    except Exception as e:
        logger.error(f"Failed to get metrics summary for origin {origin_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.get('/metrics/system')
def get_system_metrics():
    """
    Get system-wide metrics (all origins + XDP counters + machine limits)

    Returns: Complete system state
    Use case: System-wide observability, debugging

    """
    try:
        # Get latest metrics for all origins from database
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cur.execute("""
            SELECT DISTINCT ON (origin_id)
                origin_id,
                timestamp,
                pps, cps, bps,
                active_connections,
                syn_synack_ratio
            FROM origin_metrics
            ORDER BY origin_id, timestamp DESC
        """)

        origin_metrics_data = {}
        for row in cur.fetchall():
            # Access as dict (RealDictCursor)
            origin_id = row['origin_id']
            origin_metrics_data[origin_id] = {
                'timestamp': row['timestamp'].isoformat() if row['timestamp'] else None,
                'pps': row['pps'],
                'cps': row['cps'],
                'bps': row['bps'],
                'active_connections': row['active_connections'],
                'syn_synack_ratio': float(row['syn_synack_ratio']) if row['syn_synack_ratio'] else None
            }

        # Get XDP stats from latest health report
        cur.execute("""
            SELECT
                xdp_pass,
                xdp_whitelist_bypass,
                xdp_drop_blacklist,
                xdp_drop_invalid_ip,
                xdp_drop_invalid_tcp,
                xdp_drop_ratelimit,
                xdp_drop_temp_blacklist,
                xdp_drop_bogon
            FROM ddos_metrics
            ORDER BY timestamp DESC
            LIMIT 1
        """)

        xdp_row = cur.fetchone()
        xdp_stats = {}
        if xdp_row:
            xdp_stats = {
                'pass': xdp_row['xdp_pass'],
                'whitelist_bypass': xdp_row['xdp_whitelist_bypass'],
                'drop_blacklist': xdp_row['xdp_drop_blacklist'],
                'drop_invalid_ip': xdp_row['xdp_drop_invalid_ip'],
                'drop_invalid_tcp': xdp_row['xdp_drop_invalid_tcp'],
                'drop_ratelimit': xdp_row['xdp_drop_ratelimit'],
                'drop_temp_blacklist': xdp_row['xdp_drop_temp_blacklist'],
                'drop_bogon': xdp_row['xdp_drop_bogon']
            }

        cur.close()

        # Get scrubber count
        scrubber_count = len(state_manager.nodes_db)

        return jsonify({
            'status': 'success',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'origins': origin_metrics_data,
            'xdp_stats': xdp_stats,
            'scrubber_count': scrubber_count,
            'origin_count': len(state_manager.origins_db)
        })

    except Exception as e:
        logger.error(f"Failed to get system metrics: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.get('/origins/<origin_id>/counters/raw')
def get_origin_raw_counters(origin_id: str):
    """
    Get raw lifetime counters directly from BPF map

    Returns: 7 x u64 raw counters from origin_stats_map
    Use case: Verification, troubleshooting delta calculation issues

    """
    try:
        if origin_id not in state_manager.origins_db:
            return jsonify({'status': 'error', 'message': 'Origin not found'}), 404

        origin = state_manager.origins_db[origin_id]
        origin_ip = origin['origin_ip']

        # Get active scrubber
        active_edge = state_manager.shard_state['active_edge']
        if active_edge not in state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'Active scrubber not found'}), 500

        scrubber_ip = state_manager.nodes_db[active_edge]['public_ip']

        # Convert origin_ip to hex key
        origin_ip_bytes = socket.inet_aton(origin_ip)
        origin_ip_hex = ' '.join([f'{b:02x}' for b in origin_ip_bytes])

        # Query BPF map directly
        rc, stdout, stderr = ssh_exec(
            scrubber_ip,
            f"sudo bpftool map lookup pinned /sys/fs/bpf/tc/globals/origin_stats_map key hex {origin_ip_hex} -j",
            settings.ssh_key_path,
            nodes_db=state_manager.nodes_db
        )

        if rc != 0:
            return jsonify({
                'status': 'error',
                'message': 'Failed to read BPF map',
                'stderr': stderr
            }), 500

        # Parse JSON output
        bpf_data = json.loads(stdout)

        # Extract raw value bytes
        value_hex = bpf_data.get('value', [])
        if isinstance(value_hex, str):
            value_bytes = bytes.fromhex(value_hex.replace(' ', ''))
        elif isinstance(value_hex, list):
            value_bytes = bytes([int(v, 16) if isinstance(v, str) else v for v in value_hex])
        else:
            return jsonify({'status': 'error', 'message': 'Invalid BPF map format'}), 500

        # Unpack 7 x u64 (little-endian)
        if len(value_bytes) >= 56:
            vals = struct.unpack('<7Q', value_bytes[:56])
            counters = {
                'conn_opened_total': vals[0],
                'conn_closed_total': vals[1],
                'packets_total': vals[2],
                'ingress_syn_count': vals[3],
                'egress_synack_count': vals[4],
                'fin_count': vals[5],
                'rst_count': vals[6]
            }
        else:
            return jsonify({'status': 'error', 'message': 'Invalid counter size'}), 500

        # Compute derived metrics
        active_connections = counters['conn_opened_total'] - counters['conn_closed_total']
        syn_synack_ratio = None
        if counters['egress_synack_count'] > 0:
            syn_synack_ratio = round(counters['ingress_syn_count'] / counters['egress_synack_count'], 2)

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'origin_ip': origin_ip,
            'scrubber': active_edge,
            'raw_counters': counters,
            'derived': {
                'active_connections': active_connections,
                'syn_synack_ratio': syn_synack_ratio
            }
        })

    except Exception as e:
        logger.error(f"Failed to get raw counters for origin {origin_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.get('/metrics/compare')
def compare_origin_metrics():
    """
    Compare metrics between two origins side-by-side

    Query parameters:
    - origin_a: First origin ID
    - origin_b: Second origin ID
    - period: Time period (1h, 6h, 24h) - default: 1h

    Returns: Side-by-side comparison
    Use case: Isolation testing, A/B performance analysis

    """
    try:
        origin_a = request.args.get('origin_a')
        origin_b = request.args.get('origin_b')

        if not origin_a or not origin_b:
            return jsonify({'status': 'error', 'message': 'Both origin_a and origin_b required'}), 400

        if origin_a not in state_manager.origins_db or origin_b not in state_manager.origins_db:
            return jsonify({'status': 'error', 'message': 'One or both origins not found'}), 404

        period = request.args.get('period', '1h')
        period_map = {'1h': '1 hour', '6h': '6 hours', '24h': '24 hours'}
        interval = period_map.get(period, '1 hour')

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get stats for both origins
        results = {}
        for origin_id in [origin_a, origin_b]:
            cur.execute("""
                SELECT
                    COUNT(*) as sample_count,
                    SUM(packets_total) as total_packets,
                    AVG(pps) as avg_pps,
                    AVG(cps) as avg_cps,
                    AVG(active_connections) as avg_connections,
                    AVG(syn_synack_ratio) as avg_ratio
                FROM origin_metrics
                WHERE origin_id = %s
                  AND timestamp > NOW() - INTERVAL %s
            """, (origin_id, interval))

            row = cur.fetchone()
            results[origin_id] = {
                'sample_count': row['sample_count'],
                'total_packets': row['total_packets'],
                'avg_pps': int(row['avg_pps']) if row['avg_pps'] else 0,
                'avg_cps': int(row['avg_cps']) if row['avg_cps'] else 0,
                'avg_connections': int(row['avg_connections']) if row['avg_connections'] else 0,
                'avg_syn_ratio': float(row['avg_ratio']) if row['avg_ratio'] else None
            }

        cur.close()

        # Calculate isolation score (0 = perfect isolation, 1 = complete contamination)
        isolation_score = 0.0
        if results[origin_a]['total_packets'] and results[origin_b]['total_packets']:
            # If traffic patterns are identical, isolation may be compromised
            diff_ratio = abs(results[origin_a]['avg_pps'] - results[origin_b]['avg_pps']) / max(results[origin_a]['avg_pps'], results[origin_b]['avg_pps'], 1)
            isolation_score = 1.0 - diff_ratio

        return jsonify({
            'status': 'success',
            'period': period,
            'comparison': {
                origin_a: results[origin_a],
                origin_b: results[origin_b]
            },
            'isolation_score': round(isolation_score, 3),
            'isolation_ok': isolation_score < 0.1  # <10% similarity = good isolation
        })

    except Exception as e:
        logger.error(f"Failed to compare origin metrics: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.get('/protocol/stats')
def get_protocol_stats():
    """
    Get Layer 2 (protocol validation) statistics from all scrubbers

    Returns: Bogon, invalid IP, invalid TCP drop counts per scrubber
    Use case: Layer 2 validation monitoring

    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            # Get latest Layer 2 stats per scrubber (last 24h)
            cur.execute("""
                SELECT
                    node_id,
                    SUM(xdp_drop_bogon) as bogon_drops,
                    SUM(xdp_drop_invalid_ip) as invalid_ip_drops,
                    SUM(xdp_drop_invalid_tcp) as invalid_tcp_drops,
                    SUM(xdp_drop_bogon + xdp_drop_invalid_ip + xdp_drop_invalid_tcp) as total_layer2_drops,
                    COUNT(*) as sample_count,
                    MAX(timestamp) as last_update
                FROM ddos_metrics
                WHERE timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY node_id
                ORDER BY node_id
            """)

            scrubber_stats = cur.fetchall()

            # Calculate totals
            total_bogon = sum(row['bogon_drops'] or 0 for row in scrubber_stats)
            total_invalid_ip = sum(row['invalid_ip_drops'] or 0 for row in scrubber_stats)
            total_invalid_tcp = sum(row['invalid_tcp_drops'] or 0 for row in scrubber_stats)

            return jsonify({
                'status': 'success',
                'layer': 'Layer 2 - Protocol Validation',
                'scrubbers': [
                    {
                        'node_id': row['node_id'],
                        'bogon_drops': int(row['bogon_drops'] or 0),
                        'invalid_ip_drops': int(row['invalid_ip_drops'] or 0),
                        'invalid_tcp_drops': int(row['invalid_tcp_drops'] or 0),
                        'total_drops': int(row['total_layer2_drops'] or 0),
                        'samples': row['sample_count'],
                        'last_update': row['last_update'].isoformat() if row['last_update'] else None
                    }
                    for row in scrubber_stats
                ],
                'totals': {
                    'bogon_drops': total_bogon,
                    'invalid_ip_drops': total_invalid_ip,
                    'invalid_tcp_drops': total_invalid_tcp,
                    'total_layer2_drops': total_bogon + total_invalid_ip + total_invalid_tcp
                }
            })
        finally:
            cur.close()

    except Exception as e:
        logger.error(f"Failed to get protocol stats: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.get('/protocol/bogon-ranges')
def list_bogon_ranges():
    """
    List all bogon ranges currently filtered (informational)

    Returns: List of bogon ranges with descriptions
    Use case: Documentation, debugging

    """
    bogon_ranges = [
        {'range': '0.0.0.0/8', 'description': 'This network (RFC 1122)'},
        {'range': '10.0.0.0/8', 'description': 'RFC 1918 private'},
        {'range': '127.0.0.0/8', 'description': 'Loopback (RFC 1122)'},
        {'range': '169.254.0.0/16', 'description': 'Link-local (RFC 3927)'},
        {'range': '172.16.0.0/12', 'description': 'RFC 1918 private'},
        {'range': '192.0.2.0/24', 'description': 'TEST-NET-1 (RFC 5737)'},
        {'range': '192.168.0.0/16', 'description': 'RFC 1918 private'},
        {'range': '198.51.100.0/24', 'description': 'TEST-NET-2 (RFC 5737)'},
        {'range': '203.0.113.0/24', 'description': 'TEST-NET-3 (RFC 5737)'},
        {'range': '224.0.0.0/4', 'description': 'Multicast (RFC 5771)'},
        {'range': '240.0.0.0/4', 'description': 'Reserved/future use'},
        {'range': '255.255.255.255/32', 'description': 'Broadcast'}
    ]

    return jsonify({
        'status': 'success',
        'bogon_ranges': bogon_ranges,
        'total_ranges': len(bogon_ranges),
        'note': 'These ranges are hardcoded in XDP (check_bogon_source function)'
    })


@bp.route('/ratelimit/top_blocked', methods=['GET'])
def get_top_blocked_ips():
    """
    Get top IPs by blocked_count in last N hours

    Query params:
    - limit: Number of results (default 50)
    - hours: Time window (default 1)

    """
    try:
        limit = request.args.get('limit', 50, type=int)
        hours = request.args.get('hours', 1, type=int)

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT
                ip_address,
                SUM(blocked_count) as total_blocked,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                array_agg(DISTINCT node_id) as nodes
            FROM ratelimit_stats
            WHERE timestamp > NOW() - INTERVAL '%s hours'
            GROUP BY ip_address
            ORDER BY total_blocked DESC
            LIMIT %s
        """, (hours, limit))

        results = []
        for row in cur.fetchall():
            results.append({
                'ip': str(row[0]),
                'total_blocked': row[1],
                'first_seen': row[2].isoformat() if row[2] else None,
                'last_seen': row[3].isoformat() if row[3] else None,
                'nodes': row[4]
            })

        cur.close()
        conn.close()

        return jsonify(results)

    except Exception as e:
        logger.error(f"Failed to query top blocked IPs: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/ratelimit/effectiveness', methods=['GET'])
def get_ratelimit_effectiveness():
    """
    Calculate rate limit effectiveness metrics

    Query params:
    - hours: Time window (default 1)

    """
    try:
        hours = request.args.get('hours', 1, type=int)

        conn = get_db_connection()
        cur = conn.cursor()

        # Get rate limited count from ddos_metrics
        cur.execute("""
            SELECT SUM(xdp_drop_ratelimit) as total_rl,
                   SUM(xdp_pass) as total_pass
            FROM ddos_metrics
            WHERE timestamp > NOW() - INTERVAL '%s hours'
        """, (hours,))

        row = cur.fetchone()
        total_rl = (row[0] or 0) if row else 0
        total_pass = (row[1] or 0) if row else 0

        # Get distinct IPs blocked
        cur.execute("""
            SELECT COUNT(DISTINCT ip_address) as distinct_ips,
                   AVG(blocked_count) as avg_blocked
            FROM ratelimit_stats
            WHERE timestamp > NOW() - INTERVAL '%s hours'
        """, (hours,))

        stats_row = cur.fetchone()
        distinct_ips = (stats_row[0] or 0) if stats_row else 0
        avg_blocked = float(stats_row[1] or 0) if stats_row else 0.0

        cur.close()
        conn.close()

        return jsonify({
            'total_rate_limited': total_rl,
            'total_passed': total_pass,
            'block_rate': (total_rl / (total_rl + total_pass)
                          if (total_rl + total_pass) > 0 else 0),
            'distinct_sources_blocked': distinct_ips,
            'avg_blocked_per_ip': avg_blocked
        })

    except Exception as e:
        logger.error(f"Failed to calculate effectiveness: {e}")
        return jsonify({'error': str(e)}), 500
