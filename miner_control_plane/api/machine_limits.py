"""Machine Limits API

LAYER 5: Machine Limits & Runtime Configurability + Metrics Configuration

Provides endpoints for:
- GET/PUT/RESET scrubber machine limits (token bucket parameters)
- GET/PUT metrics system configuration
"""
import json
import struct
import logging
from flask import Blueprint, request, jsonify
import psycopg2.extras

from shared.config import get_settings
from shared.database import get_db_connection
from shared.utils.ssh import ssh_exec
from shared.utils.bpf_helpers import apply_bpf_map_all, get_map_path, lookup_bpf_map
from miner_control_plane.services.state_manager import state_manager

logger = logging.getLogger(__name__)
settings = get_settings()

bp = Blueprint('machine_limits', __name__, url_prefix='/api/v1')

# Global metrics configuration (in-memory, persists until restart)
metrics_config = {
    'reporting_interval_seconds': 30,
    'retention_days': 90,
    'syn_flood_threshold': 10.0,
    'high_pps_threshold': 1000000,
    'high_cps_threshold': 10000,
    'enable_hourly_aggregation': True
}


# ============================================================================
# MACHINE LIMITS ENDPOINTS
# ============================================================================
def _read_machine_limit_bytes(instance_name: str) -> bytes:
    """Lookup machine_limits_map for a scrubber and return raw bytes."""
    node = state_manager.get_node(instance_name)
    if not node:
        raise RuntimeError(f"Node {instance_name} not found")
    scrubber_ip = node['public_ip']
    provider = node.get('provider', 'aws')

    success, payload, error = lookup_bpf_map(
        scrubber_ip,
        get_map_path('machine_limits'),
        "00 00 00 00",
        settings.ssh_key_path,
        provider=provider
    )
    if not success or not payload:
        raise RuntimeError(error or 'lookup_failed')

    value_field = payload.get('value')
    if isinstance(value_field, str):
        return bytes.fromhex(value_field.replace(' ', ''))
    if isinstance(value_field, list):
        return bytes([int(v, 16) if isinstance(v, str) else v for v in value_field])
    formatted = payload.get('formatted', {}).get('value')
    if isinstance(formatted, dict):
        # Convert dict fields (e.g., {"token_capacity":123,"token_refill_rate":456}) to bytes
        capacity = int(formatted.get('token_capacity', 0))
        rate = int(formatted.get('token_refill_rate', 0))
        return struct.pack('<2I', capacity, rate)
    raise RuntimeError('invalid_bpf_value')


@bp.route('/scrubbers/<instance_name>/limits', methods=['GET'])
def get_scrubber_limits(instance_name: str):
    """
    Get current machine limits for a scrubber

    Args:
        instance_name: edge-a or edge-b

    Returns: Current limits (capacity, refill_rate, base_values, load_multiplier)
    Use case: Monitoring, verification, troubleshooting
    """
    try:
        node = state_manager.get_node(instance_name)
        if not node:
            return jsonify({
                'status': 'error',
                'message': f'Scrubber {instance_name} not found'
            }), 404

        scrubber_ip = node['public_ip']
        node_id = node.get('instance_id') or node.get('node_id')

        try:
            value_bytes = _read_machine_limit_bytes(instance_name)
        except Exception as exc:
            return jsonify({
                'status': 'error',
                'message': 'Failed to read machine_limits_map',
                'stderr': str(exc)
            }), 500

        # Unpack 2 x u32 (little-endian)
        if len(value_bytes) >= 8:
            token_capacity, token_refill_rate = struct.unpack('<2I', value_bytes[:8])
        else:
            return jsonify({
                'status': 'error',
                'message': 'Invalid limit size'
            }), 500

        # Get base hardware limits for comparison
        rc, stdout, stderr = ssh_exec(
            scrubber_ip,
            "nproc && free -g | awk '/Mem:/ {print $2}'",
            ssh_key_path=settings.ssh_key_path,
            nodes_db=state_manager.nodes_db
        )
        cpu_count = 1
        ram_gb = 4
        if rc == 0:
            lines = stdout.strip().split('\n')
            cpu_count = int(lines[0])
            ram_gb = int(lines[1]) if len(lines) > 1 else 4

        # Calculate base limits (same formula as module 37)
        max_pps = cpu_count * 9000000
        per_source_pps = (max_pps * 5) // 100 // 10000
        base_capacity = per_source_pps * 10
        base_rate = per_source_pps

        # Calculate load multiplier (current / base)
        load_multiplier = token_refill_rate / base_rate if base_rate > 0 else 1.0

        # Get latest CPU usage
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT cpu_pct
            FROM health_node
            WHERE node_id = %s
            ORDER BY last_seen DESC
            LIMIT 1
        """, (node_id,))
        row = cur.fetchone()
        cpu_pct = float(row['cpu_pct']) if row and row['cpu_pct'] else None
        cur.close()
        conn.close()

        return jsonify({
            'status': 'success',
            'instance_name': instance_name,
            'current_limits': {
                'token_capacity': token_capacity,
                'token_refill_rate': token_refill_rate
            },
            'base_limits': {
                'token_capacity': base_capacity,
                'token_refill_rate': base_rate
            },
            'hardware': {
                'cpu_count': cpu_count,
                'ram_gb': ram_gb,
                'max_pps': max_pps
            },
            'load_multiplier': round(load_multiplier, 2),
            'cpu_pct': cpu_pct,
            'mode': 'manual' if abs(load_multiplier - 1.0) > 0.15 else 'auto'
        })

    except Exception as e:
        logger.error(f"Failed to get limits for scrubber {instance_name}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/scrubbers/<instance_name>/limits', methods=['PUT'])
def set_scrubber_limits(instance_name: str):
    """
    Override machine limits (manual mode)

    Args:
        instance_name: edge-a or edge-b

    Request body:
    {
        "token_capacity": 1000,      // Optional: burst size
        "token_refill_rate": 100,    // Optional: tokens/sec
        "mode": "manual"              // "manual" or "auto"
    }

    Use cases:
    - Emergency throttling during overload
    - Testing with known values
    - Custom tuning for specific traffic patterns
    """
    try:
        node = state_manager.get_node(instance_name)
        if not node:
            return jsonify({
                'status': 'error',
                'message': f'Scrubber {instance_name} not found'
            }), 404

        data = request.json
        scrubber_ip = node['public_ip']

        current_capacity = None
        current_rate = None

        try:
            value_bytes = _read_machine_limit_bytes(instance_name)
            if len(value_bytes) >= 8:
                current_capacity, current_rate = struct.unpack('<2I', value_bytes[:8])
        except Exception:
            current_capacity = None
            current_rate = None

        # Use provided values or keep current
        token_capacity = data.get('token_capacity', current_capacity)
        token_refill_rate = data.get('token_refill_rate', current_rate)
        mode = data.get('mode', 'manual')

        if token_capacity is None or token_refill_rate is None:
            return jsonify({
                'status': 'error',
                'message': 'Must provide both capacity and rate'
            }), 400

        # Validate values
        if token_capacity < 10 or token_capacity > 100000:
            return jsonify({
                'status': 'error',
                'message': 'Capacity must be 10-100000'
            }), 400

        if token_refill_rate < 1 or token_refill_rate > 10000:
            return jsonify({
                'status': 'error',
                'message': 'Refill rate must be 1-10000'
            }), 400

        # Pack as little-endian 32-bit integers
        value_bytes = struct.pack('<2I', token_capacity, token_refill_rate)
        value_hex = ' '.join([f'{b:02x}' for b in value_bytes])

        # Update BPF map
        node_key = node.get('node_id') or instance_name
        results = apply_bpf_map_all(
            nodes={node_key: node},
            map_path=get_map_path('machine_limits'),
            key_hex="00 00 00 00",
            value_hex=value_hex,
            ssh_key_path=settings.ssh_key_path,
            verify=True
        )

        if not results[node_key].success:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update machine limits',
                'stderr': results[node_key].stderr or results[node_key].verification_error
            }), 500

        # Log to mitigation_actions
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO mitigation_actions (
                ip_address, origin_id, action_type, severity
            ) VALUES (%s, %s, %s, %s)
        """, (
            '0.0.0.0',  # Global action
            None,
            'machine_limits_override',
            'info'
        ))
        conn.commit()
        cur.close()
        conn.close()

        logger.info(
            f"Machine limits updated for {instance_name}: "
            f"capacity={token_capacity}, rate={token_refill_rate}, mode={mode}"
        )

        return jsonify({
            'status': 'success',
            'instance_name': instance_name,
            'updated_limits': {
                'token_capacity': token_capacity,
                'token_refill_rate': token_refill_rate
            },
            'mode': mode,
            'message': 'Limits updated. Note: Adaptive scaling will override in ~60s '
                      'unless mode=manual is persistent.'
        })

    except Exception as e:
        logger.error(f"Failed to set limits for scrubber {instance_name}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/scrubbers/<instance_name>/limits/reset', methods=['POST'])
def reset_scrubber_limits(instance_name: str):
    """
    Recalculate base limits from hardware and restore auto-scaling

    Args:
        instance_name: edge-a or edge-b

    Use cases:
    - Undo manual overrides
    - Apply after instance type change/resize
    - Restore optimal values
    """
    try:
        node = state_manager.get_node(instance_name)
        if not node:
            return jsonify({
                'status': 'error',
                'message': f'Scrubber {instance_name} not found'
            }), 404

        scrubber_ip = node['public_ip']

        # Re-run module 37 logic
        rc, stdout, stderr = ssh_exec(
            scrubber_ip,
            "nproc && free -g | awk '/Mem:/ {print $2}'",
            ssh_key_path=settings.ssh_key_path,
            nodes_db=state_manager.nodes_db
        )

        if rc != 0:
            return jsonify({
                'status': 'error',
                'message': 'Failed to detect hardware'
            }), 500

        lines = stdout.strip().split('\n')
        cpu_count = int(lines[0])
        ram_gb = int(lines[1]) if len(lines) > 1 else 4

        # Calculate base limits (module 37 formula)
        max_pps = cpu_count * 9000000
        per_source_pps = (max_pps * 5) // 100 // 10000
        token_capacity = per_source_pps * 10
        token_refill_rate = per_source_pps

        # Pack and update
        value_bytes = struct.pack('<2I', token_capacity, token_refill_rate)
        value_hex = ' '.join([f'{b:02x}' for b in value_bytes])

        node_key = node.get('node_id') or instance_name
        results = apply_bpf_map_all(
            nodes={node_key: node},
            map_path=get_map_path('machine_limits'),
            key_hex="00 00 00 00",
            value_hex=value_hex,
            ssh_key_path=settings.ssh_key_path,
            verify=True
        )

        if not results[node_key].success:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update machine limits',
                'stderr': results[node_key].stderr or results[node_key].verification_error
            }), 500

        # Log to mitigation_actions
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO mitigation_actions (
                ip_address, origin_id, action_type, severity
            ) VALUES (%s, %s, %s, %s)
        """, (
            '0.0.0.0',  # Global action
            None,
            'machine_limits_reset',
            'info'
        ))
        conn.commit()
        cur.close()
        conn.close()

        logger.info(
            f"Machine limits reset for {instance_name}: "
            f"capacity={token_capacity}, rate={token_refill_rate} "
            f"(based on {cpu_count} CPUs)"
        )

        return jsonify({
            'status': 'success',
            'instance_name': instance_name,
            'hardware': {
                'cpu_count': cpu_count,
                'ram_gb': ram_gb,
                'max_pps': max_pps
            },
            'reset_limits': {
                'token_capacity': token_capacity,
                'token_refill_rate': token_refill_rate
            },
            'mode': 'auto',
            'message': 'Limits reset to hardware-based values. Adaptive scaling resumed.'
        })

    except Exception as e:
        logger.error(f"Failed to reset limits for scrubber {instance_name}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================================================
# METRICS CONFIGURATION ENDPOINTS
# ============================================================================

@bp.route('/config/metrics', methods=['GET'])
def get_metrics_config():
    """
    Get current metrics system configuration

    Returns: All configurable metrics parameters
    Use case: Verification, documentation, troubleshooting
    """
    try:
        # Get actual ecp-agent reporting interval from database
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get latest metric age to infer actual reporting interval
        cur.execute("""
            SELECT origin_id, timestamp
            FROM origin_metrics
            ORDER BY timestamp DESC
            LIMIT 2
        """)
        rows_list = cur.fetchall()

        actual_interval = None
        if len(rows_list) == 2:
            # Access as list of dicts
            ts0 = rows_list[0]['timestamp']
            ts1 = rows_list[1]['timestamp']
            delta = (ts0 - ts1).total_seconds()
            actual_interval = int(delta) if delta > 0 else None

        # Get metrics table size
        cur.execute("""
            SELECT
                COUNT(*) as total_rows,
                MIN(timestamp) as oldest,
                MAX(timestamp) as newest,
                pg_size_pretty(pg_total_relation_size('origin_metrics')) as table_size
            FROM origin_metrics
        """)
        stats_data = cur.fetchone()

        cur.close()
        conn.close()

        return jsonify({
            'status': 'success',
            'configuration': metrics_config,
            'actual_state': {
                'reporting_interval_seconds': actual_interval,
                'total_metric_rows': stats_data['total_rows'],
                'oldest_metric': (
                    stats_data['oldest'].isoformat()
                    if stats_data and stats_data['oldest'] else None
                ),
                'newest_metric': (
                    stats_data['newest'].isoformat()
                    if stats_data and stats_data['newest'] else None
                ),
                'table_size': stats_data['table_size'] if stats_data else None
            }
        })

    except Exception as e:
        logger.error(f"Failed to get metrics config: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/config/metrics', methods=['PUT'])
def update_metrics_config():
    """
    Update metrics system configuration

    Request body:
    {
        "reporting_interval_seconds": 30,      // ecp-agent interval (10-300)
        "retention_days": 90,                  // Database retention (7-365)
        "syn_flood_threshold": 10.0,           // SYN/SYN-ACK ratio warning (5.0-50.0)
        "high_pps_threshold": 1000000,         // High traffic alert (100k-10M)
        "high_cps_threshold": 10000,           // High CPS alert (1k-100k)
        "enable_hourly_aggregation": true      // Pre-compute hourly stats
    }

    Use cases:
    - Tune sensitivity based on traffic patterns
    - Adjust retention for compliance requirements
    - Enable/disable features
    """
    try:
        data = request.json

        # Validate and update each field
        updated = []

        if 'reporting_interval_seconds' in data:
            interval = int(data['reporting_interval_seconds'])
            if interval < 10 or interval > 300:
                return jsonify({
                    'status': 'error',
                    'message': 'Interval must be 10-300 seconds'
                }), 400
            metrics_config['reporting_interval_seconds'] = interval
            updated.append('reporting_interval_seconds')
            logger.warning(
                "Note: ecp-agent restart required for reporting_interval change "
                "to take effect"
            )

        if 'retention_days' in data:
            days = int(data['retention_days'])
            if days < 7 or days > 365:
                return jsonify({
                    'status': 'error',
                    'message': 'Retention must be 7-365 days'
                }), 400
            metrics_config['retention_days'] = days
            updated.append('retention_days')

        if 'syn_flood_threshold' in data:
            threshold = float(data['syn_flood_threshold'])
            if threshold < 5.0 or threshold > 50.0:
                return jsonify({
                    'status': 'error',
                    'message': 'SYN threshold must be 5.0-50.0'
                }), 400
            metrics_config['syn_flood_threshold'] = threshold
            updated.append('syn_flood_threshold')

        if 'high_pps_threshold' in data:
            threshold = int(data['high_pps_threshold'])
            if threshold < 100000 or threshold > 10000000:
                return jsonify({
                    'status': 'error',
                    'message': 'PPS threshold must be 100k-10M'
                }), 400
            metrics_config['high_pps_threshold'] = threshold
            updated.append('high_pps_threshold')

        if 'high_cps_threshold' in data:
            threshold = int(data['high_cps_threshold'])
            if threshold < 1000 or threshold > 100000:
                return jsonify({
                    'status': 'error',
                    'message': 'CPS threshold must be 1k-100k'
                }), 400
            metrics_config['high_cps_threshold'] = threshold
            updated.append('high_cps_threshold')

        if 'enable_hourly_aggregation' in data:
            metrics_config['enable_hourly_aggregation'] = bool(
                data['enable_hourly_aggregation']
            )
            updated.append('enable_hourly_aggregation')

        if not updated:
            return jsonify({
                'status': 'error',
                'message': 'No valid fields to update'
            }), 400

        # Log to mitigation_actions
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO mitigation_actions (
                ip_address, origin_id, action_type, severity
            ) VALUES (%s, %s, %s, %s)
        """, (
            '0.0.0.0',  # Global config change
            None,
            'metrics_config_update',
            'info'
        ))
        conn.commit()
        cur.close()
        conn.close()

        logger.info(f"Metrics configuration updated: {', '.join(updated)}")

        return jsonify({
            'status': 'success',
            'updated_fields': updated,
            'new_configuration': metrics_config,
            'notes': [
                'ecp-agent restart required for reporting_interval changes',
                'Retention changes apply to future db_maintenance runs',
                'Thresholds apply immediately to new metrics'
            ]
        })

    except Exception as e:
        logger.error(f"Failed to update metrics config: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================================================
# GLOBAL MACHINE LIMITS ENDPOINTS (Added from migration plan Task 6)
# ============================================================================

@bp.route('/machine_limits', methods=['POST'])
def update_machine_limits():
    """
    Update token bucket parameters dynamically on all scrubbers

    Request Body:
    {
        "token_capacity": 10000,      // Optional: override capacity
        "token_refill_rate": 1000,    // Optional: override refill rate
        "auto_scale": true,           // Optional: recalculate from hardware
        "multiplier": 1.5             // Optional: scale factor (1.0 = 100%)
    }

    """
    try:
        data = request.get_json()

        if not state_manager.nodes_db:
            return jsonify({
                'status': 'error',
                'message': 'No scrubbers available'
            }), 500

        # Auto-scale: recalculate from hardware
        if data.get('auto_scale'):
            updated = []
            for edge_name, node in state_manager.nodes_db.items():
                host_ip = node['public_ip']
                rc, out, err = ssh_exec(
                    host_ip,
                    "bash /opt/tensorprox/modules/37-machine-limits.sh",
                    settings.ssh_key_path,
                    nodes_db=state_manager.nodes_db
                )
                if rc == 0:
                    updated.append(edge_name)
                    logger.info(f"Machine limits recalculated on {edge_name}")
                else:
                    logger.error(
                        f"Failed to recalculate on {edge_name}: {err}"
                    )

            if len(updated) == 0:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to recalculate on any scrubber'
                }), 500

            return jsonify({
                'status': 'success',
                'message': 'Machine limits recalculated from hardware',
                'updated_scrubbers': updated
            })

        # Manual override
        capacity = data.get('token_capacity')
        rate = data.get('token_refill_rate')
        multiplier = data.get('multiplier', 1.0)

        if not capacity or not rate:
            return jsonify({
                'status': 'error',
                'message': 'token_capacity and token_refill_rate required'
            }), 400

        # Apply multiplier
        capacity = int(capacity * multiplier)
        rate = int(rate * multiplier)

        # Pack as little-endian 32-bit integers (2 x u32 = 8 bytes)
        value_bytes = struct.pack('<2I', capacity, rate)
        value_hex = ' '.join([f'{b:02x}' for b in value_bytes])

        # Update BPF maps on all scrubbers
        updated = []
        for edge_name, node in state_manager.nodes_db.items():
            host_ip = node['public_ip']

            # NOTE: machine_limits_map is an XDP map (defined in xdp_wan.c)
            # so it's pinned at /sys/fs/bpf/xdp/globals/ (NOT tc/globals/)
            cmd = (f"sudo bpftool map update pinned "
                  f"/sys/fs/bpf/xdp/globals/machine_limits_map "
                  f"key hex 00 00 00 00 value hex {value_hex}")
            rc, out, err = ssh_exec(
                host_ip, cmd,
                settings.ssh_key_path,
                nodes_db=state_manager.nodes_db
            )

            if rc == 0:
                updated.append(edge_name)
                logger.info(
                    f"Machine limits updated on {edge_name}: "
                    f"cap={capacity}, rate={rate}"
                )
            else:
                logger.error(f"BPF update failed on {edge_name}: {err}")

        if len(updated) == 0:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update any scrubbers'
            }), 500

        # Log to audit_log
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO audit_log (action, details, user_id)
            VALUES (%s, %s, %s)
        """, ('machine_limits_update', json.dumps({
            'capacity': capacity,
            'rate': rate,
            'multiplier': multiplier
        }), 'api'))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            'status': 'success',
            'token_capacity': capacity,
            'token_refill_rate': rate,
            'max_burst_seconds': capacity / rate if rate > 0 else 0,
            'updated_scrubbers': updated
        })

    except Exception as e:
        logger.error(f"Machine limits update failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/machine_limits', methods=['GET'])
def get_machine_limits():
    """
    Query current machine limits (token bucket capacity/refill rate)
    from all scrubbers

    """
    try:
        if not state_manager.nodes_db:
            return jsonify({
                'status': 'error',
                'message': 'No scrubbers available'
            }), 500

        results = {}

        for edge_name, node in state_manager.nodes_db.items():
            host_ip = node['public_ip']

            # NOTE: machine_limits_map is an XDP map (defined in xdp_wan.c)
            rc, stdout, stderr = ssh_exec(
                host_ip,
                "sudo bpftool map dump pinned "
                "/sys/fs/bpf/xdp/globals/machine_limits_map --json",
                settings.ssh_key_path,
                nodes_db=state_manager.nodes_db
            )

            if rc == 0:
                try:
                    map_data = json.loads(stdout)
                    if map_data and len(map_data) > 0:
                        entry = map_data[0]
                        # Parse value (2 x u32 = 8 bytes: capacity, refill_rate)
                        if ('formatted' in entry and
                                'value' in entry['formatted']):
                            # Formatted parsing (if available)
                            formatted_val = entry['formatted']['value']
                            if isinstance(formatted_val, dict):
                                capacity = formatted_val.get('token_capacity', 0)
                                refill = formatted_val.get(
                                    'token_refill_rate', 0
                                )
                            else:
                                capacity = 1000  # Default
                                refill = 100
                        else:
                            # Manual hex parsing
                            value_hex = entry.get('value', '')
                            if isinstance(value_hex, str):
                                value_bytes = bytes.fromhex(
                                    value_hex.replace(' ', '')
                                )
                            elif isinstance(value_hex, list):
                                value_bytes = bytes([
                                    int(v, 16) if isinstance(v, str) else v
                                    for v in value_hex[:8]
                                ])
                            else:
                                value_bytes = b'\x00' * 8

                            if len(value_bytes) >= 8:
                                capacity, refill = struct.unpack(
                                    '<2I', value_bytes[:8]
                                )
                            else:
                                capacity, refill = 1000, 100

                        results[edge_name] = {
                            'token_capacity': capacity,
                            'token_refill_rate': refill,
                            'max_burst_seconds': (capacity / refill
                                                 if refill > 0 else 0),
                            'packets_per_second': refill
                        }
                except Exception as e:
                    logger.error(
                        f"Failed to parse machine limits for {edge_name}: {e}"
                    )
                    results[edge_name] = {'error': str(e)}
            else:
                results[edge_name] = {'error': f'Query failed: {stderr[:100]}'}

        return jsonify({
            'status': 'success',
            'scrubbers': results
        })

    except Exception as e:
        logger.error(f"Failed to get machine limits: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
