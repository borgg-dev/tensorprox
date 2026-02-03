"""Anomaly Detection Configuration API Blueprint - Layer 7

Configuration management for anomaly detection system with:
- Global configuration (27 parameters)
- Per-origin overrides
- Configuration presets (Conservative, Balanced, Aggressive, Manual)
- Audit trail for all changes
- Hot-reload support (no restart required)

Endpoints:
    GET  /api/v1/config/anomaly_detection                       - Get global config (27 params)
    PUT  /api/v1/config/anomaly_detection                       - Update global config
    POST /api/v1/config/anomaly_detection/reset                 - Reset to factory defaults
    GET  /api/v1/config/anomaly_detection/presets               - List available presets
    POST /api/v1/config/anomaly_detection/apply_preset          - Apply a preset
    GET  /api/v1/origins/<origin_id>/anomaly_config             - Get per-origin config
    PUT  /api/v1/origins/<origin_id>/anomaly_config             - Set per-origin overrides
    DELETE /api/v1/origins/<origin_id>/anomaly_config           - Clear per-origin overrides
    GET  /api/v1/config/anomaly_detection/changelog             - Get audit trail
"""
from flask import Blueprint, request, jsonify
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Optional, Dict, Any

# Import shared utilities
from shared.database import get_db_connection

logger = logging.getLogger(__name__)

bp = Blueprint('anomaly_detection', __name__, url_prefix='/api/v1')


# ============================================================================
# GLOBAL CONFIGURATION ENDPOINTS
# ============================================================================

@bp.route('/config/anomaly_detection', methods=['GET'])
def get_anomaly_detection_config():
    """
    Get global anomaly detection configuration (27 parameters)

    Returns structured configuration with:
    - Detection thresholds (6 params): Z-scores, PPS/CPS multipliers
    - Hysteresis delays (4 params): De-escalation timers
    - Challenge level multipliers (4 params): Rate limit impact per level
    - Escalation rules (5 params): Attack type → challenge level mapping
    - Behavior flags (5 params): Enable/disable auto-escalation
    - Loop settings (3 params): Loop interval, config reload interval

    Returns:
        200: Configuration data
        404: Config not found
        500: Server error

    Example:
        GET /api/v1/config/anomaly_detection

        Response:
        {
            "detection_thresholds": {
                "z_score_threshold": 3.0,
                "pps_multiplier_threshold": 2.0,
                ...
            },
            "hysteresis_delays": {...},
            "challenge_level_multipliers": {...},
            "escalation_rules": {...},
            "behavior": {...},
            "loop_settings": {...}
        }
    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT * FROM anomaly_detection_config WHERE config_id = 1")
        cfg = cur.fetchone()

        cur.close()

        if not cfg:
            return jsonify({'error': 'Config not found'}), 404

        # Structure response (27 parameters organized into 6 groups)
        return jsonify({
            'detection_thresholds': {
                'z_score_threshold': float(cfg['z_score_threshold']),
                'pps_multiplier_threshold': float(cfg['pps_multiplier_threshold']),
                'cps_multiplier_threshold': float(cfg['cps_multiplier_threshold']),
                'syn_ratio_threshold': float(cfg['syn_ratio_threshold']),
                'active_conn_threshold': float(cfg['active_conn_threshold']),
                'consecutive_samples_to_activate': cfg['consecutive_samples_to_activate']
            },
            'hysteresis_delays': {
                'level_3_to_2_delay': cfg['level_3_to_2_delay'],
                'level_2_to_1_delay': cfg['level_2_to_1_delay'],
                'level_1_to_0_delay': cfg['level_1_to_0_delay'],
                'escalation_cooldown': cfg['escalation_cooldown']
            },
            'challenge_level_multipliers': {
                'level_1': float(cfg['level_1_multiplier']),
                'level_2': float(cfg['level_2_multiplier']),
                'level_3': float(cfg['level_3_multiplier']),
                'level_4': float(cfg['level_4_multiplier'])
            },
            'escalation_rules': {
                'pps_spike_level': cfg['pps_spike_level'],
                'syn_flood_level': cfg['syn_flood_level'],
                'cps_spike_level': cfg['cps_spike_level'],
                'state_exhaustion_level': cfg['state_exhaustion_level'],
                'multi_origin_threshold': cfg['multi_origin_threshold']
            },
            'behavior': {
                'enable_auto_escalation': cfg['enable_auto_escalation'],
                'enable_auto_deescalation': cfg['enable_auto_deescalation'],
                'enable_global_escalation': cfg['enable_global_escalation'],
                'baseline_required': cfg['baseline_required'],
                'static_threshold_fallback': cfg['static_threshold_fallback']
            },
            'loop_settings': {
                'loop_interval': cfg['loop_interval'],
                'min_samples_before_detection': cfg['min_samples_before_detection'],
                'config_reload_interval': cfg['config_reload_interval']
            },
            'updated_at': cfg['updated_at'].isoformat() if cfg['updated_at'] else None,
            'updated_by': cfg['updated_by'],
            'notes': cfg['notes']
        })

    except Exception as e:
        logger.error(f"Failed to get anomaly detection config: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/config/anomaly_detection', methods=['PUT'])
def update_anomaly_detection_config():
    """
    Update global anomaly detection configuration (hot-reload, no restart)

    Request body can include any subset of the 27 configurable parameters.
    Only specified fields will be updated.

    Args:
        Request JSON:
            - Any of the 27 configurable parameters
            - updated_by (str): User/system identifier
            - notes/reason (str): Reason for change

    Returns:
        200: Update successful
        400: Invalid fields
        500: Server error

    Example:
        PUT /api/v1/config/anomaly_detection
        {
            "z_score_threshold": 3.5,
            "consecutive_samples_to_activate": 4,
            "updated_by": "admin",
            "notes": "Reducing sensitivity"
        }

        Response:
        {
            "status": "updated",
            "changes": [
                {"parameter": "z_score_threshold", "old_value": "3.0", "new_value": "3.5"}
            ],
            "updated_by": "admin",
            "note": "Config will reload within 60s (no restart required)"
        }
    """
    try:
        data = request.json
        updated_by = data.get('updated_by', 'api')
        reason = data.get('notes', data.get('reason', ''))

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get current config for audit log
        cur.execute("SELECT * FROM anomaly_detection_config WHERE config_id = 1")
        old_cfg = dict(cur.fetchone())

        # Build UPDATE statement dynamically for changed fields
        update_fields = []
        update_values = []
        changes = []

        # Map of allowed fields (27 configurable parameters)
        allowed_fields = [
            'z_score_threshold', 'pps_multiplier_threshold', 'cps_multiplier_threshold',
            'syn_ratio_threshold', 'active_conn_threshold', 'consecutive_samples_to_activate',
            'level_3_to_2_delay', 'level_2_to_1_delay', 'level_1_to_0_delay', 'escalation_cooldown',
            'level_1_multiplier', 'level_2_multiplier', 'level_3_multiplier', 'level_4_multiplier',
            'pps_spike_level', 'syn_flood_level', 'cps_spike_level', 'state_exhaustion_level',
            'multi_origin_threshold', 'enable_auto_escalation', 'enable_auto_deescalation',
            'enable_global_escalation', 'baseline_required', 'static_threshold_fallback',
            'loop_interval', 'min_samples_before_detection', 'config_reload_interval'
        ]

        for field in allowed_fields:
            if field in data:
                update_fields.append(f"{field} = %s")
                update_values.append(data[field])
                changes.append({
                    'parameter': field,
                    'old_value': str(old_cfg.get(field)),
                    'new_value': str(data[field])
                })

        if not update_fields:
            return jsonify({'error': 'No valid fields to update'}), 400

        # Add metadata fields
        update_fields.append("updated_at = NOW()")
        update_fields.append("updated_by = %s")
        update_fields.append("notes = %s")
        update_values.extend([updated_by, reason])

        # Execute update
        update_sql = f"UPDATE anomaly_detection_config SET {', '.join(update_fields)} WHERE config_id = 1"
        cur.execute(update_sql, update_values)

        # Log changes to audit trail
        for change in changes:
            cur.execute("""
                INSERT INTO config_change_log (config_type, parameter_name, old_value, new_value, changed_by, changed_via, reason)
                VALUES ('global', %s, %s, %s, %s, 'api', %s)
            """, (change['parameter'], change['old_value'], change['new_value'], updated_by, reason))

        conn.commit()
        cur.close()

        logger.info(f"Anomaly detection config updated: {len(changes)} parameters changed by {updated_by}")

        return jsonify({
            'status': 'updated',
            'changes': changes,
            'updated_by': updated_by,
            'note': 'Config will reload within 60s (no restart required)'
        })

    except Exception as e:
        logger.error(f"Failed to update anomaly detection config: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/config/anomaly_detection/reset', methods=['POST'])
def reset_anomaly_detection_config():
    """
    Reset all parameters to factory defaults

    Deletes current config and recreates with database defaults.
    All changes logged to config_change_log.

    Args:
        Request JSON:
            - updated_by (str): User/system identifier

    Returns:
        200: Reset successful
        500: Server error

    Example:
        POST /api/v1/config/anomaly_detection/reset
        {"updated_by": "admin"}

        Response:
        {
            "status": "reset",
            "updated_by": "admin"
        }
    """
    try:
        data = request.json or {}
        updated_by = data.get('updated_by', 'api')

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        # Delete and recreate with defaults
        cur.execute("DELETE FROM anomaly_detection_config WHERE config_id = 1")
        cur.execute("INSERT INTO anomaly_detection_config (config_id) VALUES (1)")

        # Log reset
        cur.execute("""
            INSERT INTO config_change_log (config_type, parameter_name, old_value, new_value, changed_by, changed_via, reason)
            VALUES ('global', 'full_reset', 'custom', 'factory_defaults', %s, 'api', 'Reset to factory defaults')
        """, (updated_by,))

        conn.commit()
        cur.close()

        logger.info(f"Anomaly detection config reset to defaults by {updated_by}")

        return jsonify({'status': 'reset', 'updated_by': updated_by})

    except Exception as e:
        logger.error(f"Failed to reset anomaly detection config: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# CONFIGURATION PRESETS
# ============================================================================

@bp.route('/config/anomaly_detection/presets', methods=['GET'])
def get_config_presets():
    """
    Get available configuration presets

    Returns predefined configurations for common scenarios:
    - Conservative: Low false positive rate, slow de-escalation
    - Balanced: Standard 3-sigma rule with moderate hysteresis (default)
    - Aggressive: Fast response, sensitive detection
    - Manual: Detection only, no automatic escalation

    Returns:
        200: List of presets with descriptions

    Example:
        GET /api/v1/config/anomaly_detection/presets

        Response:
        {
            "presets": {
                "conservative": {
                    "name": "Conservative",
                    "description": "Low false positive rate, slow de-escalation",
                    "config": {...}
                },
                ...
            }
        }
    """
    presets = {
        'conservative': {
            'name': 'Conservative',
            'description': 'Low false positive rate, slow de-escalation',
            'config': {
                'z_score_threshold': 4.0,
                'pps_multiplier_threshold': 3.0,
                'consecutive_samples_to_activate': 5,
                'level_3_to_2_delay': 600,
                'level_2_to_1_delay': 1200,
                'level_1_to_0_delay': 1800
            }
        },
        'balanced': {
            'name': 'Balanced (Default)',
            'description': 'Standard 3-sigma rule with moderate hysteresis',
            'config': {
                'z_score_threshold': 3.0,
                'pps_multiplier_threshold': 2.0,
                'consecutive_samples_to_activate': 3,
                'level_3_to_2_delay': 300,
                'level_2_to_1_delay': 600,
                'level_1_to_0_delay': 1200
            }
        },
        'aggressive': {
            'name': 'Aggressive',
            'description': 'Fast response, sensitive detection',
            'config': {
                'z_score_threshold': 2.5,
                'pps_multiplier_threshold': 1.5,
                'consecutive_samples_to_activate': 2,
                'level_3_to_2_delay': 180,
                'level_2_to_1_delay': 300,
                'level_1_to_0_delay': 600,
                'level_1_multiplier': 0.7,
                'level_2_multiplier': 0.4,
                'level_3_multiplier': 0.15
            }
        },
        'manual': {
            'name': 'Manual (Troubleshooting)',
            'description': 'Detection only, no automatic escalation',
            'config': {
                'enable_auto_escalation': False,
                'enable_auto_deescalation': False
            }
        }
    }

    return jsonify({'presets': presets})


@bp.route('/config/anomaly_detection/apply_preset', methods=['POST'])
def apply_config_preset():
    """
    Apply a predefined configuration preset

    Updates global config with preset values.
    All changes logged to config_change_log.

    Args:
        Request JSON:
            - preset (str): Preset name (conservative|balanced|aggressive|manual)
            - updated_by (str): User/system identifier
            - reason (str): Optional reason for change

    Returns:
        200: Preset applied
        400: Invalid preset name
        500: Server error

    Example:
        POST /api/v1/config/anomaly_detection/apply_preset
        {
            "preset": "aggressive",
            "updated_by": "admin",
            "reason": "Under attack, need fast response"
        }

        Response:
        {
            "status": "preset_applied",
            "preset": "aggressive",
            "parameters_updated": 7,
            "updated_by": "admin"
        }
    """
    try:
        data = request.json
        preset_name = data.get('preset')
        updated_by = data.get('updated_by', 'api')
        reason = data.get('reason', f'Applied preset: {preset_name}')

        if not preset_name:
            return jsonify({'error': 'preset parameter required'}), 400

        # Get presets
        presets_response = get_config_presets()
        presets = presets_response.json['presets']

        if preset_name not in presets:
            return jsonify({'error': f'Invalid preset: {preset_name}'}), 400

        preset_config = presets[preset_name]['config']

        # Apply preset directly to database
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        # Build UPDATE statement for preset fields
        update_fields = []
        update_values = []

        for field, value in preset_config.items():
            update_fields.append(f"{field} = %s")
            update_values.append(value)

            # Log change
            cur.execute("""
                INSERT INTO config_change_log (config_type, parameter_name, new_value, changed_by, changed_via, reason)
                VALUES ('global', %s, %s, %s, 'preset', %s)
            """, (field, str(value), updated_by, reason))

        # Add metadata
        update_fields.extend(["updated_at = NOW()", "updated_by = %s", "notes = %s"])
        update_values.extend([updated_by, reason])

        # Execute update
        update_sql = f"UPDATE anomaly_detection_config SET {', '.join(update_fields)} WHERE config_id = 1"
        cur.execute(update_sql, update_values)

        conn.commit()
        cur.close()

        logger.info(f"Preset '{preset_name}' applied: {len(preset_config)} parameters updated")

        return jsonify({
            'status': 'preset_applied',
            'preset': preset_name,
            'parameters_updated': len(preset_config),
            'updated_by': updated_by
        })

    except Exception as e:
        logger.error(f"Failed to apply preset: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# PER-ORIGIN CONFIGURATION OVERRIDES
# ============================================================================

@bp.route('/origins/<origin_id>/anomaly_config', methods=['GET'])
def get_origin_anomaly_config(origin_id: str):
    """
    Get per-origin anomaly detection configuration (overrides + effective config)

    Returns:
    - Current baseline statistics
    - Per-origin overrides (only non-NULL values)
    - Effective configuration (merges overrides with global defaults)

    Args:
        origin_id: Origin identifier (e.g., "O1")

    Returns:
        200: Configuration data
        500: Server error

    Example:
        GET /api/v1/origins/O1/anomaly_config

        Response:
        {
            "origin_id": "O1",
            "baseline": {
                "source": "learned",
                "pps_mean": 50000,
                "pps_stddev": 8000,
                ...
            },
            "overrides": {
                "z_score_threshold": 3.5
            },
            "effective_config": {
                "z_score_threshold": 3.5,
                "pps_multiplier_threshold": 2.0,
                ...
            }
        }
    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get global config
        cur.execute("SELECT * FROM anomaly_detection_config WHERE config_id = 1")
        global_cfg = dict(cur.fetchone())

        # Get baseline (for display)
        cur.execute("""
            SELECT pps_mean, pps_stddev, pps_p95, pps_p99, computed_at, is_current
            FROM traffic_baselines
            WHERE origin_id = %s AND is_current = true
            LIMIT 1
        """, (origin_id,))
        baseline = cur.fetchone()

        # Get per-origin overrides
        cur.execute("""
            SELECT z_score_threshold, pps_multiplier_threshold, cps_multiplier_threshold,
                   syn_ratio_threshold, level_3_to_2_delay, level_2_to_1_delay, level_1_to_0_delay
            FROM baseline_config
            WHERE origin_id = %s
        """, (origin_id,))
        overrides = cur.fetchone()

        cur.close()

        # Build overrides dict (only non-NULL values)
        override_dict = {}
        effective_config = {}

        if overrides:
            for key, value in dict(overrides).items():
                if value is not None:
                    override_dict[key] = value
                    effective_config[key] = value
                else:
                    effective_config[key] = global_cfg.get(key)
        else:
            # No overrides - use global config
            override_keys = ['z_score_threshold', 'pps_multiplier_threshold', 'cps_multiplier_threshold',
                           'syn_ratio_threshold', 'level_3_to_2_delay', 'level_2_to_1_delay', 'level_1_to_0_delay']
            for key in override_keys:
                effective_config[key] = global_cfg.get(key)

        return jsonify({
            'origin_id': origin_id,
            'baseline': {
                'source': 'learned' if baseline and baseline['is_current'] else 'none',
                'pps_mean': int(baseline['pps_mean']) if baseline and baseline['pps_mean'] else None,
                'pps_stddev': int(baseline['pps_stddev']) if baseline and baseline['pps_stddev'] else None,
                'pps_p95': int(baseline['pps_p95']) if baseline and baseline['pps_p95'] else None,
                'last_calculated': baseline['computed_at'].isoformat() if baseline else None
            } if baseline else None,
            'overrides': override_dict,
            'effective_config': effective_config
        })

    except Exception as e:
        logger.error(f"Failed to get anomaly config for {origin_id}: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/origins/<origin_id>/anomaly_config', methods=['PUT'])
def set_origin_anomaly_config(origin_id: str):
    """
    Set per-origin anomaly detection overrides

    Allows different thresholds for different traffic patterns.
    Overrides global defaults for specified parameters only.

    Args:
        origin_id: Origin identifier
        Request JSON:
            - Any of the 7 overridable parameters:
              z_score_threshold, pps_multiplier_threshold, cps_multiplier_threshold,
              syn_ratio_threshold, level_3_to_2_delay, level_2_to_1_delay, level_1_to_0_delay
            - reason (str): Reason for change

    Returns:
        200: Update successful
        404: Origin not found
        500: Server error

    Example:
        PUT /api/v1/origins/O1/anomaly_config
        {
            "z_score_threshold": 3.5,
            "syn_ratio_threshold": 12.0,
            "reason": "E-commerce site, needs higher SYN threshold"
        }

        Response:
        {
            "status": "updated",
            "origin_id": "O1",
            "fields_updated": 2,
            "note": "Config will reload within 60s"
        }
    """
    try:
        data = request.json
        reason = data.get('reason', 'Per-origin override')

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        # Check if origin exists
        cur.execute("SELECT 1 FROM origins WHERE origin_id = %s", (origin_id,))
        if not cur.fetchone():
            cur.close()
            return jsonify({'error': f'Origin {origin_id} not found'}), 404

        # Ensure baseline_config row exists
        cur.execute("""
            INSERT INTO baseline_config (origin_id, lookback_days, min_samples)
            VALUES (%s, 7, 100)
            ON CONFLICT (origin_id) DO NOTHING
        """, (origin_id,))

        # Update override fields
        allowed_fields = ['z_score_threshold', 'pps_multiplier_threshold', 'cps_multiplier_threshold',
                         'syn_ratio_threshold', 'level_3_to_2_delay', 'level_2_to_1_delay', 'level_1_to_0_delay']

        updates = []
        values = []
        for field in allowed_fields:
            if field in data:
                updates.append(f"{field} = %s")
                values.append(data[field])

                # Log change
                cur.execute("""
                    INSERT INTO config_change_log (config_type, origin_id, parameter_name, new_value, changed_by, changed_via, reason)
                    VALUES ('per_origin', %s, %s, %s, 'api', 'api', %s)
                """, (origin_id, field, str(data[field]), reason))

        if updates:
            values.append(origin_id)
            update_sql = f"UPDATE baseline_config SET {', '.join(updates)} WHERE origin_id = %s"
            cur.execute(update_sql, values)

        conn.commit()
        cur.close()

        logger.info(f"Per-origin anomaly config updated for {origin_id}: {len(updates)} fields")

        return jsonify({
            'status': 'updated',
            'origin_id': origin_id,
            'fields_updated': len(updates),
            'note': 'Config will reload within 60s'
        })

    except Exception as e:
        logger.error(f"Failed to set anomaly config for {origin_id}: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/origins/<origin_id>/anomaly_config', methods=['DELETE'])
def clear_origin_anomaly_config(origin_id: str):
    """
    Clear all per-origin overrides (revert to global defaults)

    Sets all override fields to NULL, causing origin to use global config.

    Args:
        origin_id: Origin identifier

    Returns:
        200: Overrides cleared
        500: Server error

    Example:
        DELETE /api/v1/origins/O1/anomaly_config

        Response:
        {
            "status": "cleared",
            "origin_id": "O1",
            "note": "Origin will use global defaults"
        }
    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        # Set all override fields to NULL
        cur.execute("""
            UPDATE baseline_config
            SET z_score_threshold = NULL,
                pps_multiplier_threshold = NULL,
                cps_multiplier_threshold = NULL,
                syn_ratio_threshold = NULL,
                level_3_to_2_delay = NULL,
                level_2_to_1_delay = NULL,
                level_1_to_0_delay = NULL
            WHERE origin_id = %s
        """, (origin_id,))

        # Log change
        cur.execute("""
            INSERT INTO config_change_log (config_type, origin_id, parameter_name, old_value, new_value, changed_by, changed_via, reason)
            VALUES ('per_origin', %s, 'all_overrides', 'custom', 'NULL', 'api', 'api', 'Cleared all overrides')
        """, (origin_id,))

        conn.commit()
        cur.close()

        logger.info(f"Cleared all anomaly config overrides for {origin_id}")

        return jsonify({
            'status': 'cleared',
            'origin_id': origin_id,
            'note': 'Origin will use global defaults'
        })

    except Exception as e:
        logger.error(f"Failed to clear anomaly config for {origin_id}: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# AUDIT TRAIL
# ============================================================================

@bp.route('/config/anomaly_detection/changelog', methods=['GET'])
def get_config_changelog():
    """
    Get configuration change audit trail

    Query parameters:
        - limit (int): Max results (default 50, max 500)
        - origin_id (str): Filter by origin
        - parameter_name (str): Filter by parameter

    Returns:
        200: List of changes
        500: Server error

    Example:
        GET /api/v1/config/anomaly_detection/changelog?limit=10&origin_id=O1

        Response:
        {
            "changes": [
                {
                    "log_id": 123,
                    "config_type": "per_origin",
                    "origin_id": "O1",
                    "parameter_name": "z_score_threshold",
                    "old_value": "3.0",
                    "new_value": "3.5",
                    "changed_by": "admin",
                    "changed_via": "api",
                    "reason": "Reducing sensitivity",
                    "changed_at": "2025-11-06T12:34:56Z"
                }
            ],
            "total": 42
        }
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 500)
        origin_id = request.args.get('origin_id')
        parameter_name = request.args.get('parameter_name')

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        where_clauses = []
        params = []

        if origin_id:
            where_clauses.append("origin_id = %s")
            params.append(origin_id)

        if parameter_name:
            where_clauses.append("parameter_name = %s")
            params.append(parameter_name)

        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        params.append(limit)

        cur.execute(f"""
            SELECT log_id, config_type, origin_id, parameter_name, old_value, new_value,
                   changed_by, changed_via, reason, changed_at
            FROM config_change_log
            {where_sql}
            ORDER BY changed_at DESC
            LIMIT %s
        """, params)
        changes = [dict(row) for row in cur.fetchall()]

        cur.execute(f"SELECT COUNT(*) as total FROM config_change_log {where_sql}", params[:-1] if params else [])
        total = cur.fetchone()['total']

        cur.close()

        return jsonify({'changes': changes, 'total': total})

    except Exception as e:
        logger.error(f"Failed to get config changelog: {e}")
        return jsonify({'error': str(e)}), 500
