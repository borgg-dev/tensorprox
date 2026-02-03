"""Mitigation API Blueprint - Auto-mitigation configuration

Endpoints for configuring automated DDoS mitigation thresholds and sensitivity.
"""
import logging
import json
from flask import Blueprint, request, jsonify
from shared.database import get_db_connection
from miner_control_plane.services.state_manager import state_manager

bp = Blueprint('mitigation', __name__, url_prefix='/api/v1')
logger = logging.getLogger(__name__)


@bp.route('/mitigation/auto', methods=['POST'])
def configure_auto_mitigation():
    """
    Configure auto-mitigation sensitivity and thresholds

    Request Body:
    {
        "origin_id": "O1",                          // Optional: origin-specific
        "enabled": true,                            // Enable/disable
        "sensitivity": "medium",                    // low, medium, high
        "max_temp_blacklist_per_hour": 1000        // Rate limit
    }

    """
    try:
        data = request.json
        origin_id = data.get('origin_id')  # None = global config
        enabled = data.get('enabled', True)
        sensitivity = data.get('sensitivity', 'medium')  # low, medium, high
        max_temp_blacklist = data.get('max_temp_blacklist_per_hour', 1000)

        # Validate sensitivity
        if sensitivity not in ['low', 'medium', 'high']:
            return jsonify({
                'status': 'error',
                'message': 'Sensitivity must be low, medium, or high'
            }), 400

        # Calculate thresholds based on sensitivity
        thresholds = {
            'low': {'soft': 30, 'temp': 50, 'perm': 80},
            'medium': {'soft': 20, 'temp': 40, 'perm': 70},
            'high': {'soft': 15, 'temp': 30, 'perm': 60}
        }
        t = thresholds[sensitivity]

        conn = get_db_connection()
        cur = conn.cursor()

        # Upsert configuration
        if origin_id:
            # Origin-specific config
            if origin_id not in state_manager.origins_db:
                return jsonify({
                    'status': 'error',
                    'message': 'Origin not found'
                }), 404

            cur.execute("""
                INSERT INTO auto_mitigation_config (
                    origin_id, enabled, sensitivity,
                    soft_threshold, temp_blacklist_threshold,
                    perm_blacklist_threshold,
                    max_temp_blacklist_per_hour
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (origin_id) DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    sensitivity = EXCLUDED.sensitivity,
                    soft_threshold = EXCLUDED.soft_threshold,
                    temp_blacklist_threshold = EXCLUDED.temp_blacklist_threshold,
                    perm_blacklist_threshold = EXCLUDED.perm_blacklist_threshold,
                    max_temp_blacklist_per_hour =
                        EXCLUDED.max_temp_blacklist_per_hour,
                    updated_at = NOW()
            """, (origin_id, enabled, sensitivity, t['soft'], t['temp'],
                 t['perm'], max_temp_blacklist))
        else:
            # Global config (origin_id = NULL)
            cur.execute("""
                INSERT INTO auto_mitigation_config (
                    origin_id, enabled, sensitivity,
                    soft_threshold, temp_blacklist_threshold,
                    perm_blacklist_threshold,
                    max_temp_blacklist_per_hour
                )
                VALUES (NULL, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (origin_id) DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    sensitivity = EXCLUDED.sensitivity,
                    soft_threshold = EXCLUDED.soft_threshold,
                    temp_blacklist_threshold = EXCLUDED.temp_blacklist_threshold,
                    perm_blacklist_threshold = EXCLUDED.perm_blacklist_threshold,
                    max_temp_blacklist_per_hour =
                        EXCLUDED.max_temp_blacklist_per_hour,
                    updated_at = NOW()
            """, (enabled, sensitivity, t['soft'], t['temp'], t['perm'],
                 max_temp_blacklist))

        conn.commit()
        cur.close()
        conn.close()

        logger.info(
            f"Auto-mitigation configured: origin={origin_id}, "
            f"enabled={enabled}, sensitivity={sensitivity}"
        )

        return jsonify({
            'status': 'success',
            'origin_id': origin_id or 'global',
            'enabled': enabled,
            'sensitivity': sensitivity,
            'thresholds': {
                'soft': t['soft'],
                'temp_blacklist': t['temp'],
                'perm_blacklist': t['perm']
            },
            'max_temp_blacklist_per_hour': max_temp_blacklist
        })

    except Exception as e:
        logger.error(f"Failed to configure auto-mitigation: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
