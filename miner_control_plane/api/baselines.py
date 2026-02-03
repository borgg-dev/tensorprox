"""Baselines API Blueprint - Layer 6: Baseline Learning & Statistical Foundation

Adapted to use state_manager and shared utilities.

Endpoints:
    GET  /api/v1/origins/<origin_id>/baseline                   - Get current baseline
    GET  /api/v1/origins/<origin_id>/baseline/history           - Get historical baselines
    GET  /api/v1/baselines/summary                              - Get all origin baselines
    GET  /api/v1/origins/<origin_id>/baseline/compare           - Compare current to baseline
    GET  /api/v1/origins/<origin_id>/baseline/confidence        - Get confidence breakdown
    GET  /api/v1/baselines/stale                                - Get outdated baselines
    POST /api/v1/origins/<origin_id>/baseline/recalculate       - Force recalculation
    GET  /api/v1/origins/<origin_id>/baseline/config            - Get baseline config
    PUT  /api/v1/origins/<origin_id>/baseline/config            - Update baseline config
    POST /api/v1/origins/<origin_id>/baseline/enable-dynamic    - Enable dynamic thresholds
    POST /api/v1/baselines/recalculate-all                      - Recalculate all origins
"""
from flask import Blueprint, request, jsonify
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Optional

# Import shared utilities
from shared.database import get_db_connection

# Import local services
from miner_control_plane.services.baseline_learner import compute_baseline_for_origin

logger = logging.getLogger(__name__)

bp = Blueprint('baselines', __name__, url_prefix='/api/v1')


# ============================================================================
# BASELINE RETRIEVAL ENDPOINTS
# ============================================================================

@bp.route('/origins/<origin_id>/baseline', methods=['GET'])
def get_origin_baseline(origin_id: str):
    """
    Get current baseline statistics for an origin.

    Returns the currently active baseline (is_current=TRUE) with all
    statistical measures (mean, stddev, percentiles).

    Args:
        origin_id: Origin identifier (e.g., "O1")

    Returns:
        200: Baseline data
        404: No baseline found
        500: Server error

    Example:
        GET /api/v1/origins/O1/baseline

        Response:
        {
            "status": "success",
            "origin_id": "O1",
            "baseline": {
                "baseline_id": 123,
                "pps_mean": 50000,
                "pps_p95": 80000,
                "confidence_score": 0.85,
                ...
            }
        }
    """
    try:
        # Use raw psycopg2 connection for RealDictCursor support
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT * FROM traffic_baselines
            WHERE origin_id = %s AND is_current = TRUE
        """, (origin_id,))

        baseline = cur.fetchone()
        cur.close()

        if not baseline:
            return jsonify({
                'status': 'not_found',
                'message': f'No baseline found for origin {origin_id}'
            }), 404

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'baseline': dict(baseline)
        })

    except Exception as e:
        logger.error(f"Failed to get baseline for {origin_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/origins/<origin_id>/baseline/history', methods=['GET'])
def get_origin_baseline_history(origin_id: str):
    """
    Get historical baselines for an origin.

    Returns paginated list of all baselines (current and historical)
    ordered by computation time.

    Args:
        origin_id: Origin identifier
        limit: Maximum results (default: 10)
        offset: Pagination offset (default: 0)

    Returns:
        200: List of baselines with pagination metadata
        500: Server error

    Example:
        GET /api/v1/origins/O1/baseline/history?limit=5&offset=0

        Response:
        {
            "status": "success",
            "baselines": [...],
            "total": 15,
            "limit": 5
        }
    """
    try:
        limit = int(request.args.get('limit', 10))
        offset = int(request.args.get('offset', 0))

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get paginated baselines
        cur.execute("""
            SELECT * FROM traffic_baselines
            WHERE origin_id = %s
            ORDER BY computed_at DESC
            LIMIT %s OFFSET %s
        """, (origin_id, limit, offset))

        baselines = [dict(row) for row in cur.fetchall()]

        # Get total count
        cur.execute(
            "SELECT COUNT(*) as total FROM traffic_baselines WHERE origin_id = %s",
            (origin_id,)
        )
        total = cur.fetchone()['total']
        cur.close()

        return jsonify({
            'status': 'success',
            'baselines': baselines,
            'total': total,
            'limit': limit
        })

    except Exception as e:
        logger.error(f"Failed to get baseline history: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/baselines/summary', methods=['GET'])
def get_baselines_summary():
    """
    Get summary of all origin baselines.

    Returns current baseline for each origin with key metrics.
    Useful for dashboard views.

    Returns:
        200: List of all current baselines
        500: Server error

    Example:
        GET /api/v1/baselines/summary

        Response:
        {
            "status": "success",
            "baselines": [
                {
                    "origin_id": "O1",
                    "pps_mean": 50000,
                    "pps_p95": 80000,
                    "confidence_score": 0.85,
                    ...
                }
            ],
            "count": 3
        }
    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT origin_id, pps_mean, pps_p95, syn_ratio_mean, syn_ratio_p95,
                   confidence_score, computed_at
            FROM traffic_baselines
            WHERE is_current = TRUE
            ORDER BY origin_id
        """)

        baselines = [dict(row) for row in cur.fetchall()]
        cur.close()

        return jsonify({
            'status': 'success',
            'baselines': baselines,
            'count': len(baselines)
        })

    except Exception as e:
        logger.error(f"Failed to get baselines summary: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================================================
# BASELINE ANALYSIS ENDPOINTS
# ============================================================================

@bp.route('/origins/<origin_id>/baseline/compare', methods=['GET'])
def compare_to_baseline(origin_id: str):
    """
    Compare current traffic to baseline with z-scores.

    Calculates standard deviations (z-scores) from baseline for
    current traffic metrics. Z-score > 3 indicates anomaly.

    Args:
        origin_id: Origin identifier

    Returns:
        200: Z-scores for current metrics
        404: No baseline or no current metrics
        500: Server error

    Example:
        GET /api/v1/origins/O1/baseline/compare

        Response:
        {
            "status": "success",
            "pps_z_score": 2.5,
            "ratio_z_score": 4.2
        }

    Notes:
        - Z-score formula: (current - baseline_mean) / baseline_stddev
        - Z > 3.0 = 3 standard deviations above mean (99.7th percentile)
        - Used by Layer 7 anomaly detection
    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get baseline
        cur.execute("""
            SELECT pps_mean, pps_stddev, pps_p95,
                   syn_ratio_mean, syn_ratio_stddev, syn_ratio_p95
            FROM traffic_baselines
            WHERE origin_id = %s AND is_current = TRUE
        """, (origin_id,))

        baseline = cur.fetchone()
        if not baseline:
            return jsonify({'status': 'not_found'}), 404

        # Get latest metrics
        cur.execute("""
            SELECT pps, syn_synack_ratio
            FROM origin_metrics
            WHERE origin_id = %s
            ORDER BY timestamp DESC
            LIMIT 1
        """, (origin_id,))

        current = cur.fetchone()
        cur.close()

        if not current:
            return jsonify({'status': 'no_data'}), 404

        # Calculate z-scores
        def calc_z(val, mean, std):
            """Calculate z-score with zero-division protection"""
            return round((val - mean) / std, 2) if std > 0 else 0.0

        pps_z = calc_z(
            current['pps'],
            baseline['pps_mean'],
            baseline['pps_stddev']
        )

        ratio_z = calc_z(
            float(current['syn_synack_ratio']),
            float(baseline['syn_ratio_mean']),
            float(baseline['syn_ratio_stddev'])
        )

        return jsonify({
            'status': 'success',
            'pps_z_score': pps_z,
            'ratio_z_score': ratio_z
        })

    except Exception as e:
        logger.error(f"Failed to compare: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/origins/<origin_id>/baseline/confidence', methods=['GET'])
def get_baseline_confidence(origin_id: str):
    """
    Get confidence score breakdown.

    Returns confidence score (0.0-1.0) and contributing factors:
    - Sample count (more samples = higher confidence)
    - Coefficient of variation (lower CV = higher confidence)

    Args:
        origin_id: Origin identifier

    Returns:
        200: Confidence score and metadata
        404: No baseline found
        500: Server error

    Example:
        GET /api/v1/origins/O1/baseline/confidence

        Response:
        {
            "status": "success",
            "confidence_score": 0.85,
            "sample_count": 150,
            "cv": 0.25
        }

    Notes:
        - confidence_score: 0.0-1.0 (0.5+ recommended for dynamic thresholds)
        - cv (coefficient of variation): stddev/mean (lower = more stable)
    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT sample_count, confidence_score, outliers_removed,
                   pps_mean, pps_stddev
            FROM traffic_baselines
            WHERE origin_id = %s AND is_current = TRUE
        """, (origin_id,))

        baseline = cur.fetchone()
        cur.close()

        if not baseline:
            return jsonify({'status': 'not_found'}), 404

        # Calculate coefficient of variation
        cv = round(
            baseline['pps_stddev'] / baseline['pps_mean'], 2
        ) if baseline['pps_mean'] > 0 else 0

        return jsonify({
            'status': 'success',
            'confidence_score': float(baseline['confidence_score']),
            'sample_count': baseline['sample_count'],
            'cv': cv
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/baselines/stale', methods=['GET'])
def get_stale_baselines():
    """
    Get origins with outdated baselines.

    Returns list of origins where baseline is older than threshold.
    Useful for triggering recalculation.

    Args:
        days: Age threshold in days (default: 2)

    Returns:
        200: List of stale baselines
        500: Server error

    Example:
        GET /api/v1/baselines/stale?days=2

        Response:
        {
            "status": "success",
            "stale_baselines": [
                {
                    "origin_id": "O1",
                    "computed_at": "2025-11-01T00:00:00Z",
                    "confidence_score": 0.85
                }
            ],
            "count": 1
        }
    """
    try:
        days = int(request.args.get('days', 2))

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT origin_id, computed_at, confidence_score
            FROM traffic_baselines
            WHERE is_current = TRUE
              AND computed_at < NOW() - INTERVAL '%s days'
        """, (days,))

        stale = [dict(row) for row in cur.fetchall()]
        cur.close()

        return jsonify({
            'status': 'success',
            'stale_baselines': stale,
            'count': len(stale)
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================================================
# BASELINE RECALCULATION ENDPOINTS
# ============================================================================

@bp.route('/origins/<origin_id>/baseline/recalculate', methods=['POST'])
def recalculate_baseline(origin_id: str):
    """
    Force baseline recalculation.

    Triggers immediate baseline computation using current configuration.
    Normally runs automatically daily, but can be forced for testing
    or after configuration changes.

    Args:
        origin_id: Origin identifier

    Returns:
        200: New baseline data
        500: Insufficient data or error

    Example:
        POST /api/v1/origins/O1/baseline/recalculate

        Response:
        {
            "status": "success",
            "baseline": {
                "baseline_id": 124,
                "sample_count": 150,
                "confidence_score": 0.85,
                ...
            }
        }

    Notes:
        - Requires min_samples hourly data points (default: 100)
        - Uses outlier removal and statistical calculation
        - Marks old baseline as is_current=FALSE
        - Updates baseline_config (last_recalc_at, next_recalc_at)
    """
    try:
        result = compute_baseline_for_origin(origin_id)

        if not result:
            return jsonify({
                'status': 'failed',
                'message': 'Insufficient data'
            }), 500

        return jsonify({
            'status': 'success',
            'baseline': result
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/baselines/recalculate-all', methods=['POST'])
def recalculate_all_baselines():
    """
    Force recalculation for all origins.

    Triggers baseline computation for every origin in the system.
    Useful for global updates after configuration changes.

    Returns:
        200: Results for each origin
        500: Server error

    Example:
        POST /api/v1/baselines/recalculate-all

        Response:
        {
            "status": "complete",
            "results": [
                {"origin_id": "O1", "success": true},
                {"origin_id": "O2", "success": false}
            ]
        }

    Notes:
        - May take several seconds for multiple origins
        - Each origin calculated independently (one failure doesn't stop others)
        - Returns success/failure status per origin
    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get all origin IDs
        cur.execute("SELECT origin_id FROM origins")
        origins = [row['origin_id'] for row in cur.fetchall()]
        cur.close()

        # Calculate baseline for each origin
        results = []
        for oid in origins:
            result = compute_baseline_for_origin(oid)
            results.append({
                'origin_id': oid,
                'success': result is not None
            })

        return jsonify({
            'status': 'complete',
            'results': results
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================================================
# BASELINE CONFIGURATION ENDPOINTS
# ============================================================================

@bp.route('/origins/<origin_id>/baseline/config', methods=['GET'])
def get_baseline_config(origin_id: str):
    """
    Get baseline configuration for an origin.

    Returns configuration parameters that control baseline calculation:
    - lookback_days: Historical period to analyze
    - min_samples: Minimum hourly samples required
    - outlier_removal_pct: Percentage of outliers to remove
    - auto_recalc_enabled: Automatic recalculation flag
    - dynamic_thresholds_enabled: Use baseline for dynamic thresholds

    Args:
        origin_id: Origin identifier

    Returns:
        200: Configuration data
        404: No configuration found
        500: Server error

    Example:
        GET /api/v1/origins/O1/baseline/config

        Response:
        {
            "status": "success",
            "config": {
                "origin_id": "O1",
                "lookback_days": 7,
                "min_samples": 100,
                "outlier_removal_pct": 1.0,
                "auto_recalc_enabled": true,
                "dynamic_thresholds_enabled": false,
                ...
            }
        }
    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute(
            "SELECT * FROM baseline_config WHERE origin_id = %s",
            (origin_id,)
        )
        config = cur.fetchone()
        cur.close()

        if not config:
            return jsonify({'status': 'not_found'}), 404

        return jsonify({
            'status': 'success',
            'config': dict(config)
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/origins/<origin_id>/baseline/config', methods=['PUT'])
def update_baseline_config(origin_id: str):
    """
    Update baseline configuration.

    Allows runtime modification of baseline calculation parameters.
    Changes take effect on next recalculation.

    Args:
        origin_id: Origin identifier

    Request Body:
        {
            "lookback_days": 7,          # 7, 14, or 30
            "min_samples": 100,          # Minimum hourly samples
            "outlier_removal_pct": 1.0,  # 0.0-5.0
            "auto_recalc_enabled": true,
            "dynamic_thresholds_enabled": false
        }

    Returns:
        200: Updated configuration
        400: Invalid fields or no data
        500: Server error

    Example:
        PUT /api/v1/origins/O1/baseline/config
        {
            "lookback_days": 14,
            "min_samples": 150
        }

        Response:
        {
            "status": "success",
            "config": {...}
        }

    Notes:
        - Only specified fields are updated
        - Invalid fields are ignored
        - Changes don't trigger recalculation (use POST .../recalculate)
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data'}), 400

        # Allowed fields for update
        allowed = [
            'lookback_days',
            'min_samples',
            'outlier_removal_pct',
            'auto_recalc_enabled',
            'dynamic_thresholds_enabled'
        ]

        # Build dynamic UPDATE query
        updates = []
        values = []
        for field in allowed:
            if field in data:
                updates.append(f"{field} = %s")
                values.append(data[field])

        if not updates:
            return jsonify({
                'status': 'error',
                'message': 'No valid fields'
            }), 400

        # Add updated_at timestamp
        updates.append("updated_at = NOW()")
        values.append(origin_id)

        # Execute update
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        query = f"""
            UPDATE baseline_config
            SET {', '.join(updates)}
            WHERE origin_id = %s
            RETURNING *
        """
        cur.execute(query, values)

        config = cur.fetchone()
        conn.commit()
        cur.close()

        return jsonify({
            'status': 'success',
            'config': dict(config)
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/origins/<origin_id>/baseline/enable-dynamic', methods=['POST'])
def enable_dynamic_thresholds(origin_id: str):
    """
    Enable dynamic thresholds for an origin.

    Enables use of baseline statistics for dynamic rate limiting and
    anomaly detection thresholds. Requires baseline with confidence >= 0.5.

    Args:
        origin_id: Origin identifier

    Returns:
        200: Success
        400: No baseline or low confidence
        500: Server error

    Example:
        POST /api/v1/origins/O1/baseline/enable-dynamic

        Response:
        {
            "status": "success",
            "message": "Dynamic thresholds enabled"
        }

    Notes:
        - Requires current baseline with confidence_score >= 0.5
        - Used by syncookie_controller for dynamic SYN flood thresholds
        - Used by anomaly_detector for adaptive Z-score thresholds
        - Can be disabled by PUT .../config with dynamic_thresholds_enabled=false
    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Check baseline exists and has sufficient confidence
        cur.execute("""
            SELECT confidence_score, syn_ratio_p95
            FROM traffic_baselines
            WHERE origin_id = %s AND is_current = TRUE
        """, (origin_id,))

        baseline = cur.fetchone()

        if not baseline or baseline['confidence_score'] < 0.5:
            return jsonify({
                'status': 'failed',
                'message': 'No baseline or low confidence'
            }), 400

        # Enable dynamic thresholds
        cur.execute("""
            UPDATE baseline_config
            SET dynamic_thresholds_enabled = TRUE
            WHERE origin_id = %s
        """, (origin_id,))

        conn.commit()
        cur.close()

        return jsonify({
            'status': 'success',
            'message': 'Dynamic thresholds enabled'
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
