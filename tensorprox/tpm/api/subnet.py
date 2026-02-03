"""
Subnet API Endpoints

REST API endpoints for Bittensor subnet (SN91) integration.
Used by validators and miners to interact with TPM.

Endpoints:
- POST /api/v1/validators/{validator_uid}/scores - Report scores
- GET /api/v1/miners/{miner_uid}/assignments - Query assignments
- GET /api/v1/exit-hubs/{exit_hub_ip} - Get exit hub access info
- POST /api/v1/miners/{miner_uid}/failure - Report miner failure
"""

import logging
import threading
from datetime import datetime, timezone
from typing import Dict, Optional
from flask import Blueprint, request, jsonify
from werkzeug.exceptions import BadRequest, NotFound

from shared.database import get_connection
from shared.utils.ssh import get_ssh_user_for_provider
from tensorprox.tpm.services.score_aggregator import ScoreAggregator
from tensorprox.tpm.services.assignment_engine import AssignmentEngine
from tensorprox.tpm.services.volume_verifier import get_volume_verifier

logger = logging.getLogger(__name__)

bp = Blueprint('subnet', __name__, url_prefix='/api/v1')


# ============================================================================
# VALIDATOR ENDPOINTS
# ============================================================================

@bp.route('/validators/<int:validator_uid>/scores', methods=['POST'])
def report_validator_scores(validator_uid: int):
    """
    Report scores from a validator for multiple miners.

    Request body:
    {
        "validator_uid": 7,
        "validator_hotkey": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        "scores": {
            "42": 0.858,
            "17": 0.723,
            "89": 0.891
        },
        "score_components": {
            "42": {
                "volume": 0.40,
                "latency": 0.28,
                "availability": 0.20,
                "mitigation": 0.095
            }
        },
        "audit_type": "production",
        "validator_version": "1.0.0",
        "timestamp": 1704643335.0
    }

    Response:
    {
        "status": "accepted",
        "scores_received": 3,
        "updated_scores": {
            "42": 0.862,
            "17": 0.715,
            "89": 0.895
        }
    }
    """
    try:
        data = request.get_json()

        if not data:
            raise BadRequest("Request body required")

        # Validate required fields
        if 'validator_hotkey' not in data:
            raise BadRequest("validator_hotkey required")
        if 'scores' not in data:
            raise BadRequest("scores required")

        validator_hotkey = data['validator_hotkey']
        scores_dict = data['scores']

        # Convert string keys to int
        scores = {int(uid): float(score) for uid, score in scores_dict.items()}

        # Optional fields
        score_components_raw = data.get('score_components', {})
        score_components = {
            int(uid): components
            for uid, components in score_components_raw.items()
        } if score_components_raw else None

        audit_type = data.get('audit_type', 'production')
        validator_version = data.get('validator_version')

        # Process scores
        conn = get_connection()
        aggregator = ScoreAggregator(conn)

        updated_scores = aggregator.process_validator_scores(
            validator_uid=validator_uid,
            validator_hotkey=validator_hotkey,
            scores=scores,
            score_components=score_components,
            audit_type=audit_type,
            validator_version=validator_version
        )

        logger.info(
            "Validator %d reported scores for %d miners",
            validator_uid,
            len(scores)
        )

        return jsonify({
            'status': 'accepted',
            'scores_received': len(scores),
            'updated_scores': updated_scores
        }), 200

    except BadRequest:
        raise
    except Exception as e:
        logger.error("Failed to process validator scores: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/validators/<int:validator_uid>/scores/<int:miner_uid>', methods=['GET'])
def get_validator_score_for_miner(validator_uid: int, miner_uid: int):
    """
    Get validator's scores for a specific miner.

    Response:
    {
        "validator_uid": 7,
        "miner_uid": 42,
        "scores": [
            {
                "score": 0.858,
                "score_components": {...},
                "audit_type": "production",
                "reported_at": "2024-01-07T10:15:35Z"
            }
        ]
    }
    """
    try:
        conn = get_connection()
        aggregator = ScoreAggregator(conn)

        scores = aggregator.get_validator_scores_for_miner(miner_uid, limit=10)

        # Filter to this validator
        validator_scores = [
            s for s in scores if s['validator_uid'] == validator_uid
        ]

        return jsonify({
            'validator_uid': validator_uid,
            'miner_uid': miner_uid,
            'scores': validator_scores
        }), 200

    except Exception as e:
        logger.error("Failed to get validator scores: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


# ============================================================================
# MINER ENDPOINTS
# ============================================================================

@bp.route('/assignments', methods=['GET'])
def get_all_assignments():
    """
    Get all active assignments across all miners.

    Used by validators to get a complete view of miner-to-origin mappings.
    Queries tensorprox_origins (main deployment table) joined with subnet_miners
    to get the Bittensor miner_uid.

    Response:
    {
        "assignments": [
            {
                "origin_id": "origin-123",
                "origin_ip": "203.0.113.50",
                "miner_uid": 42,
                "exit_hub_ip": "172.104.45.20",
                "tunnel_name": "wg-miner-42",
                "assigned_at": "2024-01-06T10:00:00Z"
            }
        ],
        "total_count": 1
    }
    """
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            # Query active origins from tensorprox_origins, joined with subnet_miners
            # to get the Bittensor miner_uid, and tensorprox_exit_hubs for exit_hub_ip
            cur.execute("""
                SELECT
                    o.origin_id,
                    o.tensorprox_ip AS origin_ip,
                    sm.miner_uid,
                    eh.exit_hub_ip,
                    COALESCE(eh.wg_interface, 'wg-origin-' || o.origin_id) AS tunnel_name,
                    o.updated_at AS assigned_at
                FROM tensorprox_origins o
                JOIN subnet_miners sm ON o.miner_id = sm.miner_id
                LEFT JOIN tensorprox_exit_hubs eh ON o.last_exit_hub_id::text = eh.exit_hub_id::text
                WHERE o.status = 'active'
                  AND o.miner_id IS NOT NULL
                  AND sm.miner_uid IS NOT NULL
                ORDER BY sm.miner_uid, o.updated_at DESC
            """)

            rows = cur.fetchall()
            columns = [desc[0] for desc in cur.description]

            assignments = []
            for row in rows:
                record = dict(zip(columns, row))
                assignments.append({
                    'origin_id': record['origin_id'],
                    'origin_ip': record['origin_ip'] or '',
                    'miner_uid': record['miner_uid'],
                    'exit_hub_ip': record['exit_hub_ip'] or '',
                    'tunnel_name': record['tunnel_name'] or '',
                    'assigned_at': record['assigned_at'].isoformat() if record.get('assigned_at') else None,
                })

        logger.info(f"Returning {len(assignments)} active assignments to validator")
        return jsonify({
            'assignments': assignments,
            'total_count': len(assignments)
        }), 200

    except Exception as e:
        logger.error("Failed to get all assignments: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/miners/<int:miner_uid>/assignments', methods=['GET'])
def get_miner_assignments(miner_uid: int):
    """
    Get active assignments for a miner.

    Response:
    {
        "miner_uid": 42,
        "assignments": [
            {
                "assignment_id": 123,
                "origin_id": "origin-123",
                "origin_ip": "203.0.113.50",
                "scrubber_ip": "18.203.45.67",
                "exit_hub_ip": "172.104.45.20",
                "tunnel_name": "wg-miner-42",
                "assigned_at": "2024-01-06T10:00:00Z",
                "reassigned_count": 0,
                "expected_bandwidth_mbps": 500,
                "traffic_type": "video_streaming"
            }
        ]
    }
    """
    try:
        conn = get_connection()
        engine = AssignmentEngine(conn)

        assignments = engine.get_miner_assignments(miner_uid)

        return jsonify({
            'miner_uid': miner_uid,
            'assignments': [
                {
                    'assignment_id': a.assignment_id,
                    'origin_id': a.origin_id,
                    'origin_ip': a.origin_ip,
                    'scrubber_ip': a.scrubber_ip,
                    'exit_hub_ip': a.exit_hub_ip,
                    'tunnel_name': a.tunnel_name,
                    'assigned_at': a.assigned_at.isoformat() if a.assigned_at else None,
                    'reassigned_count': a.reassigned_count,
                    'expected_bandwidth_mbps': a.expected_bandwidth_mbps,
                    'traffic_type': a.traffic_type
                }
                for a in assignments
            ]
        }), 200

    except Exception as e:
        logger.error("Failed to get miner assignments: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/miners/<int:miner_uid>/score', methods=['GET'])
def get_miner_score(miner_uid: int):
    """
    Get aggregated score for a miner.

    Response:
    {
        "miner_uid": 42,
        "aggregated_score": 0.862,
        "validator_count": 5,
        "score_stddev": 0.032,
        "last_updated": "2024-01-07T10:15:35Z"
    }
    """
    try:
        conn = get_connection()
        aggregator = ScoreAggregator(conn)

        miner_score = aggregator.get_miner_score(miner_uid)

        if not miner_score:
            raise NotFound(f"Miner {miner_uid} not found")

        return jsonify({
            'miner_uid': miner_score.miner_uid,
            'aggregated_score': miner_score.aggregated_score,
            'validator_count': miner_score.validator_count,
            'score_stddev': miner_score.score_stddev,
            'last_updated': miner_score.last_updated.isoformat() if miner_score.last_updated else None
        }), 200

    except NotFound:
        raise
    except Exception as e:
        logger.error("Failed to get miner score: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/miners/<int:miner_uid>/failure', methods=['POST'])
def report_miner_failure(miner_uid: int):
    """
    Report miner failure by a validator.

    Request body:
    {
        "miner_uid": 17,
        "reason": "Consecutive low scores: 0.253",
        "severity": "critical",
        "validator_uid": 7,
        "timestamp": 1704644105.0
    }

    Response:
    {
        "status": "acknowledged",
        "action": "reassignment_triggered",
        "reassigned_origins": 3
    }
    """
    try:
        data = request.get_json()

        if not data:
            raise BadRequest("Request body required")

        reason = data.get('reason', 'Failure reported by validator')
        severity = data.get('severity', 'medium')
        validator_uid = data.get('validator_uid')

        # Record failure
        conn = get_connection()

        with conn.cursor() as cur:
            cur.execute("""
                SELECT record_miner_failure(%s, %s, %s, %s) AS should_flag
            """, (miner_uid, reason, severity, validator_uid))

            result = cur.fetchone()
            should_flag = result[0] if result else False
            conn.commit()

        response = {
            'status': 'acknowledged',
            'miner_uid': miner_uid
        }

        # If miner was flagged, trigger reassignment
        if should_flag:
            engine = AssignmentEngine(conn)
            reassigned_count = engine.reassign_flagged_miner_origins(miner_uid)

            response['action'] = 'reassignment_triggered'
            response['reassigned_origins'] = reassigned_count

            logger.warning(
                "Miner %d flagged and %d origins reassigned",
                miner_uid,
                reassigned_count
            )
        else:
            response['action'] = 'failure_recorded'

        return jsonify(response), 200

    except BadRequest:
        raise
    except Exception as e:
        logger.error("Failed to report miner failure: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


# ============================================================================
# EXIT HUB ENDPOINTS
# ============================================================================

@bp.route('/exit-hubs/<exit_hub_ip>', methods=['GET'])
def get_exit_hub_access(exit_hub_ip: str):
    """
    Get exit hub access info for traffic inspection.

    Response:
    {
        "ip": "172.104.45.20",
        "ssh_host": "172.104.45.20",
        "ssh_port": 22,
        "ssh_user": "ubuntu",
        "region": "us-east",
        "miners_connected": [42, 89, 23],
        "status": "active"
    }
    """
    try:
        conn = get_connection()

        with conn.cursor() as cur:
            # Query exit hub with metadata for provider info
            cur.execute("""
                SELECT DISTINCT
                    eh.exit_hub_ip,
                    eh.exit_hub_id,
                    eh.metadata,
                    eh.created_at
                FROM tensorprox_exit_hubs eh
                WHERE eh.exit_hub_ip = %s
                LIMIT 1
            """, (exit_hub_ip,))

            exit_hub = cur.fetchone()

            if not exit_hub:
                raise NotFound(f"Exit hub {exit_hub_ip} not found")

            # Extract provider and region from metadata
            metadata = exit_hub[2] or {}
            cloud_provider = metadata.get('cloud_provider', 'aws')
            region = metadata.get('region', 'us-east')
            ssh_user = get_ssh_user_for_provider(cloud_provider)

            # Get miners connected to this exit hub
            cur.execute("""
                SELECT DISTINCT miner_uid
                FROM miner_assignments
                WHERE exit_hub_ip = %s AND status = 'active'
            """, (exit_hub_ip,))

            miners = [row[0] for row in cur.fetchall()]

        return jsonify({
            'ip': exit_hub_ip,
            'ssh_host': exit_hub_ip,
            'ssh_port': 22,
            'ssh_user': ssh_user,
            'cloud_provider': cloud_provider,
            'region': region,
            'miners_connected': miners,
            'status': 'active'
        }), 200

    except NotFound:
        raise
    except Exception as e:
        logger.error("Failed to get exit hub access: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


# ============================================================================
# STATISTICS ENDPOINTS
# ============================================================================

@bp.route('/subnet/statistics', methods=['GET'])
def get_subnet_statistics():
    """
    Get overall subnet statistics.

    Response:
    {
        "active_miners": 42,
        "pre_assignment_miners": 5,
        "flagged_miners": 2,
        "avg_score": 0.735,
        "median_score": 0.728,
        "max_score": 0.925,
        "min_score": 0.453,
        "total_assignments": 127
    }
    """
    try:
        conn = get_connection()
        aggregator = ScoreAggregator(conn)

        stats = aggregator.get_score_statistics()

        # Add assignment count
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) FROM miner_assignments WHERE status = 'active'
            """)
            total_assignments = cur.fetchone()[0]

        stats['total_assignments'] = total_assignments

        return jsonify(stats), 200

    except Exception as e:
        logger.error("Failed to get subnet statistics: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/subnet/top-miners', methods=['GET'])
def get_top_miners():
    """
    Get top-performing miners.

    Query params:
    - limit: Maximum miners to return (default 10)
    - min_validators: Minimum validators required (default 3)

    Response:
    {
        "miners": [
            {
                "miner_uid": 42,
                "aggregated_score": 0.925,
                "validator_count": 7,
                "score_stddev": 0.018,
                "last_updated": "2024-01-07T10:15:35Z"
            }
        ]
    }
    """
    try:
        limit = int(request.args.get('limit', 10))
        min_validators = int(request.args.get('min_validators', 3))

        conn = get_connection()
        aggregator = ScoreAggregator(conn)

        top_miners = aggregator.get_top_miners(
            limit=limit,
            min_validators=min_validators
        )

        return jsonify({
            'miners': [
                {
                    'miner_uid': m.miner_uid,
                    'aggregated_score': m.aggregated_score,
                    'validator_count': m.validator_count,
                    'score_stddev': m.score_stddev,
                    'last_updated': m.last_updated.isoformat() if m.last_updated else None
                }
                for m in top_miners
            ]
        }), 200

    except Exception as e:
        logger.error("Failed to get top miners: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


# ============================================================================
# VOLUME VERIFICATION ENDPOINTS
# ============================================================================

@bp.route('/miners/<int:miner_uid>/verified-volume', methods=['GET'])
def get_miner_verified_volume(miner_uid: int):
    """
    Get volume for a miner (from TPM-managed exit hubs).

    Volume comes from exit hubs which are TPM-controlled infrastructure.
    This is ground truth for reward calculation - miners cannot game this.

    Response:
    {
        "miner_uid": 42,
        "total_verified_bytes": 1234567890,
        "origin_count": 3,
        "origins": [
            {
                "origin_id": "O1",
                "origin_ip": "203.0.113.50",
                "exit_hub_bytes": 411522630,
                "exit_hub_packets": 1234567,
                "last_report": "2024-01-07T10:15:35Z"
            }
        ],
        "generated_at": "2024-01-07T10:15:40Z"
    }
    """
    try:
        verifier = get_volume_verifier()
        volume_data = verifier.to_dict_for_api(miner_uid)

        if volume_data['origin_count'] == 0:
            # No volume data for this miner
            return jsonify({
                'miner_uid': miner_uid,
                'total_verified_bytes': 0,
                'origin_count': 0,
                'origins': [],
                'generated_at': volume_data['generated_at'],
                'message': 'No volume data available for this miner'
            }), 200

        return jsonify(volume_data), 200

    except Exception as e:
        logger.error("Failed to get verified volume for miner %d: %s", miner_uid, e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/miners/verified-volumes', methods=['GET'])
def get_all_verified_volumes():
    """
    Get volumes for all miners (from TPM-managed exit hubs).

    Used by validators during batch reward calculation.

    Response:
    {
        "miners": {
            "42": {
                "total_verified_bytes": 1234567890
            },
            "17": {
                "total_verified_bytes": 987654321
            }
        },
        "stats": {
            "total_origins": 127,
            "unique_miners": 45,
            "total_bytes": 9500000000,
            "total_packets": 12345678
        },
        "generated_at": "2024-01-07T10:15:40Z"
    }
    """
    try:
        from datetime import datetime, timezone

        verifier = get_volume_verifier()
        all_volumes = verifier.get_all_miner_volumes()
        stats = verifier.get_stats()

        miners_dict = {}
        for miner_uid, total_bytes in all_volumes.items():
            miners_dict[str(miner_uid)] = {
                'total_verified_bytes': total_bytes
            }

        return jsonify({
            'miners': miners_dict,
            'stats': stats,
            'generated_at': datetime.now(timezone.utc).isoformat()
        }), 200

    except Exception as e:
        logger.error("Failed to get all verified volumes: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/volume/verification-stats', methods=['GET'])
def get_volume_verification_stats():
    """
    Get overall volume statistics.

    Response:
    {
        "total_origins": 127,
        "unique_miners": 45,
        "total_bytes": 9500000000,
        "total_packets": 12345678
    }
    """
    try:
        verifier = get_volume_verifier()
        stats = verifier.get_stats()

        return jsonify(stats), 200

    except Exception as e:
        logger.error("Failed to get volume stats: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


# ============================================================================
# LEADERBOARD SYNC ENDPOINTS (Validator <-> TPM Integration)
# ============================================================================

@bp.route('/miners/leaderboard/sync', methods=['POST'])
def sync_miner_leaderboard():
    """
    Sync miner leaderboard data from validator (Multi-Validator Support).

    Each validator reports its view of miner availability and EMA scores.
    Data is stored per-validator and aggregated via consensus:
    - Availability: Miner is available if ANY validator sees it online
    - EMA Score: Median across all validators
    - Region: Mode (most common) across validators

    Request body:
    {
        "validator_uid": 7,
        "validator_hotkey": "5GrwvaEF...",
        "miners": [
            {
                "miner_uid": 42,
                "ema_score": 0.875,
                "is_available": true,
                "region": "us-east-1"
            },
            {
                "miner_uid": 17,
                "ema_score": 0.723,
                "is_available": false,
                "region": "eu-west-1"
            }
        ],
        "timestamp": 1704643335.0
    }

    Response:
    {
        "status": "synced",
        "miners_updated": 2,
        "miners_not_found": [],
        "validator_uid": 7
    }
    """
    try:
        data = request.get_json()

        if not data:
            raise BadRequest("Request body required")

        if 'miners' not in data:
            raise BadRequest("miners list required")

        if 'validator_uid' not in data or 'validator_hotkey' not in data:
            raise BadRequest("validator_uid and validator_hotkey required")

        miners_data = data['miners']
        validator_uid = data['validator_uid']
        validator_hotkey = data['validator_hotkey']

        conn = get_connection()
        updated_count = 0
        not_found = []

        created_count = 0

        with conn.cursor() as cur:
            for miner in miners_data:
                miner_uid = miner.get('miner_uid')
                if miner_uid is None:
                    continue

                ema_score = miner.get('ema_score')
                last_audit_score = miner.get('last_audit_score')
                is_available = miner.get('is_available', False)
                region = miner.get('region')
                hotkey = miner.get('hotkey')  # Hotkey from validator

                # Check if miner exists, auto-create if not
                cur.execute(
                    "SELECT 1 FROM subnet_miners WHERE miner_uid = %s",
                    (miner_uid,)
                )
                if not cur.fetchone():
                    # Auto-register miner in subnet_miners (enables assignment flow)
                    if hotkey:
                        cur.execute("""
                            INSERT INTO subnet_miners (
                                miner_uid, hotkey, state, ema_score, last_audit_score,
                                is_available, region, registered_at, updated_at
                            ) VALUES (%s, %s, 'pre_assignment', %s, %s, %s, %s, NOW(), NOW())
                            ON CONFLICT (miner_uid) DO NOTHING
                        """, (miner_uid, hotkey, ema_score or 0.0, last_audit_score or 0.0, is_available, region))
                        created_count += 1
                        logger.info("Auto-registered miner UID %d (hotkey=%s...) in subnet_miners",
                                  miner_uid, hotkey[:16] if hotkey else 'N/A')
                    else:
                        not_found.append(miner_uid)
                        continue

                # Upsert into validator_heartbeats (per-validator data)
                cur.execute("""
                    INSERT INTO validator_heartbeats (
                        validator_uid, validator_hotkey, miner_uid,
                        is_available, ema_score, region, reported_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (validator_uid, miner_uid) DO UPDATE SET
                        validator_hotkey = EXCLUDED.validator_hotkey,
                        is_available = EXCLUDED.is_available,
                        ema_score = EXCLUDED.ema_score,
                        region = COALESCE(EXCLUDED.region, validator_heartbeats.region),
                        reported_at = NOW()
                """, (
                    validator_uid, validator_hotkey, miner_uid,
                    is_available, ema_score, region
                ))

                # Update last_audit_score directly (raw score for deployment fallback)
                if last_audit_score is not None:
                    cur.execute("""
                        UPDATE subnet_miners
                        SET last_audit_score = %s
                        WHERE miner_uid = %s
                    """, (last_audit_score, miner_uid))

                updated_count += 1

            # Also update the aggregated values in subnet_miners from consensus view
            # This keeps subnet_miners as the "materialized" consensus for fast queries
            cur.execute("""
                UPDATE subnet_miners sm
                SET
                    is_available = COALESCE(mac.is_available, FALSE),
                    ema_score = COALESCE(mac.consensus_ema_score, sm.aggregated_score),
                    region = COALESCE(mac.consensus_region, sm.region),
                    last_heartbeat = mac.last_report,
                    updated_at = NOW()
                FROM miner_availability_consensus mac
                WHERE sm.miner_uid = mac.miner_uid
            """)

            # Link miner_id from tensorprox_miners to subnet_miners via hotkey
            # This enables the validator API to find assignments by miner_uid
            cur.execute("""
                UPDATE subnet_miners sm
                SET miner_id = tm.miner_id::text,
                    updated_at = NOW()
                FROM tensorprox_miners tm
                WHERE sm.hotkey = (tm.metadata->>'hotkey')
                  AND sm.miner_id IS NULL
                  AND tm.status = 'active'
            """)
            linked_count = cur.rowcount
            if linked_count > 0:
                logger.info("Linked %d miners from tensorprox_miners to subnet_miners via hotkey", linked_count)

            # Sync scrubber_ip from tensorprox_miners to subnet_miners
            # Uses emn_ip from metadata (miner's control plane IP) or falls back to current_ip
            # This enables AssignmentEngine to find the miner's scrubber IP for deployments
            cur.execute("""
                UPDATE subnet_miners sm
                SET scrubber_ip = COALESCE(
                    tm.metadata->>'emn_ip',
                    tm.current_ip
                ),
                    updated_at = NOW()
                FROM tensorprox_miners tm
                WHERE sm.miner_id = tm.miner_id::text
                  AND tm.status = 'active'
                  AND (sm.scrubber_ip IS NULL OR sm.scrubber_ip = '')
                  AND (tm.metadata->>'emn_ip' IS NOT NULL OR tm.current_ip IS NOT NULL)
            """)
            ip_synced_count = cur.rowcount
            if ip_synced_count > 0:
                logger.info("Synced scrubber_ip for %d miners from tensorprox_miners", ip_synced_count)

            # Auto-promote miners from 'pre_assignment' to 'active' when they meet threshold
            # This enables them to receive origin assignments
            MIN_SCORE_FOR_ACTIVE = 0.8
            cur.execute("""
                UPDATE subnet_miners
                SET state = 'active', updated_at = NOW()
                WHERE state = 'pre_assignment'
                  AND ema_score >= %s
                  AND is_available = TRUE
                RETURNING miner_uid
            """, (MIN_SCORE_FOR_ACTIVE,))
            promoted_miners = [row[0] for row in cur.fetchall()]
            if promoted_miners:
                logger.info("Auto-promoted %d miners to 'active': UIDs %s",
                          len(promoted_miners), promoted_miners)

            conn.commit()

        logger.info(
            "Leaderboard sync from validator %s: %d miners updated, %d created, %d not found",
            validator_uid,
            updated_count,
            created_count,
            len(not_found)
        )

        return jsonify({
            'status': 'synced',
            'miners_updated': updated_count,
            'miners_created': created_count,
            'miners_not_found': not_found,
            'validator_uid': validator_uid
        }), 200

    except BadRequest:
        raise
    except Exception as e:
        logger.error("Failed to sync leaderboard: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/miners/leaderboard', methods=['GET'])
def get_miner_leaderboard():
    """
    Get miner leaderboard with availability and region info.

    Query params:
    - min_score: Minimum EMA score (default 0.8)
    - region: Filter by region (optional)
    - available_only: Only return available miners (default true)
    - limit: Maximum miners to return (default 50)

    Response:
    {
        "miners": [
            {
                "miner_uid": 42,
                "hotkey": "5GrwvaEF...",
                "aggregated_score": 0.862,
                "ema_score": 0.875,
                "is_available": true,
                "region": "us-east-1",
                "origins_assigned": 3,
                "max_origins": 10,
                "available_capacity": 7,
                "state": "active",
                "last_heartbeat": "2024-01-07T10:15:35Z"
            }
        ],
        "total_count": 42,
        "available_count": 38
    }
    """
    try:
        min_score = float(request.args.get('min_score', 0.8))
        region = request.args.get('region')
        available_only = request.args.get('available_only', 'true').lower() == 'true'
        limit = int(request.args.get('limit', 50))

        conn = get_connection()

        with conn.cursor() as cur:
            # Build query with filters
            # First try EMA score (more reliable), fall back to aggregated_score if no EMA miners
            query = """
                SELECT
                    miner_uid,
                    hotkey,
                    aggregated_score,
                    ema_score,
                    is_available,
                    region,
                    origins_assigned,
                    max_origins,
                    state,
                    last_heartbeat
                FROM subnet_miners
                WHERE state = 'active'
                  AND ema_score >= %s
            """
            params = [min_score]

            if available_only:
                query += " AND is_available = TRUE"

            if region:
                query += " AND (region = %s OR region IS NULL)"
                params.append(region)

            query += """
                ORDER BY
                    ema_score DESC,
                    origins_assigned ASC
                LIMIT %s
            """
            params.append(limit)

            cur.execute(query, params)
            rows = cur.fetchall()

            # Fallback: if no miners have EMA >= threshold, use last raw audit score.
            # This handles EMA warm-up (cold start from zero) where EMA is still building
            # but the miner's latest audit proves it can perform.
            if not rows:
                logger.info(
                    "No miners with ema_score >= %.2f, falling back to last_audit_score",
                    min_score
                )
                fallback_query = """
                    SELECT
                        miner_uid,
                        hotkey,
                        aggregated_score,
                        last_audit_score as ema_score,
                        is_available,
                        region,
                        origins_assigned,
                        max_origins,
                        state,
                        last_heartbeat
                    FROM subnet_miners
                    WHERE state = 'active'
                      AND last_audit_score >= %s
                """
                fallback_params = [min_score]

                if available_only:
                    fallback_query += " AND is_available = TRUE"

                if region:
                    fallback_query += " AND (region = %s OR region IS NULL)"
                    fallback_params.append(region)

                fallback_query += """
                    ORDER BY
                        last_audit_score DESC,
                        origins_assigned ASC
                    LIMIT %s
                """
                fallback_params.append(limit)

                cur.execute(fallback_query, fallback_params)
                rows = cur.fetchall()

            # Get counts
            cur.execute("""
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE is_available = TRUE) as available
                FROM subnet_miners
                WHERE state = 'active'
            """)
            counts = cur.fetchone()

        miners = []
        for row in rows:
            miners.append({
                'miner_uid': row[0],
                'hotkey': row[1],
                'aggregated_score': float(row[2]) if row[2] else 0.0,
                'ema_score': float(row[3]) if row[3] else 0.0,
                'is_available': row[4] if row[4] is not None else False,
                'region': row[5],
                'origins_assigned': row[6] or 0,
                'max_origins': row[7] or 10,
                'available_capacity': (row[7] or 10) - (row[6] or 0),
                'state': row[8],
                'last_heartbeat': row[9].isoformat() if row[9] else None
            })

        return jsonify({
            'miners': miners,
            'total_count': counts[0] if counts else 0,
            'available_count': counts[1] if counts else 0
        }), 200

    except Exception as e:
        logger.error("Failed to get miner leaderboard: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/origins/request-assignment', methods=['POST'])
def request_origin_assignment():
    """
    Request miner assignment for a new origin.

    Called when TPM deploys a new origin and needs a miner/scrubber.
    Returns the best available miner based on EMA score, region, and capacity.

    Request body:
    {
        "origin_id": "origin-123",
        "origin_ip": "203.0.113.50",
        "exit_hub_ip": "172.104.45.20",
        "tunnel_name": "wg-origin-123",
        "expected_bandwidth_mbps": 500,
        "traffic_type": "web",
        "preferred_region": "us-east-1",
        "cloud_provider": "aws"  // Optional: aws, linode (inferred from region if not specified)
    }

    Response:
    {
        "status": "assigned",
        "assignment": {
            "assignment_id": 456,
            "origin_id": "origin-123",
            "miner_uid": 42,
            "miner_hotkey": "5GrwvaEF...",
            "scrubber_ip": "18.203.45.67",
            "ema_score": 0.875,
            "region": "us-east-1"
        }
    }
    """
    try:
        from tensorprox.tpm.services.assignment_engine import AssignmentRequest

        data = request.get_json()

        if not data:
            raise BadRequest("Request body required")

        # Validate required fields
        required = ['origin_id', 'origin_ip', 'exit_hub_ip', 'tunnel_name']
        for field in required:
            if field not in data:
                raise BadRequest(f"{field} required")

        # Create assignment request
        assignment_request = AssignmentRequest(
            origin_id=data['origin_id'],
            origin_ip=data['origin_ip'],
            expected_bandwidth_mbps=data.get('expected_bandwidth_mbps'),
            traffic_type=data.get('traffic_type'),
            preferred_region=data.get('preferred_region'),
            cloud_provider=data.get('cloud_provider')
        )

        conn = get_connection()
        engine = AssignmentEngine(conn)

        # Assign origin to best miner
        assignment = engine.assign_origin(
            request=assignment_request,
            exit_hub_ip=data['exit_hub_ip'],
            tunnel_name=data['tunnel_name']
        )

        # Check data freshness for response metadata
        is_fresh, last_update, fresh_count = engine.check_data_freshness()

        if not assignment:
            return jsonify({
                'status': 'no_miner_available',
                'message': 'No suitable miner found for assignment',
                'requirements': {
                    'min_score': engine.MIN_SCORE,
                    'preferred_region': data.get('preferred_region'),
                    'require_available': True
                },
                'data_freshness': {
                    'is_fresh': is_fresh,
                    'last_update': last_update.isoformat() if last_update else None,
                    'stale_threshold_minutes': engine.STALE_DATA_THRESHOLD_MINUTES
                }
            }), 503

        # Get miner details for response
        with conn.cursor() as cur:
            cur.execute("""
                SELECT hotkey, ema_score, region
                FROM subnet_miners
                WHERE miner_uid = %s
            """, (assignment.miner_uid,))
            miner_info = cur.fetchone()

        response = {
            'status': 'assigned',
            'assignment': {
                'assignment_id': assignment.assignment_id,
                'origin_id': assignment.origin_id,
                'miner_uid': assignment.miner_uid,
                'miner_hotkey': miner_info[0] if miner_info else None,
                'scrubber_ip': assignment.scrubber_ip,
                'ema_score': float(miner_info[1]) if miner_info and miner_info[1] else 0.0,
                'region': miner_info[2] if miner_info else None
            }
        }

        # Add warning if data is stale
        if not is_fresh:
            response['warning'] = 'Leaderboard data is stale - availability info may be outdated'
            response['data_freshness'] = {
                'is_fresh': False,
                'last_update': last_update.isoformat() if last_update else None,
                'stale_threshold_minutes': engine.STALE_DATA_THRESHOLD_MINUTES
            }

        return jsonify(response), 200

    except BadRequest:
        raise
    except Exception as e:
        logger.error("Failed to request origin assignment: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/subnet/leaderboard-health', methods=['GET'])
def get_leaderboard_health():
    """
    Check leaderboard data freshness and validator sync status.

    Used for monitoring whether validators are syncing data to TPM.
    Shows per-validator sync status for multi-validator setups.

    Response:
    {
        "is_fresh": true,
        "last_update": "2024-01-07T10:15:35Z",
        "fresh_miners_count": 42,
        "stale_threshold_minutes": 30,
        "status": "healthy",
        "message": "Leaderboard data is fresh (2 validators syncing)",
        "validators": [
            {"uid": 7, "last_sync": "2024-01-07T10:15:35Z", "miners_reported": 42, "is_fresh": true},
            {"uid": 12, "last_sync": "2024-01-07T10:12:00Z", "miners_reported": 40, "is_fresh": true}
        ]
    }
    """
    try:
        conn = get_connection()
        engine = AssignmentEngine(conn)

        is_fresh, last_update, fresh_count = engine.check_data_freshness()

        # Get per-validator sync status
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)

        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    validator_uid,
                    MAX(reported_at) as last_sync,
                    COUNT(DISTINCT miner_uid) as miners_reported,
                    MAX(reported_at) > NOW() - INTERVAL '15 minutes' as is_fresh
                FROM validator_heartbeats
                WHERE reported_at > NOW() - INTERVAL '1 hour'
                GROUP BY validator_uid
                ORDER BY last_sync DESC
            """)
            validators = []
            for row in cur.fetchall():
                last_sync = row[1]
                if last_sync and last_sync.tzinfo is None:
                    last_sync = last_sync.replace(tzinfo=timezone.utc)
                validators.append({
                    'uid': row[0],
                    'last_sync': last_sync.isoformat() if last_sync else None,
                    'miners_reported': row[2],
                    'is_fresh': row[3] if row[3] is not None else False
                })

        # Calculate how long ago data was updated
        if last_update:
            if last_update.tzinfo is None:
                last_update = last_update.replace(tzinfo=timezone.utc)
            minutes_ago = (now - last_update).total_seconds() / 60
        else:
            minutes_ago = None

        fresh_validators = sum(1 for v in validators if v['is_fresh'])
        total_validators = len(validators)

        if is_fresh:
            status = 'healthy'
            if total_validators > 0:
                message = f'Leaderboard data is fresh ({fresh_validators}/{total_validators} validators syncing)'
            else:
                message = 'Leaderboard data is fresh'
        else:
            status = 'stale'
            if minutes_ago:
                message = f'WARNING: Leaderboard data is stale (last update {int(minutes_ago)} min ago). {fresh_validators}/{total_validators} validators active.'
            else:
                message = 'WARNING: No leaderboard data found. No validators have synced.'

        return jsonify({
            'is_fresh': is_fresh,
            'last_update': last_update.isoformat() if last_update else None,
            'fresh_miners_count': fresh_count,
            'stale_threshold_minutes': engine.STALE_DATA_THRESHOLD_MINUTES,
            'status': status,
            'message': message,
            'minutes_since_update': int(minutes_ago) if minutes_ago else None,
            'validators': validators,
            'validators_fresh': fresh_validators,
            'validators_total': total_validators
        }), 200

    except Exception as e:
        logger.error("Failed to check leaderboard health: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/miners/<int:miner_uid>/availability', methods=['PUT'])
def update_miner_availability(miner_uid: int):
    """
    Update miner availability status.

    Called by validators or miners to report online/offline status.

    Request body:
    {
        "is_available": true,
        "region": "us-east-1",
        "scrubber_ip": "18.203.45.67"
    }

    Response:
    {
        "status": "updated",
        "miner_uid": 42,
        "is_available": true
    }
    """
    try:
        data = request.get_json()

        if not data:
            raise BadRequest("Request body required")

        is_available = data.get('is_available')
        region = data.get('region')
        scrubber_ip = data.get('scrubber_ip')

        if is_available is None:
            raise BadRequest("is_available required")

        conn = get_connection()

        with conn.cursor() as cur:
            updates = ["is_available = %s", "last_heartbeat = NOW()", "updated_at = NOW()"]
            params = [bool(is_available)]

            if region is not None:
                updates.append("region = %s")
                params.append(region)

            if scrubber_ip is not None:
                updates.append("scrubber_ip = %s")
                params.append(scrubber_ip)

            params.append(miner_uid)

            cur.execute(f"""
                UPDATE subnet_miners
                SET {', '.join(updates)}
                WHERE miner_uid = %s
            """, params)

            if cur.rowcount == 0:
                raise NotFound(f"Miner {miner_uid} not found")

            conn.commit()

        logger.info(
            "Miner %d availability updated: %s (region=%s)",
            miner_uid,
            is_available,
            region
        )

        return jsonify({
            'status': 'updated',
            'miner_uid': miner_uid,
            'is_available': is_available
        }), 200

    except (BadRequest, NotFound):
        raise
    except Exception as e:
        logger.error("Failed to update miner availability: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


# ============================================================================
# PRODUCTION METRICS (from Exit Hubs - TPM-owned ground truth)
# ============================================================================

# In-memory cache for exit hub XDP metrics (populated via Redis subscription)
# Key: exit_hub_id, Value: latest XDP metrics report
_exit_hub_xdp_metrics: Dict[str, Dict] = {}
_exit_hub_metrics_lock = threading.Lock()


def update_exit_hub_metrics(exit_hub_id: str, metrics: Dict):
    """Update cached XDP metrics for an exit hub (called from Redis subscriber)."""
    with _exit_hub_metrics_lock:
        _exit_hub_xdp_metrics[exit_hub_id] = {
            **metrics,
            'received_at': datetime.now(timezone.utc).isoformat()
        }


def get_exit_hub_metrics(exit_hub_id: str) -> Optional[Dict]:
    """Get cached XDP metrics for an exit hub."""
    with _exit_hub_metrics_lock:
        return _exit_hub_xdp_metrics.get(exit_hub_id)


def get_all_exit_hub_metrics() -> Dict[str, Dict]:
    """Get all cached exit hub XDP metrics."""
    with _exit_hub_metrics_lock:
        return dict(_exit_hub_xdp_metrics)


@bp.route('/miners/production-metrics', methods=['GET'])
def get_production_metrics():
    """
    Get production XDP metrics for all assigned miners.

    Returns ground-truth metrics from TPM-owned exit hubs.
    These metrics cannot be gamed by miners - they come from
    infrastructure controlled by TPM.

    Used by validators for production EMA scoring.

    Response:
    {
        "miners": {
            "59": {
                "miner_uid": 59,
                "timestamp": "2024-01-07T10:15:35Z",
                "xdp_pass": 123456,
                "xdp_drop_blacklist": 100,
                "xdp_drop_ratelimit": 50,
                "syn_synack_ratio": 1.2,
                "total_packets": 200000,
                "total_bytes": 50000000,
                "origin_count": 1,
                "origins": [...]
            }
        }
    }
    """
    try:
        conn = get_connection()
        result = {"miners": {}}

        # Get all active exit hubs and their miner assignments
        # Uses tensorprox_origins + subnet_miners (standard join pattern)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    eh.exit_hub_id,
                    o.origin_id,
                    eh.exit_hub_ip,
                    eh.tensorprox_ip,
                    sm.miner_uid
                FROM tensorprox_exit_hubs eh
                JOIN tensorprox_origins o ON o.last_exit_hub_id::text = eh.exit_hub_id::text
                JOIN subnet_miners sm ON o.miner_id = sm.miner_id
                WHERE eh.status = 'active' AND o.status = 'active'
            """)

            exit_hubs = {}
            for row in cur.fetchall():
                exit_hub_id = str(row[0])
                miner_uid = row[4]

                if miner_uid not in exit_hubs:
                    exit_hubs[miner_uid] = []

                exit_hubs[miner_uid].append({
                    'exit_hub_id': exit_hub_id,
                    'origin_id': row[1],
                    'exit_hub_ip': row[2],
                    'tensorprox_ip': row[3],
                })

        # Aggregate metrics per miner from exit hub reports
        all_metrics = get_all_exit_hub_metrics()

        for miner_uid, hubs in exit_hubs.items():
            miner_metrics = {
                'miner_uid': miner_uid,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'xdp_pass': 0,
                'xdp_drop_blacklist': 0,
                'xdp_drop_ratelimit': 0,
                'xdp_drop_temp_blacklist': 0,
                'xdp_drop_bogon': 0,
                'xdp_drop_invalid_ip': 0,
                'xdp_drop_invalid_tcp': 0,
                'active_connections': 0,
                'syn_synack_ratio': 1.0,
                'total_packets': 0,
                'total_bytes': 0,
                'origin_count': len(hubs),
                'origins': [],
            }

            total_syn = 0
            total_synack = 0

            for hub in hubs:
                exit_hub_id = hub['exit_hub_id']
                xdp_report = all_metrics.get(exit_hub_id)

                origin_data = {
                    'origin_id': hub['origin_id'],
                    'exit_hub_ip': hub['exit_hub_ip'],
                    'has_metrics': xdp_report is not None,
                }

                if xdp_report:
                    global_metrics = xdp_report.get('global', {})
                    origin_metrics = xdp_report.get('origins', {})

                    # Aggregate global metrics
                    miner_metrics['xdp_pass'] += global_metrics.get('xdp_pass', 0)
                    miner_metrics['total_packets'] += global_metrics.get('total_packets', 0)
                    miner_metrics['total_bytes'] += global_metrics.get('total_bytes', 0)
                    total_syn += global_metrics.get('total_syn', 0)
                    total_synack += global_metrics.get('total_synack', 0)

                    # XDP drops (exit hub monitors, but drops happen at scrubber)
                    # For now, we don't track drops at exit hub - just pass count
                    xdp_drop = global_metrics.get('xdp_drop', 0)
                    if xdp_drop > 0:
                        miner_metrics['xdp_drop_ratelimit'] += xdp_drop

                    origin_data['global'] = global_metrics
                    origin_data['per_origin'] = origin_metrics

                miner_metrics['origins'].append(origin_data)

            # Add SYN/SYN-ACK counts for origin-down vs flood distinction
            miner_metrics['total_syn'] = total_syn
            miner_metrics['total_synack'] = total_synack

            # Calculate overall SYN/SYN-ACK ratio
            if total_synack > 0:
                miner_metrics['syn_synack_ratio'] = round(total_syn / total_synack, 2)
            elif total_syn > 0:
                miner_metrics['syn_synack_ratio'] = 999.99

            result['miners'][str(miner_uid)] = miner_metrics

        return jsonify(result), 200

    except Exception as e:
        logger.error("Failed to get production metrics: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/miners/<int:miner_uid>/production-metrics', methods=['GET'])
def get_miner_production_metrics(miner_uid: int):
    """
    Get production XDP metrics for a specific miner.

    Response:
    {
        "miner_uid": 59,
        "metrics": {
            "xdp_pass": 123456,
            "syn_synack_ratio": 1.2,
            ...
        }
    }
    """
    try:
        # Use the bulk endpoint and filter
        conn = get_connection()

        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    eh.exit_hub_id,
                    o.origin_id,
                    eh.exit_hub_ip
                FROM tensorprox_exit_hubs eh
                JOIN tensorprox_origins o ON o.last_exit_hub_id::text = eh.exit_hub_id::text
                JOIN subnet_miners sm ON o.miner_id = sm.miner_id
                WHERE eh.status = 'active' AND o.status = 'active' AND sm.miner_uid = %s
            """, (miner_uid,))

            hubs = cur.fetchall()

        if not hubs:
            return jsonify({
                'miner_uid': miner_uid,
                'metrics': None,
                'message': 'No active assignments for this miner'
            }), 200

        # Get metrics for this miner's exit hubs
        all_metrics = get_all_exit_hub_metrics()

        total_pass = 0
        total_packets = 0
        total_bytes = 0
        total_syn = 0
        total_synack = 0
        origins = []

        for row in hubs:
            exit_hub_id = str(row[0])
            xdp_report = all_metrics.get(exit_hub_id)

            origin_data = {
                'origin_id': row[1],
                'exit_hub_ip': row[2],
                'has_metrics': xdp_report is not None,
            }

            if xdp_report:
                global_metrics = xdp_report.get('global', {})
                total_pass += global_metrics.get('xdp_pass', 0)
                total_packets += global_metrics.get('total_packets', 0)
                total_bytes += global_metrics.get('total_bytes', 0)
                total_syn += global_metrics.get('total_syn', 0)
                total_synack += global_metrics.get('total_synack', 0)
                origin_data['metrics'] = global_metrics

            origins.append(origin_data)

        syn_synack_ratio = 1.0
        if total_synack > 0:
            syn_synack_ratio = round(total_syn / total_synack, 2)
        elif total_syn > 0:
            syn_synack_ratio = 999.99

        return jsonify({
            'miner_uid': miner_uid,
            'metrics': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'xdp_pass': total_pass,
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'syn_synack_ratio': syn_synack_ratio,
                'origin_count': len(origins),
                'origins': origins,
            }
        }), 200

    except Exception as e:
        logger.error("Failed to get miner production metrics: %s", e, exc_info=True)
        return jsonify({
            'error': 'internal_error',
            'message': str(e)
        }), 500


@bp.route('/exit-hubs/<exit_hub_id>/xdp-metrics', methods=['POST'])
def receive_exit_hub_xdp_metrics(exit_hub_id: str):
    """
    Receive XDP metrics from an exit hub.

    Called by the exit-hub-agent to report XDP metrics.
    Alternative to Redis pubsub for direct HTTP reporting.

    Request body:
    {
        "type": "exit_hub_xdp_metrics",
        "timestamp": "2024-01-07T10:15:35Z",
        "exit_hub_id": "uuid",
        "origins": {...},
        "global": {...}
    }
    """
    data = request.get_json()
    if not data:
        raise BadRequest("Missing request body")

    # Validate the exit hub exists
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT exit_hub_id FROM tensorprox_exit_hubs
            WHERE exit_hub_id = %s AND status = 'active'
        """, (exit_hub_id,))
        if not cur.fetchone():
            raise NotFound(f"Exit hub {exit_hub_id} not found or not active")

    # Store in cache
    update_exit_hub_metrics(exit_hub_id, data)

    logger.debug(
        "Received XDP metrics from exit hub %s: %d origins, syn_synack_ratio=%s",
        exit_hub_id,
        data.get('origin_count', 0),
        data.get('global', {}).get('syn_synack_ratio', 'N/A')
    )

    return jsonify({'status': 'received'}), 200
