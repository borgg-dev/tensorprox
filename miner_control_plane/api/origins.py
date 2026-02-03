"""Origins API Blueprint

Origin registration, lifecycle management.
"""
import json
import logging
from flask import Blueprint, request, jsonify
from shared.utils.ports import normalize_port_list
from miner_control_plane.services.origin_service import origin_service
from miner_control_plane.services.scrubber_utils import get_nodes_for_origin
from miner_control_plane.api.auth import require_tpm_auth
from miner_control_plane.services.bandwidth_quota_service import recalculate_quotas

logger = logging.getLogger(__name__)

bp = Blueprint('origins', __name__, url_prefix='/api/v1/origins')


@bp.post('', strict_slashes=False)
@require_tpm_auth
def create_origin():
    """
    Create a new Origin in a specific shard.

    Multi-region: shard_id is REQUIRED. TPM must select shard before calling.

    Request body:
    {
        "origin_id": "O1",
        "shard_id": "eu-central-1",  // REQUIRED
        "exit_hub_ip": "198.51.100.10",  // RFC 5737 example - use your exit hub IP
        "origin_ip": "198.51.100.20",    // RFC 5737 example - use your origin IP
        "required_ports": {"tcp": [80, 443], "udp": []}
    }

    Error Responses:
    - 400: Missing shard_id
    - 404: Shard not found (code: shard_not_found)
    - 409: Shard not ready (code: shard_not_ready, includes job_id if deploying)
    - 409: No capacity (code: capacity_exhausted, includes hard_capacity details)
    - 500: Internal error
    """
    data = request.json

    # shard_id is required (no auto-select)
    shard_id = data.get('shard_id')
    if not shard_id:
        return jsonify({
            'status': 'error',
            'message': 'shard_id is required. Query GET /api/v1/admin/shards to list available shards.'
        }), 400

    required_ports = normalize_port_list(data.get('required_ports'))
    response, status_code = origin_service.create_origin(
        origin_id=data['origin_id'],
        shard_id=shard_id,
        exit_hub_ip=data['exit_hub_ip'],
        origin_ip=data['origin_ip'],
        required_ports=required_ports
    )

    # Recalculate bandwidth quotas on success
    if status_code in (200, 201):
        try:
            recalculate_quotas(shard_id=shard_id)
            logger.info(f"Recalculated bandwidth quotas for shard {shard_id} after creating origin")
        except Exception as e:
            logger.warning(f"Failed to recalculate bandwidth quotas: {e}")
            # Non-fatal - origin is created, quotas will be recalculated later

    return response, status_code


@bp.get('', strict_slashes=False)
def list_origins():
    """
    List all origins.
    """
    origins = origin_service.list_origins()
    return jsonify({'origins': origins})


@bp.get('/<origin_id>')
def get_origin(origin_id):
    """
    Get origin details.
    """
    origin = origin_service.get_origin(origin_id)
    if not origin:
        return jsonify({'error': 'Origin not found'}), 404
    return jsonify(origin)


@bp.delete('/<origin_id>')
@require_tpm_auth
def delete_origin(origin_id):
    """
    Delete an Origin asynchronously via job worker.

    Returns 202 Accepted with job_id immediately. The actual deletion is
    performed by the job worker in the background (takes 2-4 minutes).

    Query GET /api/v1/admin/jobs/{job_id} to check job status.

    Note: Origin lookup is database-first (same as old sync behavior).
    If origin not in cache, we check database before creating job.

    Returns:
        202: {"status": "accepted", "job_id": "...", "origin_id": "..."}
        404: Origin not found (neither in cache nor database)
    """
    from miner_control_plane.services.state_manager import state_manager
    from miner_control_plane.services.job_worker import create_job
    from shared.database import get_db_connection
    from shared.utils.database_helpers import db_load_origins

    # Get shard_id from cache first (fast path)
    shard_id = None
    region = None

    if origin_id in state_manager.origins_db:
        origin = state_manager.origins_db[origin_id]
        shard_id = origin.get('shard_id')
    else:
        # Database-first lookup (same as delete_origin does internally)
        # This handles the miner-restart scenario where cache is empty
        logger.info(f"Origin {origin_id} not in cache, checking database...")
        db = get_db_connection()
        try:
            all_origins = db_load_origins(db)
            if origin_id in all_origins:
                origin = all_origins[origin_id]
                shard_id = origin.get('shard_id')
                # Update cache for consistency
                state_manager.origins_db[origin_id] = origin
                logger.info(f"Found origin {origin_id} in database")
            else:
                return jsonify({'status': 'error', 'message': 'Origin not found'}), 404
        finally:
            db.close()

    # Get region from shard
    if shard_id:
        shard = state_manager.shards_db.get(shard_id)
        region = shard.get('region') if shard else None

    # Create async deletion job
    job_id = create_job(
        job_type='delete_origin',
        shard_id=shard_id,
        region=region,
        metadata={
            'origin_id': origin_id,
            'shard_id': shard_id,
        }
    )

    logger.info(f"Created delete_origin job {job_id} for origin {origin_id}")

    return jsonify({
        'status': 'accepted',
        'job_id': job_id,
        'origin_id': origin_id,
        'shard_id': shard_id,
        'message': 'Origin deletion job queued. Query /api/v1/admin/jobs/{job_id} for status.'
    }), 202


@bp.post('/<origin_id>/enable')
@require_tpm_auth
def enable_origin(origin_id: str):
    """
    Enable an Origin
    """
    from miner_control_plane.services.state_manager import state_manager
    import logging
    logger = logging.getLogger(__name__)

    if origin_id not in state_manager.origins_db:
        return jsonify({'status': 'error', 'message': 'Origin not found'}), 404

    state_manager.origins_db[origin_id]['state'] = 'IN_SERVICE'
    logger.info(f"Origin {origin_id} enabled")
    return jsonify({'status': 'success'})


@bp.post('/<origin_id>/disable')
@require_tpm_auth
def disable_origin(origin_id: str):
    """
    Disable an Origin
    """
    from miner_control_plane.services.state_manager import state_manager
    import logging
    logger = logging.getLogger(__name__)

    if origin_id not in state_manager.origins_db:
        return jsonify({'status': 'error', 'message': 'Origin not found'}), 404

    state_manager.origins_db[origin_id]['state'] = 'DISABLED'
    logger.info(f"Origin {origin_id} disabled")
    return jsonify({'status': 'success'})


@bp.patch('/<origin_id>/ports')
@require_tpm_auth
def update_origin_ports(origin_id: str):
    """
    Update origin ports - client sends complete new port list, miner calculates diff.

    Authorization: Requires valid TensorProx Management Authorization header.

    Request body (CLIENT-FRIENDLY FORMAT):
    {
        "ports": [8080, 9001, 9005, 9200]    // Complete new port list
    }

    Or string format (from web UI text field):
    {
        "ports": "8080, 9001, 9005, 9200"    // Comma-separated string
    }

    Miner automatically:
    - Fetches current ports from database
    - Calculates added = new - current
    - Calculates removed = current - new
    - Applies changes with reference counting
    - Opens BOTH TCP and UDP for each port

    Features:
    - Client doesn't calculate add/remove (miner does the diff)
    - Multi-cloud provider aware (queries database for provider)
    - Reference counting (only removes ports not used by other origins)
    - Idempotent (safe to call multiple times)
    - Updates both security group AND database

    Returns:
    {
        "status": "success",
        "ports_added": [9005, 9200],         // Calculated by miner
        "ports_removed": [9003],             // Calculated by miner
        "ports_kept": [9101],                // Requested removal but kept (used by others)
        "current_ports": [8080, 9001, 9005, 9200]
    }
    """
    from miner_control_plane.services.state_manager import state_manager
    from shared.database import get_db_connection
    from shared.utils.logging import get_logger

    logger = get_logger(__name__)

    try:
        # Validate origin exists
        if origin_id not in state_manager.origins_db:
            return jsonify({'status': 'error', 'message': 'Origin not found'}), 404

        data = request.json or {}

        # Get new port list from request (normalize handles arrays, strings, dicts)
        new_ports_requested = normalize_port_list(data.get('ports', []))
        new_ports_set = set(new_ports_requested)

        if not new_ports_requested:
            return jsonify({
                'status': 'error',
                'message': 'ports field required (array or comma-separated string)'
            }), 400

        # Get current origin ports from database
        origin = state_manager.origins_db[origin_id]
        current_ports_list = normalize_port_list(origin.get('required_ports', []))
        current_ports_set = set(current_ports_list)

        # Calculate diff (miner does the work, not the client!)
        ports_to_add = new_ports_set - current_ports_set
        ports_to_remove = current_ports_set - new_ports_set

        logger.info(
            f"Port diff for {origin_id}: "
            f"add={sorted(ports_to_add)}, remove={sorted(ports_to_remove)}"
        )

        # Detect which provider the scrubbers are using (multi-cloud aware)
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        try:
            # Get nodes for this origin's shard (multi-region aware)
            nodes = get_nodes_for_origin(origin_id)

            if not nodes:
                return jsonify({
                    'status': 'error',
                    'message': 'No scrubber nodes found - cannot update ports'
                }), 404

            provider = nodes[0]['provider']
            logger.info(f"Detected provider for port update: {provider}")

            # Get provider-specific operations (currently only AWS supported)
            if provider == 'aws':
                from miner_control_plane.utils.aws import aws_operations

                # Get region from origin's shard
                shard_id = origin.get('shard_id')
                shard = state_manager.shards_db.get(shard_id) if shard_id else None
                region = shard.get('region') if shard else None

                if not region:
                    logger.error(f"Cannot determine region for origin {origin_id} with shard_id {shard_id}")
                    return jsonify({
                        'status': 'error',
                        'message': f'Cannot determine region for shard {shard_id}'
                    }), 500

                # Step 1: Add new ports to security group (idempotent)
                # Both TCP and UDP opened for each port (same as origin creation)
                if ports_to_add:
                    ports_to_add_list = sorted(list(ports_to_add))
                    logger.info(
                        f"Adding ports to AWS Security Group (TCP+UDP): {ports_to_add_list}"
                    )
                    aws_operations.add_ports_to_security_group(ports=ports_to_add_list, region=region)

                # Step 2: Remove ports with reference counting
                ports_kept = []
                ports_actually_removed = []

                if ports_to_remove:
                    # Get all OTHER origins' ports for reference counting
                    other_origins_ports = set()
                    for oid, other_origin in state_manager.origins_db.items():
                        if oid != origin_id and 'required_ports' in other_origin:
                            other_ports = normalize_port_list(
                                other_origin.get('required_ports', [])
                            )
                            other_origins_ports.update(other_ports)

                    # Check each port for removal
                    for port in ports_to_remove:
                        if port in other_origins_ports:
                            logger.info(
                                f"Keeping port {port} in Security Group "
                                f"(used by other origins)"
                            )
                            ports_kept.append(port)
                        else:
                            ports_actually_removed.append(port)

                    # Remove unused ports from security group (TCP+UDP)
                    if ports_actually_removed:
                        logger.info(
                            f"Removing unused ports from AWS Security Group (TCP+UDP): "
                            f"{ports_actually_removed}"
                        )
                        aws_operations.remove_unused_ports_from_security_group(
                            origin_id=origin_id,
                            ports=ports_actually_removed,
                            origins_db=state_manager.origins_db,
                            region=region
                        )

            elif provider == 'linode':
                # Future: Linode firewall management
                logger.warning(
                    f"Port updates for provider '{provider}' not yet implemented"
                )
                return jsonify({
                    'status': 'error',
                    'message': f"Port updates not supported for provider: {provider}"
                }), 501

            elif provider == 'gcp':
                # Future: GCP firewall management
                logger.warning(
                    f"Port updates for provider '{provider}' not yet implemented"
                )
                return jsonify({
                    'status': 'error',
                    'message': f"Port updates not supported for provider: {provider}"
                }), 501

            else:
                return jsonify({
                    'status': 'error',
                    'message': f"Unknown provider: {provider}"
                }), 400

            # Step 3: Update database (store as simple array)
            final_ports_list = sorted(list(new_ports_set))
            cur.execute("""
                UPDATE origins
                SET required_ports = %s::jsonb
                WHERE origin_id = %s
            """, (
                json.dumps(final_ports_list),
                origin_id
            ))
            conn.commit()

            # Step 4: Update in-memory state
            state_manager.origins_db[origin_id]['required_ports'] = final_ports_list

            logger.info(
                f"Port update complete for {origin_id}: "
                f"added={sorted(list(ports_to_add))}, "
                f"removed={sorted(ports_actually_removed)}, "
                f"kept={sorted(ports_kept)}, "
                f"final={final_ports_list}"
            )

            return jsonify({
                'status': 'success',
                'origin_id': origin_id,
                'provider': provider,
                'ports_added': sorted(list(ports_to_add)),
                'ports_removed': sorted(ports_actually_removed),
                'ports_kept': sorted(ports_kept),
                'current_ports': final_ports_list
            }), 200

        finally:
            cur.close()

    except Exception as e:
        logger.error(f"Failed to update ports for origin {origin_id}: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.get('/<origin_id>/attackers')
def get_origin_attackers(origin_id: str):
    """
    Get list of IPs attacking a specific origin
    """
    from miner_control_plane.services.state_manager import state_manager
    from shared.database import get_db_connection
    import logging
    logger = logging.getLogger(__name__)

    try:
        if origin_id not in state_manager.origins_db:
            return jsonify({'status': 'error', 'message': 'Origin not found'}), 404

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        # Get recent attacking IPs for this origin (last 10 minutes)
        cur.execute("""
            WITH flattened AS (
                SELECT ip_address, attack_score, unnest(attack_types) as attack_type,
                       confidence, timestamp
                FROM ip_attack_signatures
                WHERE origin_id = %s AND timestamp > NOW() - INTERVAL '10 minutes'
            )
            SELECT
                ip_address,
                MAX(attack_score) as max_score,
                array_agg(DISTINCT attack_type) as attack_types,
                AVG(confidence) as avg_confidence,
                COUNT(*) as occurrence_count,
                MAX(timestamp) as last_seen
            FROM flattened
            GROUP BY ip_address
            ORDER BY MAX(attack_score) DESC, MAX(timestamp) DESC
            LIMIT 100
        """, (origin_id,))

        attackers = []
        for row in cur.fetchall():
            attackers.append({
                'ip_address': str(row[0]),
                'attack_score': row[1],
                'attack_types': row[2] or [],
                'confidence': float(row[3]) if row[3] else 0.0,
                'occurrence_count': row[4],
                'last_seen': row[5].isoformat() if row[5] else None
            })

        cur.close()

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'attacker_count': len(attackers),
            'attackers': attackers
        })

    except Exception as e:
        logger.error(f"Failed to get attackers for origin {origin_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
