"""Capacity Management API - View and manage bandwidth QoS configuration

Endpoints:
- GET  /api/v1/capacity/scrubbers - List scrubber capacities
- GET  /api/v1/capacity/origins - List per-origin quotas and usage
- GET  /api/v1/capacity/config - Get global QoS config
- PUT  /api/v1/capacity/config - Update global QoS config
- PUT  /api/v1/capacity/origins/{origin_id}/quota - Override origin quota
- POST /api/v1/capacity/recalculate - Trigger quota recalculation
"""
import logging
from flask import Blueprint, request, jsonify
from miner_control_plane.api.auth import require_tpm_auth
from miner_control_plane.services.state_manager import state_manager
from miner_control_plane.services.bandwidth_quota_service import (
    recalculate_quotas,
    update_scrubber_capacity,
    push_quotas_to_scrubber,
)
from miner_control_plane.services.scrubber_utils import get_scrubber_nodes

logger = logging.getLogger(__name__)

capacity_bp = Blueprint('capacity', __name__, url_prefix='/api/v1/capacity')


@capacity_bp.route('/scrubbers', methods=['GET'])
def get_scrubber_capacities():
    """
    List all scrubbers with their bandwidth capacity and utilization.

    Returns:
        {
            "scrubbers": [
                {
                    "node_id": "i-xxx",
                    "shard_id": "eu-central-1",
                    "bandwidth_gbps": 5.0,
                    "usable_gbps": 4.0,
                    "origin_count": 4
                }
            ]
        }
    """
    scrubbers = []

    for node_id, node_data in state_manager.nodes_db.items():
        # Use get_node_bandwidth which checks nodes_db first, then bandwidth_capacity
        capacity = state_manager.get_node_bandwidth(node_id) or {}
        bandwidth_bps = capacity.get('bandwidth_bps', 1_000_000_000)
        usable_bps = int(bandwidth_bps * 0.8)  # 20% buffer

        # Count origins for this node's shard
        shard_id = node_data.get('shard_id')
        origins = state_manager.get_origins_for_shard(shard_id) if shard_id else []
        active_origins = [o for o in origins if o.get('state') == 'IN_SERVICE']

        # Calculate current utilization from usage data
        total_usage_bps = 0
        for origin in active_origins:
            origin_ip = origin.get('origin_ip')
            usage = state_manager.bandwidth_usage.get(origin_ip, {})
            # Estimate current BPS from quota (simplified placeholder)
            total_usage_bps += usage.get('quota_bps', 0) * 0.5  # Placeholder

        scrubbers.append({
            'node_id': node_id,
            'shard_id': shard_id,
            'region': node_data.get('region'),
            'instance_type': capacity.get('instance_type', node_data.get('instance_type', 'unknown')),
            'bandwidth_gbps': round(bandwidth_bps / 1e9, 2),
            'usable_gbps': round(usable_bps / 1e9, 2),
            'origin_count': len(active_origins),
            'origins': [o.get('origin_id') for o in active_origins],
            'role': node_data.get('role', 'unknown'),
        })

    return jsonify({'scrubbers': scrubbers})


@capacity_bp.route('/origins', methods=['GET'])
def get_origin_quotas():
    """
    List all origins with their bandwidth quotas and current usage.

    Returns:
        {
            "origins": [
                {
                    "origin_id": "O1",
                    "origin_ip": "10.0.1.100",
                    "quota_mbps": 200,
                    "usage_mbps": 45.5,
                    "utilization_percent": 22.8,
                    "bytes_exceeded": 0,
                    "is_over_quota": false
                }
            ]
        }
    """
    origins = []

    for origin_id, origin_data in state_manager.origins_db.items():
        origin_ip = origin_data.get('origin_ip')
        quota = state_manager.bandwidth_quotas.get(origin_ip, {})
        usage = state_manager.bandwidth_usage.get(origin_ip, {})

        quota_bps = quota.get('quota_bps', 0)
        bytes_exceeded = usage.get('bytes_exceeded', 0)

        origins.append({
            'origin_id': origin_id,
            'origin_ip': origin_ip,
            'shard_id': origin_data.get('shard_id'),
            'state': origin_data.get('state'),
            'quota_bps': quota_bps,
            'quota_mbps': round(quota_bps / 1e6, 1),
            'burst_bytes': quota.get('burst_bytes', 0),
            'bytes_exceeded': bytes_exceeded,
            'packets_dropped': usage.get('packets_dropped', 0),
            'is_over_quota': bytes_exceeded > 0,
        })

    return jsonify({'origins': origins})


@capacity_bp.route('/config', methods=['GET'])
def get_qos_config():
    """
    Get global QoS configuration.

    Returns:
        {
            "buffer_percent": 20,
            "enforce_mode": "monitor",
            "default_quota_mbps": null,
            "quota_mode": "simple",
            "simple_quota_mbps": 100
        }
    """
    from shared.config import get_settings
    settings = get_settings()

    return jsonify({
        'buffer_percent': getattr(settings, 'qos_buffer_percent', 20),
        'enforce_mode': getattr(settings, 'qos_enforce_mode', 'monitor'),
        'default_quota_mbps': getattr(settings, 'qos_default_quota_mbps', None),
        'quota_mode': getattr(settings, 'quota_mode', 'simple'),
        'simple_quota_mbps': getattr(settings, 'simple_quota_mbps', 100),
    })


@capacity_bp.route('/config', methods=['PUT'])
@require_tpm_auth
def update_qos_config():
    """
    Update global QoS configuration.

    Request body:
        {
            "enforce_mode": "enforce"  // "monitor" or "enforce"
        }

    Note: Changes are pushed to all scrubbers immediately.
    """
    data = request.get_json() or {}
    enforce_mode_str = data.get('enforce_mode', 'monitor')
    enforce_mode = 1 if enforce_mode_str == 'enforce' else 0

    # Push to all scrubbers
    errors = []
    for node_id, node_data in state_manager.nodes_db.items():
        host = node_data.get('public_ip') or node_data.get('current_public_ip')
        if not host:
            continue

        shard_id = node_data.get('shard_id')
        origins = state_manager.get_origins_for_shard(shard_id) if shard_id else []
        origin_count = len([o for o in origins if o.get('state') == 'IN_SERVICE'])

        if not update_scrubber_capacity(node_id, host, origin_count,
                                        enforce_mode=enforce_mode,
                                        provider=node_data.get('provider', 'aws')):
            errors.append(node_id)

    if errors:
        return jsonify({
            'status': 'partial',
            'message': f'Failed to update nodes: {errors}',
            'enforce_mode': enforce_mode_str
        }), 207

    return jsonify({
        'status': 'ok',
        'enforce_mode': enforce_mode_str,
        'message': f'Updated {len(state_manager.nodes_db)} scrubbers'
    })


@capacity_bp.route('/origins/<origin_id>/quota', methods=['PUT'])
@require_tpm_auth
def override_origin_quota(origin_id: str):
    """
    Override quota for a specific origin (premium tier, etc.)

    Request body:
        {
            "quota_mbps": 500
        }
    """
    origin = state_manager.origins_db.get(origin_id)
    if not origin:
        return jsonify({'error': 'Origin not found'}), 404

    data = request.get_json() or {}
    quota_mbps = data.get('quota_mbps')

    if quota_mbps is None:
        return jsonify({'error': 'quota_mbps required'}), 400

    if quota_mbps <= 0:
        return jsonify({'error': 'quota_mbps must be positive'}), 400

    origin_ip = origin.get('origin_ip')
    quota_bps = int(quota_mbps * 1e6)
    burst_bytes = quota_bps * 10

    quota = {
        'quota_bps': quota_bps,
        'burst_bytes': burst_bytes,
    }

    # Update cache
    state_manager.update_bandwidth_quota(origin_ip, quota)

    # Push to scrubbers
    shard_id = origin.get('shard_id')
    nodes = get_scrubber_nodes(shard_id=shard_id)

    errors = []
    for node_id, node_data in nodes.items():
        host = node_data.get('public_ip') or node_data.get('current_public_ip')
        if not host:
            continue

        if not push_quotas_to_scrubber(node_id, host, {origin_ip: quota},
                                       provider=node_data.get('provider', 'aws')):
            errors.append(node_id)

    if errors:
        return jsonify({
            'status': 'partial',
            'message': f'Failed to update nodes: {errors}'
        }), 207

    return jsonify({
        'status': 'ok',
        'origin_id': origin_id,
        'quota_mbps': quota_mbps
    })


@capacity_bp.route('/recalculate', methods=['POST'])
@require_tpm_auth
def trigger_recalculation():
    """
    Trigger quota recalculation for all shards or a specific shard.

    Request body (optional):
        {
            "shard_id": "eu-central-1"  // If omitted, recalculates all
        }
    """
    data = request.get_json() or {}
    shard_id = data.get('shard_id')

    if shard_id:
        # Recalculate specific shard
        success = recalculate_quotas(shard_id)
        return jsonify({
            'status': 'ok' if success else 'error',
            'shard_id': shard_id
        })

    # Recalculate all shards
    results = {}
    for shard_id in state_manager.shards_db.keys():
        results[shard_id] = recalculate_quotas(shard_id)

    all_success = all(results.values())
    return jsonify({
        'status': 'ok' if all_success else 'partial',
        'results': results
    })
