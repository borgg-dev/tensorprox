"""Shared helpers for retrieving scrubber metadata."""
import logging
from typing import List, Dict

from shared.utils.ssh import get_ssh_user_for_provider
from miner_control_plane.services.state_manager import state_manager

logger = logging.getLogger(__name__)


def get_scrubber_nodes() -> List[Dict[str, str]]:
    """
    Return scrubber connection metadata (node_id, host_ip, provider, ssh_user, eni_id).

    Uses the in-memory state_manager cache. If empty, returns empty list.
    state_manager syncs from database every 30 seconds automatically.
    """
    edge_nodes = state_manager.nodes_db

    nodes = []
    for name, node in edge_nodes.items():
        host_ip = node.get('public_ip')
        if not host_ip:
            continue
        provider = node.get('provider', 'aws')
        nodes.append({
            'node_id': node.get('instance_id') or name,
            'host_ip': host_ip,
            'provider': provider,
            'ssh_user': get_ssh_user_for_provider(provider),
            'eni_id': node.get('eni_id')
        })

    return nodes


def get_nodes_for_origin(origin_id: str) -> List[Dict[str, str]]:
    """
    Return scrubber nodes assigned to a specific origin's shard.

    Multi-region aware - returns nodes from the origin's assigned shard only.
    """
    try:
        # Get origin's shard from state manager
        shard_id = state_manager.get_shard_for_origin(origin_id)
        if not shard_id:
            logger.warning(f"No shard found for origin {origin_id}")
            return []

        # Get nodes for that shard
        nodes = state_manager.get_nodes_for_shard(shard_id)
        if not nodes:
            logger.warning(f"No nodes found for shard {shard_id}")
            return []

        # Format as connection metadata
        # get_nodes_for_shard returns List[dict], not Dict
        result = []
        for node_data in nodes:
            host_ip = node_data.get('public_ip')
            if not host_ip:
                continue
            provider = node_data.get('provider', 'aws')
            node_id = node_data.get('instance_id') or node_data.get('node_id')
            result.append({
                'node_id': node_id,
                'host_ip': host_ip,
                'provider': provider,
                'ssh_user': get_ssh_user_for_provider(provider),
                'eni_id': node_data.get('eni_id')
            })

        return result
    except Exception as exc:
        logger.error(f"Failed to get nodes for origin {origin_id}: {exc}")
        return []
