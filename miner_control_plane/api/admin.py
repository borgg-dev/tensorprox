"""Admin API Blueprint - Deploy/Cleanup/Failover Operations

Multi-region shard management endpoints for scrubber infrastructure.
Each shard consists of an active/standby scrubber pair in a specific AWS region.

FAILOVER EXECUTION FLOW (failover_shard function, ~lines 951-1275)
================================================================================
When triggered by health_monitor.py, executes these steps:

    STEP 1: Move EIPs to Standby (~2-3s)
        - Parallel execution via ThreadPoolExecutor (10 workers)
        - For each origin: disassociate EIP → associate to standby ENI
        - AWS API calls: DescribeAddresses, DisassociateAddress, AssociateAddress

    STEP 2: Start WireGuard Services (~2-3s)
        - Parallel SSH to standby: systemctl start wg-quick@wg{origin}
        - Tunnels are pre-configured during preconfigure_standby_origins()

    STEP 2.5: Sync expected_tunnels.json (~1s)
        - Ensures ecp-agent on new active knows which tunnels to monitor

    STEP 3: Update Shard State (<1s)
        - Swap active_node ↔ standby_node in state_manager
        - Persist role changes to database (nodes table)
        - Record failover timestamp

    STEP 3.5: Push Bandwidth Quotas (BACKGROUND)
        - Non-blocking: moved to background thread to reduce failover time
        - Recalculates and pushes per-origin bandwidth limits

    STEP 4: Swap Private IPs (<1s)
        - Swap private_ip ↔ private_ip_standby in origins table
        - Update identities.node_id to point to new active
        - Prepares for next failover

    BACKGROUND: destroy_and_spawn (async thread)
        - Step 1: Terminate failed node (non-fatal if already terminated)
        - Step 2: Clean up database records
        - Step 3: Deploy new standby scrubber
        - Step 4: Pre-configure new standby with origins

    Total failover time: ~6-7 seconds (under 10s SLO)

KEY FUNCTIONS
================================================================================
Deployment:
    deploy_single_scrubber(shard_id, region, node_name, role)
        Deploy one scrubber instance (active or standby)
        Returns: dict with node_id, public_ip, private_ip, eni_id

    preconfigure_standby_origins(shard_id, node_name, public_ip, eni_id)
        Pre-configure standby with all shard origins for fast failover:
        - Assign secondary private IPs to ENI
        - Create WireGuard interfaces (DOWN state)
        - Configure BPF dataplane maps
        - Add routes

Failover:
    failover_shard(shard_id)
        Execute failover from active to standby (POST endpoint)
        Called by health_monitor when scrubber confirmed dead

    destroy_and_spawn()
        Background thread: terminate failed node + deploy replacement standby
        Each step is independent - termination failure doesn't block deploy

API ENDPOINTS
================================================================================
Shard Management:
    POST   /admin/shards                    Create new shard (deploys active+standby)
    GET    /admin/shards                    List all shards with capacity info
    GET    /admin/shards/<shard_id>         Get shard details
    DELETE /admin/shards/<shard_id>         Delete shard (terminates instances)

Failover:
    POST   /admin/shards/<shard_id>/failover   Trigger manual/automatic failover

Cleanup:
    POST   /admin/cleanup                   Full cleanup (terminate all, truncate DB)
    POST   /admin/cleanup-orphans           Clean orphaned AWS resources only

Jobs:
    GET    /admin/jobs/<job_id>             Check async deployment job status

Mitigation:
    GET    /admin/mitigation/testing-mode   Get testing mode status
    POST   /admin/mitigation/testing-mode   Set testing mode (disables auto-mitigation)

Nodes:
    GET    /admin/nodes                     Get all nodes with health status

TIMING PARAMETERS
================================================================================
EIP_WORKERS = 10              Parallel workers for EIP operations
WG_WORKERS = 5                Parallel workers for WireGuard startup
SSH_TIMEOUT = 30              SSH command timeout (seconds)
FAILOVER_TARGET = 10s         Target failover time SLO

RELATED FILES
================================================================================
- health_monitor.py: Detection and triggering (calls POST /failover)
- state_manager.py: State persistence and caching
- bandwidth_quota_service.py: Quota calculations (called in background)
- expected_tunnels.py: Tunnel sync to new active
"""
import os
import time
import json
import threading
from pathlib import Path
from typing import Optional, Dict, List, Any
from flask import Blueprint, request, jsonify
from shared.config import get_settings
from shared.database import get_db_connection
from shared.node import Node
from shared.providers import get_provider
from shared.utils.ssh import ssh_exec
from shared.utils.logging import get_logger, OperationContext
from shared.utils.database_helpers import db_save_node, db_delete_node
from miner_control_plane.api.auth import require_tpm_auth
from miner_control_plane.services.state_manager import state_manager
from miner_control_plane.services.origin_service import origin_service
from miner_control_plane.services.scrubber_operations import (
    configure_scrubber_node,
    configure_wireguard_dataplane
)
from miner_control_plane.services.expected_tunnels import sync_expected_tunnels_to_node
from miner_control_plane.services import automated_mitigation
from miner_control_plane.utils.aws import aws_operations
from miner_control_plane.services.rate_config_service import (
    calculate_origin_rate_config,
    push_rate_configs_to_scrubber,
)

# Notification stubs (deploy_notifier module not implemented)
# These signatures match the actual call sites in create_shard()
def notify_deploy_started(shard_id: str, region: str) -> None:
    """Notification: Deployment started (stub).

    Args:
        shard_id: The shard being deployed
        region: AWS region for deployment
    """
    pass


def notify_deploy_progress(
    shard_id: str,
    step: str,
    progress: int,
    message: str | None = None,
    node_name: str | None = None
) -> None:
    """Notification: Deployment progress (stub).

    Args:
        shard_id: The shard being deployed
        step: Current step name (e.g., "Deploying active node")
        progress: Progress percentage (0-100)
        message: Optional detailed message
        node_name: Optional node being worked on
    """
    pass


def notify_deploy_error(shard_id: str, error: str) -> None:
    """Notification: Deployment error (stub).

    Args:
        shard_id: The shard that failed
        error: Error message
    """
    pass


def notify_deploy_complete(
    shard_id: str | None = None,
    deployment_id: str | None = None,
    active_node: str | None = None,
    standby_node: str | None = None,
    active_ip: str | None = None,
    standby_ip: str | None = None,
    elapsed_seconds: float | None = None
) -> None:
    """Notification: Deployment complete (stub).

    Args:
        shard_id: The shard that was deployed
        deployment_id: Optional deployment tracking ID
        active_node: Name of active node (e.g., 'eu-central-1-a')
        standby_node: Name of standby node (e.g., 'eu-central-1-b')
        active_ip: Public IP of active node
        standby_ip: Public IP of standby node
        elapsed_seconds: Total deployment time
    """
    pass

bp = Blueprint('admin', __name__, url_prefix='/api/v1')
logger = get_logger(__name__)

# Warm scrubber pool state directory
WARM_POOL_STATE_DIR = Path.home() / ".tensorprox" / "scrubbers"


def get_warm_scrubbers(region: str) -> List[Dict[str, Any]]:
    """
    Get available warm scrubbers from the scrubber_manager state file.

    Warm scrubbers are pre-deployed instances that haven't been assigned
    to a shard yet. Using them avoids deploying new instances.

    Args:
        region: Target region to find warm scrubbers for

    Returns:
        List of warm scrubber dicts with instance details
    """
    warm_scrubbers = []

    try:
        # Find all state files in the warm pool directory
        if not WARM_POOL_STATE_DIR.exists():
            return []

        for state_file in WARM_POOL_STATE_DIR.glob("*.json"):
            try:
                with open(state_file, "r") as f:
                    state = json.load(f)

                scrubbers = state.get("scrubbers", {})
                active_id = state.get("active_node_id")
                standby_id = state.get("standby_node_id")

                for node_id, scrubber in scrubbers.items():
                    # Check if scrubber is in the target region
                    if scrubber.get("region") != region:
                        continue

                    # Check if scrubber is healthy and running
                    if scrubber.get("status") != "running":
                        continue
                    if scrubber.get("health_status") != "healthy":
                        continue

                    # Include role info for matching active/standby
                    scrubber_info = {
                        "node_id": node_id,
                        "instance_id": scrubber.get("instance_id"),
                        "public_ip": scrubber.get("public_ip"),
                        "private_ip": scrubber.get("private_ip"),
                        "region": scrubber.get("region"),
                        "instance_type": scrubber.get("instance_type"),
                        "role": scrubber.get("role", "unknown"),
                        "state_file": str(state_file),
                        "is_active": node_id == active_id,
                        "is_standby": node_id == standby_id,
                    }
                    warm_scrubbers.append(scrubber_info)

            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to parse warm pool state file {state_file}: {e}")
                continue

    except Exception as e:
        logger.error(f"Error reading warm scrubber pool: {e}")

    return warm_scrubbers


def repurpose_warm_scrubber(
    warm_scrubber: Dict[str, Any],
    shard_id: str,
    region: str,
    node_name: str,
    role: str
) -> Dict[str, Any]:
    """
    Repurpose a warm scrubber for use in a shard.

    This registers an existing warm scrubber instance in the database
    and state_manager without deploying a new instance.

    Args:
        warm_scrubber: Dict from get_warm_scrubbers()
        shard_id: Shard this node will belong to
        region: AWS region
        node_name: Node name (e.g., 'us-east-1-a')
        role: 'active' or 'standby'

    Returns:
        Same format as deploy_single_scrubber()
    """
    settings = get_settings()
    start_time = time.time()

    instance_id = warm_scrubber["instance_id"]
    public_ip = warm_scrubber["public_ip"]
    private_ip = warm_scrubber["private_ip"]
    instance_type = warm_scrubber.get("instance_type", settings.scrubber_instance_type)

    logger.info(f"Repurposing warm scrubber {instance_id} ({public_ip}) for shard {shard_id} as {role}")

    # Update AWS tags for the new shard assignment
    logger.info(f"  Updating AWS tags...")
    try:
        provider = get_provider(settings.scrubber_provider)
        provider.create_tags(
            [instance_id],
            {
                'Name': node_name,
                'ShardId': shard_id,
                'Role': role,
                'Region': region,
            },
            region=region
        )
    except Exception as e:
        logger.warning(f"  Failed to update tags (non-fatal): {e}")

    # Query instance type specs for bandwidth
    logger.info(f"  Querying instance type specs...")
    bandwidth_bps = 0
    try:
        provider = get_provider(settings.scrubber_provider)
        instance_specs = provider.describe_instance_types([instance_type], region=region)
        if instance_specs and len(instance_specs) > 0:
            bandwidth_bps = instance_specs[0].get('baseline_bandwidth_bps', 0)
    except Exception as e:
        logger.warning(f"  Failed to query instance specs: {e}")

    # Get ENI ID
    logger.info(f"  Retrieving ENI ID...")
    node = Node(node_type="scrubber", region=region)
    eni_id = node.get_primary_eni_id(instance_id)
    if not eni_id:
        raise Exception(f"Failed to retrieve ENI ID for {instance_id}")
    logger.info(f"  ENI ID: {eni_id}")

    # Register in database (include miner_id for multi-miner isolation)
    logger.info(f"  Registering in database...")
    db = get_db_connection()
    try:
        db_save_node({
            'node_id': instance_id,
            'shard_id': shard_id,
            'region': region,
            'role': role,
            'instance_name': node_name,
            'hostname': node_name,
            'provider': settings.scrubber_provider,
            'status': 'active',
            'public_ip': public_ip,
            'private_ip': private_ip,
            'eni_id': eni_id,
            'instance_type': instance_type,
            'bandwidth_bps': bandwidth_bps
        }, db, miner_id=state_manager.miner_id)
    finally:
        db.close()

    # Add to state_manager.nodes_db
    state_manager.add_node({
        'node_id': instance_id,
        'instance_id': instance_id,
        'shard_id': shard_id,
        'region': region,
        'role': role,
        'instance_name': node_name,
        'public_ip': public_ip,
        'private_ip': private_ip,
        'eni_id': eni_id,
        'provider': settings.scrubber_provider,
        'instance_type': instance_type,
        'bandwidth_bps': bandwidth_bps
    })
    logger.info(f"  Added to state_manager.nodes_db")

    # Sync expected_tunnels.json with correct role
    logger.info(f"  Syncing expected_tunnels.json with role={role}...")
    try:
        sync_result = sync_expected_tunnels_to_node(
            target_host=public_ip,
            origin_ids=[],
            ssh_key_path=settings.ssh_key_path,
            nodes_db=state_manager.nodes_db,
            role=role
        )
        if sync_result:
            logger.info(f"  expected_tunnels.json synced with role={role}")
        else:
            logger.warning(f"  Failed to sync expected_tunnels.json")
    except Exception as e:
        logger.warning(f"  expected_tunnels.json sync failed: {e}")

    # Clear from warm pool state file
    clear_warm_scrubber_from_pool(warm_scrubber)

    elapsed = time.time() - start_time
    logger.info(f"  {node_name} repurposed from warm pool ({elapsed:.1f}s)")

    return {
        'node_id': instance_id,
        'instance_id': instance_id,
        'shard_id': shard_id,
        'region': region,
        'role': role,
        'instance_name': node_name,
        'public_ip': public_ip,
        'private_ip': private_ip,
        'eni_id': eni_id,
        'instance_type': instance_type
    }


def clear_warm_scrubber_from_pool(warm_scrubber: Dict[str, Any]) -> bool:
    """
    Remove a scrubber from the warm pool state file after repurposing.

    Args:
        warm_scrubber: Dict with state_file and node_id

    Returns:
        True if cleared, False otherwise
    """
    try:
        state_file = Path(warm_scrubber.get("state_file", ""))
        node_id = warm_scrubber.get("node_id")

        if not state_file.exists() or not node_id:
            return False

        with open(state_file, "r") as f:
            state = json.load(f)

        # Remove the scrubber from state
        if node_id in state.get("scrubbers", {}):
            del state["scrubbers"][node_id]

        # Clear active/standby references if they match
        if state.get("active_node_id") == node_id:
            state["active_node_id"] = None
        if state.get("standby_node_id") == node_id:
            state["standby_node_id"] = None

        state["saved_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")

        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)

        logger.info(f"Cleared {node_id} from warm pool state file")
        return True

    except Exception as e:
        logger.warning(f"Failed to clear warm scrubber from pool: {e}")
        return False


def deploy_single_scrubber(
    shard_id: str,
    region: str,
    node_name: str,
    role: str = 'standby'
) -> dict:
    """
    Deploy a single scrubber instance to a specific shard/region.

    Multi-region support: Each scrubber belongs to a shard in a region.

    Args:
        shard_id: Shard this node belongs to (e.g., 'eu-central-1')
        region: AWS region to deploy to (e.g., 'eu-central-1')
        node_name: Node name (e.g., 'eu-central-1-a' or 'eu-central-1-b')
        role: 'active' or 'standby'

    Returns:
        {
            'node_id': str,
            'instance_id': str,
            'shard_id': str,
            'region': str,
            'public_ip': str,
            'private_ip': str,
            'eni_id': str,
            'instance_type': str
        }

    Raises:
        Exception: If any step fails
    """
    settings = get_settings()
    start_time = time.time()

    logger.info(f"Deploying scrubber {node_name} for shard {shard_id} in {region}...")

    # Create Node instance for scrubber in the specified region
    node = Node(
        node_type="scrubber",
        region=region,
        instance_type=settings.scrubber_instance_type,
        cloud_provider=settings.scrubber_provider
    )

    # Deploy instance
    logger.info(f"  Creating AWS instance in {region}...")
    result = node.deploy(
        tags={
            'Name': node_name,
            'Role': 'scrubber',
            'ShardId': shard_id,
            'Region': region
        },
        skip_asset_embedding=True  # Assets uploaded via SSH
    )

    # create_instance() already waits for running state and returns public_ip
    instance_id = result.instance_id
    public_ip = result.public_ip
    logger.info(f"  Instance created: {instance_id} (IP: {public_ip})")

    # Query instance type specs to get baseline bandwidth
    logger.info(f"  Querying instance type specs for {settings.scrubber_instance_type}...")
    bandwidth_bps = 0
    try:
        provider = get_provider(settings.scrubber_provider)
        instance_specs = provider.describe_instance_types(
            [settings.scrubber_instance_type], region=region
        )
        if instance_specs and len(instance_specs) > 0:
            bandwidth_bps = instance_specs[0].get('baseline_bandwidth_bps', 0)
            baseline_gbps = instance_specs[0].get('baseline_bandwidth_gbps', 0)
            logger.info(f"  Bandwidth: {baseline_gbps} Gbps ({bandwidth_bps} bps)")
        else:
            logger.warning(f"  No specs returned for {settings.scrubber_instance_type}")
    except Exception as e:
        logger.warning(f"  Failed to query instance specs: {e}")

    # Wait for SSH to be ready
    logger.info(f"  Waiting for SSH service...")
    node.wait_for_ssh(host=public_ip, max_attempts=30, interval=5)
    logger.info(f"  SSH ready")

    # Retrieve ENI ID for database registration
    logger.info(f"  Retrieving ENI ID...")
    eni_id = node.get_primary_eni_id(instance_id)
    if not eni_id:
        raise Exception(f"Failed to retrieve ENI ID for {instance_id}")
    logger.info(f"  ENI ID: {eni_id}")

    # Register in database BEFORE configuration (with shard_id and region)
    # Include miner_id for multi-miner isolation
    logger.info(f"  Registering in database...")
    db = get_db_connection()
    try:
        db_save_node({
            'node_id': instance_id,
            'shard_id': shard_id,
            'region': region,
            'role': role,
            'instance_name': node_name,
            'hostname': node_name,
            'provider': settings.scrubber_provider,
            'status': 'active',
            'public_ip': public_ip,
            'private_ip': result.private_ip,
            'eni_id': eni_id,
            'instance_type': settings.scrubber_instance_type,
            'bandwidth_bps': bandwidth_bps
        }, db, miner_id=state_manager.miner_id)
    finally:
        db.close()

    # Add to state_manager.nodes_db (keyed by node_id)
    state_manager.add_node({
        'node_id': instance_id,
        'instance_id': instance_id,
        'shard_id': shard_id,
        'region': region,
        'role': role,
        'instance_name': node_name,
        'public_ip': public_ip,
        'private_ip': result.private_ip,
        'eni_id': eni_id,
        'provider': settings.scrubber_provider,
        'instance_type': settings.scrubber_instance_type,
        'bandwidth_bps': bandwidth_bps
    })
    logger.info(f"  Added to state_manager.nodes_db")

    # Create and upload asset bundle, then bootstrap
    logger.info(f"  Creating asset bundle...")
    bundle_path = node.create_asset_bundle()
    if not bundle_path:
        raise Exception(f"Failed to create asset bundle for {node_name}")

    config_failed = False
    try:
        # Configure scrubber using scrubber_operations
        logger.info(f"  Configuring scrubber (upload, bootstrap, verify)...")
        success = configure_scrubber_node(
            node_name=node_name,
            host=public_ip,
            bundle_path=bundle_path,
            ssh_key_path=settings.ssh_key_path,
            instance_id=instance_id
        )

        if not success:
            config_failed = True
            raise Exception(f"Scrubber configuration failed for {node_name}")

        # Sync expected_tunnels.json with correct role so ecp-agent knows its role from the start
        logger.info(f"  Syncing expected_tunnels.json with role={role}...")
        try:
            sync_result = sync_expected_tunnels_to_node(
                target_host=public_ip,
                origin_ids=[],  # Empty - no origins yet
                ssh_key_path=settings.ssh_key_path,
                nodes_db=state_manager.nodes_db,
                role=role  # 'active' or 'standby' from function param
            )
            if sync_result:
                logger.info(f"  expected_tunnels.json synced with role={role}")
            else:
                logger.warning(f"  Failed to sync expected_tunnels.json to {node_name}")
        except Exception as e:
            logger.warning(f"  expected_tunnels.json sync failed: {e}")

    except Exception as e:
        # Rollback: terminate instance and clean up database on configuration failure
        if config_failed:
            logger.error(f"  Configuration failed, rolling back instance {instance_id}...")
            try:
                # Terminate the EC2 instance
                node.destroy(instance_id)
                logger.info(f"  Terminated orphaned instance {instance_id}")
            except Exception as destroy_err:
                logger.error(f"  Failed to terminate instance {instance_id}: {destroy_err}")

            try:
                # Remove from database
                rollback_db = get_db_connection()
                try:
                    db_delete_node(instance_id, rollback_db)
                    logger.info(f"  Removed {instance_id} from database")
                finally:
                    rollback_db.close()
            except Exception as db_err:
                logger.error(f"  Failed to remove {instance_id} from database: {db_err}")

            try:
                # Remove from state_manager
                state_manager.remove_node(instance_id)
                logger.info(f"  Removed {instance_id} from state_manager")
            except Exception as state_err:
                logger.error(f"  Failed to remove {instance_id} from state_manager: {state_err}")

        raise

    finally:
        # Cleanup local bundle
        if bundle_path and os.path.exists(bundle_path):
            os.unlink(bundle_path)

    elapsed = time.time() - start_time
    logger.info(f"  {node_name} deployment complete ({elapsed:.1f}s)")

    return {
        'node_id': instance_id,
        'instance_id': instance_id,
        'shard_id': shard_id,
        'region': region,
        'role': role,
        'instance_name': node_name,
        'public_ip': public_ip,
        'private_ip': result.private_ip,
        'eni_id': eni_id,
        'instance_type': node.instance_type
    }


def preconfigure_standby_origins(
    shard_id: str,
    node_name: str,
    public_ip: str,
    eni_id: str
) -> int:
    """
    Pre-configure a standby scrubber with origins for this shard only.

    This makes the standby 95% ready - only needs WireGuard started during failover.

    Args:
        shard_id: Shard ID (only configure origins for this shard)
        node_name: Name of the standby node
        public_ip: Public IP of the standby scrubber
        eni_id: ENI ID for private IP assignment

    Returns:
        Number of origins successfully configured
    """
    settings = get_settings()
    from miner_control_plane.utils.aws import aws_operations
    from miner_control_plane.services.origin_service import origin_service
    import socket

    # Get region from shard for AWS operations
    shard = state_manager.get_shard(shard_id)
    region = shard.get('region') if shard else None

    configured_count = 0

    # Get only origins for this shard
    shard_origins = state_manager.get_origins_for_shard(shard_id)
    logger.info(f"Pre-configuring {node_name} with {len(shard_origins)} origins for shard {shard_id}...")

    for origin in shard_origins:
        origin_id = origin['origin_id']
        try:
            logger.info(f"  Configuring origin {origin_id}...")

            # Use private_ip_standby (after swap in failover, this is what standby should have)
            standby_private_ip = origin['private_ip_standby']

            # Assign private IP to ENI
            aws_operations.assign_private_ip_to_eni(eni_id, standby_private_ip, region=region)
            ssh_exec(
                public_ip,
                f"sudo ip addr add {standby_private_ip}/24 dev ens5",
                settings.ssh_key_path,
                nodes_db=state_manager.nodes_db
            )
            logger.info(f"    Private IP {standby_private_ip} assigned")

            # Build WireGuard config
            wg_subnet_base = (origin['origin_num'] - 1) * 4
            edge_ip = f"169.254.100.{wg_subnet_base + 1}"
            hub_ip = f"169.254.100.{wg_subnet_base + 2}"

            wg_config = f"""[Interface]
PrivateKey = {origin['edge_priv_key']}
Address = {edge_ip}/30
ListenPort = {origin['wg_port']}
Table = off

[Peer]
PublicKey = {origin['hub_pub_key']}
Endpoint = {origin['exit_hub_ip']}:{origin['wg_port']}
AllowedIPs = {hub_ip}/32,{origin['origin_ip']}/32
PersistentKeepalive = 15
"""

            # Upload WireGuard config via SFTP
            if not origin_service._upload_wireguard_config(
                public_ip, origin['wg_interface'], wg_config
            ):
                logger.warning(f"    Failed to upload WG config for {origin_id}")
                continue

            logger.info(f"    WireGuard config uploaded")

            # Pre-create WireGuard interface (DOWN state)
            ssh_exec(
                public_ip,
                f"sudo ip link add {origin['wg_interface']} type wireguard 2>/dev/null || true",
                settings.ssh_key_path,
                nodes_db=state_manager.nodes_db
            )
            logger.info(f"    Interface {origin['wg_interface']} created (DOWN)")

            # Configure dataplane (BPF maps, TC programs)
            wg_ok = configure_wireguard_dataplane(
                node_name, public_ip, origin['wg_interface'],
                standby_private_ip, origin['origin_ip'],
                settings.ssh_key_path, state_manager.nodes_db,
                origin_id=origin_id
            )

            if wg_ok:
                logger.info(f"    Dataplane configured (BPF + TC)")
            else:
                logger.warning(f"    Dataplane config failed for {origin_id}")

            # Pre-add routes
            ssh_exec(
                public_ip,
                f"sudo ip route add {origin['origin_ip']}/32 dev {origin['wg_interface']} 2>/dev/null || true",
                settings.ssh_key_path,
                nodes_db=state_manager.nodes_db
            )
            logger.info(f"    Route added")

            # Initialize Layer 3/4 maps
            origin_ip_bytes = socket.inet_aton(origin['origin_ip'])
            origin_ip_hex = ' '.join([f'{b:02x}' for b in origin_ip_bytes])

            # NOTE: origin_challenge_map is an XDP map (defined in xdp_wan.c)
            ssh_exec(
                public_ip,
                f"sudo bpftool map update pinned /sys/fs/bpf/xdp/globals/origin_challenge_map key hex {origin_ip_hex} value hex 00 00 00 00",
                settings.ssh_key_path,
                nodes_db=state_manager.nodes_db
            )
            ssh_exec(
                public_ip,
                f"sudo bpftool map update pinned /sys/fs/bpf/tc/globals/syncookie_mode_map key hex {origin_ip_hex} value hex 00 00 00 00",
                settings.ssh_key_path,
                nodes_db=state_manager.nodes_db
            )
            logger.info(f"    Layer 3/4 maps initialized")

            logger.info(f"  Origin {origin_id} pre-configured")
            configured_count += 1

        except Exception as origin_err:
            logger.error(f"  Failed to configure origin {origin_id}: {origin_err}")

    # Initialize QoS bandwidth maps (batch operation for all origins)
    try:
        from miner_control_plane.services.bandwidth_quota_service import push_quotas_to_specific_node

        # Get current quotas for origins in this shard
        shard_quotas = {}
        for origin in shard_origins:
            origin_ip = origin.get('origin_ip')
            if origin_ip and origin_ip in state_manager.bandwidth_quotas:
                shard_quotas[origin_ip] = state_manager.bandwidth_quotas[origin_ip]

        if shard_quotas:
            push_quotas_to_specific_node(
                node_id=node_name,
                host=public_ip,
                quotas=shard_quotas,
                provider=settings.scrubber_provider
            )
            logger.info(f"QoS bandwidth maps initialized ({len(shard_quotas)} origins)")
    except Exception as e:
        logger.warning(f"Failed to initialize QoS maps: {e}")

    # === Initialize origin_rate_config_map (CRITICAL for failover) ===
    # This MUST be pre-configured for fast failover
    # Without this, intelligent rate limiting falls back to defaults
    try:
        logger.info(f"Initializing rate configs for {len(shard_origins)} origins on standby")

        # Determine if this is an audit shard (uses stricter rate limits)
        is_audit_shard = shard.get('shard_type', 'audit') == 'audit' if shard else True

        rate_configs = {}
        for origin in shard_origins:
            origin_ip = origin.get('origin_ip')
            if not origin_ip:
                continue

            # Get bandwidth quota from state_manager
            bandwidth_quota = state_manager.bandwidth_quotas.get(origin_ip, {}).get('quota_bps', 0)

            # Calculate rate config (same as origin creation)
            # Audit shards use stricter per-source rate limits (50 PPS vs 10K PPS)
            config = calculate_origin_rate_config(
                origin_ip=origin_ip,
                bandwidth_quota_bps=bandwidth_quota if bandwidth_quota else None,
                challenge_level=0,  # Standby starts at NORMAL
                is_audit=is_audit_shard,  # Audit origins use stricter rate limits
            )
            rate_configs[origin_ip] = config

        # Batch push all configs
        if rate_configs:
            success_count = push_rate_configs_to_scrubber(
                host=public_ip,
                configs=rate_configs,
                ssh_key_path=settings.ssh_key_path,
                nodes_db=state_manager.nodes_db,
            )
            logger.info(f"Pre-configured {success_count}/{len(rate_configs)} rate configs on standby")
    except Exception as e:
        logger.warning(f"Failed to initialize rate configs: {e}")

    # Sync expected_tunnels.json with role='standby' so ecp-agent knows its role from the start
    try:
        shard_origin_ids = [o['origin_id'] for o in shard_origins]
        sync_result = sync_expected_tunnels_to_node(
            target_host=public_ip,
            origin_ids=shard_origin_ids,
            ssh_key_path=settings.ssh_key_path,
            nodes_db=state_manager.nodes_db,
            role='standby'  # This node is a standby, not yet active
        )
        if sync_result:
            logger.info(f"expected_tunnels.json synced to standby ({public_ip}) with role=standby")
        else:
            logger.warning("Failed to sync expected_tunnels.json to standby")
    except Exception as e:
        logger.warning(f"expected_tunnels.json sync to standby failed: {e}")

    return configured_count


def _parse_bool(value):
    """Convert various truthy/falsy inputs into boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {'true', '1', 'yes', 'on'}:
            return True
        if normalized in {'false', '0', 'no', 'off'}:
            return False
    raise ValueError("unable to parse boolean value")


@bp.route('/admin/mitigation/testing-mode', methods=['GET'])
@require_tpm_auth
def get_testing_mode_route():
    """Return current automated mitigation testing flag."""
    return jsonify({
        'enabled': automated_mitigation.is_testing_mode()
    })


@bp.route('/admin/mitigation/testing-mode', methods=['POST'])
@require_tpm_auth
def set_testing_mode_route():
    """
    Toggle automated mitigation testing mode at runtime.
    Body: {"enabled": true|false}
    """
    payload = request.get_json(silent=True) or {}
    if 'enabled' not in payload:
        return jsonify({'error': "'enabled' field required"}), 400

    try:
        enabled = _parse_bool(payload['enabled'])
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    new_state = automated_mitigation.set_testing_mode(enabled)
    logger.info("Mitigation testing mode set to %s", "ENABLED" if new_state else "disabled")

    return jsonify({
        'enabled': new_state,
        'message': f"testing mode {'enabled' if new_state else 'disabled'}"
    })


# =============================================================================
# SHARD CRUD ENDPOINTS (Multi-Region Support)
# =============================================================================

@bp.route('/admin/shards', methods=['POST'])
@require_tpm_auth
def create_shard():
    """
    Deploy a new shard (active + standby scrubber pair) to a region.

    ASYNCHRONOUS OPERATION: This endpoint returns immediately with a job_id.
    Use GET /api/v1/admin/jobs/<job_id> to poll deployment progress.

    Body:
    {
        "shard_id": "eu-central-1",  // Optional, defaults to region name
        "region": "eu-central-1",     // Required: AWS region
        "shard_type": "production"    // Optional: 'audit' or 'production' (default: 'production')
    }

    Shard Types:
    - 'audit': Created by miner on startup for validator scoring (exactly 1 per miner)
    - 'production': Created by TPM on-demand for customer origins

    Returns (if shard already exists):
    200 OK:
    {
        "status": "success",
        "message": "Shard already exists (idempotent)",
        "shard": {
            "shard_id": "eu-central-1",
            "region": "eu-central-1",
            "status": "active",
            "shard_type": "production",
            "nodes": [...]
        }
    }

    Returns (for new deployments):
    202 Accepted:
    {
        "status": "accepted",
        "job_id": "uuid",
        "shard_id": "eu-central-1",
        "region": "eu-central-1",
        "shard_type": "production",
        "message": "Deployment job created"
    }
    """
    from miner_control_plane.services.job_worker import create_job

    with OperationContext(operation="create_shard"):
        try:
            data = request.json or {}
            region = data.get('region')

            if not region:
                return jsonify({'error': 'region is required'}), 400

            # Default shard_id to region name
            shard_id = data.get('shard_id', region)

            # Shard type: 'audit' for validator scoring, 'production' for customer origins
            # TPM creates production shards by default (on-demand for origins)
            shard_type = data.get('shard_type', 'production')
            if shard_type not in ('audit', 'production'):
                return jsonify({'error': "shard_type must be 'audit' or 'production'"}), 400

            # IDEMPOTENT CHECK: If shard already exists with nodes, return success
            if shard_id in state_manager.shards_db:
                existing_shard = state_manager.shards_db[shard_id]
                existing_nodes = state_manager.get_nodes_for_shard(shard_id)

                # Only return success if there are actually nodes deployed
                if existing_nodes:
                    logger.info(f"Shard {shard_id} already exists with {len(existing_nodes)} nodes")
                    return jsonify({
                        'status': 'success',
                        'message': 'Shard already exists (idempotent)',
                        'shard': {
                            'shard_id': shard_id,
                            'region': existing_shard['region'],
                            'status': existing_shard['status'],
                            'shard_type': existing_shard.get('shard_type', 'audit'),
                            'nodes': [
                                {
                                    'node_id': n['node_id'],
                                    'role': n['role'],
                                    'public_ip': n['public_ip']
                                } for n in existing_nodes
                            ]
                        }
                    }), 200

            # NEW DEPLOYMENT: Create shard record first (for FK constraint), then job
            # This may raise ValueError if shard is owned by another miner
            try:
                state_manager.create_shard(shard_id, region, shard_type=shard_type)
            except ValueError as e:
                # Shard ownership conflict - return 409 Conflict
                logger.warning(f"Shard deployment rejected: {e}")
                return jsonify({
                    'status': 'error',
                    'code': 'shard_owned_by_other_miner',
                    'message': str(e),
                    'shard_id': shard_id,
                }), 409

            logger.info(f"Creating deployment job for {shard_type} shard {shard_id} in region {region}")
            job_id = create_job(
                job_type='deploy_shard',
                shard_id=shard_id,
                region=region,
                metadata={'shard_type': shard_type}
            )

            logger.info(f"Deployment job {job_id} created for {shard_type} shard {shard_id}")

            return jsonify({
                'status': 'accepted',
                'job_id': job_id,
                'shard_id': shard_id,
                'region': region,
                'shard_type': shard_type,
                'message': 'Deployment job created'
            }), 202

        except Exception as e:
            logger.error(f"Failed to create shard deployment job: {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/admin/jobs/<job_id>', methods=['GET'])
@require_tpm_auth
def get_job(job_id: str):
    """
    Get deployment job status and details.

    Returns:
    {
        "status": "success",
        "job": {
            "job_id": "uuid",
            "type": "deploy_shard",
            "state": "running",  // pending, running, completed, failed
            "progress": 50,
            "progress_message": "Deploying standby node",
            "shard_id": "eu-central-1",
            "region": "eu-central-1",
            "error": null,  // Error message if state=failed
            "result": {...},  // Result data if state=completed
            "created_at": "2025-11-20T12:00:00Z",
            "updated_at": "2025-11-20T12:02:30Z",
            "completed_at": null  // Timestamp when job completed/failed
        }
    }
    """
    from miner_control_plane.services.job_worker import get_job as get_job_status

    try:
        job = get_job_status(job_id)

        if not job:
            return jsonify({
                'status': 'error',
                'message': f'Job {job_id} not found'
            }), 404

        # Convert datetime fields to ISO format
        job_data = dict(job)
        for field in ['created_at', 'updated_at', 'completed_at']:
            if job_data.get(field):
                job_data[field] = job_data[field].isoformat()

        return jsonify({
            'status': 'success',
            'job': job_data
        })

    except Exception as e:
        logger.error(f"Failed to get job {job_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/admin/shards', methods=['GET'])
@require_tpm_auth
def list_shards():
    """
    List all shards with their nodes, capacity, and deployment status.

    Returns:
    {
        "status": "success",
        "shards": [
            {
                "shard_id": "eu-central-1",
                "region": "eu-central-1",
                "status": "active",
                "active_node": "i-xxx",
                "standby_node": "i-yyy",
                "origins_count": 5,
                "nodes": [
                    {
                        "node_id": "i-xxx",
                        "role": "active",
                        "ready": true
                    },
                    {
                        "node_id": "i-yyy",
                        "role": "standby",
                        "ready": false
                    }
                ],
                "hard_capacity": {
                    "capacity_model": "computed",
                    "origin_slots_total": 5,
                    "origin_slots_used": 2,
                    "origin_slots_available": 3,
                    "limiting_factor": "ENI IPv4 addresses per interface",
                    "details": {...},
                    "eip_quota": 5,
                    "eip_used": 3,
                    "eip_available": 2
                },
                "deploy": {
                    "job_id": "uuid",
                    "state": "running",
                    "progress": 50,
                    "progress_message": "Deploying standby node"
                }
            }
        ],
        "count": 1
    }

    Notes:
        - nodes.ready: true if node exists in health_node with last_seen < 60 seconds ago
        - hard_capacity: Technical/hard limits from NetworkPolicy (TPM may enforce stricter policy caps)
        - deploy: Present only if there's an active deployment job for this shard
    """
    try:
        from miner_control_plane.services.network_policies.registry import get_policy_for_shard
        import psycopg2.extras
        from datetime import datetime, timedelta

        db = get_db_connection()
        shards = []

        for shard_id, shard in state_manager.shards_db.items():
            shard_state = state_manager.get_shard_state(shard_id)
            origins = state_manager.get_origins_for_shard(shard_id)
            shard_nodes = state_manager.get_nodes_for_shard(shard_id)

            # Build nodes array with ready status
            nodes_list = []
            for node in shard_nodes:
                node_id = node.get('node_id')
                role = node.get('role', 'unknown')

                # Check if node is ready (in health_node with last_seen < 60s ago)
                ready = False
                try:
                    cur = db.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                    cur.execute(
                        """
                        SELECT last_seen FROM health_node
                        WHERE node_id = %s
                        """,
                        (node_id,)
                    )
                    health_row = cur.fetchone()
                    cur.close()

                    if health_row and health_row['last_seen']:
                        # Check if last_seen is within 60 seconds
                        time_since_last_seen = datetime.now() - health_row['last_seen']
                        ready = time_since_last_seen < timedelta(seconds=60)
                except Exception as e:
                    logger.warning(f"Failed to check ready status for node {node_id}: {e}")
                    ready = False

                nodes_list.append({
                    'node_id': node_id,
                    'role': role,
                    'ready': ready
                })

            # Get hard capacity from NetworkPolicy
            hard_capacity = None
            try:
                policy = get_policy_for_shard(shard_id, state_manager)
                capacity = policy.shard_hard_capacity(shard_id=shard_id)
                hard_capacity = {
                    'capacity_model': capacity.capacity_model,
                    'origin_slots_total': capacity.origin_slots_total,
                    'origin_slots_used': capacity.origin_slots_used,
                    'origin_slots_available': capacity.origin_slots_available,
                    'limiting_factor': capacity.limiting_factor,
                    'details': capacity.details,
                    # EIP availability fields for fail-fast deployment decisions
                    'eip_quota': capacity.eip_quota,
                    'eip_used': capacity.eip_used,
                    'eip_available': capacity.eip_available,
                }
            except Exception as e:
                logger.warning(f"Failed to get hard capacity for shard {shard_id}: {e}")
                hard_capacity = {
                    'capacity_model': 'unknown',
                    'origin_slots_total': None,
                    'origin_slots_used': len(origins),
                    'origin_slots_available': None,
                    'limiting_factor': None,
                    'details': {'error': str(e)},
                    'eip_quota': None,
                    'eip_used': None,
                    'eip_available': None,
                }

            # Check for active deployment job
            deploy_info = None
            try:
                cur = db.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute(
                    """
                    SELECT job_id, state, progress, progress_message
                    FROM deployment_jobs
                    WHERE shard_id = %s
                    AND state IN ('pending', 'running')
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (shard_id,)
                )
                job_row = cur.fetchone()
                cur.close()

                if job_row:
                    deploy_info = {
                        'job_id': str(job_row['job_id']),
                        'state': job_row['state'],
                        'progress': job_row['progress'],
                        'progress_message': job_row['progress_message']
                    }
            except Exception as e:
                logger.warning(f"Failed to get deployment job for shard {shard_id}: {e}")
                # Don't include deploy_info if query fails

            shard_data = {
                'shard_id': shard_id,
                'region': shard['region'],
                'status': shard.get('status', 'unknown'),
                'shard_type': shard.get('shard_type', 'audit'),  # 'audit' or 'production'
                'active_node': shard_state.get('active_node'),
                'standby_node': shard_state.get('standby_node'),
                'origins_count': len(origins),
                'created_at': str(shard.get('created_at')) if shard.get('created_at') else None,
                'nodes': nodes_list,
                'hard_capacity': hard_capacity
            }

            # Only include deploy if there's an active job
            if deploy_info:
                shard_data['deploy'] = deploy_info

            shards.append(shard_data)

        return jsonify({
            'status': 'success',
            'shards': shards,
            'count': len(shards)
        })

    except Exception as e:
        logger.error(f"Failed to list shards: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/admin/shards/<shard_id>', methods=['GET'])
@require_tpm_auth
def get_shard(shard_id: str):
    """
    Get detailed information about a specific shard.

    Returns:
    {
        "status": "success",
        "shard": {
            "shard_id": "eu-central-1",
            "region": "eu-central-1",
            "status": "active",
            "nodes": [...],
            "origins": [...]
        }
    }
    """
    try:
        shard = state_manager.get_shard(shard_id)
        if not shard:
            return jsonify({'status': 'error', 'message': f'Shard {shard_id} not found'}), 404

        nodes = state_manager.get_nodes_for_shard(shard_id)

        # Check for stale "deploying" shard (no nodes + older than 2 minutes)
        if shard.get('status') == 'deploying' and not nodes:
            created_at = shard.get('created_at')
            if created_at:
                from datetime import datetime, timedelta
                # Handle both datetime objects and strings
                if isinstance(created_at, str):
                    created_at = datetime.fromisoformat(created_at)
                age = datetime.now() - created_at
                if age > timedelta(minutes=2):
                    logger.warning(
                        f"Deleting stale deploying shard {shard_id} "
                        f"(created {age.total_seconds():.0f}s ago, no nodes)"
                    )
                    state_manager.delete_shard(shard_id)
                    return jsonify({
                        'status': 'success',
                        'nodes': [],
                        'count': 0
                    }), 200

        shard_state = state_manager.get_shard_state(shard_id)
        origins = state_manager.get_origins_for_shard(shard_id)

        return jsonify({
            'status': 'success',
            'shard': {
                'shard_id': shard_id,
                'region': shard['region'],
                'status': shard.get('status', 'unknown'),
                'active_node': shard_state.get('active_node'),
                'standby_node': shard_state.get('standby_node'),
                'last_failover': str(shard_state.get('last_failover')) if shard_state.get('last_failover') else None,
                'nodes': [
                    {
                        'node_id': n['node_id'],
                        'instance_name': n.get('instance_name'),
                        'role': n.get('role'),
                        'public_ip': n.get('public_ip'),
                        'status': n.get('status')
                    } for n in nodes
                ],
                'origins': [
                    {
                        'origin_id': o['origin_id'],
                        'eip': o.get('eip'),
                        'state': o.get('state')
                    } for o in origins
                ]
            }
        })

    except Exception as e:
        logger.error(f"Failed to get shard {shard_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/admin/shards/<shard_id>', methods=['DELETE'])
@require_tpm_auth
def delete_shard(shard_id: str):
    """
    Delete a shard and all its resources (nodes, origins, EIPs).

    This is destructive - all origins in the shard will be deleted.
    """
    try:
        shard = state_manager.get_shard(shard_id)
        if not shard:
            return jsonify({'status': 'error', 'message': f'Shard {shard_id} not found'}), 404

        logger.info(f"Deleting shard {shard_id}...")

        # Get region from shard for AWS operations
        region = shard.get('region')

        # Get all nodes and origins for this shard
        nodes = state_manager.get_nodes_for_shard(shard_id)
        origins = state_manager.get_origins_for_shard(shard_id)

        # Delete origins first (releases EIPs)
        for origin in origins:
            try:
                origin_service.delete_origin(origin['origin_id'])
                logger.info(f"Deleted origin {origin['origin_id']}")
            except Exception as e:
                logger.warning(f"Failed to delete origin {origin['origin_id']}: {e}")

        # Terminate nodes
        for node in nodes:
            try:
                node_obj = Node(node_type="scrubber", region=region)
                node_obj.destroy(node['node_id'])
                logger.info(f"Terminated node {node['node_id']}")
            except Exception as e:
                logger.warning(f"Failed to terminate node {node['node_id']}: {e}")

        # Delete shard from database (explicitly deletes nodes, shard_state)
        state_manager.delete_shard(shard_id)

        logger.info(f"Shard {shard_id} deleted successfully")
        return jsonify({
            'status': 'success',
            'message': f'Shard {shard_id} deleted',
            'nodes_deleted': len(nodes),
            'origins_deleted': len(origins)
        })

    except Exception as e:
        logger.error(f"Failed to delete shard {shard_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/admin/shards/<shard_id>/failover', methods=['POST'])
@require_tpm_auth
def failover_shard(shard_id: str):
    """
    Failover a specific shard: promote standby to active.

    Body:
    {
        "reason": "manual|health_check|scheduled",
        "automated": false
    }

    This only fails over the specified shard, not others.
    """
    try:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        settings = get_settings()
        data = request.json or {}
        reason = data.get('reason', 'manual')

        start_time = time.time()

        # Validate shard exists
        shard = state_manager.get_shard(shard_id)
        if not shard:
            return jsonify({'status': 'error', 'message': f'Shard {shard_id} not found'}), 404

        shard_state = state_manager.get_shard_state(shard_id)
        active_node_id = shard_state.get('active_node')
        standby_node_id = shard_state.get('standby_node')

        if not active_node_id or not standby_node_id:
            return jsonify({
                'status': 'error',
                'message': f'Shard {shard_id} missing active or standby node'
            }), 400

        active_node = state_manager.nodes_db.get(active_node_id)
        standby_node = state_manager.nodes_db.get(standby_node_id)

        if not active_node or not standby_node:
            return jsonify({
                'status': 'error',
                'message': f'Could not find nodes for shard {shard_id}'
            }), 400

        logger.critical(
            f"SHARD FAILOVER START: {shard_id} | "
            f"active={active_node_id} → standby={standby_node_id} | reason={reason}"
        )

        standby_ip = standby_node['public_ip']
        standby_eni = standby_node['eni_id']
        region = shard['region']

        # Get origins for this shard only
        shard_origins = state_manager.get_origins_for_shard(shard_id)

        # STEP 1: Move EIPs to standby (parallel)
        logger.info(f"STEP 1: Moving {len(shard_origins)} EIPs to standby")

        def move_eip(origin):
            try:
                try:
                    addresses = aws_operations.describe_addresses(
                        public_ips=[origin['eip']],
                        region=region
                    )
                    if addresses:
                        assoc_id = addresses[0].get('association_id')
                        if assoc_id:
                            aws_operations.disassociate_address(assoc_id, region=region)
                except Exception:
                    pass

                aws_operations.associate_eip_to_eni(
                    eip_alloc_id=origin['eip_alloc_id'],
                    eni_id=standby_eni,
                    private_ip=origin['private_ip_standby'],
                    region=region
                )
                return (origin['origin_id'], True, None)
            except Exception as e:
                return (origin['origin_id'], False, str(e))

        eip_results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(move_eip, o): o['origin_id'] for o in shard_origins}
            for future in as_completed(futures):
                origin_id, success, error = future.result()
                eip_results[origin_id] = {'success': success, 'error': error}

        # STEP 2: Start WireGuard services
        logger.info("STEP 2: Starting WireGuard services")

        def start_wireguard(origin):
            try:
                wg_iface = origin['wg_interface']
                ssh_exec(
                    standby_ip,
                    f"sudo ip link delete {wg_iface} 2>/dev/null || true",
                    settings.ssh_key_path,
                    nodes_db=state_manager.nodes_db
                )
                ssh_exec(
                    standby_ip,
                    f"sudo systemctl start wg-quick@{wg_iface}",
                    settings.ssh_key_path,
                    nodes_db=state_manager.nodes_db
                )
                return (origin['origin_id'], True, None)
            except Exception as e:
                return (origin['origin_id'], False, str(e))

        service_results = {}
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(start_wireguard, o): o['origin_id'] for o in shard_origins}
            for future in as_completed(futures):
                origin_id, success, error = future.result()
                service_results[origin_id] = {'success': success, 'error': error}

        # STEP 2.5: Sync expected_tunnels.json to new active node
        # This ensures ecp-agent on the new active knows which tunnels should exist
        logger.info("STEP 2.5: Syncing expected_tunnels.json to new active")
        try:
            shard_origin_ids = [o['origin_id'] for o in shard_origins]
            sync_result = sync_expected_tunnels_to_node(
                target_host=standby_ip,
                origin_ids=shard_origin_ids,
                ssh_key_path=settings.ssh_key_path,
                nodes_db=state_manager.nodes_db,
                role='active'  # This node is being promoted to active
            )
            if sync_result:
                logger.info(f"✓ expected_tunnels.json synced to new active ({standby_ip})")
            else:
                logger.warning("Failed to sync expected_tunnels.json to new active")
        except Exception as e:
            logger.warning(f"expected_tunnels.json sync failed: {e}")

        # STEP 3: Update shard state (swap roles)
        logger.info("STEP 3: Updating shard state")

        # Swap roles in memory
        state_manager.shard_states[shard_id] = {
            'active_node': standby_node_id,
            'standby_node': None  # Temporarily no standby
        }

        # Update node roles in memory
        if active_node_id in state_manager.nodes_db:
            state_manager.nodes_db[active_node_id]['role'] = 'failed'
        if standby_node_id in state_manager.nodes_db:
            state_manager.nodes_db[standby_node_id]['role'] = 'active'

        # Persist role changes to database
        try:
            db = get_db_connection()
            cur = db.conn.cursor()
            cur.execute("UPDATE nodes SET role = 'failed' WHERE node_id = %s", (active_node_id,))
            cur.execute("UPDATE nodes SET role = 'active' WHERE node_id = %s", (standby_node_id,))
            db.conn.commit()
            cur.close()
            db.close()
            logger.info(f"Persisted role changes: {active_node_id}=failed, {standby_node_id}=active")
        except Exception as e:
            logger.error(f"Failed to persist role changes to DB: {e}")

        # Update shard_states to reflect the swap: promoted standby is now active
        state_manager.shard_states[shard_id]['active_node'] = standby_node_id
        state_manager.shard_states[shard_id]['standby_node'] = None  # No standby until new one deployed
        logger.info(f"Updated shard_states: active={standby_node_id}, standby=None")

        # Record failover (persists shard_states to database)
        state_manager.record_failover(shard_id)

        # STEP 3.5: Push bandwidth quotas to new active node (BACKGROUND - non-blocking)
        # Moved to background thread to reduce failover time. Quotas are non-critical
        # for traffic restoration and can be applied shortly after failover completes.
        def push_quotas_background():
            try:
                from miner_control_plane.services.bandwidth_quota_service import recalculate_quotas
                recalculate_quotas(shard_id)
                logger.info("Background: Bandwidth quotas pushed to new active node")
            except Exception as e:
                logger.warning(f"Background: Failed to push bandwidth quotas: {e}")
                # Non-fatal - quotas will be recalculated on next origin change

        logger.info("STEP 3.5: Scheduling bandwidth quota push (background)")
        quota_thread = threading.Thread(target=push_quotas_background, daemon=True)
        quota_thread.start()

        # STEP 4: Swap private IPs and update identities for next failover
        logger.info("STEP 4: Swapping origin private IPs and updating identities")
        try:
            db = get_db_connection()
            conn = db.conn
            cur = conn.cursor()

            for origin in shard_origins:
                origin_id = origin['origin_id']
                old_private_ip = origin['private_ip']
                old_private_ip_standby = origin['private_ip_standby']

                # Swap in origins_db
                state_manager.origins_db[origin_id]['private_ip'] = old_private_ip_standby
                state_manager.origins_db[origin_id]['private_ip_standby'] = old_private_ip

                # Persist to database
                cur.execute("""
                    UPDATE origins
                    SET private_ip = %s, private_ip_standby = %s
                    WHERE origin_id = %s
                """, (old_private_ip_standby, old_private_ip, origin_id))

                # Update identities to point to new active node
                cur.execute("""
                    UPDATE identities
                    SET node_id = %s
                    WHERE origin_id = %s
                """, (standby_node_id, origin_id))

            conn.commit()
            logger.info(f"Updated identities.node_id to {standby_node_id} for {len(shard_origins)} origins")
            cur.close()
            db.close()
        except Exception as swap_err:
            logger.error(f"Failed to swap private IPs/update identities: {swap_err}")

        total_time = time.time() - start_time

        logger.critical(
            f"SHARD FAILOVER COMPLETE: {shard_id} | "
            f"new_active={standby_node_id} | time={total_time:.1f}s"
        )

        # Background: Destroy failed node and spawn replacement
        # CRITICAL: Each step is independent - termination failure must NOT block standby deploy
        def destroy_and_spawn():
            # Step 1: Terminate failed node (non-fatal - may already be terminated)
            try:
                logger.info(f"Background: Terminating failed node {active_node_id}")
                node_obj = Node(node_type="scrubber", region=region)
                node_obj.destroy(active_node_id)
                logger.info(f"Background: Terminated {active_node_id}")
            except Exception as e:
                # Instance may already be terminated (e.g., by health monitor or manual action)
                if "400" in str(e) or "InvalidInstanceID" in str(e) or "terminated" in str(e).lower():
                    logger.warning(f"Background: Node {active_node_id} already terminated or gone: {e}")
                else:
                    logger.warning(f"Background: Failed to terminate {active_node_id}: {e}")
                # Continue anyway - node cleanup and standby deploy are more important

            # Step 2: Clean up database record (non-fatal)
            try:
                db = get_db_connection()
                try:
                    db_delete_node(active_node_id, db)
                    logger.info(f"Background: Deleted node record {active_node_id}")
                finally:
                    db.close()
                state_manager.remove_node(active_node_id)
            except Exception as e:
                logger.warning(f"Background: DB cleanup for {active_node_id} failed: {e}")
                # Continue anyway - standby deploy is more important

            # Step 3: Deploy new standby (CRITICAL - must complete for HA)
            try:
                new_node_name = active_node.get('instance_name', f"{shard_id}-spare")
                logger.info(f"Background: Deploying new standby {new_node_name}")
                new_node = deploy_single_scrubber(
                    shard_id=shard_id,
                    region=region,
                    node_name=new_node_name,
                    role='standby'
                )

                # Pre-configure with origins
                preconfigure_standby_origins(
                    shard_id=shard_id,
                    node_name=new_node_name,
                    public_ip=new_node['public_ip'],
                    eni_id=new_node['eni_id']
                )

                # Update shard state with new standby (defensive: shard may have been deleted)
                if shard_id in state_manager.shard_states:
                    state_manager.shard_states[shard_id]['standby_node'] = new_node['node_id']
                    state_manager._save_shard_state(shard_id)
                    logger.info(f"Background: New standby ready: {new_node['node_id']}")
                else:
                    logger.warning(
                        f"Shard {shard_id} no longer exists (cleanup during background deploy?) "
                        f"- standby {new_node['node_id']} deployed but not registered"
                    )
            except Exception as e:
                logger.error(f"Background: CRITICAL - Failed to deploy new standby: {e}", exc_info=True)
                # This is a critical failure - shard has no standby for HA

        bg_thread = threading.Thread(target=destroy_and_spawn, daemon=True)
        bg_thread.start()

        return jsonify({
            'status': 'success',
            'shard_id': shard_id,
            'new_active': standby_node_id,
            'failover_time': f'{total_time:.1f}s',
            'reason': reason,
            'eip_results': eip_results,
            'service_results': service_results
        })

    except Exception as e:
        logger.error(f"Shard failover failed: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


# =============================================================================
# REMOVED: Legacy /admin/deploy endpoint
# =============================================================================
# The single-region /admin/deploy endpoint was removed in favor of the
# multi-region shard-based deployment at POST /admin/shards.
#
# Migration: Use POST /admin/shards with {"region": "eu-central-1"} instead.
# =============================================================================


@bp.route('/admin/cleanup', methods=['POST'])
@require_tpm_auth
def cleanup_scrubbers():
    """
    Cleanup function to reset stack:
    1. Terminate all EC2 instances (AWS API - no SSH)
    2. Release all EIPs (AWS API)
    3. Truncate all database tables
    4. Clear in-memory state

    Authorization: Requires valid TensorProx Management Authorization header.
    """
    try:
        logger.info("=== Starting cleanup ===")
        destroyed_count = 0
        eip_count = 0

        # Step 1: Terminate all EC2 instances via AWS API (no SSH needed)
        logger.info("Step 1: Terminating EC2 instances...")
        nodes_to_destroy = []

        # Collect from cache (includes region)
        for edge_name, edge_node in list(state_manager.nodes_db.items()):
            instance_id = edge_node.get('instance_id') or edge_node.get('node_id')
            if instance_id:
                nodes_to_destroy.append({
                    'instance_id': instance_id,
                    'name': edge_name,
                    'region': edge_node.get('region')
                })

        # Collect from database (catches orphans) - MUST include region for multi-region cleanup
        try:
            db = get_db_connection()
            rows = db.query_all("SELECT node_id, instance_name, region FROM nodes")
            db.close()
            for row in rows:
                if not any(n['instance_id'] == row['node_id'] for n in nodes_to_destroy):
                    nodes_to_destroy.append({
                        'instance_id': row['node_id'],
                        'name': row['instance_name'],
                        'region': row.get('region')
                    })
        except Exception as e:
            logger.warning(f"Failed to query nodes from database: {e}")

        if nodes_to_destroy:
            logger.info(f"Found {len(nodes_to_destroy)} instances to terminate")
            for node_info in nodes_to_destroy:
                try:
                    region = node_info.get('region')
                    node = Node(node_type="scrubber", region=region)
                    if node.destroy(node_info['instance_id']):
                        logger.info(f"Terminated {node_info['name']} ({node_info['instance_id']}) in {region}")
                        destroyed_count += 1
                    else:
                        logger.warning(f"Failed to terminate {node_info['name']} in {region}")
                except Exception as e:
                    logger.warning(f"Error terminating {node_info['name']}: {e}")
        else:
            logger.info("No instances to terminate")

        # Step 2: Release all EIPs via AWS API
        # First from database records, then discover orphans directly from AWS
        logger.info("Step 2: Releasing EIPs...")
        provider = get_provider("aws")
        released_alloc_ids = set()

        # 2a: Release EIPs tracked in database (with region awareness)
        try:
            db = get_db_connection()
            eips = []

            # From origins table - shard_id IS the region (e.g., "eu-north-1")
            rows = db.query_all(
                "SELECT DISTINCT eip_alloc_id, eip, shard_id FROM origins WHERE eip_alloc_id IS NOT NULL"
            )
            for row in rows:
                eips.append({
                    'alloc_id': row['eip_alloc_id'],
                    'ip': row['eip'],
                    'region': row.get('shard_id')  # shard_id = region
                })

            # From eips table (may not have region, use default)
            rows = db.query_all("SELECT eip_allocation_id, public_ip FROM eips")
            for row in rows:
                if not any(e['alloc_id'] == row['eip_allocation_id'] for e in eips):
                    eips.append({
                        'alloc_id': row['eip_allocation_id'],
                        'ip': row['public_ip'],
                        'region': None
                    })

            db.close()

            if eips:
                logger.info(f"Found {len(eips)} EIPs in database to release")
                for eip in eips:
                    try:
                        region = eip.get('region')
                        # Try to disassociate first
                        try:
                            addresses = provider.describe_addresses(
                                allocation_ids=[eip['alloc_id']], region=region
                            )
                            if addresses and addresses[0].get('association_id'):
                                provider.disassociate_address(
                                    addresses[0]['association_id'], region=region
                                )
                        except Exception:
                            pass
                        provider.release_address(eip['alloc_id'], region=region)
                        logger.info(f"Released EIP {eip['ip']} in {region} (from database)")
                        eip_count += 1
                        released_alloc_ids.add(eip['alloc_id'])
                    except Exception as e:
                        logger.warning(f"Failed to release EIP {eip['ip']} in {region}: {e}")
            else:
                logger.info("No EIPs in database to release")
        except Exception as e:
            logger.warning(f"Database EIP release failed: {e}")

        # 2b: Discover and release orphaned EIPs directly from AWS
        # This catches EIPs that exist on AWS but aren't tracked in database
        # Check ALL regions we might have used (from nodes table + known regions)
        logger.info("Step 2b: Checking AWS for orphaned EIPs (all regions)...")

        # Collect regions from nodes we're about to destroy + any we know about
        regions_to_check = set()
        for node_info in nodes_to_destroy:
            if node_info.get('region'):
                regions_to_check.add(node_info['region'])
        # Always check default region
        regions_to_check.add(get_settings().scrubber_region)

        orphan_count = 0
        for region in regions_to_check:
            try:
                all_addresses = provider.describe_addresses(region=region)

                for addr in all_addresses:
                    alloc_id = addr.get('allocation_id')
                    public_ip = addr.get('public_ip')

                    if not alloc_id:
                        continue

                    # Skip if already released in step 2a
                    if alloc_id in released_alloc_ids:
                        continue

                    # Release unattached EIPs (orphans from failed cleanups)
                    # These have no network_interface_id
                    if not addr.get('network_interface_id'):
                        try:
                            assoc_id = addr.get('association_id')
                            if assoc_id:
                                provider.disassociate_address(assoc_id, region=region)
                            provider.release_address(alloc_id, region=region)
                            logger.info(f"Released orphaned EIP {public_ip} in {region}")
                            eip_count += 1
                            orphan_count += 1
                        except Exception as e:
                            logger.warning(f"Failed to release orphaned EIP {public_ip} in {region}: {e}")

            except Exception as e:
                logger.warning(f"AWS orphan EIP discovery failed for {region}: {e}")

        if orphan_count > 0:
            logger.info(f"Released {orphan_count} orphaned EIPs from AWS")
        else:
            logger.info("No orphaned EIPs found on AWS")

        # Step 2c: Clean up Security Group rules (remove origin port rules) - all regions
        # This prevents SG rule accumulation that hits AWS limit (~60 rules)
        sg_rules_removed = 0
        logger.info("Step 2c: Cleaning Security Group rules (all regions)...")
        from miner_control_plane.utils.aws import aws_operations

        for region in regions_to_check:
            try:
                sg_id = aws_operations.get_scrubber_security_group_id(region=region)
                if not sg_id:
                    continue

                sgs = provider.describe_security_groups(filters={'group-id': sg_id}, region=region)

                if sgs and sgs[0].get('ip_permissions'):
                    # Keep only SSH (22) and WireGuard base port range (51820-51920)
                    # Remove all other rules (origin ports like 80, 443, etc.)
                    protected_ports = {22}  # SSH for management
                    wg_port_range = range(51820, 51921)  # WireGuard ports

                    for rule in sgs[0]['ip_permissions']:
                        from_port = rule.get('from_port')
                        to_port = rule.get('to_port')
                        protocol = rule.get('ip_protocol', 'tcp')

                        # Skip protected ports
                        if from_port in protected_ports:
                            continue

                        # Skip WireGuard port range
                        if from_port and from_port in wg_port_range:
                            continue

                        # Skip if no port (e.g., ICMP or -1 for all)
                        if from_port is None or from_port == -1:
                            continue

                        # Remove this rule
                        try:
                            for cidr_block in rule.get('ip_ranges', [{'cidr_ip': '0.0.0.0/0'}]):
                                cidr = cidr_block.get('cidr_ip', '0.0.0.0/0')
                                provider.revoke_security_group_ingress(
                                    group_id=sg_id,
                                    ip_permissions=[{
                                        'protocol': protocol,
                                        'from_port': from_port,
                                        'to_port': to_port,
                                        'cidr': cidr
                                    }],
                                    region=region
                                )
                                sg_rules_removed += 1
                                logger.debug(f"Removed SG rule in {region}: {protocol} {from_port}-{to_port}")
                        except Exception as rule_err:
                            logger.warning(f"Failed to remove SG rule {from_port} in {region}: {rule_err}")

            except Exception as e:
                logger.warning(f"Security Group cleanup failed for {region}: {e}")

        if sg_rules_removed > 0:
            logger.info(f"Removed {sg_rules_removed} Security Group rules")
        else:
            logger.info("No Security Group rules to remove")

        # Step 3: Truncate ALL database tables
        logger.info("Step 3: Truncating database tables...")
        table_count = 0
        try:
            db = get_db_connection()

            rows = db.query_all("""
                SELECT tablename FROM pg_tables
                WHERE schemaname = 'public'
                ORDER BY tablename
            """)
            tables = [row['tablename'] for row in rows]

            if tables:
                table_list = ', '.join(tables)
                # Try with short lock timeout first
                try:
                    db.execute("SET lock_timeout = '5s'")
                    db.execute(f"TRUNCATE {table_list} CASCADE")
                except Exception as lock_err:
                    # If lock timeout, rollback aborted transaction, terminate blockers, retry
                    logger.warning(f"TRUNCATE blocked, terminating blockers: {lock_err}")
                    # Rollback the aborted transaction
                    try:
                        db.conn.rollback()
                    except Exception:
                        pass
                    # Close this connection and get a fresh one
                    db.close()

                    # Use a separate admin connection to terminate blockers
                    admin_db = get_db_connection()
                    admin_db.execute("""
                        SELECT pg_terminate_backend(pid)
                        FROM pg_stat_activity
                        WHERE datname = current_database()
                          AND pid != pg_backend_pid()
                    """)
                    logger.info("Terminated blocking database connections")

                    # Retry truncate with fresh connection and longer timeout
                    admin_db.execute("SET lock_timeout = '30s'")
                    admin_db.execute(f"TRUNCATE {table_list} CASCADE")
                    db = admin_db  # Use this connection for close() below
                table_count = len(tables)
                logger.info(f"Truncated {table_count} tables")
            db.close()
        except Exception as e:
            logger.error(f"Database truncate failed: {e}")
            raise

        # Step 4: Clear in-memory state
        logger.info("Step 4: Clearing in-memory state...")
        state_manager.shard_states = {}
        state_manager.shards_db = {}
        state_manager.nodes_db = {}
        state_manager.origins_db = {}
        state_manager.bandwidth_capacity = {}
        state_manager.bandwidth_usage = {}
        state_manager.bandwidth_quotas = {}

        logger.info("=== Cleanup complete ===")
        return jsonify({
            'status': 'success',
            'message': 'Cleanup complete',
            'instances_terminated': destroyed_count,
            'eips_released': eip_count,
            'tables_truncated': table_count
        })

    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# =============================================================================
# REMOVED: Legacy /failover endpoint
# =============================================================================
# The global /failover endpoint was removed in favor of the per-shard failover
# at POST /admin/shards/<shard_id>/failover.
#
# Migration: Use POST /admin/shards/{shard_id}/failover instead.
# =============================================================================


@bp.post('/admin/cleanup-orphans')
@require_tpm_auth
def cleanup_orphan_resources():
    """
    Release orphaned Elastic IPs/private IPs that are attached to scrubbers
    but not tracked by Miner.

    Authorization: Requires valid TensorProx Management Authorization header.
    """
    try:
        summary = origin_service.cleanup_orphan_resources()
        return jsonify({'status': 'success', 'summary': summary}), 200
    except Exception as e:
        logger.error(f"Orphan resource cleanup failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/admin/config-sync', methods=['POST'])
@require_tpm_auth
def sync_scrubber_configs():
    """
    Sync configuration files to all scrubbers.

    Checks if scrubber config files (scripts, eBPF programs) are up to date
    with the repo and updates any that are outdated.

    Query Parameters:
        force (bool): If true, sync all files regardless of checksum

    Returns:
    {
        "status": "success",
        "results": {
            "node_id": {
                "host": "1.2.3.4",
                "checked": 7,
                "synced": ["ecp-agent/ecp-agent.py"],
                "failed": [],
                "skipped": ["bin/configure-origin.py", ...],
                "missing_local": []
            }
        },
        "summary": {
            "scrubbers_checked": 3,
            "files_synced": 1,
            "files_failed": 0
        }
    }
    """
    from miner_control_plane.services.config_sync import sync_all_scrubbers

    force = request.args.get('force', 'false').lower() == 'true'

    try:
        results = sync_all_scrubbers(
            nodes_db=state_manager.nodes_db,
            force=force
        )

        # Calculate summary
        total_synced = sum(len(r.get("synced", [])) for r in results.values())
        total_failed = sum(len(r.get("failed", [])) for r in results.values())

        summary = {
            "scrubbers_checked": len(results),
            "files_synced": total_synced,
            "files_failed": total_failed
        }

        return jsonify({
            'status': 'success',
            'results': results,
            'summary': summary
        }), 200

    except Exception as e:
        logger.error(f"Config sync failed: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/admin/nodes', methods=['GET'])
@require_tpm_auth
def get_nodes_status():
    """
    Get status of all scrubber nodes including health metrics.

    Authorization: Requires valid TensorProx Management Authorization header.

    Returns:
    {
        "nodes": [
            {
                "node_id": "i-xxxxx",
                "instance_name": "eu-central-1-a",
                "shard_id": "eu-central-1",
                "provider": "aws",
                "region": "eu-central-1",
                "status": "active",
                "public_ip": "3.x.x.x",
                "cpu_percent": 12.5,
                "bpf_loaded": true,
                "last_seen": "2025-11-20T11:49:12Z"
            }
        ],
        "count": 2
    }
    """
    try:
        import psycopg2.extras
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        try:
            # Query nodes with health information
            cur.execute("""
                SELECT
                    n.node_id,
                    n.instance_name,
                    n.provider,
                    n.region,
                    n.status,
                    n.current_public_ip as public_ip,
                    n.last_seen as node_last_seen,
                    h.cpu_pct as cpu_percent,
                    h.bpf_loaded,
                    h.last_seen as health_last_seen
                FROM nodes n
                LEFT JOIN health_node h ON n.node_id = h.node_id
                ORDER BY n.instance_name
            """)

            nodes = []
            for row in cur.fetchall():
                # Use the most recent last_seen timestamp
                last_seen = row['health_last_seen'] or row['node_last_seen']

                nodes.append({
                    'node_id': row['node_id'],
                    'instance_name': row['instance_name'],
                    'provider': row['provider'],
                    'region': row['region'],
                    'status': row['status'],
                    'public_ip': row['public_ip'],
                    'cpu_percent': float(row['cpu_percent']) if row['cpu_percent'] else None,
                    'bpf_loaded': row['bpf_loaded'] if row['bpf_loaded'] is not None else False,
                    'last_seen': last_seen.isoformat() if last_seen else None
                })

            return jsonify({
                'status': 'success',
                'nodes': nodes,
                'count': len(nodes)
            }), 200

        finally:
            cur.close()

    except Exception as e:
        logger.error(f"Failed to get nodes status: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
