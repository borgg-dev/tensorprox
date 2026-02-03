"""Scrubber operations - Refactored to use Node class

Scrubber-specific verification and orchestration using generic Node infrastructure.
"""
from typing import Tuple
from shared.utils.ssh import ssh_exec
from shared.utils.logging import get_logger
from shared.config import get_settings
from miner_control_plane.services.state_manager import state_manager

logger = get_logger(__name__)


def verify_scrubber_bootstrap(host: str, ssh_key_path: str, nodes_db: dict = None) -> Tuple[bool, str]:
    """
    Verify that scrubber bootstrap completed successfully.

    Scrubber-specific checks:
    - XDP program loaded on ens5 (via ip link - no sudo needed)
    - ecp-agent service running (via systemctl - no sudo needed)

    Args:
        host: IP address of scrubber node
        ssh_key_path: SSH private key path
        nodes_db: Optional nodes database (for backward compatibility)

    Returns:
        Tuple of (success: bool, message: str)

    Note: This is called by configure_scrubber_node after generic bootstrap completes.
    Other node types (origin, exit_hub) should have their own verify functions.

    IMPORTANT: Commands must not use sudo as it hangs over SSH without TTY.
    """
    logger.info(f"Verifying bootstrap completion on {host}")

    # Check 1: XDP program loaded (using ip link instead of bpftool - no sudo needed)
    # Output of 'ip link show ens5' includes 'prog/xdp id <ID>' if XDP is loaded
    rc, stdout, stderr = ssh_exec(
        host,
        "ip link show ens5 2>/dev/null | grep -c 'prog/xdp' || echo 0",
        ssh_key_path,
        user='ubuntu',
        timeout=10
    )
    if rc != 0 or stdout.strip() == "0":
        logger.error(f"XDP verification failed: rc={rc}, stdout={stdout}, stderr={stderr}")
        return False, "XDP program not loaded on ens5"

    logger.info(f"✓ XDP program loaded on ens5")

    # Check 2: ecp-agent service running (systemctl doesn't require sudo for is-active)
    rc, stdout, stderr = ssh_exec(
        host,
        "systemctl is-active ecp-agent.service 2>&1",
        ssh_key_path,
        user='ubuntu',
        timeout=10
    )
    if rc != 0 or "active" not in stdout:
        logger.error(f"ecp-agent verification failed: rc={rc}, stdout={stdout}, stderr={stderr}")
        return False, "ecp-agent service not running"

    logger.info(f"✓ ecp-agent service active")

    # Note: Skipping BPF maps check as it requires sudo which hangs without TTY.
    # If XDP is loaded and ecp-agent is running, the maps must exist (they're created during bootstrap).

    logger.info(f"Bootstrap verification passed on {host}")
    return True, "Bootstrap complete: XDP loaded, ecp-agent active"


def configure_scrubber_node(
    node_name: str,
    host: str,
    bundle_path: str,
    ssh_key_path: str,
    nodes_db: dict = None,  # Kept for backward compatibility, not used
    instance_id: str = None  # Pass from miner for NODE_ID env var
) -> bool:
    """
    Configure scrubber node using Node class generic bootstrap.

    Thin wrapper that adds scrubber-specific verification to generic bootstrap flow.

    Args:
        node_name: Name of the scrubber node
        host: IP address of the node
        bundle_path: Path to asset bundle tarball
        ssh_key_path: SSH private key path
        instance_id: AWS instance ID (used for NODE_ID env var)

    Returns:
        True if successful, False otherwise
    """
    from shared.node import Node

    logger.info(f"Configuring {node_name} scrubber at {host}")

    # Create Node instance for generic bootstrap operations
    node = Node(node_type="scrubber")

    # Phase 1: Upload and extract bundle using existing post_provision
    logger.info("Uploading and extracting asset bundle...")
    upload_success, upload_error = node.post_provision(
        instance_ip=host,
        bundle_path=bundle_path,
        ssh_key_path=ssh_key_path
    )

    if not upload_success:
        logger.error(f"Failed to upload/extract bundle on {node_name}: {upload_error}")
        return False

    # Phase 2: Execute bootstrap script with retry using node.execute_bootstrap
    logger.info("Executing bootstrap script...")

    # Get EMN settings to pass to ecp-agent
    settings = get_settings()
    env_vars = {
        'EMN_IP': settings.emn_ip,
        'EMN_PORT': str(settings.emn_port),
        'INSTANCE_ID': instance_id  # Pass instance_id from miner (metadata service blocked)
    }

    bootstrap_success, bootstrap_output = node.execute_bootstrap(
        instance_ip=host,
        ssh_key_path=ssh_key_path,
        max_retries=2,  # APT lock tolerance
        env_vars=env_vars
    )

    if not bootstrap_success:
        logger.error(f"Bootstrap failed on {node_name}:")
        logger.error(f"FULL BOOTSTRAP OUTPUT:\n{bootstrap_output}")
        return False

    logger.info(f"Bootstrap completed on {node_name}")
    logger.info(f"Bootstrap output:\n{bootstrap_output}")

    # NOTE: XDP is attached during bootstrap (bootstrap_inner.sh lines 55-72)
    # which runs as root. No need for Phase 2.5 XDP attachment anymore.
    # The bootstrap already:
    # 1. Saves miner IP to /opt/tensorprox/miner_ip
    # 2. Runs attach-xdp.sh with miner IP whitelist
    # 3. Verifies XDP is loaded on ens5/eth0

    # Phase 3: Verify scrubber-specific components
    logger.info("Verifying scrubber bootstrap...")
    verified, verify_msg = verify_scrubber_bootstrap(host, ssh_key_path, nodes_db)

    if not verified:
        logger.error(f"Verification failed on {node_name}: {verify_msg}")
        return False

    logger.info(f"Verification passed on {node_name}: {verify_msg}")

    # Phase 4: Cleanup temp files using node.cleanup_remote_files
    logger.info("Cleaning up temporary files...")
    node.cleanup_remote_files(
        instance_ip=host,
        paths=['/tmp/asset-bundle.tar.gz'],
        ssh_key_path=ssh_key_path
    )

    # Phase 5: Sync per-origin reputation from database
    logger.info("Syncing per-origin reputation to new scrubber...")
    from miner_control_plane.services.scrubber_sync import scrubber_sync, SyncResult
    sync_report = scrubber_sync.sync_all_reputation_to_scrubber(node_name)
    if sync_report.result != SyncResult.SUCCESS:
        logger.warning(f"Reputation sync incomplete: {sync_report.error_message}")
    else:
        logger.info("Per-origin reputation synced successfully")

    logger.info(f"{node_name} scrubber configured successfully")
    return True


def configure_wireguard_dataplane(
    node_name: str,
    host: str,
    wg_interface: str,
    private_ip: str,
    origin_ip: str,
    ssh_key_path: str,
    nodes_db: dict = None,
    origin_id: str = None
) -> bool:
    """
    Attach the WireGuard transparent dataplane helpers on a scrubber.

    This wires the new origin tunnel into the TC/XDP pipeline so that
    traffic hairpins through the scrubber before reaching the origin.

    Args:
        origin_id: The actual origin ID (e.g., 'O37'). MUST be provided to ensure
                   expected_tunnels.json uses the correct origin_id, not one
                   derived from the wg_interface name.
    """
    cmd = (
        "sudo /opt/tensorprox/bin/configure-origin.py "
        f"--wg-interface {wg_interface} "
        f"--private-ip {private_ip} "
        f"--origin-ip {origin_ip}"
    )
    if origin_id:
        cmd += f" --origin-id {origin_id}"
    rc, stdout, stderr = ssh_exec(host, cmd, ssh_key_path, nodes_db=nodes_db)
    if rc != 0:
        logger.error(
            f"WireGuard dataplane configure failed on {node_name} ({host}): "
            f"rc={rc}, stderr={stderr}"
        )
        return False

    logger.info(
        f"WireGuard dataplane configured on {node_name} "
        f"(wg={wg_interface}, private_ip={private_ip}, origin_ip={origin_ip})"
    )
    return True


def remove_wireguard_dataplane(
    node_name: str,
    host: str,
    wg_interface: str,
    private_ip: str,
    ssh_key_path: str,
    nodes_db: dict = None,
    origin_ip: str = None
) -> None:
    """
    DEPRECATED: This function is no longer used.

    BPF map cleanup is now handled by miner/services/bpf_map_cleaner.py::clean_origin_bpf_maps()
    which provides robust, verified cleanup without depending on scrubber-side scripts.

    This function is kept for backward compatibility only and should not be called.
    """
    logger.warning(
        f"remove_wireguard_dataplane() called on {node_name} - this function is deprecated. "
        f"Use miner.services.bpf_map_cleaner.clean_origin_bpf_maps() instead."
    )
