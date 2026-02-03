"""
Scrubber Configuration Sync Service.

Ensures deployed scrubbers have up-to-date configuration files from the repo.
Runs on miner startup and can be triggered manually via admin API.

Key files synced:
- bin/*.py: Configuration scripts (configure-origin.py, populate-blacklist.py)
- ecp-agent/ecp-agent.py: Health reporting agent
- ebpf/*.o: Compiled eBPF programs (XDP, TC)
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Any

from shared.utils.logging import get_logger
from shared.utils.ssh import ssh_exec, sftp_upload
from shared.config import get_settings

logger = get_logger(__name__)

# Files to sync and their remote paths
# Format: (local_path_relative_to_assets, remote_path, reload_command)
# Note: Missing local files are logged but skipped gracefully
SYNC_FILES = [
    # Configuration scripts - critical for origin setup
    ("bin/configure-origin.py", "/opt/tensorprox/bin/configure-origin.py", None),
    ("bin/populate-blacklist.py", "/opt/tensorprox/bin/populate-blacklist.py", None),

    # ECP Agent - requires service restart if updated
    ("ecp-agent/ecp-agent.py", "/opt/tensorprox/bin/ecp-agent.py", "sudo systemctl restart ecp-agent"),

    # Compiled eBPF programs - synced from local build/ directory
    # These are the XDP programs that do the actual packet filtering
    # IMPORTANT: xdp_wan.o is used by production (attached to ens5)
    ("ebpf/build/xdp_wan.o", "/opt/tensorprox/ebpf/xdp_wan.o", None),
    # IMPORTANT: xdp_wg_audit.o is used by audit tunnels (attached to wga* interfaces)
    # The audit code loads from /home/ubuntu/assets/ebpf/build/
    # Reload command: find all wga* interfaces with XDP attached and reload
    (
        "ebpf/build/xdp_wg_audit.o",
        "/home/ubuntu/assets/ebpf/build/xdp_wg_audit.o",
        # After syncing new XDP, reload on all active audit tunnel interfaces
        "for iface in $(ip -o link show type wireguard 2>/dev/null | grep -oE 'wga[0-9]+_[0-9]+' || true); do "
        "if sudo bpftool net show dev $iface 2>/dev/null | grep -q xdp; then "
        "sudo ip link set $iface xdp off 2>/dev/null; "
        "sudo ip link set $iface xdpgeneric obj /home/ubuntu/assets/ebpf/build/xdp_wg_audit.o sec xdp 2>/dev/null && "
        "echo \"Reloaded XDP on $iface\"; "
        "fi; done"
    ),
]


def get_assets_path() -> Path:
    """Get the path to scrubber assets in the repo."""
    # Navigate from miner_control_plane to configs/assets/scrubber/assets
    base = Path(__file__).parent.parent.parent  # tensorprox_subnet
    return base / "configs" / "assets" / "scrubber" / "assets"


def calculate_file_checksum(file_path: Path) -> Optional[str]:
    """Calculate MD5 checksum of a local file."""
    if not file_path.exists():
        return None
    try:
        with open(file_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception as e:
        logger.error(f"Failed to calculate checksum for {file_path}: {e}")
        return None


def get_ssh_user_for_node(node_info: Dict[str, Any]) -> str:
    """Get SSH user based on provider. AWS=ubuntu, Linode=root."""
    provider = node_info.get("provider", "aws")
    return "root" if provider == "linode" else "ubuntu"


def get_remote_checksum(
    host: str,
    remote_path: str,
    ssh_key_path: str,
    nodes_db: Dict[str, Any]
) -> Optional[str]:
    """Get MD5 checksum of a file on the remote scrubber."""
    rc, stdout, stderr = ssh_exec(
        host=host,
        command=f"md5sum {remote_path} 2>/dev/null | cut -d' ' -f1",
        ssh_key_path=ssh_key_path,
        nodes_db=nodes_db,
        timeout=30
    )
    if rc == 0 and stdout.strip():
        return stdout.strip()
    return None


def sync_file_to_scrubber(
    host: str,
    local_path: Path,
    remote_path: str,
    ssh_key_path: str,
    nodes_db: Dict[str, Any],
    ssh_user: str = "ubuntu",
    reload_command: Optional[str] = None
) -> bool:
    """
    Upload a file to the scrubber and optionally run a reload command.

    Returns True if successful.
    """
    try:
        # Ensure remote directory exists
        remote_dir = os.path.dirname(remote_path)
        rc, _, stderr = ssh_exec(
            host=host,
            command=f"sudo mkdir -p {remote_dir}",
            ssh_key_path=ssh_key_path,
            nodes_db=nodes_db,
            timeout=30
        )
        if rc != 0:
            logger.error(f"Failed to create directory {remote_dir} on {host}: {stderr}")
            return False

        # Upload file to temp location first
        temp_path = f"/tmp/{os.path.basename(remote_path)}"
        success, err = sftp_upload(
            host=host,
            username=ssh_user,
            key_filename=ssh_key_path,
            local_path=str(local_path),
            remote_path=temp_path,
            timeout=60
        )
        if not success:
            logger.error(f"Failed to upload {local_path} to {host}:{temp_path}: {err}")
            return False

        # Move to final location with sudo
        rc, _, stderr = ssh_exec(
            host=host,
            command=f"sudo mv {temp_path} {remote_path} && sudo chmod 755 {remote_path}",
            ssh_key_path=ssh_key_path,
            nodes_db=nodes_db,
            timeout=30
        )
        if rc != 0:
            logger.error(f"Failed to move file to {remote_path} on {host}: {stderr}")
            return False

        # Run reload command if specified
        if reload_command:
            rc, _, stderr = ssh_exec(
                host=host,
                command=reload_command,
                ssh_key_path=ssh_key_path,
                nodes_db=nodes_db,
                timeout=60
            )
            if rc != 0:
                logger.warning(f"Reload command failed on {host}: {stderr}")
                # Don't fail the sync, just warn

        logger.info(f"Synced {local_path.name} to {host}:{remote_path}")
        return True

    except Exception as e:
        logger.error(f"Failed to sync {local_path} to {host}: {e}")
        return False


def check_and_sync_scrubber(
    host: str,
    ssh_key_path: str,
    nodes_db: Dict[str, Any],
    ssh_user: str = "ubuntu",
    force: bool = False
) -> Dict[str, Any]:
    """
    Check a single scrubber's config files and sync any that are outdated.

    Args:
        host: Scrubber IP address
        ssh_key_path: Path to SSH key
        nodes_db: Node database for SSH user resolution
        ssh_user: SSH username (ubuntu for AWS, root for Linode)
        force: If True, sync all files regardless of checksum

    Returns:
        Dict with sync results:
        - checked: Number of files checked
        - synced: List of files that were synced
        - failed: List of files that failed to sync
        - skipped: List of files that were already up to date
        - missing_local: List of files not found locally
    """
    result = {
        "host": host,
        "checked": 0,
        "synced": [],
        "failed": [],
        "skipped": [],
        "missing_local": [],
        "reloaded": []  # eBPF files where reload command was run (even if file was up-to-date)
    }

    assets_path = get_assets_path()

    for local_rel, remote_path, reload_cmd in SYNC_FILES:
        local_path = assets_path / local_rel
        result["checked"] += 1

        # Check if local file exists
        if not local_path.exists():
            result["missing_local"].append(local_rel)
            continue

        # Calculate local checksum
        local_checksum = calculate_file_checksum(local_path)
        if not local_checksum:
            result["failed"].append(local_rel)
            continue

        # Get remote checksum (unless forcing sync)
        needs_sync = force
        if not force:
            remote_checksum = get_remote_checksum(host, remote_path, ssh_key_path, nodes_db)

            if remote_checksum == local_checksum:
                # File is up-to-date, but for eBPF files we still run reload command
                # in case XDP was unloaded (scrubber restart) or running stale code
                if reload_cmd and local_rel.endswith('.o'):
                    logger.info(f"eBPF file {local_rel} up-to-date on {host}, ensuring XDP is loaded")
                    rc, stdout, stderr = ssh_exec(
                        host=host,
                        command=reload_cmd,
                        ssh_key_path=ssh_key_path,
                        nodes_db=nodes_db,
                        timeout=60
                    )
                    if rc == 0:
                        result["reloaded"].append(local_rel)
                        if stdout and stdout.strip():
                            logger.info(f"XDP reload on {host}: {stdout.strip()}")
                    else:
                        logger.warning(f"eBPF reload command failed on {host}: {stderr}")
                result["skipped"].append(local_rel)
                continue
            else:
                needs_sync = True

            if remote_checksum:
                logger.info(
                    f"Config mismatch on {host} for {local_rel}: "
                    f"local={local_checksum[:8]}... remote={remote_checksum[:8]}..."
                )
            else:
                logger.info(f"Config missing on {host}: {local_rel}")

        # Sync the file
        if needs_sync:
            if sync_file_to_scrubber(host, local_path, remote_path, ssh_key_path, nodes_db, ssh_user, reload_cmd):
                result["synced"].append(local_rel)
            else:
                result["failed"].append(local_rel)

    return result


def sync_all_scrubbers(
    nodes_db: Dict[str, Any],
    force: bool = False
) -> Dict[str, Dict[str, Any]]:
    """
    Check and sync configuration on all active scrubbers.

    Args:
        nodes_db: Node database (node_id -> node_info dict)
        force: If True, sync all files regardless of checksum

    Returns:
        Dict mapping node_id to sync results
    """
    settings = get_settings()
    results = {}

    if not nodes_db:
        logger.debug("No scrubbers available for config sync")
        return results

    for node_id, node_info in nodes_db.items():
        public_ip = node_info.get("public_ip")
        if not public_ip:
            continue

        status = node_info.get("status", "")
        if status not in ("active", "standby", "healthy"):
            continue

        ssh_user = get_ssh_user_for_node(node_info)
        logger.info(f"Checking config sync for scrubber {node_id} ({public_ip}, user={ssh_user})")

        try:
            result = check_and_sync_scrubber(
                host=public_ip,
                ssh_key_path=settings.ssh_key_path,
                nodes_db=nodes_db,
                ssh_user=ssh_user,
                force=force
            )
            results[node_id] = result

            # Log summary
            if result["synced"]:
                logger.info(
                    f"Scrubber {node_id}: synced {len(result['synced'])} files: "
                    f"{result['synced']}"
                )
            elif result["failed"]:
                logger.warning(
                    f"Scrubber {node_id}: {len(result['failed'])} files failed to sync"
                )
            else:
                logger.debug(f"Scrubber {node_id}: all {result['checked']} files up to date")

        except Exception as e:
            logger.error(f"Config sync failed for scrubber {node_id}: {e}")
            results[node_id] = {
                "host": public_ip,
                "error": str(e)
            }

    return results


def run_config_sync() -> None:
    """
    Run configuration sync as part of startup cleanup.
    Called from startup_cleanup.py.
    """
    try:
        from miner_control_plane.control_plane import state_manager

        if not state_manager.nodes_db:
            logger.debug("No scrubbers available for config sync")
            return

        logger.info("Running scrubber configuration sync...")

        results = sync_all_scrubbers(
            nodes_db=state_manager.nodes_db,
            force=False  # Only sync files that differ
        )

        # Summarize results
        total_synced = sum(len(r.get("synced", [])) for r in results.values())
        total_failed = sum(len(r.get("failed", [])) for r in results.values())

        if total_synced > 0:
            logger.info(f"Config sync complete: {total_synced} files updated across {len(results)} scrubbers")
        elif total_failed > 0:
            logger.warning(f"Config sync complete with errors: {total_failed} files failed")
        else:
            logger.info("Config sync complete: all scrubbers up to date")

    except Exception as e:
        logger.error(f"Config sync failed: {e}", exc_info=True)
