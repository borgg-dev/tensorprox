"""
Expected Tunnels State Management

This module manages the expected_tunnels.json file on scrubbers, which enables
context-sensitive tunnel validation by ecp-agent.

The file tracks which origins SHOULD be present on each scrubber. ecp-agent
compares this against actual WireGuard interfaces to detect:
- Missing tunnels (expected but not present)
- Orphaned tunnels (present but not expected)

CRITICAL: This file must be kept in sync with the database and both scrubbers.
"""
import json
from typing import Any, Dict, List, Optional
from shared.utils.ssh import ssh_exec
from shared.utils.logging import get_logger

logger = get_logger(__name__)

EXPECTED_TUNNELS_PATH = '/var/lib/tensorprox/expected_tunnels.json'


def update_expected_tunnels(
    host: str,
    origin_id: str,
    action: str,
    ssh_key_path: str,
    nodes_db: dict = None
) -> bool:
    """
    Update expected_tunnels.json on a single scrubber.

    Modifies only the origins list; preserves the existing role field.

    Args:
        host: Scrubber IP address
        origin_id: Origin ID (e.g., 'O1')
        action: 'add' or 'remove'
        ssh_key_path: Path to SSH private key
        nodes_db: Node database for SSH user detection

    Returns:
        True if successful, False otherwise
    """
    # Build the update command - atomic JSON update via Python one-liner
    # Use sudo because /var/lib/tensorprox/ is root-owned
    # IMPORTANT: Preserve the existing 'role' field when modifying origins
    if action == 'add':
        cmd = f"""sudo python3 -c "
import json, time
from pathlib import Path
p = Path('{EXPECTED_TUNNELS_PATH}')
p.parent.mkdir(parents=True, exist_ok=True)
d = json.load(open(p)) if p.exists() else {{'origins': [], 'role': 'active', 'updated_at': 0}}
s = set(d.get('origins', []))
s.add('{origin_id}')
d['origins'] = sorted(list(s))
d['updated_at'] = int(time.time())
if 'role' not in d:
    d['role'] = 'active'
t = p.with_suffix('.tmp')
json.dump(d, open(t, 'w'), indent=2)
t.replace(p)
print('OK')
"
"""
    elif action == 'remove':
        cmd = f"""sudo python3 -c "
import json, time
from pathlib import Path
p = Path('{EXPECTED_TUNNELS_PATH}')
p.parent.mkdir(parents=True, exist_ok=True)
d = json.load(open(p)) if p.exists() else {{'origins': [], 'role': 'active', 'updated_at': 0}}
s = set(d.get('origins', []))
s.discard('{origin_id}')
d['origins'] = sorted(list(s))
d['updated_at'] = int(time.time())
if 'role' not in d:
    d['role'] = 'active'
t = p.with_suffix('.tmp')
json.dump(d, open(t, 'w'), indent=2)
t.replace(p)
print('OK')
"
"""
    else:
        logger.error(f"Invalid action: {action}")
        return False

    rc, stdout, stderr = ssh_exec(host, cmd, ssh_key_path, nodes_db=nodes_db, timeout=30)

    if rc == 0 and 'OK' in stdout:
        logger.info(f"Updated expected_tunnels.json on {host}: {action} {origin_id}")
        return True
    else:
        logger.error(
            f"Failed to update expected_tunnels.json on {host}: "
            f"action={action}, origin={origin_id}, rc={rc}, stderr={stderr}"
        )
        return False


def update_expected_tunnels_on_shard(
    origin_id: str,
    action: str,
    nodes_db: dict,
    ssh_key_path: str,
    shard_id: str = None
) -> Dict[str, bool]:
    """
    Update expected_tunnels.json on BOTH scrubbers in a shard.

    Args:
        origin_id: Origin ID (e.g., 'O1')
        action: 'add' or 'remove'
        nodes_db: Node database containing scrubber info
        ssh_key_path: Path to SSH private key
        shard_id: Optional shard ID to filter nodes

    Returns:
        Dict mapping node_name to success status
    """
    results = {}

    for node_name, node_data in nodes_db.items():
        # Filter by shard if specified
        if shard_id and node_data.get('shard_id') != shard_id:
            continue

        node_ip = node_data.get('public_ip')
        if not node_ip:
            continue

        success = update_expected_tunnels(
            host=node_ip,
            origin_id=origin_id,
            action=action,
            ssh_key_path=ssh_key_path,
            nodes_db=nodes_db
        )
        results[node_name] = success

    return results


def sync_expected_tunnels_to_node(
    target_host: str,
    origin_ids: List[str],
    role: str,
    ssh_key_path: str,
    nodes_db: dict = None
) -> bool:
    """
    Sync expected_tunnels.json to a scrubber with a specific list of origins and role.

    Used during:
    - Failover (sync to new active node with role='active')
    - Standby preconfiguration (sync to new standby with role='standby')
    - Startup reconciliation

    Args:
        target_host: Target scrubber IP address
        origin_ids: List of origin IDs that should be in the file
        role: Node role ('active' or 'standby')
        ssh_key_path: Path to SSH private key
        nodes_db: Node database for SSH user detection

    Returns:
        True if successful, False otherwise
    """
    if role not in ('active', 'standby'):
        logger.error(f"Invalid role '{role}', must be 'active' or 'standby'")
        return False

    # Use quoted heredoc ('PYEOF') to prevent ALL bash interpretation
    # Python f-string does the interpolation, bash passes content literally to python3
    origins_json = json.dumps(sorted(origin_ids))

    cmd = f"""sudo python3 << 'PYEOF'
import json, time
from pathlib import Path
p = Path("{EXPECTED_TUNNELS_PATH}")
p.parent.mkdir(parents=True, exist_ok=True)
origins = {origins_json}
d = {{"origins": origins, "role": "{role}", "updated_at": int(time.time())}}
t = p.with_suffix(".tmp")
json.dump(d, open(t, "w"), indent=2)
t.replace(p)
print("OK")
PYEOF
"""

    rc, stdout, stderr = ssh_exec(target_host, cmd, ssh_key_path, nodes_db=nodes_db, timeout=30)

    if rc == 0 and 'OK' in stdout:
        logger.info(f"Synced expected_tunnels.json to {target_host}: role={role}, origins={origin_ids}")
        return True
    else:
        logger.error(
            f"Failed to sync expected_tunnels.json to {target_host}: "
            f"rc={rc}, stderr={stderr}"
        )
        return False


def get_expected_tunnels(
    host: str,
    ssh_key_path: str,
    nodes_db: dict = None
) -> Optional[Dict[str, Any]]:
    """
    Read expected_tunnels.json from a scrubber.

    Returns:
        Dict with 'origins' (list of origin IDs) and 'role' (str), or None on error.
        Example: {"origins": ["O1", "O2"], "role": "active"}
    """
    cmd = f"cat {EXPECTED_TUNNELS_PATH} 2>/dev/null || echo '{{}}'"

    rc, stdout, stderr = ssh_exec(host, cmd, ssh_key_path, nodes_db=nodes_db, timeout=30)

    if rc != 0:
        logger.warning(f"Failed to read expected_tunnels.json from {host}: {stderr}")
        return None

    try:
        data = json.loads(stdout) if stdout.strip() else {}
        return {
            "origins": data.get('origins', []),
            "role": data.get('role', 'active')  # Default to 'active' for backwards compat
        }
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse expected_tunnels.json from {host}: {e}")
        return None


def reconcile_expected_tunnels_with_database(
    nodes_db: dict,
    origins_db: dict,
    ssh_key_path: str
) -> Dict[str, Dict]:
    """
    Reconcile expected_tunnels.json on all scrubbers with database state.

    Called during miner startup to clean up stale entries.
    Preserves the existing role when reconciling origins.

    Args:
        nodes_db: Node database
        origins_db: Origins database (source of truth)
        ssh_key_path: Path to SSH private key

    Returns:
        Dict with reconciliation results per node
    """
    results = {}

    for node_name, node_data in nodes_db.items():
        node_ip = node_data.get('public_ip')
        if not node_ip:
            continue

        shard_id = node_data.get('shard_id')

        # Get origins for this shard
        shard_origins = {
            oid for oid, odata in origins_db.items()
            if odata.get('shard_id') == shard_id
        }

        # Read current expected tunnels from scrubber (returns dict with origins and role)
        current_data = get_expected_tunnels(node_ip, ssh_key_path, nodes_db)

        if current_data is None:
            results[node_name] = {
                'status': 'error',
                'message': 'Failed to read expected_tunnels.json'
            }
            continue

        current_origins = current_data.get('origins', [])
        current_role = current_data.get('role', 'active')
        current_set = set(current_origins)

        # Calculate what should be expected (origins for this shard)
        expected_set = shard_origins

        # Find discrepancies
        orphaned = current_set - expected_set  # In file but not in DB
        missing = expected_set - current_set   # In DB but not in file

        if not orphaned and not missing:
            results[node_name] = {
                'status': 'ok',
                'origins': list(current_set),
                'role': current_role
            }
            continue

        # Sync the correct state, preserving the existing role
        logger.warning(
            f"Reconciling expected_tunnels.json on {node_name}: "
            f"orphaned={list(orphaned)}, missing={list(missing)}"
        )

        success = sync_expected_tunnels_to_node(
            target_host=node_ip,
            origin_ids=list(expected_set),
            role=current_role,  # Preserve the existing role
            ssh_key_path=ssh_key_path,
            nodes_db=nodes_db
        )

        results[node_name] = {
            'status': 'reconciled' if success else 'failed',
            'orphaned_removed': list(orphaned),
            'missing_added': list(missing),
            'final_origins': list(expected_set) if success else None
        }

    return results
