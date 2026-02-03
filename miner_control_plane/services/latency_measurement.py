"""Latency Measurement Module - Measure scrubber→exit hub latency via SSH"""
import logging
import re
from shared.database import get_db_connection
from shared.utils.ssh import ssh_exec
from shared.config import get_settings
from miner_control_plane.services.state_manager import state_manager

logger = logging.getLogger(__name__)


def measure_origin_latency(origin_id: str, origin: dict) -> float:
    """
    Measure scrubber→exit hub latency for one origin

    Returns: latency_ms or None if failed
    """
    settings = get_settings()
    db = get_db_connection()
    conn = db.conn
    cur = conn.cursor()

    try:
        # Get scrubber instance_name for this origin (state_manager uses instance_name as key)
        cur.execute("""
            SELECT n.instance_name, n.node_id
            FROM identities i
            JOIN nodes n ON i.node_id = n.node_id
            WHERE i.origin_id = %s
        """, (origin_id,))
        row = cur.fetchone()
        if not row:
            return None

        instance_name = row[0]
        node = state_manager.get_node(instance_name)
        if not node:
            return None

        scrubber_ip = node['public_ip']
        wg_interface = origin.get('wg_interface', f'wg-{origin_id}')

        # Get WireGuard peer IP by querying scrubber's wg config
        wg_cmd = f"sudo wg show {wg_interface} allowed-ips | head -1 | awk '{{print $2}}' | cut -d'/' -f1"
        rc, peer_ip, stderr = ssh_exec(
            scrubber_ip,
            wg_cmd,
            settings.ssh_key_path,
            nodes_db=state_manager.nodes_db
        )

        if rc != 0 or not peer_ip.strip():
            return None

        wg_peer_ip = peer_ip.strip().split(',')[0]  # First IP from list

        # SSH to scrubber, ping WireGuard peer IP
        ping_cmd = f"ping -c 3 -W 2 -I {wg_interface} {wg_peer_ip} 2>/dev/null | grep 'rtt min/avg/max'"

        rc, stdout, stderr = ssh_exec(
            scrubber_ip,
            ping_cmd,
            settings.ssh_key_path,
            nodes_db=state_manager.nodes_db
        )

        if rc != 0 or not stdout:
            return None

        # Parse RTT
        match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', stdout)
        if not match:
            return None

        latency_ms = float(match.group(1))

        # Store in database
        cur.execute("""
            INSERT INTO latency_measurements (origin_id, timestamp, latency_ms)
            VALUES (%s, CURRENT_TIMESTAMP, %s)
        """, (origin_id, latency_ms))

        conn.commit()
        return latency_ms

    except Exception as e:
        logger.error(f"Latency measurement failed for {origin_id}: {e}")
        return None
    finally:
        cur.close()


def measure_all_origins() -> dict:
    """
    Measure latency for all active origins

    Returns: {origin_id: latency_ms}
    """
    results = {}
    for origin_id, origin in state_manager.origins_db.items():
        latency = measure_origin_latency(origin_id, origin)
        if latency is not None:
            results[origin_id] = latency

    return results
