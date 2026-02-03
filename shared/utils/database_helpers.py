"""Database helpers

Origin database operations (create, delete, load).

Note: Uses shared.database.get_db_connection() from TensorProx.

MULTI-MINER SUPPORT:
All database operations now support optional miner_id filtering.
When miner_id is provided:
- INSERT operations include miner_id in the row
- SELECT operations filter by miner_id
- This enables multiple miners to share the same database safely

The miner_id should be obtained from miner_identity.miner_id.
"""
import json
import time
import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import psycopg2
import psycopg2.extras
from typing import Dict, Optional, Union
from shared.utils.ports import normalize_port_list
from shared.utils.logging import log_rate_limited

logger = logging.getLogger(__name__)


def db_create_origin(origin: dict, db_connection, miner_id: Optional[str] = None) -> None:
    """
    Persist Origin to database.

    Logic preserved - adapted to take db_connection parameter.
    Uses atomic origin_num calculation with retry on race condition.

    Args:
        origin: Origin data dict
        db_connection: Database connection
        miner_id: Optional miner UUID for multi-miner isolation
    """
    conn = db_connection.conn if hasattr(db_connection, 'conn') else db_connection
    cur = conn.cursor()

    # Insert into origins table with atomic origin_num calculation
    # Retry loop handles race condition where two concurrent inserts get same MAX+1
    max_retries = 5
    actual_origin_num = None

    # Build miner_id filter for origin_num calculation (scoped to this miner if multi-miner)
    miner_filter = "WHERE miner_id = %s" if miner_id else ""
    miner_filter_params = (miner_id,) if miner_id else ()

    for attempt in range(max_retries):
        try:
            # Build the INSERT query with or without miner_id
            if miner_id:
                cur.execute(f"""
                    INSERT INTO origins (
                        origin_id, origin_num, shard_id, eip, eip_alloc_id,
                        private_ip, private_ip_standby, origin_ip, exit_hub_ip,
                        shared_secret, required_ports,
                        wg_interface, wg_port,
                        edge_priv_key, edge_pub_key, hub_priv_key, hub_pub_key,
                        state, created_at, bogon_baseline, miner_id
                    ) VALUES (
                        %s,
                        (SELECT COALESCE(MAX(origin_num), 0) + 1 FROM origins {miner_filter}),
                        %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s, %s,
                        to_timestamp(%s), %s, %s
                    )
                    ON CONFLICT (origin_id) DO UPDATE SET
                        state = EXCLUDED.state,
                        eip = EXCLUDED.eip,
                        updated_at = CURRENT_TIMESTAMP
                    RETURNING origin_num
                """, (
                    origin['origin_id'],
                    *miner_filter_params,  # For the subquery
                    origin['shard_id'],
                    origin['eip'], origin['eip_alloc_id'],
                    origin['private_ip'], origin['private_ip_standby'], origin['origin_ip'], origin['exit_hub_ip'],
                    origin['shared_secret'], json.dumps(origin['required_ports']),
                    origin['wg_interface'], origin['wg_port'],
                    origin['edge_priv_key'], origin['edge_pub_key'], origin['hub_priv_key'], origin['hub_pub_key'],
                    origin['state'], origin['created_at'], origin.get('bogon_baseline', 0),
                    miner_id
                ))
            else:
                cur.execute("""
                    INSERT INTO origins (
                        origin_id, origin_num, shard_id, eip, eip_alloc_id,
                        private_ip, private_ip_standby, origin_ip, exit_hub_ip,
                        shared_secret, required_ports,
                        wg_interface, wg_port,
                        edge_priv_key, edge_pub_key, hub_priv_key, hub_pub_key,
                        state, created_at, bogon_baseline
                    ) VALUES (
                        %s,
                        (SELECT COALESCE(MAX(origin_num), 0) + 1 FROM origins),
                        %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s, %s,
                        to_timestamp(%s), %s
                    )
                    ON CONFLICT (origin_id) DO UPDATE SET
                        state = EXCLUDED.state,
                        eip = EXCLUDED.eip,
                        updated_at = CURRENT_TIMESTAMP
                    RETURNING origin_num
                """, (
                    origin['origin_id'], origin['shard_id'],
                    origin['eip'], origin['eip_alloc_id'],
                    origin['private_ip'], origin['private_ip_standby'], origin['origin_ip'], origin['exit_hub_ip'],
                    origin['shared_secret'], json.dumps(origin['required_ports']),
                    origin['wg_interface'], origin['wg_port'],
                    origin['edge_priv_key'], origin['edge_pub_key'], origin['hub_priv_key'], origin['hub_pub_key'],
                    origin['state'], origin['created_at'], origin.get('bogon_baseline', 0)
                ))
            result = cur.fetchone()
            actual_origin_num = result[0] if result else origin.get('origin_num', 1)
            break  # Success, exit retry loop

        except psycopg2.errors.UniqueViolation as e:
            if 'origins_origin_num_key' in str(e) and attempt < max_retries - 1:
                # Race condition on origin_num, retry with new MAX
                conn.rollback()
                logger.warning(f"origin_num race condition for {origin['origin_id']}, retry {attempt + 1}")
                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
                continue
            raise  # Re-raise if not origin_num issue or max retries exceeded

    if actual_origin_num is None:
        raise RuntimeError(f"Failed to insert origin {origin['origin_id']} after {max_retries} retries")

    try:
        # Insert into eips table
        cur.execute("""
            INSERT INTO eips (eip_allocation_id, public_ip, region)
            VALUES (%s, %s, %s)
            ON CONFLICT (eip_allocation_id) DO NOTHING
        """, (origin['eip_alloc_id'], origin['eip'], origin.get('region')))

        # Insert into identities table (use actual_origin_num from the INSERT RETURNING)
        cur.execute("""
            INSERT INTO identities (
                origin_id, eip_allocation_id, private_ip, private_ip_standby,
                eni_id, node_id, mark_id, in_service
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (origin_id) DO UPDATE SET
                eni_id = EXCLUDED.eni_id,
                node_id = EXCLUDED.node_id,
                in_service = EXCLUDED.in_service
        """, (
            origin['origin_id'], origin['eip_alloc_id'],
            origin['private_ip'], origin['private_ip_standby'],
            origin.get('eni_id'), origin.get('node_id'),
            actual_origin_num, origin['state'] == 'IN_SERVICE'
        ))

        # Insert into tunnels table
        cur.execute("""
            INSERT INTO tunnels (
                origin_id, wg_ifname, local_pubkey, peer_pubkey,
                endpoint, allowed_ips, mode
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (origin_id) DO UPDATE SET
                endpoint = EXCLUDED.endpoint
        """, (
            origin['origin_id'], origin['wg_interface'],
            origin['edge_pub_key'], origin['hub_pub_key'],
            f"{origin['exit_hub_ip']}:{origin['wg_port']}",
            f"{{{origin['origin_ip']}}}", 'transparent'  # PostgreSQL array format
        ))

        # Log to operations journal
        cur.execute("""
            INSERT INTO operations_journal (
                op_type, origin_id, requested_by, status
            ) VALUES (%s, %s, %s, %s)
        """, ('CREATE_ORIGIN', origin['origin_id'], 'api', 'success'))

        conn.commit()
        logger.info(f"Database: Origin {origin['origin_id']} persisted")
    except Exception as e:
        conn.rollback()
        logger.error(f"Database insert failed for {origin.get('origin_id')}: {e}")
        raise
    finally:
        cur.close()


def db_delete_origin(origin_id: str, eip_alloc_id: str, db_connection) -> None:
    """
    Delete Origin from database (CASCADE handles related tables).

    Logic preserved - adapted to take db_connection parameter.
    """
    conn = db_connection.conn if hasattr(db_connection, 'conn') else db_connection
    try:
        cur = conn.cursor()

        # Log operation
        cur.execute("""
            INSERT INTO operations_journal (
                op_type, origin_id, requested_by, status
            ) VALUES (%s, %s, %s, %s)
        """, ('DELETE_ORIGIN', origin_id, 'api', 'success'))

        # Delete from origins (CASCADE to identities, tunnels, health_origin)
        cur.execute("DELETE FROM origins WHERE origin_id = %s", (origin_id,))

        # Delete from eips (no CASCADE relationship)
        cur.execute("DELETE FROM eips WHERE eip_allocation_id = %s", (eip_alloc_id,))

        conn.commit()
        logger.info(f"Database: Origin {origin_id} and EIP {eip_alloc_id} deleted")
    except Exception as e:
        conn.rollback()
        logger.error(f"Database delete failed for {origin_id}: {e}")
        raise
    finally:
        cur.close()


def db_load_origins(db_connection, miner_id: Optional[str] = None) -> Dict[str, dict]:
    """
    Load all Origins from database into memory.

    Logic preserved - adapted to take db_connection parameter.

    Args:
        db_connection: Database connection
        miner_id: Optional miner UUID to filter origins for multi-miner isolation
    """
    conn = db_connection.conn if hasattr(db_connection, 'conn') else db_connection
    cur = None
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        if miner_id:
            cur.execute("SELECT * FROM origins WHERE miner_id = %s ORDER BY origin_num", (miner_id,))
        else:
            cur.execute("SELECT * FROM origins ORDER BY origin_num")
        rows = cur.fetchall()

        origins = {}
        for row in rows:
            origins[row['origin_id']] = {
                'origin_id': row['origin_id'],
                'origin_num': row['origin_num'],
                'shard_id': row['shard_id'],  # Multi-region: required for node lookup
                'eip': row['eip'],
                'eip_alloc_id': row['eip_alloc_id'],
                'private_ip': row['private_ip'],
                'private_ip_standby': row['private_ip_standby'],
                'origin_ip': row['origin_ip'],
                'exit_hub_ip': row['exit_hub_ip'],
                'shared_secret': row['shared_secret'],
                'required_ports': normalize_port_list(
                    json.loads(row['required_ports']) if isinstance(row['required_ports'], str) else row['required_ports']
                ),
                'wg_interface': row['wg_interface'],
                'wg_port': row['wg_port'],
                'edge_priv_key': row['edge_priv_key'],
                'edge_pub_key': row['edge_pub_key'],
                'hub_priv_key': row['hub_priv_key'],
                'hub_pub_key': row['hub_pub_key'],
                'state': row['state'],
                'created_at': row['created_at'].timestamp() if row['created_at'] else time.time()
            }

        logger.info(f"Loaded {len(origins)} origins from database")
        return origins
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass  # Connection may be closed
        logger.error(f"Failed to load origins from database: {e}")
        return {}
    finally:
        if cur:
            try:
                cur.close()
            except Exception:
                pass


def db_save_node(node: dict, db_connection, miner_id: Optional[str] = None) -> None:
    """
    Upsert node and ENI to database atomically.

    Single source of truth for node persistence.
    Based on production deployment code.

    Args:
        node: {
            'node_id': str,           # AWS instance ID (e.g., 'i-0a0d5e17d09f49ef4')
            'instance_name': str,     # 'edge-a' or 'edge-b'
            'hostname': str,          # Hostname (usually same as instance_name)
            'provider': str,          # 'aws', 'linode', 'gcp'
            'region': str,            # AWS region (e.g., 'eu-central-1')
            'status': str,            # 'active' or 'standby'
            'public_ip': str,         # Current public IP
            'private_ip': str,        # Private IP (for ENI)
            'eni_id': str,            # ENI ID (e.g., 'eni-0abcd1234')
            'instance_type': str,     # Instance type (e.g., 't3.medium') - optional
            'bandwidth_bps': int      # Baseline bandwidth in bits/sec - optional
        }
        db_connection: Database connection object
        miner_id: Optional miner UUID for multi-miner isolation
    """
    conn = db_connection.conn if hasattr(db_connection, 'conn') else db_connection
    try:
        cur = conn.cursor()

        # Insert/update node (include miner_id if provided)
        if miner_id:
            cur.execute("""
                INSERT INTO nodes (
                    node_id, instance_name, hostname, provider, az, status,
                    current_public_ip, current_public_ip_updated_at, last_seen,
                    shard_id, region, role, instance_type, bandwidth_bps, miner_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), %s, %s, %s, %s, %s, %s)
                ON CONFLICT (node_id) DO UPDATE SET
                    current_public_ip = EXCLUDED.current_public_ip,
                    current_public_ip_updated_at = NOW(),
                    status = EXCLUDED.status,
                    last_seen = NOW(),
                    shard_id = COALESCE(EXCLUDED.shard_id, nodes.shard_id),
                    region = COALESCE(EXCLUDED.region, nodes.region),
                    role = COALESCE(EXCLUDED.role, nodes.role),
                    instance_type = COALESCE(EXCLUDED.instance_type, nodes.instance_type),
                    bandwidth_bps = COALESCE(EXCLUDED.bandwidth_bps, nodes.bandwidth_bps),
                    miner_id = COALESCE(EXCLUDED.miner_id, nodes.miner_id)
            """, (
                node['node_id'],
                node['instance_name'],
                node.get('hostname', node['instance_name']),
                node['provider'],
                node.get('az', node.get('region', 'unknown')),
                node['status'],
                node['public_ip'],
                node.get('shard_id'),
                node.get('region'),
                node.get('role'),
                node.get('instance_type'),
                node.get('bandwidth_bps', 0),
                miner_id
            ))
        else:
            cur.execute("""
                INSERT INTO nodes (
                    node_id, instance_name, hostname, provider, az, status,
                    current_public_ip, current_public_ip_updated_at, last_seen,
                    shard_id, region, role, instance_type, bandwidth_bps
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), %s, %s, %s, %s, %s)
                ON CONFLICT (node_id) DO UPDATE SET
                    current_public_ip = EXCLUDED.current_public_ip,
                    current_public_ip_updated_at = NOW(),
                    status = EXCLUDED.status,
                    last_seen = NOW(),
                    shard_id = COALESCE(EXCLUDED.shard_id, nodes.shard_id),
                    region = COALESCE(EXCLUDED.region, nodes.region),
                    role = COALESCE(EXCLUDED.role, nodes.role),
                    instance_type = COALESCE(EXCLUDED.instance_type, nodes.instance_type),
                    bandwidth_bps = COALESCE(EXCLUDED.bandwidth_bps, nodes.bandwidth_bps)
            """, (
                node['node_id'],
                node['instance_name'],
                node.get('hostname', node['instance_name']),
                node['provider'],
                node.get('az', node.get('region', 'unknown')),
                node['status'],
                node['public_ip'],
                node.get('shard_id'),
                node.get('region'),
                node.get('role'),
                node.get('instance_type'),
                node.get('bandwidth_bps', 0)
            ))

        # Insert ENI (idempotent)
        cur.execute("""
            INSERT INTO enis (eni_id, node_id, region, primary_private_ip)
            VALUES (%s, %s, %s, %s::inet)
            ON CONFLICT (eni_id) DO NOTHING
        """, (
            node['eni_id'],
            node['node_id'],
            node.get('region', 'unknown'),
            node['private_ip']
        ))

        conn.commit()
        logger.info(
            f"Saved node {node['instance_name']} "
            f"(node_id={node['node_id']}, eni_id={node['eni_id']})"
        )
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to save node {node.get('instance_name', 'unknown')}: {e}")
        raise
    finally:
        cur.close()


def db_delete_node(node_id: str, db_connection) -> None:
    """
    Delete node and ENI from database (respects FK constraints).

    Single source of truth for node deletion.
    Deletes ENI first to respect foreign key constraints.

    Args:
        node_id: Node ID (AWS instance ID)
        db_connection: Database connection object
    """
    conn = db_connection.conn if hasattr(db_connection, 'conn') else db_connection
    try:
        cur = conn.cursor()

        # Delete ENI first (FK constraint: eni.node_id references nodes.node_id)
        cur.execute("DELETE FROM enis WHERE node_id = %s", (node_id,))

        # Then delete node
        cur.execute("DELETE FROM nodes WHERE node_id = %s", (node_id,))

        conn.commit()
        logger.info(f"Deleted node {node_id} and associated ENI")
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to delete node {node_id}: {e}")
        raise
    finally:
        cur.close()


def load_edge_nodes_from_database(db_connection, refresh_ip_func=None, miner_id: Optional[str] = None) -> Dict[str, dict]:
    """
    Load edge nodes from database, keyed by instance_name.

    Logic preserved - adapted to take db_connection and optional refresh function.

    Args:
        db_connection: Database connection
        refresh_ip_func: Optional function to refresh stale IPs from AWS
        miner_id: Optional miner UUID to filter nodes for multi-miner isolation
    """
    conn = db_connection.conn if hasattr(db_connection, 'conn') else db_connection
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        if miner_id:
            cur.execute("""
                SELECT n.node_id, n.instance_name, n.current_public_ip, n.current_public_ip_updated_at,
                       n.provider, n.role, n.shard_id, n.region, n.instance_type, n.bandwidth_bps,
                       e.eni_id, e.primary_private_ip
                FROM nodes n
                LEFT JOIN enis e ON n.node_id = e.node_id
                WHERE n.status = 'active' AND n.miner_id = %s
                ORDER BY n.instance_name
            """, (miner_id,))
        else:
            cur.execute("""
                SELECT n.node_id, n.instance_name, n.current_public_ip, n.current_public_ip_updated_at,
                       n.provider, n.role, n.shard_id, n.region, n.instance_type, n.bandwidth_bps,
                       e.eni_id, e.primary_private_ip
                FROM nodes n
                LEFT JOIN enis e ON n.node_id = e.node_id
                WHERE n.status = 'active'
                ORDER BY n.instance_name
            """)
        rows = cur.fetchall()
        cur.close()

        edge_nodes_db = {}

        for row in rows:
            node_id = row['node_id']
            instance_name = row['instance_name']

            # Get current IP (refresh from AWS if refresh function provided and IP is stale)
            public_ip = row['current_public_ip']
            if refresh_ip_func and row['current_public_ip_updated_at']:
                public_ip = refresh_ip_func(
                    node_id=node_id,
                    instance_name=instance_name,
                    current_ip=row['current_public_ip'],
                    updated_at=row['current_public_ip_updated_at'],
                    region=row.get('region')
                )
            elif not public_ip:
                logger.warning(f"No public IP for {instance_name}")

            # Key by node_id to match add_node() and get_active_node() expectations
            edge_nodes_db[node_id] = {
                'instance_id': node_id,
                'node_id': node_id,
                'instance_name': instance_name,
                'public_ip': public_ip,
                'private_ip': row['primary_private_ip'],
                'eni_id': row['eni_id'],
                'provider': row['provider'],  # Include provider for SSH user resolution
                'role': row['role'],  # active or standby
                'shard_id': row['shard_id'],
                'region': row['region'],
                'instance_type': row.get('instance_type'),
                'bandwidth_bps': row.get('bandwidth_bps', 0)
            }

        # Rate-limited logging: only log if count changed or 60s elapsed
        node_count = len(edge_nodes_db)
        log_rate_limited(
            "db_loaded_nodes",
            logger.info,
            f"Loaded {node_count} edge nodes: {list(edge_nodes_db.keys())}",
            value=node_count
        )
        return edge_nodes_db

    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass  # Connection may be closed
        logger.error(f"Failed to load nodes from database: {e}")
        return {}


def cleanup_sqlite_resources(db_path: Union[str, Path], max_age_hours: int = 24) -> int:
    """
    Remove terminated resource rows that are older than the configured retention window.

    Args:
        db_path: Path to the SQLite database file (e.g., /tmp/tensorprox/traffic_manager.db)
        max_age_hours: Retention period for terminated rows (default: 24h)

    Returns:
        Number of rows deleted.
    """
    path = Path(db_path)
    if not path.exists():
        return 0

    cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
    cutoff_iso = cutoff.isoformat()

    try:
        with sqlite3.connect(path) as conn:
            cursor = conn.execute(
                """
                DELETE FROM resources
                WHERE LOWER(status) = 'terminated'
                  AND updated_at < ?
                """,
                (cutoff_iso,)
            )
            conn.commit()
            deleted = cursor.rowcount or 0
            if deleted:
                logger.info("SQLite cleanup removed %s terminated resources older than %sh", deleted, max_age_hours)
            return deleted
    except sqlite3.Error as exc:
        logger.error(f"SQLite cleanup failed for {path}: {exc}")
        return 0
