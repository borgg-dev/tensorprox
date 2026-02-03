"""
Startup Cleanup and Initialization Services

This module contains all startup routines that ensure the miner
starts with a clean, synchronized state across all scrubbers AND
has all required database configuration seeded.

Functions:
- seed_required_config: Ensure all required config rows exist in database
- cleanup_orphaned_bpf_maps: Clean eip_map entries for deleted origins
- cleanup_orphaned_wg2priv_map: Clean wg2priv_map entries for removed WG interfaces
- reconcile_expected_tunnels: Sync expected_tunnels.json with database
- fix_node_miner_id_consistency: Ensure nodes have same miner_id as their shard
- reconcile_shard_states: Ensure shard_state entries exist for all shards
- run_all_startup_cleanup: Run all cleanup routines in order
"""
import json
import socket
import struct
from shared.config import get_settings
from shared.database import get_db_connection
from shared.utils.ssh import ssh_exec
from shared.utils.logging import get_logger
from miner_control_plane.services.state_manager import state_manager
from miner_control_plane.services.bpf_map_cleaner import clean_origin_bpf_maps

logger = get_logger(__name__)


def ensure_miner_id_columns() -> None:
    """
    Ensure required columns exist on core tables for multi-miner isolation and shard types.

    This function is idempotent - safe to run on every startup.
    Uses ALTER TABLE ... ADD COLUMN IF NOT EXISTS.

    Columns added:
    - miner_id (UUID): Multi-miner isolation on shards, nodes, origins, deployment_jobs
    - shard_type (VARCHAR): Distinguishes 'audit' vs 'production' shards

    This enables multiple miners to share the same ecp_state database
    while keeping their data isolated.
    """
    try:
        db = get_db_connection()
        cur = db.conn.cursor()

        columns_added = 0

        # Add miner_id columns (idempotent)
        tables = ['shards', 'nodes', 'origins', 'deployment_jobs']
        for table in tables:
            try:
                cur.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS miner_id UUID")
                columns_added += 1
            except Exception as e:
                logger.warning(f"Failed to add miner_id to {table}: {e}")
                db.conn.rollback()

        # Add shard_type column to shards table (idempotent)
        # 'audit' = validator scoring shards, 'production' = customer origin shards
        try:
            cur.execute("ALTER TABLE shards ADD COLUMN IF NOT EXISTS shard_type VARCHAR(20) DEFAULT 'audit'")
            columns_added += 1
        except Exception as e:
            logger.warning(f"Failed to add shard_type to shards: {e}")
            db.conn.rollback()

        # Create indexes for efficient miner-filtered queries (idempotent)
        indexes = [
            ("idx_shards_miner_id", "shards", "miner_id"),
            ("idx_shards_miner_type", "shards", "miner_id, shard_type"),
            ("idx_nodes_miner_id", "nodes", "miner_id"),
            ("idx_origins_miner_id", "origins", "miner_id"),
            ("idx_deployment_jobs_miner_id", "deployment_jobs", "miner_id"),
            ("idx_shards_miner_region", "shards", "miner_id, region"),
            ("idx_nodes_miner_shard", "nodes", "miner_id, shard_id"),
            ("idx_origins_miner_shard", "origins", "miner_id, shard_id"),
            ("idx_origins_miner_state", "origins", "miner_id, state"),
            ("idx_deployment_jobs_miner_state", "deployment_jobs", "miner_id, state"),
        ]

        indexes_created = 0
        for index_name, table, columns in indexes:
            try:
                cur.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table}({columns})")
                indexes_created += 1
            except Exception as e:
                logger.warning(f"Failed to create index {index_name}: {e}")
                db.conn.rollback()

        db.conn.commit()
        cur.close()

        logger.info(f"Schema migration complete: {columns_added} columns verified, {indexes_created} indexes verified")

    except Exception as e:
        logger.error(f"Schema migration failed: {e}", exc_info=True)


def seed_required_config() -> None:
    """
    Ensure all required configuration rows exist in the database.

    This function is idempotent - safe to run on every startup.
    Uses INSERT ... ON CONFLICT DO NOTHING to avoid overwriting existing config.

    Required config tables:
    - anomaly_detection_config: Global anomaly detection parameters (config_id=1)

    This solves the issue where:
    - schema.sql has INSERT statements for default config
    - But init-database.sh only runs on fresh database creation
    - When miner restarts after cleanup, the config rows may be missing
    """
    try:
        db = get_db_connection()
        cur = db.conn.cursor()

        seeded_count = 0

        # Seed anomaly_detection_config (config_id=1)
        # Uses column defaults from schema for all 27+ parameters
        cur.execute("""
            INSERT INTO anomaly_detection_config (config_id)
            VALUES (1)
            ON CONFLICT (config_id) DO NOTHING
        """)
        if cur.rowcount > 0:
            seeded_count += 1
            logger.info("Seeded anomaly_detection_config with default values")

        db.conn.commit()
        cur.close()

        if seeded_count > 0:
            logger.info(f"Database seeding complete: {seeded_count} config rows created")
        else:
            logger.debug("Database seeding: all required config already exists")

    except Exception as e:
        logger.error(f"Database seeding failed: {e}", exc_info=True)


def ensure_database_indexes() -> None:
    """
    Ensure all required database indexes exist for query performance.

    SCALABILITY FIX: Creates indexes on frequently queried columns to optimize:
    - Time-series lookups (origin_id + timestamp)
    - State lookups (origin_id for current state)
    - Batch queries (DISTINCT ON patterns)

    This function is idempotent - CREATE INDEX IF NOT EXISTS is safe to run
    on every startup.

    Indexes created:
    - origin_metrics: (origin_id, timestamp DESC) - for time-series queries
    - latency_measurements: (origin_id, timestamp DESC) - for latency history
    - traffic_baselines: (origin_id, is_current) - for current baseline lookup
    - anomaly_detection_state: (origin_id) - for state lookup
    - attack_events: (origin_id, detected_at DESC) - for attack history
    - syncookie_metrics: (vip_ip, timestamp DESC) - for metric lookup
    - health_node: (node_id, last_seen DESC) - for health monitoring
    """
    try:
        db = get_db_connection()
        cur = db.conn.cursor()

        indexes_created = 0

        # List of indexes to ensure exist
        # Format: (index_name, table_name, column_expr)
        indexes = [
            # origin_metrics: primary time-series lookup
            (
                "idx_origin_metrics_origin_timestamp",
                "origin_metrics",
                "origin_id, timestamp DESC"
            ),
            # latency_measurements: latency history lookup
            (
                "idx_latency_measurements_origin_timestamp",
                "latency_measurements",
                "origin_id, timestamp DESC"
            ),
            # traffic_baselines: current baseline lookup
            (
                "idx_traffic_baselines_origin_current",
                "traffic_baselines",
                "origin_id, is_current"
            ),
            # anomaly_detection_state: state lookup by origin
            (
                "idx_anomaly_detection_state_origin",
                "anomaly_detection_state",
                "origin_id"
            ),
            # attack_events: attack history by origin
            (
                "idx_attack_events_origin_detected",
                "attack_events",
                "origin_id, detected_at DESC"
            ),
            # syncookie_metrics: metric lookup by VIP
            (
                "idx_syncookie_metrics_vip_timestamp",
                "syncookie_metrics",
                "vip_ip, timestamp DESC"
            ),
            # health_node: health check lookups
            (
                "idx_health_node_node_lastseen",
                "health_node",
                "node_id, last_seen DESC"
            ),
            # origins: shard-based lookups
            (
                "idx_origins_shard",
                "origins",
                "shard_id"
            ),
            # nodes: shard-based lookups
            (
                "idx_nodes_shard",
                "nodes",
                "shard_id"
            ),
        ]

        for index_name, table_name, columns in indexes:
            try:
                cur.execute(f"""
                    CREATE INDEX IF NOT EXISTS {index_name}
                    ON {table_name} ({columns})
                """)
                # Check if index was just created (rowcount doesn't work for DDL)
                # We just log that we attempted to create it
                indexes_created += 1
            except Exception as idx_err:
                # Index may fail if table doesn't exist - this is OK
                # Table may be in a different schema or not yet created
                if "does not exist" in str(idx_err):
                    logger.debug(f"Table {table_name} not found, skipping index {index_name}")
                else:
                    logger.warning(f"Failed to create index {index_name}: {idx_err}")

        db.conn.commit()
        cur.close()

        if indexes_created > 0:
            logger.info(f"Database indexes verified: {indexes_created} indexes checked/created")
        else:
            logger.debug("Database indexes: all indexes already exist")

    except Exception as e:
        logger.error(f"Database index creation failed: {e}", exc_info=True)


def cleanup_orphaned_bpf_maps() -> None:
    """
    Detect and clean orphaned BPF map entries for deleted origins.

    Queries eip_map from scrubbers and cleans entries for origins that no longer
    exist in the database. Uses the robust miner-based cleanup function that
    provides verified deletion without scrubber script dependencies.
    """
    try:
        settings = get_settings()

        # Only proceed if we have scrubbers
        if not state_manager.nodes_db:
            logger.debug("No scrubbers available for orphan cleanup")
            return

        # Load valid origins from database
        db = get_db_connection()
        cur = db.conn.cursor()
        cur.execute("SELECT origin_ip FROM origins WHERE origin_ip IS NOT NULL")
        valid_ips = {row[0] for row in cur.fetchall()}
        cur.close()
        db.close()

        logger.info(
            f"Checking for orphaned BPF map entries "
            f"({len(valid_ips)} valid origins in database)"
        )

        # Find a scrubber to query eip_map
        scrubber_ip = None
        for node_name, node_data in state_manager.nodes_db.items():
            if node_data.get('role') == 'active':
                scrubber_ip = node_data['public_ip']
                break

        if not scrubber_ip:
            logger.warning("No active scrubber available for orphan detection")
            return

        # Dump eip_map to find entries
        logger.debug(f"Dumping eip_map from scrubber at {scrubber_ip}...")
        rc, stdout, stderr = ssh_exec(
            scrubber_ip,
            "sudo bpftool map dump pinned /sys/fs/bpf/tc/globals/eip_map -j",
            settings.ssh_key_path,
            nodes_db=state_manager.nodes_db,
            timeout=60
        )

        if rc != 0:
            if "No such file or directory" in stderr or "not found" in stderr.lower():
                logger.info(f"eip_map not found on scrubber (OK if no origins deployed)")
            else:
                logger.warning(f"Could not dump eip_map: {stderr}")
            return

        try:
            eip_entries = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse eip_map output: {e}")
            return

        if not eip_entries:
            logger.info("No entries in eip_map (no orphans to clean)")
            return

        logger.info(f"Found {len(eip_entries)} entries in eip_map, checking for orphans...")

        # Check each entry and clean if orphaned
        orphaned_count = 0
        cleaned_count = 0

        for entry in eip_entries:
            try:
                formatted = entry.get('formatted', {})
                key_int = formatted.get('key')
                value = formatted.get('value', {})
                origin_ip_int = value.get('origin_ip')

                if key_int is None or origin_ip_int is None:
                    continue

                # eip_map structure:
                #   key = private_ip (scrubber's internal IP, e.g., 10.0.1.50)
                #   value.origin_ip = origin_ip (customer's real IP, e.g., 97.107.129.10)
                private_ip_bytes = struct.pack('<I', key_int)
                private_ip = socket.inet_ntoa(private_ip_bytes)

                origin_ip_bytes = struct.pack('<I', origin_ip_int)
                origin_ip = socket.inet_ntoa(origin_ip_bytes)

                # Check if origin_ip exists in database
                if origin_ip in valid_ips:
                    logger.debug(f"Origin {origin_ip} (private_ip={private_ip}) is valid")
                    continue

                # This is an orphaned entry - clean it
                orphaned_count += 1
                logger.warning(f"Found orphaned entry: origin_ip={origin_ip}, private_ip={private_ip}")

                # Create minimal origin object for cleanup function
                mock_origin = {
                    'origin_id': f'orphan-{origin_ip}',
                    'origin_ip': origin_ip,
                    'private_ip': private_ip,
                    'private_ip_standby': None,
                    'wg_interface': 'unknown'
                }

                # Use the robust cleanup function
                cleanup_result = clean_origin_bpf_maps(
                    mock_origin['origin_id'],
                    mock_origin,
                    state_manager.nodes_db,
                    settings.ssh_key_path,
                    settings,
                    verify=True
                )

                if cleanup_result['success']:
                    cleaned_count += 1
                    logger.info(f"✓ Cleaned orphaned entry: origin_ip={origin_ip}, private_ip={private_ip}")
                else:
                    logger.warning(
                        f"Partial cleanup for origin_ip={origin_ip}, private_ip={private_ip}: {cleanup_result['errors']}"
                    )

            except Exception as e:
                logger.error(f"Error processing entry: {e}", exc_info=True)
                continue

        # Summary
        if orphaned_count == 0:
            logger.info("No orphaned BPF map entries detected")
        else:
            logger.warning(
                f"ORPHAN CLEANUP: Found {orphaned_count} orphaned entries, "
                f"successfully cleaned {cleaned_count}"
            )

    except Exception as e:
        logger.error(f"Orphan cleanup failed: {e}", exc_info=True)


def cleanup_orphaned_wg2priv_map() -> None:
    """
    Detect and clean orphaned wg2priv_map entries for removed WireGuard interfaces.

    wg2priv_map is keyed by ifindex (interface index). When a WireGuard interface
    is removed, the ifindex is freed but the map entry remains. This function:
    1. Dumps wg2priv_map from each scrubber to get all ifindex keys
    2. Queries active WireGuard interfaces on each scrubber
    3. Deletes entries where the ifindex doesn't match any existing interface
    """
    try:
        settings = get_settings()

        # Only proceed if we have scrubbers
        if not state_manager.nodes_db:
            logger.debug("No scrubbers available for wg2priv_map orphan cleanup")
            return

        logger.info("Checking for orphaned wg2priv_map entries...")

        total_orphaned = 0
        total_cleaned = 0

        # Process each scrubber
        for node_name, node_data in state_manager.nodes_db.items():
            node_ip = node_data.get('public_ip')
            if not node_ip:
                continue

            try:
                # Step 1: Get all active WireGuard interface ifindexes on this scrubber
                rc, stdout, stderr = ssh_exec(
                    node_ip,
                    "ip -j link show type wireguard 2>/dev/null || echo '[]'",
                    settings.ssh_key_path,
                    nodes_db=state_manager.nodes_db,
                    timeout=30
                )

                active_ifindexes = set()
                if rc == 0 and stdout.strip():
                    try:
                        interfaces = json.loads(stdout)
                        for iface in interfaces:
                            if 'ifindex' in iface:
                                active_ifindexes.add(iface['ifindex'])
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse WireGuard interfaces on {node_name}")

                logger.debug(
                    f"{node_name}: Found {len(active_ifindexes)} active WireGuard interfaces"
                )

                # Step 2: Dump wg2priv_map to find all entries
                rc, stdout, stderr = ssh_exec(
                    node_ip,
                    "sudo bpftool map dump pinned /sys/fs/bpf/tc/globals/wg2priv_map -j",
                    settings.ssh_key_path,
                    nodes_db=state_manager.nodes_db,
                    timeout=60
                )

                if rc != 0:
                    if "No such file" in stderr or "not found" in stderr.lower():
                        logger.debug(f"wg2priv_map not found on {node_name} (OK if no origins)")
                    else:
                        logger.warning(f"Could not dump wg2priv_map on {node_name}: {stderr}")
                    continue

                try:
                    wg2priv_entries = json.loads(stdout) if stdout.strip() else []
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse wg2priv_map on {node_name}: {e}")
                    continue

                if not wg2priv_entries:
                    logger.debug(f"No entries in wg2priv_map on {node_name}")
                    continue

                logger.info(
                    f"{node_name}: Found {len(wg2priv_entries)} wg2priv_map entries, "
                    f"checking for orphans..."
                )

                # Step 3: Check each entry and delete orphans
                for entry in wg2priv_entries:
                    try:
                        formatted = entry.get('formatted', {})
                        ifindex = formatted.get('key')
                        if ifindex is None:
                            continue

                        # Check if this ifindex corresponds to an active interface
                        if ifindex in active_ifindexes:
                            logger.debug(f"ifindex {ifindex} is valid on {node_name}")
                            continue

                        # This is an orphaned entry - delete it
                        total_orphaned += 1
                        logger.warning(
                            f"Found orphaned wg2priv_map entry: ifindex={ifindex} on {node_name}"
                        )

                        # Convert ifindex to hex for bpftool (4-byte little-endian)
                        ifindex_hex = ' '.join(
                            f'{b:02x}' for b in ifindex.to_bytes(4, byteorder='little')
                        )

                        rc_del, _, stderr_del = ssh_exec(
                            node_ip,
                            f"sudo bpftool map delete pinned "
                            f"/sys/fs/bpf/tc/globals/wg2priv_map key hex {ifindex_hex}",
                            settings.ssh_key_path,
                            nodes_db=state_manager.nodes_db,
                            timeout=30
                        )

                        if rc_del == 0:
                            total_cleaned += 1
                            logger.info(
                                f"✓ Cleaned orphaned wg2priv_map[{ifindex}] on {node_name}"
                            )
                        else:
                            logger.warning(
                                f"Failed to delete wg2priv_map[{ifindex}] on {node_name}: "
                                f"{stderr_del}"
                            )

                    except Exception as e:
                        logger.error(f"Error processing wg2priv_map entry: {e}")
                        continue

            except Exception as e:
                logger.error(f"wg2priv_map cleanup failed for {node_name}: {e}")
                continue

        # Summary
        if total_orphaned == 0:
            logger.info("No orphaned wg2priv_map entries detected")
        else:
            logger.warning(
                f"WG2PRIV CLEANUP: Found {total_orphaned} orphaned entries, "
                f"successfully cleaned {total_cleaned}"
            )

    except Exception as e:
        logger.error(f"wg2priv_map orphan cleanup failed: {e}", exc_info=True)


def cleanup_orphaned_wireguard_interfaces() -> None:
    """
    Detect and remove orphaned WireGuard interfaces (wgO*) that don't correspond
    to any origin in the database.

    This handles the case where:
    - An origin deletion failed partway through (WG interface not deleted)
    - Miner crashed before completing cleanup
    - Manual intervention left stale interfaces
    """
    try:
        settings = get_settings()

        # Only proceed if we have scrubbers
        if not state_manager.nodes_db:
            logger.debug("No scrubbers available for WireGuard orphan cleanup")
            return

        # Get valid origin WireGuard interface names from database
        db = get_db_connection()
        cur = db.conn.cursor()
        cur.execute("SELECT wg_interface FROM origins WHERE wg_interface IS NOT NULL")
        valid_interfaces = {row[0] for row in cur.fetchall()}
        cur.close()
        db.close()

        logger.info(
            f"Checking for orphaned WireGuard interfaces "
            f"({len(valid_interfaces)} valid interfaces in database)"
        )

        total_orphaned = 0
        total_cleaned = 0

        # Check each scrubber
        for node_name, node_data in state_manager.nodes_db.items():
            node_ip = node_data.get('public_ip')
            if not node_ip:
                continue

            try:
                # Get all WireGuard interfaces on this scrubber
                rc, stdout, stderr = ssh_exec(
                    node_ip,
                    "ip link show type wireguard 2>/dev/null | grep -oE 'wgO[0-9]+' || true",
                    settings.ssh_key_path,
                    nodes_db=state_manager.nodes_db,
                    timeout=30
                )

                if rc != 0:
                    logger.warning(f"Failed to list WireGuard interfaces on {node_name}")
                    continue

                scrubber_interfaces = set(stdout.strip().split()) if stdout.strip() else set()

                if not scrubber_interfaces:
                    logger.debug(f"No WireGuard interfaces on {node_name}")
                    continue

                # Find orphaned interfaces (on scrubber but not in database)
                orphaned = scrubber_interfaces - valid_interfaces

                if not orphaned:
                    logger.debug(f"{node_name}: All {len(scrubber_interfaces)} interfaces are valid")
                    continue

                logger.warning(
                    f"{node_name}: Found {len(orphaned)} orphaned WireGuard interfaces: {orphaned}"
                )

                # Remove each orphaned interface
                for iface in orphaned:
                    total_orphaned += 1
                    try:
                        # Remove TC qdisc first (if exists)
                        ssh_exec(
                            node_ip,
                            f"sudo tc qdisc del dev {iface} clsact 2>/dev/null || true",
                            settings.ssh_key_path,
                            nodes_db=state_manager.nodes_db,
                            timeout=30
                        )

                        # Delete the interface
                        rc_del, _, stderr_del = ssh_exec(
                            node_ip,
                            f"sudo ip link delete {iface}",
                            settings.ssh_key_path,
                            nodes_db=state_manager.nodes_db,
                            timeout=30
                        )

                        if rc_del == 0:
                            total_cleaned += 1
                            logger.info(f"✓ Removed orphaned interface {iface} on {node_name}")
                        else:
                            logger.warning(
                                f"Failed to delete {iface} on {node_name}: {stderr_del}"
                            )

                        # Also remove config file if exists
                        ssh_exec(
                            node_ip,
                            f"sudo rm -f /etc/wireguard/{iface}.conf",
                            settings.ssh_key_path,
                            nodes_db=state_manager.nodes_db,
                            timeout=30
                        )

                    except Exception as e:
                        logger.error(f"Error removing orphaned interface {iface}: {e}")

            except Exception as e:
                logger.error(f"WireGuard cleanup failed for {node_name}: {e}")
                continue

        # Summary
        if total_orphaned == 0:
            logger.info("No orphaned WireGuard interfaces detected")
        else:
            logger.warning(
                f"WIREGUARD CLEANUP: Found {total_orphaned} orphaned interfaces, "
                f"successfully removed {total_cleaned}"
            )

    except Exception as e:
        logger.error(f"WireGuard orphan cleanup failed: {e}", exc_info=True)


def backfill_missing_enis() -> None:
    """
    Find nodes missing ENI records and backfill from AWS.

    This handles the case where nodes were recovered or synced to the database
    but their ENI records weren't created. Without ENI records, shard capacity
    checks fail with "nodes missing ENI IDs".

    Process:
    1. Find nodes with no corresponding ENI record (for THIS miner only)
    2. For each missing node, fetch ENI info from AWS
    3. Insert the missing ENI record
    """
    try:
        from shared.node import Node
        from miner_control_plane.services.miner_identity import miner_identity

        settings = get_settings()
        db = get_db_connection()
        cur = db.conn.cursor()

        # Get current miner_id - only backfill ENIs for this miner's nodes
        current_miner_id = miner_identity.miner_id
        if not current_miner_id:
            logger.warning("No miner_id available, skipping ENI backfill")
            db.close()
            return

        # Find nodes without ENI records (filtered by miner_id)
        cur.execute("""
            SELECT n.node_id, n.region, n.provider
            FROM nodes n
            LEFT JOIN enis e ON n.node_id = e.node_id
            WHERE e.eni_id IS NULL AND n.status = 'active' AND n.miner_id = %s
        """, (current_miner_id,))
        nodes_missing_enis = cur.fetchall()
        cur.close()

        if not nodes_missing_enis:
            logger.debug("All nodes have ENI records")
            db.close()
            return

        logger.warning(
            f"Found {len(nodes_missing_enis)} nodes missing ENI records, backfilling..."
        )

        backfilled = 0
        failed = 0

        for node_id, region, provider in nodes_missing_enis:
            try:
                if provider != 'aws':
                    logger.debug(f"Skipping non-AWS node {node_id} (provider={provider})")
                    continue

                # Use Node class to fetch ENI info
                node = Node(node_type="scrubber", region=region)
                eni_id = node.get_primary_eni_id(node_id)

                if not eni_id:
                    logger.warning(f"Could not fetch ENI ID for node {node_id}")
                    failed += 1
                    continue

                # Get private IP from AWS
                enis = node.provider.describe_network_interfaces(node_id, region=region)
                private_ip = None
                for eni in enis:
                    if eni['device_index'] == 0:
                        private_ip = eni.get('private_ip_address')
                        break

                if not private_ip:
                    logger.warning(f"Could not get private IP for node {node_id}")
                    failed += 1
                    continue

                # Insert ENI record
                cur = db.conn.cursor()
                cur.execute("""
                    INSERT INTO enis (eni_id, node_id, region, primary_private_ip)
                    VALUES (%s, %s, %s, %s::inet)
                    ON CONFLICT (eni_id) DO NOTHING
                """, (eni_id, node_id, region, private_ip))
                db.conn.commit()
                cur.close()

                backfilled += 1
                logger.info(f"Backfilled ENI for node {node_id}: eni_id={eni_id}, private_ip={private_ip}")

            except Exception as e:
                logger.error(f"Failed to backfill ENI for node {node_id}: {e}")
                failed += 1
                db.conn.rollback()

        db.close()

        if backfilled > 0 or failed > 0:
            logger.warning(
                f"ENI backfill complete: {backfilled} backfilled, {failed} failed"
            )

    except Exception as e:
        logger.error(f"ENI backfill failed: {e}", exc_info=True)


def validate_and_refresh_enis() -> None:
    """
    Validate existing ENI records against AWS and refresh stale ones.

    ENI IDs can become stale after:
    - Instance termination and recreation during failover
    - Manual instance replacement
    - Region migration

    This function:
    1. Gets all ENI records for this miner's active nodes
    2. For each ENI, verifies it exists in AWS
    3. If invalid, fetches the correct ENI ID from the instance
    4. Updates the database with the correct ENI ID and private IP

    Must run AFTER backfill_missing_enis() but BEFORE any operations
    that use ENI IDs (e.g., origin registration, capacity checks).
    """
    from shared.node import Node
    from miner_control_plane.services.miner_identity import miner_identity

    try:
        db = get_db_connection()
        cur = db.conn.cursor()

        # Get current miner_id
        current_miner_id = miner_identity.miner_id
        if not current_miner_id:
            logger.warning("No miner_id available, skipping ENI validation")
            db.close()
            return

        # Get all ENI records for this miner's active nodes
        cur.execute("""
            SELECT e.eni_id, e.node_id, e.region, n.provider
            FROM enis e
            JOIN nodes n ON e.node_id = n.node_id
            WHERE n.status = 'active' AND n.miner_id = %s
        """, (current_miner_id,))
        eni_records = cur.fetchall()
        cur.close()

        if not eni_records:
            logger.debug("No ENI records to validate")
            db.close()
            return

        logger.info(f"Validating {len(eni_records)} ENI records against AWS...")

        validated = 0
        refreshed = 0
        failed = 0

        for eni_id, node_id, region, provider in eni_records:
            try:
                if provider != 'aws':
                    logger.debug(f"Skipping non-AWS node {node_id} (provider={provider})")
                    validated += 1
                    continue

                # Try to describe the ENI in AWS
                node = Node(node_type="scrubber", region=region)

                try:
                    enis = node.provider.describe_network_interfaces_by_id([eni_id], region=region)
                    if enis:
                        # ENI exists and is valid
                        validated += 1
                        continue
                except Exception as describe_err:
                    logger.warning(
                        f"ENI {eni_id} for node {node_id} is invalid: {describe_err}"
                    )

                # ENI is invalid - fetch the correct one from the instance
                logger.info(f"Refreshing stale ENI for node {node_id} in {region}...")

                # Get the actual ENI ID from the instance
                actual_eni_id = node.get_primary_eni_id(node_id)
                if not actual_eni_id:
                    logger.error(f"Could not fetch ENI ID for node {node_id}")
                    failed += 1
                    continue

                # Get private IP from the actual ENI
                actual_enis = node.provider.describe_network_interfaces(node_id, region=region)
                private_ip = None
                for eni in actual_enis:
                    if eni['device_index'] == 0:
                        private_ip = eni.get('private_ip_address')
                        break

                if not private_ip:
                    logger.warning(f"Could not get private IP for node {node_id}")
                    failed += 1
                    continue

                # Update the ENI record in the database
                cur = db.conn.cursor()
                cur.execute("""
                    UPDATE enis
                    SET eni_id = %s, primary_private_ip = %s::inet
                    WHERE node_id = %s
                """, (actual_eni_id, private_ip, node_id))
                db.conn.commit()
                cur.close()

                refreshed += 1
                logger.info(
                    f"Refreshed ENI for node {node_id}: "
                    f"old={eni_id} -> new={actual_eni_id}, private_ip={private_ip}"
                )

            except Exception as e:
                logger.error(f"Failed to validate/refresh ENI for node {node_id}: {e}")
                failed += 1
                db.conn.rollback()

        db.close()

        if refreshed > 0 or failed > 0:
            logger.warning(
                f"ENI validation complete: {validated} valid, {refreshed} refreshed, {failed} failed"
            )
        else:
            logger.info(f"ENI validation complete: all {validated} ENIs are valid")

    except Exception as e:
        logger.error(f"ENI validation failed: {e}", exc_info=True)


def fix_node_miner_id_consistency() -> None:
    """
    Ensure nodes have the same miner_id as their shard.

    In a multi-miner environment sharing a database, nodes should always have
    the same miner_id as their parent shard. This can get out of sync if:
    - A node was created before miner_id isolation was implemented
    - A node was manually inserted or migrated
    - Multiple miners accidentally created nodes in the same shard

    This function fixes inconsistencies by updating node.miner_id to match
    the shard.miner_id for all mismatched nodes.

    Must run BEFORE reconcile_shard_states() since that function joins on miner_id.
    """
    try:
        db = get_db_connection()
        cur = db.conn.cursor()

        # Find and fix nodes with inconsistent miner_id
        cur.execute("""
            UPDATE nodes n
            SET miner_id = s.miner_id
            FROM shards s
            WHERE n.shard_id = s.shard_id
              AND (n.miner_id IS NULL OR n.miner_id != s.miner_id)
            RETURNING n.node_id, n.shard_id, s.miner_id
        """)
        fixed_nodes = cur.fetchall()

        if fixed_nodes:
            logger.warning(
                f"Fixed miner_id for {len(fixed_nodes)} nodes to match their shard: "
                f"{[(n[0], n[1]) for n in fixed_nodes]}"
            )
            db.conn.commit()
        else:
            logger.debug("All nodes have consistent miner_id with their shard")

        cur.close()
        db.close()

    except Exception as e:
        logger.error(f"Node miner_id consistency fix failed: {e}", exc_info=True)


def reconcile_shard_states() -> None:
    """
    Ensure shard_state entries exist for all shards that have nodes.

    The shard_state table maps shards to their active/standby nodes.
    This can get out of sync if:
    - Shards were created outside the normal job_worker flow
    - shard_state entries were deleted but shards/nodes weren't
    - The job_worker deployment succeeded in creating nodes but failed
      before calling update_shard_state()

    This function reconciles by:
    1. Finding shards with nodes but missing shard_state entries
    2. Creating shard_state entries from the nodes table (active/standby roles)

    Filtered by miner_id for multi-miner database isolation.
    """
    try:
        from miner_control_plane.services.miner_identity import miner_identity

        db = get_db_connection()
        cur = db.conn.cursor()

        # Get current miner_id for isolation
        current_miner_id = miner_identity.miner_id
        if not current_miner_id:
            logger.warning("No miner_id available, skipping shard_state reconciliation")
            cur.close()
            db.close()
            return

        # Find shards that have nodes but no shard_state entry
        cur.execute("""
            SELECT DISTINCT s.shard_id
            FROM shards s
            INNER JOIN nodes n ON n.shard_id = s.shard_id AND n.miner_id = s.miner_id
            LEFT JOIN shard_state ss ON ss.shard_id = s.shard_id
            WHERE s.miner_id = %s
              AND ss.shard_id IS NULL
              AND n.status = 'active'
        """, (current_miner_id,))
        orphaned_shards = [row[0] for row in cur.fetchall()]

        if not orphaned_shards:
            logger.debug("All shards have shard_state entries")
            cur.close()
            db.close()
            return

        logger.warning(
            f"Found {len(orphaned_shards)} shards missing shard_state entries: {orphaned_shards}"
        )

        reconciled = 0
        for shard_id in orphaned_shards:
            try:
                # Get active and standby nodes for this shard
                cur.execute("""
                    SELECT node_id, role FROM nodes
                    WHERE shard_id = %s AND miner_id = %s AND status = 'active'
                    ORDER BY role
                """, (shard_id, current_miner_id))
                nodes = cur.fetchall()

                active_node = None
                standby_node = None
                for node_id, role in nodes:
                    if role == 'active':
                        active_node = node_id
                    elif role == 'standby':
                        standby_node = node_id

                if not active_node and not standby_node:
                    logger.warning(f"Shard {shard_id} has no active/standby nodes, skipping")
                    continue

                # Create shard_state entry
                cur.execute("""
                    INSERT INTO shard_state (shard_id, active_node, standby_node)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (shard_id) DO UPDATE SET
                        active_node = EXCLUDED.active_node,
                        standby_node = EXCLUDED.standby_node
                """, (shard_id, active_node, standby_node))
                db.conn.commit()

                reconciled += 1
                logger.info(
                    f"Created shard_state for {shard_id}: active={active_node}, standby={standby_node}"
                )

            except Exception as e:
                logger.error(f"Failed to reconcile shard_state for {shard_id}: {e}")
                db.conn.rollback()

        cur.close()
        db.close()

        if reconciled > 0:
            logger.info(f"Shard state reconciliation complete: {reconciled} entries created")

    except Exception as e:
        logger.error(f"Shard state reconciliation failed: {e}", exc_info=True)


def reconcile_expected_tunnels() -> None:
    """
    Reconcile expected_tunnels.json on all scrubbers with database state.

    This ensures ecp-agent has accurate tunnel expectations after:
    - Miner restart (origins may have been deleted while miner was down)
    - Failed origin deletions (expected_tunnels.json update may have failed)
    - Failover events (new active may not have expected_tunnels.json)
    """
    try:
        from miner_control_plane.services.expected_tunnels import reconcile_expected_tunnels_with_database

        settings = get_settings()

        # Only proceed if we have scrubbers
        if not state_manager.nodes_db:
            logger.debug("No scrubbers available for expected_tunnels reconciliation")
            return

        logger.info("Reconciling expected_tunnels.json with database...")

        results = reconcile_expected_tunnels_with_database(
            nodes_db=state_manager.nodes_db,
            origins_db=state_manager.origins_db,
            ssh_key_path=settings.ssh_key_path
        )

        # Log results
        for node_name, result in results.items():
            status = result.get('status')
            if status == 'ok':
                logger.debug(f"{node_name}: expected_tunnels.json is in sync")
            elif status == 'reconciled':
                orphaned = result.get('orphaned_removed', [])
                missing = result.get('missing_added', [])
                logger.warning(
                    f"{node_name}: expected_tunnels.json reconciled - "
                    f"removed orphans={orphaned}, added missing={missing}"
                )
            else:
                logger.error(f"{node_name}: expected_tunnels.json reconciliation failed")

    except Exception as e:
        logger.error(f"expected_tunnels reconciliation failed: {e}", exc_info=True)


def run_all_startup_cleanup() -> None:
    """
    Run all startup initialization and cleanup routines in the correct order.

    Order:
    0a. Multi-miner schema migration (idempotent - adds miner_id columns)
    0b. Seed required database config (idempotent - ensures config rows exist)
    0c. Ensure database indexes exist (idempotent - creates missing indexes)
    0c2. Backfill missing ENI records for nodes
    0c3. Validate and refresh stale ENI records (post-failover fix)
    0d. Fix node miner_id consistency (ensures nodes have same miner_id as shard)
    0e. Reconcile shard_state from nodes (ensures active/standby mappings exist)
    1. Orphaned WireGuard interfaces (must run before BPF cleanup)
    2. BPF map orphan cleanup (eip_map)
    3. wg2priv_map orphan cleanup
    4. expected_tunnels.json reconciliation

    This function provides a single entry point for miner.py to call.
    """
    logger.info("Running startup cleanup routines...")

    # STEP 0a: Multi-miner schema migration
    # This ensures miner_id columns exist for data isolation
    # Must run FIRST before any database operations that might use miner_id
    ensure_miner_id_columns()

    # STEP 0b: Seed required database configuration
    # This ensures all config tables have required default rows
    # Must run BEFORE any services that depend on config tables
    seed_required_config()

    # STEP 0b2: Ensure database indexes exist for query performance
    # Creates indexes on frequently queried columns (origin_id + timestamp patterns)
    # Must run early to ensure queries are optimized from startup
    ensure_database_indexes()

    # NOTE: Stale node cleanup is now handled by StateManager during initialization
    # This ensures miner_id is available and runs BEFORE nodes are loaded into memory

    # STEP 0c: Backfill missing ENI records for existing nodes
    # Nodes may have been recovered without ENI data - fetch from AWS
    # Must run before any capacity checks that require ENI IDs
    backfill_missing_enis()

    # STEP 0c2: Validate and refresh stale ENI records
    # ENI IDs can become invalid after instance recreation (failover, replacement)
    # Must run after backfill and before any operations that use ENI IDs
    validate_and_refresh_enis()

    # STEP 0d: Fix node miner_id consistency
    # Ensures nodes have the same miner_id as their parent shard
    # Must run BEFORE reconcile_shard_states which joins on miner_id
    fix_node_miner_id_consistency()

    # STEP 0e: Reconcile shard_state entries from nodes
    # Ensures shard_state table is in sync with nodes table
    # Required for origin registration which needs active/standby node mappings
    reconcile_shard_states()

    # FIX 1: Clean up orphaned WireGuard interfaces
    # These are left behind when origin deletion fails or miner crashes mid-cleanup
    # Must run BEFORE BPF cleanup so interfaces are gone when we clean maps
    cleanup_orphaned_wireguard_interfaces()

    # FIX 2: Clean up orphaned BPF map entries
    # Prevents traffic from routing through non-existent WireGuard tunnels
    logger.info("Checking for orphaned BPF map entries...")
    cleanup_orphaned_bpf_maps()

    # FIX 3: Clean up orphaned wg2priv_map entries
    # These entries are keyed by ifindex which becomes stale when WG interfaces are removed
    cleanup_orphaned_wg2priv_map()

    # FIX 4: Reconcile expected_tunnels.json with database
    # Ensures ecp-agent has accurate state after miner restart or failed deletions
    reconcile_expected_tunnels()

    # FIX 5: Sync scrubber configuration files
    # Ensures scrubbers have up-to-date protection code from the repo
    try:
        from miner_control_plane.services.config_sync import run_config_sync
        run_config_sync()
    except Exception as e:
        logger.error(f"Config sync failed: {e}", exc_info=True)

    logger.info("Startup cleanup routines complete")
