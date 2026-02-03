"""State Manager - Database-backed state management for multi-region shards

Manages global state:
- shards_db: Shard definitions (shard_id → region mapping)
- nodes_db: Scrubber nodes (node_id → node data)
- shard_states: Per-shard active/standby tracking
- origins_db: Origin configurations

ARCHITECTURE: Database is source of truth. Cache provides fast reads.
- All getters fall back to DB on cache miss
- Periodic sync keeps cache fresh (every 30s)
- Write operations update DB first, then cache
- Public IPs are refreshed from AWS when stale (>5 min)

MULTI-MINER SUPPORT:
All database operations filter by miner_id when available.
This enables multiple miners to share the same database safely.
The miner_id is obtained from MinerIdentityManager.
"""
import logging
import threading
import time
import psycopg2.extras
from typing import Dict, List, Optional, Callable
from shared.database import get_db_connection
from shared.utils.database_helpers import db_load_origins, load_edge_nodes_from_database

logger = logging.getLogger(__name__)

# Sync interval in seconds
STATE_SYNC_INTERVAL = 30


class StateManager:
    """
    Manages Miner global state for multi-region shard deployment.

    All state is stored in the database:
    - shards_db: Loaded from shards table
    - nodes_db: Loaded from nodes + enis tables
    - shard_states: Loaded from shard_state table (per-shard)
    - origins_db: Loaded from origins table
    """

    def __init__(self):
        """Initialize state manager"""
        self.db = get_db_connection()
        self._lock = threading.RLock()

        # Initialize state dictionaries
        self.shards_db: Dict[str, dict] = {}      # shard_id → {region, status, ...}
        self.nodes_db: Dict[str, dict] = {}       # node_id → node data
        self.shard_states: Dict[str, dict] = {}   # shard_id → {active_node, standby_node}
        self.origins_db: Dict[str, dict] = {}     # origin_id → origin data

        # REMOVED: deployment_in_progress (replaced with per-shard locking in job_worker)
        # NOTE: deployment_completed_at and deployment_grace_period kept for backward compatibility
        # but should be replaced with per-shard grace period tracking in future

        # Grace period after deployment - prevents immediate failover due to stale health data
        self.deployment_completed_at: float = 0.0
        self.deployment_grace_period: int = 60  # seconds

        # Bandwidth state - stores bandwidth capacity, usage, and quotas
        self.bandwidth_capacity: Dict[str, dict] = {}  # node_id → capacity config
        self.bandwidth_usage: Dict[str, dict] = {}     # origin_ip → usage stats
        self.bandwidth_quotas: Dict[str, dict] = {}    # origin_ip → current quota

        # Sync thread for periodic state refresh
        self._sync_thread: Optional[threading.Thread] = None
        self._sync_stop_event = threading.Event()
        self._last_sync_time: float = 0.0

        # Lazy-loaded AWS operations for IP refresh
        self._aws_ops = None

        # Multi-miner support: cache miner_id (lazily loaded)
        self._miner_id: Optional[str] = None

    @property
    def miner_id(self) -> Optional[str]:
        """
        Get the current miner's ID for database filtering.

        Lazily loads from MinerIdentityManager on first access.
        Returns None if miner is not registered (backward compatibility).
        """
        if self._miner_id is None:
            try:
                from miner_control_plane.services.miner_identity import miner_identity
                self._miner_id = miner_identity.miner_id
                if self._miner_id:
                    logger.info(f"StateManager using miner_id={self._miner_id} for database isolation")
            except Exception as e:
                logger.debug(f"Could not get miner_id (may not be registered yet): {e}")
        return self._miner_id

    def set_miner_id(self, miner_id: str) -> None:
        """
        Explicitly set miner_id (useful after registration completes).

        Args:
            miner_id: The miner's UUID
        """
        self._miner_id = miner_id
        logger.info(f"StateManager miner_id set to {miner_id}")

    def _ensure_db_connection(self) -> None:
        """Check if database connection is healthy, reconnect if needed."""
        try:
            # Test connection with a simple query
            self.db.conn.cursor().execute("SELECT 1")
        except Exception:
            logger.warning("Database connection lost, reconnecting...")
            try:
                self.db.conn.close()
            except Exception:
                pass
            self.db = get_db_connection()
            logger.info("Database connection restored")

    def _get_aws_ops(self):
        """Lazy-load AWS operations to avoid circular imports"""
        if self._aws_ops is None:
            from miner_control_plane.utils.aws import AWSMinerOperations
            self._aws_ops = AWSMinerOperations()
        return self._aws_ops

    def _make_ip_refresh_func(self) -> Callable:
        """Create IP refresh function that updates DB when IP changes"""
        def refresh_ip(node_id: str, instance_name: str, current_ip: str, updated_at,
                       region: str = None) -> str:
            return self._get_aws_ops().refresh_public_ip_if_stale(
                node_id=node_id,
                instance_name=instance_name,
                current_ip=current_ip,
                updated_at=updated_at,
                db_connection=self.db,
                region=region
            )
        return refresh_ip

    def update_node_ip(self, node_id: str, new_ip: str) -> bool:
        """
        Update node IP in both database and memory cache.

        Called when health reports reveal IP mismatch.
        Returns True if IP was updated, False if unchanged or error.
        """
        with self._lock:
            node = self.nodes_db.get(node_id)
            if not node:
                logger.warning(f"Cannot update IP for unknown node {node_id}")
                return False

            current_ip = node.get('public_ip')
            if current_ip == new_ip:
                return False  # No change needed

            # Update database first (source of truth)
            try:
                conn = self.db.conn if hasattr(self.db, 'conn') else self.db
                cur = conn.cursor()
                cur.execute("""
                    UPDATE nodes
                    SET current_public_ip = %s, current_public_ip_updated_at = NOW()
                    WHERE node_id = %s
                """, (new_ip, node_id))
                conn.commit()
                cur.close()
            except Exception as e:
                logger.error(f"Failed to update IP for {node_id} in DB: {e}")
                return False

            # Update memory cache
            node['public_ip'] = new_ip
            logger.info(f"Node {node_id} IP updated: {current_ip} → {new_ip} (DB + cache)")
            return True

    def load_state(self) -> None:
        """
        Load state from database.

        Loads:
        1. Shards from shards table
        2. Nodes from nodes + enis tables
        3. Shard states from shard_state table
        4. Origins from origins table
        """
        # Ensure connection is healthy before loading
        self._ensure_db_connection()

        with self._lock:
            # Load Shards from database
            try:
                self.shards_db = self._load_shards()
                logger.info(f"Loaded {len(self.shards_db)} shards from database")
            except Exception as e:
                logger.error(f"Failed to load shards from database: {e}")
                self.shards_db = {}

            # Clean up stale nodes from database BEFORE loading
            # This removes nodes that no longer exist on AWS to prevent SSH timeout errors
            try:
                self._cleanup_stale_nodes_from_database()
            except Exception as e:
                logger.warning(f"Stale node cleanup failed (non-fatal): {e}")

            # Load Nodes from database (with IP refresh from AWS if stale)
            try:
                self.nodes_db = load_edge_nodes_from_database(
                    self.db,
                    refresh_ip_func=self._make_ip_refresh_func(),
                    miner_id=self.miner_id
                )
                if self.nodes_db:
                    logger.info(f"Loaded {len(self.nodes_db)} nodes from database")
            except Exception as e:
                logger.warning(f"Failed to load nodes from database: {e}")
                self.nodes_db = {}

            # Load Shard States from database
            try:
                self.shard_states = self._load_shard_states()
                logger.info(f"Loaded shard states for {len(self.shard_states)} shards")
            except Exception as e:
                logger.warning(f"Failed to load shard_states from database: {e}")
                self.shard_states = {}

            # Load Origins from database
            try:
                self.origins_db = db_load_origins(self.db, miner_id=self.miner_id)
                logger.info(f"Loaded {len(self.origins_db)} origins from database")
            except Exception as e:
                logger.error(f"Failed to load origins from database: {e}")
                self.origins_db = {}

            # Load bandwidth quotas from database
            self.load_bandwidth_quotas()

    def _load_shards(self) -> Dict[str, dict]:
        """Load shards from database (filtered by miner_id if available)"""
        conn = self.db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        if self.miner_id:
            cur.execute(
                "SELECT shard_id, region, status, shard_type, notes, created_at FROM shards WHERE miner_id = %s",
                (self.miner_id,)
            )
        else:
            cur.execute("SELECT shard_id, region, status, shard_type, notes, created_at FROM shards")
        rows = cur.fetchall()
        cur.close()

        shards = {}
        for row in rows:
            shards[row['shard_id']] = dict(row)
        return shards

    def _load_shard_states(self) -> Dict[str, dict]:
        """Load per-shard active/standby states from database (filtered by miner_id if available)"""
        conn = self.db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        if self.miner_id:
            # Join with shards to filter by miner_id
            cur.execute("""
                SELECT ss.shard_id, ss.active_node, ss.standby_node, ss.last_failover
                FROM shard_state ss
                JOIN shards s ON ss.shard_id = s.shard_id
                WHERE s.miner_id = %s
            """, (self.miner_id,))
        else:
            cur.execute("""
                SELECT shard_id, active_node, standby_node, last_failover
                FROM shard_state
            """)
        rows = cur.fetchall()
        cur.close()

        states = {}
        for row in rows:
            states[row['shard_id']] = {
                'active_node': row['active_node'],
                'standby_node': row['standby_node'],
                'last_failover': row['last_failover']
            }
        return states

    def _cleanup_stale_nodes_from_database(self) -> None:
        """
        Remove nodes from database that no longer exist on AWS.

        This handles the common case where:
        - Instances were terminated outside the miner (manual cleanup, AWS issues)
        - Previous miner runs crashed before cleaning up terminated instances
        - Test environment resets left orphaned database entries

        This MUST run early in startup to prevent SSH timeout errors when
        the miner tries to communicate with non-existent instances.

        NOTE: If miner_id is available, only cleans that miner's nodes.
        Otherwise, cleans ALL active nodes (safe for single-miner environments).
        """
        from shared.node import Node
        from shared.utils.database_helpers import db_delete_node

        miner_id_filter = self.miner_id  # May be None during early startup

        try:
            conn = self.db.conn
            cur = conn.cursor()

            # IMPORTANT: On startup, clean ALL stale nodes regardless of miner_id
            # This handles the case where old nodes have different miner_ids from previous runs
            # In production, each miner typically has its own database, so this is safe
            cur.execute("""
                SELECT node_id, region, provider, instance_name
                FROM nodes
                WHERE status = 'active'
            """)
            logger.info("Checking ALL active nodes for staleness (startup cleanup)")
            nodes = cur.fetchall()
            cur.close()

            if not nodes:
                logger.debug("No active nodes to check for staleness")
                return

            logger.info(f"Checking {len(nodes)} nodes against AWS for staleness...")

            stale_nodes = []
            valid_nodes = 0

            # Group nodes by region for efficient AWS API calls
            nodes_by_region = {}
            for node_id, region, provider, instance_name in nodes:
                if provider != 'aws':
                    # Skip non-AWS nodes (they need different verification)
                    valid_nodes += 1
                    continue
                if region not in nodes_by_region:
                    nodes_by_region[region] = []
                nodes_by_region[region].append((node_id, instance_name))

            # Check each region
            for region, region_nodes in nodes_by_region.items():
                try:
                    node_ids = [n[0] for n in region_nodes]
                    node = Node(node_type="scrubber", region=region)

                    # Batch check which instances exist
                    existing_instances = node.provider.describe_instances_in_region(
                        node_ids, region
                    )
                    existing_ids = {inst.get('instance_id') for inst in existing_instances}

                    for node_id, instance_name in region_nodes:
                        if node_id in existing_ids:
                            valid_nodes += 1
                        else:
                            stale_nodes.append((node_id, region, instance_name))
                            logger.warning(
                                f"Node {instance_name} ({node_id}) not found on AWS in {region} - marking for deletion"
                            )

                except Exception as e:
                    logger.error(f"Failed to check nodes in {region}: {e}")
                    # Don't delete on error - could be transient AWS issue
                    valid_nodes += len(region_nodes)

            if not stale_nodes:
                logger.info(f"All {valid_nodes} nodes are valid on AWS")
                return

            logger.warning(f"Found {len(stale_nodes)} stale nodes to clean up...")

            # Delete stale nodes from database
            deleted = 0
            for node_id, region, instance_name in stale_nodes:
                try:
                    # FIRST: Clear shard_state references to avoid FK constraint violation
                    cur = conn.cursor()
                    cur.execute("""
                        UPDATE shard_state
                        SET active_node = NULL
                        WHERE active_node = %s
                    """, (node_id,))
                    cur.execute("""
                        UPDATE shard_state
                        SET standby_node = NULL
                        WHERE standby_node = %s
                    """, (node_id,))
                    conn.commit()
                    cur.close()

                    # THEN: Delete node (db_delete_node also deletes associated ENI)
                    db_delete_node(node_id, self.db)
                    deleted += 1
                    logger.info(f"✓ Deleted stale node {instance_name} ({node_id}) from database")

                except Exception as e:
                    logger.error(f"Failed to delete stale node {node_id}: {e}")
                    conn.rollback()

            logger.warning(
                f"STALE NODE CLEANUP: Found {len(stale_nodes)} stale nodes, "
                f"successfully deleted {deleted}"
            )

        except Exception as e:
            logger.error(f"Stale node cleanup failed: {e}", exc_info=True)

    # =========================================================================
    # Periodic Sync Thread
    # =========================================================================

    def start_sync_thread(self) -> None:
        """Start background thread for periodic state synchronization"""
        if self._sync_thread and self._sync_thread.is_alive():
            logger.warning("Sync thread already running")
            return

        self._sync_stop_event.clear()
        self._sync_thread = threading.Thread(
            target=self._sync_loop,
            name="state-sync",
            daemon=True
        )
        self._sync_thread.start()
        logger.info(f"State sync thread started (interval: {STATE_SYNC_INTERVAL}s)")

    def stop_sync_thread(self) -> None:
        """Stop the background sync thread"""
        self._sync_stop_event.set()
        if self._sync_thread and self._sync_thread.is_alive():
            self._sync_thread.join(timeout=5)
            logger.info("State sync thread stopped")

    def _sync_loop(self) -> None:
        """Background loop that periodically syncs state from database"""
        while not self._sync_stop_event.is_set():
            try:
                self._sync_state_from_db()
            except Exception as e:
                logger.error(f"State sync failed: {e}")
            self._sync_stop_event.wait(STATE_SYNC_INTERVAL)

    def _sync_state_from_db(self) -> None:
        """Sync all state from database, logging any changes detected"""
        # Ensure connection is healthy before syncing
        self._ensure_db_connection()

        with self._lock:
            # Track changes for logging
            changes = []

            # Sync origins
            try:
                new_origins = db_load_origins(self.db, miner_id=self.miner_id)
                added = set(new_origins.keys()) - set(self.origins_db.keys())
                removed = set(self.origins_db.keys()) - set(new_origins.keys())
                if added:
                    changes.append(f"origins added: {added}")
                if removed:
                    changes.append(f"origins removed: {removed}")
                self.origins_db = new_origins
            except Exception as e:
                logger.error(f"Failed to sync origins: {e}")

            # Sync nodes (with IP refresh from AWS if stale)
            try:
                new_nodes = load_edge_nodes_from_database(
                    self.db,
                    refresh_ip_func=self._make_ip_refresh_func(),
                    miner_id=self.miner_id
                )
                if new_nodes:
                    added = set(new_nodes.keys()) - set(self.nodes_db.keys())
                    removed = set(self.nodes_db.keys()) - set(new_nodes.keys())
                    if added:
                        changes.append(f"nodes added: {added}")
                    if removed:
                        changes.append(f"nodes removed: {removed}")

                    # Detect IP changes
                    for node_id, new_node in new_nodes.items():
                        old_node = self.nodes_db.get(node_id, {})
                        old_ip = old_node.get('public_ip')
                        new_ip = new_node.get('public_ip')
                        if old_ip and new_ip and old_ip != new_ip:
                            changes.append(f"node {node_id} IP: {old_ip} → {new_ip}")

                    self.nodes_db = new_nodes
            except Exception as e:
                logger.error(f"Failed to sync nodes: {e}")

            # Sync shards
            try:
                new_shards = self._load_shards()
                added = set(new_shards.keys()) - set(self.shards_db.keys())
                removed = set(self.shards_db.keys()) - set(new_shards.keys())
                if added:
                    changes.append(f"shards added: {added}")
                if removed:
                    changes.append(f"shards removed: {removed}")
                self.shards_db = new_shards
            except Exception as e:
                logger.error(f"Failed to sync shards: {e}")

            # Sync shard states
            try:
                new_states = self._load_shard_states()
                self.shard_states = new_states
            except Exception as e:
                logger.error(f"Failed to sync shard states: {e}")

            self._last_sync_time = time.time()

            if changes:
                logger.info(f"State sync detected changes: {', '.join(changes)}")
            else:
                logger.debug(
                    f"State sync complete: {len(self.origins_db)} origins, "
                    f"{len(self.nodes_db)} nodes, {len(self.shards_db)} shards"
                )

    # =========================================================================
    # Direct DB Query Methods (for fallback)
    # =========================================================================

    def _query_origin_from_db(self, origin_id: str) -> Optional[dict]:
        """Query single origin directly from database (filtered by miner_id if available)"""
        try:
            conn = self.db.conn
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            if self.miner_id:
                cur.execute("""
                    SELECT origin_id, origin_ip, eip, exit_hub_ip, exit_hub_wg_ip,
                           required_ports, state, shard_id, created_at, updated_at
                    FROM origins WHERE origin_id = %s AND miner_id = %s
                """, (origin_id, self.miner_id))
            else:
                cur.execute("""
                    SELECT origin_id, origin_ip, eip, exit_hub_ip, exit_hub_wg_ip,
                           required_ports, state, shard_id, created_at, updated_at
                    FROM origins WHERE origin_id = %s
                """, (origin_id,))
            row = cur.fetchone()
            cur.close()
            if row:
                return dict(row)
            return None
        except Exception as e:
            conn.rollback()
            logger.error(f"DB query for origin {origin_id} failed: {e}")
            return None

    def _query_nodes_for_shard_from_db(self, shard_id: str) -> List[dict]:
        """Query nodes for a shard directly from database.

        Ownership model: If this miner owns the SHARD (shards.miner_id matches),
        return ALL nodes for that shard regardless of the nodes' miner_id.
        This handles cases where nodes were incorrectly created with wrong miner_id
        but the shard ownership is correct.
        """
        try:
            conn = self.db.conn
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            if self.miner_id:
                # First verify this miner owns the shard
                cur.execute(
                    "SELECT miner_id FROM shards WHERE shard_id = %s",
                    (shard_id,)
                )
                shard_row = cur.fetchone()
                if not shard_row:
                    cur.close()
                    return []

                shard_miner_id = str(shard_row['miner_id']) if shard_row['miner_id'] else None
                if shard_miner_id != self.miner_id:
                    # This miner doesn't own the shard - return empty
                    cur.close()
                    logger.debug(
                        f"Shard {shard_id} owned by {shard_miner_id}, not this miner ({self.miner_id})"
                    )
                    return []

                # This miner owns the shard - return ALL nodes for this shard
                # (regardless of the nodes' miner_id, which may be incorrect)
                cur.execute("""
                    SELECT n.node_id, n.instance_name,
                           n.current_public_ip AS public_ip,
                           e.primary_private_ip AS private_ip,
                           n.provider, n.shard_id, n.status, n.role, n.created_at,
                           e.eni_id
                    FROM nodes n
                    LEFT JOIN enis e ON n.node_id = e.node_id
                    WHERE n.shard_id = %s
                """, (shard_id,))
            else:
                cur.execute("""
                    SELECT n.node_id, n.instance_name,
                           n.current_public_ip AS public_ip,
                           e.primary_private_ip AS private_ip,
                           n.provider, n.shard_id, n.status, n.role, n.created_at,
                           e.eni_id
                    FROM nodes n
                    LEFT JOIN enis e ON n.node_id = e.node_id
                    WHERE n.shard_id = %s
                """, (shard_id,))
            rows = cur.fetchall()
            cur.close()
            return [dict(row) for row in rows]
        except Exception as e:
            conn.rollback()
            logger.error(f"DB query for nodes in shard {shard_id} failed: {e}")
            return []

    def _query_shard_from_db(self, shard_id: str) -> Optional[dict]:
        """Query single shard directly from database (filtered by miner_id if available)"""
        try:
            conn = self.db.conn
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            if self.miner_id:
                cur.execute(
                    "SELECT shard_id, region, status, shard_type, notes, created_at FROM shards WHERE shard_id = %s AND miner_id = %s",
                    (shard_id, self.miner_id)
                )
            else:
                cur.execute(
                    "SELECT shard_id, region, status, shard_type, notes, created_at FROM shards WHERE shard_id = %s",
                    (shard_id,)
                )
            row = cur.fetchone()
            cur.close()
            if row:
                return dict(row)
            return None
        except Exception as e:
            conn.rollback()
            logger.error(f"DB query for shard {shard_id} failed: {e}")
            return None

    # =========================================================================
    # Shard Operations
    # =========================================================================

    def get_shard(self, shard_id: str) -> Optional[dict]:
        """Get shard by ID (with DB fallback)"""
        # Try cache first
        shard = self.shards_db.get(shard_id)
        if shard:
            return shard

        # Fallback to DB query
        shard = self._query_shard_from_db(shard_id)
        if shard:
            # Update cache
            with self._lock:
                self.shards_db[shard_id] = shard
            logger.debug(f"Shard {shard_id} loaded from DB (cache miss)")
        return shard

    def get_shard_state(self, shard_id: str) -> dict:
        """Get active/standby state for a specific shard"""
        return self.shard_states.get(shard_id, {})

    def get_nodes_for_shard(self, shard_id: str) -> List[dict]:
        """Get all nodes belonging to a shard (with DB fallback)"""
        # Try cache first
        nodes = [n for n in self.nodes_db.values() if n.get('shard_id') == shard_id]
        if nodes:
            return nodes

        # Fallback to DB query
        nodes = self._query_nodes_for_shard_from_db(shard_id)
        if nodes:
            # Update cache with these nodes
            with self._lock:
                for node in nodes:
                    node_id = node.get('node_id')
                    if node_id:
                        self.nodes_db[node_id] = node
            logger.debug(f"Loaded {len(nodes)} nodes for shard {shard_id} from DB (cache miss)")
        return nodes

    def get_active_node(self, shard_id: str) -> Optional[dict]:
        """Get the active node for a shard (with DB fallback)"""
        # Try cache first
        state = self.shard_states.get(shard_id, {})
        node_id = state.get('active_node')

        if not node_id:
            # Cache miss for shard_state - try direct DB query
            db_state = self._query_shard_state_from_db(shard_id)
            if db_state:
                node_id = db_state.get('active_node')
                # Update cache
                with self._lock:
                    self.shard_states[shard_id] = db_state

        if not node_id:
            return None

        # Try to find node in cache
        node = self.nodes_db.get(node_id)
        if node:
            return node

        # Cache miss for node - query DB directly
        node = self._query_node_from_db(node_id)
        if node:
            # Update cache
            with self._lock:
                self.nodes_db[node_id] = node
            logger.debug(f"Node {node_id} loaded from DB (cache miss)")
        return node

    def _query_shard_state_from_db(self, shard_id: str) -> Optional[dict]:
        """Query shard state directly from database"""
        try:
            conn = self.db.conn
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("""
                SELECT shard_id, active_node, standby_node, last_failover
                FROM shard_state WHERE shard_id = %s
            """, (shard_id,))
            row = cur.fetchone()
            cur.close()
            if row:
                return {
                    'active_node': row['active_node'],
                    'standby_node': row['standby_node'],
                    'last_failover': row['last_failover']
                }
            return None
        except Exception as e:
            conn.rollback()
            logger.error(f"DB query for shard_state {shard_id} failed: {e}")
            return None

    def _query_node_from_db(self, node_id: str) -> Optional[dict]:
        """Query single node directly from database"""
        try:
            conn = self.db.conn
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("""
                SELECT n.node_id, n.instance_name, n.current_public_ip AS public_ip,
                       n.provider, n.shard_id, n.status, n.role, n.region,
                       n.instance_type, n.bandwidth_bps, e.eni_id,
                       e.primary_private_ip AS private_ip
                FROM nodes n
                LEFT JOIN enis e ON n.node_id = e.node_id
                WHERE n.node_id = %s AND n.status = 'active'
            """, (node_id,))
            row = cur.fetchone()
            cur.close()
            if row:
                return {
                    'instance_id': row['node_id'],
                    'node_id': row['node_id'],
                    'instance_name': row['instance_name'],
                    'public_ip': row['public_ip'] or '',
                    'private_ip': row['private_ip'] or '',
                    'provider': row['provider'],
                    'shard_id': row['shard_id'],
                    'status': row['status'],
                    'role': row['role'],
                    'region': row['region'],
                    'instance_type': row['instance_type'],
                    'bandwidth_bps': row['bandwidth_bps'],
                    'eni_id': row['eni_id'] or '',
                }
            return None
        except Exception as e:
            conn.rollback()
            logger.error(f"DB query for node {node_id} failed: {e}")
            return None

    def get_standby_node(self, shard_id: str) -> Optional[dict]:
        """Get the standby node for a shard (with DB fallback)"""
        # Try cache first
        state = self.shard_states.get(shard_id, {})
        node_id = state.get('standby_node')

        if not node_id:
            # Cache miss for shard_state - try direct DB query
            db_state = self._query_shard_state_from_db(shard_id)
            if db_state:
                node_id = db_state.get('standby_node')
                # Update cache
                with self._lock:
                    self.shard_states[shard_id] = db_state

        if not node_id:
            return None

        # Try to find node in cache
        node = self.nodes_db.get(node_id)
        if node:
            return node

        # Cache miss for node - query DB directly
        node = self._query_node_from_db(node_id)
        if node:
            # Update cache
            with self._lock:
                self.nodes_db[node_id] = node
            logger.debug(f"Node {node_id} loaded from DB (cache miss)")
        return node

    def get_origins_for_shard(self, shard_id: str) -> List[dict]:
        """Get all origins assigned to a shard"""
        return [o for o in self.origins_db.values() if o.get('shard_id') == shard_id]

    def get_all_active_nodes(self) -> List[dict]:
        """Get active nodes across all shards"""
        nodes = []
        for shard_id in self.shards_db:
            node = self.get_active_node(shard_id)
            if node:
                nodes.append(node)
        return nodes

    def get_all_nodes(self) -> List[dict]:
        """Get all nodes across all shards"""
        return list(self.nodes_db.values())

    def get_node_by_name(self, instance_name: str) -> Optional[dict]:
        """Get node by instance_name (e.g., 'eu-central-1-a')"""
        for node in self.nodes_db.values():
            if node.get('instance_name') == instance_name:
                return node
        return None

    def get_node(self, node_id_or_name: str) -> Optional[dict]:
        """Get node by node_id or instance_name (flexible lookup)"""
        # Try node_id first (primary key)
        if node_id_or_name in self.nodes_db:
            return self.nodes_db[node_id_or_name]
        # Fall back to instance_name search
        return self.get_node_by_name(node_id_or_name)

    # Backward-compatible single-shard methods (use first available shard)
    def get_active_edge(self) -> Optional[str]:
        """Get active node_id from first shard (backward compatibility)"""
        if not self.shard_states:
            return None
        first_shard_state = next(iter(self.shard_states.values()))
        return first_shard_state.get('active_node')

    def get_standby_edge(self) -> Optional[str]:
        """Get standby node_id from first shard (backward compatibility)"""
        if not self.shard_states:
            return None
        first_shard_state = next(iter(self.shard_states.values()))
        return first_shard_state.get('standby_node')

    # =========================================================================
    # Shard State Updates
    # =========================================================================

    def update_shard_state(self, shard_id: str, active_node: str, standby_node: str) -> None:
        """Update shard state in memory and database"""
        with self._lock:
            self.shard_states[shard_id] = {
                'active_node': active_node,
                'standby_node': standby_node,
                'last_failover': None
            }
            self._save_shard_state(shard_id)

    def _save_shard_state(self, shard_id: str) -> None:
        """Save shard state to database"""
        state = self.shard_states.get(shard_id, {})
        try:
            conn = self.db.conn
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO shard_state (shard_id, active_node, standby_node)
                VALUES (%s, %s, %s)
                ON CONFLICT (shard_id) DO UPDATE SET
                    active_node = EXCLUDED.active_node,
                    standby_node = EXCLUDED.standby_node
            """, (shard_id, state.get('active_node'), state.get('standby_node')))
            conn.commit()
            cur.close()
            logger.info(f"Shard state saved: {shard_id} active={state.get('active_node')}")
        except Exception as e:
            logger.error(f"Failed to save shard state for {shard_id}: {e}")
            raise

    def record_failover(self, shard_id: str) -> None:
        """Record failover timestamp for a shard"""
        with self._lock:
            try:
                conn = self.db.conn
                cur = conn.cursor()
                cur.execute("""
                    UPDATE shard_state
                    SET active_node = %s,
                        standby_node = %s,
                        last_failover = NOW()
                    WHERE shard_id = %s
                """, (
                    self.shard_states[shard_id]['active_node'],
                    self.shard_states[shard_id]['standby_node'],
                    shard_id
                ))
                conn.commit()
                cur.close()
                logger.info(f"Failover recorded for shard {shard_id}")
            except Exception as e:
                logger.error(f"Failed to record failover for shard {shard_id}: {e}")
                raise

    # =========================================================================
    # Shard CRUD
    # =========================================================================

    def create_shard(self, shard_id: str, region: str, shard_type: str = 'audit') -> dict:
        """Create a new shard in database and cache (idempotent).

        Uses ON CONFLICT DO NOTHING to safely handle duplicate calls.
        Returns existing shard if already present AND owned by this miner.

        Args:
            shard_id: Unique identifier for the shard
            region: AWS region for the shard
            shard_type: 'audit' for validator scoring shards (default),
                       'production' for customer origin shards

        Raises:
            ValueError: If shard exists but is owned by a different miner.

        Includes miner_id for multi-miner isolation.
        """
        with self._lock:
            # Return from cache if already exists (cache is already filtered by miner_id)
            if shard_id in self.shards_db:
                return self.shards_db[shard_id]

            try:
                conn = self.db.conn
                cur = conn.cursor()

                # Idempotent insert - no error on duplicate (include miner_id if available)
                if self.miner_id:
                    cur.execute("""
                        INSERT INTO shards (shard_id, region, status, shard_type, miner_id)
                        VALUES (%s, %s, 'deploying', %s, %s)
                        ON CONFLICT (shard_id) DO NOTHING
                    """, (shard_id, region, shard_type, self.miner_id))
                else:
                    cur.execute("""
                        INSERT INTO shards (shard_id, region, status, shard_type)
                        VALUES (%s, %s, 'deploying', %s)
                        ON CONFLICT (shard_id) DO NOTHING
                    """, (shard_id, region, shard_type))
                conn.commit()

                # Fetch the shard (whether just inserted or already existed)
                # Include miner_id to check ownership
                cur.execute("""
                    SELECT shard_id, region, status, created_at, miner_id, shard_type
                    FROM shards WHERE shard_id = %s
                """, (shard_id,))
                row = cur.fetchone()
                cur.close()

                if not row:
                    raise ValueError(f"Failed to create or fetch shard {shard_id}")

                shard_miner_id = str(row[4]) if row[4] else None

                # OWNERSHIP CHECK: Reject if shard belongs to a different miner
                if self.miner_id and shard_miner_id and shard_miner_id != self.miner_id:
                    logger.warning(
                        f"Shard {shard_id} already exists but owned by miner {shard_miner_id}, "
                        f"not this miner ({self.miner_id}). Rejecting deployment request."
                    )
                    raise ValueError(
                        f"Shard {shard_id} is owned by another miner ({shard_miner_id[:8]}...). "
                        f"Cannot deploy nodes to a shard owned by a different miner."
                    )

                shard = {
                    'shard_id': row[0],
                    'region': row[1],
                    'status': row[2],
                    'created_at': row[3],
                    'shard_type': row[5] or 'audit'  # Default to audit if NULL
                }
                self.shards_db[shard_id] = shard
                logger.info(f"Shard {shard_id} ({shard_type}) ready in region {region}")
                return shard
            except ValueError:
                # Re-raise ValueError (ownership check failure) without wrapping
                raise
            except Exception as e:
                logger.error(f"Failed to create/get shard {shard_id}: {e}")
                raise

    def update_shard_status(self, shard_id: str, status: str) -> None:
        """Update shard status"""
        with self._lock:
            try:
                conn = self.db.conn
                cur = conn.cursor()
                cur.execute(
                    "UPDATE shards SET status = %s WHERE shard_id = %s",
                    (status, shard_id)
                )
                conn.commit()
                cur.close()

                if shard_id in self.shards_db:
                    self.shards_db[shard_id]['status'] = status
                logger.info(f"Shard {shard_id} status updated to {status}")
            except Exception as e:
                logger.error(f"Failed to update shard {shard_id} status: {e}")
                raise

    def delete_shard(self, shard_id: str) -> None:
        """Delete shard and all related data from database and cache"""
        with self._lock:
            try:
                conn = self.db.conn
                cur = conn.cursor()

                # Get nodes for this shard
                cur.execute("SELECT node_id FROM nodes WHERE shard_id = %s", (shard_id,))
                node_ids = [r[0] for r in cur.fetchall()]

                # Delete health_node entries for these nodes
                for node_id in node_ids:
                    cur.execute("DELETE FROM health_node WHERE node_id = %s", (node_id,))

                # Delete ENIs for these nodes (foreign key constraint)
                for node_id in node_ids:
                    cur.execute("DELETE FROM enis WHERE node_id = %s", (node_id,))

                # Delete shard_state entries (must come before nodes due to FK)
                cur.execute("DELETE FROM shard_state WHERE shard_id = %s", (shard_id,))

                # Delete nodes belonging to this shard from database
                cur.execute("DELETE FROM nodes WHERE shard_id = %s", (shard_id,))
                nodes_deleted = cur.rowcount

                # Delete deployment_jobs for this shard
                cur.execute("DELETE FROM deployment_jobs WHERE shard_id = %s", (shard_id,))

                # Delete the shard itself
                cur.execute("DELETE FROM shards WHERE shard_id = %s", (shard_id,))
                conn.commit()
                cur.close()

                # Remove from cache
                self.shards_db.pop(shard_id, None)
                self.shard_states.pop(shard_id, None)

                # Remove nodes belonging to this shard from cache
                nodes_to_remove = [
                    nid for nid, n in self.nodes_db.items()
                    if n.get('shard_id') == shard_id
                ]
                for nid in nodes_to_remove:
                    self.nodes_db.pop(nid, None)

                logger.info(f"Deleted shard {shard_id} ({nodes_deleted} nodes removed)")
            except Exception as e:
                logger.error(f"Failed to delete shard {shard_id}: {e}")
                raise

    # =========================================================================
    # Node CRUD (called by deployment/cleanup)
    # =========================================================================

    def add_node(self, node_data: dict) -> None:
        """Add node to cache (DB insert done by scrubber_operations)"""
        with self._lock:
            node_id = node_data.get('node_id') or node_data.get('instance_id')
            self.nodes_db[node_id] = node_data
            logger.debug(f"Added node {node_id} to cache")

    def remove_node(self, node_id: str) -> None:
        """Remove node from cache"""
        with self._lock:
            self.nodes_db.pop(node_id, None)
            logger.debug(f"Removed node {node_id} from cache")

    # =========================================================================
    # Origin Helpers
    # =========================================================================

    def get_origin(self, origin_id: str) -> Optional[dict]:
        """Get origin by ID (with DB fallback)"""
        # Try cache first
        origin = self.origins_db.get(origin_id)
        if origin:
            return origin

        # Fallback to DB query
        origin = self._query_origin_from_db(origin_id)
        if origin:
            # Update cache
            with self._lock:
                self.origins_db[origin_id] = origin
            logger.debug(f"Origin {origin_id} loaded from DB (cache miss)")
        return origin

    def get_shard_for_origin(self, origin_id: str) -> Optional[str]:
        """Get shard_id for an origin (with DB fallback)"""
        # Try cache first
        origin = self.origins_db.get(origin_id)
        if origin:
            return origin.get('shard_id')

        # Fallback to DB query
        origin = self._query_origin_from_db(origin_id)
        if origin:
            # Update cache
            with self._lock:
                self.origins_db[origin_id] = origin
            logger.debug(f"Origin {origin_id} loaded from DB (cache miss)")
            return origin.get('shard_id')
        return None

    def get_origin_by_ip(self, origin_ip: str) -> Optional[dict]:
        """Get origin by its origin_ip"""
        for origin in self.origins_db.values():
            if origin.get('origin_ip') == origin_ip:
                return origin
        return None

    def get_origin_by_eip(self, eip: str) -> Optional[dict]:
        """Get origin by its EIP"""
        for origin in self.origins_db.values():
            if origin.get('eip') == eip:
                return origin
        return None

    # =========================================================================
    # Bandwidth Helpers
    # =========================================================================

    def get_origins_for_node(self, node_id: str) -> List[dict]:
        """Get all origins for the shard containing this node"""
        node = self.nodes_db.get(node_id)
        if not node:
            return []

        shard_id = node.get('shard_id')
        if not shard_id:
            return []

        return self.get_origins_for_shard(shard_id)

    def get_node_bandwidth(self, node_id: str) -> Optional[dict]:
        """Get bandwidth capacity configuration for a node.

        Checks nodes_db first (set during deployment from AWS API),
        then falls back to bandwidth_capacity (from ecp-agent reports).
        """
        # Primary source: bandwidth_bps from nodes_db (set during deployment)
        node = self.nodes_db.get(node_id)
        if node and node.get('bandwidth_bps'):
            return {
                'bandwidth_bps': node['bandwidth_bps'],
                'instance_type': node.get('instance_type', 'unknown')
            }
        # Fallback: bandwidth_capacity from health reports
        return self.bandwidth_capacity.get(node_id)

    def update_bandwidth_quota(self, origin_ip: str, quota: dict) -> None:
        """Update bandwidth quota cache for an origin and persist to database"""
        with self._lock:
            self.bandwidth_quotas[origin_ip] = quota
            logger.debug(f"Updated bandwidth quota for {origin_ip}: {quota}")

            # Persist to database
            try:
                # Find origin_id for this origin_ip
                origin_id = None
                for oid, odata in self.origins_db.items():
                    if odata.get('origin_ip') == origin_ip:
                        origin_id = oid
                        break

                if origin_id and self.db:
                    cur = self.db.conn.cursor()
                    cur.execute("""
                        INSERT INTO origin_bandwidth_quota (origin_id, quota_bps, burst_bytes, updated_at)
                        VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT (origin_id) DO UPDATE SET
                            quota_bps = EXCLUDED.quota_bps,
                            burst_bytes = EXCLUDED.burst_bytes,
                            updated_at = CURRENT_TIMESTAMP
                    """, (origin_id, quota.get('quota_bps', 0), quota.get('burst_bytes', 0)))
                    self.db.conn.commit()
                    cur.close()
            except Exception as e:
                logger.warning(f"Failed to persist bandwidth quota for {origin_ip}: {e}")

    def load_bandwidth_quotas(self) -> None:
        """Load bandwidth quotas from database on startup"""
        try:
            if not self.db:
                return

            cur = self.db.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("""
                SELECT q.origin_id, q.quota_bps, q.burst_bytes, o.origin_ip
                FROM origin_bandwidth_quota q
                JOIN origins o ON q.origin_id = o.origin_id
            """)
            rows = cur.fetchall()
            cur.close()

            for row in rows:
                origin_ip = row.get('origin_ip')
                if origin_ip:
                    self.bandwidth_quotas[origin_ip] = {
                        'quota_bps': row.get('quota_bps', 0),
                        'burst_bytes': row.get('burst_bytes', 0),
                    }

            if self.bandwidth_quotas:
                logger.info(f"Loaded {len(self.bandwidth_quotas)} bandwidth quotas from database")

        except Exception as e:
            logger.warning(f"Failed to load bandwidth quotas from database: {e}")

# Singleton instance
state_manager = StateManager()
