"""
TensorProx Miner implementation - Production Ready.

Implements 1 active + 1 standby scrubber model:
- Active scrubber handles all production traffic
- Standby scrubber is pre-configured for instant failover
- BPF map sync every 5s to keep standby in sync
- Automatic promotion on active failure
"""

import json
import time
import asyncio
import threading
from typing import Optional, Dict, Any, List, ClassVar

from pydantic import Field
from loguru import logger

from tensorprox.base.miner import BaseMinerNeuron
from tensorprox.base.protocol import ChallengeSynapse, ScrubberConfig, AuditChallengeSynapse, SetupTunnelSynapse
from tensorprox.services.scrubber_manager import ScrubberManager, ScrubberNode
from tensorprox.services.health_monitor import HealthMonitor
from tensorprox.settings import Settings, get_settings
from shared.providers import get_provider


class TensorProxMiner(BaseMinerNeuron):
    """
    Production-ready TensorProx miner.

    Deploys and manages 2 scrubbers per miner:
    - 1 active: Handles all production traffic
    - 1 standby: Pre-configured, ready for instant failover

    Responds to validator audits and handles origin assignments from TPM.
    """

    # Scrubber management
    scrubber_manager: Optional[ScrubberManager] = Field(default=None)
    health_monitor: Optional[HealthMonitor] = Field(default=None)

    # Scrubber tracking
    active_scrubber: Optional[ScrubberNode] = Field(default=None)
    standby_scrubber: Optional[ScrubberNode] = Field(default=None)

    # Configuration for audit shard: 1 scrubber only (no standby needed for audits)
    # Production shards use 2 scrubbers (1 active + 1 standby) but those are managed by TPM
    AUDIT_SCRUBBERS_REQUIRED: ClassVar[int] = 1  # Audit shard: 1 active only
    PRODUCTION_SCRUBBERS_REQUIRED: ClassVar[int] = 2  # Production shard: 1 active + 1 standby

    # Failover tracking
    failover_count: int = Field(default=0)
    last_failover: float = Field(default=0.0)

    # BPF map sync
    bpf_sync_interval: int = Field(
        default=5,
        description="Seconds between BPF map syncs to standby"
    )
    last_bpf_sync: float = Field(default=0.0)

    # Challenge tracking
    active_challenge: Optional[str] = Field(default=None)
    challenge_start_time: float = Field(default=0.0)

    # Audit challenge tracking (for real traffic tests)
    # Support multiple concurrent audits from different validators
    # Structure: {validator_uid: {challenge_id: challenge_state}}
    # Each validator has isolated state to prevent interference
    audit_challenges: Dict[int, Dict[str, Dict[str, Any]]] = Field(default_factory=dict)
    # Max age for audit challenges before cleanup (seconds)
    audit_challenge_max_age: float = Field(default=300.0)

    # Control plane thread
    _control_plane_thread: Optional[threading.Thread] = None
    _control_plane_pending: bool = False  # True if startup deferred due to missing bootstrap token

    def __init__(
        self,
        settings: Optional[Settings] = None,
        **kwargs
    ):
        """Initialize the production miner."""
        super().__init__(settings=settings, **kwargs)

        # Initialize scrubber config (will update after deployment)
        self.scrubber_config = ScrubberConfig(
            provider=self.settings.scrubber_provider,
            region=self.settings.scrubber_region,
            num_scrubbers=2,  # Fixed at 2 (1 active + 1 standby)
            max_scrubbers=2,  # Fixed at 2
            instance_type=self.settings.scrubber_instance_type,
            supports_layer4=True,
            supports_layer7=True,
            supports_syn_cookies=True,
        )

    def setup_scrubbers(self) -> bool:
        """
        Set up audit shard scrubber for this miner instance.

        AUDIT SHARDS: 1 scrubber only (active, no standby)
        - Audit shards are used for validator scoring
        - No redundancy needed since audits are transient
        - Saves resources by not running idle standby instances

        PRODUCTION SHARDS: Managed by TPM with 2 scrubbers (1 active + 1 standby)
        - Production shards handle real customer traffic
        - Require failover for high availability

        Deployment strategy:
        1. Try to recover existing scrubber from state or cloud discovery
        2. Verify recovered scrubber is healthy and responsive
        3. Only deploy new scrubber if needed
        4. Start health monitoring

        Each miner instance (identified by wallet_name + wallet_hotkey) manages
        its own independent scrubber, allowing multiple miners on same machine.
        """
        logger.info("=" * 60)
        logger.info("Setting up AUDIT shard scrubber (1 active only, no standby)...")
        logger.info("=" * 60)

        # Generate miner_id from wallet for instance-specific scrubber management
        # This allows multiple miner instances on same machine
        miner_id = f"{self.settings.wallet_name}_{self.settings.wallet_hotkey}"
        logger.info(f"Miner instance ID: {miner_id}")

        # Initialize scrubber manager with miner-specific identity
        # Audit shards only need 1 scrubber (no standby for validator scoring)
        self.scrubber_manager = ScrubberManager(
            max_scrubbers=self.AUDIT_SCRUBBERS_REQUIRED,
            miner_id=miner_id
        )

        # Step 1: Try to recover existing scrubber pair
        logger.info("-" * 40)
        logger.info("Step 1: Checking for existing scrubbers...")
        logger.info("-" * 40)

        recovered_active, recovered_standby = self.scrubber_manager.recover_scrubber_pair(
            region=self.settings.scrubber_region
        )

        # Use recovered scrubbers
        self.active_scrubber = recovered_active
        self.standby_scrubber = recovered_standby

        # Step 2: Deploy missing scrubbers
        logger.info("-" * 40)
        logger.info("Step 2: Deploying missing scrubbers...")
        logger.info("-" * 40)

        if not self.active_scrubber:
            logger.info("No active scrubber available - deploying new one...")
            new_active = self.scrubber_manager.deploy_scrubber(
                region=self.settings.scrubber_region,
                instance_type=self.settings.scrubber_instance_type,
            )

            if not new_active:
                logger.error("FATAL: Failed to deploy active scrubber")
                return False

            # Set as active and save immediately (in case standby deployment fails)
            self.scrubber_manager.set_active(new_active.node_id)
            self.scrubber_manager.save_state()  # CRITICAL: Save after role assignment
            self.active_scrubber = new_active
            logger.info(
                f"✓ Active scrubber deployed: {new_active.node_id} "
                f"({new_active.public_ip}) - state saved"
            )
        else:
            logger.info(
                f"✓ Using existing active scrubber: {self.active_scrubber.node_id} "
                f"({self.active_scrubber.public_ip})"
            )

        # AUDIT SHARD: No standby needed - skip standby deployment
        # Standby scrubbers are only used for production shards (managed by TPM)
        # This saves resources since audit shards are transient and don't need HA
        if self.standby_scrubber:
            # If we recovered a standby from previous config, terminate it to save resources
            logger.info("Audit shards don't need standby - terminating recovered standby...")
            standby_ip = self.standby_scrubber.public_ip
            standby_node_id = self.standby_scrubber.node_id
            try:
                success = self.scrubber_manager.destroy_scrubber(standby_node_id)
                self.standby_scrubber = None
                if success:
                    logger.info(f"✓ Standby scrubber terminated: {standby_node_id} ({standby_ip})")
                else:
                    logger.warning(f"Failed to terminate standby scrubber {standby_node_id}")
            except Exception as e:
                logger.warning(f"Failed to terminate standby scrubber: {e}")
                self.standby_scrubber = None
        else:
            logger.info("✓ No standby scrubber needed for audit shard")

        # Save final state
        self.scrubber_manager.save_state()

        # Update config - audit shard only has active scrubber (no standby)
        deployed_count = 1 if self.active_scrubber else 0

        # Update scrubber config with AUDIT shard scrubbers only
        # This config is sent to validators for auditing - validators MUST only audit
        # the audit shard, not production shards created by TPM for customer origins.
        # Production shards are managed separately via the Control Plane API and TPM.
        self.scrubber_config.num_scrubbers = deployed_count
        self.scrubber_config.active_nodes = [
            self.active_scrubber.public_ip
        ] if self.active_scrubber else []

        # Start health monitor
        self.health_monitor = HealthMonitor(
            scrubber_manager=self.scrubber_manager,
            interval=30  # 30s health checks
        )
        asyncio.get_event_loop().run_until_complete(
            self.health_monitor.start()
        )

        # BPF sync only needed for production shards with standby
        # Audit shards have no standby, so no sync needed
        # (Production shards managed by TPM will have their own sync logic)

        # Final summary
        logger.info("=" * 60)
        logger.info("AUDIT SHARD SCRUBBER SETUP COMPLETE")
        logger.info("=" * 60)
        logger.info(f"  Miner ID: {self.scrubber_manager.miner_id}")
        logger.info(f"  Shard Type: AUDIT (single scrubber, no standby)")
        logger.info(f"  Active:   {self.active_scrubber.node_id if self.active_scrubber else 'NONE'} "
                    f"({self.active_scrubber.public_ip if self.active_scrubber else 'N/A'})")
        logger.info(f"  Total:    {deployed_count}/{self.AUDIT_SCRUBBERS_REQUIRED}")
        logger.info(f"  State:    {self.scrubber_manager.state_file}")
        logger.info("=" * 60)

        # Register scrubbers as a shard in control plane database
        # This enables TPM to discover and use these scrubbers for origin assignment
        if deployed_count >= 1:
            self._register_scrubbers_in_control_plane()

        return deployed_count >= 1  # At least active scrubber required

    def _register_scrubbers_in_control_plane(self) -> bool:
        """
        Register deployed scrubbers as a shard in the Miner Control Plane database.

        This bridges the gap between:
        - ScrubberManager: Deploys raw EC2 scrubbers (for validator audits)
        - Control Plane: Manages shards/origins (for TPM integration)

        Without this registration, TPM queries the miner for shards and gets an empty
        list, causing TPM to deploy new shards instead of using existing ones.

        Returns:
            True if registration successful, False otherwise.
        """
        if not self.active_scrubber:
            logger.warning("No active scrubber to register in control plane")
            return False

        try:
            from miner_control_plane.services.state_manager import state_manager
            from shared.database import get_db_connection
            from shared.utils.database_helpers import db_save_node

            region = self.settings.scrubber_region
            # Use region + short miner_id to make shard_id unique per miner
            # This prevents conflicts when multiple miners are in the same region
            miner_id_short = state_manager.miner_id[:8] if state_manager.miner_id else "local"
            shard_id = f"{region}-{miner_id_short}"

            logger.info(f"Registering scrubbers as shard '{shard_id}' in control plane...")

            # Fetch ENI IDs from AWS - required for capacity checks in TPM
            # Without ENI IDs, shards are marked as "not ready" and TPM deploys new shards
            active_eni_id = ""
            standby_eni_id = ""

            if self.settings.scrubber_provider == "aws":
                try:
                    aws_provider = get_provider("aws")

                    # Fetch ENI for active scrubber
                    active_enis = aws_provider.describe_network_interfaces(
                        instance_id=self.active_scrubber.instance_id,
                        region=region
                    )
                    for eni in active_enis:
                        if eni.get('device_index') == 0:  # Primary ENI
                            active_eni_id = eni.get('network_interface_id', '')
                            logger.info(f"  Found active scrubber ENI: {active_eni_id}")
                            break

                    # Fetch ENI for standby scrubber (if exists)
                    if self.standby_scrubber:
                        standby_enis = aws_provider.describe_network_interfaces(
                            instance_id=self.standby_scrubber.instance_id,
                            region=region
                        )
                        for eni in standby_enis:
                            if eni.get('device_index') == 0:  # Primary ENI
                                standby_eni_id = eni.get('network_interface_id', '')
                                logger.info(f"  Found standby scrubber ENI: {standby_eni_id}")
                                break
                except Exception as e:
                    logger.warning(f"Failed to fetch ENI IDs from AWS: {e}. Nodes may not be marked as ready.")

            # Create shard record (idempotent - won't duplicate if exists)
            # Miner startup always creates an 'audit' shard for validator scoring
            # Production shards are created later by TPM on-demand for customer origins
            state_manager.create_shard(shard_id, region, shard_type='audit')
            logger.info(f"  Created/verified audit shard: {shard_id}")

            # Get database connection for node persistence
            db = get_db_connection()

            # CLEANUP: Remove stale nodes that no longer exist
            # This handles the case where AWS instances were deleted but database wasn't cleaned up
            current_node_ids = {self.active_scrubber.instance_id}
            if self.standby_scrubber:
                current_node_ids.add(self.standby_scrubber.instance_id)

            try:
                cur = db.conn.cursor()
                # Find and remove stale nodes for this shard (nodes not in current_node_ids)
                cur.execute("""
                    DELETE FROM nodes
                    WHERE shard_id = %s
                      AND miner_id = %s
                      AND node_id NOT IN %s
                    RETURNING node_id
                """, (shard_id, state_manager.miner_id, tuple(current_node_ids)))
                deleted_nodes = cur.fetchall()
                if deleted_nodes:
                    deleted_ids = [row[0] for row in deleted_nodes]
                    logger.warning(f"  Cleaned up {len(deleted_ids)} stale nodes from database: {deleted_ids}")
                db.conn.commit()
                cur.close()
            except Exception as e:
                logger.warning(f"Failed to cleanup stale nodes: {e}")
                db.conn.rollback()

            try:
                # Register active scrubber as node
                active_node_data = {
                    'node_id': self.active_scrubber.instance_id,
                    'shard_id': shard_id,
                    'region': region,
                    'role': 'active',
                    'instance_name': f"{shard_id}-a",
                    'hostname': f"{shard_id}-a",
                    'provider': self.settings.scrubber_provider,
                    'status': 'active',
                    'public_ip': self.active_scrubber.public_ip,
                    'private_ip': self.active_scrubber.private_ip or '',
                    'eni_id': active_eni_id,  # Populated from AWS for capacity checks
                    'instance_type': self.settings.scrubber_instance_type,
                    'bandwidth_bps': 0,
                }

                db_save_node(active_node_data, db, miner_id=state_manager.miner_id)
                state_manager.add_node(active_node_data)
                logger.info(f"  Registered active node: {self.active_scrubber.instance_id}")

                standby_node_id = None

                # Register standby scrubber as node (if exists and different from active)
                # Safety check: prevent same instance being registered as both active and standby
                if self.standby_scrubber and self.standby_scrubber.instance_id != self.active_scrubber.instance_id:
                    standby_node_data = {
                        'node_id': self.standby_scrubber.instance_id,
                        'shard_id': shard_id,
                        'region': region,
                        'role': 'standby',
                        'instance_name': f"{shard_id}-b",
                        'hostname': f"{shard_id}-b",
                        'provider': self.settings.scrubber_provider,
                        'status': 'active',
                        'public_ip': self.standby_scrubber.public_ip,
                        'private_ip': self.standby_scrubber.private_ip or '',
                        'eni_id': standby_eni_id,  # Populated from AWS for capacity checks
                        'instance_type': self.settings.scrubber_instance_type,
                        'bandwidth_bps': 0,
                    }

                    db_save_node(standby_node_data, db, miner_id=state_manager.miner_id)
                    state_manager.add_node(standby_node_data)
                    standby_node_id = self.standby_scrubber.instance_id
                    logger.info(f"  Registered standby node: {self.standby_scrubber.instance_id}")

                # Update shard state with active/standby assignment
                state_manager.update_shard_state(
                    shard_id=shard_id,
                    active_node=self.active_scrubber.instance_id,
                    standby_node=standby_node_id
                )

                # Update shard status to 'active'
                state_manager.update_shard_status(shard_id, 'active')

                logger.info(f"  Shard state updated: active={self.active_scrubber.instance_id}, "
                            f"standby={standby_node_id}")
                logger.info(f"Scrubbers registered in control plane successfully")

                # Run config sync to ensure scrubbers have up-to-date protection code
                try:
                    from miner_control_plane.services.config_sync import run_config_sync
                    run_config_sync()
                except Exception as e:
                    logger.warning(f"Config sync after registration failed: {e}")

                return True

            finally:
                db.close()

        except ImportError as e:
            logger.warning(f"Control plane not available, skipping shard registration: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to register scrubbers in control plane: {e}", exc_info=True)
            return False

    async def _bpf_sync_loop(self) -> None:
        """
        Background task to sync BPF maps from active to standby.

        Runs every 5 seconds to keep standby scrubber state in sync.
        """
        while True:
            try:
                await asyncio.sleep(self.bpf_sync_interval)

                if not self.active_scrubber or not self.standby_scrubber:
                    continue

                # Sync BPF maps
                success = await self._sync_bpf_maps()

                if success:
                    self.last_bpf_sync = time.time()
                    logger.debug("BPF maps synced to standby scrubber")
                else:
                    logger.warning("BPF map sync failed")

            except asyncio.CancelledError:
                logger.info("BPF sync loop cancelled")
                break
            except Exception as e:
                logger.error(f"BPF sync error: {e}")
                await asyncio.sleep(self.bpf_sync_interval)

    async def _sync_bpf_maps(self) -> bool:
        """
        Sync BPF maps from active to standby scrubber.

        Maps to sync:
        - blacklist_map: IP blacklist
        - whitelist_map: IP whitelist
        - origin_rate_config_map: Per-origin rate limits
        - vip_state_map: Per-VIP challenge state

        Returns:
            True if sync successful, False otherwise.
        """
        if not self.active_scrubber or not self.standby_scrubber:
            return False

        try:
            from shared.utils.bpf_helpers import bpf_read_map, bpf_update_map

            # Maps to sync (XDP maps that contain per-origin/per-IP state)
            maps_to_sync = [
                "blacklist_map",
                "whitelist_map",
                "origin_rate_config_map",
                "vip_state_map",
            ]

            active_ip = self.active_scrubber.public_ip
            standby_ip = self.standby_scrubber.public_ip
            ssh_key = self.settings.ssh_key_path

            # Determine SSH user based on provider
            provider = get_provider(self.settings.scrubber_provider)
            user = provider.default_ssh_user

            synced_count = 0
            error_count = 0

            for map_name in maps_to_sync:
                try:
                    # Read entries from active scrubber
                    entries = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: bpf_read_map(active_ip, map_name, ssh_key, user)
                    )

                    if not entries:
                        logger.debug(f"No entries in {map_name} to sync")
                        continue

                    # Sync each entry to standby
                    for entry in entries:
                        if "key" in entry and "value" in entry:
                            # Use raw hex format for update
                            key_hex = " ".join(f"{b:02x}" for b in entry["key"])
                            value_hex = " ".join(f"{b:02x}" for b in entry["value"])

                            success = await asyncio.get_event_loop().run_in_executor(
                                None,
                                lambda kh=key_hex, vh=value_hex: self._sync_single_entry(
                                    standby_ip, map_name, kh, vh, ssh_key, user
                                )
                            )

                            if success:
                                synced_count += 1
                            else:
                                error_count += 1

                except Exception as e:
                    logger.warning(f"Error syncing {map_name}: {e}")
                    error_count += 1

            if synced_count > 0:
                logger.debug(
                    f"BPF sync complete: {synced_count} entries synced, "
                    f"{error_count} errors"
                )

            return error_count == 0

        except Exception as e:
            logger.error(f"BPF sync failed: {e}")
            return False

    def _sync_single_entry(
        self,
        host: str,
        map_name: str,
        key_hex: str,
        value_hex: str,
        ssh_key: str,
        user: str
    ) -> bool:
        """Sync a single BPF map entry to standby scrubber."""
        from shared.utils.ssh import ssh_exec

        command = (
            f"sudo bpftool map update name {map_name} "
            f"key hex {key_hex} value hex {value_hex} 2>/dev/null || true"
        )

        exit_code, _, stderr = ssh_exec(
            host=host,
            username=user,
            key_filename=ssh_key,
            command=command,
            timeout=10
        )

        return exit_code == 0

    async def handle_failover(self) -> bool:
        """
        Handle failover from active to standby scrubber.

        Process:
        1. Detect active scrubber failure
        2. Promote standby to active (update roles)
        3. Deploy new standby
        4. Save state
        5. Resume BPF sync

        Returns:
            True if failover successful, False otherwise.
        """
        logger.warning("=" * 40)
        logger.warning("INITIATING SCRUBBER FAILOVER")
        logger.warning("=" * 40)

        if not self.standby_scrubber:
            logger.error("No standby scrubber available for failover")
            return False

        state_modified = False
        try:
            old_active = self.active_scrubber
            old_active_node_id = old_active.node_id if old_active else None

            # Promote standby to active using role system
            self.scrubber_manager.set_active(self.standby_scrubber.node_id)
            self.active_scrubber = self.standby_scrubber
            self.standby_scrubber = None
            state_modified = True

            # CRITICAL: Save state immediately after promotion to prevent data loss
            self.scrubber_manager.save_state()
            logger.info(
                f"✓ Promoted standby to active: {self.active_scrubber.node_id} "
                f"({self.active_scrubber.public_ip}) - state saved"
            )

            # Track failover
            self.failover_count += 1
            self.last_failover = time.time()

            # Teardown old active (if exists)
            if old_active_node_id:
                logger.info(f"Destroying failed scrubber: {old_active_node_id}")
                self.scrubber_manager.destroy_scrubber(old_active_node_id)
                # destroy_scrubber already saves state

            # Deploy new standby
            logger.info("Deploying replacement standby scrubber...")
            new_standby = self.scrubber_manager.deploy_scrubber(
                region=self.settings.scrubber_region,
                instance_type=self.settings.scrubber_instance_type,
            )
            # deploy_scrubber already saves state

            if new_standby:
                self.scrubber_manager.set_standby(new_standby.node_id)
                self.standby_scrubber = new_standby
                state_modified = True
                logger.info(
                    f"✓ New standby deployed: {new_standby.node_id} "
                    f"({new_standby.public_ip})"
                )

                # Resume BPF sync
                asyncio.get_event_loop().create_task(self._bpf_sync_loop())
            else:
                logger.warning("⚠ Failed to deploy new standby - operating without failover")

            logger.info("=" * 40)
            logger.info(f"FAILOVER COMPLETE (total: {self.failover_count})")
            logger.info(f"  Active:  {self.active_scrubber.node_id} ({self.active_scrubber.public_ip})")
            logger.info(f"  Standby: {self.standby_scrubber.node_id if self.standby_scrubber else 'NONE'}")
            logger.info("=" * 40)

            return True

        except Exception as e:
            logger.error(f"Failover failed: {e}")
            return False

        finally:
            # CRITICAL: Always save state after failover, even on error
            if state_modified:
                try:
                    self.scrubber_manager.save_state()
                    logger.debug("Failover state saved in finally block")
                except Exception as save_error:
                    logger.error(f"CRITICAL: Failed to save state after failover: {save_error}")

    def teardown_scrubbers(self, destroy_instances: bool = False) -> bool:
        """
        Tear down scrubber management (graceful shutdown).

        By default, this saves state and stops monitoring but keeps
        cloud instances running for recovery on restart.

        Args:
            destroy_instances: If True, also terminate cloud instances.
                             Only set True for permanent deregistration.
        """
        logger.info("Tearing down scrubber management...")

        # Stop health monitor
        if self.health_monitor:
            asyncio.get_event_loop().run_until_complete(
                self.health_monitor.stop()
            )

        if self.scrubber_manager:
            if destroy_instances:
                # Permanent teardown - destroy cloud instances
                logger.warning("DESTROYING cloud instances (permanent teardown)")
                destroyed = self.scrubber_manager.destroy_all_scrubbers()
                logger.info(f"Destroyed {destroyed} scrubbers")
                self.scrubber_manager.clear_state()
            else:
                # Graceful shutdown - save state for restart recovery
                logger.info("Saving scrubber state for restart recovery...")
                self.scrubber_manager.save_state()
                logger.info(
                    f"State saved: {len(self.scrubber_manager.scrubbers)} scrubber(s) "
                    f"will be recovered on next start"
                )

        self.active_scrubber = None
        self.standby_scrubber = None

        return True

    def destroy_scrubbers_permanently(self) -> bool:
        """
        Permanently destroy all scrubbers and clear state.

        Use this only for permanent deregistration from the subnet.
        For normal restarts, use teardown_scrubbers() which preserves state.
        """
        return self.teardown_scrubbers(destroy_instances=True)

    def is_available(self) -> bool:
        """Check if miner is available for challenges/assignments.

        Returns True only if:
        1. We have an active scrubber reference
        2. The scrubber is marked as healthy
        3. The scrubber is in running status
        """
        if self.active_scrubber is None:
            return False

        # Check scrubber health status (updated by health monitor)
        if hasattr(self.active_scrubber, 'health_status'):
            if self.active_scrubber.health_status != "healthy":
                logger.debug(f"Scrubber {self.active_scrubber.node_id} health_status={self.active_scrubber.health_status}, not available")
                return False

        # Check scrubber running status
        if hasattr(self.active_scrubber, 'status'):
            if self.active_scrubber.status != "running":
                logger.debug(f"Scrubber {self.active_scrubber.node_id} status={self.active_scrubber.status}, not available")
                return False

        return True

    def _update_active_nodes(self) -> None:
        """
        Update scrubber_config.active_nodes to reflect current healthy scrubber state.

        This is called before each PingSynapse response to ensure validators
        receive accurate, up-to-date scrubber IPs instead of stale cached values.

        The active_nodes list will be:
        - [scrubber_ip] if we have a healthy, running active scrubber
        - [] (empty) if no healthy scrubber is available

        This prevents validators from seeing stale IPs after:
        - Health monitor marks scrubber as unhealthy
        - Cloud sync removes terminated instances
        - Failover changes the active scrubber
        """
        if self.is_available() and self.active_scrubber:
            # We have a healthy active scrubber - update with current IP
            current_ip = self.active_scrubber.public_ip
            if self.scrubber_config.active_nodes != [current_ip]:
                logger.info(f"Updating active_nodes: {self.scrubber_config.active_nodes} -> [{current_ip}]")
                self.scrubber_config.active_nodes = [current_ip]
        else:
            # No healthy scrubber - clear active_nodes
            if self.scrubber_config.active_nodes:
                logger.info(f"Clearing active_nodes (no healthy scrubber): {self.scrubber_config.active_nodes} -> []")
                self.scrubber_config.active_nodes = []

    def handle_challenge(
        self,
        synapse: ChallengeSynapse
    ) -> ChallengeSynapse:
        """
        Handle a challenge from a validator.

        Dispatches to appropriate handler based on task type.
        """
        task = synapse.task
        logger.info(f"Received challenge: {task}")

        try:
            if task == "setup":
                return self._handle_setup(synapse)
            elif task == "challenge":
                return self._handle_challenge_task(synapse)
            elif task == "audit":
                return self._handle_audit(synapse)
            elif task == "status":
                return self._handle_status(synapse)
            else:
                synapse.success = False
                synapse.error_message = f"Unknown task: {task}"
                return synapse

        except Exception as e:
            logger.error(f"Challenge error: {e}")
            synapse.success = False
            synapse.error_message = str(e)
            return synapse

    def _handle_setup(self, synapse: ChallengeSynapse) -> ChallengeSynapse:
        """Handle setup task from validator."""
        logger.info("Handling setup task")

        # Verify scrubbers are ready
        if not self.is_available():
            synapse.success = False
            synapse.error_message = "No active scrubber available"
            return synapse

        # Check health
        health_status = {}
        if self.active_scrubber:
            health_status["active"] = self.scrubber_manager.check_health(
                self.active_scrubber.node_id
            )

        if self.standby_scrubber:
            health_status["standby"] = self.scrubber_manager.check_health(
                self.standby_scrubber.node_id
            )

        synapse.success = health_status.get("active", False)
        synapse.result_data = {
            "active_scrubber": self.active_scrubber.public_ip if self.active_scrubber else None,
            "standby_scrubber": self.standby_scrubber.public_ip if self.standby_scrubber else None,
            "health_status": health_status,
            "failover_count": self.failover_count,
        }

        return synapse

    def _handle_audit(self, synapse: ChallengeSynapse) -> ChallengeSynapse:
        """
        Handle audit task from validator (production phase).

        Validators use this to audit active miners.
        """
        logger.info("Handling audit task")

        if not self.is_available():
            synapse.success = False
            synapse.error_message = "No active scrubber available"
            return synapse

        # Collect production metrics
        metrics = self._collect_production_metrics()

        synapse.success = True
        synapse.result_data = {
            "metrics": metrics,
            "active_scrubber_ip": self.active_scrubber.public_ip if self.active_scrubber else None,
            "failover_count": self.failover_count,
        }

        return synapse

    def _handle_challenge_task(
        self,
        synapse: ChallengeSynapse
    ) -> ChallengeSynapse:
        """Handle challenge execution task (pre-assignment phase)."""
        logger.info("Handling challenge task")

        self.active_challenge = synapse.origin_id
        self.challenge_start_time = time.time()

        # Collect initial stats
        initial_stats = {}
        if self.scrubber_manager:
            initial_stats = self.scrubber_manager.get_all_stats()

        # Wait for challenge duration
        duration = synapse.duration_seconds
        logger.info(f"Challenge running for {duration}s...")
        time.sleep(min(duration, 60))  # Cap at 60s

        # Collect final stats
        final_stats = {}
        if self.scrubber_manager:
            final_stats = self.scrubber_manager.get_all_stats()

        # Calculate metrics
        metrics = self._calculate_challenge_metrics(initial_stats, final_stats)

        synapse.success = True
        synapse.result_data = {
            "origin_id": synapse.origin_id,
            "duration": duration,
            "metrics": metrics,
        }

        self.active_challenge = None
        return synapse

    def _handle_status(self, synapse: ChallengeSynapse) -> ChallengeSynapse:
        """Handle status query."""
        synapse.success = True
        synapse.result_data = {
            "available": self.is_available(),
            "active_scrubber": {
                "node_id": self.active_scrubber.node_id if self.active_scrubber else None,
                "public_ip": self.active_scrubber.public_ip if self.active_scrubber else None,
            } if self.active_scrubber else None,
            "standby_scrubber": {
                "node_id": self.standby_scrubber.node_id if self.standby_scrubber else None,
                "public_ip": self.standby_scrubber.public_ip if self.standby_scrubber else None,
            } if self.standby_scrubber else None,
            "failover_count": self.failover_count,
            "last_failover": self.last_failover,
            "last_bpf_sync": self.last_bpf_sync,
            "active_challenge": self.active_challenge,
            "health_status": (
                self.health_monitor.get_status()
                if self.health_monitor else {}
            ),
        }
        return synapse

    def _collect_production_metrics(self) -> Dict[str, Any]:
        """
        Collect production metrics for validator audit.

        Returns:
            Dict with XDP stats, lifetime counters, etc.
        """
        metrics = {
            "xdp_pass": 0,
            "xdp_drop_blacklist": 0,
            "xdp_drop_ratelimit": 0,
            "xdp_drop_quarantine": 0,
            "xdp_drop_bogon": 0,
            "total_bytes_ingress": 0,
            "total_bytes_egress": 0,
            "active_connections": 0,
        }

        if not self.scrubber_manager or not self.active_scrubber:
            return metrics

        # Get stats from active scrubber
        stats = self.scrubber_manager.get_stats(self.active_scrubber.node_id)

        if stats:
            if hasattr(stats, 'xdp_pass'):
                metrics["xdp_pass"] = stats.xdp_pass
            if hasattr(stats, 'xdp_drop_blacklist'):
                metrics["xdp_drop_blacklist"] = stats.xdp_drop_blacklist
            if hasattr(stats, 'xdp_drop_ratelimit'):
                metrics["xdp_drop_ratelimit"] = stats.xdp_drop_ratelimit
            if hasattr(stats, 'xdp_drop_quarantine'):
                metrics["xdp_drop_quarantine"] = stats.xdp_drop_quarantine

            # Estimate byte counters from packet counts (avg packet size)
            metrics["total_bytes_ingress"] = stats.xdp_pass * 1500
            metrics["total_bytes_egress"] = stats.xdp_pass * 1400

        return metrics

    def _calculate_challenge_metrics(
        self,
        initial_stats: Dict[str, Any],
        final_stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate performance metrics from stats delta.

        Args:
            initial_stats: Stats before challenge.
            final_stats: Stats after challenge.

        Returns:
            Calculated metrics dictionary.
        """
        # Aggregate stats across all scrubbers
        def aggregate(stats_dict):
            agg = {
                "xdp_pass": 0,
                "xdp_drop_blacklist": 0,
                "xdp_drop_ratelimit": 0,
                "xdp_drop_quarantine": 0,
            }
            for stats in stats_dict.values():
                if hasattr(stats, 'xdp_pass'):
                    agg["xdp_pass"] += stats.xdp_pass
                    agg["xdp_drop_blacklist"] += stats.xdp_drop_blacklist
                    agg["xdp_drop_ratelimit"] += stats.xdp_drop_ratelimit
                    agg["xdp_drop_quarantine"] += stats.xdp_drop_quarantine
            return agg

        initial = aggregate(initial_stats)
        final = aggregate(final_stats)

        # Calculate deltas
        passed = final["xdp_pass"] - initial["xdp_pass"]
        dropped = (
            (final["xdp_drop_blacklist"] - initial["xdp_drop_blacklist"])
            + (final["xdp_drop_ratelimit"] - initial["xdp_drop_ratelimit"])
            + (final["xdp_drop_quarantine"] - initial["xdp_drop_quarantine"])
        )

        total = passed + dropped

        return {
            "total_packets_sent": total,
            "total_reaching_packets": passed,
            "total_dropped": dropped,
            # Placeholder values for pre-assignment
            "avg_rtt_ms": 15.0,  # Measured by validator's synthetic traffic
        }

    def _get_validator_uid_from_synapse(self, synapse: "bt.Synapse") -> int:
        """
        Get the validator's UID from the synapse's dendrite hotkey.

        The synapse inherently identifies its sender via dendrite.hotkey.
        We look up the UID from the metagraph to ensure proper isolation
        between validators without relying on explicit validator_uid fields.

        Args:
            synapse: Any synapse with dendrite information.

        Returns:
            The validator's UID, or -1 if not found.
        """
        try:
            caller_hotkey = synapse.dendrite.hotkey
            if not caller_hotkey:
                logger.warning("Synapse has no dendrite hotkey")
                return -1
            return self.metagraph.hotkeys.index(caller_hotkey)
        except ValueError:
            logger.warning(f"Validator hotkey not found in metagraph: {caller_hotkey}")
            return -1
        except Exception as e:
            logger.error(f"Failed to get validator UID from synapse: {e}")
            return -1

    def handle_audit_challenge(
        self,
        synapse: AuditChallengeSynapse
    ) -> AuditChallengeSynapse:
        """
        Handle real traffic audit challenge from validator.

        This is the challenge-response system that PROVES the miner
        is actually filtering traffic with XDP, not faking results.

        Flow:
        1. Validator sends 'start' phase - we snapshot XDP stats
        2. Validator sends REAL packets to our scrubber
        3. Validator sends 'collect' phase - we return XDP stats delta

        Args:
            synapse: Audit challenge with phase and challenge_id

        Returns:
            Updated synapse with real XDP stats
        """
        # Get validator UID from synapse's dendrite (not from explicit field)
        # This ensures proper isolation - each validator is identified by their hotkey
        validator_uid = self._get_validator_uid_from_synapse(synapse)
        if validator_uid < 0:
            synapse.success = False
            synapse.error_message = "Could not identify validator from synapse"
            return synapse

        logger.info(f"Audit challenge: phase={synapse.phase}, id={synapse.challenge_id}, validator_uid={validator_uid}")

        if synapse.phase == "start":
            return self._handle_audit_start(synapse, validator_uid)
        elif synapse.phase == "collect":
            return self._handle_audit_collect(synapse, validator_uid)
        else:
            synapse.success = False
            synapse.error_message = f"Unknown phase: {synapse.phase}"
            return synapse

    def _handle_audit_start(
        self,
        synapse: AuditChallengeSynapse,
        validator_uid: int
    ) -> AuditChallengeSynapse:
        """
        Handle 'start' phase of audit challenge.

        SCALABLE COMBINED FLOW:
        1. If tunnel fields provided, set up WireGuard tunnel first
        2. Snapshot AUDIT XDP stats after tunnel is ready
        3. Return tunnel config + stats snapshot in one response

        This eliminates a separate tunnel setup round-trip, reducing
        the total from 3 synapses to 2 for better scalability.

        Args:
            synapse: The audit challenge synapse.
            validator_uid: UID of the validator (derived from synapse.dendrite.hotkey).
        """
        if not self.is_available():
            synapse.success = False
            synapse.error_message = "No active scrubber available"
            logger.warning(f"Audit start rejected: no active scrubber")
            return synapse

        try:
            # Cleanup old challenges first (prevent memory leak)
            self._cleanup_old_audit_challenges()

            # === COMBINED TUNNEL SETUP (if tunnel fields provided) ===
            # This eliminates the separate SetupTunnelSynapse round-trip
            if synapse.validator_pubkey and synapse.validator_ip and synapse.validator_port:
                tunnel_result = self._setup_audit_tunnel(synapse, validator_uid)
                if not tunnel_result["success"]:
                    synapse.success = False
                    synapse.error_message = tunnel_result["error"]
                    return synapse

                # Fill in tunnel response fields
                synapse.scrubber_pubkey = tunnel_result["scrubber_pubkey"]
                synapse.scrubber_port = tunnel_result["scrubber_port"]
                synapse.tunnel_ip_scrubber = tunnel_result["tunnel_ip_scrubber"]
                synapse.tunnel_ip_validator = tunnel_result["tunnel_ip_validator"]

                logger.debug(
                    f"Audit START: tunnel setup complete for challenge={synapse.challenge_id}, "
                    f"scrubber_port={synapse.scrubber_port}"
                )

            # === SNAPSHOT XDP STATS ===
            # Read from AUDIT XDP stats map (attached to WireGuard interface)
            # Use validator_uid to find the specific map for this validator's tunnel
            snapshot_time = time.time()
            stats_snapshot = self._get_audit_xdp_stats(synapse.scrubber_ip, validator_uid)

            # === RESET NGINX RATE LIMIT STATS (Layer 7) ===
            # Clear nginx rate limit logs before audit traffic starts
            self._reset_nginx_ratelimit_stats(synapse.scrubber_ip)

            # Store challenge state in validator's isolated namespace
            # Each validator has its own dictionary to prevent interference
            if validator_uid not in self.audit_challenges:
                self.audit_challenges[validator_uid] = {}

            self.audit_challenges[validator_uid][synapse.challenge_id] = {
                "scrubber_ip": synapse.scrubber_ip,
                "validator_uid": validator_uid,  # Needed to find the right XDP map
                "stats_snapshot": stats_snapshot,
                "snapshot_time": snapshot_time,
            }

            # Count total active challenges across all validators
            total_active = sum(len(v) for v in self.audit_challenges.values())
            logger.info(
                f"Audit START: challenge={synapse.challenge_id}, "
                f"scrubber={synapse.scrubber_ip}, "
                f"snapshot={stats_snapshot}, "
                f"active_challenges={total_active} (validator {validator_uid}: {len(self.audit_challenges[validator_uid])})"
            )

            synapse.success = True
            synapse.stats_before = stats_snapshot.copy()
            synapse.response_timestamp = snapshot_time

            return synapse
        except Exception as e:
            logger.error(f"Exception in _handle_audit_start: {e}", exc_info=True)
            synapse.success = False
            synapse.error_message = f"Internal error: {str(e)}"
            return synapse

    def _setup_audit_tunnel(self, synapse: AuditChallengeSynapse, validator_uid: int) -> Dict[str, Any]:
        """
        Set up WireGuard tunnel on scrubber for audit traffic.

        OPTIMIZED: Uses a single batched SSH command instead of 10+ separate calls.
        This reduces tunnel setup time from ~30s to ~5s.

        Args:
            synapse: The audit challenge synapse with tunnel config.
            validator_uid: UID of the validator (derived from synapse.dendrite.hotkey).

        Returns:
            Dict with success, error, and tunnel config fields.
        """
        from shared.utils.ssh import ssh_exec

        result = {
            "success": False,
            "error": "",
            "scrubber_pubkey": "",
            "scrubber_port": 0,
            "tunnel_ip_scrubber": "",
            "tunnel_ip_validator": "",
        }

        # Validate scrubber IP is one of ours
        if not self.active_scrubber or synapse.scrubber_ip != self.active_scrubber.public_ip:
            result["error"] = f"Scrubber {synapse.scrubber_ip} not found or not active"
            return result

        try:
            # Generate WireGuard keypair for scrubber (local, fast)
            import subprocess
            gen_result = subprocess.run(["wg", "genkey"], capture_output=True, text=True, timeout=10)
            scrubber_private_key = gen_result.stdout.strip()
            pub_result = subprocess.run(["wg", "pubkey"], input=scrubber_private_key,
                                        capture_output=True, text=True, timeout=10)
            scrubber_public_key = pub_result.stdout.strip()

            # Calculate tunnel config
            miner_uid = self.uid
            wg_port = 10000 + (validator_uid * 216 + miner_uid)
            tunnel_name = f"wga{validator_uid}_{miner_uid}"
            subnet_second = 100 + (validator_uid % 156)
            tunnel_ip_scrubber = f"10.{subnet_second}.{miner_uid}.1"
            tunnel_ip_validator = f"10.{subnet_second}.{miner_uid}.2"
            key_file = f"/tmp/wg_key_{tunnel_name}"
            xdp_path = "/home/ubuntu/assets/ebpf/build/xdp_wg_audit.o"

            # Determine SSH user based on provider
            ssh_user = "ubuntu"
            if self.settings.scrubber_provider and self.settings.scrubber_provider.lower() == "linode":
                ssh_user = "root"

            scrubber_ip = synapse.scrubber_ip

            # OPTIMIZED: Single batched SSH command for ALL tunnel setup + blacklist population
            # This eliminates 20+ SSH connection round-trips, reducing setup from ~60s to ~5s
            #
            # Known malicious prefixes for blacklist (matches real_packet_sender.MALICIOUS_PREFIXES)
            # Format: IP/prefix_len -> LPM key hex
            malicious_prefixes_cmds = """
# Populate audit_blacklist_map with known malicious prefixes
PROG_ID=$(sudo bpftool net show dev {tunnel_name} 2>/dev/null | grep -oE 'id [0-9]+' | head -1 | cut -d' ' -f2)
if [ -n "$PROG_ID" ]; then
    MAP_IDS=$(sudo bpftool prog show id $PROG_ID 2>/dev/null | grep -oE 'map_ids [0-9,]+' | cut -d' ' -f2 | tr ',' ' ')
    for MID in $MAP_IDS; do
        if sudo bpftool map show id $MID 2>/dev/null | grep -q audit_blacklist; then
            BLMAP=$MID
            break
        fi
    done
    if [ -n "$BLMAP" ]; then
        # Add all malicious prefixes in one go (prefix_len as 4-byte LE + IP in network order)
        sudo bpftool map update id $BLMAP key hex 16 00 00 00 2d 8e d4 00 value hex 01 2>/dev/null || true
        sudo bpftool map update id $BLMAP key hex 16 00 00 00 b9 dc 64 00 value hex 01 2>/dev/null || true
        sudo bpftool map update id $BLMAP key hex 15 00 00 00 59 f8 a0 00 value hex 01 2>/dev/null || true
        sudo bpftool map update id $BLMAP key hex 18 00 00 00 c2 a5 10 00 value hex 01 2>/dev/null || true
        sudo bpftool map update id $BLMAP key hex 16 00 00 00 2d 9b cc 00 value hex 01 2>/dev/null || true
        sudo bpftool map update id $BLMAP key hex 15 00 00 00 c1 20 a0 00 value hex 01 2>/dev/null || true
        sudo bpftool map update id $BLMAP key hex 18 00 00 00 5b f1 13 00 value hex 01 2>/dev/null || true
        sudo bpftool map update id $BLMAP key hex 17 00 00 00 05 bc 56 00 value hex 01 2>/dev/null || true
        sudo bpftool map update id $BLMAP key hex 17 00 00 00 a7 5e 8a 00 value hex 01 2>/dev/null || true
        sudo bpftool map update id $BLMAP key hex 18 00 00 00 50 52 4d 00 value hex 01 2>/dev/null || true
        echo "BLACKLIST_POPULATED"
    fi
fi
""".replace("{tunnel_name}", tunnel_name)

            batched_setup_cmd = f"""
set -e
# Remove existing interface
sudo ip link del {tunnel_name} 2>/dev/null || true
# Create WireGuard interface
sudo ip link add {tunnel_name} type wireguard
# Write private key
echo '{scrubber_private_key}' | sudo tee {key_file} > /dev/null
sudo chmod 600 {key_file}
# Configure WireGuard
sudo wg set {tunnel_name} listen-port {wg_port} private-key {key_file} peer {synapse.validator_pubkey} allowed-ips 0.0.0.0/0 endpoint {synapse.validator_ip}:{synapse.validator_port}
# Clean up key file
sudo rm -f {key_file}
# Assign IP
sudo ip addr add {tunnel_ip_scrubber}/30 dev {tunnel_name} 2>/dev/null || true
# Bring interface up
sudo ip link set {tunnel_name} up
# Set MTU
sudo ip link set {tunnel_name} mtu 1380
# Attach XDP (try xdpgeneric first, then native)
sudo ip link set dev {tunnel_name} xdpgeneric obj {xdp_path} sec xdp 2>/dev/null || sudo ip link set dev {tunnel_name} xdp obj {xdp_path} sec xdp 2>/dev/null || echo "XDP_ATTACH_FAILED"
# Verify XDP
sudo ip link show {tunnel_name} | grep -q xdp && echo 'XDP_ATTACHED' || echo 'XDP_MISSING'
{malicious_prefixes_cmds}
"""
            exit_code, stdout, stderr = ssh_exec(
                host=scrubber_ip,
                command=batched_setup_cmd,
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=60  # Single timeout for entire batch
            )

            if exit_code != 0:
                result["error"] = f"Batched tunnel setup failed: {stderr}"
                return result

            xdp_attached = "XDP_ATTACHED" in stdout
            blacklist_populated = "BLACKLIST_POPULATED" in stdout
            if blacklist_populated:
                logger.debug(f"Audit blacklist populated via batched SSH for {tunnel_name}")

            logger.info(
                f"Tunnel setup: {tunnel_name} on {scrubber_ip}:{wg_port}, XDP={'attached' if xdp_attached else 'MISSING'}"
            )

            result["success"] = True
            result["scrubber_pubkey"] = scrubber_public_key
            result["scrubber_port"] = wg_port
            result["tunnel_ip_scrubber"] = tunnel_ip_scrubber
            result["tunnel_ip_validator"] = tunnel_ip_validator

            return result

        except Exception as e:
            logger.error(f"Audit tunnel setup failed: {e}", exc_info=True)
            result["error"] = f"Tunnel setup error: {str(e)}"
            return result

    def _populate_audit_blacklist(
        self,
        scrubber_ip: str,
        tunnel_name: str,
        ssh_user: str
    ) -> None:
        """
        Populate the audit_blacklist_map with known malicious IP prefixes.

        This is required for blacklist detection to work during audits.
        The prefixes match those in real_packet_sender.MALICIOUS_PREFIXES.
        """
        from shared.utils.ssh import ssh_exec

        # Known malicious prefixes (must match real_packet_sender.MALICIOUS_PREFIXES)
        MALICIOUS_PREFIXES = [
            ("45.142.212.0", 22),
            ("185.220.100.0", 22),
            ("89.248.160.0", 21),
            ("194.165.16.0", 24),
            ("45.155.204.0", 22),
            ("193.32.160.0", 21),
            ("91.241.19.0", 24),
            ("5.188.86.0", 23),
            ("167.94.138.0", 23),
            ("80.82.77.0", 24),
        ]

        try:
            # Find the XDP program ID attached to the interface
            exit_code, stdout, stderr = ssh_exec(
                host=scrubber_ip,
                command=f"sudo bpftool net show dev {tunnel_name} 2>/dev/null | grep -oE 'id [0-9]+' | head -1 | cut -d' ' -f2",
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )
            prog_id = stdout.strip() if exit_code == 0 else ""
            if not prog_id:
                logger.debug(f"Could not find XDP prog ID for {tunnel_name}")
                return

            # Find the audit_blacklist_map ID from the program
            exit_code, stdout, stderr = ssh_exec(
                host=scrubber_ip,
                command=f'sudo bpftool prog show id {prog_id} 2>/dev/null | grep -oE "map_ids [0-9,]+" | cut -d" " -f2 | tr "," " "',
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )
            map_ids = stdout.strip().split() if exit_code == 0 else []
            if not map_ids:
                logger.debug(f"Could not find map IDs for XDP prog {prog_id}")
                return

            # Find the blacklist map
            blacklist_map_id = None
            for map_id in map_ids:
                exit_code, stdout, stderr = ssh_exec(
                    host=scrubber_ip,
                    command=f"sudo bpftool map show id {map_id} 2>/dev/null | grep -q audit_blacklist && echo {map_id}",
                    ssh_key_path=self.settings.ssh_key_path,
                    user=ssh_user,
                    timeout=30
                )
                if stdout.strip():
                    blacklist_map_id = map_id
                    break

            if not blacklist_map_id:
                logger.debug(f"audit_blacklist_map not found among maps {map_ids}")
                return

            # Add each malicious prefix to the blacklist map
            # LPM key format: prefixlen (4 bytes LE) + IP (4 bytes network order)
            added = 0
            for ip_str, prefix_len in MALICIOUS_PREFIXES:
                ip_parts = [int(x) for x in ip_str.split('.')]
                ip_hex = ' '.join(f'{b:02x}' for b in ip_parts)
                prefix_hex = ' '.join(f'{b:02x}' for b in prefix_len.to_bytes(4, 'little'))
                key_hex = f"{prefix_hex} {ip_hex}"

                exit_code, stdout, stderr = ssh_exec(
                    host=scrubber_ip,
                    command=f"sudo bpftool map update id {blacklist_map_id} key hex {key_hex} value hex 01 2>/dev/null",
                    ssh_key_path=self.settings.ssh_key_path,
                    user=ssh_user,
                    timeout=10
                )
                if exit_code == 0:
                    added += 1

            logger.debug(f"Audit blacklist populated: {added}/{len(MALICIOUS_PREFIXES)} prefixes for {tunnel_name}")

        except Exception as e:
            logger.warning(f"Failed to populate audit blacklist: {e}")

    def _handle_audit_collect(
        self,
        synapse: AuditChallengeSynapse,
        validator_uid: int
    ) -> AuditChallengeSynapse:
        """
        Handle 'collect' phase of audit challenge.

        Returns AUDIT XDP stats delta since 'start' phase.
        This is the REAL proof of what the XDP program processed.

        Args:
            synapse: The audit challenge synapse.
            validator_uid: UID of the validator (derived from synapse.dendrite.hotkey).
        """
        if not self.is_available():
            synapse.success = False
            synapse.error_message = "No active scrubber available"
            return synapse

        # Look up the challenge state from validator's isolated namespace
        # validator_uid is derived from synapse.dendrite.hotkey for proper isolation
        validator_challenges = self.audit_challenges.get(validator_uid, {})
        challenge_state = validator_challenges.get(synapse.challenge_id)
        if not challenge_state:
            synapse.success = False
            synapse.error_message = (
                f"Challenge not found: {synapse.challenge_id} "
                f"(validator {validator_uid} challenges: {list(validator_challenges.keys())})"
            )
            logger.warning(
                f"Audit COLLECT failed: challenge {synapse.challenge_id} not found. "
                f"Validator {validator_uid} active challenges: {list(validator_challenges.keys())}"
            )
            return synapse

        # Check if this challenge was already collected (idempotent retry)
        # Return cached result instead of re-reading stats
        if challenge_state.get("collected"):
            cached = challenge_state.get("cached_result", {})
            logger.info(
                f"Audit COLLECT retry: returning cached result for challenge={synapse.challenge_id}"
            )
            synapse.success = True
            synapse.reported_blocked = cached.get("reported_blocked", {})
            synapse.reported_passed = cached.get("reported_passed", 0)
            synapse.stats_after = challenge_state.get("stats_after", {})
            synapse.stats_delta = cached.get("stats_delta", {})
            synapse.response_timestamp = challenge_state.get("collected_time", time.time())
            return synapse

        # Get stored state for this specific challenge
        scrubber_ip = challenge_state["scrubber_ip"]
        stats_snapshot = challenge_state["stats_snapshot"]
        snapshot_time = challenge_state["snapshot_time"]

        # Get current AUDIT XDP stats from the same scrubber
        # Use validator_uid to find the specific map for this validator's tunnel
        current_stats = self._get_audit_xdp_stats(scrubber_ip, validator_uid)
        collect_time = time.time()

        # Calculate delta (what happened during the challenge)
        # IMPORTANT: Do NOT clamp to 0 - negative deltas indicate counter resets
        # which could be a sign of cheating (resetting XDP program to hide stats).
        # The validator uses negative values to detect tampering.
        stats_delta = {}
        counter_reset_detected = False
        for key in current_stats:
            before = stats_snapshot.get(key, 0)
            after = current_stats[key]
            delta = after - before
            stats_delta[key] = delta
            if delta < 0:
                counter_reset_detected = True
                logger.warning(
                    f"Counter reset detected for {key}: before={before}, after={after}, delta={delta}"
                )

        # Flag suspicious counter resets in the response
        if counter_reset_detected:
            logger.warning(
                f"Audit COLLECT: counter reset detected for challenge={synapse.challenge_id}, "
                f"this may indicate XDP program was reloaded during audit"
            )

        logger.info(
            f"Audit COLLECT: challenge={synapse.challenge_id}, "
            f"before={stats_snapshot}, "
            f"after={current_stats}, "
            f"delta={stats_delta}, "
            f"duration={(collect_time - snapshot_time):.2f}s"
        )

        # Fill in response
        synapse.success = True
        synapse.stats_before = stats_snapshot.copy()
        synapse.stats_after = current_stats
        synapse.stats_delta = stats_delta
        synapse.response_timestamp = collect_time

        # Report what we blocked/passed - ALL 30 XDP counter types for comprehensive audit
        # Get nginx rate limit stats (layer 7 blocking)
        nginx_ratelimit_blocked = self._get_nginx_ratelimit_stats(scrubber_ip)

        synapse.reported_blocked = {
            # Blacklist/quarantine drops (indices 2, 6, 11)
            "blacklist": stats_delta.get("xdp_drop_blacklist", 0),
            "temp_blacklist": stats_delta.get("xdp_drop_temp_blacklist", 0),
            "quarantine": stats_delta.get("xdp_drop_quarantine", 0),
            # Invalid packet drops (indices 3, 4, 26)
            "invalid_ip": stats_delta.get("xdp_drop_invalid_ip", 0),
            "invalid_tcp": stats_delta.get("xdp_drop_invalid_tcp", 0),
            "malformed": stats_delta.get("xdp_drop_malformed", 0),
            # Rate limiting (index 5)
            "ratelimit": stats_delta.get("xdp_drop_ratelimit", 0),
            # Bogon drops (index 13)
            "bogon": stats_delta.get("xdp_drop_bogon", 0),
            # TCP flag anomaly drops (indices 14-17, 22-24)
            "tcp_xmas": stats_delta.get("xdp_drop_tcp_xmas", 0),
            "tcp_null": stats_delta.get("xdp_drop_tcp_null", 0),
            "tcp_synfin": stats_delta.get("xdp_drop_tcp_synfin", 0),
            "tcp_synrst": stats_delta.get("xdp_drop_tcp_synrst", 0),
            "tcp_fin": stats_delta.get("xdp_drop_tcp_fin", 0),
            "tcp_rst": stats_delta.get("xdp_drop_tcp_rst", 0),
            "tcp_ack": stats_delta.get("xdp_drop_tcp_ack", 0),
            # Flood attack drops (indices 18, 20, 25)
            "syn_flood": stats_delta.get("xdp_drop_syn_flood", 0),
            # SYN cookie metrics (reported separately for scoring — cookies challenge ALL
            # SYNs during floods, including benign, so they can't simply be added to syn_flood)
            "syncookie_challenge": stats_delta.get("xdp_syncookie_challenge", 0),
            "syncookie_reject": stats_delta.get("xdp_syncookie_reject", 0),
            "udp_flood": stats_delta.get("xdp_drop_udp_flood", 0),
            "icmp_flood": stats_delta.get("xdp_drop_icmp_flood", 0),
            # UDP amplification (index 19)
            "udp_amp": stats_delta.get("xdp_drop_udp_amp", 0),
            # Fragmentation (index 21)
            "frag": stats_delta.get("xdp_drop_frag", 0),
            # Land attack (index 29)
            "land": stats_delta.get("xdp_drop_land", 0),
            # L7 attack drops (indices 27-28) + nginx layer 7 rate limiting
            "http_flood": stats_delta.get("xdp_drop_http_flood", 0),
            "slowloris": stats_delta.get("xdp_drop_slowloris", 0),
            "ratelimit_app": nginx_ratelimit_blocked,
            # Anti-gaming flag: negative counter = suspicious counter reset
            "counter_reset_detected": 1 if counter_reset_detected else 0,
        }
        synapse.reported_passed = stats_delta.get("xdp_pass", 0)

        # Mark challenge as collected with cached result (don't delete immediately)
        # This makes COLLECT idempotent - retries will return cached result
        # The cleanup task will remove it after TTL expires (60s for collected, 300s for pending)
        if validator_uid in self.audit_challenges and synapse.challenge_id in self.audit_challenges[validator_uid]:
            self.audit_challenges[validator_uid][synapse.challenge_id]["collected"] = True
            self.audit_challenges[validator_uid][synapse.challenge_id]["collected_time"] = time.time()
            self.audit_challenges[validator_uid][synapse.challenge_id]["stats_after"] = current_stats
            self.audit_challenges[validator_uid][synapse.challenge_id]["cached_result"] = {
                "stats_delta": stats_delta,
                "reported_blocked": synapse.reported_blocked,
                "reported_passed": synapse.reported_passed,
            }

        return synapse

    def _cleanup_old_audit_challenges(self) -> None:
        """
        Remove old audit challenges that weren't collected or collected long ago.

        TTL rules:
        - Pending challenges (not yet collected): 300 seconds (audit_challenge_max_age)
        - Collected challenges (already have result): 60 seconds after collection

        This prevents memory leaks while allowing retries to get cached results.
        """
        if not self.audit_challenges:
            return

        current_time = time.time()
        expired_count = 0
        empty_validators = []

        # TTL for collected challenges (shorter since they're just cache for retries)
        COLLECTED_CHALLENGE_TTL = 60.0  # 60 seconds after collection

        # Iterate over each validator's namespace
        for validator_uid, challenges in list(self.audit_challenges.items()):
            expired_in_validator = []
            for challenge_id, state in list(challenges.items()):
                should_expire = False

                if state.get("collected"):
                    # Already collected - expire after short TTL
                    collected_time = state.get("collected_time", state["snapshot_time"])
                    age_since_collect = current_time - collected_time
                    if age_since_collect > COLLECTED_CHALLENGE_TTL:
                        should_expire = True
                        logger.debug(
                            f"Cleaning up collected challenge: {challenge_id} "
                            f"from validator {validator_uid} (collected {age_since_collect:.1f}s ago)"
                        )
                else:
                    # Pending - expire after max_age
                    age = current_time - state["snapshot_time"]
                    if age > self.audit_challenge_max_age:
                        should_expire = True
                        logger.warning(
                            f"Cleaning up expired pending challenge: {challenge_id} "
                            f"from validator {validator_uid} (age: {age:.1f}s)"
                        )

                if should_expire:
                    expired_in_validator.append(challenge_id)

            # Remove expired challenges from this validator's namespace
            for challenge_id in expired_in_validator:
                del challenges[challenge_id]
                expired_count += 1

            # Mark empty validator namespaces for removal
            if not challenges:
                empty_validators.append(validator_uid)

        # Remove empty validator namespaces
        for validator_uid in empty_validators:
            del self.audit_challenges[validator_uid]

        if expired_count > 0:
            total_active = sum(len(v) for v in self.audit_challenges.values())
            logger.info(
                f"Cleaned up {expired_count} expired challenges, "
                f"{total_active} active across {len(self.audit_challenges)} validators"
            )

    def handle_setup_tunnel(self, synapse: SetupTunnelSynapse) -> SetupTunnelSynapse:
        """
        Handle tunnel setup request from validator.

        The miner sets up WireGuard tunnel on its own scrubber and returns
        the scrubber's WireGuard configuration to the validator.

        This ensures clear security boundaries - validators never SSH to
        miner infrastructure. Each party controls only their own machines.

        Args:
            synapse: Request with validator's WG public key and endpoint.

        Returns:
            Updated synapse with scrubber's WG config.
        """
        # Get validator UID from synapse's dendrite (not from explicit field)
        validator_uid = self._get_validator_uid_from_synapse(synapse)
        if validator_uid < 0:
            synapse.success = False
            synapse.error_message = "Could not identify validator from synapse"
            return synapse

        logger.info(
            f"Tunnel setup request: action={synapse.action}, "
            f"validator_uid={validator_uid}, scrubber={synapse.scrubber_ip}"
        )

        if synapse.action == "teardown":
            return self._handle_tunnel_teardown(synapse, validator_uid)

        return self._handle_tunnel_setup(synapse, validator_uid)

    def _handle_tunnel_setup(self, synapse: SetupTunnelSynapse, validator_uid: int) -> SetupTunnelSynapse:
        """Set up WireGuard tunnel on scrubber for validator.

        Args:
            synapse: The tunnel setup synapse.
            validator_uid: UID of the validator (derived from synapse.dendrite.hotkey).
        """
        from shared.utils.ssh import ssh_exec

        # Validate scrubber IP is one of ours
        if not self.active_scrubber or synapse.scrubber_ip != self.active_scrubber.public_ip:
            synapse.success = False
            synapse.error_message = f"Scrubber {synapse.scrubber_ip} not found or not active"
            return synapse

        if not synapse.validator_pubkey:
            synapse.success = False
            synapse.error_message = "Validator public key required"
            return synapse

        try:
            # Generate WireGuard keypair for scrubber
            import subprocess
            result = subprocess.run(["wg", "genkey"], capture_output=True, text=True, timeout=10)
            scrubber_private_key = result.stdout.strip()
            result = subprocess.run(["wg", "pubkey"], input=scrubber_private_key,
                                    capture_output=True, text=True, timeout=10)
            scrubber_public_key = result.stdout.strip()

            # Calculate tunnel IPs and port based on validator_uid
            # This ensures unique tunnels per validator
            # validator_uid is derived from synapse.dendrite.hotkey
            # Port formula: 10000 + V*216 + M (max port = 65335, no collisions)
            miner_uid = self.uid
            wg_port = 10000 + (validator_uid * 216 + miner_uid)
            # Interface name: wga{V}_{M} - max 10 chars, fits Linux 15-char limit
            tunnel_name = f"wga{validator_uid}_{miner_uid}"

            # IP addressing: 10.{100 + validator_uid % 156}.{miner_uid}.{1,2}/30
            subnet_second = 100 + (validator_uid % 156)
            tunnel_ip_scrubber = f"10.{subnet_second}.{miner_uid}.1"
            tunnel_ip_validator = f"10.{subnet_second}.{miner_uid}.2"

            # Determine SSH user based on provider
            ssh_user = "ubuntu"  # Default for AWS
            if self.settings.scrubber_provider and self.settings.scrubber_provider.lower() == "linode":
                ssh_user = "root"

            # Set up WireGuard on scrubber via SSH (miner SSH's to its own scrubber)
            scrubber_ip = synapse.scrubber_ip

            # Remove existing interface if present
            ssh_exec(
                host=scrubber_ip,
                command=f"sudo ip link del {tunnel_name} 2>/dev/null || true",
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )

            # Create WireGuard interface
            exit_code, stdout, stderr = ssh_exec(
                host=scrubber_ip,
                command=f"sudo ip link add {tunnel_name} type wireguard",
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )
            if exit_code != 0:
                synapse.success = False
                synapse.error_message = f"Failed to create WG interface: {stderr}"
                return synapse

            # Write private key and configure WireGuard
            key_file = f"/tmp/wg_key_{tunnel_name}"
            ssh_exec(
                host=scrubber_ip,
                command=f"echo '{scrubber_private_key}' | sudo tee {key_file} > /dev/null && sudo chmod 600 {key_file}",
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )

            # Configure WireGuard with validator as peer
            # Note: Validator will connect to us, so we set allowed-ips to 0.0.0.0/0
            # to accept audit packets with any source IP (spoofed for testing)
            wg_config_cmd = (
                f"sudo wg set {tunnel_name} listen-port {wg_port} private-key {key_file} "
                f"peer {synapse.validator_pubkey} allowed-ips 0.0.0.0/0 "
                f"endpoint {synapse.validator_ip}:{synapse.validator_port}"
            )
            exit_code, stdout, stderr = ssh_exec(
                host=scrubber_ip,
                command=wg_config_cmd,
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )
            if exit_code != 0:
                synapse.success = False
                synapse.error_message = f"Failed to configure WG: {stderr}"
                return synapse

            # Clean up key file
            ssh_exec(
                host=scrubber_ip,
                command=f"sudo rm -f {key_file}",
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )

            # Assign IP and bring interface up
            ssh_exec(
                host=scrubber_ip,
                command=f"sudo ip addr add {tunnel_ip_scrubber}/30 dev {tunnel_name} 2>/dev/null || true",
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )

            exit_code, stdout, stderr = ssh_exec(
                host=scrubber_ip,
                command=f"sudo ip link set {tunnel_name} up",
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )
            if exit_code != 0:
                synapse.success = False
                synapse.error_message = f"Failed to bring up WG interface: {stderr}"
                return synapse

            # Set MTU to account for WireGuard overhead
            ssh_exec(
                host=scrubber_ip,
                command=f"sudo ip link set {tunnel_name} mtu 1380",
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )

            # Attach XDP program to the tunnel interface for audit traffic filtering
            xdp_path = "/home/ubuntu/assets/ebpf/build/xdp_wg_audit.o"
            exit_code, stdout, stderr = ssh_exec(
                host=scrubber_ip,
                command=f"sudo ip link set dev {tunnel_name} xdp obj {xdp_path} sec xdp 2>/dev/null || true",
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )

            logger.info(
                f"Tunnel setup complete: {tunnel_name} on {scrubber_ip}:{wg_port}, "
                f"scrubber_ip={tunnel_ip_scrubber}, validator_ip={tunnel_ip_validator}"
            )

            # Fill in response
            synapse.success = True
            synapse.scrubber_pubkey = scrubber_public_key
            synapse.scrubber_port = wg_port
            synapse.tunnel_ip_scrubber = tunnel_ip_scrubber
            synapse.tunnel_ip_validator = tunnel_ip_validator

            return synapse

        except Exception as e:
            logger.error(f"Tunnel setup failed: {e}", exc_info=True)
            synapse.success = False
            synapse.error_message = f"Tunnel setup error: {str(e)}"
            return synapse

    def _handle_tunnel_teardown(self, synapse: SetupTunnelSynapse, validator_uid: int) -> SetupTunnelSynapse:
        """Tear down WireGuard tunnel on scrubber.

        Args:
            synapse: The tunnel teardown synapse.
            validator_uid: UID of the validator (derived from synapse.dendrite.hotkey).
        """
        from shared.utils.ssh import ssh_exec

        try:
            # validator_uid is derived from synapse.dendrite.hotkey
            # Interface name: wga{V}_{M} - max 10 chars, fits Linux 15-char limit
            miner_uid = self.uid
            tunnel_name = f"wga{validator_uid}_{miner_uid}"

            # Determine SSH user
            ssh_user = "ubuntu"
            if self.settings.scrubber_provider and self.settings.scrubber_provider.lower() == "linode":
                ssh_user = "root"

            # Remove tunnel interface
            ssh_exec(
                host=synapse.scrubber_ip,
                command=f"sudo ip link del {tunnel_name} 2>/dev/null || true",
                ssh_key_path=self.settings.ssh_key_path,
                user=ssh_user,
                timeout=30
            )

            logger.info(f"Tunnel teardown complete: {tunnel_name} on {synapse.scrubber_ip}")
            synapse.success = True
            return synapse

        except Exception as e:
            logger.error(f"Tunnel teardown failed: {e}")
            synapse.success = False
            synapse.error_message = str(e)
            return synapse

    def _get_xdp_stats_dict(self) -> Dict[str, int]:
        """
        Get current XDP stats as a dictionary.

        This reads REAL stats from the XDP program's BPF maps.
        """
        stats = {
            "xdp_pass": 0,
            "xdp_drop_blacklist": 0,
            "xdp_drop_ratelimit": 0,
            "xdp_drop_quarantine": 0,
            "xdp_drop_bogon": 0,
            "xdp_syncookie_challenge": 0,
        }

        if not self.scrubber_manager or not self.active_scrubber:
            return stats

        # Get stats from active scrubber
        xdp_stats = self.scrubber_manager.get_scrubber_stats(self.active_scrubber.node_id)

        if xdp_stats:
            if hasattr(xdp_stats, 'xdp_pass'):
                stats["xdp_pass"] = xdp_stats.xdp_pass
            if hasattr(xdp_stats, 'xdp_drop_blacklist'):
                stats["xdp_drop_blacklist"] = xdp_stats.xdp_drop_blacklist
            if hasattr(xdp_stats, 'xdp_drop_ratelimit'):
                stats["xdp_drop_ratelimit"] = xdp_stats.xdp_drop_ratelimit
            if hasattr(xdp_stats, 'xdp_drop_quarantine'):
                stats["xdp_drop_quarantine"] = xdp_stats.xdp_drop_quarantine
            if hasattr(xdp_stats, 'xdp_drop_bogon'):
                stats["xdp_drop_bogon"] = xdp_stats.xdp_drop_bogon
            if hasattr(xdp_stats, 'xdp_syncookie_challenge'):
                stats["xdp_syncookie_challenge"] = xdp_stats.xdp_syncookie_challenge

        return stats

    def _get_audit_xdp_stats(self, scrubber_ip: str, validator_uid: int) -> Dict[str, int]:
        """
        Get current AUDIT XDP stats from the scrubber for a specific validator's tunnel.

        Each validator has its own WireGuard audit tunnel (wga{validator_uid}_{miner_uid})
        with its own XDP program and stats map. This reads from the SPECIFIC map for that
        validator's tunnel, not aggregating across all audit maps.

        Args:
            scrubber_ip: IP of the scrubber to query.
            validator_uid: UID of the validator performing the audit.

        Returns:
            Dictionary of counter names to values (all 21 stat types).
        """
        from shared.utils.bpf_helpers import bpf_read_xdp_stats_by_id
        from shared.utils.ssh import ssh_exec

        # Default stats - ALL 30 XDP counter types matching enum xdp_stats in common.h
        # Indices must match exactly for proper scoring by validator
        stats = {
            # Index 0-1: Pass and whitelist bypass
            "xdp_pass": 0,                    # 0: XDP_STAT_PASS
            "whitelist_bypass": 0,            # 1: XDP_STAT_WHITELIST_BYPASS
            # Index 2-6: Blacklist and invalid packet drops
            "xdp_drop_blacklist": 0,          # 2: XDP_STAT_DROP_BLACKLIST
            "xdp_drop_invalid_ip": 0,         # 3: XDP_STAT_DROP_INVALID_IP
            "xdp_drop_invalid_tcp": 0,        # 4: XDP_STAT_DROP_INVALID_TCP
            "xdp_drop_ratelimit": 0,          # 5: XDP_STAT_DROP_RATELIMIT
            "xdp_drop_temp_blacklist": 0,     # 6: XDP_STAT_DROP_TEMP_BLACKLIST
            # Index 7-12: SYN cookie and quarantine stats
            "xdp_syncookie_challenge": 0,     # 7: XDP_STAT_SYNCOOKIE_CHALLENGE
            "xdp_syncookie_validated": 0,     # 8: XDP_STAT_SYNCOOKIE_VALIDATED
            "xdp_syncookie_allow": 0,         # 9: XDP_STAT_SYNCOOKIE_ALLOW
            "xdp_syncookie_reject": 0,        # 10: XDP_STAT_SYNCOOKIE_REJECT
            "xdp_drop_quarantine": 0,         # 11: XDP_STAT_DROP_QUARANTINE
            "xdp_bypass_allowed": 0,          # 12: XDP_STAT_BYPASS_ALLOWED
            # Index 13: Bogon (private/reserved IP) drops
            "xdp_drop_bogon": 0,              # 13: XDP_STAT_DROP_BOGON
            # Index 14-17: TCP flag anomaly drops
            "xdp_drop_tcp_xmas": 0,           # 14: XDP_STAT_DROP_TCP_XMAS
            "xdp_drop_tcp_null": 0,           # 15: XDP_STAT_DROP_TCP_NULL
            "xdp_drop_tcp_synfin": 0,         # 16: XDP_STAT_DROP_TCP_SYNFIN
            "xdp_drop_tcp_synrst": 0,         # 17: XDP_STAT_DROP_TCP_SYNRST
            # Index 18-21: Flood attack drops
            "xdp_drop_syn_flood": 0,          # 18: XDP_STAT_DROP_SYN_FLOOD
            "xdp_drop_udp_amp": 0,            # 19: XDP_STAT_DROP_UDP_AMP
            "xdp_drop_icmp_flood": 0,         # 20: XDP_STAT_DROP_ICMP_FLOOD
            "xdp_drop_frag": 0,               # 21: XDP_STAT_DROP_FRAG
            # Index 22-25: Additional TCP/UDP drops
            "xdp_drop_tcp_fin": 0,            # 22: XDP_STAT_DROP_TCP_FIN
            "xdp_drop_tcp_rst": 0,            # 23: XDP_STAT_DROP_TCP_RST
            "xdp_drop_tcp_ack": 0,            # 24: XDP_STAT_DROP_TCP_ACK
            "xdp_drop_udp_flood": 0,          # 25: XDP_STAT_DROP_UDP_FLOOD
            # Index 26-29: L7 and special attack drops
            "xdp_drop_malformed": 0,          # 26: XDP_STAT_DROP_MALFORMED
            "xdp_drop_http_flood": 0,         # 27: XDP_STAT_DROP_HTTP_FLOOD (L7)
            "xdp_drop_slowloris": 0,          # 28: XDP_STAT_DROP_SLOWLORIS (L7)
            "xdp_drop_land": 0,               # 29: XDP_STAT_DROP_LAND
        }

        if not scrubber_ip:
            logger.warning("No scrubber IP provided for audit stats")
            return stats

        try:
            provider = get_provider(self.settings.scrubber_provider)
            ssh_user = provider.default_ssh_user

            # Build the interface name for this validator's audit tunnel
            # Interface name: wga{V}_{M} - max 10 chars, fits Linux 15-char limit
            interface_name = f"wga{validator_uid}_{self.uid}"

            # Step 1: Get the XDP program ID attached to this specific interface
            # Then find the audit_xdp_stats map ID from that program
            cmd = (
                f"XDP_ID=$(sudo bpftool net show dev {interface_name} 2>/dev/null | "
                f"grep -oP 'id \\K\\d+' | head -1); "
                f"if [ -n \"$XDP_ID\" ]; then "
                f"sudo bpftool prog show id $XDP_ID 2>/dev/null | "
                f"grep -oP 'map_ids \\K[0-9,]+' | tr ',' '\\n' | while read MAP_ID; do "
                f"MAP_NAME=$(sudo bpftool map show id $MAP_ID 2>/dev/null | grep -oP 'name \\K\\S+'); "
                f"if [ \"$MAP_NAME\" = \"audit_xdp_stats\" ]; then echo $MAP_ID; break; fi; done; fi"
            )

            rc, stdout, stderr = ssh_exec(
                scrubber_ip, cmd, self.settings.ssh_key_path,
                user=ssh_user, timeout=30
            )

            if rc != 0 or not stdout or not stdout.strip():
                logger.warning(
                    f"Could not find audit_xdp_stats map for {interface_name} on {scrubber_ip}: "
                    f"rc={rc}, stdout={stdout}, stderr={stderr}"
                )
                return stats

            map_id = stdout.strip()
            logger.debug(f"Found audit_xdp_stats map_id={map_id} for {interface_name}")

            # Step 2: Read stats from the specific map ID using the reliable helper
            audit_stats = bpf_read_xdp_stats_by_id(
                host=scrubber_ip,
                ssh_key_path=self.settings.ssh_key_path,
                map_id=map_id,
                user=ssh_user,
            )

            if audit_stats:
                stats.update(audit_stats)
                logger.debug(f"Read audit XDP stats from {scrubber_ip} map_id={map_id}: {stats}")
            else:
                logger.warning(f"No audit XDP stats found on {scrubber_ip} map_id={map_id}")

        except Exception as e:
            logger.error(f"Failed to read audit XDP stats from {scrubber_ip}: {e}")

        return stats

    def _reset_nginx_ratelimit_stats(self, scrubber_ip: str) -> bool:
        """
        Reset nginx rate limit stats on scrubber before audit starts.

        This clears the rate limit log so we can measure only the traffic
        from the current audit round.

        Args:
            scrubber_ip: IP of the scrubber.

        Returns:
            True if reset was successful, False otherwise.
        """
        from shared.utils.ssh import ssh_exec

        if not scrubber_ip:
            return False

        try:
            provider = get_provider(self.settings.scrubber_provider)
            ssh_user = provider.default_ssh_user

            # Reset nginx rate limit stats (clear the log file)
            cmd = "/opt/tensorprox/bin/reset-nginx-ratelimit-stats.sh 2>/dev/null || true"
            exit_code, _, _ = ssh_exec(
                scrubber_ip,
                cmd,
                self.settings.ssh_key_path,
                user=ssh_user,
                timeout=10,
            )

            if exit_code == 0:
                logger.debug(f"Reset nginx rate limit stats on {scrubber_ip}")
                return True
            else:
                logger.debug(f"nginx rate limit reset script not found on {scrubber_ip} (layer 7 not enabled)")
                return False

        except Exception as e:
            logger.debug(f"Failed to reset nginx rate limit stats on {scrubber_ip}: {e}")
            return False

    def _get_nginx_ratelimit_stats(self, scrubber_ip: str) -> int:
        """
        Get nginx rate limit blocked count from scrubber.

        Reads the count of 429 responses from nginx rate limit log.

        Args:
            scrubber_ip: IP of the scrubber.

        Returns:
            Number of requests blocked by nginx rate limiting.
        """
        from shared.utils.ssh import ssh_exec

        if not scrubber_ip:
            return 0

        try:
            provider = get_provider(self.settings.scrubber_provider)
            ssh_user = provider.default_ssh_user

            # Get nginx rate limit stats
            cmd = "/opt/tensorprox/bin/get-nginx-ratelimit-stats.sh 2>/dev/null || echo '{\"ratelimit_app_blocked\": 0}'"
            exit_code, stdout, _ = ssh_exec(
                scrubber_ip,
                cmd,
                self.settings.ssh_key_path,
                user=ssh_user,
                timeout=10,
            )

            if exit_code == 0 and stdout:
                import json
                try:
                    data = json.loads(stdout.strip())
                    blocked = data.get("ratelimit_app_blocked", 0)
                    logger.debug(f"nginx rate limit blocked on {scrubber_ip}: {blocked}")
                    return int(blocked)
                except (json.JSONDecodeError, ValueError):
                    pass

            return 0

        except Exception as e:
            logger.debug(f"Failed to get nginx rate limit stats from {scrubber_ip}: {e}")
            return 0

    def _start_control_plane(self) -> bool:
        """
        Start the Miner Control Plane API server in a background thread.

        The control plane provides:
        - REST API for TPM communication (origins, scrubbers, metrics)
        - Background services (health monitor, attack detection, etc.)
        - Database-backed state management

        Returns:
            True if control plane started successfully, False otherwise.
        """
        try:
            from miner_control_plane.control_plane import create_app
            from shared.config import get_settings as get_cp_settings

            cp_settings = get_cp_settings()
            port = getattr(cp_settings, 'emn_port', 8000)

            logger.info(f"Starting Miner Control Plane on port {port}...")

            # Create Flask app
            app = create_app()

            # Start in background thread
            self._control_plane_thread = threading.Thread(
                target=lambda: app.run(
                    host='0.0.0.0',
                    port=port,
                    debug=False,
                    use_reloader=False,
                    threaded=True
                ),
                daemon=True,
                name="miner-control-plane"
            )
            self._control_plane_thread.start()

            # Give it a moment to start
            time.sleep(2)

            logger.info(f"Miner Control Plane started on port {port}")
            return True

        except ImportError as e:
            logger.warning(f"Control plane not available (missing dependencies): {e}")
            logger.warning("Miner will run without control plane API")
            return False
        except Exception as e:
            error_msg = str(e)
            # Check if this is a bootstrap token issue - we can retry later
            if "bootstrap_token_required" in error_msg or "401" in error_msg:
                logger.warning(f"Control plane startup deferred: {e}")
                logger.info("Control plane will start automatically when bootstrap token is received from validator")
                self._control_plane_pending = True
                return False
            logger.error(f"Failed to start control plane: {e}")
            return False

    def run(self) -> None:
        """Main run loop for the TensorProx miner."""
        logger.info("Starting TensorProx miner...")
        logger.info(f"Configuration: {self.AUDIT_SCRUBBERS_REQUIRED} audit scrubber (active only, no standby)")

        # Start control plane first (provides API for TPM communication)
        self._start_control_plane()

        # Call parent run which handles setup and main loop
        super().run()

    def _handle_bootstrap_token(self, token: str) -> None:
        """
        Handle bootstrap token received from validator.

        Overrides base implementation to also start the control plane
        if it was deferred due to missing bootstrap token.
        """
        # Call parent implementation to handle registration
        super()._handle_bootstrap_token(token)

        # If control plane startup was deferred, try to start it now
        if self._control_plane_pending:
            try:
                from miner_control_plane.services.miner_identity import miner_identity
                if miner_identity.is_registered:
                    logger.info("Bootstrap token registered, starting deferred control plane...")
                    self._control_plane_pending = False
                    if self._start_control_plane():
                        logger.info("Deferred control plane started successfully")
                    else:
                        # If it still fails, re-mark as pending for next token
                        if self._control_plane_pending:
                            logger.warning("Control plane startup still pending")
            except Exception as e:
                logger.warning(f"Failed to start deferred control plane: {e}")
