"""
Origin Service
Origin registration, WireGuard setup, scrubber configuration, deletion.
"""

import json
import struct
import time
import uuid
import socket
import logging
from typing import Dict, List
from flask import jsonify
from shared.database import get_db_connection
from shared.config import _detect_public_ip
from shared.utils.database_helpers import db_create_origin, db_delete_origin
from shared.utils.wireguard import (
    generate_wg_keys,
    build_exit_hub_config,
)
from shared.utils.network import calculate_policy_table, calculate_policy_priority
from shared.utils.ssh import ssh_exec, sftp_upload, get_ssh_user_for_node
from miner_control_plane.services.state_manager import state_manager
from miner_control_plane.services.scrubber_operations import configure_wireguard_dataplane
from miner_control_plane.services.bpf_map_cleaner import clean_origin_bpf_maps
from miner_control_plane.services.expected_tunnels import update_expected_tunnels_on_shard
from miner_control_plane.services.rate_config_service import (
    calculate_origin_rate_config,
    push_origin_rate_config,
    delete_origin_rate_config,
)
from miner_control_plane.utils.aws import aws_operations
from miner_control_plane.services.eip_availability import eip_availability
from shared.config import get_settings

logger = logging.getLogger(__name__)


class OriginService:
    """
    Origin lifecycle management with create, delete, and status operations.
    """

    def __init__(self):
        """Initialize origin service"""
        self.settings = get_settings()
        self.db = get_db_connection()
        self.state = state_manager

    def _ensure_db_connection(self) -> None:
        """Check if database connection is healthy, reconnect if needed.

        Cleanup operations use pg_terminate_backend() which kills idle connections.
        This method ensures the singleton connection is restored before use.
        """
        try:
            self.db.conn.cursor().execute("SELECT 1")
        except Exception:
            logger.warning("OriginService DB connection lost, reconnecting...")
            try:
                self.db.conn.close()
            except Exception:
                pass
            self.db = get_db_connection()
            logger.info("OriginService DB connection restored")

    def _upload_wireguard_config(self, host: str, interface: str, config: str) -> bool:
        """
        Upload WireGuard config via SFTP instead of heredoc-over-SSH.

        Heredoc pattern (cat > file << EOF) fails through subprocess SSH.
        SFTP upload + chmod is reliable across all providers.

        Args:
            host: Remote host IP
            interface: WireGuard interface name (e.g., wgO1)
            config: WireGuard config text

        Returns:
            True if successful, False otherwise
        """
        import tempfile
        import os

        # Determine SSH user from nodes_db
        node_data = next(
            (node for node in self.state.nodes_db.values() if node.get("public_ip") == host), None
        )
        if not node_data:
            logger.error(f"Node not found for IP {host}")
            return False

        ssh_user = get_ssh_user_for_node(node_data)
        try:
            # Write config to temp file
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as f:
                f.write(config)
                temp_path = f.name

            # Upload via SFTP
            upload_success, upload_error = sftp_upload(
                host=host,
                username=ssh_user,
                key_filename=self.settings.ssh_key_path,
                local_path=temp_path,
                remote_path=f"/tmp/{interface}.conf",
                timeout=30,
            )

            if not upload_success:
                logger.error(f"Failed to upload WireGuard config to {host}: {upload_error}")
                return False

            # Move to /etc/wireguard and set ownership + permissions
            rc, _, _ = ssh_exec(
                host,
                f"sudo mv /tmp/{interface}.conf /etc/wireguard/{interface}.conf",
                self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )
            if rc != 0:
                logger.error(f"Failed to move WireGuard config on {host}")
                return False

            # CRITICAL: Must be owned by root:root for wg-quick to work
            rc, _, _ = ssh_exec(
                host,
                f"sudo chown root:root /etc/wireguard/{interface}.conf",
                self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )
            if rc != 0:
                logger.error(f"Failed to chown WireGuard config on {host}")
                return False

            rc, _, _ = ssh_exec(
                host,
                f"sudo chmod 600 /etc/wireguard/{interface}.conf",
                self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )
            if rc != 0:
                logger.error(f"Failed to chmod WireGuard config on {host}")
                return False

            # Cleanup temp file
            os.unlink(temp_path)

            logger.debug(f"Successfully uploaded WireGuard config for {interface} to {host}")
            return True

        except Exception as e:
            logger.error(f"Exception uploading WireGuard config to {host}: {e}")
            return False

    def _rollback_origin_provisioning(
        self, origin_id: str, provisioned: dict, shard_nodes: list, reason: str
    ) -> None:
        """
        Rollback partially provisioned origin resources on failure.

        Called when create_origin() fails mid-way to prevent orphaned resources.

        Args:
            origin_id: Origin ID being rolled back
            provisioned: Dict tracking what was provisioned:
                - eip_alloc_id: EIP allocation ID
                - private_ip: Active node private IP
                - private_ip_standby: Standby node private IP
                - active_eni: Active node ENI ID
                - standby_eni: Standby node ENI ID
                - wg_interface: WireGuard interface name
                - origin_ip: Origin server IP
            shard_nodes: List of shard nodes for cleanup
            reason: Failure reason for logging
        """
        logger.warning(f"Rolling back origin {origin_id} provisioning due to: {reason}")

        # Get region from shard if available
        region = None
        shard_id = provisioned.get("shard_id")
        if shard_id:
            shard = self.state.get_shard(shard_id)
            if shard:
                region = shard.get("region")

        # 1. Release EIP if allocated
        if provisioned.get("eip_alloc_id"):
            try:
                aws_operations.release_eip(provisioned["eip_alloc_id"], region=region)
                logger.info(f"Rollback: Released EIP {provisioned.get('eip')}")
                # Clear EIP cache after successful release
                if region:
                    eip_availability.clear_cache(region=region)
            except Exception as e:
                logger.warning(f"Rollback: Failed to release EIP: {e}")

        # 2. Release private IPs via NetworkPolicy (if allocation was completed)
        if provisioned.get("allocation"):
            try:
                from miner_control_plane.services.network_policies.registry import get_policy_for_shard

                shard_id = provisioned.get("shard_id")
                if shard_id:
                    policy = get_policy_for_shard(shard_id, self.state)
                    policy.release_origin_attachment(
                        shard_id=shard_id, origin_id=origin_id, allocation=provisioned["allocation"]
                    )
                    logger.info("Rollback: NetworkPolicy released IPs")
            except Exception as e:
                logger.warning(
                    f"Rollback: NetworkPolicy release failed: {e}, attempting manual cleanup"
                )

                # Fallback to manual cleanup
                if provisioned.get("active_eni") and provisioned.get("private_ip"):
                    try:
                        aws_operations.unassign_private_ip_addresses(
                            provisioned["active_eni"], [provisioned["private_ip"]], region=region
                        )
                        logger.info(f"Rollback: Unassigned private IP {provisioned['private_ip']}")
                    except Exception as e2:
                        logger.warning(f"Rollback: Failed to unassign active private IP: {e2}")

                if provisioned.get("standby_eni") and provisioned.get("private_ip_standby"):
                    try:
                        aws_operations.unassign_private_ip_addresses(
                            provisioned["standby_eni"], [provisioned["private_ip_standby"]], region=region
                        )
                        logger.info(
                            f"Rollback: Unassigned standby private IP {provisioned['private_ip_standby']}"
                        )
                    except Exception as e2:
                        logger.warning(f"Rollback: Failed to unassign standby private IP: {e2}")

        # 3. Clean up WireGuard and BPF on shard nodes
        if provisioned.get("wg_interface") and shard_nodes:
            for node in shard_nodes:
                node_name = node.get("instance_name", node["node_id"])
                host_ip = node["public_ip"]
                priv_ip = (
                    provisioned.get("private_ip")
                    if node.get("role") == "active"
                    else provisioned.get("private_ip_standby")
                )
                if priv_ip:
                    try:
                        # Stop WireGuard service (if running)
                        ssh_exec(
                            host_ip,
                            f"sudo systemctl stop wg-quick@{provisioned['wg_interface']} 2>/dev/null || true",
                            self.settings.ssh_key_path,
                            nodes_db=self.state.nodes_db,
                        )
                        # Clean TC qdisc (before deleting interface)
                        ssh_exec(
                            host_ip,
                            f"sudo tc qdisc del dev {provisioned['wg_interface']} clsact 2>/dev/null || true",
                            self.settings.ssh_key_path,
                            nodes_db=self.state.nodes_db,
                        )
                        # Delete WireGuard interface (we use 'ip link add', not wg-quick)
                        ssh_exec(
                            host_ip,
                            f"sudo ip link delete {provisioned['wg_interface']} 2>/dev/null || true",
                            self.settings.ssh_key_path,
                            nodes_db=self.state.nodes_db,
                        )
                        # Remove config file
                        ssh_exec(
                            host_ip,
                            f"sudo rm -f /etc/wireguard/{provisioned['wg_interface']}.conf",
                            self.settings.ssh_key_path,
                            nodes_db=self.state.nodes_db,
                        )
                        # Remove IP from interface
                        ssh_exec(
                            host_ip,
                            f"sudo ip addr del {priv_ip}/24 dev ens5 2>/dev/null || true",
                            self.settings.ssh_key_path,
                            nodes_db=self.state.nodes_db,
                        )
                        logger.info(f"Rollback: Cleaned up {node_name}")
                    except Exception as e:
                        logger.warning(f"Rollback: Failed to clean up {node_name}: {e}")

            # Clean BPF maps for this origin (in case they were partially provisioned)
            try:
                cleanup_result = clean_origin_bpf_maps(
                    provisioned.get("origin_id", "unknown"),
                    provisioned,
                    self.state.nodes_db,
                    self.settings.ssh_key_path,
                    self.settings,
                    verify=False,  # Don't verify during rollback, best effort
                )
                if cleanup_result["success"]:
                    logger.info(f"Rollback: BPF maps cleaned for {provisioned.get('origin_ip')}")
                else:
                    logger.warning(f"Rollback: BPF cleanup had issues: {cleanup_result['errors']}")
            except Exception as e:
                logger.warning(f"Rollback: BPF cleanup exception: {e}")

        # 4. Remove from in-memory state if added
        if origin_id in self.state.origins_db:
            del self.state.origins_db[origin_id]
            logger.info(f"Rollback: Removed {origin_id} from in-memory state")

        # 5. Log to operations journal
        try:
            conn = self.db.conn
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO operations_journal (op_type, origin_id, status, error_text)
                VALUES (%s, %s, %s, %s)
            """,
                ("CREATE_ORIGIN_ROLLBACK", origin_id, "rolled_back", reason),
            )
            conn.commit()
            cur.close()
        except Exception as e:
            logger.warning(f"Failed to log rollback to operations_journal: {e}")

        logger.info(f"Rollback complete for origin {origin_id}")

    def create_origin(
        self,
        origin_id: str,
        shard_id: str,
        exit_hub_ip: str,
        origin_ip: str,
        required_ports: List[int],
    ) -> tuple:
        """
        Create a new Origin in a specific shard (idempotent - reuses existing).

        Multi-region support: shard_id is required to determine region and nodes.

        Args:
            origin_id: Unique origin identifier
            shard_id: Shard to assign this origin to (determines region)
            exit_hub_ip: Exit Hub IP address
            origin_ip: Origin server IP
            required_ports: List of ports to expose

        Returns: (jsonify response, status_code)
            Success: (origin_config, 201) or (existing_config, 200)
            Errors:
                - (error, 404): Shard not found (code: shard_not_found)
                - (error, 409): Shard not ready (code: shard_not_ready, includes job_id if deploying)
                - (error, 409): No capacity (code: capacity_exhausted, includes hard_capacity)
                - (error, 500): Internal error
        """
        # Ensure DB connection is alive (cleanup kills idle connections)
        self._ensure_db_connection()

        # Track provisioned resources for rollback on failure
        provisioned = {"shard_id": shard_id}
        shard_nodes = []

        try:
            logger.info(
                f"Creating Origin: {origin_id} in shard {shard_id} with ports {required_ports}"
            )

            # Reload state if empty (handles miner restart)
            if not self.state.nodes_db:
                logger.warning("nodes_db empty - attempting reload from database...")
                try:
                    self.state.load_state()
                    if self.state.nodes_db:
                        logger.info(f"Reloaded {len(self.state.nodes_db)} nodes from database")
                except Exception as e:
                    logger.error(f"Failed to reload state: {e}")

            # Check 1: Validate shard exists
            shard = self.state.get_shard(shard_id)
            if not shard:
                return jsonify(
                    {
                        "error": f"Shard {shard_id} not found",
                        "code": "shard_not_found",
                        "shard_id": shard_id,
                    }
                ), 404

            # Check 2: Validate shard is ready (not deploying)
            shard_status = shard.get("status", "unknown")
            if shard_status == "deploying":
                # Check if there's a deployment job for this shard
                conn = self.db.conn
                cur = conn.cursor()
                try:
                    cur.execute(
                        """
                        SELECT job_id FROM deployment_jobs
                        WHERE shard_id = %s AND state IN ('pending', 'running')
                        ORDER BY created_at DESC
                        LIMIT 1
                    """,
                        (shard_id,),
                    )
                    job_row = cur.fetchone()
                    job_id = str(job_row[0]) if job_row else None
                finally:
                    cur.close()

                error_response = {
                    "error": "Shard is not ready",
                    "code": "shard_not_ready",
                    "shard_id": shard_id,
                    "shard_status": shard_status,
                }
                if job_id:
                    error_response["job_id"] = job_id

                return jsonify(error_response), 409

            # Check 3: Validate active and standby nodes exist
            active_node = self.state.get_active_node(shard_id)
            standby_node = self.state.get_standby_node(shard_id)

            if not active_node or not standby_node:
                return jsonify(
                    {
                        "error": "Shard is not ready",
                        "code": "shard_not_ready",
                        "shard_id": shard_id,
                        "reason": "Missing active or standby node",
                    }
                ), 409

            # Check 4: Validate capacity via NetworkPolicy
            try:
                from miner_control_plane.services.network_policies.registry import get_policy_for_shard

                policy = get_policy_for_shard(shard_id, self.state)
                capacity = policy.shard_hard_capacity(shard_id=shard_id)

                # Check if capacity is available
                if (
                    capacity.origin_slots_available is not None
                    and capacity.origin_slots_available <= 0
                ):
                    return jsonify(
                        {
                            "error": "No capacity available",
                            "code": "capacity_exhausted",
                            "shard_id": shard_id,
                            "hard_capacity": {
                                "capacity_model": capacity.capacity_model,
                                "origin_slots_total": capacity.origin_slots_total,
                                "origin_slots_used": capacity.origin_slots_used,
                                "origin_slots_available": capacity.origin_slots_available,
                                "limiting_factor": capacity.limiting_factor,
                            },
                        }
                    ), 409

                logger.info(
                    f"Shard {shard_id} capacity check: "
                    f"{capacity.origin_slots_available} of {capacity.origin_slots_total} slots available"
                )

            except Exception as capacity_err:
                logger.warning(f"Capacity check failed, continuing anyway: {capacity_err}")
                # Don't block origin creation if capacity check fails

            # Proceed with origin creation
            active_ip = active_node["public_ip"]
            standby_ip = standby_node["public_ip"]
            active_eni = active_node["eni_id"]
            standby_eni = standby_node["eni_id"]
            active_node_id = active_node["node_id"]
            region = shard["region"]

            # Idempotent: If Origin already exists, return existing config
            if origin_id in self.state.origins_db:
                existing = self.state.origins_db[origin_id]
                logger.info(f"Origin {origin_id} already exists - returning existing config")

                # Regenerate WireGuard config for Exit Hub from stored keys
                wg_subnet_base = (existing["origin_num"] - 1) * 4
                hub_ip = f"169.254.100.{wg_subnet_base + 2}"
                edge_ip = f"169.254.100.{wg_subnet_base + 1}"
                config_text = build_exit_hub_config(
                    existing["edge_pub_key"],
                    existing["hub_priv_key"],
                    hub_ip,
                    active_ip,
                    existing["wg_port"],
                )

                # Generate transparent mode commands
                # Detect primary interface dynamically (eth0 on Linode, ens5 on AWS)
                iface_detect = "$(ip route get 1.1.1.1 | grep -oP 'dev \\K\\S+' | head -1)"
                table_id = calculate_policy_table(existing["origin_num"])
                priority = calculate_policy_priority(existing["origin_num"])
                transparent_mode_commands = [
                    f"ip route replace table {table_id} default dev {existing['wg_interface']}",
                    f"IFACE={iface_detect}; ip rule del iif $IFACE from {existing['origin_ip']} table {table_id} priority {priority} 2>/dev/null || true",
                    f"IFACE={iface_detect}; ip rule add iif $IFACE from {existing['origin_ip']} table {table_id} priority {priority}",
                    "nft add set ip nat tp_origin_addrs '{ type ipv4_addr; }' 2>/dev/null || true",
                    f'IFACE={iface_detect}; nft add rule ip nat postrouting oifname "$IFACE" ip saddr @tp_origin_addrs return 2>/dev/null || true',
                    f"nft add element ip nat tp_origin_addrs {{ {existing['origin_ip']} }} 2>/dev/null || true",
                ]

                # Return existing origin config (TPM applies to exit hub via SSH)
                return jsonify(
                    {
                        "status": "success",
                        "origin_id": origin_id,
                        "eip": existing["eip"],
                        "state": existing["state"],
                        "secret": existing["shared_secret"],
                        "wg_interface": existing["wg_interface"],
                        "hub_wg_config": config_text,
                        "transparent_mode_commands": transparent_mode_commands,
                    }
                ), 200

            # ATOMIC origin_num allocation with database lock to prevent race conditions
            # Use transaction with table lock to ensure only one registration allocates origin_num at a time
            conn = self.db.conn
            cur = conn.cursor()
            try:
                # Lock the origins table to prevent concurrent allocations
                cur.execute("LOCK TABLE origins IN EXCLUSIVE MODE")

                # Get MAX origin_num for unique sequence number (handles gaps from deletions)
                cur.execute("SELECT COALESCE(MAX(origin_num), 0) FROM origins")
                max_origin_num = cur.fetchone()[0]

                # origin_num must be MAX+1 to avoid collisions
                origin_num = max_origin_num + 1

                logger.info(f"Allocated origin_num: {origin_num}")

                # Commit to release lock (allocation successful)
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to allocate origin_num: {e}")
                raise
            finally:
                cur.close()

            # Allocate private IPs via NetworkPolicy
            logger.info(f"Allocating private IPs via NetworkPolicy for origin {origin_id}...")
            from miner_control_plane.services.network_policies.registry import get_policy_for_shard

            policy = get_policy_for_shard(shard_id, self.state)
            allocation = policy.ensure_origin_attachment(
                shard_id=shard_id,
                origin_id=origin_id,
                context={"exit_hub_ip": exit_hub_ip, "origin_ip": origin_ip},
            )

            # Extract allocated IPs from AllocationResult
            private_ip = allocation.active["private_ip"]
            private_ip_standby = allocation.standby["private_ip"]
            active_eni = allocation.active["eni_id"]
            standby_eni = allocation.standby["eni_id"]

            logger.info(
                f"NetworkPolicy allocated IPs: {private_ip} (active), "
                f"{private_ip_standby} (standby)"
            )

            # Track for rollback
            provisioned["private_ip"] = private_ip
            provisioned["private_ip_standby"] = private_ip_standby
            provisioned["active_eni"] = active_eni
            provisioned["standby_eni"] = standby_eni
            provisioned["allocation"] = allocation  # Store for release in delete_origin

            # Pre-allocation EIP check - fail fast if quota exhausted
            if not eip_availability.has_eip_available(region):
                raise ValueError(
                    f"EIP quota exhausted in {region}. "
                    f"Cannot allocate new Elastic IP for origin {origin_id}."
                )

            # Allocate EIP AFTER we have locked IPs
            eip, eip_alloc_id = aws_operations.allocate_eip(region=region)
            provisioned["eip"] = eip
            provisioned["eip_alloc_id"] = eip_alloc_id

            # Clear EIP cache after successful allocation
            eip_availability.clear_cache(region=region)

            # Generate WireGuard keys
            edge_priv_key, edge_pub_key = generate_wg_keys()
            hub_priv_key, hub_pub_key = generate_wg_keys()

            # Generate shared secret for Exit Hub API authentication
            shared_secret = str(uuid.uuid4())

            # WireGuard interface name (max 15 chars for Linux kernel)
            # Use origin_id directly so detection matches: wgO40 → O40
            wg_interface_name = f"wg{origin_id}"

            # Get current global bogon count as baseline for this origin
            # Per-origin bogon = current_global - baseline (starts at 0, increments from deployment)
            # NOTE: ddos_metrics stores CUMULATIVE values from BPF map, so we need
            # the LATEST value (not SUM, which would massively inflate the count)
            bogon_baseline = 0
            try:
                conn = self.db.conn
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT COALESCE(xdp_drop_bogon, 0) FROM ddos_metrics
                    WHERE node_id IN (SELECT node_id FROM nodes WHERE shard_id = %s)
                    ORDER BY timestamp DESC
                    LIMIT 1
                """,
                    (shard_id,),
                )
                result = cur.fetchone()
                bogon_baseline = result[0] if result else 0
                cur.close()
                logger.info(f"Origin {origin_id} bogon baseline: {bogon_baseline}")
            except Exception as e:
                logger.warning(f"Failed to get bogon baseline: {e}, using 0")

            # Create Origin object (with shard_id for multi-region)
            origin = {
                "origin_id": origin_id,
                "shard_id": shard_id,  # Multi-region: bind to shard
                "region": region,  # For EIP table
                "origin_num": origin_num,  # Store for consistent addressing
                "eip": eip,
                "eip_alloc_id": eip_alloc_id,
                "private_ip": private_ip,
                "private_ip_standby": private_ip_standby,
                "origin_ip": origin_ip,
                "exit_hub_ip": exit_hub_ip,
                "shared_secret": shared_secret,  # For Exit Hub API auth
                "required_ports": required_ports,  # TCP/UDP ports needed
                "wg_interface": wg_interface_name,
                "wg_port": 51820 + origin_num - 1,  # O1->51820, O2->51821, etc.
                "edge_priv_key": edge_priv_key,
                "edge_pub_key": edge_pub_key,
                "hub_priv_key": hub_priv_key,
                "hub_pub_key": hub_pub_key,
                "state": "PROVISIONING",
                "created_at": time.time(),
                "node_id": active_node_id,
                "eni_id": active_eni,
                "bogon_baseline": bogon_baseline,
            }

            # Add required ports to Security Group (uses nodes for this shard)
            shard_nodes = self.state.get_nodes_for_shard(shard_id)
            # Track for rollback
            provisioned["origin_ip"] = origin_ip
            provisioned["wg_interface"] = wg_interface_name

            aws_operations.add_ports_to_security_group(required_ports, region=region)

            # NetworkPolicy already assigned private IPs on both ENIs and OS interfaces
            active_name = active_node.get("instance_name", "active")
            standby_name = standby_node.get("instance_name", "standby")
            logger.info(
                f"Private IPs assigned by NetworkPolicy: {private_ip} (active:{active_name}), {private_ip_standby} (standby:{standby_name})"
            )

            # Step 2: Associate EIP to active edge
            logger.info(f"Associating EIP {eip} to {active_name} {private_ip}")
            aws_operations.associate_eip_to_eni(eip_alloc_id, active_eni, private_ip, region=region)

            # Step 3: Configure WireGuard on BOTH Edge-A and Edge-B
            # Calculate unique /30 subnet for this Origin
            # O1: 169.254.100.0/30 (.1 = edge, .2 = hub)
            # O2: 169.254.100.4/30 (.5 = edge, .6 = hub)
            # O3: 169.254.100.8/30 (.9 = edge, .10 = hub)
            wg_subnet_base = (origin_num - 1) * 4
            edge_ip = f"169.254.100.{wg_subnet_base + 1}"
            hub_ip = f"169.254.100.{wg_subnet_base + 2}"

            wg_config = f"""[Interface]
PrivateKey = {edge_priv_key}
Address = {edge_ip}/30
ListenPort = {origin["wg_port"]}
Table = off

[Peer]
PublicKey = {hub_pub_key}
Endpoint = {exit_hub_ip}:{origin["wg_port"]}
AllowedIPs = {hub_ip}/32,{origin_ip}/32
PersistentKeepalive = 15
"""

            # Configure active edge
            ssh_exec(
                active_ip,
                f"sudo systemctl stop wg-quick@{origin['wg_interface']} 2>/dev/null || true",
                self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )

            # Upload WireGuard config via SFTP (heredoc pattern doesn't work through subprocess SSH)
            if not self._upload_wireguard_config(active_ip, origin["wg_interface"], wg_config):
                raise Exception(f"Failed to upload WireGuard config to active edge {active_ip}")

            ssh_exec(
                active_ip,
                f"sudo systemctl enable --now wg-quick@{origin['wg_interface']}",
                self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )
            # Add route for origin_ip through WireGuard tunnel
            # CRITICAL: Skip if origin_ip matches miner's public IP to prevent breaking SSH connectivity
            miner_public_ip = _detect_public_ip()
            if origin_ip == miner_public_ip:
                logger.warning(
                    f"Skipping route for origin_ip={origin_ip} - matches miner public IP. "
                    f"This would break SSH connectivity to scrubbers."
                )
            else:
                ssh_exec(
                    active_ip,
                    f"sudo ip route add {origin_ip}/32 dev {origin['wg_interface']}",
                    self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )

            # Configure standby edge - same config, but keep disabled
            ssh_exec(
                standby_ip,
                f"sudo systemctl stop wg-quick@{origin['wg_interface']} 2>/dev/null || true",
                self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )

            # Upload WireGuard config via SFTP (heredoc pattern doesn't work through subprocess SSH)
            if not self._upload_wireguard_config(standby_ip, origin["wg_interface"], wg_config):
                raise Exception(f"Failed to upload WireGuard config to standby edge {standby_ip}")

            # PRE-CREATE interface on standby (DOWN state) for 100% hot standby
            # This allows TC attachment and full BPF configuration without conflicts
            logger.info(f"Pre-creating {origin['wg_interface']} interface on standby (DOWN state)")

            ssh_exec(
                standby_ip,
                f"sudo ip link add {origin['wg_interface']} type wireguard 2>/dev/null || "
                f"echo 'Interface {origin['wg_interface']} already exists'",
                self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )

            # Don't start service on standby (keys not configured, no conflict with active)
            logger.info(
                f"WireGuard configured on {active_name} (active) and {standby_name} (standby, interface pre-created)"
            )

            # Configure the WireGuard dataplane (TC/eBPF) on active scrubber
            wg_active_ok = configure_wireguard_dataplane(
                active_name,
                active_ip,
                origin["wg_interface"],
                private_ip,
                origin_ip,
                self.settings.ssh_key_path,
                self.state.nodes_db,
                origin_id=origin_id,
            )
            if not wg_active_ok:
                raise Exception("WireGuard dataplane configuration failed on active scrubber")

            # HOT STANDBY: Pre-configure dataplane on standby for instant failover
            # BPF maps and TC programs work even when WireGuard interface is down
            logger.info(f"Pre-configuring standby {standby_name} for hot standby")

            wg_standby_ok = configure_wireguard_dataplane(
                standby_name,
                standby_ip,
                origin["wg_interface"],
                private_ip_standby,
                origin_ip,
                self.settings.ssh_key_path,
                self.state.nodes_db,
                origin_id=origin_id,
            )

            if wg_standby_ok:
                logger.info("Standby BPF configured ✅")
            else:
                logger.warning("Standby BPF configuration failed (failover will be slower)")

            # Pre-add routes on standby (work even if interface down)
            ssh_exec(
                standby_ip,
                f"sudo ip route add {origin_ip}/32 dev {origin['wg_interface']} 2>/dev/null || true",
                self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )

            logger.info(
                f"HOT STANDBY: {standby_name} is 95% ready "
                f"(only needs systemctl start for instant failover)"
            )

            # === NEW: Push intelligent rate limiting config ===
            # CRITICAL: Must be pre-configured for fast failover
            # Calculate rate config from origin's bandwidth quota
            bandwidth_quota = self.state.bandwidth_quotas.get(origin_ip, {}).get('quota_bps', 0)

            # Determine if this is an audit origin (uses stricter rate limits)
            is_audit_origin = shard.get('shard_type', 'audit') == 'audit'

            rate_config = calculate_origin_rate_config(
                origin_ip=origin_ip,
                bandwidth_quota_bps=bandwidth_quota if bandwidth_quota else None,
                challenge_level=0,  # New origins start at NORMAL
                is_audit=is_audit_origin,  # Audit origins use stricter rate limits
            )

            # Push to active scrubber
            rate_config_active_ok = push_origin_rate_config(
                host=active_ip,
                origin_ip=origin_ip,
                config=rate_config,
                ssh_key_path=self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )
            if not rate_config_active_ok:
                logger.warning(f"Rate config push failed on active for {origin_id}")

            # Push to standby scrubber (CRITICAL for fast failover)
            if standby_ip:
                rate_config_standby_ok = push_origin_rate_config(
                    host=standby_ip,
                    origin_ip=origin_ip,
                    config=rate_config,
                    ssh_key_path=self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )
                if not rate_config_standby_ok:
                    logger.warning(f"Rate config push failed on standby for {origin_id}")
                else:
                    logger.info(
                        f"Rate config pre-configured on standby for {origin_id}: "
                        f"budget={rate_config['per_source_budget_pps']} PPS"
                    )

            # Step 4: Send config to Exit Hub via API instead of SSH
            hub_wg_config = build_exit_hub_config(
                edge_pub_key, hub_priv_key, hub_ip, active_ip, origin["wg_port"]
            )

            # Save Origin to in-memory state
            origin["state"] = "PROVISIONING"
            self.state.origins_db[origin_id] = origin

            # SKIP API push during registration - Exit Hub applies config from registration response
            # API push is only used for failover/updates when Exit Hub already has secret
            # This avoids race condition: Exit Hub can't have secret until this request completes
            logger.info("Skipping API push during registration (Exit Hub applies from response)")
            exit_hub_push_success = True  # Bootstrap handles it

            # Update state to IN_SERVICE
            origin["state"] = "IN_SERVICE" if exit_hub_push_success else "PARTIAL"
            self.state.origins_db[origin_id] = origin

            # Persist to database (include miner_id for multi-miner isolation)
            try:
                db_create_origin(origin, self.db, miner_id=self.state.miner_id)
            except Exception as e:
                logger.error(f"Database persistence failed: {e}")
                raise

            # LAYER 3 & 4: Initialize per-origin maps on shard's scrubbers
            logger.info(f"Initializing Layer 3/4 maps for origin {origin_ip}...")
            origin_ip_bytes = socket.inet_aton(origin_ip)
            origin_ip_hex = " ".join([f"{b:02x}" for b in origin_ip_bytes])

            for node in shard_nodes:
                node_name = node.get("instance_name", node["node_id"])
                host_ip = node["public_ip"]

                # Initialize origin_challenge_map to NORMAL (0)
                # NOTE: origin_challenge_map is an XDP map (defined in xdp_wan.c)
                ssh_exec(
                    host_ip,
                    f"sudo bpftool map update pinned /sys/fs/bpf/xdp/globals/origin_challenge_map key hex {origin_ip_hex} value hex 00 00 00 00",
                    self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )

                # Initialize syncookie_mode_map to DISABLED (0)
                ssh_exec(
                    host_ip,
                    f"sudo bpftool map update pinned /sys/fs/bpf/tc/globals/syncookie_mode_map key hex {origin_ip_hex} value hex 00 00 00 00",
                    self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )

                logger.info(f"Initialized Layer 3/4 maps for {origin_id} on {node_name}")

            # Generate transparent mode commands for Exit Hub to apply locally
            # Detect primary interface dynamically (eth0 on Linode, ens5 on AWS)
            iface_detect = "$(ip route get 1.1.1.1 | grep -oP 'dev \\K\\S+' | head -1)"
            table_id = calculate_policy_table(origin_num)
            priority = calculate_policy_priority(origin_num)
            transparent_mode_commands = [
                f"ip route replace table {table_id} default dev {wg_interface_name}",
                f"IFACE={iface_detect}; ip rule del iif $IFACE from {origin_ip} table {table_id} priority {priority} 2>/dev/null || true",
                f"IFACE={iface_detect}; ip rule add iif $IFACE from {origin_ip} table {table_id} priority {priority}",
                "nft add set ip nat tp_origin_addrs '{ type ipv4_addr; }' 2>/dev/null || true",
                f'IFACE={iface_detect}; nft add rule ip nat postrouting oifname "$IFACE" ip saddr @tp_origin_addrs return 2>/dev/null || true',
                f"nft add element ip nat tp_origin_addrs {{ {origin_ip} }} 2>/dev/null || true",
                f"nft insert rule ip filter forward ip daddr {origin_ip} accept",
            ]

            logger.info(f"Origin {origin_id} created successfully with Layer 3/4 initialization")
            return (
                jsonify(
                    {
                        "status": "success",
                        "origin_id": origin_id,
                        "eip": eip,
                        "state": origin["state"],
                        "secret": shared_secret,
                        "wg_interface": origin["wg_interface"],
                        "hub_wg_config": hub_wg_config,
                        "transparent_mode_commands": transparent_mode_commands,  # Exit Hub applies these locally
                    }
                ),
                201,
            )

        except Exception as e:
            logger.error(f"Failed to create Origin {origin_id}: {e}")

            # Rollback any provisioned resources
            if provisioned:
                try:
                    self._rollback_origin_provisioning(
                        origin_id, provisioned, shard_nodes, reason=str(e)
                    )
                except Exception as rollback_err:
                    logger.error(f"Rollback also failed: {rollback_err}")

            return jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "rollback": "completed" if provisioned else "not_needed",
                }
            ), 500

    def _cleanup_origin_reputation(
        self, origin_id: str, eip: str, shard_id: str
    ) -> None:
        """
        Clean all per-origin reputation entries from database and scrubbers.
        Called FIRST during origin deletion (before WireGuard cleanup).

        Args:
            origin_id: The origin ID being deleted
            eip: The origin's EIP (used in compound key)
            shard_id: The shard ID - required to scope cleanup to correct scrubbers
        """
        from miner_control_plane.services.scrubber_sync import scrubber_sync, SyncOperation

        db = get_db_connection()
        try:
            # Load all entries before deletion
            entries = []
            for list_type, table in [
                ("whitelist", "origin_whitelist"),
                ("blacklist", "origin_blacklist"),
                ("override", "origin_blacklist_override"),
            ]:
                rows = db.query_all(
                    f"SELECT ip_address FROM {table} WHERE origin_id = %s", (origin_id,)
                )
                for row in rows:
                    entries.append({"list_type": list_type, "ip": str(row["ip_address"])})

            if not entries:
                logger.debug(f"No per-origin reputation entries for {origin_id}")
                return

            # Remove from shard's scrubbers only (not all scrubbers)
            removed_count = 0
            for entry in entries:
                key_hex = scrubber_sync._build_compound_key(entry["ip"], eip)

                try:
                    scrubber_sync.apply_atomic_to_shard(
                        SyncOperation(
                            map_name=f"origin_{entry['list_type']}_map",
                            key_hex=key_hex,
                            value_hex=None,
                            action="delete",
                            origin_id=origin_id,
                            ip_address=entry["ip"],
                            list_type=entry["list_type"],
                        ),
                        shard_id=shard_id,
                    )
                    removed_count += 1
                except Exception as e:
                    logger.warning(f"Failed to remove {entry['ip']} from scrubbers: {e}")

            # Delete from database (CASCADE will handle, but explicit for clarity)
            db.execute("DELETE FROM origin_whitelist WHERE origin_id = %s", (origin_id,))
            db.execute("DELETE FROM origin_blacklist WHERE origin_id = %s", (origin_id,))
            db.execute("DELETE FROM origin_blacklist_override WHERE origin_id = %s", (origin_id,))

            # Audit log
            db.execute(
                """
                INSERT INTO origin_reputation_log
                (origin_id, list_type, action, ip_address, performed_by, success)
                VALUES (%s, 'all', 'cleanup', '0.0.0.0', 'system', true)
            """,
                (origin_id,),
            )

            logger.info(
                f"Cleaned per-origin reputation for {origin_id}: "
                f"{removed_count}/{len(entries)} entries removed from scrubbers"
            )

        except Exception as e:
            logger.error(f"Failed to cleanup origin reputation for {origin_id}: {e}")
            # Non-fatal - continue with origin deletion
        finally:
            db.close()

    def delete_origin(self, origin_id: str, job_id: str = None) -> tuple:
        """
        Delete an Origin - Clean up BOTH scrubbers and database.

        Database-first: Checks database if not in cache, ensuring origins
        are always found and cleaned up even after miner restart.

        Args:
            origin_id: The origin to delete
            job_id: Optional job_id for progress updates (when called from job worker)

        Returns: (jsonify response, status_code) or dict when called from job worker
        """
        # Progress update helper (no-op if job_id not provided)
        def _progress(percent: int, message: str):
            if job_id:
                from miner_control_plane.services.job_worker import update_job_progress
                update_job_progress(job_id, percent, message)
        # Ensure DB connection is alive (cleanup kills idle connections)
        self._ensure_db_connection()

        try:
            origin = None

            # First check in-memory cache (fast path)
            if origin_id in self.state.origins_db:
                origin = self.state.origins_db[origin_id]
                logger.info(f"Deleting Origin: {origin_id} (from cache)")
            else:
                # Not in cache - query database (handles miner restart scenario)
                logger.info(f"Origin {origin_id} not in cache, checking database...")
                from shared.utils.database_helpers import db_load_origins

                db = get_db_connection()
                try:
                    all_origins = db_load_origins(db)
                    if origin_id in all_origins:
                        origin = all_origins[origin_id]
                        # Update cache for consistency
                        self.state.origins_db[origin_id] = origin
                        logger.info(f"Deleting Origin: {origin_id} (loaded from database)")
                finally:
                    db.close()

            if not origin:
                if job_id:
                    raise Exception("Origin not found")
                return jsonify({"status": "error", "message": "Origin not found"}), 404

            _progress(10, f"Found origin {origin_id}, preparing cleanup")

            # Get shard info for this origin
            shard_id = origin.get("shard_id")
            if not shard_id:
                logger.warning(f"Origin {origin_id} has no shard_id, using first available shard")
                if self.state.shards_db:
                    shard_id = list(self.state.shards_db.keys())[0]
                else:
                    raise Exception("No shards available for cleanup")

            # Get region from shard
            region = None
            shard = self.state.get_shard(shard_id)
            if shard:
                region = shard.get("region")

            # Get shard nodes - only active is required for deletion
            active_node = self.state.get_active_node(shard_id)
            standby_node = self.state.get_standby_node(shard_id)

            if not active_node:
                raise Exception(f"Shard {shard_id} has no active node - cannot clean up origin")

            active_ip = active_node["public_ip"]
            active_eni = active_node["eni_id"]
            active_name = active_node.get("instance_name", "active")

            # Standby is optional - may be None after failover until new standby is deployed
            standby_ip = standby_node["public_ip"] if standby_node else None
            standby_eni = standby_node["eni_id"] if standby_node else None
            standby_name = standby_node.get("instance_name", "standby") if standby_node else None

            if not standby_node:
                logger.warning(f"No standby node in shard {shard_id} - skipping standby cleanup")

            # Step 0: Clean per-origin reputation (FIRST - before any other cleanup)
            # Pass shard_id to only clean on shard's scrubbers, not all scrubbers
            _progress(15, "Cleaning per-origin reputation")
            logger.info(f"Cleaning per-origin reputation for {origin_id}")
            self._cleanup_origin_reputation(origin_id, origin["eip"], shard_id=shard_id)

            # Step 1: Clean BPF maps FIRST (while WireGuard interface still exists)
            # CRITICAL: wg2priv_map cleanup needs the interface to get ifindex
            # CRITICAL: Only clean on shard's scrubbers, not all scrubbers!
            _progress(20, "Cleaning BPF maps on scrubbers")
            logger.info(f"Cleaning BPF maps for {origin_id} (before stopping WireGuard)")
            shard_nodes = {}
            if active_node:
                shard_nodes[active_node["node_id"]] = active_node
            if standby_node:
                shard_nodes[standby_node["node_id"]] = standby_node

            bpf_cleanup_result = clean_origin_bpf_maps(
                origin_id,
                origin,
                shard_nodes,  # Only shard's scrubbers, not all nodes
                self.settings.ssh_key_path,
                self.settings,
                verify=True,
            )

            if not bpf_cleanup_result["success"]:
                # Log any issues but don't fail the deletion
                # Remaining stale entries will be cleaned on next miner startup
                logger.warning(
                    f"BPF map cleanup had issues for {origin_id}: {bpf_cleanup_result['errors']}"
                )

            # Step 2: Remove TC qdisc from WireGuard interface (while it still exists)
            _progress(35, "Removing TC qdisc from WireGuard")
            logger.info(f"Cleaning WireGuard TC qdisc for {origin_id}")
            nodes_to_clean = [(active_name, active_ip)]
            if standby_ip:
                nodes_to_clean.append((standby_name, standby_ip))
            for edge_name, node_ip in nodes_to_clean:
                ssh_exec(
                    node_ip,
                    f"sudo tc qdisc del dev {origin['wg_interface']} clsact 2>/dev/null || true",
                    self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )

            # Step 3: Stop and DELETE WireGuard interfaces on active (and standby if present)
            # Note: Interface was created via 'ip link add', so we must use 'ip link delete'
            # (wg-quick won't know about manually created interfaces)
            _progress(40, "Stopping WireGuard tunnels")
            logger.info("Stopping WireGuard on active" + (" and standby" if standby_ip else ""))
            ssh_exec(
                active_ip,
                f"sudo systemctl stop wg-quick@{origin['wg_interface']} 2>/dev/null || true",
                self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )
            if standby_ip:
                ssh_exec(
                    standby_ip,
                    f"sudo systemctl stop wg-quick@{origin['wg_interface']} 2>/dev/null || true",
                    self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )

            # Explicitly delete the interface (required since we use 'ip link add' not wg-quick)
            logger.info("Deleting WireGuard interfaces")
            ssh_exec(
                active_ip,
                f"sudo ip link delete {origin['wg_interface']} 2>/dev/null || true",
                self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )
            if standby_ip:
                ssh_exec(
                    standby_ip,
                    f"sudo ip link delete {origin['wg_interface']} 2>/dev/null || true",
                    self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )

            # Step 4: Remove WireGuard configs
            ssh_exec(
                active_ip,
                f"sudo rm -f /etc/wireguard/{origin['wg_interface']}.conf",
                self.settings.ssh_key_path,
                nodes_db=self.state.nodes_db,
            )
            if standby_ip:
                ssh_exec(
                    standby_ip,
                    f"sudo rm -f /etc/wireguard/{origin['wg_interface']}.conf",
                    self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )

            # Step 4.5: Update expected_tunnels.json on BOTH scrubbers
            # This ensures ecp-agent knows the origin is gone and won't report false "missing tunnel"
            logger.info("Updating expected_tunnels.json on both scrubbers")
            tunnel_results = update_expected_tunnels_on_shard(
                origin_id=origin_id,
                action="remove",
                nodes_db=self.state.nodes_db,
                ssh_key_path=self.settings.ssh_key_path,
                shard_id=shard_id,
            )
            for node_name, success in tunnel_results.items():
                if not success:
                    logger.warning(f"Failed to update expected_tunnels.json on {node_name}")

            # Step 5: Disassociate and release EIP (gracefully handle already-released)
            _progress(50, f"Releasing EIP {origin['eip']}")
            logger.info(f"Releasing EIP {origin['eip']}")
            try:
                # Uses REST API via aws_operations
                addresses = aws_operations.describe_addresses(public_ips=[origin["eip"]], region=region)
                if addresses:
                    assoc_id = addresses[0].get("association_id")
                    if assoc_id:
                        aws_operations.disassociate_address(assoc_id, region=region)
                        logger.info(f"Disassociated EIP {origin['eip']}")
                    else:
                        logger.info(f"EIP {origin['eip']} already disassociated")
                else:
                    logger.info(
                        f"EIP {origin['eip']} not found (already released or never allocated)"
                    )

                # Try to release EIP (might already be released)
                try:
                    aws_operations.release_eip(origin["eip_alloc_id"], region=region)
                    logger.info(f"Released EIP {origin['eip']}")
                    # Clear EIP cache after successful release
                    eip_availability.clear_cache(region=region)
                except Exception as release_err:
                    # EIP already released is OK (idempotent cleanup)
                    logger.info(f"EIP {origin['eip']} already released or not found: {release_err}")

            except Exception as eip_err:
                # If EIP operations fail, log but continue (EIP might be already gone)
                logger.warning(f"EIP cleanup failed (continuing with delete): {eip_err}")

            # Step 6: Release private IPs via NetworkPolicy (handles both ENI and OS cleanup)
            _progress(60, "Releasing private IP addresses")
            logger.info("Releasing private IPs via NetworkPolicy")
            try:
                from miner_control_plane.services.network_policies.registry import get_policy_for_shard
                from miner_control_plane.services.network_policies.base import AllocationResult

                policy = get_policy_for_shard(shard_id, self.state)

                # Reconstruct AllocationResult from origin data
                allocation = AllocationResult(
                    attachment_type="aws_secondary_private_ipv4",
                    active={
                        "private_ip": origin["private_ip"],
                        "eni_id": active_eni,
                        "node_id": active_node["node_id"],
                    },
                    standby={
                        "private_ip": origin.get("private_ip_standby"),
                        "eni_id": standby_eni,
                        "node_id": standby_node["node_id"] if standby_node else None,
                    } if standby_node else None,
                )

                policy.release_origin_attachment(
                    shard_id=shard_id, origin_id=origin_id, allocation=allocation
                )
                logger.info(f"NetworkPolicy released IPs for origin {origin_id}")
            except Exception as e:
                # Best-effort cleanup - log but don't fail deletion
                logger.warning(f"NetworkPolicy release failed: {e}, attempting manual cleanup")

                # Fallback to manual cleanup
                ssh_exec(
                    active_ip,
                    f"sudo ip addr del {origin['private_ip']}/24 dev ens5 2>/dev/null || true",
                    self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )

                try:
                    aws_operations.unassign_private_ip_addresses(
                        active_eni, [origin["private_ip"]], region=region
                    )
                    logger.info(f"Unassigned private IP {origin['private_ip']} from active edge")
                except Exception as e2:
                    logger.info(
                        f"Private IP {origin['private_ip']} already unassigned from active edge: {e2}"
                    )

                if standby_ip and standby_eni and origin.get("private_ip_standby"):
                    ssh_exec(
                        standby_ip,
                        f"sudo ip addr del {origin['private_ip_standby']}/24 dev ens5 2>/dev/null || true",
                        self.settings.ssh_key_path,
                        nodes_db=self.state.nodes_db,
                    )

                    try:
                        aws_operations.unassign_private_ip_addresses(
                            standby_eni, [origin["private_ip_standby"]], region=region
                        )
                        logger.info(
                            f"Unassigned private IP {origin['private_ip_standby']} from standby edge"
                        )
                    except Exception as e2:
                        logger.info(
                            f"Private IP {origin['private_ip_standby']} already unassigned from standby edge: {e2}"
                        )

            # Step 7: Remove ports from Security Group (with reference counting)
            if "required_ports" in origin:
                aws_operations.remove_unused_ports_from_security_group(
                    origin_id, origin.get("required_ports") or [], self.state.origins_db, region=region
                )

            # Step 7.5: Remove origin-specific whitelist entries (auto-cleanup)
            try:
                conn = self.db.conn
                cur = conn.cursor()

                # Find whitelist entries for this origin
                cur.execute(
                    "SELECT ip_address FROM whitelist_entries WHERE origin_id = %s", (origin_id,)
                )
                whitelist_ips = [str(row[0]) for row in cur.fetchall()]

                if whitelist_ips:
                    # Remove from database
                    cur.execute("DELETE FROM whitelist_entries WHERE origin_id = %s", (origin_id,))
                    conn.commit()

                    # Remove from BPF maps on scrubbers
                    # NOTE: whitelist_map is an XDP map (defined in xdp_wan.c)
                    edges_to_clean = [(active_name, active_ip)]
                    if standby_ip:
                        edges_to_clean.append((standby_name, standby_ip))
                    for ip in whitelist_ips:
                        ip_hex = "".join([f"{int(o):02x}" for o in ip.split(".")])
                        for edge_name, node_ip in edges_to_clean:
                            ssh_exec(
                                node_ip,
                                f"sudo bpftool map delete pinned /sys/fs/bpf/xdp/globals/whitelist_map key hex {ip_hex}",
                                self.settings.ssh_key_path,
                                nodes_db=self.state.nodes_db,
                            )

                    logger.info(
                        f"Removed {len(whitelist_ips)} origin-specific whitelist entries for {origin_id}"
                    )

                cur.close()

            except Exception as e:
                logger.warning(f"Whitelist cleanup failed for {origin_id}: {e}")

            # Step 7.6: LAYER 3 & 4 - Clean up per-origin maps and quarantine entries
            _progress(75, "Cleaning Layer 3/4 BPF maps")
            try:
                origin_ip_bytes = socket.inet_aton(origin["origin_ip"])
                origin_ip_hex = " ".join([f"{b:02x}" for b in origin_ip_bytes])

                logger.info(f"Cleaning Layer 3/4 maps for origin {origin['origin_ip']}...")

                cleanup_edges = [(active_name, active_ip)]
                if standby_ip:
                    cleanup_edges.append((standby_name, standby_ip))

                for edge_name, node_ip in cleanup_edges:
                    # Delete origin_challenge_map entry (XDP map)
                    ssh_exec(
                        node_ip,
                        f"sudo bpftool map delete pinned /sys/fs/bpf/xdp/globals/origin_challenge_map key hex {origin_ip_hex} 2>/dev/null || true",
                        self.settings.ssh_key_path,
                        nodes_db=self.state.nodes_db,
                    )

                    # Delete syncookie_mode_map entry (TC map)
                    ssh_exec(
                        node_ip,
                        f"sudo bpftool map delete pinned /sys/fs/bpf/tc/globals/syncookie_mode_map key hex {origin_ip_hex} 2>/dev/null || true",
                        self.settings.ssh_key_path,
                        nodes_db=self.state.nodes_db,
                    )

                    # Delete vip_state_map entry (SYN cookie state per-VIP)
                    ssh_exec(
                        node_ip,
                        f"sudo bpftool map delete pinned /sys/fs/bpf/xdp/globals/vip_state_map key hex {origin_ip_hex} 2>/dev/null || true",
                        self.settings.ssh_key_path,
                        nodes_db=self.state.nodes_db,
                    )

                    logger.info(f"Cleaned Layer 3/4 control maps for {origin_id} on {edge_name}")

                # Clean Layer 4 per-source maps (cookie_failure, quarantine, bypass)
                logger.info(f"Cleaning Layer 4 per-source maps for VIP {origin['eip']}...")

                eip_bytes = socket.inet_aton(origin["eip"])
                eip_hex = " ".join([f"{b:02x}" for b in eip_bytes])

                for edge_name, node_ip in cleanup_edges:
                    # Clean cookie_failure_map
                    cmd = f"sudo bpftool map dump pinned /sys/fs/bpf/tc/globals/cookie_failure_map 2>/dev/null | grep -A1 '{eip_hex}' | grep 'key:' | awk '{{print $2,$3,$4,$5,$6,$7,$8,$9}}' | while read k; do sudo bpftool map delete pinned /sys/fs/bpf/tc/globals/cookie_failure_map key hex $k 2>/dev/null; done"
                    ssh_exec(node_ip, cmd, self.settings.ssh_key_path, nodes_db=self.state.nodes_db)

                    # Clean quarantine_map
                    cmd = f"sudo bpftool map dump pinned /sys/fs/bpf/xdp/globals/quarantine_map 2>/dev/null | grep -A1 '{eip_hex}' | grep 'key:' | awk '{{print $2,$3,$4,$5,$6,$7,$8,$9}}' | while read k; do sudo bpftool map delete pinned /sys/fs/bpf/xdp/globals/quarantine_map key hex $k 2>/dev/null; done"
                    ssh_exec(node_ip, cmd, self.settings.ssh_key_path, nodes_db=self.state.nodes_db)

                    # Clean bypass_map
                    cmd = f"sudo bpftool map dump pinned /sys/fs/bpf/xdp/globals/bypass_map 2>/dev/null | grep -A1 '{eip_hex}' | grep 'key:' | awk '{{print $2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13}}' | while read k; do sudo bpftool map delete pinned /sys/fs/bpf/xdp/globals/bypass_map key hex $k 2>/dev/null; done"
                    ssh_exec(node_ip, cmd, self.settings.ssh_key_path, nodes_db=self.state.nodes_db)

                    logger.info(f"Cleaned Layer 4 per-source maps for {origin_id} on {edge_name}")

                # Clean source_state table for this VIP
                conn = self.db.conn
                cur = conn.cursor()
                cur.execute("DELETE FROM source_state WHERE vip_ip = %s", (origin["eip"],))
                deleted_sources = cur.rowcount
                conn.commit()
                cur.close()

                if deleted_sources > 0:
                    logger.info(f"Cleaned {deleted_sources} source_state entries for {origin_id}")

            except Exception as e:
                logger.warning(f"Layer 3/4 cleanup failed for {origin_id}: {e}")

            # Step 7.7: LAYER 5 - Clean origin_stats_map entry
            _progress(85, "Cleaning Layer 5 origin stats")
            try:
                origin_ip_bytes = socket.inet_aton(origin["origin_ip"])
                origin_ip_hex = " ".join([f"{b:02x}" for b in origin_ip_bytes])

                logger.info(f"Cleaning Layer 5 origin_stats_map for {origin['origin_ip']}...")

                layer5_edges = [(active_name, active_ip)]
                if standby_ip:
                    layer5_edges.append((standby_name, standby_ip))

                for edge_name, node_ip in layer5_edges:
                    rc, stdout, stderr = ssh_exec(
                        node_ip,
                        f"sudo bpftool map delete pinned /sys/fs/bpf/tc/globals/origin_stats_map key hex {origin_ip_hex}",
                        self.settings.ssh_key_path,
                        nodes_db=self.state.nodes_db,
                    )

                    if rc == 0:
                        logger.info(
                            f"Deleted origin_stats_map entry for {origin['origin_ip']} on {edge_name}"
                        )
                    else:
                        logger.debug(
                            f"origin_stats_map entry not found on {edge_name} (may be pre-initialized)"
                        )

                    # Verify deletion
                    rc_verify, stdout_verify, _ = ssh_exec(
                        node_ip,
                        f"sudo bpftool map lookup pinned /sys/fs/bpf/tc/globals/origin_stats_map key hex {origin_ip_hex} 2>&1",
                        self.settings.ssh_key_path,
                        nodes_db=self.state.nodes_db,
                    )

                    if rc_verify != 0:
                        logger.info(f"✓ Verified: origin_stats_map entry deleted on {edge_name}")
                    else:
                        logger.warning(
                            f"⚠ Warning: origin_stats_map entry still exists on {edge_name}"
                        )

            except Exception as e:
                logger.warning(f"Layer 5 cleanup failed for {origin_id}: {e}")

            # Step 7.75: Delete origin_rate_config_map entry from BPF maps
            try:
                origin_ip = origin.get("origin_ip")
                if origin_ip:
                    logger.info(f"Cleaning origin_rate_config_map for {origin_ip}...")

                    # Delete from active scrubber
                    delete_origin_rate_config(
                        host=active_ip,
                        origin_ip=origin_ip,
                        ssh_key_path=self.settings.ssh_key_path,
                        nodes_db=self.state.nodes_db,
                    )
                    logger.info(f"Deleted origin_rate_config_map entry on {active_name}")

                    # Delete from standby scrubber (if present)
                    if standby_ip:
                        delete_origin_rate_config(
                            host=standby_ip,
                            origin_ip=origin_ip,
                            ssh_key_path=self.settings.ssh_key_path,
                            nodes_db=self.state.nodes_db,
                        )
                        logger.info(f"Deleted origin_rate_config_map entry on {standby_name}")

            except Exception as e:
                logger.warning(f"Rate config cleanup failed for {origin_id}: {e}")

            # Step 7.8: Clean origin-related database records (metrics, baselines, anomaly detection)
            _progress(90, "Cleaning database records")
            try:
                conn = self.db.conn
                cur = conn.cursor()

                # Delete origin metrics and historical data
                tables_to_clean = [
                    "origin_metrics",
                    "origin_metrics_hourly",
                    "traffic_baselines",
                    "baseline_config",
                    "anomaly_detection_state",
                    "health_origin",
                    "mitigation_actions",
                    "origin_bandwidth_quota",  # QoS quota (FK may not exist in all deployments)
                    "origin_bandwidth_usage",  # QoS historical usage
                ]

                for table in tables_to_clean:
                    try:
                        cur.execute(f"DELETE FROM {table} WHERE origin_id = %s", (origin_id,))
                        deleted_count = cur.rowcount
                        if deleted_count > 0:
                            logger.info(
                                f"Cleaned {deleted_count} entries from {table} for {origin_id}"
                            )
                    except Exception as table_error:
                        logger.debug(
                            f"Table {table} cleanup (may not exist or have origin_id column): {table_error}"
                        )

                conn.commit()
                cur.close()

                logger.info(f"Completed database cleanup for {origin_id}")

            except Exception as e:
                logger.warning(f"Database cleanup failed for {origin_id}: {e}")

            # Step 8: Remove from database and memory
            _progress(95, "Finalizing deletion")
            try:
                db_delete_origin(origin_id, origin["eip_alloc_id"], self.db)
            except Exception as e:
                logger.error(f"Database delete failed (continuing): {e}")

            # Remove from in-memory cache (defensive: check exists first to avoid KeyError)
            if origin_id in self.state.origins_db:
                del self.state.origins_db[origin_id]
            else:
                logger.debug(f"Origin {origin_id} already removed from cache")

            # Clean up bandwidth quota/usage caches
            origin_ip = origin.get('origin_ip')
            if origin_ip:
                self.state.bandwidth_quotas.pop(origin_ip, None)
                self.state.bandwidth_usage.pop(origin_ip, None)

            # Recalculate quotas for remaining origins in this shard
            # (they now get more bandwidth with one less origin)
            try:
                from miner_control_plane.services.bandwidth_quota_service import recalculate_quotas
                recalculate_quotas(shard_id)
                logger.info(f"Recalculated bandwidth quotas for shard {shard_id}")
            except Exception as e:
                logger.warning(f"Quota recalculation failed after origin deletion: {e}")

            logger.info(f"Origin {origin_id} deleted successfully")

            # Return dict when called from job worker, Flask response otherwise
            result = {"status": "success", "origin_id": origin_id, "shard_id": shard_id}
            if job_id:
                return result
            return jsonify(result), 200

        except Exception as e:
            logger.error(f"Failed to delete Origin: {e}")
            if job_id:
                raise  # Let job worker handle failure
            return jsonify({"status": "error", "message": str(e)}), 500

    def cleanup_orphan_resources(self) -> Dict[str, List[Dict[str, str]]]:
        """
        Release Elastic IPs and private IPs attached to scrubbers but not tracked in Miner.

        Handles cases where origin registration failed midway and state/origins DB
        no longer reflect AWS resources.

        Multi-region aware: Cleans up resources across all deployed regions.
        """
        summary = {"released_eips": [], "detached_private_ips": [], "errors": []}

        # Ensure latest state is loaded
        if not self.state.nodes_db:
            self.state.load_state()

        if not self.state.nodes_db:
            raise Exception("No edge nodes available for cleanup")

        # Get all unique regions from shards
        regions = set()
        for shard in self.state.shards_db.values():
            if shard.get('region'):
                regions.add(shard['region'])

        # If no shards exist, use default region
        if not regions:
            regions = {self.settings.scrubber_region}

        logger.info(f"Cleaning up orphaned resources across {len(regions)} region(s): {regions}")

        tracked_alloc_ids = {
            origin.get("eip_alloc_id")
            for origin in self.state.origins_db.values()
            if origin.get("eip_alloc_id")
        }
        tracked_private_ips = {
            ip
            for origin in self.state.origins_db.values()
            for ip in [origin.get("private_ip"), origin.get("private_ip_standby")]
            if ip
        }

        # Preserve the primary private IPs for each scrubber
        retained_private_ips = set(tracked_private_ips)
        for node in self.state.nodes_db.values():
            if node.get("private_ip"):
                retained_private_ips.add(str(node["private_ip"]))

        # Cleanup orphaned Elastic IPs in each region
        # This includes:
        # 1. EIPs attached to our scrubbers but not tracked in origins_db
        # 2. EIPs NOT attached to anything (orphans from failed cleanups)
        for region in regions:
            logger.info(f"Checking for orphaned EIPs in region: {region}")

            try:
                addresses = aws_operations.describe_addresses(region=region)
            except Exception as e:
                logger.error(f"describe_addresses failed in {region}: {e}")
                summary["errors"].append(f"describe_addresses failed in {region}: {e}")
                addresses = []

            # Build ENI lookup for nodes in this region only
            eni_lookup = {
                node["eni_id"]: {"edge": edge_name, "public_ip": node["public_ip"]}
                for edge_name, node in self.state.nodes_db.items()
                if node.get("eni_id") and node.get("region") == region
            }

            # Also track scrubber public IPs in this region to avoid releasing their management EIPs
            scrubber_public_ips = {
                node.get("public_ip")
                for node in self.state.nodes_db.values()
                if node.get("public_ip") and node.get("region") == region
            }

            for addr in addresses:
                alloc_id = addr.get("allocation_id")
                public_ip = addr.get("public_ip")
                eni_id = addr.get("network_interface_id")

                if not alloc_id:
                    continue

                # Skip if this is a tracked origin EIP
                if alloc_id in tracked_alloc_ids:
                    continue

                # Skip scrubber management IPs (their own public IPs)
                if public_ip in scrubber_public_ips:
                    continue

                # Release if:
                # 1. Attached to one of our scrubber ENIs but not tracked (orphan on scrubber)
                # 2. NOT attached to any ENI (orphan from failed cleanup - the key fix!)
                is_on_our_scrubber = eni_id and eni_id in eni_lookup
                is_unattached = not eni_id

                if is_on_our_scrubber or is_unattached:
                    assoc_id = addr.get("association_id")
                    try:
                        if assoc_id:
                            aws_operations.disassociate_address(assoc_id, region=region)
                        aws_operations.release_eip(alloc_id, region=region)
                        # Clear EIP cache after successful release
                        eip_availability.clear_cache(region=region)
                        summary["released_eips"].append(
                            {"public_ip": public_ip, "allocation_id": alloc_id, "region": region}
                        )
                        reason = "unattached" if is_unattached else "on scrubber but untracked"
                        logger.info(
                            f"Released orphaned EIP {alloc_id} ({public_ip}) "
                            f"in {region} - {reason}"
                        )
                    except Exception as e:
                        msg = f"Failed to release orphaned EIP {alloc_id} in {region}: {e}"
                        logger.error(msg)
                        summary["errors"].append(msg)

        # Cleanup orphaned private IPs on each scrubber
        # Group nodes by region for clarity
        for edge_name, node in self.state.nodes_db.items():
            eni_id = node.get("eni_id")
            node_region = node.get("region")

            if not eni_id or not node_region:
                continue

            try:
                network_interfaces = aws_operations.describe_network_interfaces(
                    network_interface_ids=[eni_id],
                    region=node_region
                )
                if not network_interfaces:
                    continue
                private_ip_entries = network_interfaces[0].get("private_ip_addresses", [])
            except Exception as e:
                msg = (
                    f"describe_network_interfaces failed for {eni_id} "
                    f"in {node_region}: {e}"
                )
                logger.error(msg)
                summary["errors"].append(msg)
                continue

            for entry in private_ip_entries:
                ip_addr = entry.get("private_ip_address")
                if not ip_addr or entry.get("primary"):
                    continue
                if ip_addr in retained_private_ips:
                    continue

                try:
                    ssh_exec(
                        node["public_ip"],
                        f"sudo ip addr del {ip_addr}/24 dev ens5 2>/dev/null || true",
                        self.settings.ssh_key_path,
                        nodes_db=self.state.nodes_db,
                    )
                except Exception as ssh_err:
                    logger.warning(f"Failed to remove IP {ip_addr} on {edge_name}: {ssh_err}")

                try:
                    aws_operations.unassign_private_ip_addresses(
                        eni_id, [ip_addr], region=node_region
                    )
                    summary["detached_private_ips"].append(
                        {"edge": edge_name, "private_ip": ip_addr, "region": node_region}
                    )
                    logger.info(
                        f"Detached orphaned private IP {ip_addr} from "
                        f"{edge_name} in {node_region}"
                    )
                except Exception as e:
                    msg = (
                        f"Failed to unassign private IP {ip_addr} from "
                        f"{eni_id} in {node_region}: {e}"
                    )
                    logger.error(msg)
                    summary["errors"].append(msg)

        # Cleanup orphaned BPF map entries on each scrubber
        summary["cleaned_bpf_entries"] = []

        # Build set of tracked origin IPs for comparison
        tracked_origin_ips = {
            origin.get("origin_ip")
            for origin in self.state.origins_db.values()
            if origin.get("origin_ip")
        }

        for edge_name, node in self.state.nodes_db.items():
            host_ip = node.get("public_ip")
            if not host_ip:
                continue

            # Check eip_map for orphaned entries (key = private_ip)
            try:
                rc, stdout, _ = ssh_exec(
                    host_ip,
                    "sudo bpftool map dump pinned /sys/fs/bpf/tc/globals/eip_map -j 2>/dev/null || echo '[]'",
                    self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )
                if rc == 0 and stdout.strip():
                    entries = json.loads(stdout)
                    for entry in entries:
                        # Key is private_ip in little-endian
                        key_int = entry.get("key", 0)
                        priv_ip = socket.inet_ntoa(struct.pack("<I", key_int))
                        if priv_ip not in retained_private_ips:
                            # Orphaned entry - delete it
                            priv_bytes = socket.inet_aton(priv_ip)
                            priv_hex = " ".join([f"{b:02x}" for b in priv_bytes])
                            ssh_exec(
                                host_ip,
                                f"sudo bpftool map delete pinned /sys/fs/bpf/tc/globals/eip_map key hex {priv_hex}",
                                self.settings.ssh_key_path,
                                nodes_db=self.state.nodes_db,
                            )
                            summary["cleaned_bpf_entries"].append(
                                {"edge": edge_name, "map": "eip_map", "key": priv_ip}
                            )
                            logger.info(
                                f"Cleaned orphaned eip_map entry for {priv_ip} on {edge_name}"
                            )
            except Exception as e:
                logger.warning(f"Failed to clean eip_map on {edge_name}: {e}")

            # Check origin_to_priv_map for orphaned entries (key = origin_ip)
            try:
                rc, stdout, _ = ssh_exec(
                    host_ip,
                    "sudo bpftool map dump pinned /sys/fs/bpf/tc/globals/origin_to_priv_map -j 2>/dev/null || echo '[]'",
                    self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )
                if rc == 0 and stdout.strip():
                    entries = json.loads(stdout)
                    for entry in entries:
                        # Key is origin_ip in little-endian
                        key_int = entry.get("key", 0)
                        origin_ip = socket.inet_ntoa(struct.pack("<I", key_int))
                        if origin_ip not in tracked_origin_ips:
                            # Orphaned entry - delete it
                            origin_bytes = socket.inet_aton(origin_ip)
                            origin_hex = " ".join([f"{b:02x}" for b in origin_bytes])
                            ssh_exec(
                                host_ip,
                                f"sudo bpftool map delete pinned /sys/fs/bpf/tc/globals/origin_to_priv_map key hex {origin_hex}",
                                self.settings.ssh_key_path,
                                nodes_db=self.state.nodes_db,
                            )
                            summary["cleaned_bpf_entries"].append(
                                {"edge": edge_name, "map": "origin_to_priv_map", "key": origin_ip}
                            )
                            logger.info(
                                f"Cleaned orphaned origin_to_priv_map entry for {origin_ip} on {edge_name}"
                            )
            except Exception as e:
                logger.warning(f"Failed to clean origin_to_priv_map on {edge_name}: {e}")

        # FIX 5: Clean up ALL stale BPF map entries
        # This is the final safeguard against orphaned kernel state
        logger.info("Performing comprehensive BPF map cleanup...")
        try:
            tracked_origin_ips = {
                origin.get("origin_ip")
                for origin in self.state.origins_db.values()
                if origin.get("origin_ip")
            }

            for edge_name, node in self.state.nodes_db.items():
                edge_ip = node["public_ip"]

                # Get list of all origin_stats entries and remove those not in database
                rc, stdout, stderr = ssh_exec(
                    edge_ip,
                    "sudo bpftool map dump pinned /sys/fs/bpf/tc/globals/origin_stats_map 2>/dev/null",
                    self.settings.ssh_key_path,
                    nodes_db=self.state.nodes_db,
                )

                if rc == 0:
                    try:
                        entries = json.loads(stdout)
                        cleaned_count = 0

                        for entry in entries:
                            try:
                                origin_ip_int = entry.get("key")
                                if not origin_ip_int:
                                    continue

                                # Convert hex key to IP
                                origin_ip = socket.inet_ntoa(
                                    socket.inet_aton(
                                        ".".join(
                                            str((origin_ip_int >> (i * 8)) & 0xFF) for i in range(4)
                                        )
                                    )
                                )

                                if origin_ip not in tracked_origin_ips:
                                    # Orphaned entry - clean it up
                                    origin_ip_bytes = socket.inet_aton(origin_ip)
                                    origin_ip_hex = " ".join([f"{b:02x}" for b in origin_ip_bytes])

                                    ssh_exec(
                                        edge_ip,
                                        f"sudo bpftool map delete pinned /sys/fs/bpf/tc/globals/origin_stats_map key hex {origin_ip_hex} 2>/dev/null || true",
                                        self.settings.ssh_key_path,
                                        nodes_db=self.state.nodes_db,
                                    )
                                    cleaned_count += 1
                            except Exception:
                                # Skip entries that fail to parse
                                continue

                        if cleaned_count > 0:
                            summary["cleaned_bpf_entries"] = {edge_name: cleaned_count}
                            logger.info(
                                f"Cleaned {cleaned_count} orphaned origin_stats entries on {edge_name}"
                            )

                    except Exception as parse_err:
                        logger.debug(
                            f"Could not parse origin_stats_map on {edge_name}: {parse_err}"
                        )

        except Exception as e:
            logger.warning(f"Comprehensive BPF cleanup failed (non-critical): {e}")

        return summary

    def list_origins(self) -> List[Dict]:
        """
        List all origins.
        """
        origins_list = []
        for origin_id, origin in self.state.origins_db.items():
            origins_list.append(
                {
                    "origin_id": origin_id,
                    "origin_ip": origin.get("origin_ip"),
                    "eip": origin.get("eip"),
                    "state": origin.get("state"),
                    "exit_hub_ip": origin.get("exit_hub_ip"),
                }
            )
        return origins_list

    def get_origin(self, origin_id: str) -> Dict:
        """
        Get origin details.
        """
        if origin_id not in self.state.origins_db:
            return None

        origin = self.state.origins_db[origin_id]
        return {
            "origin_id": origin_id,
            "origin_ip": origin.get("origin_ip"),
            "eip": origin.get("eip"),
            "state": origin.get("state"),
            "exit_hub_ip": origin.get("exit_hub_ip"),
            "wg_interface": origin.get("wg_interface"),
            "required_ports": origin.get("required_ports"),
        }


# Singleton instance
origin_service = OriginService()
