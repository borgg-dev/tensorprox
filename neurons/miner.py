"""
================================================================================

TensorProx Miner Implementation

Copyright (c) 2025 Shugo LTD. All Rights Reserved.

This module defines the `Miner` class, which represents a mining node within the TensorProx network. 
The miner is responsible for secure SSH key distribution to validators, packet sniffing, 
firewall management, and real-time DDoS detection.

Key Features:
- **SSH Key Management:** Generates and distributes SSH key pairs to authorized machines.
- **Packet Inspection:** Captures and processes network packets using raw sockets.
- **Firewall Control:** Dynamically enables or disables firewall functionality based on challenge states.
- **Machine Learning-Based Traffic Filtering:** Uses a trained Decision Tree model to classify network traffic 
  and determine whether to allow or block packets.
- **Batch Processing:** Aggregates packets over a configurable interval and evaluates them using feature extraction.

Dependencies:
- `tensorprox`: Provides core functionalities and network protocols.
- `paramiko`: Used for SSH key distribution and management.
- `sklearn`, `joblib`: Used for loading and running machine learning models.
- `numpy`: Supports feature extraction and data manipulation.
- `loguru`: Handles logging and debugging information.

License:
This software is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0).
You are free to use, share, and modify the code for non-commercial purposes only.

Commercial Usage:
The only authorized commercial use of this software is for mining or validating within the TensorProx subnet.
For any other commercial licensing requests, please contact Shugo LTD.

See the full license terms here: https://creativecommons.org/licenses/by-nc/4.0/

Author: Shugo LTD
Version: 0.1.0

================================================================================
"""


# ruff: noqa: E402
import os, sys
sys.path.append(os.path.expanduser("~/tensorprox"))
import os
from tensorprox import *
from tensorprox import settings
settings.settings = settings.Settings.load(mode="miner")
settings = settings.settings
import time
from loguru import logger
from tensorprox.base.miner import BaseMinerNeuron
from tensorprox.utils.logging import ErrorLoggingEvent, log_event
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse, MachineDetails
from tensorprox.utils.utils import *
from tensorprox.core.immutable.gre_setup import GRESetup
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from threading import Thread, Event
import asyncio
import socket
import struct
from pydantic import Field, PrivateAttr
from typing import List, Tuple, Any
import select
from collections import defaultdict
import numpy as np
import joblib
from sklearn.tree import DecisionTreeClassifier
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
import asyncssh

NEURON_STOP_ON_FORWARD_EXCEPTION: bool = False

#Miner global vars
ATTACKER_PUBLIC_IP: str = os.environ.get("ATTACKER_PUBLIC_IP")
BENIGN_PUBLIC_IP: str = os.environ.get("BENIGN_PUBLIC_IP")
KING_PUBLIC_IP: str = os.environ.get("KING_PUBLIC_IP")
ATTACKER_PRIVATE_IP: str = os.environ.get("ATTACKER_PRIVATE_IP")
BENIGN_PRIVATE_IP: str = os.environ.get("BENIGN_PRIVATE_IP")
KING_PRIVATE_IP: str = os.environ.get("KING_PRIVATE_IP")
MOAT_PRIVATE_IP: str = os.environ.get("MOAT_PRIVATE_IP")
FORWARD_PORT: int = os.environ.get("FORWARD_PORT", 8080)
ATTACKER_USERNAME: str = os.environ.get("ATTACKER_USERNAME", "root")
BENIGN_USERNAME: str = os.environ.get("BENIGN_USERNAME", "root")
KING_USERNAME: str = os.environ.get("KING_USERNAME", "root")
INITIAL_PK_PATH: str = os.environ.get("PRIVATE_KEY_PATH")

class Miner(BaseMinerNeuron):
    """
    A class representing a miner node in the TensorProx network. 
    This node performs SSH key distribution to validators, packet inspection
    and firewall management for secure network access.
    """

    should_exit: bool = False
    firewall_active: bool = False
    firewall_thread: Thread = None
    stop_firewall_event: Event = Field(default_factory=Event)
    packet_buffer: List[Tuple[bytes, int]] = Field(default_factory=list)
    batch_interval: int = 10
            
    _lock: asyncio.Lock = PrivateAttr()
    _model: DecisionTreeClassifier = PrivateAttr()
    _imputer: SimpleImputer = PrivateAttr()
    _scaler: StandardScaler = PrivateAttr()

    def __init__(self, **data):
        """Initializes the Miner neuron with necessary machine learning models and configurations."""

        super().__init__(**data)
        self._lock = asyncio.Lock()

        base_path = os.path.expanduser("~/tensorprox/model") 
        self._model = joblib.load(os.path.join(base_path, "decision_tree.pkl"))
        self._imputer = joblib.load(os.path.join(base_path, "imputer.pkl"))
        self._scaler = joblib.load(os.path.join(base_path, "scaler.pkl"))


    async def forward(self, synapse: PingSynapse) -> PingSynapse:
        """
        Handles incoming PingSynapse messages, sets up SSH key pairs, and distributes them to validator.

        Args:
            synapse (PingSynapse): The synapse message containing machine details and configurations.

        Returns:
            PingSynapse: The updated synapse message.
        """

        logger.debug(f"📧 Ping received from {synapse.dendrite.hotkey}, IP: {synapse.dendrite.ip}.")

        try:
            ssh_public_key, ssh_private_key = self.generate_ssh_key_pair()

            synapse.machine_availabilities.key_pair = (ssh_public_key, ssh_private_key)
            synapse.machine_availabilities.machine_config["attacker"] = MachineDetails(ip=ATTACKER_PUBLIC_IP, username=RESTRICTED_USER, private_ip=ATTACKER_PRIVATE_IP)
            synapse.machine_availabilities.machine_config["benign"] = MachineDetails(ip=BENIGN_PUBLIC_IP, username=RESTRICTED_USER, private_ip=BENIGN_PRIVATE_IP)
            synapse.machine_availabilities.machine_config["king"] = MachineDetails(ip=KING_PUBLIC_IP, username=RESTRICTED_USER, private_ip=KING_PRIVATE_IP)
            synapse.machine_availabilities.machine_config["moat"] = MachineDetails(private_ip=MOAT_PRIVATE_IP)

            #Machine's main user
            machine_usernames = {
                "attacker": ATTACKER_USERNAME,
                "benign": BENIGN_USERNAME,
                "king": KING_USERNAME
            }

            # Run SSH key addition in parallel
            tasks = [
                self.add_ssh_key_to_remote_machine(
                    machine_ip=machine_details.ip,
                    ssh_public_key=ssh_public_key,
                    username=machine_usernames.get(machine_name)
                )
                for machine_name, machine_details in synapse.machine_availabilities.machine_config.items()
                if machine_name != "moat"  # Skip Moat machine
            ]

            await asyncio.gather(*tasks)

        except Exception as e:
            logger.exception(e)
            logger.error(f"Error in forward: {e}")
            log_event(ErrorLoggingEvent(error=str(e)))
            if NEURON_STOP_ON_FORWARD_EXCEPTION:
                self.should_exit = True

        logger.debug(f"⏩ Forwarding Ping synapse with machine details to validator {synapse.dendrite.hotkey}: {synapse}.")

        return synapse


    def handle_challenge(self, synapse: ChallengeSynapse) -> ChallengeSynapse:
        """
        Handles challenge requests, including firewall activation and deactivation based on the challenge state.

        Args:
            synapse (ChallengeSynapse): The received challenge synapse containing task details and state information.

        Returns:
            ChallengeSynapse: The same `synapse` object after processing the challenge.
        """

        try:
            # Extract challenge information from the synapse
            task = synapse.task
            state=synapse.state

            logger.debug(f"📧 Synapse received from {synapse.dendrite.hotkey}. Task : {task} | State : {state}.")

            if state == "GET_READY":

                if not self.firewall_active:
                    self.firewall_active = True
                    self.stop_firewall_event.clear()  # Reset stop event
                    # Start sniffing in a separate thread to avoid blocking
                    self.firewall_thread = Thread(target=self.run_packet_stream, args=(KING_OVERLAY_IP, ["gre-benign", "gre-attacker"]))
                    self.firewall_thread.daemon = True  # Set the thread to daemon mode to allow termination
                    self.firewall_thread.start()
                    logger.info("🔥 Moat firewall activated.")
                else:
                    logger.info("💥 Moat firewall already activated.")
    
            elif state == "END_ROUND":

                if self.firewall_active:
                    self.firewall_active = False
                    self.stop_firewall_event.set()  # Signal firewall to stop
                    logger.info("🛑 Moat firewall deactivated.")
                else:
                    logger.info("💥 Moat firewall already deactivated.")

                logger.warning("🚨 Round finished, waiting for next one...")    

        except Exception as e:
            logger.exception(e)
            logger.error(f"Error in challenge handling: {e}")
            log_event(ErrorLoggingEvent(error=str(e)))
            if NEURON_STOP_ON_FORWARD_EXCEPTION:
                self.should_exit = True

        return synapse


    def is_allowed_batch(self, features):
        """
        Determines if a batch of packets should be allowed or blocked.

        Args:
            features (np.ndarray): A 1D NumPy array representing the extracted features of a batch of packets.

        Returns:
            bool: 
                - `False` if the batch should be **blocked** (prediction is 1 or 2).  
                - `True` if the batch should be **allowed** (prediction is -1 or 0).
            label_type: `UDP_FLOOD`, `TCP_SYN_FLOOD`, `BENIGN` or None
        """

        prediction = self.predict_sample(features)  # Get prediction
        label_type = None
        allowed = True

        if prediction == 1 :
            label_type = "UDP_FLOOD"
            allowed = False
        elif prediction == 2 :
            label_type = "TCP_SYN_FLOOD"
            allowed = False

        return allowed, label_type
    
    
    def run_packet_stream(self, destination_ip, iface):
        """
        Runs the firewall sniffing logic in an asynchronous event loop.

        Args:
            king_private_ip (str): The private IP address of the King node to forward packets to.
            iface (str, optional): The network interface to sniff packets from. Defaults to "eth0".
        """

        loop = asyncio.new_event_loop()  # Create a new event loop for the sniffing thread
        asyncio.set_event_loop(loop)  # Set the new loop as the current one for this thread
        
        # Ensure that the sniffer doesn't block the main process
        loop.create_task(self.sniff_packets_stream(destination_ip, iface, self.stop_firewall_event))
        loop.run_forever()  # Ensure the loop keeps running


    async def moat_forward_packet(self, packet, destination_ip):
        """
        Forward the packet to King using raw sockets.
        
        Args:
            packet (bytes): The network packet to be forwarded.
            destination_ip (str): The IP address of King.
        """
        
        try:
            # Create a raw socket
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
                # Set IP header options if needed (e.g., TTL)
                # s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
                
                # Forward the packet directly
                s.sendto(packet, (destination_ip, 0))  # Port 0 is ignored for raw sockets
                
        except Exception as e:
            # Log any errors encountered during forwarding
            # logger.error(f"Failed to forward packet to King ({destination_ip}) - Error: {e}")
            pass


    async def process_packet_stream(self, packet_data, destination_ip):
        """
        Store packet and its protocol in buffer instead of processing immediately.
        
        Args:
            packet_data (bytes): The network packet data to store.   
        """

        if len(packet_data) < 20:
            return

        ip_header = packet_data[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        protocol = iph[6]

        if protocol not in (6, 17):
            return  # Ignore non-TCP and non-UDP packets

        # Convert the destination IP from binary to string format
        dest_ip = socket.inet_ntoa(iph[9])

        # Filter: Only process packets where the destination IP matches king_overlay_ip
        if dest_ip != destination_ip :
            return  # Ignore packets not originating from king_overlay_ip

        async with self._lock:
            self.packet_buffer.append((packet_data, protocol))  # Store tuple


    def extract_batch_features(self, packet_batch):
        """
        Extract features from a batch of packets.
        
        Args:
            packet_batch (bytes): The network packet buffer to process.

        Returns:
            np.array : output data sample with model input features.
        """

        if not packet_batch:
            return None

        # Initialize flow statistics
        flow_stats = defaultdict(lambda: {
            "tcp_syn_fwd_count": 0, "tcp_syn_bwd_count": 0,
            "fwd_packet_count": 0, "bwd_packet_count": 0,
            "unique_udp_source_ports": set(), "unique_udp_dest_ports": set(),
            "total_fwd_pkt_size": 0, "total_bwd_pkt_size": 0,
            "flow_packets_per_sec": 0, "flow_bytes_per_sec": 0,
            "source_ip_entropy": 0, "dest_port_entropy": 0
        })

        for packet_data, protocol in packet_batch:
            eth_protocol = struct.unpack('!H', packet_data[12:14])[0]
            if eth_protocol != 0x0800:  # Ignore non-IPv4 packets
                continue

            ip_header = struct.unpack('!BBHHHBBH4s4s', packet_data[14:34])
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dest_ip = socket.inet_ntoa(ip_header[9])

            if protocol not in (6, 17):  # Only process TCP/UDP packets
                continue

            key = (src_ip, dest_ip)
            entry = flow_stats[key]
            entry["fwd_packet_count"] += 1

            if protocol == 6:  # TCP
                tcp_header = struct.unpack('!HHLLBBHHH', packet_data[34:54])
                flags = tcp_header[5]
                pkt_size = len(packet_data)
                entry["total_fwd_pkt_size"] += pkt_size

                if flags & 0x02:  # SYN flag
                    entry["tcp_syn_fwd_count"] += 1

            elif protocol == 17:  # UDP
                udp_header = struct.unpack('!HHHH', packet_data[34:42])
                src_port, dest_port = udp_header[0], udp_header[1]
                pkt_size = len(packet_data)
                entry["total_fwd_pkt_size"] += pkt_size

                entry["unique_udp_source_ports"].add(src_port)
                entry["unique_udp_dest_ports"].add(dest_port)

        # Compute aggregated feature values
        tcp_syn_flag_ratio = (
            sum(e["tcp_syn_fwd_count"] + e["tcp_syn_bwd_count"] for e in flow_stats.values()) /
            (sum(e["fwd_packet_count"] + e["bwd_packet_count"] for e in flow_stats.values()) + 1e-6)
        )

        udp_port_entropy = sum(len(e["unique_udp_source_ports"]) * len(e["unique_udp_dest_ports"]) for e in flow_stats.values())

        avg_pkt_size = (
            sum(e["total_fwd_pkt_size"] + e["total_bwd_pkt_size"] for e in flow_stats.values()) /
            (2 * len(flow_stats) + 1e-6)
        )

        flow_density = sum(
            e["flow_packets_per_sec"] / (e["flow_bytes_per_sec"] + 1e-6)
            for e in flow_stats.values()
        )

        ip_entropy = sum(
            e["source_ip_entropy"] + e["dest_port_entropy"]
            for e in flow_stats.values()
        )

        return np.array([tcp_syn_flag_ratio, udp_port_entropy, avg_pkt_size, flow_density, ip_entropy])
    

    async def batch_processing_loop(self):
        """
        Process the buffered packets every `batch_interval` seconds.
        """

        try:
            while not self.stop_firewall_event.is_set():
                await asyncio.sleep(self.batch_interval)  # Wait for batch interval

                async with self._lock:
                    if not self.packet_buffer:
                        continue  # No packets to process

                    batch = self.packet_buffer[:]
                    self.packet_buffer.clear()

                # Extract batch-level features
                features = self.extract_batch_features(batch)

                # Predict whether batch is allowed
                is_allowed, label_type = self.is_allowed_batch(features)  
                
                # Forward or block the packets based on decision
                if is_allowed:
                    logger.info(f"Allowing batch of {len(batch)} packets...")
                    for packet_data, protocol in batch:  # Extract packet and protocol
                        await self.moat_forward_packet(packet_data, KING_OVERLAY_IP)
                else:
                    logger.info(f"Blocked {len(batch)} packets : {label_type} detected !")
                
        except Exception as e:
            logger.error(f"Error in batch processing: {e}")


    async def sniff_packets_stream(self, destination_ip, ifaces, stop_event=None):
        """
        Sniffs packets on multiple interfaces asynchronously.

        Args:
            destination_ip (str): The destination IP to filter packets.
            ifaces (list): List of network interfaces to sniff packets on.
        """

        tasks = [self._sniff_on_interface(destination_ip, iface, stop_event) for iface in ifaces]
        await asyncio.gather(*tasks)  # Run sniffing tasks concurrently

    async def _sniff_on_interface(self, destination_ip, iface, stop_event):
        """
        Sniffs packets and adds them to the buffer.
        
        Args:
            king_private_ip (str): The private IP of the King for batch packet forwarding.  
            iface (str, optional): The network interface to sniff packets on. Defaults to 'eth0'.
            stop_event (asyncio.Event, optional): An event to signal stopping the sniffing loop. 
                If provided, the function will exit when stop_event is set. Defaults to None.
        """
        
        logger.info(f"Sniffing packets going to {destination_ip} on interface {iface}")

        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind((iface, 0))
        raw_socket.setblocking(False)

        # Start batch processing immediately and ensure it's non-blocking
        asyncio.create_task(self.batch_processing_loop())  # Create task to run concurrently

        while not stop_event.is_set():
            ready, _, _ = select.select([raw_socket], [], [], 1)  # 1s timeout
            if ready:
                packet_data = raw_socket.recv(65535)
                await self.process_packet_stream(packet_data, destination_ip)

            await asyncio.sleep(0)  # Yield control back to the event loop to run other tasks (like batch_processing_loop)

        logger.info(f"Stopping packet sniffing on interface {iface}...")
        raw_socket.close()


    def predict_sample(self, sample_data):
        """
        Predicts whether a batch of packets should be allowed or blocked.
        
        Args:
            sample_data (np.ndarray): A 1D NumPy array representing the extracted features of a batch of packets.
        
        Returns:
            int | None: The predicted class label, which can be one of [-1, 0, 1, 2].
                - -1: UNKNOWN
                -  0: BENIGN
                -  1: UDP_FLOOD
                -  2: TCP_SYN_FLOOD
                
                Returns `None` if the prediction fails.
        """

        # Impute missing values
        sample_data_imputed = self._imputer.transform([sample_data])

        # Standardize the sample
        sample_data_scaled =self._scaler.transform(sample_data_imputed)

        # Predict using the model
        prediction = self._model.predict(sample_data_scaled)

        return prediction[0] if isinstance(prediction, np.ndarray) and len(prediction) > 0 else None

    def generate_ssh_key_pair(self) -> tuple[str, str]:
        """
        Generates a random RSA SSH key pair and returns the private and public keys as strings.

        Returns:
            tuple[str, str]: A tuple containing:
                - public_key_str (str): The generated SSH public key in OpenSSH format.
                - private_key_str (str): The generated RSA private key in PEM format.
        """

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Serialize private key
        private_key_str = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        # Serialize public key
        public_key = private_key.public_key()
        public_key_str = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode("utf-8")

        return public_key_str, private_key_str

    async def add_ssh_key_to_remote_machine(
        self,
        machine_ip: str,
        ssh_public_key: str,
        username: str,  # This is the user you connect as (e.g., 'borgg-vm' or 'root')
        initial_private_key_path: str = INITIAL_PK_PATH,
        target_user: str = RESTRICTED_USER,
        timeout: int = 5,
        retries: int = 3,
    ):
        """
        Asynchronously connects to a remote machine via SSH using asyncssh,
        generates an SSH key pair for the restriced user, adds the given SSH public key to the
        authorized_keys file, and updates sudoers for passwordless sudo access.

        Args:
            machine_ip (str): The public IP of the machine.
            ssh_public_key (str): The SSH public key to add to the remote machine.
            initial_private_key_path (str): Path to the initial private key used for SSH authentication.
            username (str): The username for the SSH connection (e.g., 'borgg-vm' or 'root').
            timeout (int, optional): Timeout in seconds for the SSH connection. Defaults to 5.
            retries (int, optional): Number of retry attempts in case of failure. Defaults to 3.
        """
        

        for attempt in range(retries):
            try:
                logger.info(f"Attempting SSH connection to {machine_ip} with user {username} (Attempt {attempt + 1}/{retries})...")

                connection_params = {
                    "host": machine_ip,
                    "username": username,
                    "client_keys": [initial_private_key_path],
                    "known_hosts": None,
                    "connect_timeout": timeout,
                }

                # Connect to the remote machine
                async with asyncssh.connect(**connection_params) as conn:
                    logger.info(f"✅ Successfully connected to {machine_ip} as {username}")

                    # Ensure .ssh directory exists and set proper permissions for the restricted user
                    commands = [
                        f"sudo mkdir -p /home/{target_user}/.ssh",
                        f"sudo chmod 700 /home/{target_user}/.ssh",
                        f"sudo touch /home/{target_user}/.ssh/authorized_keys",
                        f"sudo chmod 600 /home/{target_user}/.ssh/authorized_keys",
                        f"sudo chown -R {target_user}:{target_user} /home/{target_user}/.ssh"
                    ]
                    for cmd in commands:
                        await conn.run(cmd)

                    # Check if the public key already exists in authorized_keys
                    result = await conn.run(f"sudo cat /home/{target_user}/.ssh/authorized_keys", check=False)
                    authorized_keys = result.stdout.strip()

                    if ssh_public_key.strip() in authorized_keys:
                        logger.info(f"SSH key already exists on {machine_ip}.")
                    else:
                        # Add the new public key to authorized_keys
                        logger.info(f"Adding SSH key to {machine_ip}...")
                        await conn.run(f'sudo -u {target_user} sh -c \'echo "{ssh_public_key.strip()}" >> /home/{target_user}/.ssh/authorized_keys\'')

                        # Ensure correct permissions on authorized_keys
                        await conn.run(f"sudo chmod 600 /home/{target_user}/.ssh/authorized_keys")

                    # Update sudoers file for passwordless sudo for the restricted user
                    sudoers_entry = f"{target_user} ALL=(ALL) NOPASSWD: ALL"
                    logger.info(f"Updating sudoers file for user {target_user}...")
                    await conn.run(f'sudo echo "{sudoers_entry}" | sudo EDITOR="tee -a" visudo', check=False)

                    logger.info(f"Sudoers file updated on {machine_ip} for user {target_user}.")
                    await conn.run('sudo systemctl restart sudo || sudo echo "Skipping sudo restart"', check=False)

                    return  # Exit function on success

            except (asyncssh.Error, OSError) as e:
                logger.error(f"Error connecting to {machine_ip} on attempt {attempt+1}/{retries}: {e}")
                if attempt == retries - 1:
                    logger.error(f"Failed to connect to {machine_ip} after {retries} attempts.")

        return
    
async def clone_or_update_repository(
    machine_ip: str,
    github_token: str,
    username: str,
    initial_private_key_path: str = INITIAL_PK_PATH,
    repo_path: str = f"/home/{RESTRICTED_USER}/tensorprox",
    repo_url: str = "github.com/borgg-dev/tensorprox.git",
    branch: str = "tensorproxV3",
    sparse_folder: str = "tensorprox/core/immutable",
    timeout: int = 5,
    retries: int = 3,
):
    """
    Asynchronously connects to a remote machine via SSH using asyncssh,
    and either clones or updates a specific folder of a GitHub repository using sparse checkout.

    Args:
        machine_ip (str): The public IP of the machine.
        github_token (str): GitHub personal access token for authentication.
        repo_url (str): The GitHub repository URL.
        branch (str): The branch to clone or pull.
        initial_private_key_path (str): Path to the initial private key for SSH authentication.
        username (str): The username for the SSH connection.
        sparse_folder (str): The relative path of the folder to clone within the repository.
        timeout (int, optional): Timeout in seconds for the SSH connection. Defaults to 5.
        retries (int, optional): Number of retry attempts in case of failure. Defaults to 3.
    """
    for attempt in range(retries):
        try:
            logger.info(f"Attempting SSH connection to {machine_ip} with user {username} (Attempt {attempt + 1}/{retries})...")

            connection_params = {
                "host": machine_ip,
                "username": username,
                "client_keys": [initial_private_key_path],
                "known_hosts": None,
                "connect_timeout": timeout,
            }

            async with asyncssh.connect(**connection_params) as conn:
                logger.info(f"✅ Successfully connected to {machine_ip} as {username}")

                # Check if Git is installed
                try:
                    await conn.run("git --version", check=True)
                    logger.info(f"Git is already installed on {machine_ip}.")
                except asyncssh.ProcessError:
                    logger.warning(f"Git is not installed on {machine_ip}. Installing Git...")
                    install_git_command = "sudo apt-get update && sudo apt-get install -y git"
                    await conn.run(install_git_command, check=True)
                    logger.info(f"Git installation successful on {machine_ip}.")

                # Clone or update the repository with sparse checkout
                result = await conn.run(f"sudo test -d {repo_path}/.git", check=False)
                repo_exists = result.returncode == 0

                if repo_exists:
                    # Pull the latest changes
                    logger.info(f"Repository already exists at {repo_path} on {machine_ip}. Pulling latest changes...")
                    pull_command = (
                        f"sudo bash -c 'cd {repo_path} && "
                        f"git fetch origin {branch} && "
                        f"git checkout {branch} && "
                        f"git pull origin {branch}'"
                    )
                    result = await conn.run(pull_command, check=True)
                    logger.info(f"Repository updated successfully on {machine_ip}: {result.stdout}")
                else:
                    # Sparse checkout setup
                    logger.info(f"Setting up sparse checkout on {machine_ip} for folder '{sparse_folder}'...")
                    clone_commands = [
                        f"sudo mkdir -p {repo_path}",
                        f"sudo bash -c 'cd {repo_path} && git init'",
                        f"sudo bash -c 'cd {repo_path} && git remote add origin https://{github_token}@{repo_url}'",
                        f"sudo bash -c 'cd {repo_path} && git config core.sparseCheckout true'",
                        f"sudo bash -c 'echo \"{sparse_folder}\" | sudo tee {repo_path}/.git/info/sparse-checkout'",
                        f"sudo bash -c 'cd {repo_path} && git fetch origin {branch}'",
                        f"sudo bash -c 'cd {repo_path} && git checkout {branch}'",
                    ]

                    for command in clone_commands:
                        await conn.run(command, check=True)
                    
                    logger.info(f"Sparse checkout completed successfully on {machine_ip} for folder '{sparse_folder}'.")

                return  # Exit function on success

        except (asyncssh.Error, OSError) as e:
            logger.error(f"Error cloning/updating repository on attempt {attempt + 1}/{retries}: {e}")
            if attempt == retries - 1:
                logger.error(f"Failed after {retries} attempts.")

    return

async def clone_repositories(github_token: str, machines: List[tuple]):
    """
    This function clones or updates the repositories on the remote machines.
    """
    tasks = []
    for machine_ip, username in machines:
        tasks.append(clone_or_update_repository(
            machine_ip=machine_ip,
            github_token=github_token,
            username=username,
        ))

    # Run all cloning tasks concurrently and wait for them to complete
    await asyncio.gather(*tasks)


async def run_whitelist_setup(
    ip: str,
    private_key_path: str,
    username: str,
    remote_path: str = "/tmp/restrict.sh",
    local_script_path: str = os.path.join(BASE_DIR, "tensorprox/core/restrict.sh"),
    restricted_user: str = RESTRICTED_USER
):    
    """
    This function will execute the restrict.sh setup on the remote machine.
    It uploads the restrict.sh script, makes it executable, runs it, and then removes it.
    
    Args:
        ip (str): IP address of the remote machine.
        private_key_path (str): Path to the private SSH key for authentication.
        username (str): SSH username for the remote machine.
        remote_path (str): Path on the remote machine where the script will be uploaded (default is "/tmp/restrict.sh").
        
    Returns:
        result (str): The result of executing the restrict.sh script.
    """
    
    try:
        # Upload the whitelist script to the remote machine using SCP
        await send_file_via_scp(local_script_path, remote_path, ip, private_key_path, username)
        
        # Make the script executable and run it with the restricted user
        result = await ssh_connect_execute(
            ip, 
            private_key_path, 
            username, 
            f"chmod +x {remote_path} && bash {remote_path} {restricted_user} && rm -rf {remote_path}"
        )
        
        return result
    
    except Exception as e:
        # Handle any exceptions and return an error message
        return f"An error occurred: {str(e)}"

async def setup_machines(github_token: str, machines: List[tuple], initial_private_key_path: str = INITIAL_PK_PATH):
    """
    Set up repository cloning for multiple machines using their corresponding IPs and usernames.
    
    Args:
        ips (list): A list of IP addresses for the machines.
        github_token (str): GitHub personal access token.
        initial_private_key_path (str): Path to the private SSH key used for authentication.
        usernames (list): A list of usernames corresponding to each machine's IP.
    """
    
    logger.info("Starting Restricted User creation + files cloning ...")

    tasks = []

    for machine_ip, username in machines:
        tasks.append(run_whitelist_setup(machine_ip, initial_private_key_path, username))
    
    # Run all whitelist setup tasks concurrently and wait for them to complete
    setup_results = await asyncio.gather(*tasks)
    
    # If any whitelist setup fails, don't proceed with cloning
    if all(setup_results):
        logger.info("Whitelist setup successful on all machines, proceeding with cloning.")
        await clone_repositories(github_token, machines)
    else:
        logger.info("Whitelist setup failed on one or more machines, aborting cloning.")


        
def run_gre_setup():

    logger.info("Running GRE Setup...")
    
    try:
        # Performing GRE Setup before starting
        gre = GRESetup(node_type="moat")
        success = gre.moat(benign_private_ip=BENIGN_PRIVATE_IP, 
                    attacker_private_ip=ATTACKER_PRIVATE_IP, 
                    king_private_ip=KING_PRIVATE_IP)
        if success :
            logger.info("GRE setup successfully done.")
        else :
            logger.info("GRE setup failed.")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Error during GRE Setup: {e}")
        sys.exit(1)

if __name__ == "__main__":

    logger.info("Miner Instance started.")

    run_gre_setup()

    machines = [
        (BENIGN_PUBLIC_IP, BENIGN_USERNAME), 
        (ATTACKER_PUBLIC_IP, ATTACKER_USERNAME), 
        (KING_PUBLIC_IP, KING_USERNAME)
    ]
    
    github_token = ""
    
    # Run the repository cloning setup first, wait for it to complete
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        setup_machines(
            github_token,
            machines
        )
    )

    with Miner() as miner:
        while not miner.should_exit:
            miner.log_status()
            time.sleep(5)
        logger.warning("Ending miner...")