# ruff: noqa: E402
import os, sys
sys.path.append(os.path.expanduser("~/tensorprox"))
import os
import paramiko
from tensorprox import settings
settings.settings = settings.Settings.load(mode="miner")
settings = settings.settings
import time
from loguru import logger
from tensorprox.base.miner import BaseMinerNeuron
from tensorprox.utils.logging import ErrorLoggingEvent, log_event
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse, MachineDetails
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
from sklearn.tree import DecisionTreeClassifier  # Add this import


NEURON_STOP_ON_FORWARD_EXCEPTION: bool = False


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
    batch_interval: int = 1
    
    # Private attributes
    _lock: asyncio.Lock = PrivateAttr()
    _model: DecisionTreeClassifier = PrivateAttr()
    _imputer: Any = PrivateAttr()
    _scaler: Any = PrivateAttr()

    def __init__(self, **data):
        """
        Initializes the Miner neuron with necessary machine learning models and configurations.
        """
        super().__init__(**data)
        self._lock = asyncio.Lock()  # Now safely initialized

        # Load models during initialization
        self._model = joblib.load("/home/azureuser/tensorprox/model/decision_tree_model.pkl")
        self._imputer = joblib.load("/home/azureuser/tensorprox/model/imputer.pkl")
        self._scaler = joblib.load("/home/azureuser/tensorprox/model/scaler.pkl")

    def forward(self, synapse: PingSynapse) -> PingSynapse:
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
            attacker_username = os.environ.get("ATTACKER_USERNAME")
            benign_username = os.environ.get("BENIGN_USERNAME")
            king_username = os.environ.get("KING_USERNAME")
            
            synapse.machine_availabilities.key_pair = (ssh_public_key, ssh_private_key)
            synapse.machine_availabilities.machine_config["Attacker"] = MachineDetails(ip=os.environ.get("ATTACKER_IP"), username=attacker_username)
            synapse.machine_availabilities.machine_config["Benign"] = MachineDetails(ip=os.environ.get("BENIGN_IP"), username=benign_username)
            synapse.machine_availabilities.machine_config["King"] = MachineDetails(ip=os.environ.get("KING_IP"), username=king_username, private_ip=os.environ.get("KING_PRIVATE_IP"))
            synapse.machine_availabilities.machine_config["Moat"] = MachineDetails(private_ip=os.environ.get("MOAT_PRIVATE_IP"))

            
            # Use the initial private key for initial connection
            initial_private_key_path = os.environ.get("PRIVATE_KEY_PATH")

            # Add the public key to each machine
            for machine_name, machine_details in synapse.machine_availabilities.machine_config.items():
                if machine_name == "Moat":
                    continue  # Skip the Moat machine
                machine_ip = machine_details.ip
                machine_username = machine_details.username
                logger.debug(f"Adding SSH key to {machine_name} at IP {machine_ip}")
                self.add_ssh_key_to_remote_machine(
                    machine_ip=machine_ip,
                    ssh_public_key=ssh_public_key,
                    initial_private_key_path=initial_private_key_path,
                    username=machine_username,
                )

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
            king_private_ip = os.environ.get("KING_PRIVATE_IP")

            logger.debug(f"📧 Task {task} received from {synapse.dendrite.hotkey}. State : {state}.")

            if state == "GET_READY":
                if not self.firewall_active:
                    self.firewall_active = True
                    self.stop_firewall_event.clear()  # Reset stop event
                    # Start sniffing in a separate thread to avoid blocking
                    self.firewall_thread = Thread(target=self.run_packet_stream, args=(king_private_ip,))
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
        """
        prediction = self.predict_sample(features)  # Get prediction

        # Check if the prediction is 1 or 2
        if prediction in [1, 2]:
            return False  #Block packets

        return True  #Allow packets
    
    def run_packet_stream(self, king_private_ip, iface="eth0"):
        """Runs the firewall sniffing logic until stop event is set."""
        loop = asyncio.new_event_loop()  # Create a new event loop for the sniffing thread
        asyncio.set_event_loop(loop)  # Set the new loop as the current one for this thread
        
        # Ensure that the sniffer doesn't block the main process
        loop.create_task(self.sniff_packets_stream(king_private_ip, iface, self.stop_firewall_event))
        loop.run_forever()  # Ensure the loop keeps running

    # Moat logic: intercepts and forwards packets to King
    async def moat_forward_packet(self, packet, destination_ip, destination_port, protocol):
        """
        Forward the packet to King based on its protocol (TCP/UDP).
        
        Args:
            packet (bytes): The network packet to be forwarded.
            destination_ip (str): The IP address of King.
            destination_port (int): The port number of King.
            protocol (int): The protocol identifier (6 for TCP, 17 for UDP).
        """
        try:
            if protocol == 6:  # TCP protocol
                # Create a TCP socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((destination_ip, destination_port))  # Establish connection
                    s.sendall(packet)  # Send the full packet

            elif protocol == 17:  # UDP protocol
                # Create a UDP socket
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(packet, (destination_ip, destination_port))  # Send the packet

        except Exception as e:
            # Log any errors encountered during forwarding
            # logger.error(f"Failed to forward packet to King ({destination_ip}:{destination_port}) - Error: {e}")
            pass

    # Sniff packets in a streamed manner and forward to Moat for processing
    async def process_packet_stream(self, packet_data, king_private_ip):
        """
        Store packet and its protocol in buffer instead of processing immediately.
        
        Args:
            packet_data (bytes): The network packet data to store.   
        """
        eth_header = packet_data[0:14]
        eth_protocol = struct.unpack('!H', eth_header[12:14])[0]

        if eth_protocol != 0x0800:
            return  # Ignore non-IPv4 packets

        ip_header = packet_data[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        protocol = iph[6]

        if protocol not in (6, 17):
            return  # Ignore non-TCP and non-UDP packets

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

    async def batch_processing_loop(self, king_private_ip):
        """
        Process the buffered packets every `batch_interval` seconds.
        
        Args:
            king_private_ip (str): The private IP of the King for batch packets forwarding.  
        """
        try:
            while not self.stop_firewall_event.is_set():
                await asyncio.sleep(self.batch_interval)  # Wait for batch interval

                async with self._lock:
                    if not self.packet_buffer:
                        continue  # No packets to process

                    batch = self.packet_buffer[:]
                    self.packet_buffer.clear()

                logger.info(f"Processing batch of {len(batch)} packets...")

                # Extract batch-level features
                features = self.extract_batch_features(batch)

                # Predict whether batch is allowed
                is_allowed = self.is_allowed_batch(features)  

                # Forward or block the packets based on decision
                if is_allowed:
                    for packet_data, protocol in batch:  # Extract packet and protocol
                        await self.moat_forward_packet(packet_data, king_private_ip, 8080, protocol)
                else:
                    logger.info(f"Blocked {len(batch)} packets")
        except Exception as e:
            logger.error(f"Error in batch processing: {e}")

    # Function to continuously sniff packets and handle them in a stream
    async def sniff_packets_stream(self, king_private_ip, iface='eth0', stop_event=None):
        """
        Sniffs packets and adds them to the buffer.
        
        Args:
            king_private_ip (str): The private IP of the King for batch packet forwarding.  
            iface (str, optional): The network interface to sniff packets on. Defaults to 'eth0'.
            stop_event (asyncio.Event, optional): An event to signal stopping the sniffing loop. 
                If provided, the function will exit when stop_event is set. Defaults to None.
        """
        logger.info(f"Sniffing packets for King Private IP: {king_private_ip} on interface {iface}")

        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind((iface, 0))
        raw_socket.setblocking(False)

        # Start batch processing immediately and ensure it's non-blocking
        asyncio.create_task(self.batch_processing_loop(king_private_ip))  # Create task to run concurrently

        while not stop_event.is_set():
            ready, _, _ = select.select([raw_socket], [], [], 1)  # 1s timeout
            if ready:
                packet_data = raw_socket.recv(65535)
                await self.process_packet_stream(packet_data, king_private_ip)

            await asyncio.sleep(0)  # Yield control back to the event loop to run other tasks (like batch_processing_loop)

        logger.info("Stopping packet sniffing...")
        raw_socket.close()


    # Perform ddos detection on a single batch of packets
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


    def add_ssh_key_to_remote_machine(
        self,
        machine_ip: str,
        ssh_public_key: str,
        initial_private_key_path: str,
        username: str,
        timeout: int = 5,
        retries: int = 3,
    ):
        """
        Connects to a remote machine via SSH using the initial private key, appends the given SSH public key 
        to the authorized_keys file if it does not already exist, and updates the sudoers file for passwordless sudo.
        Includes a retry mechanism in case of failure.

        Args:
            machine_ip (str): The Public IP of the machine.
            ssh_public_key (str): The SSH public key to add to the remote machine's authorized_keys file.
            initial_private_key_path (str): Path to the initial private key used for SSH authentication.
            username (str): The username for the SSH connection.
            timeout (int, optional): Timeout in seconds for the SSH connection. Defaults to 5.
            retries (int, optional): Number of retry attempts in case of failure. Defaults to 3.
   
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        prefix_path = f"/root" if username == "root" else f"/home/{username}"
        
        attempt = 0
        while attempt < retries:
            try:
                logger.info(f"Connecting to {machine_ip} using initial private key at {initial_private_key_path}...")

                #Connect using the private key
                ssh.connect(machine_ip, username=username, key_filename=initial_private_key_path, timeout=timeout)

                #Ensure the .ssh directory exists
                commands = [
                    f"mkdir -p {prefix_path}/.ssh",
                    f"chmod 700 {prefix_path}/.ssh",
                    f"touch {prefix_path}/.ssh/authorized_keys",
                    f"chmod 600 {prefix_path}/.ssh/authorized_keys",
                    f"chown -R {username}:{username} {prefix_path}/.ssh"
                ]
                for cmd in commands:
                    ssh.exec_command(cmd)

                #Check if the public key already exists
                stdin, stdout, stderr = ssh.exec_command(f"cat {prefix_path}/.ssh/authorized_keys")
                authorized_keys = stdout.read().decode().strip()

                if ssh_public_key.strip() in authorized_keys:
                    logger.info(f"SSH key already exists on {machine_ip}.")
                else:
                    #Add the new public key
                    logger.info(f"Adding SSH key to {machine_ip}...")
                    stdin, stdout, stderr = ssh.exec_command(f'echo "{ssh_public_key.strip()}" >> {prefix_path}/.ssh/authorized_keys')
                    error = stderr.read().decode().strip()
                    if error:
                        logger.error(f"Error adding SSH key: {error}")
                    else:
                        logger.info(f"SSH key successfully added to {machine_ip}.")
                    
                    # Ensure correct permissions again
                    ssh.exec_command(f"chmod 600 {prefix_path}/.ssh/authorized_keys")

                #Update sudoers file for passwordless sudo
                sudoers_entry = f"{username} ALL=(ALL) NOPASSWD: ALL"
                logger.info(f"Updating sudoers file for user {username}...")
                stdin, stdout, stderr = ssh.exec_command(f'echo "{sudoers_entry}" | sudo EDITOR="tee -a" visudo')
                err = stderr.read().decode().strip()
                if err:
                    logger.error(f"Error updating sudoers file: {err}")
                else:
                    logger.info(f"Sudoers file updated on {machine_ip} for user {username}.")
                    ssh.exec_command('sudo systemctl restart sudo || echo "Skipping sudo restart"')

                break  # Exit loop if successful

            except paramiko.ssh_exception.SSHException as e:
                attempt += 1
                logger.error(f"Error while connecting to {machine_ip} on attempt {attempt}/{retries}: {e}")
                if attempt == retries:
                    logger.error(f"Failed to connect to {machine_ip} after {retries} attempts.")

            except socket.error as e:
                logger.error(f"Network error while connecting to {machine_ip}: {e}")
                if attempt == retries:
                    logger.error(f"Failed to connect to {machine_ip} after {retries} attempts.")

            finally:
                ssh.close()

if __name__ == "__main__":
    with Miner() as miner:
        while not miner.should_exit:
            miner.log_status()
            time.sleep(5)
        logger.warning("Ending miner...")