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
from tensorprox import settings
settings.settings = settings.Settings.load(mode="miner")
settings = settings.settings
import time
from loguru import logger
from tensorprox.base.miner import BaseMinerNeuron
from tensorprox.utils.logging import ErrorLoggingEvent, log_event
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse, MachineDetails
from tensorprox.utils.utils import *
from tensorprox.core.gre_setup import gre
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


class Miner(BaseMinerNeuron):
    """
    A class representing a miner node in the TensorProx network. 
    This node performs SSH key distribution to validators, packet inspection
    and firewall management for secure network access.
    """

    should_exit: bool = False
    moat_gre_setup_completed: bool = False
    firewall_active: bool = False
    firewall_thread: Thread = None
    stop_firewall_event: Event = Field(default_factory=Event)
    packet_buffer: List[Tuple[bytes, int]] = Field(default_factory=list)
    batch_interval: int = 10
    attacker_public_ip: str = os.environ.get("ATTACKER_PUBLIC_IP")
    benign_public_ip: str = os.environ.get("BENIGN_PUBLIC_IP")
    king_public_ip: str = os.environ.get("KING_PUBLIC_IP")
    attacker_overlay_ip: str = os.environ.get("ATTACKER_OVERLAY_IP")
    benign_overlay_ip: str = os.environ.get("BENIGN_OVERLAY_IP")
    king_overlay_ip: str = os.environ.get("KING_OVERLAY_IP")
    attacker_private_ip: str = os.environ.get("ATTACKER_PRIVATE_IP")
    benign_private_ip: str = os.environ.get("BENIGN_PRIVATE_IP")
    king_private_ip: str = os.environ.get("KING_PRIVATE_IP")
    moat_private_ip: str = os.environ.get("MOAT_PRIVATE_IP")
    forward_port: int = os.environ.get("FORWARD_PORT", 8080)
    attacker_iface: str = os.environ.get("ATTACKER_IFACE", "eth0")
    attacker_username: str = os.environ.get("ATTACKER_USERNAME", "root")
    benign_iface: str = os.environ.get("BENIGN_IFACE", "eth0")
    benign_username: str = os.environ.get("BENIGN_USERNAME", "root")
    king_iface: str = os.environ.get("KING_IFACE", "eth0")
    king_username: str = os.environ.get("KING_USERNAME", "root")
    moat_iface: str = os.environ.get("MOAT_IFACE", "eth0")
            
    _lock: asyncio.Lock = PrivateAttr()
    _model: DecisionTreeClassifier = PrivateAttr()
    _imputer: SimpleImputer = PrivateAttr()
    _scaler: StandardScaler = PrivateAttr()

    def __init__(self, **data):
        """Initializes the Miner neuron with necessary machine learning models and configurations."""

        super().__init__(**data)
        self._lock = asyncio.Lock()
        self._model = joblib.load("/home/borgg/tensorprox/model/decision_tree.pkl")
        self._imputer = joblib.load("/home/borgg/tensorprox/model/imputer.pkl")
        self._scaler = joblib.load("/home/borgg/tensorprox/model/scaler.pkl")


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
            synapse.machine_availabilities.machine_config["Attacker"] = MachineDetails(ip=self.attacker_public_ip, iface=self.attacker_iface, username=self.attacker_username)
            synapse.machine_availabilities.machine_config["Benign"] = MachineDetails(ip=self.benign_public_ip, iface=self.benign_iface, username=self.benign_username)
            synapse.machine_availabilities.machine_config["King"] = MachineDetails(ip=self.king_public_ip, iface=self.king_iface, username=self.king_username, private_ip=self.king_private_ip)
            synapse.machine_availabilities.machine_config["Moat"] = MachineDetails(private_ip=self.moat_private_ip)

            # Use the initial private key for initial connection
            initial_private_key_path = os.environ.get("PRIVATE_KEY_PATH")

            # Run SSH key addition in parallel
            tasks = [
                self.add_ssh_key_to_remote_machine(
                    machine_ip=machine_details.ip,
                    ssh_public_key=ssh_public_key,
                    initial_private_key_path=initial_private_key_path,
                    username=machine_details.username
                )
                for machine_name, machine_details in synapse.machine_availabilities.machine_config.items()
                if machine_name != "Moat"  # Skip Moat machine
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

        if not self.moat_gre_setup_completed:
            logger.warning("Moat GRE Setup is not finished yet. Cannot handle challenge.")
            return  # Don't proceed with the challenge handling if setup is not done

        try:
            # Extract challenge information from the synapse
            task = synapse.task
            state=synapse.state
            source_ip = os.environ.get("ATTACKER_IP")


            logger.debug(f"📧 Task {task} received from {synapse.dendrite.hotkey}. State : {state}.")

            if state == "GET_READY":
                if not self.firewall_active:
                    self.firewall_active = True
                    self.stop_firewall_event.clear()  # Reset stop event
                    # Start sniffing in a separate thread to avoid blocking
                    self.firewall_thread = Thread(target=self.run_packet_stream, args=(source_ip, self.moat_iface))
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
    
    
    def run_packet_stream(self, source_ip, iface="eth0"):
        """
        Runs the firewall sniffing logic in an asynchronous event loop.

        Args:
            king_private_ip (str): The private IP address of the King node to forward packets to.
            iface (str, optional): The network interface to sniff packets from. Defaults to "eth0".
        """

        loop = asyncio.new_event_loop()  # Create a new event loop for the sniffing thread
        asyncio.set_event_loop(loop)  # Set the new loop as the current one for this thread
        
        # Ensure that the sniffer doesn't block the main process
        loop.create_task(self.sniff_packets_stream(source_ip, iface, self.stop_firewall_event))
        loop.run_forever()  # Ensure the loop keeps running


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


    async def process_packet_stream(self, packet_data, source_ip):
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

        # Convert the source IP from binary to string format
        src_ip = socket.inet_ntoa(iph[8])

        # Filter: Only process packets where the source IP matches king_private_ip
        if src_ip != source_ip :
            return  # Ignore packets not originating from king_private_ip

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
                        await self.moat_forward_packet(packet_data, self.king_private_ip, int(self.forward_port), protocol)
                else:
                    logger.info(f"Blocked {len(batch)} packets : {label_type} detected !")
        except Exception as e:
            logger.error(f"Error in batch processing: {e}")


    async def sniff_packets_stream(self, source_ip, iface='eth0', stop_event=None):
        """
        Sniffs packets and adds them to the buffer.
        
        Args:
            king_private_ip (str): The private IP of the King for batch packet forwarding.  
            iface (str, optional): The network interface to sniff packets on. Defaults to 'eth0'.
            stop_event (asyncio.Event, optional): An event to signal stopping the sniffing loop. 
                If provided, the function will exit when stop_event is set. Defaults to None.
        """
        logger.info(f"Sniffing packets coming from {source_ip} on interface {iface}")

        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind((iface, 0))
        raw_socket.setblocking(False)

        # Start batch processing immediately and ensure it's non-blocking
        asyncio.create_task(self.batch_processing_loop())  # Create task to run concurrently

        while not stop_event.is_set():
            ready, _, _ = select.select([raw_socket], [], [], 1)  # 1s timeout
            if ready:
                packet_data = raw_socket.recv(65535)
                await self.process_packet_stream(packet_data, source_ip)

            await asyncio.sleep(0)  # Yield control back to the event loop to run other tasks (like batch_processing_loop)

        logger.info("Stopping packet sniffing...")
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
    
    def moat_gre_setup(self, benign_moat_key="77", attacker_moat_key="79", moat_king_key="88", gre_mtu=1465, ipip_mtu=1445):
        
        """Configure Moat node with enhanced acceleration and improved reliability"""
        # --- Begin robust error handling ---
        # Try to detect if a previous installation attempt was interrupted
        if os.path.exists("/var/lib/dpkg/lock-frontend") or os.path.exists("/var/lib/apt/lists/lock"):
            log("[INFO] Detected possible interrupted package installation, cleaning up...", level=1)
            
            # Kill any hanging dpkg/apt processes
            run_cmd(["pkill", "-f", "dpkg"], quiet=True)
            run_cmd(["pkill", "-f", "apt"], quiet=True)
            
            # Wait a moment for processes to terminate
            time.sleep(5)
            
            # Remove locks
            run_cmd(["rm", "-f", "/var/lib/dpkg/lock*"], quiet=True)
            run_cmd(["rm", "-f", "/var/lib/apt/lists/lock"], quiet=True)
            run_cmd(["rm", "-f", "/var/cache/apt/archives/lock"], quiet=True)
            
            # Fix interrupted dpkg
            run_cmd(["dpkg", "--configure", "-a"], quiet=True)
            
            # Update apt repository with resilience
            gre.update_apt_repositories()
        # --- End robust error handling ---
        
        # Auto-detect primary interface
        primary_interface, local_ip = gre.detect_primary_interface()
        if not primary_interface or not local_ip:
            log("[ERROR] Failed to detect primary interface", level=0)
            return False
        
        # Validate input IPs
        if not self.benign_private_ip or not self.king_private_ip:
            log("[ERROR] Both Benign and King IP addresses are required", level=0)
            return False
        
        log("[INFO] Setting up optimized Moat node with IP {0}".format(local_ip))
        log("[INFO] Connecting to Benign at {0} and King at {1}".format(self.benign_private_ip, self.king_private_ip))
        if self.attacker_private_ip:
            log("[INFO] Also connecting to Attacker at {0}".format(self.attacker_private_ip))
        
        # Detect system capabilities and calculate resource allocation
        # Moat node needs more resources as it's the central router
        capabilities = gre.detect_system_capabilities()
        resource_plan = gre.calculate_resource_allocation(capabilities, "moat")
        
        # Install AF_XDP dependencies
        gre.install_afxdp_dependencies()
        
        # Optimize kernel parameters
        gre.optimize_kernel_params()
        
        # Clean up existing interfaces
        for dev in ["gre-benign", "gre-king", "gre-attacker", "ipip-to-king"]:
            gre.flush_device(dev)
        
        # Clean any existing policy routing
        gre.clean_policy_routing()
        
        # 1. Create GRE tunnel to Benign
        run_cmd(["ip", "tunnel", "add", "gre-benign", "mode", "gre", 
                "local", local_ip, "remote", self.benign_private_ip, "ttl", "inherit", 
                "key", benign_moat_key], check=True)
        
        run_cmd(["ip", "link", "set", "gre-benign", "mtu", str(gre_mtu)])
        run_cmd(["ip", "addr", "add", "192.168.100.2/30", "dev", "gre-benign"])
        run_cmd(["ip", "link", "set", "gre-benign", "up"])
        
        # Apply tunnel-specific optimizations
        gre.optimize_tunnel_interface("gre-benign")
        
        # 2. Create GRE tunnel to King
        run_cmd(["ip", "tunnel", "add", "gre-king", "mode", "gre", 
                "local", local_ip, "remote", self.king_private_ip, "ttl", "inherit", 
                "key", moat_king_key], check=True)
        
        run_cmd(["ip", "link", "set", "gre-king", "mtu", str(gre_mtu)])
        run_cmd(["ip", "addr", "add", "192.168.101.1/30", "dev", "gre-king"])
        run_cmd(["ip", "link", "set", "gre-king", "up"])
        
        # Apply tunnel-specific optimizations
        gre.optimize_tunnel_interface("gre-king")
        
        # 3. Create IPIP tunnel to King
        run_cmd(["ip", "tunnel", "add", "ipip-to-king", "mode", "ipip", 
                "local", "192.168.101.1", "remote", "192.168.101.2", 
                "ttl", "inherit"], check=True)
        
        run_cmd(["ip", "link", "set", "ipip-to-king", "mtu", str(ipip_mtu)])
        run_cmd(["ip", "link", "set", "ipip-to-king", "up"])
        
        # Apply tunnel-specific optimizations
        gre.optimize_tunnel_interface("ipip-to-king")
        
        # 4. Create GRE tunnel to Attacker if provided
        if self.attacker_private_ip:
            run_cmd(["ip", "tunnel", "add", "gre-attacker", "mode", "gre", 
                    "local", local_ip, "remote", self.attacker_private_ip, "ttl", "inherit", 
                    "key", attacker_moat_key], check=True)
            
            run_cmd(["ip", "link", "set", "gre-attacker", "mtu", str(gre_mtu)])
            run_cmd(["ip", "addr", "add", "192.168.102.2/30", "dev", "gre-attacker"])
            run_cmd(["ip", "link", "set", "gre-attacker", "up"])
            
            # Apply tunnel-specific optimizations
            gre.optimize_tunnel_interface("gre-attacker")
        
        # 5. Set up routing for overlay IPs
        run_cmd(["ip", "route", "add", self.benign_overlay_ip, "via", "192.168.100.1", "dev", "gre-benign", "metric", "100"])
        run_cmd(["ip", "route", "add", self.king_overlay_ip, "via", "192.168.101.2", "dev", "gre-king", "metric", "100"])
        
        if self.attacker_private_ip:
            run_cmd(["ip", "route", "add", self.attacker_overlay_ip, "via", "192.168.102.1", "dev", "gre-attacker", "metric", "100"])
        
        # 6. Create policy routing tables for different directions
        # Table 100: Benign → King
        run_cmd(["ip", "rule", "add", "iif", "gre-benign", "lookup", "100", "pref", "100"])
        run_cmd(["ip", "route", "add", self.king_overlay_ip, "via", "192.168.101.2", "dev", "gre-king", "table", "100"])
        run_cmd(["ip", "route", "add", "10.0.0.0/8", "via", "192.168.101.2", "dev", "gre-king", "table", "100"])
        
        # Table 101: King → Benign/Attacker
        run_cmd(["ip", "rule", "add", "iif", "gre-king", "lookup", "101", "pref", "101"])
        run_cmd(["ip", "route", "add", self.benign_overlay_ip, "via", "192.168.100.1", "dev", "gre-benign", "table", "101"])
        # Add broad route for 10.200.77.0/24 network (for dynamic IPs on Benign)
        run_cmd(["ip", "route", "add", "10.200.77.0/24", "via", "192.168.100.1", "dev", "gre-benign", "table", "101"])
        
        if self.attacker_private_ip:
            # Add route for Attacker in king->x table
            run_cmd(["ip", "route", "add", self.attacker_overlay_ip, "via", "192.168.102.1", "dev", "gre-attacker", "table", "101"])
            # Add broad route for 10.200.77.0/24 network (for dynamic IPs on Attacker too)
            run_cmd(["ip", "route", "add", "10.200.77.128/25", "via", "192.168.102.1", "dev", "gre-attacker", "table", "101"])
            
            # Table 102: Attacker → King
            run_cmd(["ip", "rule", "add", "iif", "gre-attacker", "lookup", "102", "pref", "102"])
            run_cmd(["ip", "route", "add", self.king_overlay_ip, "via", "192.168.101.2", "dev", "gre-king", "table", "102"])
            run_cmd(["ip", "route", "add", "10.0.0.0/8", "via", "192.168.101.2", "dev", "gre-king", "table", "102"])
        
        # Table 103: Catch-all for any 10.0.0.0/8 traffic from any tunnel interface
        run_cmd(["ip", "rule", "add", "from", "10.0.0.0/8", "lookup", "103", "pref", "110"])
        run_cmd(["ip", "rule", "add", "to", "10.0.0.0/8", "lookup", "103", "pref", "111"])
        run_cmd(["ip", "route", "add", self.king_overlay_ip, "via", "192.168.101.2", "dev", "gre-king", "table", "103"])
        run_cmd(["ip", "route", "add", self.benign_overlay_ip, "via", "192.168.100.1", "dev", "gre-benign", "table", "103"])
        if self.attacker_private_ip:
            run_cmd(["ip", "route", "add", self.attacker_overlay_ip, "via", "192.168.102.1", "dev", "gre-attacker", "table", "103"])
        
        # 7. Set up enhanced acceleration for the moat node (central router)
        gre.setup_enhanced_acceleration("moat", "gre-benign", resource_plan)
        
        # 8. Allow ICMP traffic for testing
        run_cmd(["iptables", "-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"])
        run_cmd(["iptables", "-A", "OUTPUT", "-p", "icmp", "-j", "ACCEPT"])
        run_cmd(["iptables", "-A", "FORWARD", "-p", "icmp", "-j", "ACCEPT"])
        
        log("[INFO] Moat node setup complete with enhanced acceleration", level=1)
        log("[INFO] Supporting dynamic IPs in 10.0.0.0/8 subnet for Benign/Attacker", level=1)
        
        # Log resource allocation for performance monitoring
        log(f"[INFO] MOAT node using {resource_plan['dpdk_cores']} DPDK cores, {resource_plan['hugepages_gb']}GB hugepages", level=0)
        log(f"[INFO] CPU mask: {resource_plan['cpu_mask']}, socket memory: {resource_plan['socket_mem']}", level=0)
        
        return True


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
        initial_private_key_path: str,
        username: str,
        timeout: int = 5,
        retries: int = 3,
    ):
        """
        Asynchronously connects to a remote machine via SSH using asyncssh,
        appends the given SSH public key to the authorized_keys file, and updates sudoers.

        Args:
            machine_ip (str): The public IP of the machine.
            ssh_public_key (str): The SSH public key to add to the remote machine.
            initial_private_key_path (str): Path to the initial private key used for SSH authentication.
            username (str): The username for the SSH connection.
            timeout (int, optional): Timeout in seconds for the SSH connection. Defaults to 5.
            retries (int, optional): Number of retry attempts in case of failure. Defaults to 3.
        """

        prefix_path = f"/root" if username == "root" else f"/home/{username}"

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


                # Add password or private key based on what's provided
                connection_params["client_keys"] = [initial_private_key_path]

                async with asyncssh.connect(**connection_params) as conn:

                    logger.info(f"✅ Successfully connected to {machine_ip} as {username}")

                    # Ensure .ssh directory exists
                    commands = [
                        f"mkdir -p {prefix_path}/.ssh",
                        f"chmod 700 {prefix_path}/.ssh",
                        f"touch {prefix_path}/.ssh/authorized_keys",
                        f"chmod 600 {prefix_path}/.ssh/authorized_keys",
                        f"chown -R {username}:{username} {prefix_path}/.ssh"
                    ]
                    for cmd in commands:
                        await conn.run(cmd)

                    # Check if the public key already exists
                    result = await conn.run(f"cat {prefix_path}/.ssh/authorized_keys", check=False)
                    authorized_keys = result.stdout.strip()

                    if ssh_public_key.strip() in authorized_keys:
                        logger.info(f"SSH key already exists on {machine_ip}.")
                    else:
                        # Add the new public key
                        logger.info(f"Adding SSH key to {machine_ip}...")
                        await conn.run(f'echo "{ssh_public_key.strip()}" >> {prefix_path}/.ssh/authorized_keys')

                        # Ensure correct permissions again
                        await conn.run(f"chmod 600 {prefix_path}/.ssh/authorized_keys")

                    # Update sudoers file for passwordless sudo
                    sudoers_entry = f"{username} ALL=(ALL) NOPASSWD: ALL"
                    logger.info(f"Updating sudoers file for user {username}...")
                    await conn.run(f'echo "{sudoers_entry}" | sudo EDITOR="tee -a" visudo', check=False)

                    logger.info(f"Sudoers file updated on {machine_ip} for user {username}.")
                    await conn.run('sudo systemctl restart sudo || echo "Skipping sudo restart"', check=False)

                    return  # Exit function on success

            except (asyncssh.Error, OSError) as e:
                logger.error(f"Error connecting to {machine_ip} on attempt {attempt+1}/{retries}: {e}")
                if attempt == retries - 1:
                    logger.error(f"Failed to connect to {machine_ip} after {retries} attempts.")

        return


if __name__ == "__main__":
    with Miner() as miner:

        logger.info("Miner Instance started. Running GRE Setup...")

        #Performing GRE Setup before starting 
        miner.moat_gre_setup()

        while not miner.should_exit:
            miner.log_status()
            time.sleep(5)
        logger.warning("Ending miner...")