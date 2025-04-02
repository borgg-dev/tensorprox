#!/usr/bin/env python3
"""
DDoS Detector for TensorProx

This module provides DDoS detection capabilities, receiving sampled packets from the XDP program
via AF_XDP sockets, extracting features, and using ML models to detect attack patterns.
"""

import os
import time
import threading
import socket
import struct
import select
import queue
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any, Set
from datetime import datetime
import numpy as np
from loguru import logger

# Import feature extractor
from tensorprox.core.ddos.detector.feature_extractor import FeatureExtractor
from tensorprox.core.ddos.config.config_manager import ConfigManager

# Try to import AF_XDP support if available
try:
    import ctypes
    import resource
    from bcc import XSKMap, BPF
    
    # Try to import xdp_tools if available
    try:
        import xdp_tools
        from xdp_tools import libxdp
        HAVE_LIBXDP = True
    except ImportError:
        HAVE_LIBXDP = False
    
    HAVE_AFXDP = True
except ImportError:
    HAVE_AFXDP = False
    logger.warning("AF_XDP support not available, falling back to raw sockets")

class DDoSDetector:
    """
    Detector for L3/L4 DDoS attacks, using ML models to analyze network traffic patterns.
    """
    
    def __init__(self, config_manager: ConfigManager, bpf_loader=None):
        """
        Initialize the DDoS detector.
        
        Args:
            config_manager: Configuration manager instance
            bpf_loader: BPF loader instance for XDP interaction (optional)
        """
        self.config_manager = config_manager
        self.bpf_loader = bpf_loader
        
        # Initialize components
        self.feature_extractor = FeatureExtractor()
        self.running = False
        self.threads = []
        self.packet_queue = queue.Queue(maxsize=100000)  # Buffer up to 100K packets
        self.batch_interval = config_manager.get_config("detection", "batch_interval", default=10)
        self.detection_threshold = config_manager.get_config("detection", "threshold", default=0.7)
        
        # Initialize thread synchronization
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        
        # State tracking
        self.active_sockets = {}  # Interface -> socket mapping
        self.flow_cache = {}      # Flow key -> verdict cache
        self.detected_attacks = {}  # Attack ID -> attack details
        self.last_batch_time = time.time()
    
    def start(self):
        """
        Start the DDoS detector.
        
        Returns:
            True if started successfully, False otherwise
        """
        with self._lock:
            if self.running:
                logger.warning("DDoS Detector is already running")
                return True
            
            self._stop_event.clear()
            self.running = True
            
            try:
                # Start packet processing thread
                processor_thread = threading.Thread(
                    target=self._packet_processor_thread,
                    name="DDoSDetector-Processor"
                )
                processor_thread.daemon = True
                processor_thread.start()
                self.threads.append(processor_thread)
                
                # Start sniffing threads for configured interfaces
                interfaces = self.config_manager.get_config("detector", "interfaces", default=[])
                if not interfaces:
                    logger.warning("No interfaces configured for packet sniffing, using default")
                    interfaces = ["gre-benign", "gre-attacker"]
                
                for interface in interfaces:
                    self._start_sniffing(interface)
                
                logger.info(f"DDoS Detector started (batch interval: {self.batch_interval}s)")
                return True
            
            except Exception as e:
                logger.exception(f"Failed to start DDoS Detector: {e}")
                self.stop()
                return False
    
    def _start_sniffing(self, interface: str):
        """
        Start packet sniffing on an interface.
        
        Args:
            interface: Network interface to sniff packets on
        """
        # Try to use AF_XDP if available
        if HAVE_AFXDP and self.bpf_loader:
            logger.info(f"Starting AF_XDP sniffing on {interface}")
            
            try:
                # Set up AF_XDP socket
                # This is a placeholder for the actual AF_XDP setup
                # In a real implementation, this would register with the XDP program
                
                # For now, we'll use raw sockets as a fallback
                self._start_raw_socket_sniffing(interface)
                
            except Exception as e:
                logger.error(f"Failed to set up AF_XDP for {interface}: {e}")
                logger.info(f"Falling back to raw socket for {interface}")
                self._start_raw_socket_sniffing(interface)
        else:
            # Use raw sockets as fallback
            self._start_raw_socket_sniffing(interface)
    
    def _start_raw_socket_sniffing(self, interface: str):
        """
        Start packet sniffing using raw sockets.
        
        Args:
            interface: Network interface to sniff packets on
        """
        logger.info(f"Starting raw socket sniffing on {interface}")
        
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((interface, 0))
            sock.setblocking(False)
            
            # Store socket
            self.active_sockets[interface] = sock
            
            # Start sniffing thread
            sniffer_thread = threading.Thread(
                target=self._raw_socket_sniffer_thread,
                args=(interface, sock),
                name=f"DDoSDetector-Sniffer-{interface}"
            )
            sniffer_thread.daemon = True
            sniffer_thread.start()
            self.threads.append(sniffer_thread)
            
            logger.info(f"Raw socket sniffing started on {interface}")
            
        except Exception as e:
            logger.exception(f"Failed to start raw socket sniffing on {interface}: {e}")
    
    def _raw_socket_sniffer_thread(self, interface: str, sock: socket.socket):
        """
        Thread function for sniffing packets using raw sockets.
        
        Args:
            interface: Network interface being sniffed
            sock: Raw socket for packet capture
        """
        logger.debug(f"Raw socket sniffer thread started for {interface}")
        
        try:
            while not self._stop_event.is_set():
                # Wait for data with timeout
                readable, _, _ = select.select([sock], [], [], 0.1)
                
                if not readable:
                    continue
                
                # Read packet
                packet_data = sock.recv(65535)
                
                # Check for IP packet
                eth_length = 14
                if len(packet_data) <= eth_length:
                    continue
                
                # Check for IPv4 (0x0800)
                eth_protocol = socket.ntohs(struct.unpack('!H', packet_data[12:14])[0])
                if eth_protocol != 0x0800:
                    continue
                
                # Process IP packet
                try:
                    self.packet_queue.put((interface, packet_data[eth_length:]), block=False)
                except queue.Full:
                    # Queue is full, log a warning and continue
                    if time.time() - self.last_queue_warning > 5:  # Only log every 5 seconds
                        logger.warning("Packet queue is full, dropping packets")
                        self.last_queue_warning = time.time()
        
        except Exception as e:
            if not self._stop_event.is_set():
                logger.exception(f"Error in raw socket sniffer for {interface}: {e}")
        
        finally:
            logger.debug(f"Raw socket sniffer thread for {interface} exiting")
    
    def _packet_processor_thread(self):
        """Thread function for processing captured packets and detecting attacks."""
        logger.debug("Packet processor thread started")
        
        batch_packets = []
        last_batch_time = time.time()
        self.last_queue_warning = 0
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Get a packet with timeout
                    try:
                        interface, packet_data = self.packet_queue.get(timeout=0.1)
                        batch_packets.append((interface, packet_data))
                    except queue.Empty:
                        pass
                    
                    # Check if it's time to process the batch
                    current_time = time.time()
                    if (current_time - last_batch_time >= self.batch_interval and batch_packets) or \
                       len(batch_packets) >= 10000:  # Also process if we have a lot of packets
                        
                        # Process the batch
                        self._process_packet_batch(batch_packets)
                        
                        # Reset the batch
                        batch_packets = []
                        last_batch_time = current_time
                
                except Exception as e:
                    logger.exception(f"Error processing packet batch: {e}")
                    # Reset the batch to avoid cascading errors
                    batch_packets = []
                    last_batch_time = time.time()
        
        except Exception as e:
            if not self._stop_event.is_set():
                logger.exception(f"Error in packet processor thread: {e}")
        
        finally:
            logger.debug("Packet processor thread exiting")
    
    def _process_packet_batch(self, batch_packets: List[Tuple[str, bytes]]):
        """
        Process a batch of packets for attack detection.
        
        Args:
            batch_packets: List of (interface, packet_data) tuples
        """
        if not batch_packets:
            return
        
        logger.debug(f"Processing batch of {len(batch_packets)} packets")
        
        try:
            # Extract features from the packet batch
            features = self.feature_extractor.extract_features(batch_packets)
            
            if features is not None:
                # Make prediction
                is_attack, attack_type, confidence = self.feature_extractor.is_attack(features)
                
                if is_attack and confidence >= self.detection_threshold:
                    # Attack detected, trigger mitigation
                    logger.warning(f"DDoS attack detected: {attack_type} (confidence: {confidence:.2f})")
                    
                    # Extract source IPs for potential mitigation
                    source_ips = self._extract_source_ips(batch_packets)
                    
                    # Record the attack
                    attack_id = f"{attack_type}_{int(time.time())}"
                    self.detected_attacks[attack_id] = {
                        "type": attack_type,
                        "confidence": confidence,
                        "timestamp": datetime.now().isoformat(),
                        "packet_count": len(batch_packets),
                        "source_ips": list(source_ips),
                        "features": features.tolist()
                    }
                    
                    # Trigger mitigation callback
                    self._on_attack_detected(attack_id, attack_type, confidence, source_ips, features)
                else:
                    logger.debug(f"No attack detected in batch (confidence: {confidence:.2f if confidence else 0})")
        
        except Exception as e:
            logger.exception(f"Error processing packet batch: {e}")
    
    def _extract_source_ips(self, batch_packets: List[Tuple[str, bytes]]) -> Set[str]:
        """
        Extract unique source IPs from a batch of packets.
        
        Args:
            batch_packets: List of (interface, packet_data) tuples
        
        Returns:
            Set of unique source IP addresses
        """
        source_ips = set()
        
        for _, packet_data in batch_packets:
            # Skip packets that are too short
            if len(packet_data) < 20:
                continue
            
            # Extract source IP
            try:
                src_ip = socket.inet_ntoa(packet_data[12:16])
                source_ips.add(src_ip)
            except:
                pass
        
        return source_ips
    
    def _on_attack_detected(self, attack_id: str, attack_type: str, confidence: float, 
                           source_ips: Set[str], features: np.ndarray):
        """
        Handle attack detection by triggering mitigation.
        
        Args:
            attack_id: Unique identifier for the attack
            attack_type: Type of attack detected
            confidence: Confidence level of the detection
            source_ips: Set of source IP addresses involved in the attack
            features: Feature vector that triggered the detection
        """
        # Get mitigation strategy based on attack type
        default_strategy = self.config_manager.get_config("mitigation", "default_strategy", default="block")
        
        # Get strategy specific to this attack type if available
        attack_specific_strategy = self.config_manager.get_config(
            "mitigation", 
            f"strategy_{attack_type.lower()}", 
            default=default_strategy
        )
        
        # Example: Call the mitigator if available
        try:
            # Import here to avoid circular import
            from tensorprox.core.ddos_manager import get_instance
            
            # Get the manager instance
            manager = get_instance()
            
            # Get the mitigator from the manager
            if hasattr(manager, "mitigator") and manager.mitigator:
                # Apply mitigation to each source IP
                for src_ip in source_ips:
                    manager.mitigator.apply_mitigation(
                        src_ip=src_ip,
                        attack_id=attack_id,
                        attack_type=attack_type,
                        confidence=confidence,
                        strategy=attack_specific_strategy
                    )
                
                logger.info(f"Mitigation initiated for {attack_type} attack using {attack_specific_strategy} strategy")
        
        except ImportError:
            logger.warning("Cannot import manager instance, mitigation not triggered")
        except Exception as e:
            logger.error(f"Failed to trigger mitigation: {e}")
    
    def stop(self):
        """
        Stop the DDoS detector.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        with self._lock:
            if not self.running:
                logger.warning("DDoS Detector is not running")
                return True
            
            logger.info("Stopping DDoS Detector...")
            
            # Signal threads to stop
            self._stop_event.set()
            
            # Close all sockets
            for interface, sock in self.active_sockets.items():
                try:
                    sock.close()
                    logger.debug(f"Closed socket for {interface}")
                except Exception as e:
                    logger.error(f"Error closing socket for {interface}: {e}")
            
            # Clear socket dictionary
            self.active_sockets.clear()
            
            # Wait for threads to finish (with timeout)
            for thread in self.threads:
                thread.join(timeout=2.0)
            
            # Clear thread list
            self.threads.clear()
            
            self.running = False
            logger.info("DDoS Detector stopped")
            return True
    
    def get_detected_attacks(self):
        """
        Get list of detected attacks.
        
        Returns:
            Dictionary of attack ID -> attack details
        """
        with self._lock:
            return dict(self.detected_attacks)
    
    def clear_attack_history(self):
        """Clear the history of detected attacks."""
        with self._lock:
            self.detected_attacks.clear()