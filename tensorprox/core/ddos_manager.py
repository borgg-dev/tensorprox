#!/usr/bin/env python3
"""
DDoS Manager for TensorProx

This module serves as the main integration point for the DDoS detection and mitigation system
with the existing TensorProx infrastructure. It handles initialization, configuration, 
and orchestration of the DDoS protection components.
"""

import os
import sys
import time
import signal
import asyncio
import threading
from typing import Dict, List, Optional, Union, Any
from loguru import logger

# Import TensorProx components
from tensorprox.core.immutable.gre_setup import GRESetup
from tensorprox.core.immutable.bpf_loader import BPFLoader

# Import DDoS protection components
from tensorprox.core.ddos.detector.detector import DDoSDetector
from tensorprox.core.ddos.mitigation.mitigator import DDoSMitigator
from tensorprox.core.ddos.config.config_manager import ConfigManager
from tensorprox.core.ddos.metrics.metrics_collector import MetricsCollector

class DDoSManager:
    """
    Manages the DDoS protection system for TensorProx, integrating with the existing
    GRE tunnel setup and providing detection and mitigation capabilities.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the DDoS Manager.
        
        Args:
            config_path: Optional path to a configuration file
        """
        self.config_manager = ConfigManager(config_path)
        self.bpf_loader = None
        self.detector = None
        self.mitigator = None
        self.metrics_collector = None
        
        self.running = False
        self.stopping = False
        self.ready = threading.Event()
        self._lock = threading.RLock()
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        """Handle termination signals by initiating a graceful shutdown."""
        logger.info(f"Received signal {sig}, initiating shutdown...")
        self.stop()
    
    def initialize(self):
        """
        Initialize the DDoS protection system.
        
        Returns:
            True if initialization is successful, False otherwise
        """
        with self._lock:
            if self.running or self.stopping:
                logger.warning("DDoS Manager is already running or stopping")
                return False
            
            try:
                logger.info("Initializing DDoS protection system...")
                
                # Create components
                self.bpf_loader = BPFLoader(
                    use_generic=self.config_manager.get_config("xdp", "use_generic", default=False)
                )
                
                self.detector = DDoSDetector(
                    self.config_manager,
                    self.bpf_loader
                )
                
                self.mitigator = DDoSMitigator(
                    self.config_manager,
                    self.bpf_loader
                )
                
                self.metrics_collector = MetricsCollector(
                    self.config_manager,
                    self.bpf_loader
                )
                
                # Initialize BPF loader
                if not self.bpf_loader.load_xdp():
                    logger.error("Failed to load XDP program")
                    return False
                
                # Load initial configuration
                self._configure_xdp()
                
                logger.info("DDoS protection system initialized successfully")
                return True
            
            except Exception as e:
                logger.exception(f"Failed to initialize DDoS protection system: {e}")
                return False
    
    def _configure_xdp(self):
        """Apply configuration to the XDP program."""
        # Configure sampling rates
        sampling_config = {
            "base_rate": self.config_manager.get_config("sampling", "base_rate", default=100),
            "syn_rate": self.config_manager.get_config("sampling", "syn_rate", default=10),
            "udp_rate": self.config_manager.get_config("sampling", "udp_rate", default=50),
            "icmp_rate": self.config_manager.get_config("sampling", "icmp_rate", default=50),
            "min_size": self.config_manager.get_config("sampling", "min_size", default=64),
            "max_size": self.config_manager.get_config("sampling", "max_size", default=1500),
            "size_rate": self.config_manager.get_config("sampling", "size_rate", default=20),
        }
        
        self.bpf_loader.update_sampling_config(sampling_config)
        
        # Configure any default allow/block rules
        default_rules = self.config_manager.get_config("rules", "default", default=[])
        for rule in default_rules:
            if "src_ip" in rule and "dst_ip" in rule:
                self.bpf_loader.update_flow_verdict(
                    src_ip=rule["src_ip"],
                    dst_ip=rule["dst_ip"],
                    src_port=rule.get("src_port", 0),
                    dst_port=rule.get("dst_port", 0),
                    protocol=rule.get("protocol", 0),
                    action=rule.get("action", 1),  # Default to ALLOW
                    priority=rule.get("priority", 0),
                    rate_limit=rule.get("rate_limit", 0)
                )
    
    def start(self, attach_interfaces: Optional[Dict[str, str]] = None):
        """
        Start the DDoS protection system.
        
        Args:
            attach_interfaces: Optional dictionary mapping ingress interfaces to egress interfaces
                               for XDP attachment (default: use configured interfaces)
        
        Returns:
            True if started successfully, False otherwise
        """
        with self._lock:
            if self.running:
                logger.warning("DDoS Manager is already running")
                return True
            
            if self.stopping:
                logger.warning("DDoS Manager is currently stopping, cannot start")
                return False
            
            # Initialize if not already initialized
            if not self.bpf_loader:
                if not self.initialize():
                    return False
            
            try:
                # Get interfaces to attach
                if not attach_interfaces:
                    attach_interfaces = self.config_manager.get_config("interfaces", "mappings", default={})
                
                # Attach XDP program to interfaces
                for ingress, egress in attach_interfaces.items():
                    logger.info(f"Attaching XDP program to {ingress} (redirecting to {egress})")
                    if not self.bpf_loader.attach_xdp(ingress, egress):
                        logger.error(f"Failed to attach XDP program to {ingress}")
                        self.stop()
                        return False
                
                # Start detector
                self.detector.start()
                
                # Start mitigator
                self.mitigator.start()
                
                # Start metrics collector
                self.metrics_collector.start()
                
                self.running = True
                self.ready.set()
                logger.info("DDoS protection system started successfully")
                return True
            
            except Exception as e:
                logger.exception(f"Failed to start DDoS protection system: {e}")
                self.stop()
                return False
    
    def stop(self):
        """
        Stop the DDoS protection system.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        with self._lock:
            if not self.running:
                logger.warning("DDoS Manager is not running")
                return True
            
            if self.stopping:
                logger.warning("DDoS Manager is already stopping")
                return True
            
            self.stopping = True
            self.ready.clear()
            
            try:
                logger.info("Stopping DDoS protection system...")
                
                # Stop components in reverse order
                if self.metrics_collector:
                    self.metrics_collector.stop()
                
                if self.mitigator:
                    self.mitigator.stop()
                
                if self.detector:
                    self.detector.stop()
                
                # Detach XDP program from interfaces
                if self.bpf_loader:
                    for interface in list(self.bpf_loader.attached_interfaces.keys()):
                        logger.info(f"Detaching XDP program from {interface}")
                        self.bpf_loader.detach_xdp(interface)
                    
                    # Clean up BPF loader
                    self.bpf_loader.cleanup()
                
                self.running = False
                self.stopping = False
                logger.info("DDoS protection system stopped successfully")
                return True
            
            except Exception as e:
                logger.exception(f"Failed to stop DDoS protection system: {e}")
                self.running = False
                self.stopping = False
                return False
    
    def update_config(self, section: str, key: str, value: Any):
        """
        Update a configuration value.
        
        Args:
            section: Configuration section
            key: Configuration key
            value: New value
        
        Returns:
            True if updated successfully, False otherwise
        """
        if self.config_manager.set_config(section, key, value):
            # Apply updates to running components if needed
            if section == "sampling":
                self._configure_xdp()
            
            return True
        
        return False
    
    def apply_mitigation(self, 
                        src_ip: str, 
                        dst_ip: str = "",
                        strategy: str = "block",
                        **kwargs):
        """
        Apply a mitigation strategy to a flow.
        
        Args:
            src_ip: Source IP address to mitigate
            dst_ip: Optional destination IP address (if empty, applies to all destinations)
            strategy: Mitigation strategy to apply (block, rate_limit, etc.)
            **kwargs: Additional parameters for the mitigation strategy
        
        Returns:
            True if mitigation applied successfully, False otherwise
        """
        if not self.running:
            logger.error("Cannot apply mitigation: DDoS Manager is not running")
            return False
        
        if not self.mitigator:
            logger.error("Cannot apply mitigation: Mitigator not initialized")
            return False
        
        return self.mitigator.apply_mitigation(
            src_ip=src_ip,
            dst_ip=dst_ip,
            strategy=strategy,
            **kwargs
        )
    
    def revoke_mitigation(self, src_ip: str, dst_ip: str = ""):
        """
        Revoke a mitigation for a flow.
        
        Args:
            src_ip: Source IP address
            dst_ip: Optional destination IP address
        
        Returns:
            True if mitigation revoked successfully, False otherwise
        """
        if not self.running:
            logger.error("Cannot revoke mitigation: DDoS Manager is not running")
            return False
        
        if not self.mitigator:
            logger.error("Cannot revoke mitigation: Mitigator not initialized")
            return False
        
        return self.mitigator.revoke_mitigation(
            src_ip=src_ip,
            dst_ip=dst_ip
        )
    
    def get_metrics(self):
        """
        Get current metrics from the DDoS protection system.
        
        Returns:
            Dictionary of metrics, or None if failed
        """
        if not self.running:
            logger.error("Cannot get metrics: DDoS Manager is not running")
            return None
        
        if not self.metrics_collector:
            logger.error("Cannot get metrics: Metrics collector not initialized")
            return None
        
        return self.metrics_collector.get_current_metrics()
    
    def get_active_mitigations(self):
        """
        Get list of active mitigations.
        
        Returns:
            List of active mitigations, or None if failed
        """
        if not self.running:
            logger.error("Cannot get active mitigations: DDoS Manager is not running")
            return None
        
        if not self.mitigator:
            logger.error("Cannot get active mitigations: Mitigator not initialized")
            return None
        
        return self.mitigator.get_active_mitigations()

    @staticmethod
    def setup_moat():
        """
        Set up the Moat node with GRE tunnels.
        
        Returns:
            True if setup is successful, False otherwise
        """
        try:
            logger.info("Setting up Moat node with GRE tunnels...")
            
            # Get environment variables for IPs
            benign_ip = os.environ.get("BENIGN_PRIVATE_IP")
            attacker_ip = os.environ.get("ATTACKER_PRIVATE_IP")
            king_ip = os.environ.get("KING_PRIVATE_IP")
            
            if not benign_ip or not attacker_ip or not king_ip:
                logger.error("Missing required environment variables for GRE setup")
                return False
            
            # Create GRE setup and configure Moat node
            gre = GRESetup(node_type="moat")
            success = gre.moat(
                benign_private_ip=benign_ip,
                attacker_private_ip=attacker_ip,
                king_private_ip=king_ip
            )
            
            if success:
                logger.info("GRE tunnel setup completed successfully")
                return True
            else:
                logger.error("GRE tunnel setup failed")
                return False
        
        except Exception as e:
            logger.exception(f"Failed to set up GRE tunnels: {e}")
            return False

# Global instance for easy access
ddos_manager = None

def init(config_path: Optional[str] = None):
    """
    Initialize the global DDoS Manager instance.
    
    Args:
        config_path: Optional path to a configuration file
    
    Returns:
        The DDoS Manager instance
    """
    global ddos_manager
    
    if ddos_manager is None:
        ddos_manager = DDoSManager(config_path)
    
    return ddos_manager

def get_instance():
    """
    Get the global DDoS Manager instance, initializing it if necessary.
    
    Returns:
        The DDoS Manager instance
    """
    global ddos_manager
    
    if ddos_manager is None:
        ddos_manager = DDoSManager()
    
    return ddos_manager

if __name__ == "__main__":
    # Simple CLI for testing
    import argparse
    
    parser = argparse.ArgumentParser(description="TensorProx DDoS Manager")
    parser.add_argument("--config", "-c", help="Path to configuration file")
    parser.add_argument("--setup", "-s", action="store_true", help="Set up GRE tunnels")
    args = parser.parse_args()
    
    # Set up logging
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    
    # Initialize the manager
    manager = DDoSManager(args.config)
    
    # Set up GRE tunnels if requested
    if args.setup:
        if not DDoSManager.setup_moat():
            sys.exit(1)
    
    # Initialize and start the manager
    if not manager.initialize():
        logger.error("Failed to initialize DDoS Manager")
        sys.exit(1)
    
    if not manager.start():
        logger.error("Failed to start DDoS Manager")
        sys.exit(1)
    
    # Keep running until interrupted
    try:
        while manager.running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        manager.stop()