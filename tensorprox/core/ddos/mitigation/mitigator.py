#!/usr/bin/env python3
"""
DDoS Mitigator for TensorProx

This module provides DDoS mitigation capabilities, applying protective measures
when attacks are detected by implementing various mitigation strategies.
"""

import os
import time
import threading
import socket
import ipaddress
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from loguru import logger

# Import configuration manager
from tensorprox.core.ddos.config.config_manager import ConfigManager

# Import mitigation strategies
from tensorprox.core.ddos.mitigation.strategies.base import MitigationStrategy
from tensorprox.core.ddos.mitigation.strategies.block import BlockStrategy
from tensorprox.core.ddos.mitigation.strategies.rate_limit import RateLimitStrategy

class DDoSMitigator:
    """
    Applies and manages DDoS mitigation strategies based on detected attacks.
    """
    
    def __init__(self, config_manager: ConfigManager, bpf_loader=None):
        """
        Initialize the DDoS mitigator.
        
        Args:
            config_manager: Configuration manager instance
            bpf_loader: BPF loader instance for XDP interaction (optional)
        """
        self.config_manager = config_manager
        self.bpf_loader = bpf_loader
        
        # Initialize state
        self.running = False
        self.active_mitigations = {}  # src_ip -> mitigation_details
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        
        # Load available strategies
        self._load_strategies()
        
        # Configuration
        self.auto_revoke_time = self.config_manager.get_config("mitigation", "auto_revoke_time", default=300)  # 5 minutes
        self.max_simultaneous_mitigations = self.config_manager.get_config("mitigation", "max_mitigations", default=1000)
    
    def _load_strategies(self):
        """Load available mitigation strategies."""
        self.strategies = {
            "block": BlockStrategy(self.bpf_loader),
            "rate_limit": RateLimitStrategy(self.bpf_loader)
        }
        
        logger.info(f"Loaded {len(self.strategies)} mitigation strategies: {', '.join(self.strategies.keys())}")
    
    def start(self):
        """
        Start the DDoS mitigator.
        
        Returns:
            True if started successfully, False otherwise
        """
        with self._lock:
            if self.running:
                logger.warning("DDoS Mitigator is already running")
                return True
            
            self._stop_event.clear()
            self.running = True
            
            try:
                # Start maintenance thread for auto-revoking mitigations
                self.maintenance_thread = threading.Thread(
                    target=self._maintenance_thread,
                    name="DDoSMitigator-Maintenance"
                )
                self.maintenance_thread.daemon = True
                self.maintenance_thread.start()
                
                logger.info(f"DDoS Mitigator started (auto revoke time: {self.auto_revoke_time}s)")
                return True
            
            except Exception as e:
                logger.exception(f"Failed to start DDoS Mitigator: {e}")
                self.running = False
                return False
    
    def _maintenance_thread(self):
        """Thread function for maintenance tasks like auto-revoking expired mitigations."""
        logger.debug("Mitigation maintenance thread started")
        
        try:
            while not self._stop_event.is_set():
                try:
                    self._auto_revoke_expired_mitigations()
                except Exception as e:
                    logger.error(f"Error in mitigation maintenance: {e}")
                
                # Sleep for a while
                time.sleep(10)
        
        except Exception as e:
            if not self._stop_event.is_set():
                logger.exception(f"Error in mitigation maintenance thread: {e}")
        
        finally:
            logger.debug("Mitigation maintenance thread exiting")
    
    def _auto_revoke_expired_mitigations(self):
        """Automatically revoke expired mitigations."""
        with self._lock:
            current_time = datetime.now()
            mitigations_to_revoke = []
            
            # Find expired mitigations
            for src_ip, mitigation in self.active_mitigations.items():
                expiry_time = mitigation.get("expiry_time")
                if expiry_time and expiry_time <= current_time:
                    mitigations_to_revoke.append(src_ip)
            
            # Revoke expired mitigations
            for src_ip in mitigations_to_revoke:
                try:
                    self._revoke_mitigation(src_ip)
                    logger.info(f"Auto-revoked expired mitigation for {src_ip}")
                except Exception as e:
                    logger.error(f"Failed to auto-revoke mitigation for {src_ip}: {e}")
    
    def apply_mitigation(self, src_ip: str, attack_id: str = None, attack_type: str = None,
                        confidence: float = None, strategy: str = "block", duration: int = None,
                        **kwargs):
        """
        Apply a mitigation strategy to a specific source IP.
        
        Args:
            src_ip: Source IP address to mitigate
            attack_id: Identifier for the attack (optional)
            attack_type: Type of attack detected (optional)
            confidence: Confidence level of the detection (optional)
            strategy: Mitigation strategy to apply (default: "block")
            duration: Duration of the mitigation in seconds (optional)
            **kwargs: Additional parameters for the mitigation strategy
        
        Returns:
            True if mitigation applied successfully, False otherwise
        """
        if not self.running:
            logger.error("Cannot apply mitigation: DDoS Mitigator is not running")
            return False
        
        with self._lock:
            # Validate IP address
            try:
                ipaddress.ip_address(src_ip)
            except ValueError:
                logger.error(f"Invalid IP address: {src_ip}")
                return False
            
            # Check if we already have too many active mitigations
            if len(self.active_mitigations) >= self.max_simultaneous_mitigations:
                logger.warning(f"Maximum number of simultaneous mitigations reached ({self.max_simultaneous_mitigations})")
                return False
            
            # Check if we already have an active mitigation for this IP
            if src_ip in self.active_mitigations:
                existing_strategy = self.active_mitigations[src_ip]["strategy"]
                
                # If the strategy is the same, just update the expiry time
                if existing_strategy == strategy:
                    logger.info(f"Updating existing {strategy} mitigation for {src_ip}")
                    
                    # Update expiry time
                    if duration:
                        self.active_mitigations[src_ip]["expiry_time"] = datetime.now() + timedelta(seconds=duration)
                    else:
                        self.active_mitigations[src_ip]["expiry_time"] = datetime.now() + timedelta(seconds=self.auto_revoke_time)
                    
                    return True
                
                # Otherwise, revoke the existing mitigation first
                self._revoke_mitigation(src_ip)
            
            # Get the strategy implementation
            if strategy not in self.strategies:
                logger.error(f"Unknown mitigation strategy: {strategy}")
                return False
            
            strategy_impl = self.strategies[strategy]
            
            try:
                # Apply the mitigation
                result = strategy_impl.apply(src_ip, **kwargs)
                
                if result:
                    # Record the mitigation
                    self.active_mitigations[src_ip] = {
                        "strategy": strategy,
                        "attack_id": attack_id,
                        "attack_type": attack_type,
                        "confidence": confidence,
                        "start_time": datetime.now(),
                        "expiry_time": datetime.now() + timedelta(seconds=duration or self.auto_revoke_time),
                        "params": kwargs
                    }
                    
                    logger.info(f"Applied {strategy} mitigation to {src_ip}")
                    return True
                else:
                    logger.error(f"Failed to apply {strategy} mitigation to {src_ip}")
                    return False
            
            except Exception as e:
                logger.exception(f"Error applying {strategy} mitigation to {src_ip}: {e}")
                return False
    
    def revoke_mitigation(self, src_ip: str):
        """
        Revoke a mitigation for a specific source IP.
        
        Args:
            src_ip: Source IP address to revoke mitigation for
        
        Returns:
            True if mitigation revoked successfully, False otherwise
        """
        if not self.running:
            logger.error("Cannot revoke mitigation: DDoS Mitigator is not running")
            return False
        
        with self._lock:
            return self._revoke_mitigation(src_ip)
    
    def _revoke_mitigation(self, src_ip: str):
        """
        Internal method to revoke a mitigation without locking (caller must hold the lock).
        
        Args:
            src_ip: Source IP address to revoke mitigation for
        
        Returns:
            True if mitigation revoked successfully, False otherwise
        """
        if src_ip not in self.active_mitigations:
            logger.warning(f"No active mitigation for {src_ip}")
            return False
        
        mitigation = self.active_mitigations[src_ip]
        strategy_name = mitigation["strategy"]
        
        if strategy_name not in self.strategies:
            logger.error(f"Unknown mitigation strategy: {strategy_name}")
            return False
        
        strategy_impl = self.strategies[strategy_name]
        
        try:
            # Revoke the mitigation
            result = strategy_impl.revoke(src_ip)
            
            if result:
                # Remove from active mitigations
                del self.active_mitigations[src_ip]
                logger.info(f"Revoked {strategy_name} mitigation from {src_ip}")
                return True
            else:
                logger.error(f"Failed to revoke {strategy_name} mitigation from {src_ip}")
                return False
        
        except Exception as e:
            logger.exception(f"Error revoking {strategy_name} mitigation from {src_ip}: {e}")
            return False
    
    def get_active_mitigations(self):
        """
        Get list of active mitigations.
        
        Returns:
            Dictionary of source IP -> mitigation details
        """
        with self._lock:
            return dict(self.active_mitigations)
    
    def clear_all_mitigations(self):
        """
        Clear all active mitigations.
        
        Returns:
            True if all mitigations cleared successfully, False otherwise
        """
        if not self.running:
            logger.error("Cannot clear mitigations: DDoS Mitigator is not running")
            return False
        
        with self._lock:
            success = True
            
            # Revoke all active mitigations
            for src_ip in list(self.active_mitigations.keys()):
                if not self._revoke_mitigation(src_ip):
                    success = False
            
            return success
    
    def stop(self):
        """
        Stop the DDoS mitigator.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        with self._lock:
            if not self.running:
                logger.warning("DDoS Mitigator is not running")
                return True
            
            logger.info("Stopping DDoS Mitigator...")
            
            # Signal maintenance thread to stop
            self._stop_event.set()
            
            # Wait for maintenance thread to exit
            if hasattr(self, "maintenance_thread") and self.maintenance_thread.is_alive():
                self.maintenance_thread.join(timeout=2.0)
            
            # Clear all active mitigations
            self.clear_all_mitigations()
            
            self.running = False
            logger.info("DDoS Mitigator stopped")
            return True