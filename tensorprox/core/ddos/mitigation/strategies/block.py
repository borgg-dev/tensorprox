#!/usr/bin/env python3
"""
Block Mitigation Strategy for TensorProx

This module implements a simple blocking strategy for DDoS mitigation.
"""

import time
from typing import Dict, Any
from loguru import logger

from tensorprox.core.ddos.mitigation.strategies.base import MitigationStrategy

# Constants for verdict actions
VERDICT_UNKNOWN = 0
VERDICT_ALLOW = 1
VERDICT_BLOCK = 2

class BlockStrategy(MitigationStrategy):
    """
    Strategy that completely blocks traffic from a source IP.
    """
    
    def apply(self, src_ip: str, dst_ip: str = None, protocol: int = 0, 
             priority: int = 0, **kwargs) -> bool:
        """
        Apply a complete block to traffic from a source IP.
        
        Args:
            src_ip: Source IP address to block
            dst_ip: Optional destination IP address (if None, blocks all destinations)
            protocol: Optional protocol number to block (0 for all protocols)
            priority: Priority level of the block (higher values take precedence)
            **kwargs: Additional parameters (ignored)
            
        Returns:
            True if block applied successfully, False otherwise
        """
        if not self._validate_ip_address(src_ip):
            return False
        
        # Default dst_ip to wildcard if not specified
        if dst_ip is None:
            dst_ip = "0.0.0.0"
        elif not self._validate_ip_address(dst_ip):
            return False
        
        # Apply block using BPF loader
        if self.bpf_loader:
            success = self.bpf_loader.update_flow_verdict(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                action=VERDICT_BLOCK,
                priority=priority
            )
            
            if success:
                # Record the mitigation
                self.active_mitigations[src_ip] = {
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "priority": priority,
                    "start_time": time.time(),
                    "packet_count": 0  # Will be updated by metrics collector
                }
                
                logger.info(f"Applied block to {src_ip}")
                return True
            else:
                logger.error(f"Failed to apply block to {src_ip}")
                return False
        else:
            logger.error("BPF loader not available, cannot apply block")
            return False
    
    def revoke(self, src_ip: str, dst_ip: str = None) -> bool:
        """
        Revoke a block for a specific source IP.
        
        Args:
            src_ip: Source IP address to unblock
            dst_ip: Optional destination IP address
            
        Returns:
            True if block revoked successfully, False otherwise
        """
        if not self._validate_ip_address(src_ip):
            return False
        
        # Get mitigation details
        mitigation = self.active_mitigations.get(src_ip)
        if not mitigation:
            logger.warning(f"No active block for {src_ip}")
            return False
        
        # Use dst_ip from parameters or from stored mitigation
        if dst_ip is None:
            dst_ip = mitigation.get("dst_ip", "0.0.0.0")
        elif not self._validate_ip_address(dst_ip):
            return False
        
        # Apply "allow" verdict using BPF loader to override block
        if self.bpf_loader:
            success = self.bpf_loader.update_flow_verdict(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=mitigation.get("protocol", 0),
                action=VERDICT_ALLOW,
                priority=mitigation.get("priority", 0) + 1  # Higher priority to override
            )
            
            if success:
                # Remove the mitigation from our tracking
                del self.active_mitigations[src_ip]
                logger.info(f"Revoked block from {src_ip}")
                return True
            else:
                logger.error(f"Failed to revoke block from {src_ip}")
                return False
        else:
            logger.error("BPF loader not available, cannot revoke block")
            return False
    
    def get_block_count(self) -> int:
        """
        Get the number of active blocks.
        
        Returns:
            Number of active blocks
        """
        return len(self.active_mitigations)