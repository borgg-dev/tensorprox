#!/usr/bin/env python3
"""
Rate Limit Mitigation Strategy for TensorProx

This module implements a rate limiting strategy for DDoS mitigation.
"""

import time
from typing import Dict, Any
from loguru import logger

from tensorprox.core.ddos.mitigation.strategies.base import MitigationStrategy

# Constants for verdict actions
VERDICT_UNKNOWN = 0
VERDICT_ALLOW = 1
VERDICT_BLOCK = 2
VERDICT_RATE_LIMIT = 3

class RateLimitStrategy(MitigationStrategy):
    """
    Strategy that rate limits traffic from a source IP.
    """
    
    def apply(self, src_ip: str, dst_ip: str = None, protocol: int = 0,
             rate_limit: int = 10, priority: int = 0, **kwargs) -> bool:
        """
        Apply rate limiting to traffic from a source IP.
        
        Args:
            src_ip: Source IP address to rate limit
            dst_ip: Optional destination IP address (if None, rate limits all destinations)
            protocol: Optional protocol number to rate limit (0 for all protocols)
            rate_limit: Rate limit value (e.g., 10 = allow 1 in 10 packets)
            priority: Priority level of the rate limit (higher values take precedence)
            **kwargs: Additional parameters (ignored)
            
        Returns:
            True if rate limit applied successfully, False otherwise
        """
        if not self._validate_ip_address(src_ip):
            return False
        
        # Default dst_ip to wildcard if not specified
        if dst_ip is None:
            dst_ip = "0.0.0.0"
        elif not self._validate_ip_address(dst_ip):
            return False
        
        # Ensure rate limit is valid
        rate_limit = max(2, min(1000, int(rate_limit)))
        
        # Apply rate limit using BPF loader
        if self.bpf_loader:
            success = self.bpf_loader.update_flow_verdict(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                action=VERDICT_RATE_LIMIT,
                priority=priority,
                rate_limit=rate_limit
            )
            
            if success:
                # Record the mitigation
                self.active_mitigations[src_ip] = {
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "rate_limit": rate_limit,
                    "priority": priority,
                    "start_time": time.time(),
                    "packet_count": 0,  # Will be updated by metrics collector
                    "packet_passed": 0  # Will be updated by metrics collector
                }
                
                logger.info(f"Applied rate limit of 1/{rate_limit} to {src_ip}")
                return True
            else:
                logger.error(f"Failed to apply rate limit to {src_ip}")
                return False
        else:
            logger.error("BPF loader not available, cannot apply rate limit")
            return False
    
    def revoke(self, src_ip: str, dst_ip: str = None) -> bool:
        """
        Revoke a rate limit for a specific source IP.
        
        Args:
            src_ip: Source IP address to remove rate limit from
            dst_ip: Optional destination IP address
            
        Returns:
            True if rate limit revoked successfully, False otherwise
        """
        if not self._validate_ip_address(src_ip):
            return False
        
        # Get mitigation details
        mitigation = self.active_mitigations.get(src_ip)
        if not mitigation:
            logger.warning(f"No active rate limit for {src_ip}")
            return False
        
        # Use dst_ip from parameters or from stored mitigation
        if dst_ip is None:
            dst_ip = mitigation.get("dst_ip", "0.0.0.0")
        elif not self._validate_ip_address(dst_ip):
            return False
        
        # Apply "allow" verdict using BPF loader to override rate limit
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
                logger.info(f"Revoked rate limit from {src_ip}")
                return True
            else:
                logger.error(f"Failed to revoke rate limit from {src_ip}")
                return False
        else:
            logger.error("BPF loader not available, cannot revoke rate limit")
            return False
    
    def update_rate(self, src_ip: str, rate_limit: int) -> bool:
        """
        Update the rate limit for a specific source IP.
        
        Args:
            src_ip: Source IP address to update
            rate_limit: New rate limit value
            
        Returns:
            True if rate limit updated successfully, False otherwise
        """
        if not self._validate_ip_address(src_ip):
            return False
        
        # Get mitigation details
        mitigation = self.active_mitigations.get(src_ip)
        if not mitigation:
            logger.warning(f"No active rate limit for {src_ip}")
            return False
        
        # Ensure rate limit is valid
        rate_limit = max(2, min(1000, int(rate_limit)))
        
        # Apply updated rate limit
        if self.bpf_loader:
            success = self.bpf_loader.update_flow_verdict(
                src_ip=src_ip,
                dst_ip=mitigation.get("dst_ip", "0.0.0.0"),
                protocol=mitigation.get("protocol", 0),
                action=VERDICT_RATE_LIMIT,
                priority=mitigation.get("priority", 0),
                rate_limit=rate_limit
            )
            
            if success:
                # Update the mitigation record
                mitigation["rate_limit"] = rate_limit
                logger.info(f"Updated rate limit for {src_ip} to 1/{rate_limit}")
                return True
            else:
                logger.error(f"Failed to update rate limit for {src_ip}")
                return False
        else:
            logger.error("BPF loader not available, cannot update rate limit")
            return False