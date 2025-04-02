#!/usr/bin/env python3
"""
Base Mitigation Strategy for TensorProx

This module defines the base class for all DDoS mitigation strategies.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from loguru import logger

class MitigationStrategy(ABC):
    """
    Abstract base class for DDoS mitigation strategies.
    All concrete mitigation strategies should inherit from this class.
    """
    
    def __init__(self, bpf_loader=None):
        """
        Initialize the mitigation strategy.
        
        Args:
            bpf_loader: BPF loader instance for XDP interaction (optional)
        """
        self.bpf_loader = bpf_loader
        self.active_mitigations = {}  # src_ip -> mitigation_details
    
    @abstractmethod
    def apply(self, src_ip: str, **kwargs) -> bool:
        """
        Apply the mitigation strategy to a specific source IP.
        
        Args:
            src_ip: Source IP address to mitigate
            **kwargs: Additional parameters for the mitigation
            
        Returns:
            True if mitigation applied successfully, False otherwise
        """
        pass
    
    @abstractmethod
    def revoke(self, src_ip: str) -> bool:
        """
        Revoke the mitigation for a specific source IP.
        
        Args:
            src_ip: Source IP address to revoke mitigation for
            
        Returns:
            True if mitigation revoked successfully, False otherwise
        """
        pass
    
    def get_active_mitigations(self) -> Dict[str, Dict[str, Any]]:
        """
        Get list of active mitigations for this strategy.
        
        Returns:
            Dictionary of source IP -> mitigation details
        """
        return dict(self.active_mitigations)
    
    def get_mitigation_stats(self, src_ip: str) -> Optional[Dict[str, Any]]:
        """
        Get statistics for a specific mitigation.
        
        Args:
            src_ip: Source IP address of the mitigation
            
        Returns:
            Dictionary of mitigation statistics, or None if not found
        """
        return self.active_mitigations.get(src_ip)
    
    def _validate_ip_address(self, ip_address: str) -> bool:
        """
        Validate an IP address format.
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            True if the IP address is valid, False otherwise
        """
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            logger.error(f"Invalid IP address: {ip_address}")
            return False