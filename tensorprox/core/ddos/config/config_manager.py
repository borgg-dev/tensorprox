#!/usr/bin/env python3
"""
Configuration Manager for TensorProx DDoS Protection

This module manages configuration settings for the DDoS protection system,
providing a centralized way to access and update settings.
"""

import os
import json
import threading
from typing import Dict, List, Optional, Union, Any
from loguru import logger

class ConfigManager:
    """
    Manages configuration for the DDoS protection system.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Optional path to a configuration file
        """
        self._config = self._get_default_config()
        self._config_path = config_path
        self._lock = threading.RLock()
        
        # Load configuration from file if provided
        if config_path:
            self.load_config_file(config_path)
    
    def _get_default_config(self) -> Dict[str, Dict[str, Any]]:
        """
        Get the default configuration settings.
        
        Returns:
            Dictionary of default configuration settings
        """
        return {
            "detection": {
                "enabled": True,
                "batch_interval": 10,  # Seconds
                "threshold": 0.7,      # Confidence threshold for attack detection
                "model_dir": os.path.expanduser("~/tensorprox/model")
            },
            "mitigation": {
                "enabled": True,
                "default_strategy": "block",
                "auto_revoke_time": 300,  # Seconds (5 minutes)
                "max_mitigations": 1000,
                "strategy_udp_flood": "rate_limit",
                "strategy_tcp_syn_flood": "block"
            },
            "sampling": {
                "base_rate": 100,  # 1 in 100 packets (1%)
                "syn_rate": 10,    # 1 in 10 SYN packets (10%)
                "udp_rate": 50,    # 1 in 50 UDP packets (2%)
                "icmp_rate": 50,   # 1 in 50 ICMP packets (2%)
                "min_size": 64,    # Minimum packet size
                "max_size": 1500,  # Maximum packet size
                "size_rate": 20    # 1 in 20 packets of suspicious size (5%)
            },
            "detector": {
                "interfaces": ["gre-benign", "gre-attacker"]
            },
            "interfaces": {
                "mappings": {
                    "gre-benign": "gre-king",
                    "gre-attacker": "gre-king",
                    "gre-king": "gre-benign"  # Default route - can be overridden by destination
                }
            },
            "rules": {
                "default": []
            },
            "xdp": {
                "use_generic": False
            },
            "metrics": {
                "collection_interval": 5  # Seconds
            }
        }
    
    def get_config(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            section: Configuration section
            key: Optional configuration key (if None, returns the entire section)
            default: Default value to return if not found
            
        Returns:
            Configuration value, or default if not found
        """
        with self._lock:
            if section not in self._config:
                return default
            
            if key is None:
                return self._config[section]
            
            return self._config[section].get(key, default)
    
    def set_config(self, section: str, key: str, value: Any) -> bool:
        """
        Set a configuration value.
        
        Args:
            section: Configuration section
            key: Configuration key
            value: New value
            
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            # Create section if it doesn't exist
            if section not in self._config:
                self._config[section] = {}
            
            # Update the value
            self._config[section][key] = value
            
            # Save to file if a path is set
            if self._config_path:
                return self.save_config_file(self._config_path)
            
            return True
    
    def load_config_file(self, config_path: str) -> bool:
        """
        Load configuration from a file.
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            try:
                if not os.path.exists(config_path):
                    logger.warning(f"Configuration file {config_path} does not exist, using defaults")
                    return False
                
                with open(config_path, "r") as f:
                    config = json.load(f)
                
                # Update configuration
                for section, section_config in config.items():
                    if section not in self._config:
                        self._config[section] = {}
                    
                    if isinstance(section_config, dict):
                        self._config[section].update(section_config)
                    else:
                        self._config[section] = section_config
                
                logger.info(f"Loaded configuration from {config_path}")
                return True
            
            except Exception as e:
                logger.exception(f"Failed to load configuration from {config_path}: {e}")
                return False
    
    def save_config_file(self, config_path: str) -> bool:
        """
        Save configuration to a file.
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            try:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
                
                with open(config_path, "w") as f:
                    json.dump(self._config, f, indent=2)
                
                logger.info(f"Saved configuration to {config_path}")
                return True
            
            except Exception as e:
                logger.exception(f"Failed to save configuration to {config_path}: {e}")
                return False
    
    def reset_to_defaults(self) -> bool:
        """
        Reset configuration to defaults.
        
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            self._config = self._get_default_config()
            
            # Save to file if a path is set
            if self._config_path:
                return self.save_config_file(self._config_path)
            
            return True