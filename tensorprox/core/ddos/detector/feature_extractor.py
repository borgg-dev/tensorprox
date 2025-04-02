#!/usr/bin/env python3
"""
Feature Extractor for TensorProx DDoS Detection

This module extracts statistical features from network packets for DDoS attack detection,
based on the original extraction logic from miner.py but optimized for performance.
"""

import os
import socket
import struct
import numpy as np
import joblib
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict
from loguru import logger

class FeatureExtractor:
    """
    Extracts and analyzes features from network packets for DDoS detection.
    """
    
    def __init__(self, model_dir: str = None):
        """
        Initialize the feature extractor with ML models.
        
        Args:
            model_dir: Directory containing ML model files
        """
        self.model_dir = model_dir or os.path.expanduser("~/tensorprox/model")
        self._load_models()
    
    def _load_models(self):
        """Load ML models for attack detection."""
        try:
            # Load decision tree model
            model_path = os.path.join(self.model_dir, "decision_tree.pkl")
            self._model = joblib.load(model_path)
            
            # Load preprocessing components
            imputer_path = os.path.join(self.model_dir, "imputer.pkl")
            self._imputer = joblib.load(imputer_path)
            
            scaler_path = os.path.join(self.model_dir, "scaler.pkl")
            self._scaler = joblib.load(scaler_path)
            
            logger.info("ML models loaded successfully")
        
        except Exception as e:
            logger.exception(f"Failed to load ML models: {e}")
            # Set models to None to indicate loading failure
            self._model = None
            self._imputer = None
            self._scaler = None
    
    def extract_features(self, packet_batch: List[Tuple[str, bytes]]) -> Optional[np.ndarray]:
        """
        Extract L3/L4 features from a batch of packets.
        
        Args:
            packet_batch: List of (interface, packet_data) tuples
        
        Returns:
            NumPy array of extracted features, or None if extraction fails
        """
        if not packet_batch:
            return None
        
        try:
            # Initialize flow statistics
            flow_stats = defaultdict(lambda: {
                "tcp_syn_fwd_count": 0, "tcp_syn_bwd_count": 0,
                "fwd_packet_count": 0, "bwd_packet_count": 0,
                "unique_udp_source_ports": set(), "unique_udp_dest_ports": set(),
                "total_fwd_pkt_size": 0, "total_bwd_pkt_size": 0,
                "flow_packets_per_sec": 0, "flow_bytes_per_sec": 0,
                "source_ip_entropy": 0, "dest_port_entropy": 0
            })
            
            # Process each packet
            for interface, packet_data in packet_batch:
                # Skip packets that are too short
                if len(packet_data) < 20:
                    continue
                
                try:
                    # Parse IP header
                    ip_header = packet_data[:20]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    
                    # Extract header fields
                    version_ihl = iph[0]
                    ihl = version_ihl & 0xF
                    iph_length = ihl * 4
                    protocol = iph[6]
                    src_ip = socket.inet_ntoa(iph[8])
                    dest_ip = socket.inet_ntoa(iph[9])
                    
                    # Skip non-TCP/UDP packets
                    if protocol not in (6, 17):
                        continue
                    
                    # Get flow key
                    key = (src_ip, dest_ip)
                    entry = flow_stats[key]
                    entry["fwd_packet_count"] += 1
                    
                    # Process based on protocol
                    if protocol == 6:  # TCP
                        self._process_tcp_packet(packet_data, iph_length, entry)
                    elif protocol == 17:  # UDP
                        self._process_udp_packet(packet_data, iph_length, entry)
                
                except Exception as e:
                    # Skip packets that can't be parsed
                    continue
            
            # Compute aggregated feature values
            return self._compute_aggregated_features(flow_stats)
        
        except Exception as e:
            logger.exception(f"Error extracting features: {e}")
            return None
    
    def _process_tcp_packet(self, packet_data: bytes, iph_length: int, entry: Dict[str, Any]):
        """
        Process a TCP packet and update flow statistics.
        
        Args:
            packet_data: Raw packet data
            iph_length: IP header length
            entry: Flow statistics entry to update
        """
        try:
            # Parse TCP header (if enough data is available)
            if len(packet_data) < iph_length + 20:
                return
            
            tcp_header = packet_data[iph_length:iph_length+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            # Extract fields
            src_port = tcph[0]
            dest_port = tcph[1]
            flags = tcph[5]
            
            # Update statistics
            pkt_size = len(packet_data)
            entry["total_fwd_pkt_size"] += pkt_size
            
            # Check for SYN flag (0x02)
            if flags & 0x02:
                entry["tcp_syn_fwd_count"] += 1
        
        except Exception:
            # Skip this packet if parsing fails
            pass
    
    def _process_udp_packet(self, packet_data: bytes, iph_length: int, entry: Dict[str, Any]):
        """
        Process a UDP packet and update flow statistics.
        
        Args:
            packet_data: Raw packet data
            iph_length: IP header length
            entry: Flow statistics entry to update
        """
        try:
            # Parse UDP header (if enough data is available)
            if len(packet_data) < iph_length + 8:
                return
            
            udp_header = packet_data[iph_length:iph_length+8]
            udph = struct.unpack('!HHHH', udp_header)
            
            # Extract fields
            src_port = udph[0]
            dest_port = udph[1]
            
            # Update statistics
            pkt_size = len(packet_data)
            entry["total_fwd_pkt_size"] += pkt_size
            
            # Track unique ports
            entry["unique_udp_source_ports"].add(src_port)
            entry["unique_udp_dest_ports"].add(dest_port)
        
        except Exception:
            # Skip this packet if parsing fails
            pass
    
    def _compute_aggregated_features(self, flow_stats: Dict[Tuple[str, str], Dict[str, Any]]) -> np.ndarray:
        """
        Compute aggregated features from flow statistics.
        
        Args:
            flow_stats: Dictionary of flow statistics
        
        Returns:
            NumPy array of extracted features
        """
        # Calculate TCP SYN flag ratio
        total_packets = sum(e["fwd_packet_count"] + e["bwd_packet_count"] for e in flow_stats.values())
        total_syn_flags = sum(e["tcp_syn_fwd_count"] + e["tcp_syn_bwd_count"] for e in flow_stats.values())
        
        tcp_syn_flag_ratio = total_syn_flags / max(total_packets, 1)
        
        # Calculate UDP port entropy
        udp_port_entropy = sum(len(e["unique_udp_source_ports"]) * len(e["unique_udp_dest_ports"]) 
                               for e in flow_stats.values())
        
        # Calculate average packet size
        total_bytes = sum(e["total_fwd_pkt_size"] + e["total_bwd_pkt_size"] for e in flow_stats.values())
        avg_pkt_size = total_bytes / max(total_packets, 1)
        
        # Calculate flow density
        # This is a simplification for performance; in production, use a more precise calculation
        flow_count = len(flow_stats)
        flow_density = flow_count / max(total_packets, 1)
        
        # Calculate IP entropy
        # This is a simplification; in production, use Shannon entropy
        ip_count = len(set(src for src, _ in flow_stats.keys()))
        dest_count = len(set(dest for _, dest in flow_stats.keys()))
        ip_entropy = ip_count * dest_count / max(flow_count, 1)
        
        # Return feature vector
        return np.array([
            tcp_syn_flag_ratio,
            udp_port_entropy,
            avg_pkt_size,
            flow_density,
            ip_entropy
        ])
    
    def is_attack(self, features: np.ndarray) -> Tuple[bool, str, float]:
        """
        Determine if the extracted features represent an attack.
        
        Args:
            features: Feature vector extracted from packet batch
        
        Returns:
            Tuple of (is_attack, attack_type, confidence)
        """
        if self._model is None or self._imputer is None or self._scaler is None:
            logger.error("ML models not loaded, cannot predict")
            return False, "unknown", 0.0
        
        try:
            # Preprocess features
            features_imputed = self._imputer.transform([features])
            features_scaled = self._scaler.transform(features_imputed)
            
            # Make prediction
            prediction = self._model.predict(features_scaled)
            
            # Get prediction probabilities if available
            try:
                probabilities = self._model.predict_proba(features_scaled)
                confidence = np.max(probabilities)
            except:
                # If predict_proba is not available, use a simple confidence measure
                confidence = 0.8  # Default confidence
            
            # Convert prediction to attack type
            attack_type = self._get_attack_type(prediction[0])
            is_attack = prediction[0] > 0  # Assuming 0 is benign, >0 is attack
            
            return is_attack, attack_type, confidence
        
        except Exception as e:
            logger.exception(f"Error predicting attack: {e}")
            return False, "unknown", 0.0
    
    def _get_attack_type(self, prediction: int) -> str:
        """
        Convert a numeric prediction to an attack type string.
        
        Args:
            prediction: Numeric prediction from the model
        
        Returns:
            String representing the attack type
        """
        # Map prediction values to attack types
        attack_types = {
            -1: "UNKNOWN",
            0: "BENIGN",
            1: "UDP_FLOOD",
            2: "TCP_SYN_FLOOD"
        }
        
        return attack_types.get(prediction, "UNKNOWN")