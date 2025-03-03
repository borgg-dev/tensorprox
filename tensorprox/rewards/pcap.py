"""
================================================================================

Packet Analyzer Module

This module provides functionality for analyzing packet capture (pcap) files to
identify and count occurrences of specified search strings within network traffic.
It includes the following components:

Classes:
    - PacketAnalyzer: Processes pcap files to extract time ranges, analyze packets
      for specific content, and estimate average packet sizes.

Dependencies:
    - dpkt: For parsing pcap files and interpreting packet structures.
    - datetime: For handling and formatting timestamps.
    - sys: For system-specific parameters and functions.
    - psutil: For accessing system and process utilities, particularly memory info.
    - pandas: For data manipulation and analysis.
    - collections.defaultdict: For handling dictionary-like collections with default values.
    - multiprocessing.Pool and cpu_count: For parallel processing of packets.
    - typing: For type hinting of function signatures and return types.

License:
This software is licensed under the Creative Commons Attribution-NonCommercial
4.0 International (CC BY-NC 4.0). You are free to share and adapt the material
for non-commercial purposes, provided appropriate credit is given, and any changes
are indicated. For more details, visit: https://creativecommons.org/licenses/by-nc/4.0/

Author: Shugo LTD
Version: 0.1.0

================================================================================
"""

import dpkt
import datetime
import sys
import psutil
from multiprocessing import Pool, cpu_count
from typing import Dict, Tuple, List, Iterator, Union
import os
import numpy as np
import hashlib
import logging

class PacketAnalyzer:
    """
    A class to analyze packet capture (pcap) files for specific search strings.

    Attributes:
        pcap_file (str): The path to the pcap file to be analyzed.
    """

    def __init__(self, pcap_file: str):
        """
        Initializes the PacketAnalyzer with the specified pcap file.

        Args:
            pcap_file (str): The path to the pcap file to be analyzed.
        """

        self.pcap_file = pcap_file


    def _extract_timestamps(self, pcap_path: str, label: Union[str, bytes], sender: bool, sent_timestamps: Dict[str, float] = None) -> List[float]:
        """
        Extracts packet payloads and timestamps from a PCAP file.

        Args:
            pcap_path (str): Path to the PCAP file.
            sender (bool): Whether this is the sender's PCAP.
            sent_timestamps (Dict[str, float], optional): Sender timestamps for latency calculation.

        Returns:
            List[float]: 
                - If sender=True: List of timestamps mapping hashed payloads.
                - If sender=False: List of payload latencies for matching packets.
        """

        # Skip processing if pcap_path or label is None
        if not pcap_path or label is None:
            logging.warning("PCAP path or label is None, skipping processing.")
            return []

        timestamps = {} if sender else []

        try:
            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                if not pcap:
                    logging.error(f"Failed to read the PCAP file: {pcap_path}. It may be corrupted or invalid.")
                    return []
                for ts, buf in pcap:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                        payload = eth.data.data.data
                        if not label in payload:  # Skip if label not in payload
                            continue
                        payload_hash = hashlib.sha256(payload).hexdigest()  # Hash for efficient lookup
                        if sender:  # Proceed only if label is in payload
                            timestamps[payload_hash] = ts  # Store sender timestamp
                        elif payload_hash in sent_timestamps:  # Match with sender timestamp    
                            latency = ts - sent_timestamps[payload_hash]
                            latency_ms = latency * 1000  # Convert to ms
                            timestamps.append(latency_ms)                 
        except Exception as e:
            logging.error(f"Error while processing pcap file {pcap_path}: {str(e)}")

        return timestamps
    
    
    def compute_latency(self, king_pcap: str, label: Union[str, bytes]) -> dict:
        """
        Computes latency of packets by matching payloads with timestamps.

        Args:
            king_pcap (str): Path to the king's pcap file.

        Returns:
            dict: Dictionary with latency statistics (min, max, mean, median).
        """
        if not os.path.exists(self.pcap_file) or not os.path.exists(king_pcap):
            raise FileNotFoundError("One or more pcap files are missing.")

        num_cores = cpu_count()

        # Parallel extraction of timestamps
        with Pool(processes=num_cores) as pool:
            sender_result = pool.apply_async(self._extract_timestamps, (self.pcap_file, label, True))
            sent_timestamps = sender_result.get()

            receiver_result = pool.apply_async(self._extract_timestamps, (king_pcap, label, False, sent_timestamps))
            latencies = receiver_result.get()

        # If latencies exist, calculate stats
        if latencies:
            latency_stats = {
                "min": np.min(latencies),
                "max": np.max(latencies),
                "mean": np.mean(latencies),
                "median": np.median(latencies)
            }
            return latency_stats

        # Return None if no valid latencies found
        return {"min": None, "max": None, "mean": None, "median": None}
    