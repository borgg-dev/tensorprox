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

    def get_time_range(self) -> Tuple[str, str]:
        """
        Extracts the start and end timestamps from the pcap file.

        Returns:
            Tuple[str, str]: A tuple containing the start and end timestamps
            in the format "YYYY-MM-DD HH:MM:SS.ffffff". Returns (None, None)
            if no timestamps are found.
        """

        with open(self.pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            timestamps = [ts for ts, _ in pcap]

        if timestamps:
            start_date = datetime.datetime.fromtimestamp(timestamps[0]).strftime("%Y-%m-%d %H:%M:%S.%f")
            end_date = datetime.datetime.fromtimestamp(timestamps[-1]).strftime("%Y-%m-%d %H:%M:%S.%f")
            return start_date, end_date
        return None, None

    def process_packet(self, args: Tuple[float, bytes, List[str]]) -> Tuple[Dict[str, int], int]:
        """
        Processes a single packet to count occurrences of search strings.

        Args:
            args (Tuple[float, bytes, List[str]]): A tuple containing the timestamp,
            packet buffer, and a list of search strings.

        Returns:
            Tuple[Dict[str, int], int]: A dictionary with search strings as keys
            and their occurrence counts as values, and the total number of packets
            processed (0 or 1).
        """

        ts, buf, search_labels = args
        match_counts = {search_string: 0 for search_string in search_labels}
        total_packets = 0

        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                return match_counts, total_packets

            ip = eth.data
            total_packets += 1

            if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                payload = ip.data.data if hasattr(ip.data, 'data') else b""
                for search_string in search_labels:
                    if search_string.encode() in payload:
                        match_counts[search_string] += 1

        except Exception as e:
            print(f"Error processing packet: {e}", file=sys.stderr)

        return match_counts, total_packets

    def chunked_read(self, chunk_size: int) -> Iterator[List[Tuple[float, bytes]]]:
        """
        Reads the pcap file in chunks of specified size.

        Args:
            chunk_size (int): The number of packets to include in each chunk.

        Yields:
            Iterator[List[Tuple[float, bytes]]]: An iterator over chunks of packets,
            where each chunk is a list of tuples containing the timestamp and packet buffer.
        """

        with open(self.pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            chunk = []
            for ts, buf in pcap:
                chunk.append((ts, buf))
                if len(chunk) >= chunk_size:
                    yield chunk
                    chunk = []
            if chunk:
                yield chunk

    def analyze(self, search_labels: List[str], start_date: str = None, end_date: str = None) -> Tuple[Dict[str, int], int]:
        """
        Analyzes the pcap file to count occurrences of search strings within a specified time range.

        Args:
            search_labels (List[str]): A list of search strings to look for in the packet payloads.
            start_date (str, optional): The start timestamp in the format "YYYY-MM-DD HH:MM:SS.ffffff".
            end_date (str, optional): The end timestamp in the format "YYYY-MM-DD HH:MM:SS.ffffff".

        Returns:
            Tuple[Dict[str, int], int]: A dictionary with search strings as keys and their occurrence
            counts as values, and the total number of packets processed.
        """

        match_counts = {search_string: 0 for search_string in search_labels}
        total_packets = 0

        if isinstance(start_date, str):
            start_date = datetime.datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S.%f")
        if isinstance(end_date, str):
            end_date = datetime.datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S.%f")

        start_date = start_date or datetime.datetime.min
        end_date = end_date or datetime.datetime.max

        avg_packet_size = self.estimate_average_packet_size(sample_size=10000) or 1500
        num_cores = cpu_count()
        memory_per_core = psutil.virtual_memory().available * 0.95 / num_cores
        chunk_size = int(memory_per_core / avg_packet_size)

        with Pool(processes=num_cores) as pool:
            for chunk in self.chunked_read(chunk_size):
                filtered_chunk = [(ts, buf) for ts, buf in chunk if start_date <= datetime.datetime.fromtimestamp(ts) <= end_date]
                args = [(ts, buf, search_labels) for ts, buf in filtered_chunk]
                results = pool.map(self.process_packet, args)

                for packet_match_counts, chunk_total in results:
                    for search_string in search_labels:
                        match_counts[search_string] += packet_match_counts[search_string]
                    total_packets += chunk_total

        return match_counts
    

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
    
    def estimate_average_packet_size(self, sample_size: int = 10000) -> float:
        """
        Estimate the average packet size in the pcap file.

        This method reads packets from the specified pcap file and calculates the average size
        of the packets. It processes up to `sample_size` packets to compute this average.

        Args:
            sample_size (int): The maximum number of packets to process. Defaults to 10,000.

        Returns:
            float: The average packet size in bytes. Returns 0.0 if no packets are found.
        """

        total_size, count = 0, 0
        with open(self.pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for _, buf in pcap:
                total_size += len(buf)
                count += 1
                if count >= sample_size:
                    break
        return total_size / count if count else 0.0



# # Example usage
# analyzer = PacketAnalyzer("./pcap_files/7/King_capture.pcap")
# labels = ["UDP_FLOOD", "SYN_ATTACK", "MALWARE"]  # Example keywords
# start_date, end_date = analyzer.get_time_range()

# matched_packets = analyzer.analyze(search_labels=labels, start_date=start_date, end_date=end_date)

# print(f'Period: {start_date} -> {end_date}')
# print("Count of Packets with Matching Strings:")
# print(matched_packets)
