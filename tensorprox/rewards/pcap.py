import dpkt
import datetime
import sys
import psutil
import pandas as pd
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from typing import Dict, Tuple, List, Iterator


class PacketAnalyzer:
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file

    def get_time_range(self) -> Tuple[str, str]:
        """Extract the start and end timestamps from the pcap file."""
        with open(self.pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            timestamps = [ts for ts, _ in pcap]

        if timestamps:
            start_date = datetime.datetime.fromtimestamp(timestamps[0]).strftime("%Y-%m-%d %H:%M:%S.%f")
            end_date = datetime.datetime.fromtimestamp(timestamps[-1]).strftime("%Y-%m-%d %H:%M:%S.%f")
            return start_date, end_date
        return None, None

    def process_packet(self, args: Tuple[float, bytes, List[str]]) -> Tuple[Dict[str, int], int]:
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

    def estimate_average_packet_size(self, sample_size: int = 10000) -> float:
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
