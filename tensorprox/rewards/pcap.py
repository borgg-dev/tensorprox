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

    def process_packet(self, args: Tuple[float, bytes, str]) -> Tuple[Dict[str, int], Dict[str, int], int, int]:
        ts, buf, search_string = args
        local_tcp_rates = defaultdict(int)
        local_udp_rates = defaultdict(int)
        total_packets = 0
        matched_packets = 0

        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                return local_tcp_rates, local_udp_rates, total_packets, matched_packets

            ip = eth.data
            total_packets += 1
            dt = datetime.datetime.fromtimestamp(ts)
            time_key = dt.strftime('%Y-%m-%d %H:%M:%S')

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                if hasattr(tcp, 'data') and search_string.encode() in tcp.data:
                    local_tcp_rates[time_key] += 1
                    matched_packets += 1
            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                if hasattr(udp, 'data') and search_string.encode() in udp.data:
                    local_udp_rates[time_key] += 1
                    matched_packets += 1
        except Exception as e:
            print(f"Error processing packet: {e}", file=sys.stderr)

        return local_tcp_rates, local_udp_rates, total_packets, matched_packets

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

    def analyze(self, search_string: str = None, start_date: str = None, end_date: str = None):
        tcp_rates = defaultdict(int)
        udp_rates = defaultdict(int)
        total_packets = 0
        matched_packets = 0

        if isinstance(start_date, str):
            start_date = datetime.datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
        if isinstance(end_date, str):
            end_date = datetime.datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")

        start_date = start_date or datetime.datetime.min
        end_date = end_date or datetime.datetime.max

        avg_packet_size = self.estimate_average_packet_size(sample_size=10000) or 1500
        num_cores = cpu_count()
        memory_per_core = psutil.virtual_memory().available * 0.95 / num_cores
        chunk_size = int(memory_per_core / avg_packet_size)

        with Pool(processes=num_cores) as pool:
            for chunk in self.chunked_read(chunk_size):
                filtered_chunk = [(ts, buf) for ts, buf in chunk if start_date <= datetime.datetime.fromtimestamp(ts) <= end_date]
                args = [(ts, buf, search_string) for ts, buf in filtered_chunk]
                results = pool.map(self.process_packet, args)
                for local_tcp_rates, local_udp_rates, chunk_total, chunk_matched in results:
                    for timestamp, count in local_tcp_rates.items():
                        tcp_rates[timestamp] += count
                    for timestamp, count in local_udp_rates.items():
                        udp_rates[timestamp] += count
                    total_packets += chunk_total
                    matched_packets += chunk_matched

        return self.get_dataframe_results(tcp_rates, udp_rates, total_packets)

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

    def get_dataframe_results(self, tcp_rates, udp_rates, total_packets):
        timestamps = sorted(set(tcp_rates.keys()).union(udp_rates.keys()))
        data = {"timestamp": timestamps, "tcp_packets/s": [], "udp_packets/s": []}

        for timestamp in timestamps:
            data["tcp_packets/s"].append(tcp_rates.get(timestamp, 0))
            data["udp_packets/s"].append(udp_rates.get(timestamp, 0))
        
        df = pd.DataFrame(data)
        total_tcp_packets = df["tcp_packets/s"].sum()
        total_udp_packets = df["udp_packets/s"].sum()
        
        return df, total_tcp_packets, total_udp_packets


analyzer = PacketAnalyzer("King_capture.pcap")
search_string=""
start_date="2025-02-21 15:10:00"
end_date="2025-02-21 23:15:00"
df, total_tcp_packets, total_udp_packets = analyzer.analyze(search_string=search_string,start_date=start_date, end_date=end_date)
print(f'Period : {start_date} -> {end_date}')
print(df)
print(f"Total TCP Packets with the Payload Substring : {total_tcp_packets}")
print(f"Total UDP Packets with the Payload Substring : {total_udp_packets}")
