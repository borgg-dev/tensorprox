#!/usr/bin/env python3
"""
High-Volume Traffic Generator for TensorProx Load Testing
Generates sustained traffic at configurable bandwidth across multiple ports
"""

import argparse
import socket
import threading
import time
import random
import string
import signal
import sys
from dataclasses import dataclass
from typing import List, Dict
from datetime import datetime

# Global flag for graceful shutdown
running = True


@dataclass
class PortConfig:
    port: int
    protocol: str  # 'tcp' or 'udp'
    name: str


@dataclass
class TrafficStats:
    bytes_sent: int = 0
    packets_sent: int = 0
    errors: int = 0
    start_time: float = 0


class TrafficGenerator:
    """High-volume traffic generator for load testing"""

    def __init__(
        self,
        target_ip: str,
        ports: List[PortConfig],
        target_mbps: float = 50.0,
        payload_size: int = 8192,
    ):
        self.target_ip = target_ip
        self.ports = ports
        self.target_mbps = target_mbps
        self.payload_size = payload_size
        self.stats: Dict[int, TrafficStats] = {}
        self.threads: List[threading.Thread] = []
        self.lock = threading.Lock()

        # Pre-generate payloads for efficiency
        self.tcp_payload = self._generate_payload(payload_size)
        self.udp_payload = self._generate_payload(min(payload_size, 65000))

        # Calculate target bytes per second per port
        total_bytes_per_sec = (target_mbps * 1_000_000) / 8
        self.bytes_per_port_per_sec = total_bytes_per_sec / len(ports)

    def _generate_payload(self, size: int) -> bytes:
        """Generate random payload data"""
        return "".join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

    def log(self, message: str):
        """Thread-safe logging"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] {message}", flush=True)

    def _tcp_sender(self, port_config: PortConfig):
        """TCP traffic sender thread"""
        global running
        port = port_config.port
        stats = self.stats[port]
        stats.start_time = time.time()

        target_pps = self.bytes_per_port_per_sec / self.payload_size
        interval = 1.0 / target_pps if target_pps > 0 else 0.001

        while running:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.connect((self.target_ip, port))

                # Send continuously on this connection
                while running:
                    try:
                        sent = sock.send(self.tcp_payload)
                        with self.lock:
                            stats.bytes_sent += sent
                            stats.packets_sent += 1

                        # Minimal delay to achieve target rate
                        if interval > 0.0001:
                            time.sleep(interval * 0.5)

                    except (socket.error, BrokenPipeError):
                        break

            except socket.error as e:
                with self.lock:
                    stats.errors += 1
                time.sleep(0.1)

            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass

    def _udp_sender(self, port_config: PortConfig):
        """UDP traffic sender thread"""
        global running
        port = port_config.port
        stats = self.stats[port]
        stats.start_time = time.time()

        target_pps = self.bytes_per_port_per_sec / len(self.udp_payload)
        interval = 1.0 / target_pps if target_pps > 0 else 0.001

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        while running:
            try:
                sent = sock.sendto(self.udp_payload, (self.target_ip, port))
                with self.lock:
                    stats.bytes_sent += sent
                    stats.packets_sent += 1

                if interval > 0.0001:
                    time.sleep(interval * 0.5)

            except socket.error:
                with self.lock:
                    stats.errors += 1
                time.sleep(0.01)

        sock.close()

    def _stats_reporter(self):
        """Periodic stats reporting thread"""
        global running
        last_stats: Dict[int, tuple] = {}

        while running:
            time.sleep(5)
            if not running:
                break

            total_mbps = 0
            total_pps = 0

            print("\n" + "=" * 70)
            print(f"{'Port':<8} {'Protocol':<8} {'Mbps':<12} {'PPS':<12} {'Sent':<15} {'Errors':<8}")
            print("-" * 70)

            for port_config in self.ports:
                port = port_config.port
                stats = self.stats[port]

                with self.lock:
                    current_bytes = stats.bytes_sent
                    current_packets = stats.packets_sent
                    errors = stats.errors

                # Calculate rates
                last = last_stats.get(port, (0, 0, time.time()))
                elapsed = time.time() - last[2]

                if elapsed > 0:
                    bytes_delta = current_bytes - last[0]
                    packets_delta = current_packets - last[1]
                    mbps = (bytes_delta * 8) / (elapsed * 1_000_000)
                    pps = packets_delta / elapsed
                else:
                    mbps = 0
                    pps = 0

                total_mbps += mbps
                total_pps += pps

                last_stats[port] = (current_bytes, current_packets, time.time())

                print(
                    f"{port:<8} {port_config.protocol.upper():<8} {mbps:<12.2f} "
                    f"{int(pps):<12} {current_bytes:<15,} {errors:<8}"
                )

            print("-" * 70)
            print(f"{'TOTAL':<16} {total_mbps:<12.2f} {int(total_pps):<12}")
            print(f"Target: {self.target_mbps} Mbps | Actual: {total_mbps:.2f} Mbps")
            print("=" * 70 + "\n")

    def start(self):
        """Start all traffic generators"""
        global running
        running = True

        self.log(f"Starting load generator targeting {self.target_ip}")
        self.log(f"Target bandwidth: {self.target_mbps} Mbps across {len(self.ports)} ports")
        self.log(f"Payload size: TCP={len(self.tcp_payload)}B, UDP={len(self.udp_payload)}B")

        # Initialize stats and start sender threads
        for port_config in self.ports:
            self.stats[port_config.port] = TrafficStats()

            if port_config.protocol == "tcp":
                # Multiple TCP threads per port for higher throughput
                for i in range(3):
                    t = threading.Thread(
                        target=self._tcp_sender,
                        args=(port_config,),
                        name=f"TCP-{port_config.port}-{i}",
                        daemon=True,
                    )
                    t.start()
                    self.threads.append(t)
            else:
                t = threading.Thread(
                    target=self._udp_sender,
                    args=(port_config,),
                    name=f"UDP-{port_config.port}",
                    daemon=True,
                )
                t.start()
                self.threads.append(t)

            self.log(f"Started {port_config.protocol.upper()} sender on port {port_config.port}")

        # Start stats reporter
        stats_thread = threading.Thread(target=self._stats_reporter, daemon=True)
        stats_thread.start()
        self.threads.append(stats_thread)

        self.log("All senders started. Press Ctrl+C to stop.")

    def stop(self):
        """Stop all traffic generators"""
        global running
        running = False
        self.log("Stopping traffic generators...")

        # Wait for threads to finish
        for t in self.threads:
            t.join(timeout=2)

        # Print final stats
        total_bytes = sum(s.bytes_sent for s in self.stats.values())
        total_packets = sum(s.packets_sent for s in self.stats.values())
        total_errors = sum(s.errors for s in self.stats.values())

        self.log(f"Final stats: {total_bytes:,} bytes, {total_packets:,} packets, {total_errors} errors")

    def run_forever(self):
        """Run until interrupted"""
        self.start()
        try:
            while running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


def signal_handler(signum, frame):
    """Handle interrupt signals"""
    global running
    running = False


def main():
    parser = argparse.ArgumentParser(description="High-volume traffic generator for load testing")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument(
        "--tcp-ports",
        nargs="+",
        type=int,
        default=[8080, 9001, 9003],
        help="TCP ports to target",
    )
    parser.add_argument(
        "--udp-ports",
        nargs="+",
        type=int,
        default=[9101, 9102, 9103],
        help="UDP ports to target",
    )
    parser.add_argument(
        "--mbps",
        type=float,
        default=50.0,
        help="Target bandwidth in Mbps (default: 50)",
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=8192,
        help="Payload size in bytes (default: 8192)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Duration in seconds (0=infinite, default: 0)",
    )

    args = parser.parse_args()

    # Build port configurations
    ports: List[PortConfig] = []
    for port in args.tcp_ports:
        ports.append(PortConfig(port=port, protocol="tcp", name=f"TCP-{port}"))
    for port in args.udp_ports:
        ports.append(PortConfig(port=port, protocol="udp", name=f"UDP-{port}"))

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    generator = TrafficGenerator(
        target_ip=args.target_ip,
        ports=ports,
        target_mbps=args.mbps,
        payload_size=args.payload_size,
    )

    if args.duration > 0:
        generator.start()
        time.sleep(args.duration)
        generator.stop()
    else:
        generator.run_forever()


if __name__ == "__main__":
    main()
