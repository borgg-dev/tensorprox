#!/usr/bin/env python3
"""
Origin Test Client - Automated Testing for TensorProx Origin Servers
Tests all 6 Origin server applications with RTT/latency measurements
"""

import argparse
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

@dataclass
class TestConfig:
    """Test configuration parameters"""
    origin_ip: str
    tcp_echo_port: int = 7001
    tcp_http_port: int = 7080
    tcp_custom_port: int = 7003
    udp_echo_port: int = 7101
    udp_dgram_port: int = 7102
    udp_custom_port: int = 7103
    test_duration: int = 60  # seconds
    icmp_count: int = 10
    tcp_iterations: int = 10
    udp_iterations: int = 10

@dataclass
class TestResult:
    """Individual test result"""
    service: str
    protocol: str
    port: int
    success: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    details: Optional[Dict] = None

@dataclass
class TestSummary:
    """Complete test run summary"""
    timestamp: str
    origin_ip: str
    duration: float
    icmp_rtt: Optional[Dict] = None
    tcp_results: List[TestResult] = None
    udp_results: List[TestResult] = None
    overall_success: bool = True

class OriginTestClient:
    """Automated test client for Origin servers"""

    def __init__(self, config: TestConfig):
        self.config = config
        self.results = []
        self.start_time = None
        self.end_time = None

    def log(self, message: str):
        """Log with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] {message}")

    def test_icmp_rtt(self) -> Dict:
        """Test ICMP RTT using ping for configured duration"""
        self.log(f"Testing ICMP RTT to {self.config.origin_ip} for {self.config.test_duration}s...")

        try:
            # Calculate ping count based on duration (1 ping per second) unless overridden
            ping_count = self.config.icmp_count or self.config.test_duration
            result = subprocess.run(
                ['ping', '-c', str(ping_count), '-W', '2', '-i', '1', self.config.origin_ip],
                capture_output=True,
                text=True,
                timeout=self.config.test_duration + 10
            )

            # Parse output robustly
            lines = result.stdout.split('\n')

            # Find packet summary line: "X packets transmitted, Y received, Z% packet loss"
            summary_line = [l for l in lines if 'packets transmitted' in l and 'received' in l]
            if not summary_line:
                return {'success': False, 'error': 'Could not parse packet summary'}

            # Extract packet counts
            import re
            summary = summary_line[0]
            match = re.search(r'(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss', summary)
            if not match:
                return {'success': False, 'error': 'Could not parse packet counts'}

            packets_sent = int(match.group(1))
            packets_received = int(match.group(2))
            packet_loss_pct = float(match.group(3))

            # Find RTT statistics line
            rtt_line = [l for l in lines if 'rtt min/avg/max/mdev' in l or 'min/avg/max' in l]
            if not rtt_line:
                return {'success': False, 'error': 'Could not parse RTT statistics'}

            # Extract RTT values: rtt min/avg/max/mdev = 0.123/0.456/0.789/0.111 ms
            rtt_match = re.search(r'=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', rtt_line[0])
            if not rtt_match:
                return {'success': False, 'error': 'Could not parse RTT values'}

            icmp_data = {
                'success': True,
                'packets_sent': packets_sent,
                'packets_received': packets_received,
                'packet_loss_pct': packet_loss_pct,
                'rtt_min_ms': float(rtt_match.group(1)),
                'rtt_avg_ms': float(rtt_match.group(2)),
                'rtt_max_ms': float(rtt_match.group(3)),
                'rtt_mdev_ms': float(rtt_match.group(4))
            }

            self.log(f"ICMP RTT - Sent: {packets_sent}, Received: {packets_received}, "
                    f"Loss: {packet_loss_pct}%, "
                    f"Min: {icmp_data['rtt_min_ms']:.3f}ms, "
                    f"Avg: {icmp_data['rtt_avg_ms']:.3f}ms, "
                    f"Max: {icmp_data['rtt_max_ms']:.3f}ms")

            return icmp_data

        except subprocess.TimeoutExpired:
            self.log(f"ICMP test completed (timeout after {self.config.test_duration}s)")
            # Try to parse partial output
            return {'success': False, 'error': 'Test duration expired'}
        except Exception as e:
            self.log(f"ICMP test error: {e}")
            return {'success': False, 'error': str(e)}

    def test_tcp_echo(self) -> TestResult:
        """Test TCP Echo server with latency measurement (persistent connection)"""
        self.log(f"Testing TCP Echo server on port {self.config.tcp_echo_port} for {self.config.test_duration}s...")

        latencies = []
        start_time = time.time()
        iteration = 0

        try:
            # Establish persistent connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.config.origin_ip, self.config.tcp_echo_port))

            # Run tests until duration expires
            while (time.time() - start_time) < self.config.test_duration:
                iteration += 1

                # Time only the send→receive cycle (request/response latency)
                test_data = f"TEST_ECHO_{iteration}_{time.time()}".encode('utf-8')

                send_start = time.time()
                sock.sendall(test_data)
                response = sock.recv(4096)
                latency = (time.time() - send_start) * 1000  # ms

                latencies.append(latency)

                if response != test_data:
                    raise Exception(f"Echo mismatch: sent {len(test_data)} bytes, got {len(response)} bytes")

                # Small delay to avoid flooding
                time.sleep(0.1)

            sock.close()

            avg_latency = statistics.mean(latencies)
            self.log(f"TCP Echo - Success. {iteration} iterations, Avg latency: {avg_latency:.3f}ms")

            return TestResult(
                service="TCP Echo",
                protocol="TCP",
                port=self.config.tcp_echo_port,
                success=True,
                latency_ms=avg_latency,
                details={
                    'iterations': iteration,
                    'duration_seconds': self.config.test_duration,
                    'min_latency_ms': min(latencies),
                    'max_latency_ms': max(latencies),
                    'stddev_ms': statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
                    'all_latencies': latencies
                }
            )

        except Exception as e:
            self.log(f"TCP Echo - Failed: {e}")
            return TestResult(
                service="TCP Echo",
                protocol="TCP",
                port=self.config.tcp_echo_port,
                success=False,
                error=str(e)
            )

    def test_tcp_http(self) -> TestResult:
        """Test TCP HTTP server with latency measurement (persistent connection)"""
        self.log(f"Testing TCP HTTP server on port {self.config.tcp_http_port} for {self.config.test_duration}s...")

        latencies = []
        start_time = time.time()
        iteration = 0

        try:
            # Run tests until duration expires (HTTP 1.1 keep-alive)
            while (time.time() - start_time) < self.config.test_duration:
                iteration += 1

                # New connection per iteration (HTTP semantics)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.config.origin_ip, self.config.tcp_http_port))

                request = f"GET / HTTP/1.1\r\nHost: {self.config.origin_ip}\r\nConnection: close\r\n\r\n"

                send_start = time.time()
                sock.sendall(request.encode('utf-8'))

                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                latency = (time.time() - send_start) * 1000  # ms
                latencies.append(latency)

                sock.close()

                if b"HTTP/1.1 200 OK" not in response and b'"status":"ok"' not in response:
                    raise Exception("Invalid HTTP response")

                # Small delay
                time.sleep(0.1)

            avg_latency = statistics.mean(latencies)
            self.log(f"TCP HTTP - Success. {iteration} iterations, Avg latency: {avg_latency:.3f}ms")

            return TestResult(
                service="TCP HTTP",
                protocol="TCP",
                port=self.config.tcp_http_port,
                success=True,
                latency_ms=avg_latency,
                details={
                    'iterations': iteration,
                    'duration_seconds': self.config.test_duration,
                    'min_latency_ms': min(latencies),
                    'max_latency_ms': max(latencies),
                    'stddev_ms': statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
                    'all_latencies': latencies
                }
            )

        except Exception as e:
            self.log(f"TCP HTTP - Failed: {e}")
            return TestResult(
                service="TCP HTTP",
                protocol="TCP",
                port=self.config.tcp_http_port,
                success=False,
                error=str(e)
            )

    def test_tcp_custom(self) -> TestResult:
        """Test TCP Custom protocol server with latency measurement (persistent connection)"""
        self.log(f"Testing TCP Custom server on port {self.config.tcp_custom_port} for {self.config.test_duration}s...")

        latencies = []
        commands = ['PING', 'TIME', 'INFO']
        start_time = time.time()
        iteration = 0

        try:
            # Establish persistent connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.config.origin_ip, self.config.tcp_custom_port))

            # Read welcome message
            welcome = sock.recv(4096).decode('utf-8')

            # Run tests until duration expires
            while (time.time() - start_time) < self.config.test_duration:
                iteration += 1

                # Time only the command→response cycle
                command = commands[iteration % len(commands)]

                send_start = time.time()
                sock.sendall(f"{command}\n".encode('utf-8'))
                response = sock.recv(4096).decode('utf-8')
                latency = (time.time() - send_start) * 1000  # ms

                latencies.append(latency)

                if '"status"' not in response:
                    raise Exception("Invalid JSON response")

                # Small delay
                time.sleep(0.1)

            # Send QUIT
            sock.sendall(b"QUIT\n")
            sock.recv(4096)  # Read goodbye
            sock.close()

            avg_latency = statistics.mean(latencies)
            self.log(f"TCP Custom - Success. {iteration} iterations, Avg latency: {avg_latency:.3f}ms")

            return TestResult(
                service="TCP Custom",
                protocol="TCP",
                port=self.config.tcp_custom_port,
                success=True,
                latency_ms=avg_latency,
                details={
                    'iterations': iteration,
                    'duration_seconds': self.config.test_duration,
                    'commands_tested': commands,
                    'min_latency_ms': min(latencies),
                    'max_latency_ms': max(latencies),
                    'stddev_ms': statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
                    'all_latencies': latencies
                }
            )

        except Exception as e:
            self.log(f"TCP Custom - Failed: {e}")
            return TestResult(
                service="TCP Custom",
                protocol="TCP",
                port=self.config.tcp_custom_port,
                success=False,
                error=str(e)
            )

    def test_udp_echo(self) -> TestResult:
        """Test UDP Echo server with latency measurement"""
        self.log(f"Testing UDP Echo server on port {self.config.udp_echo_port} for {self.config.test_duration}s...")

        latencies = []
        start_time = time.time()
        iteration = 0

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            # Run tests until duration expires
            while (time.time() - start_time) < self.config.test_duration:
                iteration += 1

                send_start = time.time()
                test_data = f"UDP_ECHO_TEST_{iteration}_{time.time()}".encode('utf-8')
                sock.sendto(test_data, (self.config.origin_ip, self.config.udp_echo_port))

                response, addr = sock.recvfrom(4096)
                latency = (time.time() - send_start) * 1000  # ms

                latencies.append(latency)

                if response != test_data:
                    raise Exception(f"Echo mismatch")

                # Small delay
                time.sleep(0.1)

            sock.close()

            avg_latency = statistics.mean(latencies)
            self.log(f"UDP Echo - Success. {iteration} iterations, Avg latency: {avg_latency:.3f}ms")

            return TestResult(
                service="UDP Echo",
                protocol="UDP",
                port=self.config.udp_echo_port,
                success=True,
                latency_ms=avg_latency,
                details={
                    'iterations': iteration,
                    'duration_seconds': self.config.test_duration,
                    'min_latency_ms': min(latencies),
                    'max_latency_ms': max(latencies),
                    'stddev_ms': statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
                    'all_latencies': latencies
                }
            )

        except Exception as e:
            self.log(f"UDP Echo - Failed: {e}")
            return TestResult(
                service="UDP Echo",
                protocol="UDP",
                port=self.config.udp_echo_port,
                success=False,
                error=str(e)
            )

    def test_udp_dgram(self) -> TestResult:
        """Test UDP Datagram server with latency measurement"""
        self.log(f"Testing UDP Datagram server on port {self.config.udp_dgram_port} for {self.config.test_duration}s...")

        latencies = []
        start_time = time.time()
        iteration = 0

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            # Run tests until duration expires
            while (time.time() - start_time) < self.config.test_duration:
                iteration += 1

                send_start = time.time()
                test_data = f"UDP_DGRAM_TEST_{iteration}".encode('utf-8')
                sock.sendto(test_data, (self.config.origin_ip, self.config.udp_dgram_port))

                response, addr = sock.recvfrom(4096)
                latency = (time.time() - send_start) * 1000  # ms

                latencies.append(latency)

                # Response format: ACK:<count>:<timestamp>:<bytes>
                if not response.decode('utf-8').startswith('ACK:'):
                    raise Exception(f"Invalid ACK format")

                # Small delay
                time.sleep(0.1)

            sock.close()

            avg_latency = statistics.mean(latencies)
            self.log(f"UDP Datagram - Success. {iteration} iterations, Avg latency: {avg_latency:.3f}ms")

            return TestResult(
                service="UDP Datagram",
                protocol="UDP",
                port=self.config.udp_dgram_port,
                success=True,
                latency_ms=avg_latency,
                details={
                    'iterations': iteration,
                    'duration_seconds': self.config.test_duration,
                    'min_latency_ms': min(latencies),
                    'max_latency_ms': max(latencies),
                    'stddev_ms': statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
                    'all_latencies': latencies
                }
            )

        except Exception as e:
            self.log(f"UDP Datagram - Failed: {e}")
            return TestResult(
                service="UDP Datagram",
                protocol="UDP",
                port=self.config.udp_dgram_port,
                success=False,
                error=str(e)
            )

    def test_udp_custom(self) -> TestResult:
        """Test UDP Custom protocol server with latency measurement"""
        self.log(f"Testing UDP Custom server on port {self.config.udp_custom_port} for {self.config.test_duration}s...")

        latencies = []
        commands = ['PING', 'TIME', 'STATUS', 'HELLO']
        start_time = time.time()
        iteration = 0

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            # Run tests until duration expires
            while (time.time() - start_time) < self.config.test_duration:
                iteration += 1

                command = commands[iteration % len(commands)]

                send_start = time.time()
                sock.sendto(command.encode('utf-8'), (self.config.origin_ip, self.config.udp_custom_port))

                response, addr = sock.recvfrom(4096)
                latency = (time.time() - send_start) * 1000  # ms

                latencies.append(latency)

                # Response should be JSON
                json_response = json.loads(response.decode('utf-8'))
                if 'status' not in json_response:
                    raise Exception("Invalid JSON response")

                # Small delay
                time.sleep(0.1)

            sock.close()

            avg_latency = statistics.mean(latencies)
            self.log(f"UDP Custom - Success. {iteration} iterations, Avg latency: {avg_latency:.3f}ms")

            return TestResult(
                service="UDP Custom",
                protocol="UDP",
                port=self.config.udp_custom_port,
                success=True,
                latency_ms=avg_latency,
                details={
                    'iterations': iteration,
                    'duration_seconds': self.config.test_duration,
                    'commands_tested': commands,
                    'min_latency_ms': min(latencies),
                    'max_latency_ms': max(latencies),
                    'stddev_ms': statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
                    'all_latencies': latencies
                }
            )

        except Exception as e:
            self.log(f"UDP Custom - Failed: {e}")
            return TestResult(
                service="UDP Custom",
                protocol="UDP",
                port=self.config.udp_custom_port,
                success=False,
                error=str(e)
            )

    def run_all_tests(self) -> TestSummary:
        """Run complete test suite"""
        self.log("="*60)
        self.log("Origin Test Client - Starting Test Suite")
        self.log(f"Target: {self.config.origin_ip}")
        self.log(f"Duration: {self.config.test_duration}s")
        self.log("="*60)

        self.start_time = time.time()

        # ICMP RTT Test
        icmp_result = self.test_icmp_rtt()

        # TCP Tests
        tcp_results = [
            self.test_tcp_echo(),
            self.test_tcp_http(),
            self.test_tcp_custom()
        ]

        # UDP Tests
        udp_results = [
            self.test_udp_echo(),
            self.test_udp_dgram(),
            self.test_udp_custom()
        ]

        self.end_time = time.time()
        duration = self.end_time - self.start_time

        # Check overall success
        all_tcp_ok = all(r.success for r in tcp_results)
        all_udp_ok = all(r.success for r in udp_results)
        overall_success = all_tcp_ok and all_udp_ok and icmp_result.get('success', False)

        summary = TestSummary(
            timestamp=datetime.now().isoformat(),
            origin_ip=self.config.origin_ip,
            duration=duration,
            icmp_rtt=icmp_result,
            tcp_results=tcp_results,
            udp_results=udp_results,
            overall_success=overall_success
        )

        self.log("="*60)
        self.log("Test Suite Complete")
        self.log(f"Duration: {duration:.2f}s")
        self.log(f"Overall Status: {'SUCCESS' if overall_success else 'FAILED'}")
        self.log("="*60)

        return summary

    def save_results(self, summary: TestSummary, filename: str):
        """Save results to timestamped log file"""

        # Create detailed output
        output = {
            'test_run': {
                'timestamp': summary.timestamp,
                'origin_ip': summary.origin_ip,
                'duration_seconds': summary.duration,
                'overall_success': summary.overall_success
            },
            'icmp_rtt': summary.icmp_rtt,
            'tcp_tests': [],
            'udp_tests': []
        }

        # Add TCP results
        for result in summary.tcp_results:
            output['tcp_tests'].append({
                'service': result.service,
                'port': result.port,
                'success': result.success,
                'latency_ms': result.latency_ms,
                'error': result.error,
                'details': result.details
            })

        # Add UDP results
        for result in summary.udp_results:
            output['udp_tests'].append({
                'service': result.service,
                'port': result.port,
                'success': result.success,
                'latency_ms': result.latency_ms,
                'error': result.error,
                'details': result.details
            })

        # Save JSON
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)

        self.log(f"Results saved to: {filename}")

def _normalize_ports(values: Optional[List[int]], defaults: List[int]) -> List[int]:
    if not values:
        return defaults
    cleaned = [int(v) for v in values if v is not None]
    # Pad or trim to match defaults length
    if len(cleaned) < len(defaults):
        cleaned.extend(defaults[len(cleaned):])
    return cleaned[:len(defaults)]


def _determine_output_path(origin_ip: str, explicit_path: Optional[str], explicit_dir: Optional[str]) -> str:
    if explicit_path:
        parent = os.path.dirname(explicit_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        return explicit_path

    base_dir = explicit_dir
    if not base_dir:
        base_dir = "/root/test_results" if os.access("/root", os.W_OK) else "/tmp/test_results"

    os.makedirs(base_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"test_results_{origin_ip.replace('.', '_')}_{timestamp}.json"
    return os.path.join(base_dir, filename)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Origin validation traffic generator")
    parser.add_argument("origin_ip", help="Origin public IP/EIP to target")
    parser.add_argument("--duration", type=int, default=60, help="Duration per test (seconds)")
    parser.add_argument("--tcp-ports", nargs="*", type=int, help="Override TCP ports (echo,http,custom)")
    parser.add_argument("--udp-ports", nargs="*", type=int, help="Override UDP ports (echo,datagram,custom)")
    parser.add_argument("--icmp-count", type=int, default=10, help="Number of ICMP probes (default 10)")
    parser.add_argument("--tcp-iterations", type=int, default=10, help="Max TCP iterations per test window")
    parser.add_argument("--udp-iterations", type=int, default=10, help="Max UDP iterations per test window")
    parser.add_argument("--json-out", help="Explicit JSON output path")
    parser.add_argument("--results-dir", help="Directory for JSON output (default: /root/test_results or /tmp)")
    parser.add_argument("--summary-marker", action="store_true", help="Print final summary prefixed with ###RESULT###")

    args = parser.parse_args()

    default_tcp = [TestConfig.tcp_echo_port, TestConfig.tcp_http_port, TestConfig.tcp_custom_port]
    default_udp = [TestConfig.udp_echo_port, TestConfig.udp_dgram_port, TestConfig.udp_custom_port]
    tcp_ports = _normalize_ports(args.tcp_ports, default_tcp)
    udp_ports = _normalize_ports(args.udp_ports, default_udp)

    config = TestConfig(
        origin_ip=args.origin_ip,
        test_duration=args.duration,
        tcp_echo_port=tcp_ports[0],
        tcp_http_port=tcp_ports[1],
        tcp_custom_port=tcp_ports[2],
        udp_echo_port=udp_ports[0],
        udp_dgram_port=udp_ports[1],
        udp_custom_port=udp_ports[2],
        icmp_count=args.icmp_count,
        tcp_iterations=args.tcp_iterations,
        udp_iterations=args.udp_iterations,
    )

    client = OriginTestClient(config)
    summary = client.run_all_tests()

    output_path = _determine_output_path(args.origin_ip, args.json_out, args.results_dir)
    client.save_results(summary, output_path)

    if args.summary_marker:
        print("###RESULT###" + json.dumps(asdict(summary)), flush=True)

    sys.exit(0 if summary.overall_success else 1)

if __name__ == '__main__':
    main()
