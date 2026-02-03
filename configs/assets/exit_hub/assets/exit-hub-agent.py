#!/usr/bin/env python3
"""
Exit Hub Volume & XDP Metrics Reporting Agent

This agent runs on exit hubs and reports volume and XDP metrics to TPM.
The data is used for:
1. Volume verification (detect scrubber manipulation)
2. Production audit (track real traffic through scrubbers)

Key Design:
- Reads from Linux interface statistics (basic counters)
- Reads from XDP BPF maps (detailed packet metrics)
- Reports to TPM via Redis channel
- Exit hubs are TPM-managed infrastructure (trusted source)
- XDP metrics cannot be gamed by miners - they're from TPM-owned infrastructure

Data Flow:
  Client -> Scrubber -> WireGuard -> Exit Hub -> Origin
                           |              |
                    traffic flows    XDP metrics
                           |              |
                    exit-hub-agent ----+
                           |
                          TPM
"""

import json
import os
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

# Configuration
TPM_HOST = os.getenv("TPM_HOST", "localhost")
TPM_PORT = int(os.getenv("TPM_PORT", "6379"))
TPM_PASSWORD = os.getenv("TPM_PASSWORD", "")  # Redis password (optional)
REPORT_INTERVAL = int(os.getenv("REPORT_INTERVAL", "60"))  # seconds
EXIT_HUB_ID = os.getenv("EXIT_HUB_ID", "")
ORIGIN_ID = os.getenv("ORIGIN_ID", "")
MINER_ID = os.getenv("MINER_ID", "")

# Redis channels
VOLUME_CHANNEL = "exithub.volume"
METRICS_CHANNEL = "exithub.xdp_metrics"  # Production metrics for validator

# XDP BPF map paths
XDP_ORIGIN_METRICS_MAP = "/sys/fs/bpf/xdp/globals/origin_metrics_map"
XDP_GLOBAL_METRICS_MAP = "/sys/fs/bpf/xdp/globals/global_metrics_map"
XDP_MONITORED_ORIGINS_MAP = "/sys/fs/bpf/xdp/globals/monitored_origins_map"

# Interface patterns to monitor
# wg-miner-* is used on scrubbers (from scrubber's perspective)
# wgO* is used on exit hubs (e.g., wgO91 for origin O91)
WG_INTERFACE_PATTERNS = ["wgO", "wg-miner-"]
ETH_INTERFACE_PATTERN = "eth"


@dataclass
class InterfaceStats:
    """Statistics for a network interface."""
    interface: str
    rx_bytes: int
    rx_packets: int
    tx_bytes: int
    tx_packets: int


def read_interface_stats(interface: str) -> Optional[InterfaceStats]:
    """Read statistics for a network interface from sysfs."""
    base_path = Path(f"/sys/class/net/{interface}/statistics")

    if not base_path.exists():
        return None

    try:
        rx_bytes = int((base_path / "rx_bytes").read_text().strip())
        rx_packets = int((base_path / "rx_packets").read_text().strip())
        tx_bytes = int((base_path / "tx_bytes").read_text().strip())
        tx_packets = int((base_path / "tx_packets").read_text().strip())

        return InterfaceStats(
            interface=interface,
            rx_bytes=rx_bytes,
            rx_packets=rx_packets,
            tx_bytes=tx_bytes,
            tx_packets=tx_packets,
        )
    except Exception as e:
        print(f"Error reading stats for {interface}: {e}", file=sys.stderr)
        return None


def get_wireguard_interfaces() -> List[str]:
    """Get list of WireGuard interfaces (tunnels from scrubbers)."""
    interfaces = []
    net_path = Path("/sys/class/net")

    if not net_path.exists():
        return interfaces

    for iface_path in net_path.iterdir():
        iface_name = iface_path.name
        # Check if interface matches any WireGuard pattern
        for pattern in WG_INTERFACE_PATTERNS:
            if iface_name.startswith(pattern):
                interfaces.append(iface_name)
                break

    return interfaces


def get_all_wg_stats() -> Dict[str, InterfaceStats]:
    """Get statistics for all WireGuard interfaces."""
    stats = {}

    for iface in get_wireguard_interfaces():
        iface_stats = read_interface_stats(iface)
        if iface_stats:
            stats[iface] = iface_stats

    return stats


# ============================================================================
# XDP Metrics Functions (Production Audit Ground Truth)
# ============================================================================

@dataclass
class XDPOriginMetrics:
    """Per-origin XDP metrics from BPF map."""
    origin_ip: str
    packets_in: int
    packets_out: int
    bytes_in: int
    bytes_out: int
    syn_count: int
    synack_count: int
    fin_count: int
    rst_count: int
    ack_count: int
    data_packets: int


@dataclass
class XDPGlobalMetrics:
    """Global XDP metrics from BPF map."""
    total_packets: int
    total_bytes: int
    total_syn: int
    total_synack: int
    xdp_pass: int
    xdp_drop: int
    parse_errors: int


def ip_bytes_to_str(ip_bytes: bytes) -> str:
    """Convert 4-byte IP to dotted string (big-endian/network order)."""
    if len(ip_bytes) != 4:
        return ""
    return f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"


def ip_str_to_bytes(ip_str: str) -> bytes:
    """Convert dotted IP string to 4-byte (big-endian/network order)."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return b""
    return bytes([int(p) for p in parts])


def read_xdp_origin_metrics() -> Dict[str, XDPOriginMetrics]:
    """Read per-origin XDP metrics from BPF map using bpftool."""
    metrics = {}

    if not os.path.exists(XDP_ORIGIN_METRICS_MAP):
        return metrics

    try:
        result = subprocess.run(
            ["bpftool", "map", "dump", "pinned", XDP_ORIGIN_METRICS_MAP, "-j"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            print(f"bpftool error: {result.stderr}", file=sys.stderr)
            return metrics

        # Parse JSON output
        entries = json.loads(result.stdout)

        for entry in entries:
            # Key is origin IP (4 bytes, network order)
            # bpftool may return hex strings like ["0xac","0xe8",...] or integers
            key_raw = entry.get("key", [])
            if key_raw and isinstance(key_raw[0], str):
                key_bytes = bytes([int(x, 16) for x in key_raw])
            else:
                key_bytes = bytes(key_raw)
            origin_ip = ip_bytes_to_str(key_bytes)

            if not origin_ip:
                continue

            # Value is struct origin_metrics (all u64 fields)
            value = entry.get("value", {})

            # bpftool returns values as hex strings or arrays
            # Parse the struct fields (11 x u64 = 88 bytes)
            if isinstance(value, list):
                # Raw bytes - parse as little-endian u64s
                # bpftool may return hex strings like ["0x88","0x05",...] or integers
                if value and isinstance(value[0], str):
                    raw = bytes([int(x, 16) for x in value])
                else:
                    raw = bytes(value)
                if len(raw) >= 88:
                    import struct
                    fields = struct.unpack("<11Q", raw[:88])
                    metrics[origin_ip] = XDPOriginMetrics(
                        origin_ip=origin_ip,
                        packets_in=fields[0],
                        packets_out=fields[1],
                        bytes_in=fields[2],
                        bytes_out=fields[3],
                        syn_count=fields[4],
                        synack_count=fields[5],
                        fin_count=fields[6],
                        rst_count=fields[7],
                        ack_count=fields[8],
                        data_packets=fields[9],
                    )
            elif isinstance(value, dict):
                # Formatted output
                metrics[origin_ip] = XDPOriginMetrics(
                    origin_ip=origin_ip,
                    packets_in=value.get("packets_in", 0),
                    packets_out=value.get("packets_out", 0),
                    bytes_in=value.get("bytes_in", 0),
                    bytes_out=value.get("bytes_out", 0),
                    syn_count=value.get("syn_count", 0),
                    synack_count=value.get("synack_count", 0),
                    fin_count=value.get("fin_count", 0),
                    rst_count=value.get("rst_count", 0),
                    ack_count=value.get("ack_count", 0),
                    data_packets=value.get("data_packets", 0),
                )

    except subprocess.TimeoutExpired:
        print("bpftool timeout", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"JSON parse error: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Error reading XDP metrics: {e}", file=sys.stderr)

    return metrics


def read_xdp_global_metrics() -> Optional[XDPGlobalMetrics]:
    """Read global XDP metrics from BPF map using bpftool."""
    if not os.path.exists(XDP_GLOBAL_METRICS_MAP):
        return None

    try:
        result = subprocess.run(
            ["bpftool", "map", "dump", "pinned", XDP_GLOBAL_METRICS_MAP, "-j"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return None

        entries = json.loads(result.stdout)

        if not entries:
            return None

        # Global map has single entry at key=0
        entry = entries[0]
        value = entry.get("value", {})

        if isinstance(value, list):
            # bpftool may return hex strings like ["0x88","0x05",...] or integers
            if value and isinstance(value[0], str):
                raw = bytes([int(x, 16) for x in value])
            else:
                raw = bytes(value)
            if len(raw) >= 64:  # 8 x u64 = 64 bytes
                import struct
                fields = struct.unpack("<8Q", raw[:64])
                return XDPGlobalMetrics(
                    total_packets=fields[0],
                    total_bytes=fields[1],
                    total_syn=fields[2],
                    total_synack=fields[3],
                    xdp_pass=fields[4],
                    xdp_drop=fields[5],
                    parse_errors=fields[6],
                )
        elif isinstance(value, dict):
            return XDPGlobalMetrics(
                total_packets=value.get("total_packets", 0),
                total_bytes=value.get("total_bytes", 0),
                total_syn=value.get("total_syn", 0),
                total_synack=value.get("total_synack", 0),
                xdp_pass=value.get("xdp_pass", 0),
                xdp_drop=value.get("xdp_drop", 0),
                parse_errors=value.get("parse_errors", 0),
            )

    except Exception as e:
        print(f"Error reading global XDP metrics: {e}", file=sys.stderr)

    return None


def add_monitored_origin(origin_ip: str) -> bool:
    """Add an origin IP to the XDP monitoring map."""
    if not os.path.exists(XDP_MONITORED_ORIGINS_MAP):
        return False

    try:
        # Convert IP to hex bytes for bpftool
        ip_bytes = ip_str_to_bytes(origin_ip)
        if not ip_bytes:
            return False

        key_hex = " ".join(f"{b:02x}" for b in ip_bytes)
        value_hex = "01 00 00 00"  # u32 = 1

        result = subprocess.run(
            ["bpftool", "map", "update", "pinned", XDP_MONITORED_ORIGINS_MAP,
             "key", "hex"] + key_hex.split() + ["value", "hex"] + value_hex.split(),
            capture_output=True,
            text=True,
            timeout=5,
        )

        return result.returncode == 0

    except Exception as e:
        print(f"Error adding monitored origin {origin_ip}: {e}", file=sys.stderr)
        return False


def build_xdp_metrics_report(
    origin_metrics: Dict[str, XDPOriginMetrics],
    global_metrics: Optional[XDPGlobalMetrics],
    metadata: Dict
) -> Dict:
    """Build XDP metrics report for TPM production audit."""

    origins = {}
    for origin_ip, m in origin_metrics.items():
        # Calculate SYN/SYN-ACK ratio (key indicator of unmitigated floods)
        syn_synack_ratio = 1.0
        if m.synack_count > 0:
            syn_synack_ratio = m.syn_count / m.synack_count
        elif m.syn_count > 0:
            syn_synack_ratio = 999.99  # No SYN-ACKs = bad

        origins[origin_ip] = {
            "packets_in": m.packets_in,
            "packets_out": m.packets_out,
            "bytes_in": m.bytes_in,
            "bytes_out": m.bytes_out,
            "syn_count": m.syn_count,
            "synack_count": m.synack_count,
            "fin_count": m.fin_count,
            "rst_count": m.rst_count,
            "ack_count": m.ack_count,
            "data_packets": m.data_packets,
            "syn_synack_ratio": round(syn_synack_ratio, 2),
        }

    # Global metrics
    global_data = {}
    if global_metrics:
        total_syn_synack_ratio = 1.0
        if global_metrics.total_synack > 0:
            total_syn_synack_ratio = global_metrics.total_syn / global_metrics.total_synack
        elif global_metrics.total_syn > 0:
            total_syn_synack_ratio = 999.99

        global_data = {
            "total_packets": global_metrics.total_packets,
            "total_bytes": global_metrics.total_bytes,
            "total_syn": global_metrics.total_syn,
            "total_synack": global_metrics.total_synack,
            "xdp_pass": global_metrics.xdp_pass,
            "xdp_drop": global_metrics.xdp_drop,
            "parse_errors": global_metrics.parse_errors,
            "syn_synack_ratio": round(total_syn_synack_ratio, 2),
        }

    return {
        "type": "exit_hub_xdp_metrics",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "exit_hub_id": metadata.get("exit_hub_id", ""),
        "exit_hub_ip": metadata.get("exit_hub_ip", ""),
        "origin_id": metadata.get("origin_id", ""),
        "origins": origins,
        "global": global_data,
        "origin_count": len(origins),
    }


def extract_origin_id_from_interface(interface: str) -> Optional[str]:
    """Extract origin ID from interface name.

    Supports:
    - wgO91 -> 'O91' (exit hub naming)
    - wg-miner-57 -> '57' (scrubber naming, deprecated)
    """
    for pattern in WG_INTERFACE_PATTERNS:
        if interface.startswith(pattern):
            try:
                suffix = interface[len(pattern):]
                # For wgO* pattern, prepend 'O' to form origin_id like 'O91'
                if pattern == "wgO":
                    return f"O{suffix}"
                return suffix
            except ValueError:
                pass
    return None


def get_exit_hub_metadata() -> Dict:
    """Get exit hub metadata for identification."""
    # Get public IP
    public_ip = ""
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", "5", "http://169.254.169.254/latest/meta-data/public-ipv4"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            public_ip = result.stdout.strip()
    except Exception:
        pass

    if not public_ip:
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "5", "https://ifconfig.me"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                public_ip = result.stdout.strip()
        except Exception:
            pass

    return {
        "exit_hub_id": EXIT_HUB_ID,
        "exit_hub_ip": public_ip,
        "origin_id": ORIGIN_ID,
        "miner_id": MINER_ID,
        "hostname": socket.gethostname(),
    }


def build_volume_report(
    wg_stats: Dict[str, InterfaceStats],
    prev_stats: Dict[str, InterfaceStats],
    metadata: Dict
) -> Dict:
    """Build volume report payload for TPM."""

    miners = {}
    total_bytes = 0
    total_packets = 0
    total_delta_bytes = 0
    total_delta_packets = 0

    for iface, stats in wg_stats.items():
        origin_id = extract_origin_id_from_interface(iface)
        if origin_id is None:
            # Use interface name as fallback identifier
            origin_id = iface

        # Calculate deltas if we have previous stats
        prev = prev_stats.get(iface)
        if prev:
            delta_bytes = max(0, stats.rx_bytes - prev.rx_bytes)
            delta_packets = max(0, stats.rx_packets - prev.rx_packets)
        else:
            delta_bytes = 0
            delta_packets = 0

        miners[origin_id] = {
            "interface": iface,
            "rx_bytes": stats.rx_bytes,
            "rx_packets": stats.rx_packets,
            "tx_bytes": stats.tx_bytes,
            "tx_packets": stats.tx_packets,
            "delta_bytes": delta_bytes,
            "delta_packets": delta_packets,
        }

        # For totals, use rx (traffic coming FROM scrubber TO origin)
        total_bytes += stats.rx_bytes
        total_packets += stats.rx_packets
        total_delta_bytes += delta_bytes
        total_delta_packets += delta_packets

    return {
        "type": "exit_hub_volume",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "exit_hub_id": metadata.get("exit_hub_id", ""),
        "exit_hub_ip": metadata.get("exit_hub_ip", ""),
        "origin_id": metadata.get("origin_id", ""),
        "hostname": metadata.get("hostname", ""),
        "miners": miners,
        "totals": {
            "bytes": total_bytes,
            "packets": total_packets,
            "miner_count": len(miners),
        },
        "deltas": {
            "bytes": total_delta_bytes,
            "packets": total_delta_packets,
        },
    }


def publish_to_redis(payload: Dict) -> bool:
    """Publish volume report to TPM via Redis."""
    try:
        import redis

        # Connect with optional password authentication
        r = redis.Redis(
            host=TPM_HOST,
            port=TPM_PORT,
            password=TPM_PASSWORD if TPM_PASSWORD else None,
            decode_responses=True
        )
        message = json.dumps(payload)
        r.publish(VOLUME_CHANNEL, message)
        return True

    except ImportError:
        # Fallback: use redis-cli if redis-py not available
        try:
            message = json.dumps(payload)
            cmd = ["redis-cli", "-h", TPM_HOST, "-p", str(TPM_PORT)]
            if TPM_PASSWORD:
                cmd.extend(["-a", TPM_PASSWORD])
            cmd.extend(["PUBLISH", VOLUME_CHANNEL, message])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception as e:
            print(f"redis-cli error: {e}", file=sys.stderr)
            return False

    except Exception as e:
        print(f"Redis publish error: {e}", file=sys.stderr)
        return False


def report_to_tpm_http(payload: Dict) -> bool:
    """Alternative: Report volume via HTTP API."""
    tpm_api_url = os.getenv("TPM_API_URL", "")
    if not tpm_api_url:
        return False

    try:
        import urllib.request
        import urllib.error

        url = f"{tpm_api_url}/api/v1/volume/exit_hub"
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200

    except Exception as e:
        print(f"HTTP report error: {e}", file=sys.stderr)
        return False


def publish_xdp_metrics_to_redis(payload: Dict) -> bool:
    """Publish XDP metrics report to TPM via Redis."""
    try:
        import redis

        r = redis.Redis(
            host=TPM_HOST,
            port=TPM_PORT,
            password=TPM_PASSWORD if TPM_PASSWORD else None,
            decode_responses=True
        )
        message = json.dumps(payload)
        r.publish(METRICS_CHANNEL, message)
        return True

    except ImportError:
        # Fallback: use redis-cli
        try:
            message = json.dumps(payload)
            cmd = ["redis-cli", "-h", TPM_HOST, "-p", str(TPM_PORT)]
            if TPM_PASSWORD:
                cmd.extend(["-a", TPM_PASSWORD])
            cmd.extend(["PUBLISH", METRICS_CHANNEL, message])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception as e:
            print(f"redis-cli error (metrics): {e}", file=sys.stderr)
            return False

    except Exception as e:
        print(f"Redis publish error (metrics): {e}", file=sys.stderr)
        return False


def report_xdp_metrics_http(payload: Dict) -> bool:
    """Report XDP metrics to TPM via HTTP API (fallback when Redis fails)."""
    # Try to construct TPM API URL from Redis host
    # TPM API runs on port 5001 by default
    tpm_api_host = TPM_HOST
    tpm_api_port = os.getenv("TPM_API_PORT", "5001")
    exit_hub_id = payload.get("exit_hub_id", EXIT_HUB_ID)

    if not exit_hub_id:
        print("Cannot report XDP metrics via HTTP: no exit_hub_id", file=sys.stderr)
        return False

    try:
        import urllib.request
        import urllib.error

        url = f"http://{tpm_api_host}:{tpm_api_port}/api/v1/exit-hubs/{exit_hub_id}/xdp-metrics"
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200

    except Exception as e:
        print(f"HTTP XDP metrics error: {e}", file=sys.stderr)
        return False


# ============================================================================
# TPTEST Benign Packet Detection (Production Benign Test Support)
# ============================================================================

class TPTESTCollector:
    """Thread-safe buffer for detected TPTEST packet IDs.

    Sniffer thread calls add(); flush thread wakes immediately on new packets
    (or every 1s as fallback).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._buffer: Dict[str, Set[str]] = {}  # {test_id: set(packet_ids)}
        self._event = threading.Event()  # signals flush thread to wake

    def add(self, test_id: str, packet_id: str):
        with self._lock:
            if test_id not in self._buffer:
                self._buffer[test_id] = set()
            self._buffer[test_id].add(packet_id)
        self._event.set()  # wake flush thread immediately

    def drain(self) -> Dict[str, List[str]]:
        """Atomically return and clear the buffer."""
        with self._lock:
            result = {tid: list(pids) for tid, pids in self._buffer.items()}
            self._buffer.clear()
        self._event.clear()
        return result

    def wait(self, timeout: float = 1.0) -> bool:
        """Wait for new packets or timeout. Returns True if packets available."""
        return self._event.wait(timeout=timeout)


def _get_wg_outbound_interfaces() -> List[str]:
    """Get list of wgO* interfaces (WireGuard tunnels to origins)."""
    interfaces = []
    net_path = Path("/sys/class/net")
    if not net_path.exists():
        return interfaces
    for iface_path in net_path.iterdir():
        if iface_path.name.startswith("wgO"):
            interfaces.append(iface_path.name)
    return interfaces


def _open_raw_socket(iface: str):
    """Open an AF_PACKET raw socket bound to a specific interface.

    WireGuard interfaces use ARPHRD_NONE (type 65534) so we receive raw IP
    packets with no Ethernet header.
    """
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
        sock.bind((iface, 0x0800))
        sock.setblocking(False)
        return sock
    except OSError as e:
        print(f"[TPTEST] Cannot open raw socket on {iface}: {e}", file=sys.stderr)
        return None


def _parse_tptest_from_ip_packet(data: bytes):
    """Parse raw IP packet and extract TPTEST payload if present.

    Returns (test_id, packet_id) or None.
    Expected: IPv4 + TCP with dst_port=80, PSH+ACK flags, payload starts with 'TPTEST:'
    """
    if len(data) < 20:
        return None

    # IPv4 header
    version_ihl = data[0]
    version = (version_ihl >> 4) & 0xF
    if version != 4:
        return None
    ihl = (version_ihl & 0xF) * 4
    if ihl < 20 or len(data) < ihl:
        return None

    protocol = data[9]
    if protocol != 6:  # TCP
        return None

    # TCP header starts at ihl offset
    tcp_start = ihl
    if len(data) < tcp_start + 20:
        return None

    dst_port = struct.unpack("!H", data[tcp_start + 2:tcp_start + 4])[0]
    if dst_port != 80:
        return None

    # TCP data offset (header length)
    data_offset_byte = data[tcp_start + 12]
    tcp_hdr_len = ((data_offset_byte >> 4) & 0xF) * 4
    if tcp_hdr_len < 20:
        return None

    # Check PSH+ACK flags (0x18)
    tcp_flags = data[tcp_start + 13]
    if (tcp_flags & 0x18) != 0x18:
        return None

    # TCP payload
    payload_start = tcp_start + tcp_hdr_len
    if payload_start >= len(data):
        return None

    payload = data[payload_start:]

    # Check TPTEST: prefix
    if not payload.startswith(b"TPTEST:"):
        return None

    try:
        text = payload.decode("utf-8", errors="replace")
        # Format: TPTEST:{test_id}:{packet_id}:{timestamp}
        parts = text.split(":")
        if len(parts) < 4:
            return None
        # parts[0] = "TPTEST", parts[1] = test_id, parts[2] = packet_id, parts[3] = timestamp
        test_id = parts[1]
        packet_id = parts[2]
        if not test_id or not packet_id:
            return None
        return (test_id, packet_id)
    except Exception:
        return None


def tptest_sniffer_thread(collector: TPTESTCollector):
    """Background thread: sniff wgO* interfaces for TPTEST packets."""
    print("[TPTEST] Sniffer thread started", file=sys.stderr)

    sockets: Dict[str, socket.socket] = {}
    last_refresh = 0.0
    REFRESH_INTERVAL = 30.0

    while True:
        try:
            now = time.monotonic()

            # Refresh interface list periodically
            if now - last_refresh >= REFRESH_INTERVAL:
                current_ifaces = set(_get_wg_outbound_interfaces())
                old_ifaces = set(sockets.keys())

                # Close sockets for removed interfaces
                for iface in old_ifaces - current_ifaces:
                    try:
                        sockets[iface].close()
                    except Exception:
                        pass
                    del sockets[iface]

                # Open sockets for new interfaces
                for iface in current_ifaces - old_ifaces:
                    sock = _open_raw_socket(iface)
                    if sock is not None:
                        sockets[iface] = sock
                        print(f"[TPTEST] Listening on {iface}", file=sys.stderr)

                last_refresh = now

            if not sockets:
                time.sleep(5)
                continue

            # Use select to wait for data on any socket (1s timeout)
            readable, _, _ = select.select(list(sockets.values()), [], [], 1.0)

            for sock in readable:
                try:
                    data = sock.recv(65535)
                    result = _parse_tptest_from_ip_packet(data)
                    if result is not None:
                        test_id, packet_id = result
                        collector.add(test_id, packet_id)
                except Exception:
                    pass

        except Exception as e:
            print(f"[TPTEST] Sniffer error: {e}", file=sys.stderr)
            # Close all sockets on error and let refresh reopen them
            for sock in sockets.values():
                try:
                    sock.close()
                except Exception:
                    pass
            sockets.clear()
            last_refresh = 0.0
            time.sleep(5)


def _get_tpm_api_base() -> str:
    """Get TPM API base URL for TPTEST reporting."""
    tpm_api_url = os.getenv("TPM_API_URL", "")
    if tpm_api_url:
        return tpm_api_url.rstrip("/")
    tpm_api_host = TPM_HOST
    tpm_api_port = os.getenv("TPM_API_PORT", "5001")
    return f"http://{tpm_api_host}:{tpm_api_port}"


def flush_tptest_to_tpm(collector: TPTESTCollector):
    """Drain the collector buffer and POST packet IDs to TPM."""
    import urllib.request
    import urllib.error

    buffered = collector.drain()
    if not buffered:
        return

    base_url = _get_tpm_api_base()
    total_reported = 0

    for test_id, packet_ids in buffered.items():
        url = f"{base_url}/api/v1/benign-tests/{test_id}/report-received"
        payload = json.dumps({"packet_ids": packet_ids}).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    matched = resp_data.get("matched", 0)
                    total_reported += matched
                    print(
                        f"[TPTEST] Reported {len(packet_ids)} packets for test {test_id} "
                        f"(matched={matched})",
                        file=sys.stderr,
                    )
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Test expired or unknown — discard silently
                print(
                    f"[TPTEST] Test {test_id} not found (expired?), discarding {len(packet_ids)} packets",
                    file=sys.stderr,
                )
            else:
                print(f"[TPTEST] HTTP error reporting test {test_id}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"[TPTEST] Error reporting test {test_id}: {e}", file=sys.stderr)

    if total_reported > 0:
        print(f"[TPTEST] Flush complete: {total_reported} packets matched across {len(buffered)} tests", file=sys.stderr)


def tptest_flush_thread(collector: TPTESTCollector):
    """Background thread: flush TPTEST detections to TPM.

    Wakes immediately when packets are detected (via event) or every 1s as
    fallback. This ensures packets are reported to TPM within ~100ms of
    detection, well within the validator's query window.
    """
    print("[TPTEST] Flush thread started (event-driven, 1s fallback)", file=sys.stderr)
    while True:
        collector.wait(timeout=1.0)
        try:
            flush_tptest_to_tpm(collector)
        except Exception as e:
            print(f"[TPTEST] Flush error: {e}", file=sys.stderr)


def main():
    """Main loop: read interface stats and XDP metrics, report to TPM."""
    print(f"Exit Hub Volume & XDP Metrics Agent starting")
    print(f"  TPM: {TPM_HOST}:{TPM_PORT}")
    print(f"  Report interval: {REPORT_INTERVAL}s")
    print(f"  Monitoring: WireGuard interfaces ({', '.join(WG_INTERFACE_PATTERNS)}*)")

    # Start TPTEST sniffer and flush daemon threads
    tptest_collector = TPTESTCollector()

    sniffer_t = threading.Thread(
        target=tptest_sniffer_thread, args=(tptest_collector,), daemon=True
    )
    sniffer_t.start()

    flush_t = threading.Thread(
        target=tptest_flush_thread, args=(tptest_collector,), daemon=True
    )
    flush_t.start()

    print(f"  TPTEST sniffer: started (sniffing wgO* for benign test packets)")

    # Check for XDP metrics support
    xdp_available = os.path.exists(XDP_ORIGIN_METRICS_MAP)
    print(f"  XDP metrics: {'available' if xdp_available else 'NOT AVAILABLE'}")

    metadata = get_exit_hub_metadata()
    print(f"  Exit Hub ID: {metadata.get('exit_hub_id', 'unknown')}")
    print(f"  Exit Hub IP: {metadata.get('exit_hub_ip', 'unknown')}")

    # Add origin to XDP monitoring if configured
    origin_id = metadata.get("origin_id", "")
    if xdp_available and origin_id:
        # Try to extract origin IP from environment or WireGuard config
        # This would need to be set during registration
        origin_ip = os.getenv("ORIGIN_IP", "")
        if origin_ip:
            if add_monitored_origin(origin_ip):
                print(f"  Added origin {origin_ip} to XDP monitoring")
            else:
                print(f"  WARNING: Failed to add {origin_ip} to XDP monitoring")

    prev_stats: Dict[str, InterfaceStats] = {}

    while True:
        try:
            # Read current WireGuard interface stats
            wg_stats = get_all_wg_stats()

            if not wg_stats:
                print(f"[{datetime.now().isoformat()}] No WireGuard interfaces found")
            else:
                # Build and send volume report
                volume_report = build_volume_report(wg_stats, prev_stats, metadata)
                volume_success = publish_to_redis(volume_report)
                if not volume_success:
                    volume_success = report_to_tpm_http(volume_report)

                # Save for next delta calculation
                prev_stats = wg_stats

            # Read and send XDP metrics (if available)
            if xdp_available:
                origin_metrics = read_xdp_origin_metrics()
                global_metrics = read_xdp_global_metrics()

                if origin_metrics or global_metrics:
                    xdp_report = build_xdp_metrics_report(
                        origin_metrics, global_metrics, metadata
                    )
                    # Try HTTP first (more reliable - Redis pubsub needs subscriber)
                    xdp_success = report_xdp_metrics_http(xdp_report)

                    # Fallback to Redis if HTTP fails
                    if not xdp_success:
                        xdp_success = publish_xdp_metrics_to_redis(xdp_report)

                    # Log combined status
                    syn_synack = xdp_report.get("global", {}).get("syn_synack_ratio", "N/A")
                    print(
                        f"[{datetime.now().isoformat()}] "
                        f"Volume: {len(wg_stats)} ifaces | "
                        f"XDP: {len(origin_metrics)} origins, "
                        f"syn_synack_ratio={syn_synack}"
                    )
                else:
                    print(
                        f"[{datetime.now().isoformat()}] "
                        f"Volume: {len(wg_stats)} ifaces | XDP: no data"
                    )
            else:
                # Volume only
                if wg_stats:
                    print(
                        f"[{datetime.now().isoformat()}] "
                        f"Reported: {len(wg_stats)} miners, "
                        f"+{volume_report['deltas']['bytes']:,} bytes"
                    )

        except Exception as e:
            print(f"Error in main loop: {e}", file=sys.stderr)

        time.sleep(REPORT_INTERVAL)


if __name__ == "__main__":
    main()
