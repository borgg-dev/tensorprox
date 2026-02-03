#!/usr/bin/env python3
"""
ECP Agent - Local agent on Scrubbers
Reports health metrics to EMN and maintains local state
Per dev-plan.md Section 10
"""

import os
import sys
import json
import time
import logging
import subprocess
import requests
import psutil
import ipaddress
import socket
import struct
from pathlib import Path
from typing import Dict, Optional

# Configuration
EMN_URL = os.getenv('EMN_URL', 'http://localhost:8000')
NODE_ID = os.getenv('NODE_ID', 'unknown')

# Dual-cycle reporting for fast failover detection
# Heartbeat: lightweight "I'm alive" ping (for failover detection)
# Metrics: heavy collection (XDP stats, origin metrics, etc.)
HEARTBEAT_INTERVAL = int(os.getenv('HEARTBEAT_INTERVAL', '5'))   # Fast heartbeat (5s)
METRICS_INTERVAL = int(os.getenv('METRICS_INTERVAL', '30'))      # Heavy metrics (30s)

SOURCE_IP_BEHAVIOR_STALE_SECONDS = int(
    os.getenv('SOURCE_IP_BEHAVIOR_STALE_SECONDS', '180')
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ecp-agent')

BPF_MAP_PATHS = {
    'origin_stats': '/sys/fs/bpf/tc/globals/origin_stats_map',
    'source_ip_behavior': '/sys/fs/bpf/xdp/globals/source_ip_behavior_map',
    'ratelimit': '/sys/fs/bpf/xdp/globals/ratelimit_map',
    'quarantine': '/sys/fs/bpf/xdp/globals/quarantine_map',
    'bypass': '/sys/fs/bpf/xdp/globals/bypass_map',
    'syncookie_metrics': '/sys/fs/bpf/tc/globals/syncookie_metrics_map',
    'syncookie_mode': '/sys/fs/bpf/tc/globals/syncookie_mode_map',
    'eip': '/sys/fs/bpf/tc/globals/eip_map',
    'cookie_failure': '/sys/fs/bpf/tc/globals/cookie_failure_map',
    # AWS Billing: Per-origin egress tracking (PERCPU map)
    'egress_billing': '/sys/fs/bpf/tc/globals/egress_billing_map',
    # Bandwidth QoS maps
    'scrubber_capacity': '/sys/fs/bpf/tc/globals/scrubber_capacity_map',
    'origin_bandwidth': '/sys/fs/bpf/tc/globals/origin_bandwidth_map',
    'qos_stats': '/sys/fs/bpf/tc/globals/qos_stats_map',
    # Per-EIP security statistics
    'eip_security_stats': '/sys/fs/bpf/xdp/globals/eip_security_stats_map',
}


def get_bpf_map_path(map_name: str) -> str:
    """Return canonical pinned path for a named BPF map."""
    if map_name not in BPF_MAP_PATHS:
        raise KeyError(f"Unknown BPF map: {map_name}")
    return BPF_MAP_PATHS[map_name]


def detect_bpf_loaded() -> bool:
    """Check if critical XDP maps are pinned, indicating BPF program loaded."""
    try:
        ratelimit_map = Path(get_bpf_map_path('ratelimit'))
        return ratelimit_map.exists()
    except Exception:
        return False

def get_node_metadata():
    """Get EC2 instance metadata"""
    try:
        # Try AWS metadata service
        instance_id = subprocess.check_output(
            ['curl', '-s', '--max-time', '2', 'http://169.254.169.254/latest/meta-data/instance-id'],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        if instance_id and instance_id.startswith('i-'):
            return instance_id
    except:
        pass

    # Fallback to hostname
    return subprocess.check_output(['hostname']).decode().strip()

def check_wireguard_interfaces():
    """Check all WireGuard interfaces and their status"""
    wg_interfaces = []
    try:
        # List all WireGuard interfaces (matches actual naming: wgO1.conf, wgO2.conf, etc.)
        configs = Path('/etc/wireguard').glob('wg*.conf')
        for config in configs:
            wg_if = config.stem

            # Get interface status
            try:
                output = subprocess.check_output(
                    ['wg', 'show', wg_if],
                    stderr=subprocess.DEVNULL
                ).decode()

                # Parse handshake
                handshake_age = None
                transfer_rx = 0
                transfer_tx = 0

                for line in output.split('\n'):
                    if 'latest handshake:' in line:
                        # Parse "X seconds ago" or "X minutes ago"
                        parts = line.split('latest handshake:')[1].strip().split()
                        if len(parts) >= 2:
                            value = int(parts[0])
                            unit = parts[1]
                            if 'minute' in unit:
                                handshake_age = value * 60
                            elif 'second' in unit:
                                handshake_age = value
                            elif 'hour' in unit:
                                handshake_age = value * 3600

                    if 'transfer:' in line:
                        # Parse "X KiB received, Y KiB sent"
                        transfer_parts = line.split('transfer:')[1].strip()
                        if 'received' in transfer_parts:
                            rx_part = transfer_parts.split('received')[0].strip().split()
                            if len(rx_part) >= 1:
                                transfer_rx = float(rx_part[0])

                wg_interfaces.append({
                    'interface': wg_if,
                    'up': True,
                    'handshake_age_seconds': handshake_age,
                    'transfer_rx_kib': transfer_rx
                })
            except:
                wg_interfaces.append({
                    'interface': wg_if,
                    'up': False,
                    'handshake_age_seconds': None,
                    'transfer_rx_kib': 0
                })
    except Exception as e:
        logger.error(f"Failed to check WireGuard interfaces: {e}")

    return wg_interfaces

def get_system_metrics():
    """Get system-level metrics (lightweight only)"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent

        # Network interface stats
        net_io = psutil.net_io_counters(pernic=True)
        ens5_stats = net_io.get('ens5', None)

        # Conntrack count
        try:
            conntrack_count = int(subprocess.check_output(
                ['conntrack', '-C'],
                stderr=subprocess.DEVNULL
            ).decode().strip())
        except:
            conntrack_count = 0

        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'conntrack_count': conntrack_count,
            'interface_rx_bytes': ens5_stats.bytes_recv if ens5_stats else 0,
            'interface_tx_bytes': ens5_stats.bytes_sent if ens5_stats else 0,
            'bpf_loaded': detect_bpf_loaded()
        }
    except Exception as e:
        logger.error(f"Failed to get system metrics: {e}")
        return {
            'cpu_percent': 0,
            'memory_percent': 0,
            'conntrack_count': 0,
            'interface_rx_bytes': 0,
            'interface_tx_bytes': 0,
            'bpf_loaded': False
        }

def get_origin_stats():
    """Read per-origin lifetime statistics from BPF map (7 x u64 struct)"""
    try:
        result = subprocess.check_output([
            'bpftool', 'map', 'dump', 'pinned',
            get_bpf_map_path('origin_stats'),
            '--json'
        ], stderr=subprocess.DEVNULL)
        map_data = json.loads(result)

        origin_stats = {}
        import struct

        def maybe_store(ip, record):
            last_seen = record.get('last_seen_ts')
            if not last_seen:
                return
            if (current_monotonic - last_seen) > SOURCE_IP_BEHAVIOR_STALE_SECONDS:
                return
            ip_behaviors[ip] = record

        for entry in map_data:
            # Parse key (origin IP address)
            if 'formatted' in entry and 'key' in entry['formatted']:
                # Formatted output: key is integer IP address
                ip_int = entry['formatted']['key']
                # Convert integer to IP address (network byte order)
                ip_bytes = [
                    (ip_int >> 0) & 0xFF,
                    (ip_int >> 8) & 0xFF,
                    (ip_int >> 16) & 0xFF,
                    (ip_int >> 24) & 0xFF
                ]
                origin_ip = '.'.join([str(b) for b in ip_bytes])
            else:
                # Fallback: manual parsing of hex key
                key_hex = entry.get('key', '')
                if isinstance(key_hex, list):
                    key_hex = ''.join(key_hex)
                key_bytes = [int(key_hex[i:i+2], 16) for i in range(0, min(8, len(key_hex)), 2)]
                if len(key_bytes) >= 4:
                    origin_ip = '.'.join([str(b) for b in key_bytes[:4]])
                else:
                    continue

            # Parse value (7 x u64 = 56 bytes struct)
            if 'formatted' in entry and 'value' in entry['formatted']:
                # If bpftool provides formatted struct parsing (unlikely for custom structs)
                val_formatted = entry['formatted']['value']
                if isinstance(val_formatted, dict):
                    # Extract fields if available
                    origin_stats[origin_ip] = val_formatted
                    continue

            # Fallback: manual parsing of hex value
            value_hex = entry.get('value', '')
            if isinstance(value_hex, str):
                # Convert hex string to bytes
                val_bytes = bytes.fromhex(value_hex.replace(' ', ''))
            elif isinstance(value_hex, list):
                # List of hex strings or integers
                val_bytes = bytes([int(v, 16) if isinstance(v, str) else v for v in value_hex])
            else:
                continue

            # Unpack 7 x u64 (little-endian)
            if len(val_bytes) >= 56:
                vals = struct.unpack('<7Q', val_bytes[:56])
                origin_stats[origin_ip] = {
                    'conn_opened_total': vals[0],
                    'conn_closed_total': vals[1],
                    'packets_total': vals[2],
                    'ingress_syn_count': vals[3],      # PHASE 1: Client → Origin SYNs
                    'egress_synack_count': vals[4],    # PHASE 1: Origin → Client SYN-ACKs (REAL indicator)
                    'fin_count': vals[5],
                    'rst_count': vals[6]
                }

        return origin_stats
    except subprocess.CalledProcessError:
        # Map might not exist yet (BPF not loaded)
        return {}
    except Exception as e:
        logger.error(f"Failed to read origin stats: {e}")
        return {}


def get_egress_billing_stats():
    """
    Read per-origin egress billing statistics from PERCPU BPF map.

    AWS Billing: Tracks L3 bytes (iph->tot_len) for accurate data transfer billing.
    Two egress paths tracked:
      - to_origin: Requests going TO origin (before WireGuard encryption)
      - to_client: Responses going TO client (after WireGuard decryption)

    Returns: Dict keyed by origin_ip with aggregated (summed across CPUs) stats:
        {
            "203.0.113.50": {  # RFC 5737 TEST-NET-3 example
                "to_origin_packets": 12345,
                "to_origin_bytes": 67890123,
                "to_client_packets": 54321,
                "to_client_bytes": 98765432,
                "total_egress_bytes": 166655555  # Sum for AWS billing
            }
        }
    """
    try:
        map_path = get_bpf_map_path('egress_billing')
        if not Path(map_path).exists():
            return {}

        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'pinned', map_path, '--json', '-p'],
            capture_output=True, text=True, timeout=15
        )

        if result.returncode != 0:
            logger.debug(f"egress_billing_map not available: {result.stderr}")
            return {}

        map_data = json.loads(result.stdout or "[]")
        egress_stats = {}

        for entry in map_data:
            # Parse key: origin_ip (__be32, network byte order)
            key_data = entry.get('key')
            if key_data is None:
                continue

            # Handle different bpftool output formats
            if isinstance(key_data, int):
                # Integer from formatted output - use _int_to_ip
                origin_ip = _int_to_ip(key_data)
            elif isinstance(key_data, dict):
                origin_ip_int = key_data.get('value', key_data.get('data', 0))
                origin_ip = _int_to_ip(origin_ip_int)
            elif isinstance(key_data, list):
                # Hex bytes list - directly convert to IP (network byte order)
                try:
                    ip_bytes = [int(k.replace('0x', ''), 16) for k in key_data[:4]]
                    origin_ip = '.'.join(str(b) for b in ip_bytes)
                except (ValueError, TypeError):
                    continue
            else:
                continue

            # Parse per-CPU values and sum them
            # PERCPU maps return 'values' array with one entry per CPU
            values_data = entry.get('values', [])
            if not values_data:
                # Try 'value' for single value format
                values_data = [entry.get('value', {})]

            # Aggregate across all CPUs
            to_origin_packets = 0
            to_origin_bytes = 0
            to_client_packets = 0
            to_client_bytes = 0

            for cpu_value in values_data:
                if isinstance(cpu_value, dict):
                    # Formatted struct output - handle both {"cpu": N, "value": {...}}
                    # and direct struct format {"to_origin_packets": N, ...}
                    stats = cpu_value.get('value', cpu_value)
                    if isinstance(stats, dict):
                        # Named fields format
                        to_origin_packets += stats.get('to_origin_packets', 0)
                        to_origin_bytes += stats.get('to_origin_bytes', 0)
                        to_client_packets += stats.get('to_client_packets', 0)
                        to_client_bytes += stats.get('to_client_bytes', 0)
                    elif isinstance(stats, list):
                        # Raw hex bytes inside {"cpu": N, "value": [hex...]}
                        try:
                            hex_str = ''.join(
                                v.replace('0x', '') if isinstance(v, str) else f'{v:02x}'
                                for v in stats
                            )
                            val_bytes = bytes.fromhex(hex_str)
                            if len(val_bytes) >= 32:
                                vals = struct.unpack('<4Q', val_bytes[:32])
                                to_origin_packets += vals[0]
                                to_origin_bytes += vals[1]
                                to_client_packets += vals[2]
                                to_client_bytes += vals[3]
                        except (ValueError, struct.error):
                            continue
                elif isinstance(cpu_value, list):
                    # Raw hex bytes - parse as 4x u64 (little-endian)
                    try:
                        hex_str = ''.join(
                            v.replace('0x', '') if isinstance(v, str) else f'{v:02x}'
                            for v in cpu_value
                        )
                        val_bytes = bytes.fromhex(hex_str)
                        if len(val_bytes) >= 32:
                            vals = struct.unpack('<4Q', val_bytes[:32])
                            to_origin_packets += vals[0]
                            to_origin_bytes += vals[1]
                            to_client_packets += vals[2]
                            to_client_bytes += vals[3]
                    except (ValueError, struct.error):
                        continue

            egress_stats[origin_ip] = {
                'to_origin_packets': to_origin_packets,
                'to_origin_bytes': to_origin_bytes,
                'to_client_packets': to_client_packets,
                'to_client_bytes': to_client_bytes,
                # Total egress = both paths (this is what AWS bills)
                'total_egress_bytes': to_origin_bytes + to_client_bytes,
                'total_egress_packets': to_origin_packets + to_client_packets,
            }

        if egress_stats:
            logger.info(f"Egress billing: {len(egress_stats)} origins tracked")

        return egress_stats

    except subprocess.TimeoutExpired:
        logger.warning("egress_billing_map read timeout")
        return {}
    except Exception as e:
        logger.error(f"Failed to read egress billing stats: {e}")
        return {}


def get_bandwidth_capacity():
    """
    Read bandwidth capacity from bootstrap-created config file.

    Returns: dict with bandwidth_bps, usable_bps, etc. or empty dict if not available
    """
    try:
        capacity_file = Path('/var/lib/tensorprox/bandwidth_capacity.json')
        if not capacity_file.exists():
            return {}

        with open(capacity_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to read bandwidth capacity: {e}")
        return {}


def get_bandwidth_usage():
    """
    Read per-origin bandwidth usage from origin_bandwidth_map BPF map.

    Returns: dict keyed by origin_ip with quota, bytes_exceeded, packets_dropped, etc.
    """
    try:
        map_path = '/sys/fs/bpf/tc/globals/origin_bandwidth_map'
        if not Path(map_path).exists():
            return {}

        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'pinned', map_path, '--json', '-p'],
            capture_output=True, text=True, timeout=15
        )

        if result.returncode != 0:
            logger.debug(f"origin_bandwidth_map not available: {result.stderr}")
            return {}

        map_data = json.loads(result.stdout or "[]")
        bandwidth_usage = {}

        for entry in map_data:
            # Prefer formatted output (when BTF is available) for correct parsing
            formatted = entry.get('formatted', {})
            if formatted:
                key_data = formatted.get('key')
                value_data = formatted.get('value', {})
            else:
                key_data = entry.get('key')
                value_data = entry.get('value', {})

            if key_data is None:
                continue

            if isinstance(key_data, int):
                origin_ip_int = key_data
            elif isinstance(key_data, dict):
                origin_ip_int = key_data.get('value', key_data.get('data', 0))
            elif isinstance(key_data, list):
                # Raw hex bytes in network order - convert to little-endian int
                try:
                    hex_bytes = [int(k, 16) if isinstance(k, str) else k for k in key_data[:4]]
                    origin_ip_int = struct.unpack('<I', bytes(hex_bytes))[0]
                except (ValueError, TypeError, struct.error):
                    continue
            else:
                continue

            origin_ip = _int_to_ip(origin_ip_int)

            if isinstance(value_data, dict):
                # Formatted struct output
                bandwidth_usage[origin_ip] = {
                    'quota_bps': value_data.get('quota_bps', 0),
                    'tokens': value_data.get('tokens', 0),
                    'burst_bytes': value_data.get('burst_bytes', 0),
                    'bytes_exceeded': value_data.get('bytes_exceeded', 0),
                    'packets_dropped': value_data.get('packets_dropped', 0),
                }
            elif isinstance(value_data, list):
                # Raw hex bytes - parse as 8x u64
                try:
                    hex_str = ''.join(
                        v.replace('0x', '') if isinstance(v, str) else f'{v:02x}'
                        for v in value_data
                    )
                    val_bytes = bytes.fromhex(hex_str)
                    if len(val_bytes) >= 56:  # 7 x u64 minimum
                        vals = struct.unpack('<7Q', val_bytes[:56])
                        # Struct layout: quota_bps, tokens, burst_bytes, last_refill_ns,
                        #               _reserved, bytes_exceeded, packets_dropped
                        bandwidth_usage[origin_ip] = {
                            'quota_bps': vals[0],
                            'tokens': vals[1],
                            'burst_bytes': vals[2],
                            'bytes_exceeded': vals[5],
                            'packets_dropped': vals[6],
                        }
                except (ValueError, struct.error) as e:
                    logger.debug(f"Failed to parse bandwidth entry for {origin_ip}: {e}")
                    continue

        if bandwidth_usage:
            logger.info(f"Bandwidth usage: {len(bandwidth_usage)} origins tracked")

        return bandwidth_usage

    except subprocess.TimeoutExpired:
        logger.warning("origin_bandwidth_map read timeout")
        return {}
    except Exception as e:
        logger.error(f"Failed to read bandwidth usage: {e}")
        return {}


def get_eip_security_stats():
    """
    Read per-EIP security drop statistics from PERCPU BPF map.

    Returns: Dict keyed by EIP with aggregated (summed across CPUs) stats:
        {
            "203.0.113.10": {  # RFC 5737 TEST-NET-3 example
                "drop_blacklist": 523,
                "drop_temp_blacklist": 89,
                "drop_ratelimit": 1234,
                "drop_quarantine": 45,
                "drop_bogon": 12
            }
        }
    """
    try:
        map_path = get_bpf_map_path('eip_security_stats')
        if not Path(map_path).exists():
            return {}

        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'pinned', map_path, '--json', '-p'],
            capture_output=True, text=True, timeout=15
        )

        if result.returncode != 0:
            logger.debug(f"eip_security_stats_map not available: {result.stderr}")
            return {}

        map_data = json.loads(result.stdout or "[]")
        security_stats = {}

        for entry in map_data:
            # Parse key: EIP (__be32, network byte order)
            key_data = entry.get('key')
            if key_data is None:
                continue

            if isinstance(key_data, int):
                eip = _int_to_ip(key_data)
            elif isinstance(key_data, dict):
                eip_int = key_data.get('value', key_data.get('data', 0))
                eip = _int_to_ip(eip_int)
            elif isinstance(key_data, list):
                try:
                    ip_bytes = [int(k.replace('0x', ''), 16) for k in key_data[:4]]
                    eip = '.'.join(str(b) for b in ip_bytes)
                except (ValueError, TypeError):
                    continue
            else:
                continue

            # Parse per-CPU values and sum them
            values_data = entry.get('values', [])
            if not values_data:
                values_data = [entry.get('value', {})]

            # Aggregate across all CPUs
            # 8 fields: drop_blacklist, drop_temp_blacklist, drop_ratelimit, drop_quarantine,
            #           drop_bogon, drop_origin_blacklist, origin_whitelist_bypass, origin_override_used
            drop_blacklist = 0
            drop_temp_blacklist = 0
            drop_ratelimit = 0
            drop_quarantine = 0
            drop_bogon = 0
            drop_origin_blacklist = 0
            origin_whitelist_bypass = 0
            origin_override_used = 0

            for cpu_value in values_data:
                if isinstance(cpu_value, dict):
                    stats = cpu_value.get('value', cpu_value)
                    if isinstance(stats, dict):
                        drop_blacklist += stats.get('drop_blacklist', 0)
                        drop_temp_blacklist += stats.get('drop_temp_blacklist', 0)
                        drop_ratelimit += stats.get('drop_ratelimit', 0)
                        drop_quarantine += stats.get('drop_quarantine', 0)
                        drop_bogon += stats.get('drop_bogon', 0)
                        drop_origin_blacklist += stats.get('drop_origin_blacklist', 0)
                        origin_whitelist_bypass += stats.get('origin_whitelist_bypass', 0)
                        origin_override_used += stats.get('origin_override_used', 0)
                    elif isinstance(stats, list):
                        # Raw hex bytes: 8 x u64 = 64 bytes
                        try:
                            hex_str = ''.join(
                                v.replace('0x', '') if isinstance(v, str) else f'{v:02x}'
                                for v in stats
                            )
                            val_bytes = bytes.fromhex(hex_str)
                            if len(val_bytes) >= 64:
                                vals = struct.unpack('<8Q', val_bytes[:64])
                                drop_blacklist += vals[0]
                                drop_temp_blacklist += vals[1]
                                drop_ratelimit += vals[2]
                                drop_quarantine += vals[3]
                                drop_bogon += vals[4]
                                drop_origin_blacklist += vals[5]
                                origin_whitelist_bypass += vals[6]
                                origin_override_used += vals[7]
                            elif len(val_bytes) >= 40:
                                # Backward compat: old 5-field struct
                                vals = struct.unpack('<5Q', val_bytes[:40])
                                drop_blacklist += vals[0]
                                drop_temp_blacklist += vals[1]
                                drop_ratelimit += vals[2]
                                drop_quarantine += vals[3]
                                drop_bogon += vals[4]
                        except (ValueError, struct.error):
                            continue

            security_stats[eip] = {
                'drop_blacklist': drop_blacklist,
                'drop_temp_blacklist': drop_temp_blacklist,
                'drop_ratelimit': drop_ratelimit,
                'drop_quarantine': drop_quarantine,
                'drop_bogon': drop_bogon,
                'drop_origin_blacklist': drop_origin_blacklist,
                'origin_whitelist_bypass': origin_whitelist_bypass,
                'origin_override_used': origin_override_used,
                'total_drops': (drop_blacklist + drop_temp_blacklist + drop_ratelimit +
                               drop_quarantine + drop_bogon + drop_origin_blacklist)
            }

        if security_stats:
            logger.info(f"EIP security stats: {len(security_stats)} EIPs tracked")

        return security_stats

    except subprocess.TimeoutExpired:
        logger.warning("eip_security_stats_map read timeout")
        return {}
    except Exception as e:
        logger.error(f"Failed to read EIP security stats: {e}")
        return {}


def get_xdp_metrics():
    """Read XDP statistics from xdp_wan_stats BPF map"""
    try:
        result = subprocess.check_output([
            'bpftool', 'map', 'dump', 'name', 'xdp_wan_stats', '--json'
        ], stderr=subprocess.DEVNULL)
        map_data = json.loads(result)

        # Per-CPU counters need to be summed
        # Key mapping: 0=PASS, 1=WHITELIST_BYPASS, 2=DROP_BLACKLIST, 3=DROP_INVALID_IP, 4=DROP_INVALID_TCP, 5=DROP_RATELIMIT, 6=DROP_TEMP_BLACKLIST, 13=DROP_BOGON
        stats = {
            'xdp_pass': 0,
            'xdp_whitelist_bypass': 0,
            'xdp_drop_blacklist': 0,
            'xdp_drop_invalid_ip': 0,
            'xdp_drop_invalid_tcp': 0,
            'xdp_drop_ratelimit': 0,
            'xdp_drop_temp_blacklist': 0,
            'xdp_drop_bogon': 0
        }

        stat_keys = ['xdp_pass', 'xdp_whitelist_bypass', 'xdp_drop_blacklist',
                     'xdp_drop_invalid_ip', 'xdp_drop_invalid_tcp', 'xdp_drop_ratelimit',
                     'xdp_drop_temp_blacklist', 'xdp_syncookie_challenge',
                     'xdp_syncookie_validated', 'xdp_syncookie_allow', 'xdp_syncookie_reject',
                     'xdp_drop_quarantine', 'xdp_bypass_allowed', 'xdp_drop_bogon']

        for entry in map_data:
            # Use 'formatted' field if available (bpftool >= 5.x)
            if 'formatted' in entry:
                key = entry['formatted']['key']
                values = entry['formatted']['values']
                total = sum(v['value'] for v in values if isinstance(v, dict) and 'value' in v)
            else:
                # Fallback to manual parsing
                key = entry.get('key', 0)
                if isinstance(key, list):
                    key = int(key[0], 16) if len(key) > 0 else 0
                values = entry.get('values', [])
                total = sum(v.get('value', 0) for v in values if isinstance(v, dict))

            if key < len(stat_keys):
                stats[stat_keys[key]] = total

        return stats

    except subprocess.CalledProcessError:
        # Map might not exist yet
        return None
    except Exception as e:
        logger.error(f"Failed to read XDP metrics: {e}")
        return None

def _int_to_ip(value: int) -> str:
    packed = struct.pack('<I', value & 0xFFFFFFFF)
    return socket.inet_ntoa(packed)


def _extract_u32(value):
    """Normalize bpftool key/value fields to integers."""
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        for candidate in ('value', 'data', 'mode'):
            candidate_val = value.get(candidate)
            if isinstance(candidate_val, int):
                return candidate_val
    if isinstance(value, list):
        try:
            hex_str = ''.join(part.replace('0x', '') for part in value)
            return int(hex_str, 16)
        except ValueError:
            return None
    return None


def _extract_ipv4_from_entry(entry, preferred_fields=None):
    """Extract IPv4 integer from a bpftool map entry."""
    if isinstance(entry, list):
        entry = {'key': entry}
    formatted = entry.get('formatted')
    if isinstance(formatted, dict):
        for field in ('key', 'dst_eip', 'vip_ip', 'origin_ip'):
            val = formatted.get(field)
            if isinstance(val, int):
                return val
    key_data = entry.get('key', {})
    if isinstance(key_data, dict):
        fields = preferred_fields or ('value', 'vip_ip', 'dst_eip', 'origin_ip')
        for field in fields:
            val = key_data.get(field)
            if isinstance(val, int):
                return val
    return _extract_u32(key_data)


def _log_local_bpf(action: str, map_name: str, rc: int, stderr: str = "") -> None:
    status = "SUCCESS" if rc == 0 else "FAILED"
    message = f"[scrubber] {action.upper()} {map_name} status={status} rc={rc}"
    if stderr:
        message += f" stderr='{stderr.strip()[:200]}'"
    if rc == 0:
        logger.info(message)
    else:
        logger.warning(message)


def _dump_bpf_map(map_name: str):
    """Dump a pinned BPF map as Python data."""
    path = get_bpf_map_path(map_name)
    cmd = ['sudo', 'bpftool', 'map', 'dump', 'pinned', path, '--json', '-p']
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    _log_local_bpf('dump', map_name, result.returncode, result.stderr)
    if result.returncode != 0:
        return []
    try:
        return json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        logger.error(f"Failed to decode bpftool output for {map_name}")
        return []


def get_vip_metadata():
    """
    Build VIP metadata:
    - vip_modes: origin_ip -> cookie_mode flag
    - origin_to_vip: origin_ip -> vip_ip (unused placeholder for now)
    """
    try:
        origin_modes = {}
        for entry in _dump_bpf_map('syncookie_mode'):
            origin_val = _extract_ipv4_from_entry(entry, preferred_fields=('value', 'origin_ip'))
            mode_val = _extract_u32(entry.get('value'))
            if origin_val is None or mode_val is None:
                continue
            origin_modes[origin_val] = 1 if mode_val else 0

        vip_modes = {}
        for origin_val, mode in origin_modes.items():
            vip_modes[_int_to_ip(origin_val)] = mode

        return vip_modes, {}
    except Exception as exc:
        logger.error(f"Failed to derive VIP cookie modes: {exc}")
        return {}, {}


def get_syncookie_metrics(limit=100, cookie_modes=None, origin_to_vip=None):
    """Read per-VIP SYN cookie metrics from TC map"""
    cookie_modes = cookie_modes or {}
    origin_to_vip = origin_to_vip or {}
    try:
        map_data = _dump_bpf_map('syncookie_metrics')
        logger.info(f"syncookie_metrics_map entries: {len(map_data)}")
        metrics = []

        for entry in map_data:
            vip_val = _extract_ipv4_from_entry(entry)

            if vip_val is None:
                continue

            raw_ip = _int_to_ip(vip_val)
            vip_ip = origin_to_vip.get(raw_ip, raw_ip)
            formatted_value = entry.get('formatted', {})
            if isinstance(formatted_value, dict):
                value = formatted_value.get('value', {})
            else:
                value = entry.get('value', {})
            if isinstance(value, list):
                value = {}
            metrics.append({
                'vip_ip': vip_ip,
                'incoming_syn': value.get('incoming_syn_pps', 0),
                'cookie_validates': value.get('cookie_validates', 0),
                'cookie_rejects': value.get('cookie_rejects', 0),
                'handshake_completes': value.get('handshake_completes', 0),
                'challenged_clients': value.get('challenged_clients', 0),
                'pending_cookies': value.get('pending_cookies', 0),
                'allow_list_size': value.get('allow_list_size', 0),
                'syn_retransmits': value.get('syn_retransmits', 0),
                'false_positives': value.get('false_positives', 0),
                'outgoing_synack': value.get('outgoing_synack_pps', 0),
                'last_update_ts': value.get('last_update_ts', 0),
                'cookie_mode': cookie_modes.get(vip_ip, 0)
            })

        metrics.sort(key=lambda m: m.get('incoming_syn', 0), reverse=True)
        return metrics[:limit]

    except Exception as e:
        logger.exception(f"Failed to read syncookie metrics: {e}")
        return []


def get_cookie_failure_samples(limit=100):
    """Read cookie_failure_map and return the noisiest sources"""
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'pinned', get_bpf_map_path('cookie_failure'), '--json'],
            capture_output=True,
            text=True,
            timeout=15
        )
        _log_local_bpf('dump', 'cookie_failure', result.returncode, result.stderr)
        if result.returncode != 0:
            return []

        map_data = json.loads(result.stdout or "[]")
        failures = []

        for entry in map_data:
            key = entry.get('key', {})
            value = entry.get('value', {})
            src_val = key.get('src_ip') if isinstance(key, dict) else None
            vip_val = key.get('vip_ip') if isinstance(key, dict) else None
            if src_val is None or vip_val is None:
                continue

            failures.append({
                'src_ip': _int_to_ip(src_val),
                'vip_ip': _int_to_ip(vip_val),
                'failure_count': value.get('failure_count', 0),
                'success_count': value.get('success_count', 0),
                'last_failure_ts': value.get('last_failure_ts', 0)
            })

        failures.sort(key=lambda f: f['failure_count'], reverse=True)
        return failures[:limit]

    except Exception as e:
        logger.error(f"Failed to read cookie failure map: {e}")
        return []

def get_source_ip_behavior(limit=100):
    """PHASE 2: Read per-IP behavior stats (top attacking IPs)"""
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'pinned', get_bpf_map_path('source_ip_behavior'), '--json'],
            capture_output=True,
            text=True,
            timeout=15
        )
        _log_local_bpf('dump', 'source_ip_behavior', result.returncode, result.stderr)
        if result.returncode != 0:
            return {}
        map_data = json.loads(result.stdout or "[]")

        ip_behaviors = {}
        import struct
        current_monotonic = int(time.monotonic())

        def maybe_store(ip, record):
            last_seen = record.get('last_seen_ts')
            if not last_seen:
                return
            if (current_monotonic - last_seen) > SOURCE_IP_BEHAVIOR_STALE_SECONDS:
                return
            ip_behaviors[ip] = record

        for entry in map_data:
            # Parse key (source IP)
            if 'formatted' in entry and 'key' in entry['formatted']:
                ip_int = entry['formatted']['key']
                ip_bytes = [
                    (ip_int >> 0) & 0xFF,
                    (ip_int >> 8) & 0xFF,
                    (ip_int >> 16) & 0xFF,
                    (ip_int >> 24) & 0xFF
                ]
                src_ip = '.'.join([str(b) for b in ip_bytes])
            else:
                key_hex = entry.get('key', '')
                if isinstance(key_hex, list):
                    key_hex = ''.join(key_hex)
                key_bytes = [int(key_hex[i:i+2], 16) for i in range(0, min(8, len(key_hex)), 2)]
                if len(key_bytes) >= 4:
                    src_ip = '.'.join([str(b) for b in key_bytes[:4]])
                else:
                    continue

            # Prefer bpftool-formatted struct if available
            formatted = entry.get('formatted', {})
            formatted_value = formatted.get('value') if isinstance(formatted, dict) else None
            if isinstance(formatted_value, dict):
                maybe_store(src_ip, {
                    'syn_count': formatted_value.get('syn_count', 0),
                    'rst_count': formatted_value.get('rst_count', 0),
                    'packets_total': formatted_value.get('packets_total', 0),
                    'first_seen_ts': formatted_value.get('first_seen_ts', 0),
                    'last_seen_ts': formatted_value.get('last_seen_ts', 0),
                    'burst_count': formatted_value.get('burst_count', 0)
                })
                continue

            # Fallback: parse raw bytes (struct source_ip_behavior)
            value_hex = entry.get('value', '')
            if isinstance(value_hex, str):
                val_bytes = bytes.fromhex(value_hex.replace(' ', ''))
            elif isinstance(value_hex, list):
                val_bytes = bytes([int(v, 16) if isinstance(v, str) else v for v in value_hex])
            else:
                continue

            if len(val_bytes) >= 36:
                vals = struct.unpack('<3Q2I2H', val_bytes[:36])
                maybe_store(src_ip, {
                    'syn_count': vals[0],
                    'rst_count': vals[1],
                    'packets_total': vals[2],
                    'first_seen_ts': vals[3],
                    'last_seen_ts': vals[4],
                    'burst_count': vals[5]
                })

        if not ip_behaviors:
            return {}

        # Return top N favoring most recent activity, then packet volume
        sorted_ips = sorted(
            ip_behaviors.items(),
            key=lambda item: (
                item[1].get('last_seen_ts', 0),
                item[1].get('packets_total', 0)
            ),
            reverse=True
        )
        return dict(sorted_ips[:limit])

    except Exception as e:
        logger.error(f"Failed to read source IP behavior: {e}")
        return {}

def get_ratelimit_stats(limit=100):
    """
    LAYER 3: Collect rate limit statistics from ratelimit_map
    Returns top N IPs by blocked_count
    """
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'pinned', get_bpf_map_path('ratelimit'), '--json'],
            capture_output=True,
            text=True,
            timeout=15
        )
        _log_local_bpf('dump', 'ratelimit', result.returncode, result.stderr)
        if result.returncode != 0:
            return []

        map_data = json.loads(result.stdout or "[]")

        ip_stats = []
        for entry in map_data:
            try:
                # key is u32 (IP address in network byte order)
                key_val = entry.get('key')
                if isinstance(key_val, int):
                    # Convert network byte order int to IP string
                    import socket
                    import struct
                    ip_bytes = struct.pack('<I', key_val)  # Little-endian to bytes
                    ip = socket.inet_ntoa(ip_bytes)
                else:
                    continue

                # value is struct ratelimit_state: {tokens(u64), last_refill_ns(u64), blocked_count(u32), penalty_level(u8), penalty_expires(u32), pad(u8)}
                value = entry.get('value', {})
                if isinstance(value, dict):
                    blocked_count = value.get('blocked_count', 0)
                else:
                    # Fallback: try to parse formatted value
                    continue

                if blocked_count > 0:
                    ip_stats.append({
                        'ip': ip,
                        'blocked_count': blocked_count
                    })
            except Exception as e:
                logger.debug(f"Failed to parse ratelimit entry: {e}")
                continue

        # Sort by blocked_count descending, return top N
        ip_stats.sort(key=lambda x: x['blocked_count'], reverse=True)
        return ip_stats[:limit]

    except subprocess.TimeoutExpired:
        logger.warning("Rate limit stats collection timed out")
        return []
    except Exception as e:
        logger.error(f"Failed to read rate limit stats: {e}")
        return []

def report_ratelimit_stats_to_emn(node_id, ratelimit_stats):
    """Report rate limit statistics to EMN"""
    if not ratelimit_stats:
        return  # Nothing to report

    try:
        payload = {
            'node_id': node_id,
            'top_blocked': ratelimit_stats
        }

        response = requests.post(
            f"{EMN_URL}/api/v1/ratelimit/stats",
            json=payload,
            timeout=10
        )

        if response.status_code == 200:
            logger.debug(f"Rate limit stats sent: {len(ratelimit_stats)} IPs")
        else:
            logger.warning(f"Rate limit stats failed: {response.status_code}")

    except Exception as e:
        logger.error(f"Failed to report rate limit stats: {e}")

def get_quarantine_stats(limit=50):
    """
    LAYER 4: Collect quarantine map statistics
    Returns count and sample of quarantined IPs
    """
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'pinned', get_bpf_map_path('quarantine'), '--json'],
            capture_output=True,
            text=True,
            timeout=15
        )
        _log_local_bpf('dump', 'quarantine', result.returncode, result.stderr)

        if result.returncode != 0:
            return {'count': 0, 'entries': []}

        map_data = json.loads(result.stdout or "[]")

        entries = []
        for entry in map_data[:limit]:  # Top N entries
            try:
                key_data = entry.get('key', {})
                value_data = entry.get('value', {})

                entries.append({
                    'src_ip': key_data.get('src_ip', 0),
                    'vip_ip': key_data.get('vip_ip', 0),
                    'score': value_data.get('score', 0),
                    'reason': value_data.get('reason', 0),
                    'expires_at_ns': value_data.get('expires_at_ns', 0)
                })
            except:
                continue

        return {'count': len(map_data), 'entries': entries}

    except Exception as e:
        logger.error(f"Failed to read quarantine map: {e}")
        return {'count': 0, 'entries': []}

def get_bypass_stats():
    """
    LAYER 4: Collect bypass map statistics
    Returns count of active bypass entries
    """
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'show', 'pinned', get_bpf_map_path('bypass')],
            capture_output=True,
            text=True,
            timeout=10
        )
        _log_local_bpf('show', 'bypass', result.returncode, result.stderr)

        if result.returncode != 0:
            return {'count': 0}

        # Parse output for current_entries
        # Output format: "id: 123 ... current_entries: 456"
        import re
        match = re.search(r'current_entries:\s*(\d+)', result.stdout)
        count = int(match.group(1)) if match else 0

        return {'count': count}

    except Exception as e:
        logger.error(f"Failed to read bypass map: {e}")
        return {'count': 0}

def report_layer4_stats_to_emn(node_id, quarantine_stats, bypass_stats):
    """Report Layer 4 (quarantine/bypass) statistics to EMN"""
    try:
        payload = {
            'node_id': node_id,
            'quarantine': quarantine_stats,
            'bypass': bypass_stats
        }

        response = requests.post(
            f"{EMN_URL}/api/v1/layer4/stats",
            json=payload,
            timeout=10
        )

        if response.status_code == 200:
            logger.debug(f"Layer 4 stats sent: {quarantine_stats['count']} quarantined, {bypass_stats['count']} bypassed")
        else:
            logger.warning(f"Layer 4 stats failed: {response.status_code}")

    except Exception as e:
        logger.error(f"Failed to report Layer 4 stats: {e}")

def load_expected_tunnels():
    """
    Load expected tunnel state from local file.

    This file is maintained by configure-origin.py (on origin add) and by the
    miner's update_expected_tunnels_on_shard() via SSH (on origin remove).
    Returns dict with 'origins' (list) and 'role' (str), or None on error.
    """
    try:
        expected_file = Path('/var/lib/tensorprox/expected_tunnels.json')
        if not expected_file.exists():
            # No expected state yet (fresh deployment or file not created)
            return None

        with open(expected_file, 'r') as f:
            data = json.load(f)
            return {
                'origins': data.get('origins', []),
                'role': data.get('role', 'active')  # Default active for safety
            }

    except Exception as e:
        logger.error(f"Failed to load expected tunnels: {e}")
        return None

def validate_tunnel_state(wg_interfaces, expected_origins):
    """
    Compare expected vs actual tunnel state.

    Returns:
        {
            'missing': ['O2'],      # Expected but not found on disk
            'orphaned': ['O3']      # Found on disk but not expected
        }
    """
    # Extract actual origin IDs from reported interfaces (wgO1 → O1)
    actual_origins = {
        wg['interface'][2:] if wg['interface'].startswith('wg') else wg['interface']
        for wg in wg_interfaces
        if wg['interface'].startswith('wg')
    }

    # Calculate discrepancies
    expected_set = set(expected_origins)
    missing = expected_set - actual_origins
    orphaned = actual_origins - expected_set

    discrepancies = {
        'missing': sorted(list(missing)),
        'orphaned': sorted(list(orphaned))
    }

    # Log locally for debugging
    if missing:
        logger.error(f"Missing tunnels (expected but not found): {missing}")
    if orphaned:
        logger.warning(f"Orphaned tunnels (found but not expected): {orphaned}")

    return discrepancies

# State for delta-based bandwidth calculation
_last_net_bytes = 0
_last_net_time = 0.0

# State for delta-based PPS calculation (total_pps in scrubber_load_map)
_last_packets_per_origin: Dict[str, int] = {}
_last_pps_sample_time = 0.0

# State for interface speed caching (link speed doesn't change at runtime)
_cached_link_speed_bps: Optional[int] = None


def _get_monotonic_ns() -> int:
    """
    Get monotonic nanoseconds matching kernel's bpf_ktime_get_ns().
    Reads /proc/uptime to match XDP's clock domain.
    """
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_sec = float(f.read().split()[0])
        return int(uptime_sec * 1_000_000_000)
    except Exception:
        # Fallback to Python monotonic (may have different epoch but still useful)
        return time.monotonic_ns()


def _get_interface_speed_bps(interface: str = 'ens5') -> int:
    """
    Get interface link speed in bits per second.
    Reads from /sys/class/net/{interface}/speed (reports Mbps).
    Falls back to 10 Gbps if unavailable.
    Caches result since link speed doesn't change at runtime.
    """
    global _cached_link_speed_bps
    if _cached_link_speed_bps is not None:
        return _cached_link_speed_bps

    DEFAULT_BPS = 1_000_000_000  # 1 Gbps fallback
    try:
        with open(f'/sys/class/net/{interface}/speed', 'r') as f:
            speed_mbps = int(f.read().strip())
            if speed_mbps > 0:
                _cached_link_speed_bps = speed_mbps * 1_000_000  # Mbps to bps
            else:
                _cached_link_speed_bps = DEFAULT_BPS
    except (FileNotFoundError, ValueError, PermissionError, OSError):
        # OSError with EINVAL can occur on virtual interfaces (AWS, etc.)
        _cached_link_speed_bps = DEFAULT_BPS

    return _cached_link_speed_bps


def _get_bandwidth_utilization() -> int:
    """
    Calculate bandwidth utilization as percentage (0-100).
    Uses delta-based calculation between calls.
    """
    global _last_net_bytes, _last_net_time

    net_io = psutil.net_io_counters(pernic=True).get('ens5')
    if not net_io:
        return 0

    current_bytes = net_io.bytes_sent + net_io.bytes_recv
    current_time = time.time()

    if _last_net_time == 0:
        _last_net_bytes = current_bytes
        _last_net_time = current_time
        return 0

    elapsed = current_time - _last_net_time
    if elapsed < 0.1:
        return 0  # Too soon for accurate measurement

    bytes_delta = current_bytes - _last_net_bytes
    bps = (bytes_delta * 8) / elapsed  # bits per second

    _last_net_bytes = current_bytes
    _last_net_time = current_time

    max_bps = _get_interface_speed_bps()
    return min(100, round((bps / max_bps) * 100))


def _calculate_total_pps() -> int:
    """
    Calculate aggregate PPS across all origins using delta-based calculation.

    Uses the same proven approach as miner's health.py:
    - Track previous packets_total per origin
    - Calculate delta (handle restart: if delta < 0, use current as delta)
    - Sum deltas across all origins
    - Divide by elapsed time to get PPS

    Returns:
        int: Total packets per second (0 on first call or if dt too small)
    """
    global _last_packets_per_origin, _last_pps_sample_time

    current_time = time.monotonic()
    current_stats = get_origin_stats()

    # First call - initialize state and return 0
    if _last_pps_sample_time == 0.0:
        _last_packets_per_origin = {
            origin_ip: stats.get('packets_total', 0)
            for origin_ip, stats in current_stats.items()
        }
        _last_pps_sample_time = current_time
        return 0

    # Calculate elapsed time
    dt = current_time - _last_pps_sample_time
    if dt < 0.5:
        # Too soon for accurate measurement
        return 0

    # Calculate delta for each origin, handling restarts
    total_packets_delta = 0
    new_packets_state = {}

    for origin_ip, stats in current_stats.items():
        current_packets = stats.get('packets_total', 0)
        last_packets = _last_packets_per_origin.get(origin_ip, 0)

        # Delta calculation with restart detection
        delta = current_packets - last_packets
        if delta < 0:
            # Counter reset detected (scrubber restart or BPF reload)
            delta = current_packets

        total_packets_delta += delta
        new_packets_state[origin_ip] = current_packets

    # Update state for next cycle
    _last_packets_per_origin = new_packets_state
    _last_pps_sample_time = current_time

    # Calculate PPS
    total_pps = int(total_packets_delta / dt)
    return total_pps


def update_scrubber_load_map() -> bool:
    """
    Update scrubber_load_map with current system metrics.
    Called every heartbeat (5s) for XDP to read.

    This provides real-time load awareness to the intelligent rate limiter.
    XDP reads this map to adjust rate limits based on actual system load.
    """
    try:
        # Get CPU utilization (0-100) - non-blocking using cached value
        cpu_pct = int(psutil.cpu_percent(interval=None))
        cpu_pct = min(100, max(0, cpu_pct))

        # Calculate bandwidth utilization from interface stats (delta-based)
        bw_utilization = _get_bandwidth_utilization()

        # Count active origins (WireGuard interfaces that are UP)
        active_origins = 0
        for iface in psutil.net_if_stats():
            if iface.startswith('wg') and psutil.net_if_stats()[iface].isup:
                active_origins += 1

        # Get monotonic timestamp (matches XDP's bpf_ktime_get_ns())
        now_ns = _get_monotonic_ns()

        # Calculate aggregate PPS across all origins (delta-based)
        total_pps = _calculate_total_pps()

        # Pack struct scrubber_load (16 bytes):
        # u8 cpu_pct, u8 bw_utilization_pct, u16 active_origin_count,
        # u32 total_pps, __u64 last_update_ns (unsigned)
        value_bytes = struct.pack('<BBHIQ',
            cpu_pct,
            bw_utilization,
            active_origins,
            total_pps,
            now_ns
        )

        # Convert to hex string for bpftool
        value_hex = ' '.join(f'{b:02x}' for b in value_bytes)

        # Update the map (service runs as root, use full path for reliability)
        result = subprocess.run([
            '/usr/sbin/bpftool', 'map', 'update', 'pinned',
            '/sys/fs/bpf/xdp/globals/scrubber_load_map',
            'key', 'hex', '00', '00', '00', '00',
            'value', 'hex', *value_hex.split()
        ], capture_output=True, text=True, timeout=5)

        if result.returncode != 0:
            logger.warning(f"Failed to update scrubber_load_map: {result.stderr}")
            return False

        return True

    except Exception as e:
        logger.warning(f"Error updating scrubber_load_map: {e}")
        return False


def send_heartbeat(node_id):
    """
    Send ultra-lightweight heartbeat for fast failover detection.

    This is separate from heavy metrics collection. Only sends:
    - node_id
    - timestamp

    Response time: <10ms (no DB writes on miner side)
    """
    try:
        # UPDATE: Update scrubber load map before sending heartbeat
        # This ensures XDP has fresh load metrics every 5 seconds
        update_scrubber_load_map()

        payload = {
            'node_id': node_id,
            'timestamp': time.time()
        }

        response = requests.post(
            f"{EMN_URL}/api/v1/health/heartbeat",
            json=payload,
            timeout=5  # Short timeout for fast detection
        )

        if response.status_code == 200:
            logger.debug(f"Heartbeat sent successfully")
            return True
        else:
            logger.warning(f"Heartbeat failed: {response.status_code}")
            return False

    except requests.exceptions.Timeout:
        logger.warning("Heartbeat timeout - miner may be overloaded")
        return False
    except Exception as e:
        logger.error(f"Heartbeat failed: {e}")
        return False


def report_health_to_emn(node_id, wg_interfaces, system_metrics, tunnel_discrepancies=None):
    """Report health metrics to EMN"""
    try:
        # Get per-origin lifetime statistics
        origin_stats = get_origin_stats()

        # PHASE 2: Get top attacking IPs (for attack fingerprinting)
        source_ip_behavior = get_source_ip_behavior(limit=100)

        # AWS Billing: Per-origin egress tracking (L3 bytes for data transfer billing)
        egress_billing = get_egress_billing_stats()

        # Per-EIP security statistics (PHASE 2: DDoS mitigation tracking)
        eip_security = get_eip_security_stats()

        payload = {
            'node_id': node_id,
            'timestamp': time.time(),
            'wireguard_interfaces': wg_interfaces,
            'system_metrics': system_metrics,
            'origin_stats': origin_stats,
            'source_ip_behavior': source_ip_behavior,  # PHASE 2: Attack fingerprinting data
            'egress_billing': egress_billing,  # AWS Billing: Per-origin L3 egress bytes
            'bandwidth_capacity': get_bandwidth_capacity(),  # QoS: Scrubber bandwidth config
            'bandwidth_usage': get_bandwidth_usage(),  # QoS: Per-origin bandwidth usage
            'eip_security': eip_security,  # PHASE 2: Per-EIP security drop statistics
        }

        # Add tunnel discrepancies only if they exist (minimize payload)
        if tunnel_discrepancies:
            if tunnel_discrepancies['missing'] or tunnel_discrepancies['orphaned']:
                payload['tunnel_discrepancies'] = tunnel_discrepancies
                logger.info(f"Reporting tunnel discrepancies: missing={tunnel_discrepancies['missing']}, orphaned={tunnel_discrepancies['orphaned']}")

        response = requests.post(
            f"{EMN_URL}/api/v1/health/node",
            json=payload,
            timeout=10
        )

        if response.status_code == 200:
            logger.info(f"Health report sent successfully")
        else:
            logger.warning(f"Health report failed: {response.status_code} {response.text}")

    except Exception as e:
        logger.error(f"Failed to report health: {e}")

def report_metrics_to_emn(node_id, xdp_metrics, syncookie_metrics=None, cookie_failures=None):
    """Report DDoS metrics to EMN (separate from health)"""
    if xdp_metrics is None and not syncookie_metrics and not cookie_failures:
        return  # Nothing to report

    try:
        payload = {
            'node_id': node_id,
            'timestamp': time.time(),
            'xdp_metrics': xdp_metrics or {}
        }

        if syncookie_metrics:
            payload['syncookie_metrics'] = syncookie_metrics
            logger.info(f"Posting {len(syncookie_metrics)} syncookie metric entries")
        if cookie_failures:
            payload['cookie_failures'] = cookie_failures

        response = requests.post(
            f"{EMN_URL}/api/v1/metrics",
            json=payload,
            timeout=10
        )

        if response.status_code == 200:
            logger.debug(f"Metrics report sent successfully")
        else:
            logger.warning(f"Metrics report failed: {response.status_code} {response.text}")

    except Exception as e:
        logger.error(f"Failed to report metrics: {e}")

def main():
    """
    Main agent loop with DUAL-CYCLE reporting:

    1. HEARTBEAT (every 5s): Ultra-lightweight "I'm alive" ping for fast failover detection
       - Enables sub-25-second failover detection
       - No heavy collection, minimal payload

    2. METRICS (every 30s): Heavy collection (XDP stats, origin metrics, etc.)
       - BPF map dumps
       - Origin statistics
       - Rate limit stats
       - Layer 4 stats
    """
    # Use NODE_ID from environment if set, otherwise query metadata service
    node_id = NODE_ID if NODE_ID != 'unknown' else get_node_metadata()
    logger.info(f"ECP Agent starting - Node ID: {node_id}")
    logger.info(f"EMN URL: {EMN_URL}")
    logger.info(f"Heartbeat interval: {HEARTBEAT_INTERVAL}s (fast failover)")
    logger.info(f"Metrics interval: {METRICS_INTERVAL}s (heavy collection)")

    last_metrics_time = 0  # Force immediate metrics on startup

    while True:
        try:
            current_time = time.time()

            # === HEARTBEAT (every cycle - fast) ===
            send_heartbeat(node_id)

            # === METRICS (only when interval elapsed - heavy) ===
            if (current_time - last_metrics_time) >= METRICS_INTERVAL:
                logger.info("Starting heavy metrics collection cycle...")

                # Collect health data
                wg_interfaces = check_wireguard_interfaces()

                # STANDBY MODE CHECK: Use explicit role from expected_tunnels.json
                # Role is set by miner when assigning EIP (active) or as backup (standby)
                # This is authoritative - packet count check was unreliable for new active nodes
                expected_data = load_expected_tunnels()
                if expected_data and expected_data.get('role') == 'standby':
                    logger.debug("Role=standby, skipping heavy metrics collection")
                    last_metrics_time = current_time
                    time.sleep(HEARTBEAT_INTERVAL)
                    continue

                system_metrics = get_system_metrics()

                logger.info(
                    f"Collected: {len(wg_interfaces)} WG interfaces, "
                    f"CPU: {system_metrics['cpu_percent']}%"
                )

                # Context-sensitive validation: Compare expected vs actual tunnel state
                # expected_data already loaded above for standby check
                expected_origins = expected_data.get('origins', []) if expected_data else []
                tunnel_discrepancies = validate_tunnel_state(wg_interfaces, expected_origins)

                # Report health to EMN (infrastructure status + tunnel validation)
                report_health_to_emn(node_id, wg_interfaces, system_metrics, tunnel_discrepancies)

                # Collect and report DDoS metrics (separate pipeline)
                xdp_metrics = get_xdp_metrics()
                vip_cookie_modes, origin_to_vip = get_vip_metadata()
                syncookie_metrics = get_syncookie_metrics(
                    cookie_modes=vip_cookie_modes,
                    origin_to_vip=origin_to_vip
                )
                cookie_failures = get_cookie_failure_samples()

                if xdp_metrics or syncookie_metrics or cookie_failures:
                    if syncookie_metrics:
                        logger.info(f"Syncookie metrics collected: {len(syncookie_metrics)} entries")
                    report_metrics_to_emn(node_id, xdp_metrics, syncookie_metrics, cookie_failures)
                    logger.debug(
                        f"Metrics posted: xdp={bool(xdp_metrics)} "
                        f"syncookies={len(syncookie_metrics)} cookie_failures={len(cookie_failures)}"
                    )

                # LAYER 3: Collect and report rate limit statistics
                ratelimit_stats = get_ratelimit_stats(limit=100)
                if ratelimit_stats:
                    report_ratelimit_stats_to_emn(node_id, ratelimit_stats)
                    logger.debug(f"Rate limit stats: {len(ratelimit_stats)} IPs with blocks")

                # LAYER 4: Collect and report quarantine/bypass statistics
                quarantine_stats = get_quarantine_stats(limit=50)
                bypass_stats = get_bypass_stats()
                if quarantine_stats['count'] > 0 or bypass_stats['count'] > 0:
                    report_layer4_stats_to_emn(node_id, quarantine_stats, bypass_stats)
                    logger.debug(
                        f"Layer 4 stats: {quarantine_stats['count']} quarantined, "
                        f"{bypass_stats['count']} bypassed"
                    )

                last_metrics_time = current_time
                logger.info("Heavy metrics collection complete")

        except Exception as e:
            logger.error(f"Agent cycle failed: {e}")

        # Wait for next heartbeat cycle
        time.sleep(HEARTBEAT_INTERVAL)

if __name__ == '__main__':
    main()
