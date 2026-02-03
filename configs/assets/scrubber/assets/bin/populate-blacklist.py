#!/usr/bin/env python3
"""Populate blacklist_map (LPM_TRIE) from threat intelligence feeds with native CIDR support"""

import requests
import subprocess
import ipaddress
import struct
import sys

# IMPORTANT: blacklist_map is defined in xdp_wan.c (XDP program)
# so it's pinned at /sys/fs/bpf/xdp/globals/ (NOT /sys/fs/bpf/tc/globals/)
BLACKLIST_MAP_PATH = "/sys/fs/bpf/xdp/globals/blacklist_map"

# Both Spamhaus (CIDR blocks) and EmergingThreats (individual IPs)
FEEDS = {
    'spamhaus': 'https://www.spamhaus.org/drop/drop.txt',
    'emergingthreats': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
}

def download_threat_feeds():
    """Download and parse threat intelligence feeds - supports both CIDR and individual IPs"""
    entries = []  # List of (network_str, prefixlen) tuples

    for name, url in FEEDS.items():
        try:
            print(f"[populate-blacklist] Downloading {name}...")
            r = requests.get(url, timeout=30)

            for line in r.text.split('\n'):
                line = line.strip()

                # Skip comments and empty lines
                if not line or line[0] in '#;':
                    continue

                # Extract CIDR or IP
                # Spamhaus format: "1.10.16.0/20 ; SBL256894"
                # EmergingThreats format: "101.126.138.113"
                cidr_or_ip = line.split(';')[0].split()[0] if ';' in line or ' ' in line else line

                try:
                    if '/' in cidr_or_ip:
                        # CIDR block (e.g., "1.10.16.0/20")
                        network = ipaddress.IPv4Network(cidr_or_ip, strict=False)
                        entries.append((str(network.network_address), network.prefixlen))
                    elif '.' in cidr_or_ip:
                        # Individual IP - treat as /32
                        ipaddress.IPv4Address(cidr_or_ip)  # Validate
                        entries.append((cidr_or_ip, 32))
                except ValueError:
                    pass  # Skip invalid entries

        except Exception as e:
            print(f"[populate-blacklist] Error downloading {name}: {e}", file=sys.stderr)

    print(f"[populate-blacklist] Total entries collected: {len(entries)} (CIDR blocks + individual IPs)")
    return entries

def populate_blacklist_map(entries):
    """Populate LPM_TRIE blacklist_map with CIDR blocks and individual IPs"""
    success_count = 0
    fail_count = 0

    for ip_str, prefixlen in entries:
        # Build LPM key: {prefixlen (4 bytes little-endian), IP (4 bytes network byte order)}
        # Example: 1.2.3.0/24 → key = [18 00 00 00] [01 02 03 00]
        #          5.6.7.8/32 → key = [20 00 00 00] [05 06 07 08]

        # Convert prefixlen to 4-byte little-endian hex
        prefixlen_hex = struct.pack('<I', prefixlen).hex()

        # Convert IP to 4-byte network byte order (big-endian) hex
        ip_bytes = ipaddress.IPv4Address(ip_str).packed
        ip_hex = ip_bytes.hex()

        # Combine: prefixlen + IP (8 bytes total)
        key_hex = prefixlen_hex + ip_hex

        # Split into space-separated bytes for bpftool
        key_hex_spaced = ' '.join([key_hex[i:i+2] for i in range(0, len(key_hex), 2)])

        # Reputation score 10 = very bad (threshold is < 20)
        result = subprocess.run(
            ['bpftool', 'map', 'update', 'pinned', BLACKLIST_MAP_PATH,
             'key', 'hex'] + key_hex_spaced.split() + ['value', 'hex', '0a'],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            success_count += 1
        else:
            fail_count += 1
            if fail_count < 10:  # Only show first few failures
                print(f"[populate-blacklist] Failed to add {ip_str}/{prefixlen}: {result.stderr.strip()}", file=sys.stderr)

    print(f"[populate-blacklist] Blacklist populated: {success_count} entries added, {fail_count} failed")

    if success_count == 0 and len(entries) > 0:
        # Only warn if we had entries to add but all failed (bpftool issue)
        print("[populate-blacklist] WARNING: No entries added to blacklist_map (bpftool failures)", file=sys.stderr)
        # Don't exit(1) - this shouldn't break bootstrap

if __name__ == '__main__':
    entries = download_threat_feeds()

    if len(entries) == 0:
        # Blacklist is OPTIONAL - don't fail bootstrap if DNS/network issues prevent download
        # Blacklist can be populated later via POST /api/v1/admin/refresh-blacklist
        print("[populate-blacklist] WARNING: No entries downloaded from threat feeds (will be empty)", file=sys.stderr)
        print("[populate-blacklist] Blacklist can be populated later via API", file=sys.stderr)
        sys.exit(0)  # Exit success - empty blacklist is acceptable

    populate_blacklist_map(entries)
