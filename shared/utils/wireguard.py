"""
WireGuard utility functions.

Provides key generation and configuration building for
WireGuard tunnels between scrubbers and exit hubs.
"""

import subprocess
from typing import Tuple, Optional

from loguru import logger


def generate_wg_keys() -> Tuple[str, str]:
    """
    Generate a WireGuard key pair.

    Returns:
        Tuple of (private_key, public_key).
    """
    # Generate private key
    result = subprocess.run(
        ["wg", "genkey"],
        capture_output=True,
        text=True,
        check=True
    )
    private_key = result.stdout.strip()

    # Derive public key
    result = subprocess.run(
        ["wg", "pubkey"],
        input=private_key,
        capture_output=True,
        text=True,
        check=True
    )
    public_key = result.stdout.strip()

    return private_key, public_key


def build_exit_hub_config(
    edge_pub_key: str,
    hub_priv_key: str,
    hub_ip: str,
    active_ip: str,
    wg_port: int = 51820,
    keepalive: int = 15
) -> str:
    """
    Build WireGuard configuration for an exit hub.

    Args:
        edge_pub_key: Scrubber's public key.
        hub_priv_key: Exit hub's private key.
        hub_ip: Exit hub's WireGuard interface IP.
        active_ip: Active scrubber's public IP.
        wg_port: WireGuard UDP port.
        keepalive: Keepalive interval in seconds.

    Returns:
        WireGuard configuration file content.
    """
    config = f"""[Interface]
PrivateKey = {hub_priv_key}
Address = {hub_ip}/30
ListenPort = {wg_port}
Table = off

[Peer]
PublicKey = {edge_pub_key}
Endpoint = {active_ip}:{wg_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = {keepalive}
"""
    return config


def build_scrubber_config(
    hub_pub_key: str,
    edge_priv_key: str,
    edge_ip: str,
    hub_ip: str,
    wg_port: int = 51820,
    keepalive: int = 15
) -> str:
    """
    Build WireGuard configuration for a scrubber.

    Args:
        hub_pub_key: Exit hub's public key.
        edge_priv_key: Scrubber's private key.
        edge_ip: Scrubber's WireGuard interface IP.
        hub_ip: Exit hub's public IP.
        wg_port: WireGuard UDP port.
        keepalive: Keepalive interval in seconds.

    Returns:
        WireGuard configuration file content.
    """
    config = f"""[Interface]
PrivateKey = {edge_priv_key}
Address = {edge_ip}/30
ListenPort = {wg_port}
Table = off

[Peer]
PublicKey = {hub_pub_key}
Endpoint = {hub_ip}:{wg_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = {keepalive}
"""
    return config


def parse_wg_status(output: str) -> dict:
    """
    Parse output from 'wg show' command.

    Args:
        output: Raw output from 'wg show'.

    Returns:
        Dictionary with parsed WireGuard status.
    """
    result = {
        "interface": None,
        "public_key": None,
        "listening_port": None,
        "peers": []
    }

    current_peer = None

    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.startswith("interface:"):
            result["interface"] = line.split(":")[1].strip()
        elif line.startswith("public key:"):
            result["public_key"] = line.split(":")[1].strip()
        elif line.startswith("listening port:"):
            result["listening_port"] = int(line.split(":")[1].strip())
        elif line.startswith("peer:"):
            if current_peer:
                result["peers"].append(current_peer)
            current_peer = {"public_key": line.split(":")[1].strip()}
        elif current_peer:
            if line.startswith("endpoint:"):
                current_peer["endpoint"] = line.split(":", 1)[1].strip()
            elif line.startswith("allowed ips:"):
                current_peer["allowed_ips"] = line.split(":")[1].strip()
            elif line.startswith("latest handshake:"):
                current_peer["latest_handshake"] = line.split(":", 1)[1].strip()
            elif line.startswith("transfer:"):
                current_peer["transfer"] = line.split(":")[1].strip()

    if current_peer:
        result["peers"].append(current_peer)

    return result


def allocate_wg_ips(origin_id: str, base_subnet: str = "10.20.30") -> Tuple[str, str]:
    """
    Allocate WireGuard IPs for an origin.

    Uses the origin_id to create deterministic IP allocation
    within a /30 subnet.

    Args:
        origin_id: Origin identifier (e.g., "O37").
        base_subnet: Base /24 subnet.

    Returns:
        Tuple of (scrubber_ip, exit_hub_ip).
    """
    # Extract numeric part from origin_id
    if origin_id.startswith("O"):
        origin_num = int(origin_id[1:])
    else:
        origin_num = hash(origin_id) % 60

    # Calculate /30 subnet offset (each origin gets 4 IPs)
    subnet_offset = (origin_num * 4) % 252

    scrubber_ip = f"{base_subnet}.{subnet_offset + 1}"
    exit_hub_ip = f"{base_subnet}.{subnet_offset + 2}"

    return scrubber_ip, exit_hub_ip


def get_wg_interface_name(origin_id: str) -> str:
    """
    Get WireGuard interface name for an origin.

    Args:
        origin_id: Origin identifier.

    Returns:
        Interface name (e.g., "wgO37").
    """
    return f"wg{origin_id}"


def calculate_wg_port(origin_id: str, base_port: int = 51820) -> int:
    """
    Calculate WireGuard port for an origin.

    Args:
        origin_id: Origin identifier.
        base_port: Base port number.

    Returns:
        Port number for this origin.
    """
    if origin_id.startswith("O"):
        origin_num = int(origin_id[1:])
    else:
        origin_num = hash(origin_id) % 1000

    return base_port + origin_num
