"""Shared helpers for handling port lists."""
from __future__ import annotations

from typing import Iterable, List, Sequence, Union


def normalize_port_list(raw_ports: Union[None, int, str, Sequence[Union[int, str]], dict]) -> List[int]:
    """
    Accept any historical port payload (list, dict with tcp/udp, mixed types, comma-separated strings)
    and return a sorted list of unique integers.

    Supports:
    - [80, 443, 8080]
    - "80, 443, 8080"
    - {"tcp": [80, 443], "udp": [53]}
    - 8080
    """
    if raw_ports is None:
        return []

    ports: List[int] = []
    values: Iterable = []

    if isinstance(raw_ports, dict):
        values = raw_ports.values()
    elif isinstance(raw_ports, (list, tuple, set)):
        values = raw_ports
    elif isinstance(raw_ports, str):
        # Handle comma-separated string (from web UI text fields)
        values = [p.strip() for p in raw_ports.split(',') if p.strip()]
    else:
        values = [raw_ports]

    for entry in values:
        if isinstance(entry, (list, tuple, set)):
            items = entry
        else:
            items = [entry]
        for item in items:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
            if 0 < port < 65536:
                ports.append(port)

    return sorted(set(ports))
