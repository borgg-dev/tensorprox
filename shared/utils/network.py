"""Network utilities

IP addressing, routing calculations, and network helpers.
"""


def calculate_policy_table(origin_num: int) -> int:
    """Deterministic routing table number for an origin."""
    return 60000 + origin_num


def calculate_policy_priority(origin_num: int) -> int:
    """Deterministic routing rule priority for an origin."""
    return 20000 + origin_num


def hex_bytes(data: bytes) -> list:
    """Convert bytes to hex string list for bpftool"""
    return [f"{b:02x}" for b in data]
