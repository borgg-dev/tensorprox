#!/usr/bin/env python3
"""Configure the WireGuard transparent dataplane for an origin."""

import argparse
import ipaddress
import json
import struct
import subprocess
import time
from pathlib import Path

BPF_ROOT = Path("/opt/tensorprox/ebpf")
OBJ_DIR = BPF_ROOT / "build"
WAN_MAP_PATH = Path("/sys/fs/bpf/tc/globals/eip_map")
WG_MAP_PATH = Path("/sys/fs/bpf/tc/globals/wg2priv_map")
WG_IFINDEX_TO_ORIGIN_MAP_PATH = Path("/sys/fs/bpf/tc/globals/wg_ifindex_to_origin_map")
SYS_NET = Path("/sys/class/net")


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def verify_deployment_complete() -> None:
    """Verify scrubber deployment completed successfully"""
    # Check XDP loaded
    result = subprocess.run(
        ["bpftool", "net", "show", "dev", "ens5"],
        capture_output=True, text=True
    )
    if "xdp" not in result.stdout:
        raise RuntimeError("XDP not loaded on ens5. Run bootstrap_inner.sh first.")

    # Required maps (Layer 0 verification)
    required_maps = [
        "/sys/fs/bpf/tc/globals/eip_map",
        "/sys/fs/bpf/xdp/globals/xdp_wan_stats",
        "/sys/fs/bpf/xdp/globals/blacklist_map",
        "/sys/fs/bpf/xdp/globals/whitelist_map",
        "/sys/fs/bpf/xdp/globals/machine_limits_map",
        "/sys/fs/bpf/xdp/globals/challenge_level_map",
        "/sys/fs/bpf/xdp/globals/quarantine_map",
        "/sys/fs/bpf/xdp/globals/bypass_map",
        "/sys/fs/bpf/xdp/globals/vip_state_map",
    ]

    missing = [m for m in required_maps if not Path(m).exists()]
    if missing:
        raise RuntimeError(f"Required maps missing: {missing}. Run bootstrap_inner.sh.")

    # Check TC loaded on WAN
    tc_check = subprocess.run(
        ["tc", "filter", "show", "dev", "ens5", "ingress"],
        capture_output=True, text=True
    )
    if "tc_ingress_wan" not in tc_check.stdout and "direct-action" not in tc_check.stdout:
        raise RuntimeError("TC ingress not attached. Run module 40-runtime.sh.")

    print("✓ Deployment verification passed (all maps and programs loaded)")


def hex_bytes(data: bytes) -> list[str]:
    return [f"{b:02x}" for b in data]


def ensure_accept_local(interface: str) -> None:
    drop_in = Path("/etc/sysctl.d/60-wireguard-accept-local.conf")
    line = f"net.ipv4.conf.{interface}.accept_local=1\n"
    existing = drop_in.read_text().splitlines() if drop_in.exists() else []
    if line.strip() not in (x.strip() for x in existing):
        existing.append(line.strip())
        drop_in.write_text("\n".join(existing) + "\n")
    run(["sysctl", f"net.ipv4.conf.{interface}.accept_local=1"])


def wait_for_interface(interface: str, timeout: int = 30) -> None:
    """Wait until /sys/class/net/<interface> exists."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if (SYS_NET / interface).exists():
            return
        time.sleep(1)
    raise RuntimeError(f"Interface {interface} not present after {timeout}s")


def attach_wg_tc(interface: str) -> None:
    wait_for_interface(interface)
    obj = OBJ_DIR / "tc_ingress_wg.o"
    if not obj.exists():
        raise FileNotFoundError(f"Missing {obj}")
    subprocess.run(["tc", "qdisc", "del", "dev", interface, "clsact"], check=False)
    run(["tc", "qdisc", "add", "dev", interface, "clsact"])
    sections = ["tc/ingress", "cls_ingress"]
    last_error = ""
    for section in sections:
        result = subprocess.run(
            [
                "tc",
                "filter",
                "replace",
                "dev",
                interface,
                "ingress",
                "bpf",
                "direct-action",
                "obj",
                str(obj),
                "sec",
                section,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(f"✓ Attached WireGuard TC ingress program using section '{section}'")
            break
        last_error = result.stderr or result.stdout
    else:
        raise RuntimeError(
            f"Failed to attach WireGuard TC ingress ({obj}). Last error: {last_error.strip()}"
        )

    # Attach egress monitor for AWS billing (L3 bytes per-origin)
    attach_wg_egress_monitor(interface)


def attach_wg_egress_monitor(interface: str) -> None:
    """Attach wg_egress_monitor TC program for per-origin egress billing tracking."""
    obj = OBJ_DIR / "wg_egress_monitor.o"
    if not obj.exists():
        print(f"⚠ Skipping egress billing: {obj} not found")
        return

    sections = ["tc/egress", "cls_egress"]
    last_error = ""
    for section in sections:
        result = subprocess.run(
            [
                "tc",
                "filter",
                "replace",
                "dev",
                interface,
                "egress",
                "bpf",
                "direct-action",
                "obj",
                str(obj),
                "sec",
                section,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(f"✓ Attached WireGuard TC egress monitor (billing) using section '{section}'")
            return
        last_error = result.stderr or result.stdout
    print(f"⚠ Failed to attach egress billing monitor: {last_error.strip()}")


def update_maps(private_ip: str, origin_ip: str, ifindex: int) -> None:
    priv_packed = ipaddress.IPv4Address(private_ip).packed
    origin_packed = ipaddress.IPv4Address(origin_ip).packed

    eip_value = origin_packed + struct.pack("<I", ifindex) + struct.pack("<I", 1)
    run([
        "bpftool",
        "map",
        "update",
        "pinned",
        str(WAN_MAP_PATH),
        "key",
        "hex",
        *hex_bytes(priv_packed),
        "value",
        "hex",
        *hex_bytes(eip_value),
    ])

    run([
        "bpftool",
        "map",
        "update",
        "pinned",
        str(WG_MAP_PATH),
        "key",
        "hex",
        *hex_bytes(struct.pack("<I", ifindex)),
        "value",
        "hex",
        *hex_bytes(priv_packed),
    ])

    # Map WG interface index to origin_ip for billing attribution
    # All traffic on this WG interface gets billed to this origin
    run([
        "bpftool",
        "map",
        "update",
        "pinned",
        str(WG_IFINDEX_TO_ORIGIN_MAP_PATH),
        "key",
        "hex",
        *hex_bytes(struct.pack("<I", ifindex)),
        "value",
        "hex",
        *hex_bytes(origin_packed),
    ])
    print(f"✓ Mapped wg ifindex {ifindex} -> origin {origin_ip} for billing")


def init_origin_counters(origin_ip: str) -> None:
    """Initialize origin_stats_map with zeroed lifetime counters"""
    packed = ipaddress.IPv4Address(origin_ip).packed
    # origin_stats struct: 7 × u64 = 56 bytes (bytes_total removed)
    zeros = bytes(56)

    run([
        "bpftool", "map", "update", "pinned",
        "/sys/fs/bpf/tc/globals/origin_stats_map",
        "key", "hex", *hex_bytes(packed),
        "value", "hex", *hex_bytes(zeros)
    ])
    print(f"✓ Initialized origin_stats for {origin_ip}")


def init_vip_state(origin_ip: str) -> None:
    """Initialize per-VIP state machine (NORMAL mode)"""
    packed = ipaddress.IPv4Address(origin_ip).packed
    # vip_state struct: {u8 flags, u8 challenge_level, u16 reserved, u32 state_changed_ts}
    # Start in NORMAL: flags=0, challenge_level=0, reserved=0, ts=0
    state_value = bytes(8)  # All zeros

    run([
        "bpftool", "map", "update", "pinned",
        "/sys/fs/bpf/xdp/globals/vip_state_map",
        "key", "hex", *hex_bytes(packed),
        "value", "hex", *hex_bytes(state_value)
    ])
    print(f"✓ Initialized VIP state for {origin_ip} (NORMAL mode)")


def init_reverse_nat(origin_ip: str, private_ip: str) -> None:
    """Initialize reverse NAT map for egress SNAT (origin_ip -> private_ip)"""
    origin_packed = ipaddress.IPv4Address(origin_ip).packed
    priv_packed = ipaddress.IPv4Address(private_ip).packed

    # reverse_nat_entry struct: {__be32 priv_ip} = 4 bytes

    run([
        "bpftool", "map", "update", "pinned",
        "/sys/fs/bpf/tc/globals/origin_to_priv_map",
        "key", "hex", *hex_bytes(origin_packed),
        "value", "hex", *hex_bytes(priv_packed)
    ])
    print(f"✓ Initialized reverse NAT: {origin_ip} -> {private_ip}")


def init_origin_rate_config(origin_ip: str, private_ip: str) -> None:
    """
    Initialize origin_rate_config_map with default values.

    This provides a baseline configuration that the miner will override
    with actual bandwidth-derived values during origin registration.

    IMPORTANT: This is a fallback only. The miner should push the real
    config with bandwidth quota-derived values.

    NOTE: Default uses 50 PPS which works for audit mode. Production
    origins will have the miner push 10K+ PPS limits. This is safe
    because the miner always pushes the correct config after origin
    creation - this default just ensures XDP has valid values.
    """
    packed = ipaddress.IPv4Address(origin_ip).packed

    # Default origin_rate_config struct (24 bytes):
    # u64 quota_bps = 1 Gbps (default)
    # u32 derived_max_pps = ~83K
    # u32 per_source_budget_pps = 50 (conservative default for audit mode)
    # u32 current_pps = 0
    # u8  challenge_level = 0 (NORMAL)
    # u8  override_enabled = 0 (use derived)
    # u16 override_pps = 0
    #
    # The miner MUST push the actual config after origin creation.
    # This default is conservative (low rate limit) to ensure audit works
    # if the miner's config push is delayed.

    default_config = struct.pack('<QIIIBBH',
        1_000_000_000,  # quota_bps: 1 Gbps default
        83333,          # derived_max_pps
        50,             # per_source_budget_pps: 50 PPS (audit-safe default)
        0,              # current_pps
        0,              # challenge_level: NORMAL
        0,              # override_enabled: False
        0,              # override_pps: 0
    )

    run([
        "bpftool", "map", "update", "pinned",
        "/sys/fs/bpf/xdp/globals/origin_rate_config_map",
        "key", "hex", *hex_bytes(packed),
        "value", "hex", *hex_bytes(default_config)
    ])
    print(f"✓ Initialized rate config for {origin_ip} (default: 50 PPS/source, miner will override)")


def update_expected_tunnels(origin_id: str, action: str = 'add') -> None:
    """
    Update expected tunnels state file for context-sensitive validation.

    This file enables ecp-agent to detect missing/orphaned tunnels by comparing
    expected state (from miner) vs actual state (filesystem scan).

    Args:
        origin_id: Origin ID (e.g., 'O1')
        action: 'add' or 'remove'
    """
    expected_file = Path('/var/lib/tensorprox/expected_tunnels.json')
    expected_file.parent.mkdir(parents=True, exist_ok=True)

    # Load existing state
    if expected_file.exists():
        try:
            with open(expected_file, 'r') as f:
                data = json.load(f)
        except Exception:
            data = {'origins': [], 'role': 'active', 'updated_at': 0}
    else:
        data = {'origins': [], 'role': 'active', 'updated_at': 0}

    # Preserve role from existing file, default to 'active' if not present
    role = data.get('role', 'active')

    # Update origin list
    origins_set = set(data.get('origins', []))

    if action == 'add' and origin_id not in origins_set:
        origins_set.add(origin_id)
        print(f"✓ Added {origin_id} to expected tunnels")
    elif action == 'remove' and origin_id in origins_set:
        origins_set.remove(origin_id)
        print(f"✓ Removed {origin_id} from expected tunnels")

    # Rebuild data with preserved role
    data = {
        'origins': sorted(list(origins_set)),
        'role': role,
        'updated_at': int(time.time())
    }

    # Atomic write
    tmp_file = expected_file.with_suffix('.tmp')
    with open(tmp_file, 'w') as f:
        json.dump(data, f, indent=2)
    tmp_file.replace(expected_file)

    print(f"✓ Expected tunnels state: {data['origins']} (role: {role})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Configure the WireGuard dataplane for an origin")
    parser.add_argument("--wg-interface", required=True)
    parser.add_argument("--private-ip", required=True)
    parser.add_argument("--origin-ip", required=True)
    parser.add_argument("--origin-id", required=False, default=None,
                        help="Origin ID (e.g., 'O37'). If not provided, derived from wg-interface.")
    args = parser.parse_args()

    # Verify deployment complete before configuring origin
    verify_deployment_complete()

    # Check if interface exists (determines active vs standby mode)
    interface_path = Path(f"/sys/class/net/{args.wg_interface}")
    interface_exists = interface_path.exists()

    if interface_exists:
        # ACTIVE MODE: Interface running, full configuration with TC programs
        print(f"✓ Interface {args.wg_interface} exists (active mode)")

        ifindex = int((interface_path / "ifindex").read_text().strip())

        attach_wg_tc(args.wg_interface)
        ensure_accept_local(args.wg_interface)
        update_maps(args.private_ip, args.origin_ip, ifindex)

    else:
        # STANDBY MODE: Interface not running, BPF maps only (no TC)
        print(f"✓ Interface {args.wg_interface} doesn't exist (standby mode - hot standby config)")
        print("  Configuring BPF maps without TC attachment (TC will be attached during failover)")

        # NOTE: In standby mode, we can't populate eip_map or wg2priv_map because:
        # - eip_map needs ifindex (interface must exist)
        # - wg2priv_map needs ifindex as key
        # These will be configured when interface is created during failover.
        # We can still initialize origin counters and VIP state (global maps).
        print(f"  ⚠ Skipping eip_map/wg2priv_map (requires interface)")
        print(f"  ✓ Will initialize origin stats and VIP state")

    # Initialize Layer 0 state (works in both modes - global maps)
    init_origin_counters(args.origin_ip)
    init_vip_state(args.origin_ip)
    init_reverse_nat(args.origin_ip, args.private_ip)
    init_origin_rate_config(args.origin_ip, args.private_ip)

    # Update expected tunnels state for context-sensitive validation
    # Use explicit origin_id if provided, otherwise derive from interface name (legacy fallback)
    if args.origin_id:
        origin_id = args.origin_id
    else:
        # Legacy fallback: extract from interface name (wgO1 → O1)
        # WARNING: This is incorrect when origin_id differs from wg_interface suffix
        origin_id = args.wg_interface[2:] if args.wg_interface.startswith('wg') else args.wg_interface
        print(f"  ⚠ No --origin-id provided, derived '{origin_id}' from interface name")
    update_expected_tunnels(origin_id, action='add')

    if interface_exists:
        print(f"✓ Active configuration complete")
    else:
        print(f"✓ Standby hot configuration complete (TC deferred to failover)")


if __name__ == "__main__":
    main()
