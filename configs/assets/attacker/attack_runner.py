#!/usr/bin/env python3
"""Helper to run canned attack scripts with consistent interface.

The functional test orchestrator can SSH into an attacker node and invoke this
script instead of re-implementing per-attack CLI conventions.

Usage:
    python3 attack_runner.py --attack syn-flood --target 203.0.113.10 \
        --port 7080 --duration 60
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

ATTACK_SCRIPTS = {
    'syn-flood': {
        'script': 'syn-flood.sh',
        'args': ['target', 'port', 'duration'],
        'defaults': {'port': 7080, 'duration': 60},
        'help': 'Layer4 SYN flood using hping3',
    },
    'rst-flood': {
        'script': 'rst-flood.sh',
        'args': ['target', 'port', 'count'],
        'defaults': {'port': 7080, 'count': 20000},
        'help': 'Layer4 RST flood spike',
    },
    'pps-spike': {
        'script': 'pps-spike.sh',
        'args': ['target', 'port', 'duration'],
        'defaults': {'port': 7080, 'duration': 30},
        'help': 'High packet-per-second spike',
    },
    'cps-spike': {
        'script': 'cps-spike.sh',
        'args': ['target', 'port', 'duration'],
        'defaults': {'port': 7080, 'duration': 30},
        'help': 'High connections-per-second spike',
    },
    'slowloris': {
        'script': 'slowloris.sh',
        'args': ['target', 'port', 'duration'],
        'defaults': {'port': 7080, 'duration': 120},
        'help': 'Slowloris style Layer7 attack',
    },
    'port-scan': {
        'script': 'port-scan.sh',
        'args': ['target', 'ports'],
        'defaults': {'ports': '7000-7100'},
        'help': 'nmap-based TCP scan',
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--attack',
        choices=ATTACK_SCRIPTS.keys(),
        required=True,
        help='Attack profile to execute',
    )
    parser.add_argument('--target', required=True, help='Target EIP / hostname')
    parser.add_argument('--port', type=int, help='Destination port (if applicable)')
    parser.add_argument('--duration', type=int, help='Attack duration seconds')
    parser.add_argument('--count', type=int, help='Packet count for burst attacks')
    parser.add_argument('--ports', help='Port range for scans (e.g., 7000-7100)')
    return parser.parse_args()


def build_command(args: argparse.Namespace) -> list[str]:
    profile = ATTACK_SCRIPTS[args.attack]
    script_path = ROOT / profile['script']
    if not script_path.exists():
        raise SystemExit(f"Attack script missing: {script_path}")

    mapping = {
        'target': args.target,
        'port': str(args.port or profile['defaults'].get('port', '')),
        'duration': str(args.duration or profile['defaults'].get('duration', '')),
        'count': str(args.count or profile['defaults'].get('count', '')),
        'ports': args.ports or profile['defaults'].get('ports', ''),
    }

    cmd = [str(script_path)]
    for field in profile['args']:
        value = mapping.get(field)
        if not value:
            raise SystemExit(f"Missing required parameter '{field}' for {args.attack}")
        cmd.append(value)
    return cmd


def main():
    args = parse_args()
    cmd = build_command(args)
    print(f"[attack_runner] Executing: {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, check=False)
    if proc.returncode != 0:
        sys.exit(proc.returncode)


if __name__ == '__main__':
    main()
