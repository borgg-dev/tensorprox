"""Helpers to start/verify local TensorProx services for test orchestration."""
from __future__ import annotations

import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from shared.utils.logging import get_logger


logger = get_logger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class ServiceProcess:
    name: str
    start_cmd: str
    port: int


SERVICES: Dict[str, ServiceProcess] = {
    "tensorprox": ServiceProcess(
        name="TensorProx Management",
        start_cmd=(
            f"cd {REPO_ROOT} && "
            "nohup env TP_ENV_FILE=tensorprox_management/tp_m.env PYTHONUNBUFFERED=1 PYTHONPATH=$PWD uv run python -m tensorprox_management.tensorprox_management "
            "> /tmp/tensorprox/tpm_stdout.log 2>&1 &"
        ),
        port=5001,
    ),
    "miner": ServiceProcess(
        name="Miner",
        start_cmd=(
            f"cd {REPO_ROOT} && "
            "nohup env PYTHONPATH=$PWD uv run python -m miner.miner "
            "> /tmp/tensorprox/miner.log 2>&1 &"
        ),
        port=8000,
    ),
    "traffic_manager": ServiceProcess(
        name="Traffic Manager",
        start_cmd=(
            f"cd {REPO_ROOT} && "
            "nohup env PYTHONPATH=$PWD uv run python -m traffic_manager.traffic_manager "
            "> /tmp/tensorprox/traffic_manager.log 2>&1 &"
        ),
        port=5002,
    ),
}


def _is_port_open(host: str, port: int, timeout: int = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _wait_for_port(host: str, port: int, deadline: int = 150) -> None:
    end = time.time() + deadline
    while time.time() < end:
        if _is_port_open(host, port):
            return
        time.sleep(2)
    raise TimeoutError(f"Service on {host}:{port} did not become ready within {deadline}s")


def ensure_local_service(service_key: str, *, auto_start: bool) -> bool:
    svc = SERVICES[service_key]
    if _is_port_open("127.0.0.1", svc.port):
        return True
    if not auto_start:
        logger.warning("%s not running and auto-start disabled", svc.name)
        return False
    logger.info("Starting %s...", svc.name)
    subprocess.Popen(["bash", "-lc", svc.start_cmd])
    _wait_for_port("127.0.0.1", svc.port)
    logger.info("%s ready on port %s", svc.name, svc.port)
    return True


def ensure_local_stack(auto_start: bool = True) -> None:
    for key in ("tensorprox", "miner", "traffic_manager"):
        ensure_local_service(key, auto_start=auto_start)


def ensure_miner_ready(target_ip: str, *, auto_start_local: bool, port: int | None = None) -> None:
    """Ensure the target miner endpoint is reachable.

    If the miner IP points to localhost and auto-start is allowed, we bootstrap
    the local Miner process; otherwise we simply verify the TCP port.

    Args:
        target_ip: IP address of the miner
        auto_start_local: Whether to auto-start local services
        port: Optional port override. Defaults to SERVICES["miner"].port (8000) for local.
    """
    if not target_ip:
        raise ValueError("Miner IP is required")
    if target_ip in {"127.0.0.1", "localhost"}:
        # Use provided port or default to SERVICES["miner"].port
        miner_port = port if port is not None else SERVICES["miner"].port
        # Check if miner is already running on the specified port
        if _is_port_open("127.0.0.1", miner_port):
            return
        # Try auto-starting if enabled (uses default port 8000)
        if auto_start_local:
            ensure_local_service("tensorprox", auto_start=True)
            if ensure_local_service("miner", auto_start=True):
                return
        raise RuntimeError(f"Local miner is unavailable on port {miner_port}")
    miner_port = port if port is not None else SERVICES["miner"].port
    if not _is_port_open(target_ip, miner_port):
        raise RuntimeError(f"Miner at {target_ip}:{miner_port} is unreachable")
