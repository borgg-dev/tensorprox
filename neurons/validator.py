#!/usr/bin/env python3
"""
TensorProx Validator Neuron

Entry point for running a TensorProx subnet validator.
Validators manage miner assignments and audit their performance
through traffic inspection and synthetic testing.

Usage:
    python -m neurons.validator --env-file .env.validator --wallet.name <wallet> --wallet.hotkey <hotkey>

Environment variables (set in .env.validator):
    TP_WALLET_NAME: Wallet name
    TP_WALLET_HOTKEY: Hotkey name
    TP_SUBTENSOR_NETWORK: Network (finney, test, local)
"""

import argparse
import os
import sys
import subprocess
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Pre-parse --env-file argument before loading dotenv
# Each validator instance MUST specify its own env file
def _get_env_file() -> Path | None:
    """Get env file path from command line. Returns None if not specified."""
    for i, arg in enumerate(sys.argv):
        if arg == "--env-file" and i + 1 < len(sys.argv):
            return Path(sys.argv[i + 1])
        if arg.startswith("--env-file="):
            return Path(arg.split("=", 1)[1])
    return None

# Load environment variables from env file
from dotenv import load_dotenv
env_file = _get_env_file()
if env_file is None:
    sys.stderr.write("ERROR: --env-file is required. Example: --env-file .env.validator\n")
    sys.stderr.write("Copy .env.validator.example to .env.validator and configure it.\n")
    sys.exit(1)
if env_file.exists():
    load_dotenv(env_file)
else:
    sys.stderr.write(f"ERROR: Config file not found: {env_file}\n")
    sys.exit(1)

# Set role early so config loading knows this is a validator
os.environ["TP_ROLE"] = "validator"

# Setup logging BEFORE importing tensorprox modules
from loguru import logger

def setup_logging(level: str = "INFO") -> None:
    """Configure loguru with INFO level to stderr, DEBUG to file."""
    log_dir = Path(os.path.expanduser("~/.tensorprox/logs"))
    log_dir.mkdir(parents=True, exist_ok=True)

    logger.remove()
    logger.add(
        sys.stderr,
        level=level,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}",
    )
    logger.add(
        log_dir / "validator.log",
        rotation="100 MB",
        retention="7 days",
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}",
    )

setup_logging("INFO")

# Now safe to import tensorprox modules
from tensorprox.settings import reload_settings
from tensorprox.core.validator import TensorProxValidator
from tensorprox import __version__, NETUID


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="TensorProx Subnet Validator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Environment file (required)
    parser.add_argument(
        "--env-file",
        type=str,
        required=True,
        dest="env_file",
        help="Path to environment file (e.g., .env.validator). Copy from .env.validator.example",
    )

    # Bittensor arguments
    parser.add_argument(
        "--netuid",
        type=int,
        default=NETUID,
        help="Subnet network UID",
    )
    parser.add_argument(
        "--subtensor.network",
        type=str,
        default=None,
        dest="subtensor_network",
        help="Subtensor network (finney, test, local)",
    )
    parser.add_argument(
        "--subtensor.chain_endpoint",
        type=str,
        default=None,
        dest="subtensor_chain_endpoint",
        help="Custom chain endpoint URL",
    )
    parser.add_argument(
        "--wallet.name",
        type=str,
        default="default",
        dest="wallet_name",
        help="Wallet name",
    )
    parser.add_argument(
        "--wallet.hotkey",
        type=str,
        default="default",
        dest="wallet_hotkey",
        help="Hotkey name",
    )
    parser.add_argument(
        "--wallet.path",
        type=str,
        default="~/.bittensor/wallets",
        dest="wallet_path",
        help="Wallet path",
    )

    # Validator arguments
    parser.add_argument(
        "--audit-interval",
        type=int,
        default=0,
        help="DEPRECATED: Audits now run continuously. This argument is ignored.",
    )
    parser.add_argument(
        "--miners-per-audit",
        type=int,
        default=5,
        help="Number of miners to audit per cycle",
    )
    parser.add_argument(
        "--audit-duration",
        type=int,
        default=60,
        help="Duration of each audit in seconds",
    )

    # Weight setting
    parser.add_argument(
        "--weight-setter-step",
        type=int,
        default=None,
        help="Blocks between weight setting attempts (default from env/settings, must be >= 100)",
    )

    # Logging
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level",
    )

    # Weights & Biases
    parser.add_argument(
        "--wandb",
        action="store_true",
        help="Enable Weights & Biases logging",
    )
    parser.add_argument(
        "--wandb.project",
        type=str,
        default="tensorprox-subnet",
        dest="wandb_project",
        help="W&B project name",
    )

    # TPM-Lite Integration (Decentralized TPM) - Always enabled, mandatory for validators
    parser.add_argument(
        "--tpm-port",
        type=int,
        default=5001,
        help="Port for TPM-Lite API (default: 5001)",
    )

    return parser.parse_args()


def ensure_raw_socket_capability() -> bool:
    """
    Ensure Python has CAP_NET_RAW capability for sending raw audit packets.

    This is required for the validator to send spoofed packets through
    WireGuard tunnels or directly via scapy for miner audits.

    Returns:
        True if capability is available, False otherwise.
    """
    # Root user already has all capabilities
    if os.geteuid() == 0:
        logger.debug("Running as root - all capabilities available")
        return True

    python_path = sys.executable

    # Resolve symlinks to get the real binary
    try:
        real_python = os.path.realpath(python_path)
    except Exception:
        real_python = python_path

    # Check if capability is already set
    try:
        result = subprocess.run(
            ["getcap", real_python],
            capture_output=True,
            text=True,
            timeout=5
        )
        if "cap_net_raw" in result.stdout:
            logger.debug(f"CAP_NET_RAW capability verified on {real_python}")
            return True
    except Exception as e:
        logger.warning(f"Could not check capabilities: {e}")

    # Try to set the capability (requires sudo)
    logger.info(f"CAP_NET_RAW not set on {real_python}, attempting to set...")
    try:
        result = subprocess.run(
            ["sudo", "-n", "setcap", "cap_net_raw+eip", real_python],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            logger.info(f"CAP_NET_RAW capability set successfully")
            return True
    except Exception:
        pass  # Fall through to error message

    # Provide clear setup instructions
    logger.error(
        f"\n{'='*60}\n"
        f"SETUP REQUIRED: CAP_NET_RAW capability needed for audits\n"
        f"{'='*60}\n"
        f"Run this ONCE as root to enable automatic capability setup:\n\n"
        f"  sudo setcap 'cap_net_raw+eip' {real_python}\n\n"
        f"To make this permanent (auto-set on validator restart), also run:\n\n"
        f"  echo 'ALL ALL=(root) NOPASSWD: /usr/sbin/setcap cap_net_raw+eip {real_python}' | sudo tee /etc/sudoers.d/tensorprox\n"
        f"  sudo chmod 440 /etc/sudoers.d/tensorprox\n"
        f"{'='*60}"
    )
    return False


def main():
    """Main entry point for the validator."""
    args = parse_args()

    logger.info(f"TensorProx Validator v{__version__}")

    # Ensure raw socket capability for audit traffic
    ensure_raw_socket_capability()
    logger.info(f"Network UID: {args.netuid}")

    # Set environment variables from args
    if args.wallet_name:
        os.environ["TP_WALLET_NAME"] = args.wallet_name
    if args.wallet_hotkey:
        os.environ["TP_WALLET_HOTKEY"] = args.wallet_hotkey
    if args.wallet_path:
        os.environ["TP_WALLET_PATH"] = args.wallet_path
    if args.subtensor_network:
        os.environ["TP_SUBTENSOR_NETWORK"] = args.subtensor_network
    if args.subtensor_chain_endpoint:
        os.environ["TP_SUBTENSOR_CHAIN_ENDPOINT"] = args.subtensor_chain_endpoint

    os.environ["TP_NETUID"] = str(args.netuid)
    os.environ["TP_MODE"] = "validator"
    if args.weight_setter_step is not None:
        os.environ["TP_WEIGHT_SETTER_STEP"] = str(args.weight_setter_step)

    if args.wandb:
        os.environ["TP_WANDB_ON"] = "true"
        os.environ["TP_WANDB_PROJECT"] = args.wandb_project

    # TPM-Lite settings (mandatory for validators)
    os.environ["TP_TPM_PORT"] = str(args.tpm_port)
    logger.info(f"TPM-Lite will start on port {args.tpm_port}")

    # Reload settings with new environment
    settings = reload_settings()

    logger.info(f"Wallet: {settings.wallet_name}/{settings.wallet_hotkey}")
    logger.info(f"Audit mode: continuous (30s cooldown between cycles)")
    logger.info(f"Miners per audit: {args.miners_per_audit}")

    # Check registration
    if not settings.is_registered():
        logger.error("Validator not registered on subnet")
        sys.exit(1)

    # Create and run validator
    try:
        validator = TensorProxValidator(
            settings=settings,
            audit_interval=args.audit_interval,
            miners_per_audit=args.miners_per_audit,
        )
        validator.audit_duration = args.audit_duration

        # Configure TPM-Lite port (TPM is mandatory)
        validator.tpm_port = args.tpm_port

        with validator:
            validator.run()

    except KeyboardInterrupt:
        logger.info("Validator interrupted by user")
    except Exception as e:
        logger.error(f"Validator error: {e}")
        raise


if __name__ == "__main__":
    main()
