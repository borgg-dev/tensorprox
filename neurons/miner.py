#!/usr/bin/env python3
"""
TensorProx Miner Neuron

Entry point for running a TensorProx subnet miner.
Miners deploy and manage scrubber infrastructure to provide
DDoS protection services.

Usage:
    python -m neurons.miner --env-file .env.miner --wallet.name <wallet> --wallet.hotkey <hotkey>

Environment variables (set in .env.miner):
    TP_WALLET_NAME: Wallet name
    TP_WALLET_HOTKEY: Hotkey name
    TP_SUBTENSOR_NETWORK: Network (finney, test, local)
    TP_SCRUBBER_PROVIDER: Cloud provider (aws, linode)
    TP_SCRUBBER_REGION: Cloud region
"""

import argparse
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Pre-parse --env-file argument before loading dotenv
# Each miner instance MUST specify its own env file
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
    sys.stderr.write("ERROR: --env-file is required. Example: --env-file .env.miner\n")
    sys.stderr.write("Copy .env.miner.example to .env.miner and configure it.\n")
    sys.exit(1)
if env_file.exists():
    load_dotenv(env_file)
else:
    sys.stderr.write(f"ERROR: Config file not found: {env_file}\n")
    sys.exit(1)

# Set role early so config loading knows this is a miner
os.environ["TP_ROLE"] = "miner"

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
        log_dir / "miner.log",
        rotation="100 MB",
        retention="7 days",
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}",
    )

setup_logging("INFO")

# Now safe to import tensorprox modules
from tensorprox.settings import reload_settings
from tensorprox.core.miner import TensorProxMiner
from tensorprox import __version__, NETUID


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="TensorProx Subnet Miner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Environment file (required)
    parser.add_argument(
        "--env-file",
        type=str,
        required=True,
        dest="env_file",
        help="Path to environment file (e.g., .env.miner). Copy from .env.miner.example",
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
    parser.add_argument(
        "--axon.port",
        type=int,
        default=None,
        dest="axon_port",
        help="Axon port for serving requests (required when running multiple miners on same machine)",
    )
    parser.add_argument(
        "--emn.port",
        type=int,
        default=None,
        dest="emn_port",
        help="Miner control plane port (required when running multiple miners on same machine)",
    )

    # Scrubber arguments
    parser.add_argument(
        "--scrubber.provider",
        type=str,
        default=None,
        dest="scrubber_provider",
        choices=["aws", "linode"],
        help="Cloud provider for scrubbers (default: from .env)",
    )
    parser.add_argument(
        "--scrubber.region",
        type=str,
        default=None,
        dest="scrubber_region",
        help="Cloud region for scrubbers",
    )
    parser.add_argument(
        "--scrubber.instance-type",
        type=str,
        default=None,
        dest="scrubber_instance_type",
        help="Instance type for scrubbers",
    )

    # Logging
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level",
    )

    return parser.parse_args()


def main():
    """Main entry point for the miner."""
    args = parse_args()

    logger.info(f"TensorProx Miner v{__version__}")
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
    if args.scrubber_provider:
        os.environ["TP_SCRUBBER_PROVIDER"] = args.scrubber_provider
    if args.scrubber_region:
        os.environ["TP_SCRUBBER_REGION"] = args.scrubber_region
    if args.scrubber_instance_type:
        os.environ["TP_SCRUBBER_INSTANCE_TYPE"] = args.scrubber_instance_type
    if args.axon_port:
        os.environ["TP_AXON_PORT"] = str(args.axon_port)
    if args.emn_port:
        os.environ["TP_EMN_PORT"] = str(args.emn_port)

    os.environ["TP_NETUID"] = str(args.netuid)
    os.environ["TP_MODE"] = "miner"

    # Reload settings with new environment
    settings = reload_settings()

    logger.info(f"Wallet: {settings.wallet_name}/{settings.wallet_hotkey}")
    logger.info(f"Scrubber provider: {settings.scrubber_provider}")
    logger.info(f"Scrubber region: {settings.scrubber_region}")

    # Create and run miner
    try:
        miner = TensorProxMiner(settings=settings)

        with miner:
            miner.run()

    except KeyboardInterrupt:
        logger.info("Miner interrupted by user")
    except Exception as e:
        logger.error(f"Miner error: {e}")
        raise


if __name__ == "__main__":
    main()
