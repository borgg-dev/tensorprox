"""
Configuration utilities for TensorProx subnet.

Provides argument parsing and configuration helpers.
"""

import argparse
import os
from typing import Any, Dict, Optional

import bittensor as bt


def add_args(parser: argparse.ArgumentParser) -> None:
    """
    Add common TensorProx arguments to an argument parser.

    Args:
        parser: ArgumentParser to add arguments to.
    """
    # Bittensor wallet args
    bt.Wallet.add_args(parser)

    # Bittensor subtensor args
    bt.Subtensor.add_args(parser)

    # Bittensor axon args
    bt.Axon.add_args(parser)

    # TensorProx specific args
    parser.add_argument(
        "--netuid",
        type=int,
        default=int(os.getenv("TP_NETUID")) if os.getenv("TP_NETUID") else None,
        help="Subnet network UID (defaults to the TP_NETUID env var)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level",
    )


def config(parser: Optional[argparse.ArgumentParser] = None) -> "bt.Config":
    """
    Create a Bittensor config from parsed arguments.

    Args:
        parser: Optional parser. Creates new one if None.

    Returns:
        Bittensor config object.
    """
    if parser is None:
        parser = argparse.ArgumentParser()
        add_args(parser)

    return bt.Config(parser)


def validate_config(cfg: "bt.Config") -> bool:
    """
    Validate configuration values.

    Args:
        cfg: Config to validate.

    Returns:
        True if valid.

    Raises:
        ValueError: If config is invalid.
    """
    if not hasattr(cfg, "wallet") or not cfg.wallet.name:
        raise ValueError("Wallet name is required")

    if not hasattr(cfg, "netuid") or cfg.netuid is None or cfg.netuid < 0:
        raise ValueError("Valid netuid is required")

    return True


def get_config_dict(cfg: "bt.Config") -> Dict[str, Any]:
    """
    Convert config to dictionary for logging.

    Args:
        cfg: Config to convert.

    Returns:
        Dictionary representation.
    """
    result = {}

    for key in dir(cfg):
        if key.startswith("_"):
            continue
        try:
            value = getattr(cfg, key)
            if not callable(value):
                result[key] = value
        except Exception:
            pass

    return result
