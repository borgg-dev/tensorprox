"""
Settings module for TensorProx Subnet.

Provides singleton configuration management with Bittensor integration.
Loads from environment variables and manages wallet/subtensor connections.
"""

from functools import cached_property
from typing import Literal, Optional
import math
import os
import time

import bittensor as bt
from pydantic_settings import BaseSettings
from pydantic import Field, model_validator

from tensorprox import NETUID, EPOCH_TIME


class Settings(BaseSettings):
    """
    Singleton settings for TensorProx subnet neurons.

    Loads configuration from environment variables and provides
    lazy-loaded Bittensor primitives (wallet, subtensor, metagraph).
    """

    model_config = {"extra": "ignore", "env_prefix": "TP_", "env_file": ".env", "env_file_encoding": "utf-8"}

    # Runtime mode
    mode: Literal["miner", "validator"] = "miner"

    # Network configuration
    netuid: int = Field(default=NETUID, description="Subnet network UID")
    subtensor_network: Optional[str] = Field(
        default=None,
        description="Subtensor network (finney, test, local)"
    )
    subtensor_chain_endpoint: Optional[str] = Field(
        default=None,
        description="Custom chain endpoint URL"
    )

    # Wallet configuration
    wallet_name: str = Field(default="default", description="Wallet name")
    wallet_hotkey: str = Field(default="default", description="Hotkey name")
    wallet_path: str = Field(default="~/.bittensor/wallets", description="Wallet path")

    # Neuron configuration
    neuron_epoch_length: int = Field(
        default=100,  # Must be >= chain weights_rate_limit (100 blocks on testnet SN234)
        description="Blocks between weight updates"
    )
    neuron_timeout: int = Field(
        default=15,
        description="Forward timeout in seconds"
    )
    neuron_forward_max_time: int = Field(
        default=240,
        description="Maximum forward duration in seconds"
    )
    neuron_axon_off: bool = Field(
        default=False,
        description="Disable axon serving"
    )
    axon_port: Optional[int] = Field(
        default=None,
        description="Axon port for serving requests (required when running multiple miners)"
    )
    # Scrubber configuration
    scrubber_provider: Literal["aws", "linode"] = Field(
        default="aws",
        description="Cloud provider for scrubber deployment"
    )
    scrubber_region: str = Field(
        default="eu-central-1",
        description="Cloud region for scrubbers"
    )
    scrubber_instance_type: str = Field(
        default="t3.medium",
        description="Instance type for scrubbers"
    )

    # AWS configuration (if using AWS)
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_vpc_id: Optional[str] = None
    aws_subnet_id: Optional[str] = None
    aws_security_group_id: Optional[str] = None
    aws_ssh_key_name: Optional[str] = None

    # Linode configuration (if using Linode)
    linode_token: Optional[str] = None

    # SSH configuration
    ssh_key_path: str = Field(
        default="~/.ssh/tensorprox",
        description="Path to SSH private key"
    )

    # Database configuration (for miner state)
    db_host: str = Field(default="localhost", description="PostgreSQL host")
    db_port: int = Field(default=5432, description="PostgreSQL port")
    db_name: str = Field(default="ecp_state", description="Database name")
    db_user: str = Field(default="ecp_api", description="Database user")
    db_password: str = Field(default="", description="Database password")

    # Redis configuration
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL"
    )

    # TPM Integration
    tpm_api_url: Optional[str] = Field(
        default=None,
        description="TensorProx Management API URL (e.g., http://localhost:5001)"
    )
    tpm_api_key: Optional[str] = Field(
        default=None,
        description="Optional API key for TPM authentication"
    )

    # Auditing configuration
    max_concurrent_audits: int = Field(
        default=256,
        ge=64,
        description="Maximum concurrent audits (default 256 = subnet size, minimum 64). Reduce if validator has limited resources."
    )

    # Weights and scoring
    weight_setter_step: int = Field(
        default=175,
        description="Blocks between weight setting attempts (175 = ~2x per 360-block tempo, must be >= chain weights_rate_limit of 100)"
    )
    
    ema_alpha: float = Field(
        default=0.2,
        ge=0.05,
        le=0.5,
        description="EMA decay factor for audit scores (0.2 = ~9 audit effective window, higher = more reactive)"
    )
    ema_warmup_audits: Optional[int] = Field(
        default=None,
        ge=1,
        le=30,
        description="Audits before miner EMA is trusted for flagging (immune during warm-up). "
                    "Auto-computed from ema_alpha as ceil(2/alpha - 1) if not set. "
                    "For alpha=0.2 → 9, alpha=0.3 → 6."
    )
    log_weights: bool = Field(
        default=True,
        description="Log weights to file"
    )
    past_weights_count: int = Field(
        default=24,
        description="Number of past weights to average"
    )

    # Monitoring / W&B (Weights & Biases)
    # Miners view scores at: https://wandb.ai/shugo-labs/tensorprox
    wandb_on: bool = Field(default=False, description="Enable W&B logging (legacy)")
    wandb_enabled: bool = Field(default=False, description="Enable W&B audit reporting")
    wandb_entity: str = Field(default="shugo-labs", description="W&B entity")
    wandb_project: str = Field(default="tensorprox", description="W&B project")
    wandb_offline: bool = Field(default=False, description="Run W&B offline")
    wandb_api_key: Optional[str] = Field(default=None, description="W&B API key")

    # Logging
    log_level: str = Field(default="INFO", description="Log level")
    log_dir: str = Field(default="/tmp/tensorprox", description="Log directory")

    # Storage
    save_path: str = Field(default="./storage", description="Local storage path")

    # Internal state
    _wallet: Optional["bt.Wallet"] = None
    _subtensor: Optional["bt.Subtensor"] = None
    _metagraph: Optional["bt.Metagraph"] = None
    _metagraph_last_sync: float = 0
    _metagraph_sync_interval: int = 1200  # 20 minutes

    @model_validator(mode="after")
    def _resolve_ema_warmup(self) -> "Settings":
        """Auto-compute ema_warmup_audits from ema_alpha if not explicitly set."""
        if self.ema_warmup_audits is None:
            # Equivalent SMA span: ceil(2/alpha - 1)
            # alpha=0.2 → 9, alpha=0.3 → 6, alpha=0.1 → 19
            self.ema_warmup_audits = math.ceil((2.0 / self.ema_alpha) - 1)
        return self

    @cached_property
    def wallet(self) -> "bt.Wallet":
        """Get or create Bittensor wallet."""
        return bt.Wallet(
            name=self.wallet_name,
            hotkey=self.wallet_hotkey,
            path=os.path.expanduser(self.wallet_path)
        )

    @cached_property
    def subtensor(self) -> "bt.Subtensor":
        """Get or create Bittensor subtensor connection."""
        if self.subtensor_chain_endpoint:
            return bt.Subtensor(chain_endpoint=self.subtensor_chain_endpoint)
        elif self.subtensor_network:
            return bt.Subtensor(network=self.subtensor_network)
        else:
            return bt.Subtensor()

    @property
    def metagraph(self) -> "bt.Metagraph":
        """
        Get metagraph with automatic sync.

        Syncs every 20 minutes to keep data fresh without
        excessive chain queries.
        """
        current_time = time.time()
        if (
            self._metagraph is None
            or current_time - self._metagraph_last_sync > self._metagraph_sync_interval
        ):
            self._metagraph = self.subtensor.metagraph(self.netuid)
            self._metagraph_last_sync = current_time
        return self._metagraph

    def sync_metagraph(self) -> "bt.Metagraph":
        """Force metagraph sync."""
        self._metagraph = self.subtensor.metagraph(self.netuid)
        self._metagraph_last_sync = time.time()
        return self._metagraph

    @cached_property
    def dendrite(self) -> "bt.Dendrite":
        """Get or create dendrite for outbound queries."""
        return bt.Dendrite(wallet=self.wallet)

    @property
    def axon(self) -> "bt.Axon":
        """Create axon for serving requests."""
        if self.axon_port:
            return bt.Axon(wallet=self.wallet, port=self.axon_port)
        return bt.Axon(wallet=self.wallet)

    def get_uid(self) -> Optional[int]:
        """Get this neuron's UID from metagraph."""
        try:
            return self.metagraph.hotkeys.index(self.wallet.hotkey.ss58_address)
        except ValueError:
            return None

    def is_registered(self) -> bool:
        """Check if this neuron is registered on the subnet."""
        return self.get_uid() is not None

    def get_stake(self, uid: Optional[int] = None) -> float:
        """Get stake for a UID (defaults to self)."""
        if uid is None:
            uid = self.get_uid()
        if uid is None:
            return 0.0
        return float(self.metagraph.S[uid])

    def is_validator(self, uid: Optional[int] = None) -> bool:
        """Check if UID has validator permit from chain."""
        if uid is None:
            uid = self.get_uid()
        if uid is None:
            return False
        # Use chain's validator_permit
        return self.metagraph.validator_permit[uid]


# Global settings singleton
settings: Settings = Settings()


def get_settings() -> Settings:
    """Get the global settings singleton."""
    return settings


def reload_settings() -> Settings:
    """Reload settings from environment."""
    global settings
    settings = Settings()
    return settings
