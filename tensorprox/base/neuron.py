"""
Base neuron class for TensorProx subnet.

Provides common functionality for both miners and validators:
- Bittensor chain interaction
- Metagraph synchronization
- Registration verification
- Lifecycle management
"""

import time
from abc import ABC, abstractmethod
from typing import Optional, List

import bittensor as bt
from loguru import logger

from tensorprox.settings import get_settings, Settings
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse


class BaseNeuron(ABC):
    """
    Abstract base class for all TensorProx neurons.

    Provides core Bittensor integration and lifecycle management.
    Subclasses (BaseMinerNeuron, BaseValidatorNeuron) extend this
    with role-specific functionality.
    """

    def __init__(self, settings: Optional[Settings] = None):
        """
        Initialize the base neuron.

        Args:
            settings: Optional settings override. Uses global settings if None.
        """
        # Only set attributes if not already set (e.g., by Pydantic in subclasses)
        if not hasattr(self, 'settings') or self.settings is None:
            self.settings = settings or get_settings()
        elif settings is not None:
            self.settings = settings

        if not hasattr(self, 'step'):
            self.step: int = 0
        if not hasattr(self, 'last_sync_block'):
            self.last_sync_block: int = 0

        # Bittensor primitives (lazy loaded from settings)
        if not hasattr(self, '_wallet'):
            self._wallet: Optional["bt.Wallet"] = None
        if not hasattr(self, '_subtensor'):
            self._subtensor: Optional["bt.Subtensor"] = None
        if not hasattr(self, '_metagraph'):
            self._metagraph: Optional["bt.Metagraph"] = None
        if not hasattr(self, '_uid'):
            self._uid: Optional[int] = None

        logger.info(f"Initializing {self.__class__.__name__}")

    @property
    def wallet(self) -> "bt.Wallet":
        """Get Bittensor wallet."""
        if self._wallet is None:
            self._wallet = self.settings.wallet
        return self._wallet

    @property
    def subtensor(self) -> "bt.Subtensor":
        """Get Bittensor subtensor connection."""
        if self._subtensor is None:
            self._subtensor = self.settings.subtensor
        return self._subtensor

    @property
    def metagraph(self) -> "bt.Metagraph":
        """Get Bittensor metagraph."""
        return self.settings.metagraph

    @property
    def uid(self) -> Optional[int]:
        """Get this neuron's UID."""
        if self._uid is None:
            self._uid = self.settings.get_uid()
        return self._uid

    @property
    def block(self) -> int:
        """Get current block number."""
        return self.subtensor.get_current_block()

    @abstractmethod
    def forward(self, synapse: PingSynapse) -> PingSynapse:
        """
        Handle incoming ping synapse.

        Must be implemented by subclasses to respond to
        availability queries.
        """
        pass

    @abstractmethod
    def handle_challenge(self, synapse: ChallengeSynapse) -> ChallengeSynapse:
        """
        Handle incoming challenge synapse.

        Must be implemented by subclasses to process
        validation challenges.
        """
        pass

    @abstractmethod
    def run(self) -> None:
        """
        Main run loop.

        Must be implemented by subclasses with their
        specific execution logic.
        """
        pass

    def check_registered(self) -> bool:
        """
        Check if this neuron is registered on the subnet.

        Returns:
            True if registered, False otherwise.
        """
        if not self.settings.is_registered():
            logger.error(
                f"Neuron not registered on subnet {self.settings.netuid}. "
                f"Hotkey: {self.wallet.hotkey.ss58_address}"
            )
            return False

        self._uid = self.settings.get_uid()
        logger.info(f"Registered with UID: {self._uid}")
        return True

    def should_sync_metagraph(self) -> bool:
        """
        Check if metagraph should be synced.

        Syncs every epoch_length blocks to stay up to date
        without excessive chain queries.
        """
        current_block = self.block
        blocks_since_sync = current_block - self.last_sync_block
        return blocks_since_sync >= self.settings.neuron_epoch_length

    def sync(self) -> None:
        """
        Synchronize with the Bittensor network.

        Updates metagraph and checks registration status.
        """
        logger.debug("Syncing with network...")

        # Check registration
        if not self.check_registered():
            raise RuntimeError("Neuron not registered")

        # Sync metagraph
        self.resync_metagraph()

        # Update block tracking
        self.last_sync_block = self.block
        logger.info(f"Synced at block {self.last_sync_block}")

    def resync_metagraph(self) -> None:
        """
        Force metagraph resync.

        Fetches latest state from chain and updates
        internal metagraph reference.
        """
        logger.debug("Resyncing metagraph...")
        self._metagraph = self.settings.sync_metagraph()

        # Update UID in case it changed
        self._uid = self.settings.get_uid()

    def should_set_weights(self) -> bool:
        """
        Check if this neuron should set weights.

        Only validators with sufficient stake should set weights.
        Default implementation returns False (miners don't set weights).
        """
        return False

    def get_validator_uids(self) -> List[int]:
        """
        Get UIDs of all validators on the network.

        Returns:
            List of validator UIDs with sufficient stake.
        """
        validators = []
        for uid in range(len(self.metagraph.S)):
            if self.metagraph.validator_permit[uid]:
                validators.append(uid)
        return validators

    def get_miner_uids(self) -> List[int]:
        """
        Get UIDs of all potential miners on the network.

        Returns:
            List of all UIDs except our own (any neuron can run scrubber infra).

        Note: Bittensor is chain-agnostic - a neuron can be both validator and miner.
        We query all UIDs and let the availability check filter those with scrubber config.
        """
        return [
            uid for uid in range(len(self.metagraph.S))
            if uid != self.uid  # Exclude ourselves
        ]

    def log_status(self) -> None:
        """Log current neuron status."""
        logger.info(
            f"Status: UID={self.uid}, "
            f"Block={self.block}, "
            f"Step={self.step}, "
            f"Stake={self.settings.get_stake():.4f}"
        )

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        logger.info(f"Shutting down {self.__class__.__name__}")
        return False
