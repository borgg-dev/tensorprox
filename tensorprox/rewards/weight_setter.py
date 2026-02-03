"""
Weight setter for TensorProx subnet.

Manages the process of setting weights on-chain:
- Uses local process_weights_for_netuid with burn_uid/burn_weight support
- Handles NaN values and normalization
- Interacts with Bittensor subtensor
"""

from typing import List, Optional
import numpy as np

from pydantic import Field
from loguru import logger

from tensorprox.base.loop_runner import ConditionalRunner
from tensorprox.settings import get_settings, Settings
from tensorprox.utils.weight_utils import (
    process_weights_for_netuid,
    convert_weights_and_uids_for_emit,
)
from tensorprox import BURN_UID, BURN_WEIGHT


class WeightSetter(ConditionalRunner):
    """
    Weight setter that sets on-chain weights with burn UID handling.

    Takes pre-computed weights from the validator, processes them through
    the local weight utilities (with burn_uid/burn_weight), and submits
    to the Bittensor chain.
    """

    # Current weights (raw, set each round)
    current_weights: Optional[np.ndarray] = Field(default=None)

    # Settings
    settings: Optional[Settings] = Field(default=None)

    # State tracking
    last_set_block: int = Field(default=0)
    total_weight_sets: int = Field(default=0)

    # Configuration
    min_blocks_between_sets: int = Field(default=120)  # 120 blocks * 12s = ~24 minutes
    log_weights_to_file: bool = Field(default=True)
    weights_file_path: str = Field(default="./storage/weights.csv")

    def __init__(self, **kwargs):
        """Initialize the weight setter."""
        super().__init__(
            interval=60,  # Check every minute
            name="WeightSetter",
            **kwargs
        )
        if self.settings is None:
            self.settings = get_settings()

    async def should_run(self) -> bool:
        """
        Check if weights should be set.

        Only runs if enough blocks have passed since last set.
        """
        current_block = self.settings.subtensor.get_current_block()
        blocks_since_set = current_block - self.last_set_block

        return blocks_since_set >= self.min_blocks_between_sets

    async def run_step(self) -> None:
        """Set weights on-chain."""
        if self.current_weights is None:
            logger.debug("No weights to set")
            return

        success = await self._set_weights()

        if success:
            self.total_weight_sets += 1
            self.last_set_block = self.settings.subtensor.get_current_block()
            logger.info(
                f"Weights set successfully. Total sets: {self.total_weight_sets}"
            )

    def update_weights(self, new_weights: np.ndarray) -> np.ndarray:
        """
        Update weights with new values (raw, no rolling average).

        Cleans NaN values and normalizes with epsilon to prevent zero-sum.

        Args:
            new_weights: New weight array to incorporate.

        Returns:
            Normalized weights array.
        """
        # Clean NaN values
        weights = np.nan_to_num(new_weights, nan=0.0)

        # Normalize with epsilon (prevents zero-sum fallback in process_weights_for_netuid)
        weight_sum = weights.sum()
        if weight_sum > 0:
            weights = weights / weight_sum
        # If all zeros, keep as zeros — _set_weights will return False

        self.current_weights = weights

        non_zero = np.count_nonzero(weights)

        return weights

    async def _set_weights(self) -> bool:
        """
        Set weights on the Bittensor chain.

        Uses the local process_weights_for_netuid which handles burn_uid/burn_weight
        to allocate BURN_WEIGHT to BURN_UID and distribute the rest proportionally.

        Returns:
            True if successful, False otherwise.
        """
        if self.current_weights is None:
            return False

        weights = self.current_weights.copy()

        # If all weights are zero, let it flow through to process_weights_for_netuid
        # which will allocate 100% to burn UID
        if weights.sum() == 0:
            logger.info("All miner weights are zero — will set 100% burn")

        try:
            # Get metagraph info
            metagraph = self.settings.metagraph
            n_uids = len(metagraph.S)

            # Ensure weights array is correct size
            if len(weights) != n_uids:
                logger.warning(
                    f"Weight size mismatch: {len(weights)} vs {n_uids}. "
                    "Resizing..."
                )
                new_weights = np.zeros(n_uids)
                copy_len = min(len(weights), n_uids)
                new_weights[:copy_len] = weights[:copy_len]
                weights = new_weights

            # Debug: log input state
            non_zero_idx = np.where(weights > 0)[0]

            # Process through LOCAL weight utilities with burn_uid/burn_weight
            # This removes burn_uid from regular weights and allocates BURN_WEIGHT to it
            processed_uids, processed_weights = process_weights_for_netuid(
                uids=np.arange(len(weights)),
                weights=weights,
                netuid=self.settings.netuid,
                subtensor=self.settings.subtensor,
                metagraph=metagraph,
                burn_uid=BURN_UID,
                burn_weight=BURN_WEIGHT,
            )

            # Skip if process_weights returned empty (no UIDs at all)
            if len(processed_uids) == 0:
                logger.warning("process_weights_for_netuid returned empty — skipping weight setting")
                return False

            # Convert to uint16 format for chain
            uint_uids, uint_weights = convert_weights_and_uids_for_emit(
                uids=processed_uids,
                weights=processed_weights,
            )

            # Convert to numpy arrays if they're lists
            uint_uids = np.array(uint_uids) if isinstance(uint_uids, list) else uint_uids
            uint_weights = np.array(uint_weights) if isinstance(uint_weights, list) else uint_weights

            # Submit to chain
            result = self.settings.subtensor.set_weights(
                wallet=self.settings.wallet,
                netuid=self.settings.netuid,
                uids=uint_uids,
                weights=uint_weights,
                wait_for_finalization=True,
                wait_for_inclusion=True,
            )

            # ExtrinsicResponse supports tuple-like access: result[0] = success, result[1] = message
            if result[0]:
                # Log to file if enabled
                if self.log_weights_to_file:
                    self._log_weights_to_file(
                        uids=uint_uids,
                        uint_weights=uint_weights,
                        normalized_weights=processed_weights,
                    )
                logger.info("Successfully set weights on chain")
                return True
            else:
                # Get more details about the failure
                error_msg = getattr(result, 'error_message', None) or getattr(result, 'error', None) or 'Unknown'
                current_block = self.settings.subtensor.get_current_block()
                last_update = metagraph.last_update[self.settings.get_uid()] if self.settings.get_uid() else 'N/A'
                logger.error(
                    f"Failed to set weights on chain: {result}\n"
                    f"  Error: {error_msg}\n"
                    f"  Current block: {current_block}, Last update: {last_update}\n"
                    f"  Blocks since last update: {current_block - last_update if isinstance(last_update, int) else 'N/A'}\n"
                    f"  Note: Chain weights_rate_limit is typically 100 blocks"
                )
                return False

        except Exception as e:
            logger.error(f"Error setting weights: {e}")
            return False

    def _log_weights_to_file(
        self,
        uids: np.ndarray,
        uint_weights: np.ndarray,
        normalized_weights: np.ndarray,
    ) -> None:
        """Log weights to CSV file with both uint16 and normalized values."""
        try:
            import csv
            import os
            from datetime import datetime

            # Ensure directory exists
            os.makedirs(os.path.dirname(self.weights_file_path), exist_ok=True)

            # Check if file exists (for header)
            file_exists = os.path.exists(self.weights_file_path)

            # Convert to arrays if needed
            normalized_weights = np.array(normalized_weights) if isinstance(normalized_weights, list) else normalized_weights

            with open(self.weights_file_path, "a", newline="") as f:
                writer = csv.writer(f)

                # Write header if new file
                if not file_exists:
                    writer.writerow([
                        "timestamp",
                        "block",
                        "step",
                        "uid",
                        "normalized_weight",
                        "uint_weight",
                    ])

                # Write weights
                timestamp = datetime.utcnow().isoformat()
                block = self.settings.subtensor.get_current_block()

                for i, uid in enumerate(uids):
                    norm_w = float(normalized_weights[i]) if i < len(normalized_weights) else 0.0
                    uint_w = int(uint_weights[i]) if i < len(uint_weights) else 0
                    writer.writerow([
                        timestamp,
                        block,
                        self.total_weight_sets,
                        int(uid),
                        f"{norm_w:.6f}",
                        uint_w,
                    ])

        except Exception as e:
            logger.warning(f"Failed to log weights to file: {e}")

    def get_weight_for_uid(self, uid: int) -> float:
        """Get the current weight for a specific UID."""
        if self.current_weights is None:
            return 0.0

        if 0 <= uid < len(self.current_weights):
            return float(self.current_weights[uid])

        return 0.0

    def get_top_miners(self, n: int = 10) -> List[tuple[int, float]]:
        """
        Get the top N miners by weight.

        Args:
            n: Number of top miners to return.

        Returns:
            List of (uid, weight) tuples sorted by weight descending.
        """
        if self.current_weights is None:
            return []

        # Get indices sorted by weight descending
        sorted_indices = np.argsort(self.current_weights)[::-1]

        result = []
        for idx in sorted_indices[:n]:
            weight = float(self.current_weights[idx])
            if weight > 0:
                result.append((int(idx), weight))

        return result

    def reset(self) -> None:
        """Reset current weights."""
        self.current_weights = None
        self.total_weight_sets = 0
        self.last_set_block = 0
        logger.info("Weight setter reset")
