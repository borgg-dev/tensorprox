"""
================================================================================

TensorProx Weight Setting and Scoring Module

This module provides functionality for setting validator weights and scoring tasks
in the TensorProx subnetwork. It includes classes and functions to manage the
weight-setting process and task scoring based on miner performance.

Key Components:
- `TaskScorer`: Manages the scoring of tasks and logging of rewards.
- `WeightSetter`: Manages the setting of validator weights based on reward events.
- `set_weights`: Function to set validator weights based on miner scoring.

Dependencies:
- `asyncio`: For asynchronous operations.
- `threading`: To manage background threads.
- `numpy`: For numerical operations and array handling.
- `pandas`: For data manipulation and analysis.
- `os`: For interacting with the operating system, particularly in handling file paths.
- `pydantic`: For data validation and settings management.
- `loguru`: For structured logging and debugging.
- `dataclasses`: To define simple data structures.
- `typing`: For type hinting and annotations.
- `tensorprox`: Specifically, modules from `tensorprox.base`, `tensorprox.utils`, and `tensorprox.rewards` for network operations, logging, and reward computations.

================================================================================
"""

from loguru import logger
import bittensor as bt
import numpy as np
import os
import asyncio
import pandas as pd

from tensorprox import __spec_version__
from tensorprox.settings import settings
from tensorprox.utils.misc import ttl_get_block
from tensorprox.base.loop_runner import AsyncLoopRunner
from tensorprox import global_vars
from tensorprox.utils.logging import WeightSetEvent, log_event

PAST_WEIGHTS: list[np.ndarray] = []
WEIGHTS_HISTORY_LENGTH = 24


def set_weights(weights: np.ndarray, step: int = 0):
    """
    Set validator weights for metagraph hotkeys based on miner scoring.

    Args:
        weights (np.ndarray): Array of weights assigned to each miner.
        step (int, optional): Current step or iteration in the process. Defaults to 0.

    Returns:
        None
    """

    log_event(WeightSetEvent(weight_set_event=list(weights)))
    # Check if self.scores contains any NaN values and log a warning if it does.
    try:
        if any(np.isnan(weights).flatten()):
            logger.warning(
                f"Scores contain NaN values. This may be due to a lack of responses from miners, or a bug in your reward functions. Scores: {weights}"
            )

        # Replace any NaN values with 0
        weights = np.nan_to_num(weights, nan=0.0)

        # Calculate the average reward for each uid across non-zero values.
        # Replace any NaN values with 0.
        PAST_WEIGHTS.append(weights)
        if len(PAST_WEIGHTS) > WEIGHTS_HISTORY_LENGTH:
            PAST_WEIGHTS.pop(0)

        averaged_weights = np.average(np.array(PAST_WEIGHTS), axis=0)

        # Process the raw weights to final_weights via subtensor limitations.
        (processed_weight_uids, processed_weights) = bt.utils.weight_utils.process_weights_for_netuid(
            uids=settings.METAGRAPH.uids,
            weights=averaged_weights,
            netuid=settings.NETUID,
            subtensor=settings.SUBTENSOR,
            metagraph=settings.METAGRAPH)

        # Convert to uint16 weights and uids.
        (uint_uids,uint_weights) = bt.utils.weight_utils.convert_weights_and_uids_for_emit(uids=processed_weight_uids, weights=processed_weights)

    except Exception as ex:
        logger.exception(f"Issue with setting weights: {ex}")

    # Create a dataframe from weights and uids and save it as a csv file, with the current step as the filename.
    if settings.LOG_WEIGHTS:
        try:
            logger.debug(f"Lengths... UIDS: {len(uint_uids)}, WEIGHTS: {len(processed_weights.flatten())}, RAW_WEIGHTS: {len(weights.flatten())}, UINT_WEIGHTS: {len(uint_weights)}")
            weights_df = pd.DataFrame(
                {
                    "step": step,
                    "uids": uint_uids,
                    "weights": processed_weights.flatten(),
                    "raw_weights": str(list(weights.flatten())),
                    "averaged_weights": str(list(averaged_weights.flatten())),
                    "block": ttl_get_block(),
                }
            )
            step_filename = "weights.csv"
            file_exists = os.path.isfile(step_filename)
            # Append to the file if it exists, otherwise write a new file.
            weights_df.to_csv(step_filename, mode="a", index=False, header=not file_exists)
        except Exception as ex:
            logger.exception(f"Couldn't write to df: {ex}")

    if settings.NEURON_DISABLE_SET_WEIGHTS:
        logger.debug(f"Set weights disabled: {settings.NEURON_DISABLE_SET_WEIGHTS}")
        return


    # Set the weights on chain via our subtensor connection.
    result = settings.SUBTENSOR.set_weights(
        wallet=settings.WALLET,
        netuid=settings.NETUID,
        uids=uint_uids,
        weights=uint_weights,
        wait_for_finalization=False,
        wait_for_inclusion=False,
        version_key=__spec_version__,
    )

    if result[0]:
        logger.info("Successfully set weights on chain")
    else:
        logger.error(f"Failed to set weights on chain: {result}")


class WeightSetter(AsyncLoopRunner):
    """
    Manages the setting of validator weights based on reward events.

    Attributes:
        interval (int): Time interval (in minutes) between weight updates.
    """

    interval: int = settings.WEIGHT_SETTER_STEP
    
    async def run_step(self):
        """
        Execute a single step in the weight-setting loop.

        This method processes reward events, calculates final rewards,
        and sets the corresponding weights on the chain.

        Args:
            None

        Returns:
            np.ndarray: Array of final rewards calculated for each miner.
        """

        await asyncio.sleep(0.01)
        
        # Initialize final_rewards as None or a default array
        final_rewards = np.zeros(settings.SUBNET_NEURON_SIZE, dtype=float)
    
        try:
            logger.info("Reward setting loop running")
            if not global_vars.reward_events or len(global_vars.reward_events) == 0:
                logger.warning("No reward events in queue, skipping weight setting...")
                return
            logger.debug(f"Found {len(global_vars.reward_events)} reward events in queue")

            reward_dict = {uid: 0 for uid in range(settings.SUBNET_NEURON_SIZE)}

            miner_rewards: dict[dict[int, float]] = {uid: {"reward": 0, "count": 0} for uid in range(settings.SUBNET_NEURON_SIZE)}
            
            for reward_event in global_vars.reward_events:
                await asyncio.sleep(0.01)

                # give each uid the reward they received
                for uid, reward in zip(reward_event.uids, reward_event.rewards):
                    miner_rewards[uid]["reward"] += reward
                    miner_rewards[uid]["count"] += 1

            # logger.debug(f"Miner rewards after processing: {miner_rewards}")

            # Calculate the average reward per UID
            for uid, reward_data in miner_rewards.items():
                reward_dict[uid] = reward_data["reward"] / max(1, reward_data["count"])
                
            final_rewards = np.array(list(reward_dict.values())).astype(float)
            final_rewards[final_rewards < 0] = 0
            final_rewards /= np.sum(final_rewards) + 1e-10
            logger.debug(f"Final reward dict: {final_rewards}")
        except Exception as ex:
            logger.exception(f"{ex}")
            
        # set weights on chain
        set_weights(final_rewards, step=self.step)
        global_vars.reward_events = []
        await asyncio.sleep(0.01)
        return final_rewards


weight_setter = WeightSetter()