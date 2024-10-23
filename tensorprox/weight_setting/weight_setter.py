from loguru import logger
import bittensor as bt
import numpy as np
import os
import asyncio
import pandas as pd

from tensorprox import __version__
from tensorprox.settings import settings
from tensorprox.utils.uids import get_uids
from tensorprox.utils.misc import ttl_get_block
from tensorprox.base.loop_runner import AsyncLoopRunner
from tensorprox.mutable_globals import reward_events
from tensorprox.rewards.reward import FScoreRewardEvent
from tensorprox.utils.logging import WeightSetEvent, log_event

PAST_WEIGHTS: list[np.ndarray] = []
WEIGHTS_HISTORY_LENGTH = 24


def apply_reward_func(raw_rewards: np.ndarray, p=0.5):
    """Apply the reward function to the raw rewards. P adjusts the steepness of the function - p = 0.5 leaves
    the rewards unchanged, p < 0.5 makes the function more linear (at p=0 all miners with positives reward values get the same reward),
    p > 0.5 makes the function more exponential (winner takes all).
    """
    exponent = (p**6.64385619) * 100  # 6.64385619 = ln(100)/ln(2) -> this way if p=0.5, the exponent is exatly 1
    raw_rewards = np.array(raw_rewards) / max(1, (np.sum(raw_rewards[raw_rewards > 0]) + 1e-10))
    positive_rewards = np.clip(raw_rewards, 1e-10, np.inf)
    normalised_rewards = positive_rewards / np.max(positive_rewards)
    post_func_rewards = normalised_rewards**exponent
    all_rewards = post_func_rewards / (np.sum(post_func_rewards) + 1e-10)
    all_rewards[raw_rewards <= 0] = raw_rewards[raw_rewards <= 0]
    return all_rewards


def set_weights(weights: np.ndarray, step: int = 0):
    """
    Sets the validator weights to the metagraph hotkeys based on the scores it has received from the miners. The weights determine the trust and incentive level the validator assigns to miner nodes on the network.
    """
    log_event(WeightSetEvent(weight_set_event=list(weights)))
    # Check if self.scores contains any NaN values and log a warning if it does.
    try:
        if any(np.isnan(weights).flatten()):
            logger.warning(
                f"Scores contain NaN values. This may be due to a lack of responses from miners, or a bug in your reward functions. Scores: {weights}"
            )

        # Calculate the average reward for each uid across non-zero values.
        # Replace any NaN values with 0.
        PAST_WEIGHTS.append(weights)
        if len(PAST_WEIGHTS) > WEIGHTS_HISTORY_LENGTH:
            PAST_WEIGHTS.pop(0)
        averaged_weights = np.average(np.array(PAST_WEIGHTS), axis=0)

        # Process the raw weights to final_weights via subtensor limitations.
        (
            processed_weight_uids,
            processed_weights,
        ) = bt.utils.weight_utils.process_weights_for_netuid(
            uids=settings.METAGRAPH.uids,
            weights=averaged_weights,
            netuid=settings.NETUID,
            subtensor=settings.SUBTENSOR,
            metagraph=settings.METAGRAPH,
        )

        # Convert to uint16 weights and uids.
        (
            uint_uids,
            uint_weights,
        ) = bt.utils.weight_utils.convert_weights_and_uids_for_emit(uids=processed_weight_uids, weights=processed_weights)
        logger.debug("uint_weights", uint_weights)
        logger.debug("uint_uids", uint_uids)
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
        version_key=__version__,
    )

    if result is True:
        logger.info("set_weights on chain successfully!")
    else:
        logger.error("set_weights failed")


class WeightSetter(AsyncLoopRunner):
    """The weight setter looks at RewardEvents in the reward_events queue and sets the weights of the miners accordingly."""

    sync: bool = True
    interval: int = 60*22  # set rewards every 20 minutes
    # interval: int = 60

    async def run_step(self):
        await asyncio.sleep(0.01)
        try:
            logger.info("Reward setting loop running")
            if len(reward_events) == 0:
                logger.warning("No reward events in queue, skipping weight setting...")
                return
            logger.debug(f"Found {len(reward_events)} reward events in queue")

            reward_dict = {uid: 0 for uid in range(1024)}

            miner_rewards: dict[dict[int, float]] = {uid: {"reward": 0, "count": 0} for uid in range(1024)}
            

            logger.debug(f"Miner rewards before processing: {miner_rewards}")

            inference_events: list[FScoreRewardEvent] = []
            for rwd_event in reward_events:
                await asyncio.sleep(0.01)
                for reward_event in rwd_event:
                    if np.sum(reward_event.rewards) > 0:
                        logger.debug("Identified positive reward event")

                    # give each uid the reward they received
                    for uid, reward in zip(reward_event.uids, reward_event.rewards):
                        miner_rewards[uid]["reward"] += reward
                        miner_rewards[uid]["count"] += 1

            logger.debug(f"Miner rewards after processing: {miner_rewards}")

            for rewards in miner_rewards.items():
                r = np.array([x["reward"]/max(1, x["count"]) for x in list(rewards.values())])
                logger.debug(f"Rewards: {r}")
                u = np.array(list(rewards.keys()))
                processed_rewards = apply_reward_func(raw_rewards=r, p=settings.REWARD_STEEPNESS)
                # update reward dict
                for uid, reward in zip(u, processed_rewards):
                    reward_dict[uid] += reward
            final_rewards = np.array(list(reward_dict.values())).astype(float)
            final_rewards[final_rewards < 0] = 0
            final_rewards /= np.sum(final_rewards) + 1e-10
            logger.debug(f"Final reward dict: {final_rewards}")
        except Exception as ex:
            logger.exception(f"{ex}")
        # set weights on chain
        set_weights(final_rewards, step=self.step)
        reward_events = list[FScoreRewardEvent] = []
        await asyncio.sleep(0.01)
        return final_rewards


weight_setter = WeightSetter()