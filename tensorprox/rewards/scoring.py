"""
================================================================================

Asynchronous Task Scoring Module

This module defines classes and functions for managing and scoring tasks in an
asynchronous environment. It utilizes Python's `asyncio` library to handle
concurrent operations, ensuring efficient task processing without blocking the
event loop.

Key Components:
- `ScoringConfig`: A data class that encapsulates configuration details for
  scoring, including user IDs (`uids`), block numbers, and step counts.
- `TaskScorer`: An asynchronous loop runner that maintains a queue of tasks and
  responses to be scored. It processes the queue in a background thread,
  computes rewards using the specified reward model, and logs the results.
- `WeightSetter`: A placeholder class inheriting from `AsyncLoopRunner`,
  intended for future implementation related to weight management.

Dependencies:
- `asyncio`: For managing asynchronous operations and event loops.
- `threading`: To run the scoring loop in a background thread.
- `numpy`: For numerical operations and array handling.
- `pydantic`: For data validation and settings management.
- `loguru`: For structured logging and debugging.
- `dataclasses`: To define simple data structures.
- `typing`: For type annotations and hints.
- `tensorprox`: A custom library providing core components such as `DendriteResponseEvent`,
  `RewardLoggingEvent`, `log_event`, `global_vars`, `AsyncLoopRunner`, `BaseRewardConfig`,
  and `ChallengeRewardModel`.

License:
This software is licensed under the Creative Commons Attribution-NonCommercial
4.0 International (CC BY-NC 4.0). You are free to use, share, and modify the code
for non-commercial purposes only.

Commercial Usage:
The only authorized commercial use of this software is for mining or validating
within the TensorProx subnet. For any other commercial licensing requests, please
contact Shugo LTD.

See the full license terms here: https://creativecommons.org/licenses/by-nc/4.0/

Author: Shugo LTD
Version: 0.1.0

================================================================================
"""

import asyncio
import threading
import shutil
import os
import numpy as np

from pydantic import ConfigDict
from loguru import logger
from dataclasses import dataclass
from typing import ClassVar
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.utils.logging import RewardLoggingEvent, log_event
from tensorprox import global_vars
from tensorprox.base.loop_runner import AsyncLoopRunner
import asyncio
from tensorprox.rewards.reward import BaseRewardConfig, ChallengeRewardModel

@dataclass
class ScoringConfig:
    """
    Configuration for scoring tasks.

    Attributes:
        uids (int): Unique identifier for the user.
        block (int): The block number associated with the task.
        step (int): The step count within the block.
    """
    response: DendriteResponseEvent
    uids: int
    label_hashes: dict
    block: int
    step: int


class TaskScorer(AsyncLoopRunner):
    """
    Manages a queue of tasks and responses to score, running a scoring loop in a
    background thread. This loop processes tasks, computes rewards, and logs the
    results.

    Attributes:
        is_running (bool): Indicates if the scoring loop is active.
        thread (threading.Thread): The background thread running the scoring loop.
        interval (int): Time interval (in seconds) between scoring iterations.
        model_config (ConfigDict): Configuration for the Pydantic model.
        base_reward_model (ClassVar[BaseRewardConfig]): The reward model used for
            computing rewards.
    """
    is_running: bool = False
    thread: threading.Thread = None
    interval: int = 10
    model_config = ConfigDict(arbitrary_types_allowed=True)
    base_reward_model: ClassVar[BaseRewardConfig] = BaseRewardConfig(reward_model=ChallengeRewardModel())
    scoring_round: ScoringConfig = None

    def score_round(
        self,
        response: DendriteResponseEvent,
        uids : int,
        label_hashes:dict,
        block: int,
        step: int,
    ) -> None:
        """
        Adds a new scoring configuration to the global scoring queue.

        Args:
            uids (int): Unique identifier for the user.
            block (int): The block number associated with the task.
            step (int): The step count within the block.

        Returns:
            None
        """
        
        self.scoring_round = ScoringConfig(response=response, uids=uids, label_hashes=label_hashes, block=block, step=step)

    async def run_step(self) -> RewardLoggingEvent:
        """
        Executes a single iteration of the scoring loop. Processes tasks from the
        scoring queue, computes rewards, logs the results, and manages the queue.
        """

        await asyncio.sleep(0.01)

        if not self.scoring_round:
            await asyncio.sleep(0.01)
            return
        
        scoring_config: ScoringConfig = self.scoring_round

        self.scoring_round = None

        #Calculate the reward
        reward_event = self.base_reward_model.apply(response_event=scoring_config.response, uids=scoring_config.uids, label_hashes=scoring_config.label_hashes)

        global_vars.reward_events.append(reward_event)

        log_event(RewardLoggingEvent(
            block=scoring_config.block,
            step=scoring_config.step,
            response_event=reward_event.response,
            uids=reward_event.uids,
            rewards=reward_event.rewards,
        ))


        logger.info("Scoring completed for this round.")

        await asyncio.sleep(0.01)


class WeightSetter(AsyncLoopRunner):
    """
    Placeholder class for managing weight settings in an asynchronous loop.
    Intended for future implementation.

    Attributes:
        Inherits all attributes from AsyncLoopRunner.
    """
    pass


task_scorer = TaskScorer()