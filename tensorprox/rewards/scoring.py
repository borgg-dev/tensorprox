import asyncio
import threading

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
    uids: int
    block: int
    step: int


class TaskScorer(AsyncLoopRunner):
    """The scoring manager maintains a queue of tasks & responses to score and then runs a scoring loop in a background thread.
    This scoring loop will score the responses and log the rewards.
    """
    is_running: bool = False
    thread: threading.Thread = None
    interval: int = 10
    model_config = ConfigDict(arbitrary_types_allowed=True)
    base_reward_model: ClassVar[BaseRewardConfig] = BaseRewardConfig(reward_model=ChallengeRewardModel())


    def add_to_queue(
        self,
        uids : int,
        block: int,
        step: int,
    ) -> None:

        
        # logger.debug(f"SCORING: Added to queue: {task.__class__.__name__}")
        global_vars.scoring_queue.append(
            ScoringConfig(
                uids=uids,
                block=block,
                step=step,
            )
        )

    async def run_step(self) -> RewardLoggingEvent:
        
        await asyncio.sleep(0.01)
        scorable = [scoring_config for scoring_config in global_vars.scoring_queue]

        if len(scorable) == 0:
            await asyncio.sleep(0.01)
            logger.debug("Nothing to score. Skipping scoring step.")
            await asyncio.sleep(5)
            return
        
        global_vars.scoring_queue.remove(scorable[0])
        scoring_config: ScoringConfig = scorable.pop(0)
        
        # logger.debug(f"""{len(scoring_config.response.predictions)} predictions to score for task {scoring_config.task}""")

        #Calculate the reward
        reward_event = self.base_reward_model.apply(uids=scoring_config.uids)

        global_vars.reward_events.append(reward_event)

        # logger.debug(f"SCORING: Scored {scoring_config.task.__class__.__name__} {scoring_config.task.task_id} with reward")

        log_event(RewardLoggingEvent(
            block=scoring_config.block,
            step=scoring_config.step,
            uids=reward_event.uids,
            rewards=reward_event.rewards,

        ))

        await asyncio.sleep(0.01)


class WeightSetter(AsyncLoopRunner):
    pass


task_scorer = TaskScorer()