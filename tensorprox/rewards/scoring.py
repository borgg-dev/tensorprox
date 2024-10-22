import asyncio
import threading

import numpy as np

from pydantic import ConfigDict
from loguru import logger
from dataclasses import dataclass

from tensorprox.tasks.base_task import BaseTask
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.utils.logging import RewardLoggingEvent, log_event
from tensorprox.mutable_globals import scoring_queue, feature_queue, reward_events
from tensorprox.base.loop_runner import AsyncLoopRunner
import asyncio
from tensorprox.rewards.reward import BaseRewardConfig



@dataclass
class ScoringConfig:
    task: BaseTask
    response: DendriteResponseEvent
    block: int
    step: int
    task_id: str


class TaskScorer(AsyncLoopRunner):
    """The scoring manager maintains a queue of tasks & responses to score and then runs a scoring loop in a background thread.
    This scoring loop will score the responses once the LLM needed is loaded in the model_manager and log the rewards.
    """

    is_running: bool = False
    thread: threading.Thread = None
    interval: int = 10

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def add_to_queue(
        self,
        task: BaseTask,
        response: DendriteResponseEvent,
        block: int,
        step: int,
        task_id: str,
    ) -> None:
        logger.debug(f"SCORING: Added to queue: {task.__class__.__name__} {task.task_id}")
        scoring_queue.append(
            ScoringConfig(
                task=task,
                response=response,
                block=block,
                step=step,
                task_id=task_id,
            )
        )

    async def run_step(self) -> RewardLoggingEvent:
        await asyncio.sleep(0.01)
        # Only score responses for which the model is loaded
        scorable = [
            scoring_config
            for scoring_config in scoring_queue
        ]
        if len(scorable) == 0:
            await asyncio.sleep(0.01)
            logger.debug("Nothing to score. Skipping scoring step.")
            await asyncio.sleep(5)
            return
        scoring_queue.remove(scorable[0])
        scoring_config: ScoringConfig = scorable.pop(0)
        
        # here we generate the actual reference
        scoring_config.task.make_reference(
            feature_data=scoring_config.task.query,
        )

        # and there we then calculate the reward
        logger.debug(
            f"""{len(scoring_config.response.predictions)} predictions to score for task {scoring_config.task}"""
        )
        rwd_events = BaseRewardConfig.apply(
            response_event=scoring_config.response,
            challenge=scoring_config.task.query,
            reference=scoring_config.task.reference,
            task=scoring_config.task,
        )
        reward_events.append(rwd_events)
        logger.debug(
            f"SCORING: Scored {scoring_config.task.__class__.__name__} {scoring_config.task.task_id} with reward"
        )
        log_event(
            RewardLoggingEvent(
                response_event=scoring_config.response,
                reward_events=reward_events,
                reference=scoring_config.task.reference,
                challenge=scoring_config.task.query,
                task=scoring_config.task.name,
                block=scoring_config.block,
                step=scoring_config.step,
                task_id=scoring_config.task_id,
            )
        )
        logger.info("Adding scores to rewards_and_uids")
        await asyncio.sleep(0.01)


class WeightSetter(AsyncLoopRunner):
    pass


task_scorer = TaskScorer()