import threading
import asyncio
from tensorprox.base.loop_runner import AsyncLoopRunner
from tensorprox.mutable_globals import task_queue, scoring_queue, feature_queue
from tensorprox.settings import settings
from tensorprox.tasks.base_task import BaseTask
from loguru import logger
from pydantic import ConfigDict
from tensorprox.miner_availability.miner_availability import miner_availabilities


class TaskLoop(AsyncLoopRunner):
    is_running: bool = False
    thread: threading.Thread = None
    interval: int = 10
    model_config = ConfigDict(arbitrary_types_allowed=True)

        
    def __init__(self, feature_queue):
        super().__init__()
        self._feature_queue = feature_queue

    async def run_step(self) -> None:
        print('Running TaskLoop Step...')

        if len(task_queue) > settings.TASK_QUEUE_LENGTH_THRESHOLD:
            logger.debug("Task queue is full. Skipping task generation.")
            return
        if len(scoring_queue) > settings.SCORING_QUEUE_LENGTH_THRESHOLD:
            logger.debug("Scoring queue is full. Skipping task generation.")
            return

        try:
            task = BaseTask()

            # Check if miners are available
            if len(miner_availabilities.get_available_miners(task=task)) == 0:
                logger.debug(
                    f"No available miners for Task: {task.__class__.__name__}. Skipping step."
                )
                return

            # Generate the query and reference for the task
            if not task.query:
                logger.debug(f"Generating query for task: {task.__class__.__name__}.")
                traffic_data = await self._feature_queue.get()
                if traffic_data:
                    logger.debug("Successfully retrieved traffic data from feature_queue.")
                else:
                    logger.warning("No traffic data retrieved from feature_queue.")
                
                task.generate_query_reference(traffic_data)

            task_queue.append(task)
            logger.debug(f"Task {task.__class__.__name__} added to the queue.")

        except Exception as ex:
            logger.exception("Exception during task generation:", ex)
            return None
        await asyncio.sleep(0.01)
        
# Instantiate TaskLoop to process data from the feature_queue
task_loop = TaskLoop(feature_queue)
