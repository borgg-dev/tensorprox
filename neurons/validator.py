# ruff: noqa: E402
import sys
sys.path.append("/home/azureuser/tensorprox/")
import asyncio
import time
from tensorprox import settings

settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings

from loguru import logger
from tensorprox.base.validator import BaseValidatorNeuron
from tensorprox.base.dendrite import DendriteResponseEvent, TensorProxSynapse
from tensorprox.utils.logging import ValidatorLoggingEvent, ErrorLoggingEvent
from tensorprox.rewards.scoring import task_scorer
from tensorprox.miner_availability.miner_availability import availability_checking_loop, miner_availabilities
from tensorprox.utils.timer import Timer
from tensorprox.mutable_globals import task_queue, scoring_queue, feature_queue
from tensorprox.tasks.base_task import BaseTask
from tensorprox.weight_setting.weight_setter import weight_setter
from neurons.Validator.traffic_data import TrafficData
from tensorprox.tasks.task_creation import task_loop


NEURON_SAMPLE_SIZE = 100

class Validator(BaseValidatorNeuron):
    """Tensorprox validator neuron."""
    
    def __init__(self, config=None):
        super(Validator, self).__init__(config=config)
        self.load_state()
        self._lock = asyncio.Lock()

    async def run_step(self, k: int, timeout: float) -> ValidatorLoggingEvent | ErrorLoggingEvent | None:
        """Executes a single step of the agent, which consists of:
        - Getting a list of uids to query
        - Querying the network
        - Rewarding the network
        - Updating the scores
        - Logging the event
        Args:
            agent (HumanAgent): The agent to run the step for.
            roles (List[str]): The roles for the synapse.
            messages (List[str]): The messages for the synapse.
            k (int): The number of uids to query.
            timeout (float): The timeout for the queries.
            exclude (list, optional): The list of uids to exclude from the query. Defaults to [].
        """
        
        while len(scoring_queue) > settings.SCORING_QUEUE_LENGTH_THRESHOLD:
            logger.debug("Scoring queue is full. Waiting 1 second...")
            await asyncio.sleep(1)
        while len(task_queue) == 0:
            logger.warning("No tasks in queue. Waiting 1 second...")
            await asyncio.sleep(1)

        try:

            # get task from the task queue
            task = task_queue.pop(0)

            # Simulate sending task to miners and collecting responses
            with Timer() as timer:
                response_event = await self.collect_responses(task=task)

            logger.debug(f"Received responses in {timer.elapsed_time:.2f} seconds")
            print('************************************************')
            print(task)
            print(response_event)
            print("***********************************************")
            # Scoring manager will score the responses
            task_scorer.add_to_queue(
                task=task,
                response=response_event,
                block=self.block,
                step=self.step,
                time_to_answer=2,
                task_id=task.task_id,  # Use task_id from BaseTask
            )

            # Log the step event.
            return ValidatorLoggingEvent(
                block=self.block,
                step=self.step,
                step_time=timer.elapsed_time,
                response_event=response_event,
                task_id=task.task_id,
            )

        except Exception as ex:
            logger.exception(ex)
            return ErrorLoggingEvent(
                error=str(ex),
            )

    async def collect_responses(self, task: BaseTask) -> DendriteResponseEvent | None:
        # Get the list of uids and their axons to query for this step.
        uids = miner_availabilities.get_available_miners(task=task, k=NEURON_SAMPLE_SIZE)
        logger.debug(f"🔍 Querying uids: {uids}")
        if len(uids) == 0:
            logger.debug("No available miners. Skipping step.")
            return
        axons = [settings.METAGRAPH.axons[uid] for uid in uids]


        # Directly call dendrite and process responses in parallel
        synapse = TensorProxSynapse(
            task_name=task.__class__.__name__,
            challenges=[task.query]
        )

        responses = await settings.DENDRITE(
            axons=axons,
            synapse=synapse,
            timeout=settings.NEURON_TIMEOUT,
            deserialize=False,
            streaming=False,
        )


        # Encapsulate the responses in a response event (dataclass)
        response_event = DendriteResponseEvent(
            results=responses, uids=uids, timeout=settings.NEURON_TIMEOUT
        )
        return response_event

    async def forward(self):
        """
        Encapsulates a full conversation between the validator and miners. Contains one or more rounds of request-response.

        """
        logger.info("🚀 Starting forward loop...")
        with Timer() as timer:
            # in run_step, a task is generated and sent to the miners
            async with self._lock:
                event = await self.run_step(
                    k=NEURON_SAMPLE_SIZE,
                    timeout=settings.NEURON_TIMEOUT,
                )

        if not event:
            return

        event.forward_time = timer.elapsed_time

    def __enter__(self):
        if settings.NO_BACKGROUND_THREAD:
            logger.warning("Running validator in main thread.")
            self.run()
        else:
            self.run_in_background_thread()

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Stops the validator's background operations upon exiting the context.
        This method facilitates the use of the validator in a 'with' statement.

        Args:
            exc_type: The type of the exception that caused the context to be exited.
                      None if the context was exited without an exception.
            exc_value: The instance of the exception that caused the context to be exited.
                       None if the context was exited without an exception.
            traceback: A traceback object encoding the stack trace.
                       None if the context was exited without an exception.
        """
        if self.is_running:
            logger.debug("Stopping validator in background thread.")
            self.should_exit = True
            self.thread.join(5)
            self.is_running = False
            logger.debug("Stopped")



async def main():

    # Start the traffic listener
    traffic_data_handler = TrafficData(uri="ws://20.172.67.75:8765", feature_queue=feature_queue)
    asyncio.create_task(traffic_data_handler.start())  # Start traffic data listener
    
    # Add your run_system call here to ensure the WebSocket listener is started.
    asyncio.create_task(task_loop.start())

    # will start checking the availability of miners at regular intervals
    asyncio.create_task(availability_checking_loop.start())

    asyncio.create_task(weight_setter.start())

    # start scoring tasks in separate loop
    asyncio.create_task(task_scorer.start())

    with Validator() as v:
        while True:
            logger.info(
                f"Validator running:: network: {settings.SUBTENSOR.network} "
                f"| block: {v.block} "
                f"| step: {v.step} "
                f"| uid: {v.uid} "
                f"| last updated: {v.block - settings.METAGRAPH.last_update[v.uid]} "
                f"| vtrust: {settings.METAGRAPH.validator_trust[v.uid]:.3f} "
                f"| emission {settings.METAGRAPH.emission[v.uid]:.3f}"
            )
            time.sleep(5)

            if v.should_exit:
                logger.warning("Ending validator...")


# The main function parses the configuration and runs the validator.
if __name__ == "__main__":
    asyncio.run(main())
    # will start rotating the different LLMs in/out of memory