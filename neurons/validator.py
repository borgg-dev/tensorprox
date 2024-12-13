# ruff: noqa: E402
import sys
sys.path.append("/home/azureuser/tensorprox/")
import asyncio
import time
from tensorprox import settings
import os
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings

from loguru import logger
from tensorprox.base.validator import BaseValidatorNeuron
from tensorprox.base.dendrite import DendriteResponseEvent, PingSynapse
from tensorprox.base.protocol import MachineConfig
from tensorprox.utils.logging import ValidatorLoggingEvent, ErrorLoggingEvent
from tensorprox.miner_availability.miner_availability import query_availabilities

from tensorprox.rewards.scoring import task_scorer
from tensorprox.utils.timer import Timer
from tensorprox import global_vars
from tensorprox.tasks.base_task import DDoSDetectionTask
from tensorprox.rewards.weight_setter import weight_setter
from tensorprox.tasks.traffic_data import TrafficData
from tensorprox.tasks.task_creation import task_loop
from tensorprox.utils.uids import extract_axons_ips
from tensorprox.utils.utils import get_location_from_maxmind, get_my_public_ip, haversine_distance


class Validator(BaseValidatorNeuron):
    """Tensorprox validator neuron."""
    
    def __init__(self, config=None):
        super(Validator, self).__init__(config=config)
        self.load_state()
        self._lock = asyncio.Lock()

    async def run_step(self, timeout: float) -> ValidatorLoggingEvent | ErrorLoggingEvent | None:
        """Runs a single step for the validation :
        1. Get Task from the task queue
        2. Get list of UIDS from the Metagraph and  query the network with the corresponding synapse
        3. Get back responses and reward the network
        4. Update scores
        Args:
            challenges (List[dict]): The input features for the synapse.
            timeout (float): The timeout for the queries.
        """
        
        try:

            #Ping miners to check if they are ready for the challenge
            with Timer() as timer:
                uids = settings.METAGRAPH.uids
                responses = await query_availabilities(uids=uids)

            logger.debug(f"Received responses in {timer.elapsed_time:.2f} seconds")
            logger.debug(responses)

            # Encapsulate the responses in a response event
            response_event = DendriteResponseEvent(results=responses, uids=uids)

            return response_event


        except Exception as ex:
            logger.exception(ex)
            return ErrorLoggingEvent(
                error=str(ex),
            )


    async def forward(self):
        logger.info("🚀 Starting forward loop...")
        with Timer() as timer:
            # in run_step, a task is generated and sent to the miners
            async with self._lock:
                event = await self.run_step(timeout=settings.NEURON_TIMEOUT)
                

        if not event:
            return

        # event.forward_time = timer.elapsed_time

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
    traffic_data_handler = TrafficData(uri="ws://127.0.0.1:8765", feature_queue=global_vars.feature_queue)
    asyncio.create_task(traffic_data_handler.start())  # Start traffic data listener
    
    # Add your run_system call here to ensure the WebSocket listener is started.
    asyncio.create_task(task_loop.start())

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


#Main function which runs the validator.
if __name__ == "__main__":
    asyncio.run(main())
