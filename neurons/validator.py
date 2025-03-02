
"""
================================================================================

TensorProx Validator

This module initializes a TensorProx validator responsible for managing miners and running validation tasks. 
It sets up the necessary dependencies, configurations, and the aiohttp web server for orchestrator communication.

Key Responsibilities:
- Check miner's availability.
- Manages the lifecycle of validation tasks, including setup, lockdown, challenge, and revert phases.
- Provides an API for readiness checks and miner assignments.

Dependencies:
- `aiohttp`: For handling asynchronous web requests.
- `asyncio`: For managing concurrent tasks.
- `loguru`: For structured logging.
- `tensorprox`: Core TensorProx framework for miner management and validation.

License:
This software is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0).
You are free to use, share, and modify the code for non-commercial purposes only.

Commercial Usage:
The only authorized commercial use of this software is for mining or validating within the TensorProx subnet.
For any other commercial licensing requests, please contact Shugo LTD.

See the full license terms here: https://creativecommons.org/licenses/by-nc/4.0/

Author: Shugo LTD
Version: 0.1.0

================================================================================
"""


import os, sys
sys.path.append(os.path.expanduser("~/tensorprox"))

from aiohttp import web
import asyncio
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings
from loguru import logger
from tensorprox.base.validator import BaseValidatorNeuron
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.utils.logging import ErrorLoggingEvent

from tensorprox.core.miner_management import MinerManagement
from tensorprox.rewards.scoring import task_scorer
from tensorprox.utils.timer import Timer
from tensorprox.rewards.weight_setter import weight_setter
from datetime import datetime

# Create an aiohttp app for validator
app = web.Application()
miner_manager = MinerManagement()


class Validator(BaseValidatorNeuron):
    """Tensorprox validator neuron responsible for managing miners and running validation tasks."""

    def __init__(self, config=None):
        """
        Initializes the validator instance.

        Args:
            config (dict, optional): Configuration settings for the validator.
        """
        super(Validator, self).__init__(config=config)
        self.load_state()
        self._lock = asyncio.Lock()
        self.assigned_miners = []  # List of assigned miner UIDs
        self.playlist = []  #Playlist for traffic generation


    def check_timeout(self, start_time: datetime, round_timeout: float = settings.ROUND_TIMEOUT) -> tuple:
        """
        Checks if the round should be broken due to a timeout.

        Args:
            start_time (datetime): The start time of the round.
            round_timeout (float): Timeout for the round (default is settings.ROUND_TIMEOUT).

        Returns:
            tuple: A tuple containing:
                - condition (bool): The updated condition indicating whether the round should be broken.
                - elapsed_time (float): The elapsed time in seconds since the round started.
                - remaining_time (float): The remaining time in seconds until the round timeout.
        """
        elapsed_time = (datetime.now() - start_time).total_seconds()
        remaining_time = round_timeout - elapsed_time

        # If the timeout has been reached
        if remaining_time <= 0:
            logger.info("Timeout reached for this round.")
            return True # Timeout occurred

        elif elapsed_time % 10 < 1:
            logger.debug(f"Waiting until the end of the round... Remaining time: {int(remaining_time // 60)}m {int(remaining_time % 60)}s")
    
        return False  # Round is still active


    async def run_step(self, timeout: float) -> DendriteResponseEvent | None:
        """
        Runs a validation step to query assigned miners, process availability, and initiate challenges.

        Args:
            timeout (float): Maximum allowed time for the step execution.

        Returns:
            DendriteResponseEvent | None: The response event with miner availability details or None if no miners are available.
        """

        try:
            async with self._lock:

                logger.debug(f"🎉 Starting new epoch ...")

                round_counter = 1

                for subset_miners in self.assigned_miners:

                    start_time = datetime.now()
                    logger.info(f"▶️  Initiating round {round_counter}/{len(self.assigned_miners)} at {start_time.strftime('%Y-%m-%d %H:%M:%S')}...")  # Formatted time
                    round_counter += 1
                    backup_suffix = start_time.strftime("%Y%m%d%H%M%S")
                    if subset_miners:
                        success = False
                        while not success :
                            try:
                                elapsed_time = (datetime.now() - start_time).total_seconds()
                                timeout_process = settings.ROUND_TIMEOUT - elapsed_time
                                success = await asyncio.wait_for(self._process_miners(subset_miners, backup_suffix), timeout=timeout_process)
                            except asyncio.TimeoutError:
                                logger.warning(f"Timeout reached for this round after {settings.ROUND_TIMEOUT / 60} minutes.")
                            except Exception as ex:
                                logger.exception(f"Unexpected error while processing miners: {ex}.")

                            condition = self.check_timeout(start_time)
                            
                            if condition :
                                break
                    else :
                        logger.warning("📖 No miners assigned for this round.")
                        condition = False

                    if not condition:  
                        await self._wait_for_condition(start_time)


                logger.debug(f"🎉  End of epoch, waiting for the next one...")

        except Exception as ex:
            logger.exception(ex)
            return ErrorLoggingEvent(
                error=str(ex),
            )
        

    async def _wait_for_condition(self, start_time):
        """
        Waits for the timeout condition to be met by checking the elapsed time.

        Args:
            start_time (datetime): The start time of the current round.

        Returns:
            bool: Returns True when the condition is met, False otherwise.
        """

        while not self.check_timeout(start_time):
            await asyncio.sleep(1)  # Check the condition every second
        return True  # The condition is met, the loop ends
    

    async def _process_miners(self, subset_miners, backup_suffix):
        """Handles processing of miners, including availability check, setup, challenge, and revert phases."""
        
        # Step 1: Query miner availability
        with Timer() as timer:
            # # hardcoded for testing purpose
            # if 7 not in subset_miners:
            #     subset_miners += [7]

            logger.debug(f"🔍 Querying machine availabilities for UIDs: {subset_miners}")
            try:
                synapses, all_miners_availability = await miner_manager.check_machines_availability(subset_miners)
            except Exception as e:
                logger.error(f"Error querying machine availabilities: {e}")
                return False

        logger.debug(f"Received responses in {timer.elapsed_time:.2f} seconds")

        available_miners = [
            (uid, synapse) for uid, synapse, availability in zip(subset_miners, synapses, all_miners_availability)
            if availability["ping_status_code"] == 200
        ]

        if not available_miners:
            logger.warning("No miners are available after availability check. Retrying..")
            return False

        # Step 2: Setup
        with Timer() as setup_timer:
            logger.info(f"Setting up available miners : {[uid for uid, _ in available_miners]}")
            try:
                setup_results = await miner_manager.execute_task(task="setup", miners=available_miners, subset_miners=subset_miners, task_function=miner_manager.async_setup, backup_suffix=backup_suffix)
            except Exception as e:
                logger.error(f"Error during setup phase: {e}")
                setup_results = []
                return False

        logger.debug(f"Setup completed in {setup_timer.elapsed_time:.2f} seconds")

        setup_complete_miners = [
            (uid, synapse) for uid, synapse in available_miners
            if any(entry["uid"] == uid and entry["setup_status_code"] == 200 for entry in setup_results)
        ]

        if not setup_complete_miners:
            logger.warning("No miners left after the setup attempt.")
            return False

        logger.debug(f"Setup phase completed in {setup_timer.elapsed_time:.2f} seconds")

        # # Step 3: Lockdown
        # with Timer() as lockdown_timer:
        #     logger.info(f"🔒 Locking down miners : {setup_completed_uids}")
        #     try:
        #         lockdown_results = await miner_manager.execute_task(task="lockdown", miners=setup_complete_miners, subset_miners=subset_miners, task_function = miner_manager.async_lockdown)
        #     except Exception as e:
        #         logger.error(f"Error during lockdown phase: {e}")
        #         lockdown_results = []
        #         return False
            
        # logger.debug(f"Lockdown phase completed in {lockdown_timer.elapsed_time:.2f} seconds")

        # ready_miners = [
        #     (uid, synapse) for uid, synapse in setup_complete_miners
        #     if any(entry["uid"] == uid and entry["lockdown_status_code"] == 200 for entry in lockdown_results)
        # ]

        # if not ready_miners:
        #     logger.warning("No miners are available for challenge phase.")
        #     return False

        ready_miners = setup_complete_miners
        ready_uids = [uid for uid, _ in ready_miners]

        # Step 4: Challenge
        with Timer() as challenge_timer:
            logger.info(f"🚀 Starting challenge phase for miners: {ready_uids} | Duration: {settings.CHALLENGE_DURATION} seconds")
            try:
                ready_results = await miner_manager.get_ready(ready_uids)
                challenge_results = await miner_manager.execute_task(task="challenge", miners=ready_miners, subset_miners=subset_miners, task_function=miner_manager.async_challenge)
            except Exception as e:
                logger.error(f"Error during challenge phase: {e}")
                challenge_results = []

        logger.debug(f"Challenge phase completed in {challenge_timer.elapsed_time:.2f} seconds")

        # Step 5: Revert
        with Timer() as revert_timer:    
            logger.info(f"🔄 Reverting miner's machines access : {ready_uids}")
            try:
                revert_results = await miner_manager.execute_task(task="revert", miners=ready_miners, subset_miners=subset_miners, task_function=miner_manager.async_revert, backup_suffix=backup_suffix)
            except Exception as e:
                logger.error(f"Error during revert phase: {e}")
                revert_results = []

        logger.debug(f"Revert completed in {revert_timer.elapsed_time:.2f} seconds")

        # Create a complete response event
        response_event = DendriteResponseEvent(
            synapses=synapses,
            all_miners_availability=all_miners_availability,
            setup_status=setup_results,
            #lockdown_status=lockdown_results,
            challenge_status=challenge_results,
            revert_status=revert_results,
            uids=subset_miners,
        )

        logger.debug(f"🎯 Scoring round and adding it to reward event ..")

        # Scoring manager will score the round
        task_scorer.score_round(response=response_event, uids=subset_miners, block=self.block, step=self.step)
        
        return True
        
    async def forward(self):
        """Implements the abstract forward method."""
        await asyncio.sleep(1)


    async def handle_challenge(self):
        """Implements the abstract handle challenge method."""
        await asyncio.sleep(1)


# Define the validator instance
validator_instance = Validator()


async def ready(request):
    """
    Handles readiness checks from the orchestrator.

    Args:
        request (aiohttp.web.Request): Incoming HTTP request.

    Returns:
        aiohttp.web.Response: JSON response indicating readiness status.
    """
    data = await request.json()
    message = data.get("message", "").lower()

    if message == "ready":
        return web.json_response({"status": "ready"})
    else:
        return web.json_response({"status": "failed"}, status=400)
    

async def assign_miners(request):
    """
    Handles miner assignment requests from the orchestrator.

    Args:
        request (aiohttp.web.Request): Incoming HTTP request containing miner assignments.

    Returns:
        aiohttp.web.Response: JSON response confirming miner assignment.
    """
    data = await request.json()
    assigned_miners = data.get("assigned_miners", [])
    playlist = data.get("playlist", [])

    if not assigned_miners:
        return web.json_response({"status": "failed", "error": "No miners provided"}, status=400)

    async with validator_instance._lock:
        validator_instance.assigned_miners = assigned_miners
        validator_instance.playlist = playlist
        # logger.info(f"Assigned miners updated: {assigned_miners}")
        # logger.info(f"Playlist updated: {playlist}")

    # Trigger run_step manually only when miners are assigned
    asyncio.create_task(validator_instance.run_step(timeout=settings.NEURON_TIMEOUT))

    return web.json_response({"status": "miners_assigned"})


# Add routes to the aiohttp app
app.router.add_post('/ready', ready)
app.router.add_post('/assign_miners', assign_miners)


# Main function to start both the validator and aiohttp server
async def main():
    """
    Starts the validator's aiohttp server.

    This function initializes and runs the web server to handle incoming requests.
    """

    runner = web.AppRunner(app)
    await runner.setup()

    aiohttp_port = int(os.environ.get("VALIDATOR_AXON_PORT"))+1 #do not change this port
    site = web.TCPSite(runner, host="0.0.0.0", port=aiohttp_port)

    await site.start()

    logger.info("Validator aiohttp server started.")

    # Start background tasks
    asyncio.create_task(weight_setter.start())
    asyncio.create_task(task_scorer.start())
    
    try:
        await asyncio.Event().wait()  # Keeps the server running indefinitely
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())