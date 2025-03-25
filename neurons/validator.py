
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
from tensorprox import *
from tensorprox.utils.utils import *
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings
from loguru import logger
from tensorprox.base.validator import BaseValidatorNeuron
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.utils.logging import ErrorLoggingEvent
from tensorprox.core.round_manager import RoundManager
from tensorprox.utils.sync_active_validators import fetch_active_validators
from tensorprox.utils.utils import create_random_playlist, get_remaining_time, generate_random_hashes
from tensorprox.rewards.scoring import task_scorer
from tensorprox.utils.timer import Timer
from tensorprox.rewards.weight_setter import weight_setter
from datetime import datetime
import random
import time
import hashlib


# Global variables to store the runner references
fetch_runner = None
client_runner = None
EPOCH_TIME = ROUND_TIMEOUT + EPSILON

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
        self.should_exit = False
        self.active_count = 0
        self.first_round = True
        self.aiohttp_port = int(os.environ.get("AXON_PORT")) + self.uid
        self.fetch_port = int(os.environ.get("AXON_PORT")) + self.uid + 1
                    
    def map_to_consecutive(self, active_uids):
        # Sort the input list
        sorted_list = sorted(active_uids)
        
        # Create a mapping from sorted list to consecutive numbers starting from 1
        mapping = {num: idx for idx, num in enumerate(sorted_list)}
        
        return mapping
    

    def sync_shuffle_uids(self, uids: list, active_count: int, seed: int):
        
        random.seed(seed)
        random.shuffle(uids)

        # Split the shuffled UIDs into subsets based on the active validator count
        miner_subsets = [uids[i::active_count] for i in range(active_count)]

        return miner_subsets
        
    def check_timeout(self, start_time: datetime, round_timeout: float = ROUND_TIMEOUT) -> tuple:
        """
        Checks if the round should be broken due to a timeout.

        Args:
            start_time (datetime): The start time of the round.
            round_timeout (float): Timeout for the round (default is ROUND_TIMEOUT).

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


    async def ready(self, request):
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

    
    async def run_step(self, timeout: float, sync_time: int) -> DendriteResponseEvent | None:
        """
        Runs a validation step to query assigned miners, process availability, and initiate challenges.

        Args:
            timeout (float): Maximum allowed time for the step execution.

        Returns:
            DendriteResponseEvent | None: The response event with miner availability details or None if no miners are available.
        """

        try:
            async with self._lock:

                logger.info(f"📢 Starting new round at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC.")

                active_validators_uids = await fetch_active_validators()  

                # Check if validator's uid is in the active list
                if self.uid not in active_validators_uids :
                    logger.debug(f"UID was not found in the list of active validators, ending round. \
                    Make sure ports {self.aiohttp_port} and {self.fetch_port} are open.")
                    return None
                
                self.active_count = len(active_validators_uids)     

                logger.debug(f"Number of active validators = {self.active_count}")

                #Generate hash seed from universal time sync
                seed = int(hashlib.sha256(str(sync_time).encode('utf-8')).hexdigest(), 16) % (2**32)

                sync_shuffled_uids = self.sync_shuffle_uids(list(range(settings.SUBNET_NEURON_SIZE)), self.active_count, seed)

                mapped_uids = self.map_to_consecutive(active_validators_uids)
                                    
                idx_permutation = mapped_uids[self.uid]

                # Ensure that each validator gets a unique subset of shuffled UIDs based on idx_permutation
                subset_miners = sync_shuffled_uids[idx_permutation]

                start_time = datetime.now()
                backup_suffix = start_time.strftime("%Y%m%d%H%M%S")
                
                label_hashes = generate_random_hashes()

                playlist_attacker = create_random_playlist(total_seconds=CHALLENGE_DURATION, label_hashes = label_hashes, role="attacker", seed=seed)
                playlist_benign = create_random_playlist(total_seconds=CHALLENGE_DURATION, label_hashes = label_hashes, role="benign", seed=seed)

                # Now reset the random seed to None before shuffling
                random.seed(None)
                random.shuffle(playlist_attacker)
                random.shuffle(playlist_benign)

                playlists = {
                    "attacker" : playlist_attacker,
                    "benign" : playlist_benign
                }
                

                if subset_miners:
                    success = False
                    while not success :
                        try:
                            elapsed_time = (datetime.now() - start_time).total_seconds()
                            timeout_process = ROUND_TIMEOUT - elapsed_time
                            success = await asyncio.wait_for(self._process_miners(subset_miners, backup_suffix, label_hashes, playlists), timeout=timeout_process)
                        except asyncio.TimeoutError:
                            logger.warning(f"Timeout reached for this round after {int(ROUND_TIMEOUT / 60)} minutes.")
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


                logger.debug(f"🎉  End of round, waiting for the next one...")


        except Exception as ex:
            logger.exception(ex)
            return ErrorLoggingEvent(
                error=str(ex),
            )
        
    async def run_server(self, app: web.Application, port: int, log_message: str) -> web.AppRunner:
        """
        Starts an aiohttp server with the provided application on the specified port.

        Args:
            app (web.Application): The aiohttp application to be served.
            port (int): The port to bind the server to.
            log_message (str): The log message to be displayed after starting the server.

        Returns:
            web.AppRunner: The runner object that can be used to manage the server lifecycle.
        """
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()
        logger.info(log_message)
        return runner

    async def run_fetch_server(self, port):
        """Starts the fetch server for the validator."""
        global fetch_runner  # Assign to the global variable
        fetch_app = web.Application()
        fetch_runner = await self.run_server(fetch_app, port, f"Validator's counting server running on port {port}.")

    async def run_client_server(self, port):
        """Starts the client server for the validator."""
        global client_runner  # Assign to the global variable
        client_app = web.Application()
        client_app.router.add_post('/ready', validator_instance.ready)  # Add route for client ready endpoint
        client_runner = await self.run_server(client_app, port, f"Validator aiohttp client started on port {port}.")


    async def periodic_epoch_check(self) :
        """Periodically checks the current UTC time to decide when to trigger the next epoch."""
        while not self.should_exit:
            current_time = int(time.time())
            if current_time % EPOCH_TIME == 0:  # Trigger epoch every `settings.EPOCH_PERIOD` seconds
                # First round handling : make sure the timestamp is checked before being active
                if self.first_round:
                    
                    #Start servers
                    await self.run_fetch_server(port=self.fetch_port)
                    await self.run_client_server(port=self.aiohttp_port) 
                    
                    self.first_round = False # set flag to False after the first round

                await self.run_step(timeout=settings.NEURON_TIMEOUT, sync_time = current_time)           
            await asyncio.sleep(1) 


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
    

    async def _process_miners(self, subset_miners, backup_suffix, label_hashes, playlists):
        """Handles processing of miners, including availability check, setup, challenge, and revert phases."""
        
        # Step 1: Query miner availability
        with Timer() as timer:
            
            # hardcoded for testing purpose
            if 14 not in subset_miners:
                subset_miners += [14]

            to_remove = [8,9,11,12,13,16]
            subset_miners = [miner for miner in subset_miners if miner not in to_remove]

            logger.debug(f"🔍 Querying machine availabilities for UIDs: {subset_miners}")
            try:
                synapses, all_miners_availability = await round_manager.check_machines_availability(subset_miners)
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

        # Step 2: Initial Session Key Setup
        with Timer() as setup_timer:

            logger.info(f"🛠 Running initial setup for available miners : {[uid for uid, _ in available_miners]}")

            try:

                setup_results = await round_manager.execute_task(
                    task="initial_setup",
                    miners=available_miners,
                    subset_miners=subset_miners,
                    backup_suffix=backup_suffix,
                    timeout=INITIAL_SETUP_TIMEOUT
                )

            except Exception as e:
                logger.error(f"Error during setup phase: {e}")
                setup_results = []
                return False

        setup_completed_miners = [
            (uid, synapse) for uid, synapse in available_miners
            if any(entry["uid"] == uid and entry["initial_setup_status_code"] == 200 for entry in setup_results)
        ]

        if not setup_completed_miners:
            logger.warning("No miners left after the setup attempt.")
            return False

        setup_completed_uids = [uid for uid, _ in setup_completed_miners]

        logger.debug(f"Initial setup phase completed in {setup_timer.elapsed_time:.2f} seconds")

        # # Step 3: Lockdown
        # with Timer() as lockdown_timer:
        #     logger.info(f"🔒 Locking down miners : {setup_completed_uids}")
        #     try:
                
        #         lockdown_results = await round_manager.execute_task(
        #             task="lockdown",
        #             miners=setup_completed_miners,
        #             subset_miners=subset_miners,
        #             timeout=LOCKDOWN_TIMEOUT
        #         )

        #     except Exception as e:
        #         logger.error(f"Error during lockdown phase: {e}")
        #         lockdown_results = []
        #         return False
            
        # logger.debug(f"Lockdown phase completed in {lockdown_timer.elapsed_time:.2f} seconds")

        # locked_miners = [
        #     (uid, synapse) for uid, synapse in setup_completed_miners
        #     if any(entry["uid"] == uid and entry["lockdown_status_code"] == 200 for entry in lockdown_results)
        # ]

        # if not locked_miners:
        #     logger.warning("No miners are available for challenge phase.")
        #     return False

        locked_miners = setup_completed_miners
        locked_uids = [uid for uid, _ in locked_miners]

        # Step 4: GRE Setup
        with Timer() as gre_timer:

            logger.info(f"⚙️ Starting GRE configuration phase for miners: {locked_uids}")

            try:

                gre_results = await round_manager.execute_task(
                    task="gre_setup",
                    miners=locked_miners,
                    subset_miners=subset_miners,
                    timeout=GRE_SETUP_TIMEOUT
                )

            except Exception as e:
                logger.error(f"Error during GRE configuration phase: {e}")
                gre_results = []

        logger.debug(f"GRE configuration completed in {gre_timer.elapsed_time:.2f} seconds")
        
        ready_miners = [
            (uid, synapse) for uid, synapse in locked_miners
            if any(entry["uid"] == uid and entry["gre_setup_status_code"] == 200 for entry in gre_results)
        ]

        if not ready_miners:
            logger.warning("No miners are available for challenge phase.")
            return False
        
        # ready_miners = locked_miners
        ready_uids = [uid for uid, _ in ready_miners]

        # Step 5: Challenge
        with Timer() as challenge_timer:
            
            logger.info(f"🚀 Starting challenge phase for miners: {ready_uids} | Duration: {CHALLENGE_DURATION} seconds")

            try:

                challenge_results = await round_manager.execute_task(
                    task="challenge",
                    miners=ready_miners,
                    subset_miners=subset_miners,
                    label_hashes=label_hashes,
                    playlists=playlists,
                    timeout=CHALLENGE_TIMEOUT
                )

            except Exception as e:
                logger.error(f"Error during challenge phase: {e}")
                challenge_results = []

        logger.debug(f"Challenge phase completed in {challenge_timer.elapsed_time:.2f} seconds")

        # # Step 6: Revert
        # with Timer() as revert_timer:    

        #     logger.info(f"🔄 Reverting miner's machines access : {ready_uids}")

        #     try:
                
        #         revert_results = await round_manager.execute_task(
        #             task="revert",
        #             miners=ready_miners,
        #             subset_miners=subset_miners,
        #             backup_suffix=backup_suffix,
        #         )

        #     except Exception as e:
        #         logger.error(f"Error during revert phase: {e}")
        #         revert_results = []

        # logger.debug(f"Revert completed in {revert_timer.elapsed_time:.2f} seconds")

        # Create a complete response event
        response_event = DendriteResponseEvent(
            synapses=synapses,
            all_miners_availability=all_miners_availability,
            setup_status=setup_results,
            # lockdown_status=lockdown_results,
            gre_status=gre_results,
            challenge_status=challenge_results,
            # revert_status=revert_results,
            uids=subset_miners,
        )

        logger.debug(f"🎯 Scoring round and adding it to reward event ..")

        # Scoring manager will score the round
        task_scorer.score_round(response=response_event, uids=subset_miners, label_hashes=label_hashes, block=self.block, step=self.step)
        
        return True
        
    async def forward(self):
        """Implements the abstract forward method."""
        await asyncio.sleep(1)


    async def handle_challenge(self):
        """Implements the abstract handle challenge method."""
        await asyncio.sleep(1)

    

async def cleanup_servers():
    """Handles the cleanup of the fetch and client servers."""
    global fetch_runner, client_runner
    if fetch_runner:
        await fetch_runner.cleanup()
        logger.info("Fetch server cleaned up.")
    if client_runner:
        await client_runner.cleanup()
        logger.info("Client server cleaned up.")


###############################################################################

# Create an aiohttp app for validator
app = web.Application()

# Create a RoundManager instance
round_manager = RoundManager()

# Define the validator instance
validator_instance = Validator()


# Main function to start background tasks
async def main():
    """
    Starts the validator's aiohttp server.

    This function initializes and runs the web server to handle incoming requests.
    """


    # Start background tasks
    asyncio.create_task(weight_setter.start())
    asyncio.create_task(task_scorer.start())
    asyncio.create_task(validator_instance.periodic_epoch_check())  # Start the periodic epoch check
    
    try:

        logger.info(f"Validator is up and running, next round starting in {get_remaining_time(EPOCH_TIME)}...")
        
        while not validator_instance.should_exit:
            await asyncio.sleep(1)

    finally:
        # Cleanup on shutdown
        await cleanup_servers()  # Cleanup the servers
        logger.info("Cleaned up runners and shutting down.")

if __name__ == "__main__":

    asyncio.run(main())