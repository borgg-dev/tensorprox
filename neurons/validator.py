import sys
sys.path.append("/home/azureuser/tensorprox/")
from aiohttp import web
import asyncio
import time
from tensorprox import settings
import os
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings
from typing import Tuple
from loguru import logger
from tensorprox.base.validator import BaseValidatorNeuron
from tensorprox.base.dendrite import DendriteResponseEvent, PingSynapse
from tensorprox.base.protocol import MachineConfig
from tensorprox.utils.logging import ValidatorLoggingEvent, ErrorLoggingEvent
from tensorprox.miner_availability.miner_availability import query_availability, setup_available_machines
from tensorprox.rewards.scoring import task_scorer
from tensorprox.utils.timer import Timer
from tensorprox import global_vars
from tensorprox.tasks.base_task import DDoSDetectionTask
from tensorprox.rewards.weight_setter import weight_setter
from tensorprox.tasks.traffic_data import TrafficData
from tensorprox.tasks.task_creation import task_loop
from tensorprox.utils.uids import extract_axons_ips
from tensorprox.utils.utils import get_location_from_maxmind, get_my_public_ip, haversine_distance

# Create an aiohttp app for validator
app = web.Application()

class Validator(BaseValidatorNeuron):
    """Tensorprox validator neuron."""

    def __init__(self, config=None):
        super(Validator, self).__init__(config=config)
        self.load_state()
        self._lock = asyncio.Lock()
        self.assigned_miners = []  # To store the assigned miners (UIDs)
        self.playlist = []  # To store the playlist 

    async def check_miner(self, uid):
        """Check the status of an individual miner."""
        # Query the availability of a single miner
        synapse, uid_status_availability = await query_availability(uid)  # Get both lists from the query
        return synapse, uid_status_availability


    async def run_step(self, timeout: float) -> Tuple[DendriteResponseEvent, DendriteResponseEvent] | DendriteResponseEvent | None:
        """Runs a single step to query the assigned miners' availability."""
        try:
            async with self._lock:
                if not self.assigned_miners:
                    logger.warning("No miners assigned. Skipping availability check.")
                    return None

                # Step 1: Query availabilities of the assigned miners in parallel
                with Timer() as timer:

                    logger.debug(f"🔍 Querying machine availabilities for UIDs: {self.assigned_miners}")

                    # Gather all the results of the availability checks concurrently
                    tasks = [self.check_miner(uid) for uid in self.assigned_miners]
                    results = await asyncio.gather(*tasks)
                    synapses, all_miners_availability = zip(*results) if results else ([], [])


                logger.debug(f"Received responses in {timer.elapsed_time:.2f} seconds")

                # Encapsulate the responses in a response event
                response_event_1 = DendriteResponseEvent(
                    synapses=synapses, 
                    all_miners_availability=all_miners_availability,
                    uids=self.assigned_miners
                )

                logger.debug(response_event_1)

                # Step 2: Process miner availability results
                available_miners = []
                for uid, synapse, availability in zip(self.assigned_miners, synapses, all_miners_availability):
                    if isinstance(availability["ping_status_code"], int) and availability["ping_status_code"] == 200:
                        available_miners.append((uid, synapse))

                if not available_miners:
                    logger.warning("No miners are available after availability check.")
                    return None  # Return None if no miners are available

                # Step 3: Setup available miners
                with Timer() as setup_timer:
                    logger.info(f"Setting up available miners : {[uid for uid, synapse in available_miners]}")
                    setup_status = await setup_available_machines(available_miners, self.playlist)

                # Step 4: Create second response event (After machine setup)
                response_event_2 = DendriteResponseEvent(
                    synapses=synapses,  # Keep original synapses
                    setup_status=setup_status,  # Updated availability after setup
                    uids=[uid for uid, _ in available_miners],  # Extract only UIDs
                )

                logger.debug(f"Setup completed in {setup_timer.elapsed_time:.2f} seconds")
                logger.debug(response_event_2)

                return response_event_1, response_event_2

        except Exception as ex:
            logger.exception(ex)
            return None


    async def forward(self):
        """Implements the abstract forward method."""
        logger.info("Placeholder forward method called.")
        await asyncio.sleep(1)  # Prevents crash, can be modified for actual processing logic

# Define the validator instance
validator_instance = Validator()

async def ready(request):
    """Receive readiness request from the orchestrator."""
    data = await request.json()
    message = data.get("message", "").lower()

    if message == "ready":
        return web.json_response({"status": "ready"})
    else:
        return web.json_response({"status": "failed"}, status=400)

async def assign_miners(request):
    """Receive assigned miners from the orchestrator and update Validator instance."""
    data = await request.json()
    assigned_miners = data.get("assigned_miners", [])
    playlist = data.get("playlist", [])

    if not assigned_miners:
        return web.json_response({"status": "failed", "error": "No miners provided"}, status=400)

    async with validator_instance._lock:
        validator_instance.assigned_miners = assigned_miners
        validator_instance.playlist = playlist
        logger.info(f"Assigned miners updated: {assigned_miners}")
        logger.info(f"Playlist updated: {playlist}")

    # Trigger run_step manually only when miners are assigned
    asyncio.create_task(validator_instance.run_step(timeout=settings.NEURON_TIMEOUT))

    return web.json_response({"status": "miners_assigned"})

# Add routes to the aiohttp app
app.router.add_post('/ready', ready)
app.router.add_post('/assign_miners', assign_miners)

# Main function to start both the validator and aiohttp server
async def main():
    # Start the aiohttp server
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="0.0.0.0", port=8000)
    await site.start()

    logger.info("Validator aiohttp server started.")

    try:
        await asyncio.Event().wait()  # Keeps the server running indefinitely
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
