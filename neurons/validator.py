# ruff: noqa: E402
import sys
sys.path.append("/home/azureuser/tensorprox/")
from aiohttp import web
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


# Create an aiohttp app for validator
app = web.Application()


class Validator(BaseValidatorNeuron):
    """Tensorprox validator neuron."""

    def __init__(self, config=None):
        super(Validator, self).__init__(config=config)
        self.load_state()
        self._lock = asyncio.Lock()
        self.assigned_miners = []  # To store the assigned miners (UIDs)

    async def run_step(self, timeout: float) -> DendriteResponseEvent | None:
        """Runs a single step to query the assigned miners' availability."""
        try:
            async with self._lock:
                if not self.assigned_miners:
                    logger.warning("No miners assigned. Skipping availability check.")
                    return None

                # Query availabilities of the assigned miners
                with Timer() as timer:
                    responses = await query_availabilities(uids=self.assigned_miners)

                # Encapsulate the responses in a response event
                response_event = DendriteResponseEvent(results=responses, uids=self.assigned_miners)

                logger.debug(f"Received responses in {timer.elapsed_time:.2f} seconds")
                logger.debug(response_event)

                return response_event

        except Exception as ex:
            logger.exception(ex)
            return None

    async def forward(self):
        logger.info("🚀 Starting forward loop...")
        while not self.should_exit:
            event = await self.run_step(timeout=settings.NEURON_TIMEOUT)
            if event:
                logger.info(f"Processing event: {event}")
            await asyncio.sleep(5)  # Add delay between runs


# Define the aiohttp routes for validator endpoints
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

    if not assigned_miners:
        return web.json_response({"status": "failed", "error": "No miners provided"}, status=400)

    async with validator_instance._lock:
        validator_instance.assigned_miners = assigned_miners
        logger.info(f"Assigned miners updated: {assigned_miners}")

    return web.json_response({"status": "miners_assigned"})


# Add routes to the aiohttp app
app.router.add_post('/ready', ready)
app.router.add_post('/assign_miners', assign_miners)


# Main function to start both the validator and aiohttp server
async def main():
    validator_task = asyncio.create_task(validator_instance.forward())

    # Start the aiohttp server
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="0.0.0.0", port=8000)
    await site.start()

    logger.info("Validator aiohttp server started.")
    try:
        await validator_task
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())