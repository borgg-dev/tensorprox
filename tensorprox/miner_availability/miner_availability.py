import asyncio
import random
from typing import Dict, List
from loguru import logger
from pydantic import BaseModel

from tensorprox.base.protocol import PingSynapse
from tensorprox.base.loop_runner import AsyncLoopRunner
from tensorprox.settings import settings
from tensorprox.utils.uids import get_uids, extract_axons_ips
from tensorprox.utils.timer import Timer
from tensorprox.base.protocol import MachineConfig


class MinerAvailabilities(BaseModel):
    """Tracks all miners' availability using PingSynapse."""
    miners: Dict[int, PingSynapse] = {}

    def check_machine_availability(self, machine_name: str = None, uid: int = None) -> bool:
        ip_machine = self.miners[uid].machine_availabilities[machine_name]
        if ip_machine :
            return True
        return False
    
    def is_miner_ready(self, uid: int = None) -> bool:
        """
        Check if a miner is ready by verifying all machines are available.

        Args:
            uid (int): The UID of the miner to check.

        Returns:
            bool: True if all machines are available for the miner, False otherwise.
        """
        for machine_name in self.miners[uid].machine_availabilities.keys():
            if not self.check_machine_availability(machine_name=machine_name, uid=uid):
                return False
        return True

    
def get_available_miners(self, k: int = None) -> List[int]:
    """
    Get a list of miners where all machines are available.

    Args:
        k (int, optional): The number of miners to return. Defaults to None.

    Returns:
        List[int]: A list of miner UIDs with all machines marked as available (True).
    """
    available = [uid for uid in self.miners.keys() if self.is_miner_ready(uid)]

    if k:
        available = random.sample(available, min(len(available), k))

    return available

async def query_availabilities(uids: List[int]) -> List[PingSynapse]:
    """
    Simulates querying miners for their availability.

    Args:
        uids (List[int]): A list of miner UIDs to query.
        machine_config (List[str]): The list of machine names to check availability for.

    Returns:
        List[PingSynapse]: Ping responses for each queried UID.
    """
    
    logger.debug(f"🔍 Querying uids machine's availabilities: {uids}")
    if len(uids) == 0:
        logger.debug("No available miners. Skipping step.")
        return

    axons = [settings.METAGRAPH.axons[uid] for uid in uids]

    responses = []
    
    # Querying miners to see if they are ready
    try:
        responses = await settings.DENDRITE(
            axons=axons,
            synapse=PingSynapse(ssh_public_key="", machine_availabilities=MachineConfig()),
            timeout=settings.NEURON_TIMEOUT,
            deserialize=False,
        )

        return responses

    except Exception as e:
        logger.error(f"Error in availability call: {e}")
        return []
    

# class CheckMinerAvailability(AsyncLoopRunner):
#     """Checks miner availability every 5 minutes."""
#     interval: int = 300  # 5 minutes
#     uids: List[int] = settings.TEST_MINER_IDS or get_uids(sampling_mode="all")
#     current_index: int = 0
#     uids_per_step: int = 10

#     async def run_step(self):
#         """Query miner availability."""
#         start_index = self.current_index
#         end_index = min(start_index + self.uids_per_step, len(self.uids))
#         uids_to_query = self.uids[start_index:end_index]
#         if self.step == 0:
#             uids_to_query = self.uids

#         logger.info(f"Querying availability for UIDs: {uids_to_query}")

#         responses: List[PingSynapse] = await query_availabilities(
#             uids=uids_to_query, 
#             machine_config=machine_config,
#         )

#         for response, uid in zip(responses, uids_to_query):
#             miner_availabilities.miners[uid] = response

#         logger.debug("Updated miner availabilities.")
#         self.current_index = end_index if end_index < len(self.uids) else 0
#         await asyncio.sleep(0.1)


# Start availability checking
miner_availabilities = MinerAvailabilities()
# availability_checking_loop = CheckMinerAvailability()
