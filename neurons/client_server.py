"""
================================================================================

TensorProx Orchestrator Module

This module facilitates the dynamic assignment of miners to active validators
within the subnetwork. It continuously monitors validator readiness
and distributes miners accordingly to ensure balanced network participation.

Key Components:
- `send_ready_request`: Asynchronously checks if a validator is ready to accept
  miners by sending a POST request to its '/ready' endpoint.
- `create_random_playlist`: Generates a randomized playlist of activities
  totaling a specified duration, used for assigning tasks to validators.
- `neurons_to_ips`: Retrieves IP addresses of neurons (validators) that have
  active permits and meet the minimum stake requirement.
- `assign_miners_to_validators`: Core function that orchestrates the assignment
  of miners to active validators in a loop, ensuring continuous network
  operation.
- `on_startup`: Initializes the assignment process upon application startup.

Dependencies:
- `aiohttp`: For handling asynchronous HTTP requests.
- `asyncio`: To manage asynchronous operations and event loops.
- `bittensor`: Interacts with the Bittensor network to fetch neuron data.
- `random`: Generates random choices for playlist creation.
- `json`: Handles JSON serialization and deserialization.

License:
This software is licensed under the Creative Commons Attribution-NonCommercial
4.0 International (CC BY-NC 4.0). You are free to use, share, and adapt the code
for non-commercial purposes, provided appropriate credit is given.

Commercial Usage:
Authorized commercial use of this software is limited to mining or validating
within the specified subnet. For other commercial licensing inquiries, please
contact the author.

See the full license terms here: https://creativecommons.org/licenses/by-nc/4.0/

Author: Shugo LTD
Version: 0.1.0

================================================================================
"""

from aiohttp import web, ClientSession, ClientTimeout
import asyncio
import bittensor as bt
from loguru import logger

active_validators = []  # List of active validators
REQUEST_TIMEOUT = 3  # Set a timeout of 3 seconds per request
ROUND_TIME = 240
epsilon = 30
app = web.Application()

async def send_ready_request(session, validator_url, validator_hotkey):
    """
    Send a readiness request to a validator.

    This asynchronous function sends a POST request to the '/ready' endpoint of a validator
    to check its readiness status.

    Args:
        session (ClientSession): The aiohttp client session used to send the request.
        validator_url (str): The URL of the validator's endpoint.
        validator_hotkey (str): The hotkey identifier of the validator.

    Returns:
        bool: True if the validator responds with status 200, False otherwise.
    """

    try:
        payload = {"message": "Ready", "validator_hotkey": validator_hotkey}
        async with session.post(f"{validator_url}/ready", json=payload, timeout=REQUEST_TIMEOUT) as response:
            return response.status == 200
    except asyncio.TimeoutError:
        return False
    except Exception as e:
        return False


def neurons_to_ips(netuid, vpermit, network):
    """espilon
    Retrieve IPs of neurons with active validator permits.

    Fetches neurons from the specified subnet and filters those with active validator permits
    and total stake above the given threshold.

    Args:
        netuid (int): The network UID of the subnet.
        vpermit (float): The minimum stake required for a neuron to be considered as a validator.

    Returns:
        tuple: A tuple containing:
            - list: A list of dictionaries with 'host' and 'hotkey' of active validators.
            - list: A list of UIDs of all neurons in the subnet.
    """

    subnet_neurons = bt.subtensor(network=network).neurons_lite(netuid)
    ips = []
    for neuron in subnet_neurons :
        if neuron.validator_permit and int(neuron.total_stake) >= vpermit : 
            ips.append({"host": f"http://127.0.0.1:{neuron.axon_info.port+1}", "hotkey": neuron.axon_info.hotkey, "uid": neuron.uid})
    return list({tuple(ip.items()): dict(ip) for ip in ips}.values()), [neuron.uid for neuron in subnet_neurons]

async def fetch_active_validators():
    """
    Assign miners to active validators.

    Continuously checks for active validators and assigns miners to them based on availability.
    This function runs indefinitely, performing assignments in rounds with pauses in between.

    Globals:
        active_validators (list): Updated with the list of currently active validators.

    Notes:
        - Each round consists of:
            1. Checking validator readiness.
            2. Assigning miners to ready validators.
            3. Waiting for a specified duration before the next round.
    """

    global active_validators
    async with ClientSession(timeout=ClientTimeout(total=REQUEST_TIMEOUT)) as session:


        active_validators = []
        NETUID = 234
        NEURON_VPERMIT_TAO_LIMIT = 100*1e9
        NETWORK = "test"

        validators, uids = neurons_to_ips(NETUID, NEURON_VPERMIT_TAO_LIMIT, NETWORK)

        logger.debug(f"Checking availability of {len(validators)} validator(s)...")
        tasks = [send_ready_request(session, v["host"], v["hotkey"]) for v in validators]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        active_uids = [validator["uid"] for validator, is_ready in zip(validators, results) if is_ready]

        return active_uids
