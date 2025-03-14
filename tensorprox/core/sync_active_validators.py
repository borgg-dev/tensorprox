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

from aiohttp import ClientSession, ClientTimeout
import asyncio
import bittensor as bt
from loguru import logger
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings


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
              A response status of 200 indicates that the validator is ready.
    """

    try:
        payload = {"message": "Ready", "validator_hotkey": validator_hotkey}
        async with session.post(f"{validator_url}/ready", json=payload, timeout=3) as response:
            return response.status == 200
    except asyncio.TimeoutError:
        return False
    except Exception as e:
        return False


def neurons_to_ips(netuid, vpermit, network):
    """
    Retrieve IP addresses of neurons with active validator permits.

    This function fetches a list of neurons from a specified subnet, then filters and collects
    those neurons which have an active validator permit and have a total stake greater than or equal to
    the provided threshold (`vpermit`). It returns a list of dictionaries, each representing a valid validator.

    Args:
        netuid (int): The unique identifier for the network (subnet), used to query neurons in a specific subnet.
        vpermit (float): The minimum required total stake that a neuron must have to be considered for validation.
        network (str): The name or identifier of the network (e.g., a subnet) from which neurons are queried.

    Returns:
        list of dict:
            - A list of dictionaries where each dictionary represents a validator neuron and contains:
                - 'host' (str): The IP address and port of the neuron (constructed as 'http://127.0.0.1:<port>').
                - 'hotkey' (str): The hotkey of the neuron, used for validation.
                - 'uid' (int): The unique identifier (UID) of the neuron.
                
        In addition to this, it also returns a unique list of UIDs of all the neurons that meet the criteria.
    """

    subnet_neurons = bt.subtensor(network=network).neurons_lite(netuid)
    validators = []
    for neuron in subnet_neurons :
        if neuron.validator_permit and int(neuron.total_stake) >= vpermit : 
            validators.append({"host": f"http://{neuron.axon_info.ip}:{neuron.axon_info.port+neuron.uid}", "hotkey": neuron.axon_info.hotkey, "uid": neuron.uid})
    return list({tuple(v.items()): dict(v) for v in validators}.values())


async def fetch_active_validators():
    """
    Continuously checks for active validators and returns their unique identifiers (UIDs).

    This asynchronous function checks the status of a list of validator neurons by calling 
    the `send_ready_request` function for each validator. It checks each validator's readiness status
    and returns a list of UIDs of the active (ready) validators.

    Args:
        None: This function does not require any arguments directly, as it uses global settings (e.g., `settings.NETUID`).

    Returns:
        list[int]:
            - A list of UIDs (Unique Identifiers) of the validators that are ready (responded with status 200).
            - The list only contains the UIDs of the active validators.
    """

    async with ClientSession(timeout=ClientTimeout(total=3)) as session:

        validators = neurons_to_ips(settings.NETUID, settings.NEURON_VPERMIT_TAO_LIMIT, settings.SUBTENSOR_NETWORK)
        tasks = [send_ready_request(session, v["host"], v["hotkey"]) for v in validators]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        active_uids = [validator["uid"] for validator, is_ready in zip(validators, results) if is_ready]
        return active_uids
