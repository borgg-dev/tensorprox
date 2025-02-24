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
import random
import asyncio
import bittensor as bt
import json

active_validators = []  # List of active validators
REQUEST_TIMEOUT = 3  # Set a timeout of 3 seconds per request

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
        # print(f"⚠️ Timeout: Validator {validator_hotkey} did not respond in time.")
        return False
    except Exception as e:
        # print(f"❌ Error sending readiness request to {validator_hotkey}: {e}")
        return False

def create_random_playlist(total_minutes=15):
    """
    Create a random playlist totaling a specified duration.

    Generates a playlist consisting of random activities ('pause' or a class type)
    with durations summing up to the specified total minutes.

    Args:
        total_minutes (int): The total duration of the playlist in minutes. Defaults to 15.

    Returns:
        list: A list of dictionaries, each containing 'name' and 'duration' keys.
    """

    type_class_map = {'a': "ClassA", 'b': "ClassB", 'c': "ClassC", 'd': "ClassD"}
    playlist = []
    current_total = 0
    while current_total < total_minutes:
        name = "pause" if random.random() < 0.5 else random.choice(list(type_class_map.keys()))
        duration = min(random.randint(1, 3), total_minutes - current_total)
        playlist.append({"name": name, "duration": duration})
        current_total += duration
    return playlist

def neurons_to_ips(netuid, vpermit):
    """
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

    subnet_neurons = bt.subtensor(network="test").neurons_lite(netuid)
    ips = [{"host": "http://" + neuron.axon_info.ip + ":8000", "hotkey": neuron.axon_info.hotkey}
           for neuron in subnet_neurons if neuron.validator_permit and neuron.total_stake >= vpermit]
    return list({tuple(ip.items()): dict(ip) for ip in ips}.values()), [neuron.uid for neuron in subnet_neurons]

async def assign_miners_to_validators():
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

    global active_validators  # Ensure we're modifying the global variable

    async with ClientSession(timeout=ClientTimeout(total=REQUEST_TIMEOUT)) as session:
        first_iteration = True  # Track if it's the first round

        while True:

            active_validators = []  # Reset active validators

            # Define the network and vpermit (minimum stake) values
            NETUID = 234
            NEURON_VPERMIT_TAO_LIMIT = 10

            # Fetch the list of active validators and their IPs (this will trigger only once per round)
            validators, uids = neurons_to_ips(NETUID, NEURON_VPERMIT_TAO_LIMIT)

            print(f"Checking availability of {len(validators)} validator(s)...")
            tasks = [send_ready_request(session, v["host"], v["hotkey"]) for v in validators]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            active_validators = [
                {"hotkey": validator["hotkey"], "url": validator["host"]}
                for validator, is_ready in zip(validators, results) if is_ready
            ]


            if not active_validators:     
                print("⏳ No active validators. Retrying in 10s...")
                await asyncio.sleep(10)
                continue  # Skip waiting and immediately check again
            else :
                print(f"✅ Active validators: {len(active_validators)}")  # Green check if active validators are present

            print("🏁▶️ Starting a new round...")
            
            # Ensure miners are distributed fairly (do this only once per round)
            random.shuffle(uids)
            num_validators = len(active_validators)
            num_miners = len(uids)

            base_share = num_miners // num_validators
            extra = num_miners % num_validators  # Distribute extra miners

            miner_idx = 0
            for i, validator in enumerate(active_validators):
                num_miner_assigned = base_share + (1 if i < extra else 0)
                assigned_miners = uids[miner_idx: miner_idx + num_miner_assigned]
                miner_idx += num_miner_assigned

                print(f"Assigning {len(assigned_miners)} miners to {validator['hotkey']}: {assigned_miners}")

                playlist = create_random_playlist(total_minutes=15)
                payload = {"assigned_miners": assigned_miners, "playlist": playlist}

                try:
                    async with session.post(f"{validator['url']}/assign_miners", json=payload, timeout=REQUEST_TIMEOUT) as miner_response:
                        if miner_response.status == 200:
                            print(f"✅ Miners assigned to {validator['hotkey']}")
                        else:
                            print(f"❌ Failed to assign miners to {validator['hotkey']}.")
                except asyncio.TimeoutError:
                    print(f"⚠️ Timeout: Validator {validator['hotkey']} did not respond.")
                except Exception as e:
                    print(f"❌ Error assigning miners to {validator['hotkey']}: {e}")

            # Wait for 240 seconds **only after miners have been assigned**
            print("⏳ Waiting 240 seconds before next round...")
            await asyncio.sleep(240)

async def on_startup(app):
    asyncio.create_task(assign_miners_to_validators())

app.on_startup.append(on_startup)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=8001)
