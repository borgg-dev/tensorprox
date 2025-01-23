from aiohttp import web, ClientSession
import random
import asyncio
import bittensor as bt

# NEW: Additional imports for JSON, hashing, logging, etc.
import json
import hashlib
import time


active_validators = []  # List to keep track of active validators

# Create an aiohttp app for orchestrator to run
app = web.Application()

async def send_ready_request(session, validator_url, validator_hotkey):
    """Send readiness request to a validator and handle the response."""
    try:
        payload = {"message": "Ready", "validator_hotkey": validator_hotkey}
        async with session.post(f"{validator_url}/ready", json=payload) as response:
            if response.status == 200:
                return True
            else:
                return False
    except Exception as e:
        # print(f"Error connecting to {validator_url}: {e}")
        return False

# -----------------------------------------------------------------------------------
# NEW: Sample type_class_map from traffic_generator.py
# In practice, this should be read or imported from the actual 'traffic_generator.py'.
# -----------------------------------------------------------------------------------
type_class_map = {
    'a': "ClassA",
    'b': "ClassB",
    'c': "ClassC",
    'd': "ClassD",
    # ...
    # Potentially many more
}

# -----------------------------------------------------------------------------------
# NEW: Function to create a random playlist of 15 minutes
# -----------------------------------------------------------------------------------
def create_random_playlist(total_minutes=15):
    """
    Creates a random playlist, each item has:
      - 'name'     -> The class key or "pause"
      - 'duration' -> random number of minutes (>= 1)
    The function ensures the total sum of durations is ~15 minutes.
    """
    playlist = []
    current_total = 0
    while current_total < total_minutes:
        # 50% chance to pick an actual class, 50% chance to pick a pause
        is_pause = (random.random() < 0.5)

        if is_pause:
            name = "pause"
        else:
            name = random.choice(list(type_class_map.keys()))

        # We choose at least 1 minute, but you could do up to 3 to vary
        duration = random.randint(1, 3)
        if current_total + duration > total_minutes:
            duration = total_minutes - current_total

        playlist.append({"name": name, "duration": duration})
        current_total += duration

    return playlist


async def assign_miners_to_validators():
    """Periodically assign miners to active validators."""

    # Function to get the IPs of any neurons that have vpermit = True
    def neurons_to_ips(netuid, vpermit):
        subnet_neurons = subtensor.neurons_lite(netuid)
        uids = [neuron.uid for neuron in subnet_neurons]

        # Transform dictionaries into tuples
        ips = [{"host": "http://"+neuron.axon_info.ip+":8000", "hotkey": neuron.axon_info.hotkey} for neuron in subnet_neurons if neuron.validator_permit and neuron.total_stake > vpermit]
        unique_ips = {tuple(ip.items()) for ip in ips}  # Use a set with tuples
        # Convert tuples back to dictionaries
        validators = [dict(ip) for ip in unique_ips]
        return validators, uids

    async with ClientSession() as session:  # Reuse session
        while True:
            print("🏁▶️  Starting new Round...")

            # Clear the list of active validators at the start of each round
            active_validators.clear()

            subtensor = bt.subtensor(network="test")
            NETUID = 234
            NEURON_VPERMIT_TAO_LIMIT = 0
            validators, uids = neurons_to_ips(netuid=NETUID, vpermit=NEURON_VPERMIT_TAO_LIMIT)

            print(f"Sending readiness check to {len(validators)} validator(s)...")
            # Perform readiness checks in parallel
            tasks = [
                send_ready_request(session, validator["host"], validator["hotkey"])
                for validator in validators
            ]
            results = await asyncio.gather(*tasks)

            # Update active validators based on the results
            for validator, is_ready in zip(validators, results):
                if is_ready:
                    active_validators.append({"hotkey": validator["hotkey"], "url": validator["host"]})

            # Display the number of active validators at the start of the round
            num_active_validators = len(active_validators)
            print(f"Number of active validators: {num_active_validators}")

            # If no active validators found, wait and continue to the next round
            if num_active_validators == 0:
                print("No active validators found.")
                await asyncio.sleep(10)
                continue

            # Shuffle the miners list for random assignment
            random.shuffle(uids)

            # Calculate the subset size
            subset_size = len(uids) // num_active_validators
            remaining_miners = len(uids) % num_active_validators

            # Assign miners to validators, including the remaining miners
            miner_idx = 0
            for i, validator in enumerate(active_validators):
                validator_hotkey = validator["hotkey"]
                validator_url = validator["url"]

                # For each validator, get the subset of miners
                num_miner_assigned = subset_size + (1 if i < remaining_miners else 0)
                assigned_miners = uids[miner_idx: miner_idx + num_miner_assigned]
                miner_idx += num_miner_assigned

                # NEW: Generate and distribute the random playlist in cleartext
                playlist = create_random_playlist(total_minutes=15)

                print(f"Random playlist generated for this round : {playlist}")

                # Send assigned miners to the validator
                miner_response_payload = {"assigned_miners": assigned_miners, "playlist": playlist}

                try:
                    async with session.post(f"{validator_url}/assign_miners", json=miner_response_payload) as miner_response:
                        if miner_response.status == 200:
                            print(f"Miners assigned to {validator_hotkey}: {assigned_miners}")
                        else:
                            print(f"Failed to assign miners to {validator_hotkey}.")
                except Exception as e:
                    print(f"Error assigning miners to {validator_hotkey}: {e}")

            print("Waiting 10 seconds before next check...")
            await asyncio.sleep(10)  # Wait 10 seconds before the next readiness check

# Startup event for the app
async def on_startup(app):
    asyncio.create_task(assign_miners_to_validators())


app.on_startup.append(on_startup)

# Run the aiohttp app for orchestrator
if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=8001)
