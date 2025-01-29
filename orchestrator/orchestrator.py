from aiohttp import web, ClientSession
import random
import asyncio
import bittensor as bt
import json
import hashlib
import time

active_validators = []  # List of active validators

# Create the aiohttp application
app = web.Application()

async def send_ready_request(session, validator_url, validator_hotkey):
    """Sends a readiness request to a validator and handles the response."""
    try:
        payload = {"message": "Ready", "validator_hotkey": validator_hotkey}
        async with session.post(f"{validator_url}/ready", json=payload) as response:
            if response.status == 200:
                return True
            else:
                print(f"Validator {validator_hotkey} responded with status {response.status}")
                return False
    except Exception as e:
        print(f"Error sending readiness request to {validator_hotkey}: {e}")
        return False

# Mapping of classes for simulated traffic
type_class_map = {
    'a': "ClassA",
    'b': "ClassB",
    'c': "ClassC",
    'd': "ClassD",
}

def create_random_playlist(total_minutes=15):
    """
    Creates a random 15-minute playlist with pauses and traffic types.
    """
    playlist = []
    current_total = 0
    while current_total < total_minutes:
        name = "pause" if random.random() < 0.5 else random.choice(list(type_class_map.keys()))
        duration = min(random.randint(1, 3), total_minutes - current_total)
        playlist.append({"name": name, "duration": duration})
        current_total += duration

    return playlist

async def assign_miners_to_validators():
    """Assigns miners to active validators periodically."""

    def neurons_to_ips(netuid, vpermit):
        """Retrieves IPs of neurons with an active vpermit."""
        subnet_neurons = bt.subtensor(network="test").neurons_lite(netuid)
        ips = [{"host": "http://" + neuron.axon_info.ip + ":8000", "hotkey": neuron.axon_info.hotkey}
               for neuron in subnet_neurons if neuron.validator_permit and neuron.total_stake > vpermit]
        return list({tuple(ip.items()): dict(ip) for ip in ips}.values()), [neuron.uid for neuron in subnet_neurons]

    async with ClientSession() as session:
        first_iteration = True  # Ensures the first iteration runs immediately

        while True:
            print("🏁▶️  Starting a new round...")

            active_validators.clear()
            NETUID = 234
            NEURON_VPERMIT_TAO_LIMIT = 10
            validators, uids = neurons_to_ips(NETUID, NEURON_VPERMIT_TAO_LIMIT)

            print(f"Checking availability of {len(validators)} validator(s)...")
            results = await asyncio.gather(*[send_ready_request(session, v["host"], v["hotkey"]) for v in validators])

            for validator, is_ready in zip(validators, results):
                if is_ready:
                    active_validators.append({"hotkey": validator["hotkey"], "url": validator["host"]})

            print(f"Number of active validators: {len(active_validators)}")

            if not active_validators:
                print("No active validators found.")
                await asyncio.sleep(10)
                continue

            random.shuffle(uids)
            subset_size, remaining_miners = divmod(len(uids), len(active_validators))

            miner_idx = 0
            for i, validator in enumerate(active_validators):
                num_miner_assigned = subset_size + (1 if i < remaining_miners else 0)
                assigned_miners = uids[miner_idx: miner_idx + num_miner_assigned]
                miner_idx += num_miner_assigned

                playlist = create_random_playlist(total_minutes=15)
                print(f"Generated random playlist: {playlist}")

                payload = {"assigned_miners": assigned_miners, "playlist": playlist}

                try:
                    async with session.post(f"{validator['url']}/assign_miners", json=payload) as miner_response:
                        if miner_response.status == 200:
                            print(f"Miners assigned to {validator['hotkey']}: {assigned_miners}")
                        else:
                            print(f"Failed to assign miners to {validator['hotkey']}.")
                except Exception as e:
                    print(f"Error assigning miners to {validator['hotkey']}: {e}")

            wait_time = 240 if not first_iteration else 0  # 240 seconds for subsequent rounds
            first_iteration = False
            print(f"Waiting {wait_time} seconds before the next round...")
            await asyncio.sleep(wait_time)

async def on_startup(app):
    asyncio.create_task(assign_miners_to_validators())

app.on_startup.append(on_startup)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=8001)
