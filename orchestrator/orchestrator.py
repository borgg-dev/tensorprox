from aiohttp import web, ClientSession
import random
import asyncio
import bittensor as bt


# Function to get the IPs of any neurons that have vpermit = True
def neurons_to_ips(netuid):
    subnet_neurons = subtensor.neurons_lite(netuid)
    uids = [neuron.uid for neuron in subnet_neurons]
    # Transform dictionaries into tuples
    ips = [{"host": "http://"+neuron.axon_info.ip+":8000", "hotkey": neuron.axon_info.hotkey} for neuron in subnet_neurons if neuron.validator_permit and neuron.total_stake > NEURON_VPERMIT_TAO_LIMIT]
    unique_ips = {tuple(ip.items()) for ip in ips}  # Use a set with tuples
    # Convert tuples back to dictionaries
    validators = [dict(ip) for ip in unique_ips]
    return validators, uids

subtensor = bt.subtensor(network="test")
netuid = 234
NEURON_VPERMIT_TAO_LIMIT = 10
validators, uids = neurons_to_ips(netuid=netuid)

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
        print(f"Error connecting to {validator_url}: {e}")
        return False

async def assign_miners_to_validators():
    """Periodically assign miners to active validators."""
    async with ClientSession() as session:  # Reuse session
        while True:
            print("Sending readiness check to validators...")

            # Clear the list of active validators at the start of each round
            active_validators.clear()

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

                # Send assigned miners to the validator
                miner_response_payload = {"assigned_miners": assigned_miners}
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
    print("Starting orchestrator...")
    asyncio.create_task(assign_miners_to_validators())

app.on_startup.append(on_startup)

# Run the aiohttp app for orchestrator
if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=8001)
