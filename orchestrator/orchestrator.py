from aiohttp import web, ClientSession
import random
import asyncio

# List of validator IPs and ports (replace with actual IPs and ports)
validators = [
    {"ip": "http://20.244.85.168:8000", "id": "validator_1"},
    {"ip": "http://20.244.30.251:8001", "id": "validator_2"},
    # Add more validators as needed
]

miners = list(range(256))  # List of miner UIDs
active_validators = []  # List to keep track of active validators

# Create an aiohttp app for orchestrator to run
app = web.Application()

async def send_ready_request(validator_url, validator_id):
    """Send readiness request to a validator and handle the response."""
    async with ClientSession() as session:
        try:
            # Send readiness request
            payload = {"message": "Ready", "validator_id": validator_id}
            async with session.post(f"{validator_url}/ready", json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return True
                else:
                    return False
        except Exception as e:
            print(f"Error connecting to {validator_url}: {e}")
            return False

async def assign_miners_to_validators():
    """Periodically assign miners to active validators."""
    while True:
        print("Sending readiness check to validators...")

        # Clear the list of active validators at the start of each round
        active_validators.clear()

        # Check readiness of each validator
        for validator in validators:
            validator_url = validator["ip"]
            validator_id = validator["id"]
            
            # Send request and await response
            is_ready = await send_ready_request(validator_url, validator_id)
            
            if is_ready:
                # Add only those validators that are ready in the current round
                active_validators.append(validator_id)
        
        # Display the number of active validators at the start of the round
        num_active_validators = len(active_validators)
        print(f"Number of active validators: {num_active_validators}")

        # If no active validators found, wait and continue to next round
        if num_active_validators == 0:
            print("No active validators found.")
            await asyncio.sleep(10)
            continue
        
        # Shuffle the miners list for random assignment
        random.shuffle(miners)

        # Calculate the subset size
        subset_size = len(miners) // num_active_validators
        remaining_miners = len(miners) % num_active_validators
        
        # Assign miners to validators, including the remaining miners
        miner_idx = 0
        for i, validator_id in enumerate(active_validators):
            # For each validator, get the subset of miners
            num_miner_assigned = subset_size + (1 if i < remaining_miners else 0)
            assigned_miners = miners[miner_idx: miner_idx + num_miner_assigned]
            miner_idx += num_miner_assigned

            # Send assigned miners to the validator
            async with ClientSession() as session:
                miner_response_payload = {"assigned_miners": assigned_miners}
                async with session.post(f"{validators[i]['ip']}/assign_miners", json=miner_response_payload) as miner_response:
                    if miner_response.status == 200:
                        print(f"Miners assigned to {validator_id}: {assigned_miners}")
                    else:
                        print(f"Failed to assign miners to {validator_id}.")
        
        print("Waiting 10 seconds before next check...")
        await asyncio.sleep(10)  # Wait 10 seconds before the next readiness check
        
# Startup event for the app
async def on_startup(app):
    print("Starting orchestrator...")
    asyncio.create_task(assign_miners_to_validators())

app.on_startup.append(on_startup)

# Run the aiohttp app for orchestrator
if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=8000)
