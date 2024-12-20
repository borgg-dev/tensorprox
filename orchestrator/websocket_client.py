from aiohttp import web
import random

# Initialize list of miners (replace with actual miners if needed)
miners = list(range(256))  # Converting range to a list for easier manipulation

# Create an aiohttp app for validator
app = web.Application()

active = False  # Validator's readiness status

async def ready(request):
    """Receive readiness request from the orchestrator."""
    global active
    data = await request.json()
    message = data.get("message", "").lower()

    if message == "ready":
        active = True
        # Send a simple acknowledgment that the validator is ready
        return web.json_response({"status": "ready"})

    else:
        return web.json_response({"status": "failed"}, status=400)

async def assign_miners(request):
    """Receive assigned miners from the orchestrator."""
    data = await request.json()
    assigned_miners = data.get("assigned_miners", [])
    print(f"Assigned miners: {assigned_miners}")
    return web.json_response({"status": "miners_assigned"})

# Define the routes for the validator
app.router.add_post('/ready', ready)
app.router.add_post('/assign_miners', assign_miners)

# Run the aiohttp app for the validator
if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=8000)  # Change port for each validator
