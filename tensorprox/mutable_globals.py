import asyncio

# Define shared mutable globals
reward_events: list = []
scoring_queue: list = []
task_queue: list = []
feature_queue: asyncio.Queue = asyncio.Queue()  # Use asyncio.Queue for feature_queue
