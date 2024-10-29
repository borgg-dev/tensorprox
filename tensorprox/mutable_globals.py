import asyncio
from tensorprox.rewards.reward import DDoSDetectionRewardEvent

# Define shared mutable globals
reward_events: list[DDoSDetectionRewardEvent] = []
scoring_queue: list = []
task_queue: list = []
feature_queue: asyncio.Queue = asyncio.Queue()  # Use asyncio.Queue for feature_queue
