"""
Reward and scoring module for TensorProx subnet.

Implements the 4-factor incentive mechanism:
- Accuracy: Benign delivery rate + Attack mitigation accuracy
- Efficiency: Selective processing + Relative throughput
- Throughput: Volume processing capacity
- Latency: Response time performance
"""

from tensorprox.rewards.reward import (
    ProductionRewardModel,
    RewardEvent,
    compute_rewards,
)
from tensorprox.rewards.scoring import TaskScorer, ScoringConfig
from tensorprox.rewards.weight_setter import WeightSetter

# Aliases for backwards compatibility
ChallengeRewardModel = ProductionRewardModel
ChallengeRewardEvent = RewardEvent

__all__ = [
    "ProductionRewardModel",
    "ChallengeRewardModel",
    "RewardEvent",
    "ChallengeRewardEvent",
    "compute_rewards",
    "TaskScorer",
    "ScoringConfig",
    "WeightSetter",
]
