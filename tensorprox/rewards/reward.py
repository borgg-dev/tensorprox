import numpy as np
import time
from typing import Any, Dict, ClassVar, Literal
from pydantic import BaseModel, ConfigDict
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.tasks.base_task import BaseTask

RewardTypeLiteral = Literal["reward", "penalty"]

class FScoreRewardEvent(BaseModel):
    task: BaseTask
    rewards: list[float]
    rewards_normalized: list[float]
    timings: list[float]
    uids: list[float]

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def asdict(self) -> dict:
        # Return a dictionary representation of the object
        return {
            "rewards": self.rewards,
            "rewards_normalized": self.rewards_normalized,
            "timings": self.timings,
            "uids": self.uids,
            "task": self.task,
        }

class BatchRewardOutput(BaseModel):
    rewards: np.ndarray
    timings: np.ndarray
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def rewards_normalized(self) -> np.ndarray:
        if self.rewards.shape != self.timings.shape:
            raise ValueError(f"rewards.shape {self.rewards.shape} != timings.shape {self.timings.shape}")
        if self.rewards.min() == self.rewards.max():
            return np.array([1 / len(self.rewards)] * len(self.rewards))
        return (self.rewards - self.rewards.min()) / (self.rewards.max() - self.rewards.min())


class FScoreRewardModel(BaseModel):

    alpha: float = 0.1  # Decay rate parameter for exponential decrease

    def reward(self, reference: str, response_event: DendriteResponseEvent) -> BatchRewardOutput:
        # Compute base scores (1 for match, 0 otherwise)
        scores = np.array([1 if prediction == reference else 0 for prediction in response_event.predictions])
        timings = np.array(response_event.timings)

        # Apply exponential decay based on timing, limiting the minimum to 0
        decayed_scores = np.maximum(0, scores * np.exp(-self.alpha * timings))
        
        # Return BatchRewardOutput with decayed scores
        return BatchRewardOutput(
            rewards=decayed_scores,
            timings=timings
        )

class BaseRewardConfig(BaseModel):

    reward_model: ClassVar[FScoreRewardModel] = FScoreRewardModel()

    @classmethod
    def apply(
        cls,
        response_event: DendriteResponseEvent,
        reference: str,
        task: BaseTask,
    ) -> FScoreRewardEvent:
        
        # Get the reward output
        batch_rewards_output = cls.reward_model.reward(reference, response_event)

        # Return the FScoreRewardEvent using the BatchRewardOutput
        return FScoreRewardEvent(
            task=task,
            rewards=batch_rewards_output.rewards.tolist(),
            rewards_normalized=batch_rewards_output.rewards_normalized.tolist(),
            timings=batch_rewards_output.timings.tolist(),
            uids=response_event.uids,
        )
