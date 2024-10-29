import numpy as np
import time
from typing import Any, Dict, ClassVar, Literal
from pydantic import BaseModel, ConfigDict
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.tasks.base_task import DDoSDetectionTask

RewardTypeLiteral = Literal["reward", "penalty"]

class DDoSDetectionRewardEvent(BaseModel):
    task: DDoSDetectionTask
    rewards: list[float]
    timings: list[float]
    uids: list[int]

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def asdict(self) -> dict:
        # Return a dictionary representation of the object
        return {
            "rewards": self.rewards,
            "timings": self.timings,
            "uids": self.uids,
            "task": self.task,
        }

class BatchRewardOutput(BaseModel):
    rewards: np.ndarray
    timings: np.ndarray
    model_config = ConfigDict(arbitrary_types_allowed=True)


class DDoSDetectionRewardModel(BaseModel):

    alpha: float = 5.0  # Decay rate parameter for exponential decrease

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

    reward_model: ClassVar[DDoSDetectionRewardModel] = DDoSDetectionRewardModel()

    @classmethod
    def apply(
        cls,
        response_event: DendriteResponseEvent,
        reference: str,
        task: DDoSDetectionTask,
    ) -> DDoSDetectionRewardEvent:
        
        # Get the reward output
        batch_rewards_output = cls.reward_model.reward(reference, response_event)

        # Return the DDoSDetectionRewardEvent using the BatchRewardOutput
        return DDoSDetectionRewardEvent(
            task=task,
            rewards=batch_rewards_output.rewards.tolist(),
            timings=batch_rewards_output.timings.tolist(),
            uids=response_event.uids,
        )
