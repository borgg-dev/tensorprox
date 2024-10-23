import numpy as np
import time
from typing import Any, Dict, ClassVar, Literal
from pydantic import BaseModel, ConfigDict
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.tasks.base_task import BaseTask

RewardTypeLiteral = Literal["reward", "penalty"]

class FScoreRewardEvent(BaseModel):
    task: BaseTask
    reward_model_name: str
    rewards: list[float]
    rewards_normalized: list[float]
    timings: list[float]
    reward_model_type: RewardTypeLiteral
    batch_time: float
    uids: list[float]

    threshold: float | None = None
    extra_info: dict | None = None
    reward_type: Literal["reward", "penalty"] = "reward"
    penalty: float = 0.0  # Added to account for penalties

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def asdict(self) -> dict:
        # Return a dictionary representation of the object
        return {
            f"{self.reward_model_name}_raw_{self.reward_model_type}": self.rewards,
            f"{self.reward_model_name}_{self.reward_model_type}": self.rewards_normalized,
            f"{self.reward_model_name}_{self.reward_model_type}_timings": self.timings,
            f"{self.reward_model_name}_{self.reward_model_type}_batch_time": self.batch_time,
            f"{self.reward_model_name}_{self.reward_model_type}_threshold": self.threshold,
            f"{self.reward_model_name}_{self.reward_model_type}_extra_info": self.extra_info,
            f"{self.reward_model_name}_{self.reward_model_type}_uids": self.uids,
            f"{self.reward_model_name}_{self.reward_model_type}_penalty": self.penalty,
            f"{self.reward_model_name}_{self.reward_model_type}_task": self.task,
        }

class BatchRewardOutput(BaseModel):
    rewards: np.ndarray
    timings: np.ndarray
    threshold: float | None = None
    extra_info: dict = {}
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def rewards_normalized(self) -> np.ndarray:
        if self.rewards.shape != self.timings.shape:
            raise ValueError(f"rewards.shape {self.rewards.shape} != timings.shape {self.timings.shape}")
        if self.rewards.min() == self.rewards.max():
            return np.array([1 / len(self.rewards)] * len(self.rewards))
        return (self.rewards - self.rewards.min()) / (self.rewards.max() - self.rewards.min())


class FScoreRewardModel(BaseModel):

    def reward(self, reference: str, response_event: DendriteResponseEvent) -> BatchRewardOutput:
        # Dummy F-score calculation logic, should be replaced with actual logic
        predictions = response_event.predictions
        true_positives = sum(1 for pred in predictions if pred == reference)  # Simplified calculation
        total_predictions = len(predictions)
        precision = true_positives / total_predictions if total_predictions > 0 else 0
        recall = true_positives / 1  # Assume only one positive class for simplification
        f_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        # Timing for batch processing
        batch_time = time.time()

        # Return BatchRewardOutput (handling multiple predictions and timings)
        return BatchRewardOutput(
            rewards=np.array([f_score] * len(predictions)),  # Placeholder for rewards per prediction
            timings=np.array([batch_time] * len(predictions)),  # Placeholder for timing per prediction
        )


class BaseRewardConfig(BaseModel):

    reward_model: ClassVar[FScoreRewardModel] = FScoreRewardModel()

    @classmethod
    def apply(
        cls,
        response_event: DendriteResponseEvent,
        reference: str,
        challenge: Dict[str, Any],
        task: BaseTask,
        time_to_answer: float,
    ) -> FScoreRewardEvent:
        # Get the reward output
        batch_rewards_output = cls.reward_model.reward(reference, response_event)

        # Apply penalty based on time to answer (if needed)
        penalty = cls.calculate_penalty(time_to_answer)

        # Return the FScoreRewardEvent using the BatchRewardOutput
        return FScoreRewardEvent(
            task=task,
            reward_model_name=cls.reward_model.__class__.__name__,
            rewards=batch_rewards_output.rewards.tolist(),
            rewards_normalized=batch_rewards_output.rewards_normalized.tolist(),
            timings=batch_rewards_output.timings.tolist(),
            reward_model_type="reward",
            batch_time=batch_rewards_output.timings.mean(),
            uids=response_event.uids,
            penalty=penalty
        )

    @staticmethod
    def calculate_penalty(time_to_answer: float) -> float:
        # Penalty logic based on time to answer
        return min(time_to_answer, 1.0)  # Penalize answers taking longer than 1 second
