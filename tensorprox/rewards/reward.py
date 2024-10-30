import numpy as np
from typing import ClassVar
from pydantic import BaseModel, ConfigDict
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.tasks.base_task import DDoSDetectionTask

class DDoSDetectionRewardEvent(BaseModel):
    task: DDoSDetectionTask
    rewards: list[float]
    timings: list[float]
    adjusted_timings: list[float]
    uids: list[int]

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def asdict(self) -> dict:
        return {
            "rewards": self.rewards,
            "timings": self.timings,
            "uids": self.uids,
            "task": self.task,
        }

class BatchRewardOutput(BaseModel):
    rewards: np.ndarray
    timings: np.ndarray
    adjusted_timings: np.ndarray
    model_config = ConfigDict(arbitrary_types_allowed=True)


class DDoSDetectionRewardModel(BaseModel):

    alpha: float = 5.0  # Decay rate parameter for exponential decrease
    transmission_speed: float = 200000 #5ms latency per 1000km

    def reward(self, reference: str, response_event: DendriteResponseEvent) -> BatchRewardOutput:

        # Compute base scores (1 for match, 0 otherwise)
        scores = np.array([1 if prediction == reference else 0 for prediction in response_event.predictions])
        timings = np.array(response_event.response_times)
        distances = np.array(response_event.distances)

        #Adjust timing based on the distance to validator machine
        adjusted_timings = np.array([t - d/self.transmission_speed for t, d in zip(timings, distances)])


        # Apply exponential decay based on combined decay factors, limiting the minimum to 0
        decayed_scores = np.maximum(0, scores * np.exp(-self.alpha * adjusted_timings))


        # Return BatchRewardOutput with decayed scores
        return BatchRewardOutput(
            rewards=decayed_scores,
            timings=timings,
            adjusted_timings=adjusted_timings
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
            adjusted_timings=batch_rewards_output.adjusted_timings.tolist(),
            uids=response_event.uids,
        )
