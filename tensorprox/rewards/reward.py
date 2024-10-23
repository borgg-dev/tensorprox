import numpy as np
import time
from typing import Any, Dict, ClassVar, Literal
from pydantic import BaseModel, ConfigDict
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.tasks.base_task import BaseTask


class FScoreRewardEvent(BaseModel):
    score: float
    penalty: float
    batch_time: float
    task : BaseTask = None
    extra_info: Dict[str, Any] = {}

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # implement custom asdict to return a dict with the same keys as the dataclass using the model name
    def asdict(self) -> dict:
        return {
            "score": self.score,
            "penalty": self.penalty,
            "batch_time": self.batch_time,
            "extra_info": self.extra_info,
        }
        

    

class FScoreRewardModel(BaseModel):

    def reward(self, reference: str, response_event: DendriteResponseEvent) -> FScoreRewardEvent:
        # Calculate the F-score (dummy implementation, replace with your logic)
        predictions = response_event.predictions
        true_positives = sum(1 for pred in predictions if pred == reference)  # Simplified calculation
        total_predictions = len(predictions)
        precision = true_positives / total_predictions if total_predictions > 0 else 0
        recall = true_positives / 1  # Assume only one positive class for simplification
        f_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        return FScoreRewardEvent(
            score=f_score,
            penalty=0,  # Penalty will be applied later
            batch_time=time.time(),
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
        reward_model = cls.reward_model
        if reward_model is None:
            raise ValueError("reward_model has not been set.")
        
        reward_event = cls.reward_model.reward(reference, response_event)
        
        # Apply penalty based on time to answer
        penalty = cls.calculate_penalty(time_to_answer)
        reward_event.penalty = penalty
        
        return reward_event

    @staticmethod
    def calculate_penalty(time_to_answer: float) -> float:
        # Define your penalty logic based on time to answer
        penalty = min(time_to_answer, 1)  # Example: penalize 1 for answers taking longer than 1 second
        return penalty
