import numpy as np
from tensorprox.base.protocol import TensorProxSynapse
from pydantic import BaseModel, model_validator, ConfigDict
from tensorprox import (labels,)

class DendriteResponseEvent(BaseModel):
    uids: np.ndarray | list[float]
    results: list[TensorProxSynapse]
    response_times: list[float]
    distances: list[float]
    status_messages: list[str] = []
    status_codes: list[int] = []
    predictions: list[str] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @model_validator(mode="after")
    def process_results(self) -> "DendriteResponseEvent":

        if len(self.predictions) > 0:
            return self

        for synapse in self.results:

            prediction = synapse.prediction
            self.status_messages.append(synapse.dendrite.status_message)
            status_code = synapse.dendrite.status_code

            if prediction not in labels and status_code == 200:
                status_code = 204

            self.predictions.append(prediction)
            self.status_codes.append(status_code)

        return self