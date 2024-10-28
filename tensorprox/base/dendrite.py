import numpy as np
from tensorprox.base.protocol import TensorProxSynapse
from pydantic import BaseModel, model_validator, ConfigDict


class DendriteResponseEvent(BaseModel):
    uids: np.ndarray | list[float]
    timeout: float
    results: list[TensorProxSynapse]
    response_times: list[float]
    status_messages: list[str] = []
    status_codes: list[int] = []
    results_uids: list[int] = []
    predictions: list[str] = []
    timings: list[float] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @model_validator(mode="after")
    def process_results(self) -> "DendriteResponseEvent":

        self.status_messages = []
        self.status_codes = []
        self.results_uids = []
        self.predictions = []
        self.timings = []

        for uid, synapse, timing in zip(self.uids, self.results, self.response_times):

            prediction = synapse.prediction
            self.status_messages.append(synapse.dendrite.status_message)
            status_code = synapse.dendrite.status_code

            if prediction == "" and status_code == 200:
                status_code = 204

            self.predictions.append(prediction)
            self.status_codes.append(status_code)
            self.results_uids.append(uid)
            self.timings.append(timing)

        return self