import numpy as np
from tensorprox.base.protocol import TensorProxSynapse
from pydantic import BaseModel, model_validator, ConfigDict


class DendriteResponseEvent(BaseModel):
    uids: np.ndarray | list[float]
    timeout: float
    results: list[TensorProxSynapse]
    response_times: list[float]
    ip_addresses: list[str]
    status_messages: list[str] = []
    status_codes: list[int] = []
    results_uids: list[int] = []
    predictions: list[str] = []
    timings: list[float] = []
    ips: list[str] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @model_validator(mode="after")
    def process_results(self) -> "DendriteResponseEvent":

        if len(self.predictions) > 0:
            return self

        for uid, synapse, timing, ip in zip(self.uids, self.results, self.response_times, self.ip_addresses):
            synapse : TensorProxSynapse
            prediction = synapse.prediction
            self.status_messages.append(synapse.dendrite.status_message)
            status_code = synapse.dendrite.status_code

            if prediction == "" and status_code == 200:
                status_code = 204

            self.predictions.append(prediction)
            self.status_codes.append(status_code)
            self.results_uids.append(uid)
            self.timings.append(timing)
            self.ips.append(ip)

        return self