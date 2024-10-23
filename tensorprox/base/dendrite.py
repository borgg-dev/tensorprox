import numpy as np
from tensorprox.base.protocol import StreamPromptingSynapse
from tensorprox.utils.misc import serialize_exception_to_string
from pydantic import BaseModel, model_validator, ConfigDict
from loguru import logger


class SynapseStreamResult(BaseModel):
    exception: BaseException | None = None
    uid: int | None = None
    synapse: StreamPromptingSynapse | None = None
    predictions: list[str] | None = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def prediction(self) -> str:
        if not self.synapse:
            logger.warning("Synapse is None")
            return
        return self.synapse.prediction

    def model_dump(self):

        return {
            "exception": self.exception,
            "uid": self.uid,
            "synapse": self.synapse.model_dump() if self.synapse is not None else None,
            "predictions": self.predictions
        }


class DendriteResponseEvent(BaseModel):
    uids: np.ndarray | list[float]
    timeout: float
    stream_results: list[SynapseStreamResult]
    predictions: list[str] = []
    status_messages: list[str] = []
    status_codes: list[int] = []
    stream_results_uids: list[int] = []
    stream_results_exceptions: list[str] = []
    stream_results_all_predictions: list[list[str]] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @model_validator(mode="after")
    def process_stream_results(self) -> "DendriteResponseEvent":
        # when passing this to a pydantic model, this method can be called multiple times, leading
        # to duplicating the arrays. If the arrays are already filled, we can skip this step
        if len(self.predictions) > 0:
            return self
        for stream_result in self.stream_results:
            # for some reason the language server needs this line to understand the type of stream_result
            stream_result: SynapseStreamResult

            synapse = stream_result.synapse

            self.predictions.append(synapse.prediction)
            self.status_messages.append(synapse.dendrite.status_message)
            status_code = synapse.dendrite.status_code

            if len(synapse.prediction) == 0 and status_code == 200:
                status_code = 204

            self.status_codes.append(status_code)
            self.stream_results_uids.append(stream_result.uid)
            self.stream_results_exceptions.append(serialize_exception_to_string(stream_result.exception))
            self.stream_results_all_predictions.append(stream_result.predictions)
        return self