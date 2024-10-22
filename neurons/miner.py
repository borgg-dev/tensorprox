# ruff: noqa: E402

# This is an example miner that can respond to the inference task using a vllm model.
from tensorprox import settings

settings.settings = settings.Settings.load(mode="miner")
settings = settings.settings
import time
from functools import partial
from loguru import logger
from tensorprox.base.miner import BaseStreamMinerNeuron
from tensorprox.base.protocol import StreamPromptingSynapse
from starlette.types import Send
from tensorprox.utils.logging import ErrorLoggingEvent, log_event
from tensorprox.base.protocol import AvailabilitySynapse

NEURON_STOP_ON_FORWARD_EXCEPTION: bool = False

class Miner(BaseStreamMinerNeuron):
    should_exit: bool = False

    def predict_model(self, challenges: list[dict]) -> dict:
        """Predicts the label for the input JSON object (challenge) for DDoS detection."""
        
        return {"output": 0}
            
        
    def forward(self, synapse: StreamPromptingSynapse) -> StreamPromptingSynapse:
        """The forward function generates text based on a prompt, model, and seed."""

        async def _forward(
            self: "Miner",
            synapse: StreamPromptingSynapse,
            init_time: float,
            timeout_threshold: float,
            send: Send,
        ):
            timeout_reached = False

            try:

                stream_response = self.predict_model(challenges=[synapse.challenges[0]])

                label_output = stream_response.output

                if not label_output:
                    logger.info("model returned label with None")


                if time.time() - init_time > timeout_threshold:
                    logger.debug("⏰ Timeout reached, stopping streaming")
                    timeout_reached = True

                if stream_response and not timeout_reached:  # Don't send the last buffer of data if timeout.
                    await send(
                        {
                            "type": "http.response.body",
                            "body": stream_response,
                            "more_body": False,
                        }
                    )

            except Exception as e:
                logger.exception(e)
                logger.error(f"Error in forward: {e}")
                log_event(ErrorLoggingEvent(error=str(e)))
                if NEURON_STOP_ON_FORWARD_EXCEPTION:
                    self.should_exit = True

            finally:
                synapse_latency = time.time() - init_time
                self.log_event(
                    synapse=synapse,
                    timing=synapse_latency,
                    challenges=synapse.challenges,
                    stream_response = stream_response
                )

        logger.debug(
            f"📧 Message received from {synapse.dendrite.hotkey}, IP: {synapse.dendrite.ip}; \nForwarding synapse: {synapse}"
        )
        init_time = time.time()
        timeout_threshold = synapse.timeout

        token_streamer = partial(
            _forward,
            self,
            synapse,
            init_time,
            timeout_threshold,
        )
        return synapse.create_streaming_response(token_streamer)

    def check_availability(self, synapse: AvailabilitySynapse) -> AvailabilitySynapse:
        """The check_availability function returns an AvailabilitySynapse which indicates
        which tasks and models this miner can handle."""

        logger.info(f"Checking availability of miner... {synapse}")
        synapse.task_availabilities = {
            task: True
            for task, _ in synapse.task_availabilities.items()
            if task == "BaseTask"
        }
        return synapse


if __name__ == "__main__":
    with Miner() as miner:
        while not miner.should_exit:
            miner.log_status()
            time.sleep(5)
        logger.warning("Ending miner...")
