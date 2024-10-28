# ruff: noqa: E402
import sys
sys.path.append("/home/azureuser/tensorprox/")

# This is an example miner that can respond to the inference task using a vllm model.
from tensorprox import settings

settings.settings = settings.Settings.load(mode="miner")
settings = settings.settings
import time
from loguru import logger
from tensorprox.base.miner import BaseMinerNeuron
from tensorprox.base.protocol import TensorProxSynapse
from tensorprox.utils.logging import ErrorLoggingEvent, log_event
from tensorprox.base.protocol import AvailabilitySynapse

NEURON_STOP_ON_FORWARD_EXCEPTION: bool = False

class Miner(BaseMinerNeuron):
    should_exit: bool = False

    def generate_prediction(self, challenges: list[dict]) -> str:
        """Predicts the label for the input JSON object (challenge) for DDoS detection."""
        
        return "0"

    def forward(self, synapse: TensorProxSynapse) -> TensorProxSynapse:
        """The forward function predicts class output for a set of features and forwards it to the validator."""


        logger.debug(f"Message received from {synapse.dendrite.hotkey}, IP: {synapse.dendrite.ip}.")

        try:
            # Generate prediction based on the first challenge
            prediction = self.generate_prediction(challenges=[synapse.challenges[0]])

            if prediction:
                synapse.prediction = prediction

            else:
                logger.info("Model returned label with None")

        except Exception as e:
            logger.exception(e)
            logger.error(f"Error in forward: {e}")
            log_event(ErrorLoggingEvent(error=str(e)))
            if NEURON_STOP_ON_FORWARD_EXCEPTION:
                self.should_exit = True


        logger.debug(f"Forwarding Synapse to validator {synapse.dendrite.hotkey}: {synapse}.")

        return synapse


    
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