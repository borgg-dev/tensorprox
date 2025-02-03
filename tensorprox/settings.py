import sys
sys.path.append("/home/azureuser/tensorprox/")

import os
from functools import cached_property
from typing import Any, Literal, Optional
import bittensor as bt
import dotenv
from loguru import logger
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings

from tensorprox.utils.config import config


dotenv.load_dotenv()

class Settings(BaseSettings):
    mode: Literal["miner", "validator"]
    NO_BACKGROUND_THREAD: bool = True
    SAVE_PATH: Optional[str] = Field("./storage", env="SAVE_PATH")

    # W&B.
    WANDB_ON: bool = Field(True, env="WANDB_ON")
    WANDB_ENTITY: Optional[str] = Field("data-deepmind", env="WANDB_ENTITY")
    WANDB_PROJECT_NAME: Optional[str] = Field("TensorProx", env="WANDB_PROJECT_NAME")
    WANDB_RUN_STEP_LENGTH: int = Field(100, env="WANDB_RUN_STEP_LENGTH")
    WANDB_API_KEY: Optional[str] = Field(None, env="WANDB_API_KEY")
    WANDB_OFFLINE: bool = Field(False, env="WANDB_OFFLINE")
    WANDB_NOTES: str = Field("", env="WANDB_NOTES")
    MAX_WANDB_DURATION: int = 24

    # Neuron.
    NEURON_EPOCH_LENGTH: int = Field(100, env="NEURON_EPOCH_LENGTH")


    # Logging.
    LOGGING_DONT_SAVE_EVENTS: bool = Field(False, env="LOGGING_DONT_SAVE_EVENTS")
    LOG_WEIGHTS: bool = Field(True, env="LOG_WEIGHTS")

    # Neuron parameters.
    NEURON_TIMEOUT: int = Field(30, env="NEURON_TIMEOUT")
    NEURON_DISABLE_SET_WEIGHTS: bool = Field(False, env="NEURON_DISABLE_SET_WEIGHTS")
    NEURON_AXON_OFF: bool = Field(False, env="NEURON_AXON_OFF")
    NEURON_VPERMIT_TAO_LIMIT: int = Field(10, env="NEURON_VPERMIT_TAO_LIMIT")
    NEURON_QUERY_UNIQUE_COLDKEYS: bool = Field(False, env="NEURON_QUERY_UNIQUE_COLDKEYS")
    NEURON_QUERY_UNIQUE_IPS: bool = Field(False, env="NEURON_QUERY_UNIQUE_IPS")
    NEURON_FORWARD_MAX_TIME: int = Field(240, env="NEURON_FORWARD_MAX_TIME")


    TASK_QUEUE_LENGTH_THRESHOLD: int = Field(10, env="TASK_QUEUE_LENGTH_THRESHOLD")
    SCORING_QUEUE_LENGTH_THRESHOLD: int = Field(10, env="SCORING_QUEUE_LENGTH_THRESHOLD")

    # Additional Fields.
    NETUID: Optional[int] = Field(234, env="NETUID")
    WALLET_NAME: Optional[str] = Field(None, env="WALLET_NAME")
    VALIDATOR_HOTKEY: Optional[str] = Field(None, env="HOTKEY")
    VALIDATOR_AXON_PORT: Optional[int] = Field(None, env="AXON_PORT")
    MINER_HOTKEY: Optional[str] = Field(None, env="HOTKEY")
    MINER_AXON_PORT: Optional[int] = Field(None, env="AXON_PORT")
    SUBTENSOR_NETWORK: Optional[str] = Field(None, env="SUBTENSOR_NETWORK")

    # Class variables for singleton.
    _instance: Optional["Settings"] = None
    _instance_mode: Optional[str] = None

    @classmethod
    def load_env_file(cls, mode: Literal["miner", "validator"]):
        """Load the appropriate .env file based on the mode."""
        if mode == "miner":
            dotenv_file = ".env.miner"
        elif mode == "validator":
            dotenv_file = ".env.validator"
        else:
            raise ValueError(f"Invalid mode: {mode}")

        if dotenv_file:
            if not dotenv.load_dotenv(dotenv.find_dotenv(filename=dotenv_file)):
                logger.warning(
                    f"No {dotenv_file} file found. The use of args when running a {mode} will be deprecated "
                    "in the near future."
                )

    @classmethod
    def load(cls, mode: Literal["miner", "validator"]) -> "Settings":
        """Load or retrieve the Settings instance based on the mode."""
        if cls._instance is not None and cls._instance_mode == mode:
            return cls._instance
        else:
            cls.load_env_file(mode)
            cls._instance = cls(mode=mode)
            cls._instance_mode = mode
            return cls._instance

    @model_validator(mode="before")
    def complete_settings(cls, values: dict[str, Any]) -> dict[str, Any]:
        mode = values["mode"]
        netuid = values.get("NETUID", 234)
        if netuid is None:
            raise ValueError("NETUID must be specified")


        # Ensure SAVE_PATH exists.
        save_path = values.get("SAVE_PATH", "./storage")
        if not os.path.exists(save_path):
            os.makedirs(save_path)

        return values

    @cached_property
    def WALLET(self) -> bt.wallet:
        wallet_name = self.WALLET_NAME or config().wallet.name

        if self.VALIDATOR_HOTKEY :
            HOTKEY = self.VALIDATOR_HOTKEY
        elif self.MINER_HOTKEY :
            HOTKEY = self.MINER_HOTKEY
        hotkey = HOTKEY or config().wallet.hotkey
        logger.info(f"Instantiating wallet with name: {wallet_name}, hotkey: {hotkey}")
        return bt.wallet(name=wallet_name, hotkey=hotkey)

    @cached_property
    def SUBTENSOR(self) -> bt.subtensor:
        subtensor_network = self.SUBTENSOR_NETWORK or os.environ.get("SUBTENSOR_NETWORK", "local")
        # bt_config = config()
        if subtensor_network.lower() == "local":
            subtensor_network = os.environ.get("SUBTENSOR_CHAIN_ENDPOINT")  # bt_config.subtensor.chain_endpoint or
        else:
            subtensor_network = subtensor_network.lower()  # bt_config.subtensor.network or
        logger.info(f"Instantiating subtensor with network: {subtensor_network}")
        return bt.subtensor(network=subtensor_network)

    @cached_property
    def METAGRAPH(self) -> bt.metagraph:
        logger.info(f"Instantiating metagraph with NETUID: {self.NETUID}")
        return bt.metagraph(netuid=self.NETUID, network=self.SUBTENSOR_NETWORK, sync=True, lite=True)

    @cached_property
    def DENDRITE(self) -> bt.dendrite:
        logger.info(f"Instantiating dendrite with wallet: {self.WALLET}")
        return bt.dendrite(wallet=self.WALLET)


settings: Optional[Settings] = None