import json
import numpy as np
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Literal, Any, Dict

import wandb
from loguru import logger
from pydantic import BaseModel, ConfigDict
from wandb.wandb_run import Run

import tensorprox
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.settings import settings

WANDB: Run


@dataclass
class Log:
    validator_model_id: str
    challenge: str
    challenge_prompt: str
    reference: str
    miners_ids: list[str]
    responses: list[str]
    miners_time: list[float]
    challenge_time: float
    reference_time: float
    rewards: list[float]
    task: dict


def export_logs(logs: list[Log]):
    logger.info("📝 Exporting logs...")

    # Create logs folder if it doesn't exist
    if not os.path.exists("logs"):
        os.makedirs("logs")

    # Get the current date and time for logging purposes
    date_string = datetime.now().strftime("%Y-%m-%d_%H:%M")

    all_logs_dict = [asdict(log) for log in logs]

    for logs in all_logs_dict:
        task_dict = logs.pop("task")
        prefixed_task_dict = {f"task_{k}": v for k, v in task_dict.items()}
        logs.update(prefixed_task_dict)

    log_file = f"./logs/{date_string}_output.json"
    with open(log_file, "w") as file:
        json.dump(all_logs_dict, file)

    return log_file


def should_reinit_wandb():
    """Checks if 24 hours have passed since the last wandb initialization."""
    # Get the start time from the wandb config
    wandb_start_time = wandb.run.config.get("wandb_start_time", None)

    if wandb_start_time:
        # Convert the stored time (string) back to a datetime object
        wandb_start_time = datetime.strptime(wandb_start_time, "%Y-%m-%d %H:%M:%S")
        current_time = datetime.now()
        elapsed_time = current_time - wandb_start_time
        # Check if more than 24 hours have passed
        if elapsed_time > timedelta(hours = settings.MAX_WANDB_DURATION):
            return True
    return False


def init_wandb(reinit=False, neuron: Literal["validator", "miner"] = "validator", custom_tags: list = []):
    """Starts a new wandb run."""
    global WANDB
    tags = [
        f"Wallet: {settings.WALLET.hotkey.ss58_address}",
        f"Version: {tensorprox.__version__}",
        f"Netuid: {settings.NETUID}",
    ]


    if settings.NEURON_DISABLE_SET_WEIGHTS:
        tags.append("disable_set_weights")
        tags += [
            f"Neuron UID: {settings.METAGRAPH.hotkeys.index(settings.WALLET.hotkey.ss58_address)}",
            f"Time: {datetime.now().strftime('%Y_%m_%d_%H_%M_%S')}",
        ]

    tags += custom_tags

    wandb_config = {
        "HOTKEY_SS58": settings.WALLET.hotkey.ss58_address,
        "NETUID": settings.NETUID,
        "wandb_start_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    

    wandb.login(anonymous="allow", key=settings.WANDB_API_KEY, verify=True)
    logger.info(f"Logging in to wandb on entity: {settings.WANDB_ENTITY} and project: {settings.WANDB_PROJECT_NAME}")
    WANDB = wandb.init(
        reinit=reinit,
        project=settings.WANDB_PROJECT_NAME,
        entity=settings.WANDB_ENTITY,
        mode="offline" if settings.WANDB_OFFLINE else "online",
        dir=settings.SAVE_PATH,
        tags=tags,
        notes=settings.WANDB_NOTES,
        config=wandb_config,
    )
    signature = settings.WALLET.hotkey.sign(WANDB.id.encode()).hex()
    wandb_config["SIGNATURE"] = signature
    WANDB.config.update(wandb_config, allow_val_change=True)
    logger.success(f"Started a new wandb run <blue> {WANDB.name} </blue>")


def reinit_wandb():
    """Reinitializes wandb, rolling over the run."""
    global WANDB
    WANDB.finish()
    init_wandb(reinit=True)


class BaseEvent(BaseModel):
    forward_time: float | None = None

class WeightSetEvent(BaseEvent):
    weight_set_event: list[float]

class ErrorLoggingEvent(BaseEvent):
    error: str
    forward_time: float | None = None


class RewardLoggingEvent(BaseEvent):
    block: int
    step: int
    uids: list[int]
    rewards: list[float]
    response_event: DendriteResponseEvent

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __str__(self):
        rewards = self.rewards
        uids = self.uids
        
        return f"""RewardLoggingEvent:
            Rewards:
                Uids: {uids}
                Rewards: {rewards}
                Min: {np.min(rewards) if len(rewards) > 0 else None}
                Max: {np.max(rewards) if len(rewards) > 0 else None}
                Average: {np.mean(rewards) if len(rewards) > 0 else None}
        """


class MinerLoggingEvent(BaseEvent):
    epoch_time: float
    challenges: int
    prediction: int
    validator_uid: int
    validator_ip: str
    validator_coldkey: str
    validator_hotkey: str
    validator_stake: float
    validator_trust: float
    validator_incentive: float
    validator_consensus: float
    validator_dividends: float
    model_config = ConfigDict(arbitrary_types_allowed=True)


def log_event(event: BaseEvent):
    if not settings.LOGGING_DONT_SAVE_EVENTS:
        logger.info(f"{event}")

    if settings.WANDB_ON:
        if should_reinit_wandb():
            reinit_wandb()
        unpacked_event = unpack_events(event)
        unpacked_event = convert_arrays_to_lists(unpacked_event)
        wandb.log(unpacked_event)


def unpack_events(event: BaseEvent) -> dict[str, Any]:
    """reward_events and penalty_events are unpacked into a list of dictionaries."""
    event_dict = event.model_dump()
    for key in list(event_dict.keys()):
        if key == "response_event":
            nested_dict = event_dict.pop(key)
            if isinstance(nested_dict, dict):
                event_dict.update(nested_dict)
    return event_dict


def convert_arrays_to_lists(data: dict) -> dict:
    return {key: value.tolist() if hasattr(value, "tolist") else value for key, value in data.items()}