from pydantic import Field, BaseModel
import bittensor as bt
from typing import Dict, Tuple
from tensorprox import *
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings

class MachineDetails(BaseModel):
    ip: str | None = None
    username: str | None = None
    private_ip: str | None = None
    
    def get(self, key, default=None):
        return getattr(self, key, default)
    
class MachineConfig(BaseModel):
    key_pair: Tuple[str, str] = ("", "")
    machine_config: Dict[str, MachineDetails] = {name: MachineDetails() for name in NODE_TYPES}


class AvailabilitySynapse(bt.Synapse):
    """AvailabilitySynapse is a specialized implementation of the `Synapse` class used to allow miners to let validators know
    about their status/availability to serve certain tasks"""
    task_availabilities: dict[str, bool]

class PingSynapse(bt.Synapse):
    """
    Synapse for miners to report machine availability and corresponding details.
    """

    machine_availabilities: MachineConfig = Field(
        default_factory=MachineConfig,
        title="Machine's Availabilities",
        description="A dictionary where keys are machine names and values are MachineDetails instances. Miners populate this field.",
        allow_mutation=True,
    )

    def serialize(self) -> dict:
        """
        Serializes the `PingSynapse` into a dictionary.

        Converts `MachineDetails` instances to dictionaries for external usage.
        Also, properly includes the SSH key pair and ssh_user for validation purposes.
        """
        return {
            "machine_availabilities": {
                "key_pair": self.machine_availabilities.key_pair,
                "machine_config": {
                    key: details.dict() 
                    for key, details in self.machine_availabilities.machine_config.items()
                }
            },
        }


    @classmethod
    def deserialize(cls, data: dict) -> "PingSynapse":
        """
        Deserializes a dictionary into an `PingSynapse`.

        Converts nested dictionaries into `MachineDetails` instances.
        Properly handles the SSH key pair and machine availability details.
        """
        machine_availabilities = {
            key: MachineDetails(**details)
            for key, details in data.get("machine_availabilities", {}).items()
        }
        
        return cls(
            machine_availabilities=MachineConfig(
                key_pair=tuple(data.get("machine_availabilities", {}).get("key_pair", ("", ""))),
                machine_config=machine_availabilities,
            ),
        )


class ChallengeSynapse(bt.Synapse):
    """
    Synapse for sending challenge state to miners.
    """

    task: str = Field(
        ..., title="Task Name", description="Description of the task assigned to miners."
    )

    state: str = Field(
        ..., title="State", description="State of the task assigned."
    )


    def serialize(self) -> dict:
        """
        Serializes the ChallengeSynapse into a dictionary.
        """
        return {
            "task" : self.task,
            "state" : self.state,
        }

    @classmethod
    def deserialize(cls, data: dict) -> "ChallengeSynapse":
        """
        Deserializes a dictionary into a ChallengeSynapse instance.
        Converts ISO 8601 date strings to datetime.
        """
        return cls(
            task=data["task"],
            state=data["state"],
        )

