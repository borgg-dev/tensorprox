from pydantic import Field, BaseModel
import bittensor as bt
from typing import List, Dict, Tuple, Optional

class MachineDetails(BaseModel):
    ip: str | None = None
    username: str | None = None
    private_ip: str | None = None
    
    def get(self, key, default=None):
        return getattr(self, key, default)
    
class MachineConfig(BaseModel):
    key_pair: Tuple[str, str] = ("", "")
    machine_config: Dict[str, MachineDetails] = {name: MachineDetails() for name in ["Attacker", "Benign", "King", "Moat"]}


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
    Synapse for sending necessary configuration details to miners before a challenge round begins.
    """

    task: str = Field(
        ..., title="Task Name", description="Description of the task assigned to miners."
    )

    state: str = Field(
        ..., title="Task State", description="Status of the task assigned."
    )

    king_private_ip: str = Field(
        ..., title="King Machine Private IP", description="The Private IP address of the King machine."
    )

    challenge_start_time: Optional[int] = Field(
        None, title="Challenge Start Time", description="Start Time of the challenge (timestamp)."
    )

    challenge_end_time: Optional[int] = Field(
        None, title="Challenge End Time", description="End Time of the challenge (timestamp)."
    )

    challenge_duration: Optional[int] = Field(
        None, title="Challenge Duration", description="Duration of the challenge round in seconds."
    )


    def serialize(self) -> dict:
        """
        Serializes the ChallengeSynapse into a dictionary.
        """
        return {
            "task" : self.task,
            "state" : self.state,
            "king_private_ip": self.king_private_ip,
            "challenge_start_time": self.challenge_start_time,
            "challenge_end_time": self.challenge_end_time,
            "challenge_duration": self.challenge_duration,
        }

    @classmethod
    def deserialize(cls, data: dict) -> "ChallengeSynapse":
        """
        Deserializes a dictionary into a ChallengeSynapse instance.
        """
        return cls(
            task=data["task"],
            state=data["state"],
            king_private_ip=data["king_private_ip"],
            challenge_start_time = data["challenge_start_time"],
            challenge_end_time = data["challenge_end_time"],
            challenge_duration=data["challenge_duration"],
        )

