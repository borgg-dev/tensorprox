from pydantic import Field, BaseModel
import bittensor as bt
from typing import List, Dict, Tuple

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

    king_private_ip: str = Field(
        ..., title="King Machine Private IP", description="The Private IP address of the King machine."
    )

    king_port: int = Field(
        8080, title="King Machine Port", description="The port on which the King machine is listening."
    )

    moat_private_ip: str = Field(
        ..., title="Moat Machine Private IP", description="The Private IP address of the Moat machine."
    )

    moat_listen_port: int = Field(
        8080, title="Moat Listening Port", description="The port on which the Moat should listen for incoming traffic."
    )

    challenge_duration: int = Field(
        ..., title="Challenge Duration", description="Duration of the challenge round in seconds."
    )


    def serialize(self) -> dict:
        """
        Serializes the ChallengeSynapse into a dictionary.
        """
        return {
            "king_private_ip": self.king_private_ip,
            "king_port": self.king_port,
            "moat_private_ip": self.moat_private_ip,
            "moat_listen_port": self.moat_listen_port,
            "challenge_duration": self.challenge_duration,
        }

    @classmethod
    def deserialize(cls, data: dict) -> "ChallengeSynapse":
        """
        Deserializes a dictionary into a ChallengeSynapse instance.
        """
        return cls(
            king_private_ip=data["king_private_ip"],
            king_port=data.get("king_port", 8080),
            moat_private_ip=data["moat_private_ip"],
            moat_listen_port=data.get("moat_listen_port", 8080),
            challenge_duration=data["challenge_duration"],
        )


class TensorProxSynapse(bt.Synapse):
    """
    TensorProxSynapse is a specialized implementation of the `Synapse`. 
    This class is intended to interact with a streaming response that contains a sequence of tokens,
    which represent prompts or messages in a certain scenario.

    As a developer, when using or extending the `TensorProxSynapse` class, you should be primarily focused on the structure
    and behavior of the prompts you are working with. The class has been designed to seamlessly handle the streaming,
    decoding, and accumulation of tokens that represent these prompts.

    Attributes:

    - `task_name` (str): Name of the task sent to miners. Immutable.
        For now we only process one task type => DDoSDetectionTask

    - `challenges` (List[dict]): These represent the actual input features in the DDoS Detection scenario. Immutable.

    - `prediction` (int): Stores the result of the output label predicted by miners.

    Note: While you can directly use the `TensorProxSynapse` class, it's designed to be extensible. Thus, you can create
    subclasses to further customize behavior for specific scenarios or requirements.
    """

    task_name: str = Field(
        ...,
        title="Task",
        description="The task for the current TensorProxSynapse object.",
        allow_mutation=False,
    )

    challenges: List[dict] = Field(
        ...,
        title="Challenges",
        description="A list of challenges.",
        allow_mutation=False,
    )

    prediction: str = Field(
        "",
        title="Prediction",
        description="Prediction for the output class. This attribute is mutable and can be updated.",
    )

    def deserialize(self) -> str:
        """
        Deserializes the response by returning the prediction attribute.

        Returns:
            str: The prediction result.
        """
        return self.prediction