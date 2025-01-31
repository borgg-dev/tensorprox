from pydantic import Field, BaseModel
import bittensor as bt
from typing import List, Dict, Tuple

class MachineDetails(BaseModel):
    ip: str = ""
    username: str = ""
    
    def get(self, key, default=None):
        return getattr(self, key, default)
    
class MachineConfig(BaseModel):
    key_pair: Tuple[str, str] = ("", "")
    machine_config: Dict[str, MachineDetails] = {
        "Attacker": MachineDetails(),
        "Benign": MachineDetails(),
        "King": MachineDetails(),
    }

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
            }
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
            machine_availabilities=MachineConfig(machine_config=machine_availabilities)
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
