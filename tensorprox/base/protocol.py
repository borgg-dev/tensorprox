import pydantic
import bittensor as bt
from typing import List, Dict

class AvailabilitySynapse(bt.Synapse):
    """
    Synapse for miners to report machine availability and corresponding IPs.

    Attributes:
    - machine_availabilities (Dict[str, str]): A dictionary where the keys are machine names and the values are their IP addresses. This is mutable and will be populated by the miners.
    """
    machine_availabilities: Dict[str, str] = pydantic.Field(
        default_factory=dict,
        title="Machine's Availabilities",
        description="A dictionary where keys are machine names and values are IP addresses. Miners populate this field.",
    )

    def serialize(self) -> dict:
        """
        Serializes the `AvailabilitySynapse` into a dictionary.

        Returns:
            dict: Serialized representation of machine availabilities.
        """
        return {"machine_availabilities": self.machine_availabilities}

    @classmethod
    def deserialize(cls, data: dict) -> "AvailabilitySynapse":
        """
        Deserializes a dictionary into an `AvailabilitySynapse`.

        Args:
            data (dict): The dictionary containing machine data.

        Returns:
            AvailabilitySynapse: An instance of the AvailabilitySynapse.
        """
        return cls(machine_availabilities=data.get("machine_availabilities", {}))
    
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

    task_name: str = pydantic.Field(
        ...,
        title="Task",
        description="The task for the current TensorProxSynapse object.",
        allow_mutation=False,
    )

    challenges: List[dict] = pydantic.Field(
        ...,
        title="Challenges",
        description="A list of challenges.",
        allow_mutation=False,
    )

    prediction: str = pydantic.Field(
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


