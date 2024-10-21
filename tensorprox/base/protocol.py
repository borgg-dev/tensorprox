import pydantic
import bittensor as bt
from typing import List, AsyncIterator
from starlette.responses import StreamingResponse

class AvailabilitySynapse(bt.Synapse):
    """AvailabilitySynapse is a specialized implementation of the `Synapse` class used to allow miners to let validators know
    about their status/availability to server certain tasks"""

    task_availabilities: dict[str, bool]


class StreamPromptingSynapse(bt.StreamingSynapse):
    """
    StreamPromptingSynapse is a specialized implementation of the `StreamingSynapse` tailored for prompting functionalities within
    the Bittensor network. This class is intended to interact with a streaming response that contains a sequence of tokens,
    which represent prompts or messages in a certain scenario.

    As a developer, when using or extending the `StreamPromptingSynapse` class, you should be primarily focused on the structure
    and behavior of the prompts you are working with. The class has been designed to seamlessly handle the streaming,
    decoding, and accumulation of tokens that represent these prompts.

    Attributes:

    - `task_name` (str): These represent the actual prompts or messages in the prompting scenario. They are also
                            immutable to ensure consistent behavior during processing.

    - `challenges` (List[dict]): These represent the actual prompts or messages in the prompting scenario. They are also
                              immutable to ensure consistent behavior during processing.

    - `prediction` (bool): Stores the processed result of the streaming tokens. As tokens are streamed, decoded, and
                          processed, they are accumulated in the completion attribute. This represents the "final"
                          product or result of the streaming process.

    Note: While you can directly use the `StreamPromptingSynapse` class, it's designed to be extensible. Thus, you can create
    subclasses to further customize behavior for specific prompting scenarios or requirements.
    """

    task_name: str = pydantic.Field(
        ...,
        title="Task",
        description="The task for the current StreamPromptingSynapse object.",
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
        description="Completion status of the current PromptingSynapse object. This attribute is mutable and can be updated.",
    )

