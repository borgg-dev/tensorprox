#!/usr/bin/env python3

import numpy as np
from tensorprox.base.protocol import PingSynapse
from pydantic import BaseModel, model_validator, ConfigDict
import os
import random
import string
import re
from typing import Dict, Union

def is_valid_ip(ip: str) -> bool:
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?\d?\d?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?\d?\d?)$"
    return re.match(pattern, ip) is not None

######################################################################
# 5) MODEL CLASS
######################################################################

class DendriteResponseEvent(BaseModel):
    uids: np.ndarray | list[int]
    synapses: list[PingSynapse]
    all_miners_availability: list[Dict[str, Union[int, str]]]
    ping_status_messages: list[str] = []
    ping_status_codes: list[int] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)


    @model_validator(mode="after")
    def process_results(self) -> "DendriteResponseEvent":
        """
        For each synapse, run session setup on each machine in the machine_config,
        using optional user commands based on role, then shuffle the playlist.
        """


        for uid, avail  in zip(self.uids, self.all_miners_availability):

            if "ping_status_message" in avail : 
                self.ping_status_messages.append(avail["ping_status_message"])
            else :
                self.ping_status_messages.append("")

            if "ping_status_code" in avail : 
                self.ping_status_codes.append(avail["ping_status_code"])
            else :
                self.ping_status_codes.append(0)
           
        return self
