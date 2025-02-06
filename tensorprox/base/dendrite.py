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
    all_miners_availability: list[Dict[str, Union[int, str]]] = []
    setup_status: list[Dict[str, Dict[str, Union[int, str]]]] = []
    ping_status_messages: list[str] = []
    ping_status_codes: list[int] = []
    setup_status_by_uid: dict[int, Dict[str, Dict[str, Union[int, str]]]] = {}

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @model_validator(mode="after")
    def process_results(self) -> "DendriteResponseEvent":
        """
        Processes miner availability and extracts relevant ping and setup status details.
        This ensures response_event_1 and response_event_2 are handled separately.
        """
        if self.all_miners_availability:
            for avail in self.all_miners_availability:
                self.ping_status_messages.append(avail.get("ping_status_message", ""))
                self.ping_status_codes.append(avail.get("ping_status_code", 0))
        

        if self.setup_status:
            for uid, setup in zip(self.uids, self.setup_status):
                self.setup_status_by_uid[uid] = {}
                self.setup_status_by_uid[uid]["setup_status_message"] = setup.get("setup_status_message", f"UID {uid} missed availability check. Not selected for this round.")
                self.setup_status_by_uid[uid]["setup_status_code"] = setup.get("setup_status_code", 400)
        
        return self
