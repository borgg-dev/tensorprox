#!/usr/bin/env python3

import numpy as np
from tensorprox.base.protocol import PingSynapse
from pydantic import BaseModel, model_validator, ConfigDict
from typing import Dict, Union

######################################################################
# 5) MODEL CLASS
######################################################################

class DendriteResponseEvent(BaseModel):
    uids: np.ndarray | list[int]
    synapses: list[PingSynapse]
    all_miners_availability: list[Dict[str, Union[int, str]]] = []
    setup_status: list[Dict[str, Union[int, str]]] = []
    lockdown_status: list[Dict[str, Union[int, str]]] = []
    gre_status: list[Dict[str, Union[int, str]]] = []
    challenge_status: list[Dict[str, Union[int, str, list]]] = []
    revert_status: list[Dict[str, Union[int, str]]] = []
    ping_status_messages: list[str] = []
    ping_status_codes: list[int] = []
    setup_status_by_uid: dict[int, Dict[str, Union[int, str]]] = {}
    lockdown_status_by_uid: dict[int, Dict[str, Union[int, str]]] = {}
    gre_status_by_uid: dict[int, Dict[str, Union[int, str]]] = {}
    challenge_status_by_uid: dict[int, Dict[str, Union[int, str, list]]] = {}
    revert_status_by_uid: dict[int, Dict[str, Union[int, str]]] = {}

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @model_validator(mode="after")
    def process_results(self) -> "DendriteResponseEvent":
        """
        Processes miner availability and extracts relevant status details for each step.
        """

        # Reset all lists and dictionaries to start fresh
        self.ping_status_messages = []
        self.ping_status_codes = []
        self.setup_status_by_uid = {}
        self.lockdown_status_by_uid = {}
        self.gre_status_by_uid = {}
        self.challenge_status_by_uid = {}
        self.revert_status_by_uid = {}
        
        if self.all_miners_availability:
            for avail in self.all_miners_availability:
                self.ping_status_messages.append(avail.get("ping_status_message", ""))
                self.ping_status_codes.append(avail.get("ping_status_code", 0))

        # Setup Step
        if self.setup_status:
            for setup in self.setup_status:
                uid = setup.get("uid")
                if uid is not None:
                    self.setup_status_by_uid[uid] = {
                        "initial_setup_status_message": setup.get("initial_setup_status_message", f"UID {uid} not set up."),
                        "initial_setup_status_code": setup.get("initial_setup_status_code", 400),
                    }

        # Lockdown Step
        if self.lockdown_status:
            for lockdown in self.lockdown_status:
                uid = lockdown.get("uid")
                if uid is not None:
                    self.lockdown_status_by_uid[uid] = {
                        "lockdown_status_message": lockdown.get("lockdown_status_message", f"UID {uid} not locked down."),
                        "lockdown_status_code": lockdown.get("lockdown_status_code", 400),
                    }

        # GRE Step
        if self.gre_status:
            for gre in self.gre_status:
                uid = gre.get("uid")
                if uid is not None:
                    self.gre_status_by_uid[uid] = {
                        "gre_setup_status_message": gre.get("gre_setup_status_message", f"UID {uid} not set up."),
                        "gre_setup_status_code": gre.get("gre_setup_status_code", 400),
                    }

        # Challenge Step
        if self.challenge_status:
            for challenge in self.challenge_status:
                uid = challenge.get("uid")
                if uid is not None:
                    self.challenge_status_by_uid[uid] = {
                        "challenge_status_message": challenge.get("challenge_status_message", f"UID {uid} not set up."),
                        "challenge_status_code": challenge.get("challenge_status_code", 400),
                        "label_counts_results" : challenge.get('label_counts_results', [])
                    }

        # Revert Step
        if self.revert_status:
            for revert in self.revert_status:
                uid = revert.get("uid")
                if uid is not None:
                    self.revert_status_by_uid[uid] = {
                        "revert_status_message": revert.get("revert_status_message", f"UID {uid} not reverted."),
                        "revert_status_code": revert.get("revert_status_code", 400),
                    }

        return self
