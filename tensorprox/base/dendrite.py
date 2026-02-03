"""
Dendrite response event tracking.

Collects and organizes responses from miners during
validation rounds for scoring.
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class DendriteResponseEvent(BaseModel):
    """
    Collects responses from all miners during a validation round.

    Organizes data by phase (ping, setup, challenge, lockdown)
    for easy access during scoring.
    """

    # Round identification
    round_id: str = Field(default="", description="Unique round identifier")
    block_number: int = Field(default=0, description="Block at round start")
    validator_uid: int = Field(default=-1, description="Validator's UID")

    # Raw responses by phase
    ping_responses: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Raw ping synapse responses"
    )
    setup_responses: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Raw setup phase responses"
    )
    challenge_responses: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Raw challenge phase responses"
    )
    lockdown_responses: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Raw lockdown phase responses"
    )

    # Indexed by UID for faster access
    ping_by_uid: Dict[int, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Ping responses indexed by miner UID"
    )
    setup_by_uid: Dict[int, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Setup responses indexed by miner UID"
    )
    challenge_by_uid: Dict[int, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Challenge responses indexed by miner UID"
    )
    lockdown_by_uid: Dict[int, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Lockdown responses indexed by miner UID"
    )

    # Metrics collected during challenge
    metrics_by_uid: Dict[int, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Performance metrics indexed by miner UID"
    )

    # UIDs that participated
    participating_uids: List[int] = Field(
        default_factory=list,
        description="UIDs that participated in this round"
    )

    # Timing
    round_start_time: float = Field(default=0.0, description="Round start timestamp")
    round_end_time: float = Field(default=0.0, description="Round end timestamp")

    def add_ping_response(
        self,
        uid: int,
        response: Dict[str, Any],
        success: bool = True
    ) -> None:
        """Add a ping response for a miner."""
        self.ping_responses.append(response)
        self.ping_by_uid[uid] = {
            "response": response,
            "success": success
        }
        if uid not in self.participating_uids:
            self.participating_uids.append(uid)

    def add_setup_response(
        self,
        uid: int,
        response: Dict[str, Any],
        success: bool = True
    ) -> None:
        """Add a setup phase response for a miner."""
        self.setup_responses.append(response)
        self.setup_by_uid[uid] = {
            "response": response,
            "success": success
        }

    def add_challenge_response(
        self,
        uid: int,
        response: Dict[str, Any],
        metrics: Optional[Dict[str, Any]] = None,
        success: bool = True
    ) -> None:
        """Add a challenge phase response with metrics."""
        self.challenge_responses.append(response)
        self.challenge_by_uid[uid] = {
            "response": response,
            "success": success
        }
        if metrics:
            self.metrics_by_uid[uid] = metrics

    def add_lockdown_response(
        self,
        uid: int,
        response: Dict[str, Any],
        success: bool = True
    ) -> None:
        """Add a lockdown phase response."""
        self.lockdown_responses.append(response)
        self.lockdown_by_uid[uid] = {
            "response": response,
            "success": success
        }

    def get_available_uids(self) -> List[int]:
        """Get UIDs that responded to ping with availability."""
        available = []
        for uid, data in self.ping_by_uid.items():
            if data.get("success") and data.get("response", {}).get("is_available"):
                available.append(uid)
        return available

    def get_successful_challenge_uids(self) -> List[int]:
        """Get UIDs that completed the challenge successfully."""
        successful = []
        for uid, data in self.challenge_by_uid.items():
            if data.get("success"):
                successful.append(uid)
        return successful

    def get_metrics(self, uid: int) -> Optional[Dict[str, Any]]:
        """Get metrics for a specific miner."""
        return self.metrics_by_uid.get(uid)

    def get_all_metrics(self) -> Dict[int, Dict[str, Any]]:
        """Get all collected metrics."""
        return self.metrics_by_uid.copy()

    def summary(self) -> Dict[str, Any]:
        """Get a summary of the round responses."""
        return {
            "round_id": self.round_id,
            "block": self.block_number,
            "validator_uid": self.validator_uid,
            "total_participants": len(self.participating_uids),
            "available_miners": len(self.get_available_uids()),
            "successful_challenges": len(self.get_successful_challenge_uids()),
            "duration_seconds": self.round_end_time - self.round_start_time
        }
