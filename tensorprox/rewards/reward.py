"""
================================================================================

TensorProx Challenge Reward Computation Module

This module defines classes and functions for computing rewards on the TensorProx 
subnetwork. It processes packet capture (pcap) files to analyze
network traffic and assigns rewards based on attack detection accuracy, false
positive rates, and the volume of packets processed.

Key Components:
- `ChallengeRewardEvent`: Represents a reward event in a challenge, encapsulating
  reward values and associated user IDs.
- `BatchRewardOutput`: Represents the output of a batch reward computation,
  containing an array of computed reward values.
- `ChallengeRewardModel`: Provides methods to extract labeled packet counts from
  pcap files and calculate rewards based on network traffic analysis.
- `BaseRewardConfig`: Configuration class for setting up the reward model and
  default labels, offering a method to apply the reward model to a list of user IDs.

Dependencies:
- `numpy`: For numerical operations and array handling.
- `pydantic`: For data validation and settings management.
- `tensorprox`: Specifically, the `PacketAnalyzer` from `tensorprox.rewards.pcap`
  for analyzing pcap files.
- `os`: For interacting with the operating system, particularly in handling file
  paths.
- `logging`: For structured logging and debugging.

License:
This software is licensed under the Creative Commons Attribution-NonCommercial
4.0 International (CC BY-NC 4.0). You are free to use, share, and modify the code
for non-commercial purposes only.

Commercial Usage:
The only authorized commercial use of this software is for mining or validating
within the TensorProx subnet. For any other commercial licensing requests, please
contact Shugo LTD.

See the full license terms here: https://creativecommons.org/licenses/by-nc/4.0/

Author: Shugo LTD
Version: 0.1.0

================================================================================
"""

import numpy as np
from typing import ClassVar, Dict, List, Union
from tensorprox.base.dendrite import DendriteResponseEvent
from pydantic import BaseModel, ConfigDict
import os
import logging

class ChallengeRewardEvent(BaseModel):
    """
    Represents a reward event in a challenge.

    Attributes:
        response (DendriteResponseEvent): DendriteResponseEvent.
        rewards (list[float]): A list of reward values.
        uids (list[int]): A list of user IDs associated with the rewards.
    """
    response: DendriteResponseEvent
    rewards: list[float]
    uids: list[int]

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def asdict(self) -> dict:
        """
        Convert the ChallengeRewardEvent instance to a dictionary.

        Returns:
            dict: A dictionary representation of the instance with keys 'response_event', 'rewards' and 'uids'.
        """
        return {
            "response_event": self.response,
            "rewards": self.rewards,
            "uids": self.uids,
        }

class BatchRewardOutput(BaseModel):
    """
    Represents the output of a batch reward computation.

    Attributes:
        rewards (np.ndarray): An array of computed reward values.
    """
    rewards: np.ndarray
    model_config = ConfigDict(arbitrary_types_allowed=True)

class ChallengeRewardModel(BaseModel):
    
    
    def reward(self, response_event: DendriteResponseEvent, uids: List[int], labels_dict: Dict) -> BatchRewardOutput:
        """
        Calculate rewards for a batch of users based on their packet capture data.

        Args:
            uids (List[int]): A list of user IDs.
            labels_dict (Dict): A dictionary mapping original labels to encrypted labels.

        Returns:
            BatchRewardOutput: An instance containing an array of computed rewards.
        """

        scores = []
        base_path = os.path.expanduser("~/tensorprox/tensorprox/rewards/pcap_files")

        # Define weights
        alpha = 0.3  # Attack Detection Accuracy (ADA)
        beta = 0.3   # False Positive Rate (FPR)
        gamma = 0.2  # Throughput efficiency
        delta = 0.2  # Latency factor

        # Determine the maximum number of packets sent by any participant
        max_packets = 0
        packet_data = {}
        rtt_dict = {}  # List to store latencies for all users

        for uid in uids:

            label_counts_results = response_event.challenge_status_by_uid[uid]["label_counts_results"]

            default_count = {label:0 for label in labels_dict.keys()}

            attack_counts = next((counts for machine, counts, _ in label_counts_results if machine == "Attacker"), default_count)
            benign_counts = next((counts for machine, counts, _ in label_counts_results if machine == "Benign"), default_count)
            king_counts = next((counts for machine, counts, _ in label_counts_results if machine == "King"), default_count)

            attack_avg_rtt = next((avg_rtt for machine, _, avg_rtt in label_counts_results if machine == "Attacker"), 0)
            benign_avg_rtt = next((avg_rtt for machine, _, avg_rtt in label_counts_results if machine == "Benign"), 0)

            # If all counts are the default (i.e., zero), skip this user
            if all(value == 0 for value in attack_counts.values()) and \
            all(value == 0 for value in benign_counts.values()) and \
            all(value == 0 for value in king_counts.values()):
                continue
            
            # Average RTT of the traffic gen machines
            
            rtt = (attack_avg_rtt+benign_avg_rtt)/2

            # Total packets sent
            total_packets_sent = sum(attack_counts.values()) + sum(benign_counts.values())
            max_packets = max(max_packets, total_packets_sent)

            packet_data[uid] = (attack_counts, benign_counts, king_counts)
            rtt_dict[uid] = rtt

        # Calculate the min RTT across all users
        min_rtt = min(rtt_dict.values(), default=0)

        # Calculate rewards for each participant
        for uid in uids:

            if uid not in packet_data.keys():
                scores.append(0.0)
                continue

            attack_counts, benign_counts, king_counts = packet_data[uid]

            # Total packets sent from the Attacker machine
            total_attacks_from_attacker = sum(attack_counts.get(label, 0) for label in ["TCP_SYN_FLOOD", "UDP_FLOOD"])
            total_benign_from_attacker = attack_counts.get("BENIGN", 0)

            # Total packets sent from the Benign machine
            total_benign_from_benign = benign_counts.get("BENIGN", 0)
            total_attacks_from_benign = sum(benign_counts.get(label, 0) for label in ["TCP_SYN_FLOOD", "UDP_FLOOD"])
        
            total_attacks_sent = total_attacks_from_attacker + total_attacks_from_benign
            total_benign_sent = total_benign_from_benign + total_benign_from_attacker

            # Total packets sent
            total_packets_sent = total_attacks_sent + total_benign_sent

            # Total attack packets processed (reaching King)
            total_reaching_attacks = sum(king_counts.get(label, 0) for label in ["TCP_SYN_FLOOD", "UDP_FLOOD"])
            # Total benign packets processed (reaching King)
            total_reaching_benign = king_counts.get("BENIGN", 0)

            # Attack Detection Accuracy (ADA)
            ADA = (total_attacks_sent - total_reaching_attacks) / total_attacks_sent if total_attacks_sent > 0 else 0

            # False Positive Rate (FPR)
            FPR = (total_benign_sent - total_reaching_benign) / total_benign_sent if total_benign_sent > 0 else 1

            # Normalized total packets sent
            normalized_packets_sent = total_packets_sent / max_packets if max_packets > 0 else 0

            # Normalize latency based on min and max latency of all users
            rtt = rtt_dict[uid]  # Get the latency for the current user

            normalized_rtt = min_rtt / rtt  if rtt > 0 else 0

            logging.info(f"ADA for UID {uid} : {ADA}")
            logging.info(f"1-FPR for UID {uid} : {1-FPR}")
            logging.info(f"Normalized_packets_sent for UID {uid} : {normalized_packets_sent}")
            logging.info(f"Average RTT for UID {uid} : {rtt} ms")
            logging.info(f"Normalized RTT for UID {uid} : {normalized_rtt}")

            # Calculate reward function
            reward = alpha * ADA + beta * (1 - FPR) + gamma * normalized_packets_sent**2 + delta * normalized_rtt**2
            scores.append(reward)

        return BatchRewardOutput(rewards=np.array(scores))
        

class BaseRewardConfig(BaseModel):
    """
    Configuration class for setting up the reward model and default labels.

    Attributes:
        default_labels (ClassVar[dict]): Default mapping of labels.
        reward_model (ClassVar[ChallengeRewardModel]): An instance of the reward model.
    """

    reward_model: ClassVar[ChallengeRewardModel] = ChallengeRewardModel()

    @classmethod
    def apply(
        cls,
        response_event: DendriteResponseEvent,
        uids: list[int],
        labels_dict: dict,
    ) -> ChallengeRewardEvent:
        """
        Apply the reward model to a list of user IDs with optional custom labels.

        Args:
            uids (list[int]): A list of user IDs.
            labels_dict (dict, optional): A custom dictionary mapping original labels to encrypted labels. Defaults to None.

        Returns:
            ChallengeRewardEvent: An event containing the computed rewards and associated user IDs.
        """

        # Get the reward output
        batch_rewards_output = cls.reward_model.reward(response_event, uids, labels_dict)

        # Return the ChallengeRewardEvent using the BatchRewardOutput
        return ChallengeRewardEvent(
            response=response_event,
            rewards=batch_rewards_output.rewards.tolist(),
            uids=uids,
        )
