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
import math

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
    
    @staticmethod
    def normalize_rtt(input, exponent=3, scale_factor=10):
        # Use max to avoid negative logs causing unexpected results
        return 1 / (1 + math.log(input + 1)**exponent / scale_factor)
    
    @staticmethod
    def exponential_ratio(ratio):
        return (math.exp(ratio**2) - 1) / (math.exp(1) - 1)

    def reward(self, response_event: DendriteResponseEvent, uids: List[int], label_hashes: Dict) -> BatchRewardOutput:
        """
        Calculate rewards for a batch of users based on their packet capture data.

        Args:
            uids (List[int]): A list of user IDs.
            label_hashes (Dict): A dictionary mapping original labels to encrypted labels.

        Returns:
            BatchRewardOutput: An instance containing an array of computed rewards.
        """

        scores = []

        # Define weights
        alpha = 0.3  # Attack Detection Accuracy (ADA)
        beta = 0.3   # False Positive Rate (FPR)
        gamma = 0.2  # Throughput efficiency
        delta = 0.2  # Latency factor

        # Determine the maximum number of packets sent by any participant
        max_packets_processed = 0
        packet_data = {}

        # Helper function to calculate total attack and benign traffic
        def calculate_traffic_counts(counts, attack_labels):
            total_attacks = sum(counts.get(label, 0) for label in attack_labels)
            total_benign = counts.get("BENIGN", 0)
            return total_attacks, total_benign

        # Data collection for each user
        for uid in uids:
            label_counts_results = response_event.challenge_status_by_uid[uid]["label_counts_results"]
            default_count = {label: 0 for label in label_hashes.keys()}

            attack_counts = next((counts for machine, counts, _ in label_counts_results if machine == "attacker"), default_count)
            benign_counts = next((counts for machine, counts, _ in label_counts_results if machine == "benign"), default_count)
            king_counts = next((counts for machine, counts, _ in label_counts_results if machine == "king"), default_count)

            attack_avg_rtt = next((avg_rtt for machine, _, avg_rtt in label_counts_results if machine == "attacker"), 0)
            benign_avg_rtt = next((avg_rtt for machine, _, avg_rtt in label_counts_results if machine == "benign"), 0)

            # If all counts are the default (i.e., zero), skip this user
            if all(value == 0 for value in attack_counts.values()) and \
            all(value == 0 for value in benign_counts.values()) and \
            all(value == 0 for value in king_counts.values()):
                continue

            # Average RTT of the traffic gen machines
            rtt = max((attack_avg_rtt + benign_avg_rtt) / 2, 0)

            # Calculate total packets sent from attacker and benign machines
            attack_labels = ["TCP_SYN_FLOOD", "UDP_FLOOD"]
            total_attacks_from_attacker, total_benign_from_attacker = calculate_traffic_counts(attack_counts, attack_labels)
            total_benign_from_benign, total_attacks_from_benign = calculate_traffic_counts(benign_counts, attack_labels)

            total_attacks_sent = total_attacks_from_attacker + total_attacks_from_benign
            total_benign_sent = total_benign_from_benign + total_benign_from_attacker

            # Calculate total attack packets processed (reaching King)
            total_reaching_attacks = sum(king_counts.get(label, 0) for label in attack_labels)

            # Total attacks blocked (not reaching King)
            total_blocked_attacks = total_attacks_sent - total_reaching_attacks

            # Total benign packets processed (reaching King)
            total_reaching_benign = king_counts.get("BENIGN", 0)

            total_packets_processed = total_blocked_attacks + total_reaching_benign
            max_packets_processed = max(max_packets_processed, total_packets_processed)

            # Save all the calculated values in a dictionary for use in the reward calculation loop
            packet_data[uid] = {
                "total_attacks_sent": total_attacks_sent,
                "total_benign_sent": total_benign_sent,
                "total_blocked_attacks": total_blocked_attacks,
                "total_reaching_benign": total_reaching_benign,
                "rtt": rtt
            }

        # Calculate rewards for each participant
        for uid in uids:
            if uid not in packet_data.keys():
                scores.append(0.0)
                continue

            # Get the pre-calculated values for the user
            data = packet_data[uid]
            total_attacks_sent = data["total_attacks_sent"]
            total_benign_sent = data["total_benign_sent"]
            total_blocked_attacks = data["total_blocked_attacks"]
            total_reaching_benign = data["total_reaching_benign"]
            rtt = data["rtt"]

            # Attack Mitigation Accuracy (AMA)
            AMA = total_blocked_attacks / total_attacks_sent if total_attacks_sent > 0 else 0
            reward_AMA = self.exponential_ratio(ratio=AMA)

            # Benign Delivery Rate (BDR)
            BDR = total_reaching_benign / total_benign_sent if total_benign_sent > 0 else 0    
            reward_BDR = self.exponential_ratio(ratio=BDR)

            # Relative Throughput Capacity (RTC)
            RTC = (total_blocked_attacks + total_reaching_benign) / max_packets_processed if max_packets_processed > 0 else 0

            # Log-based Normalized RTT          
            LF = self.normalize_rtt(input=rtt)

            logging.info(f"AMA for UID {uid} : {AMA}")
            logging.info(f"BDR for UID {uid} : {BDR}")
            logging.info(f"RTC for UID {uid} : {RTC}")
            logging.info(f"Average RTT for UID {uid} : {rtt} ms")
            logging.info(f"LF for UID {uid} : {LF}")

            # Calculate reward function
            reward = alpha * reward_AMA + beta * reward_BDR + gamma * RTC + delta * LF
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
        label_hashes: dict,
    ) -> ChallengeRewardEvent:
        """
        Apply the reward model to a list of user IDs with optional custom labels.

        Args:
            uids (list[int]): A list of user IDs.
            label_hashes (dict): A custom dictionary mapping original labels to encrypted labels.

        Returns:
            ChallengeRewardEvent: An event containing the computed rewards and associated user IDs.
        """

        # Get the reward output
        batch_rewards_output = cls.reward_model.reward(response_event, uids, label_hashes)

        # Return the ChallengeRewardEvent using the BatchRewardOutput
        return ChallengeRewardEvent(
            response=response_event,
            rewards=batch_rewards_output.rewards.tolist(),
            uids=uids,
        )
