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
from typing import ClassVar, Dict, List
from tensorprox.base.dendrite import DendriteResponseEvent
from pydantic import BaseModel, ConfigDict
from tensorprox.rewards.pcap import PacketAnalyzer
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

    @staticmethod
    def extract_labeled_counts(pcap_path: str, label_dict: dict) -> dict:
        """
        Extract labeled packet counts from a pcap file based on provided labels.

        Args:
            pcap_path (str): The file path to the pcap file.
            label_dict (dict): A dictionary mapping original labels to encrypted labels.

        Returns:
            dict: A dictionary with original labels as keys and their corresponding packet counts as values.
        """

        # Extraire uniquement les valeurs encryptées pour la recherche
        encrypted_labels = list(label_dict.values())

        analyzer = PacketAnalyzer(pcap_path)
        start_date, end_date = analyzer.get_time_range()

        matched_packets_encrypted = analyzer.analyze(search_labels=encrypted_labels, start_date=start_date, end_date=end_date)

        # Transformer les labels encryptés en labels d'origine
        reverse_label_lookup = {v: k for k, v in label_dict.items()}
        matched_packets = {reverse_label_lookup[key]: value for key, value in matched_packets_encrypted.items() if key in reverse_label_lookup}

        return matched_packets

    def reward(self, uids: List[int], labels_dict: Dict) -> BatchRewardOutput:
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
        latencies = {}  # List to store latencies for all users

        for uid in uids:
            attack_path = os.path.join(base_path, f"{uid}/Attacker_capture.pcap")
            benign_path = os.path.join(base_path, f"{uid}/Attacker_capture.pcap")
            king_path = os.path.join(base_path, f"{uid}/King_capture.pcap")

            # Check if all required pcap files exist and are non-empty
            if not all(os.path.exists(path) and os.path.getsize(path) > 0 for path in [attack_path, benign_path, king_path]):
                logging.warning(f"Missing or empty pcap files for UID {uid}. Skipping reward calculation.")
                packet_data[uid] = None
                continue

            attack_counts = self.extract_labeled_counts(attack_path, labels_dict)
            benign_counts = self.extract_labeled_counts(benign_path, labels_dict)
            king_counts = self.extract_labeled_counts(king_path, labels_dict)

            # #Hardcoded
            # attack_counts = {"BENIGN" : 0, "UDP_FLOOD" : 100, "TCP_SYN_FLOOD" : 0}
            # benign_counts = {"BENIGN" : 100, "UDP_FLOOD" : 0, "TCP_SYN_FLOOD" : 0}
            # king_counts = {"BENIGN" : 90, "UDP_FLOOD" : 20, "TCP_SYN_FLOOD" : 0}

            # Calculate average latency of the benign traffic
            analyzer = PacketAnalyzer(benign_path)
            label_bytes = labels_dict["BENIGN"].encode()
            latency_stats = analyzer.compute_latency(king_path, label=label_bytes)
            latency_score = max(0, latency_stats["mean"] or 0) #ensures latency is always >= 0

            # Total packets sent
            total_packets_sent = sum(attack_counts.values()) + sum(benign_counts.values())
            max_packets = max(max_packets, total_packets_sent)

            packet_data[uid] = (attack_counts, benign_counts, king_counts)
            latencies[uid] = latency_score

        # Calculate the min and max latency across all users
        max_latency = max(latencies.values(), default=0)

        # Calculate rewards for each participant
        for uid in uids:
            if packet_data[uid] is None:
                scores.append(0.0)
                continue

            attack_counts, benign_counts, king_counts = packet_data[uid]

            # Total attack packets sent
            total_attacks_sent = sum(attack_counts.get(label, 0) for label in ["TCP_SYN_FLOOD", "UDP_FLOOD"])
            # Total benign packets sent
            total_benign_sent = benign_counts.get("BENIGN", 0)
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
            latency = latencies[uid]  # Get the latency for the current user

            normalized_latency = latency / max_latency  if max_latency > 0 else 0

            logging.info(f"ADA for UID {uid} : {ADA}")
            logging.info(f"1-FPR for UID {uid} : {1-FPR}")
            logging.info(f"Normalized_packets_sent for UID {uid} : {normalized_packets_sent}")
            logging.info(f"Average Latency for UID {uid} : {latency} ms")
            logging.info(f"Normalized_latency for UID {uid} : {normalized_latency}")

            # Calculate reward function
            reward = alpha * ADA + beta * (1 - FPR) + gamma * normalized_packets_sent**2 + delta * normalized_latency**2
            scores.append(reward)

        return BatchRewardOutput(rewards=np.array(scores))
        

class BaseRewardConfig(BaseModel):
    """
    Configuration class for setting up the reward model and default labels.

    Attributes:
        default_labels (ClassVar[dict]): Default mapping of labels.
        reward_model (ClassVar[ChallengeRewardModel]): An instance of the reward model.
    """

    default_labels: ClassVar[dict] = {
        "BENIGN": "BENIGN",
        "UDP_FLOOD": "UDP_FLOOD",
        "TCP_SYN_FLOOD": "TCP_SYN_FLOOD"
    }

    reward_model: ClassVar[ChallengeRewardModel] = ChallengeRewardModel()

    @classmethod
    def apply(
        cls,
        response_event: DendriteResponseEvent,
        uids: list[int],
        labels_dict: dict = None  # Optional parameter
    ) -> ChallengeRewardEvent:
        """
        Apply the reward model to a list of user IDs with optional custom labels.

        Args:
            uids (list[int]): A list of user IDs.
            labels_dict (dict, optional): A custom dictionary mapping original labels to encrypted labels. Defaults to None.

        Returns:
            ChallengeRewardEvent: An event containing the computed rewards and associated user IDs.
        """

        # Use default labels if no custom labels_dict is provided
        labels_dict = labels_dict or cls.default_labels

        # Get the reward output
        batch_rewards_output = cls.reward_model.reward(uids, labels_dict)

        # Return the ChallengeRewardEvent using the BatchRewardOutput
        return ChallengeRewardEvent(
            response=response_event,
            rewards=batch_rewards_output.rewards.tolist(),
            uids=uids,
        )
