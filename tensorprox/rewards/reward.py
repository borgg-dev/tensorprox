import numpy as np
from typing import ClassVar
from pydantic import BaseModel, ConfigDict
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.rewards.pcap import PacketAnalyzer
import dpkt
import os
import logging

class ChallengeRewardEvent(BaseModel):
    rewards: list[float]
    uids: list[int]

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def asdict(self) -> dict:
        return {
            "rewards": self.rewards,
            "uids": self.uids,
        }

class BatchRewardOutput(BaseModel):
    rewards: np.ndarray
    model_config = ConfigDict(arbitrary_types_allowed=True)

class ChallengeRewardModel(BaseModel):

    @staticmethod
    def extract_labeled_counts(pcap_path: str, label_dict: dict) -> dict:
        """Extract labeled counts from a pcap file based on encrypted labels."""

        # Extraire uniquement les valeurs encryptées pour la recherche
        encrypted_labels = list(label_dict.values())

        analyzer = PacketAnalyzer(pcap_path)
        start_date, end_date = analyzer.get_time_range()

        matched_packets_encrypted = analyzer.analyze(search_labels=encrypted_labels, start_date=start_date, end_date=end_date)

        # Transformer les labels encryptés en labels d'origine
        reverse_label_lookup = {v: k for k, v in label_dict.items()}
        matched_packets = {reverse_label_lookup[key]: value for key, value in matched_packets_encrypted.items() if key in reverse_label_lookup}

        return matched_packets

    def reward(self, uids: list[int], labels_dict: dict) -> BatchRewardOutput:
        scores = []
        base_path = os.path.expanduser("~/tensorprox/tensorprox/rewards/pcap_files")

        for uid in uids:
            attack_path = os.path.join(base_path, f"{uid}/Attacker_capture.pcap")
            benign_path = os.path.join(base_path, f"{uid}/Attacker_capture.pcap")
            king_path = os.path.join(base_path, f"{uid}/King_capture.pcap")


            if not all(os.path.exists(path) for path in [attack_path, benign_path, king_path]):
                logging.warning(f"Missing files for UID {uid}. Skipping reward calculation.")
                scores.append(0.0)
                continue

            attack_counts = self.extract_labeled_counts(attack_path, labels_dict)
            benign_counts = self.extract_labeled_counts(benign_path, labels_dict)
            king_counts = self.extract_labeled_counts(king_path, labels_dict)

            attack_counts = {"BENIGN" : 0, "UDP_FLOOD" : 100, "TCP_SYN_FLOOD" : 0}
            benign_counts = {"BENIGN" : 100, "UDP_FLOOD" : 0, "TCP_SYN_FLOOD" : 0}
            king_counts = {"BENIGN" : 90, "UDP_FLOOD" : 20, "TCP_SYN_FLOOD" : 0}

            # Compute total attack packets sent by the Attacker during the challenge round
            total_attacks_sent = sum(attack_counts.get(label, 0) for label in ["TCP_SYN_FLOOD", "UDP_FLOOD"])

            # Compute total attack detections by the model (King)
            total_reaching_attacks = sum(king_counts.get(label, 0) for label in ["TCP_SYN_FLOOD", "UDP_FLOOD"])

            # Compute total benign packets
            total_benign_sent = benign_counts["BENIGN"]

            # Compute total benign samples misclassified as attacks
            total_reaching_benign = king_counts["BENIGN"]

            # Compute Attack Detection Accuracy (ADA)
            ADA = (total_attacks_sent - total_reaching_attacks) / total_attacks_sent if total_attacks_sent > 0 else 0

            # Compute False Positive Rate (FPR)
            FPR = (total_benign_sent - total_reaching_benign) / total_benign_sent if total_benign_sent > 0 else 0

            # Final reward calculation
            reward = 0.5 * ADA + 0.5 * (1 - FPR)
            scores.append(reward)

        return BatchRewardOutput(rewards=np.array(scores))
    

class BaseRewardConfig(BaseModel):

    default_labels: ClassVar[dict] = {
        "BENIGN": "BENIGN",
        "UDP_FLOOD": "UDP_FLOOD",
        "TCP_SYN_FLOOD": "TCP_SYN_FLOOD"
    }

    reward_model: ClassVar[ChallengeRewardModel] = ChallengeRewardModel()

    @classmethod
    def apply(
        cls,
        uids: list[int],
        labels_dict: dict = None  # Optional parameter
    ) -> ChallengeRewardEvent:
        
        # Use default labels if no custom labels_dict is provided
        labels_dict = labels_dict or cls.default_labels

        # Get the reward output
        batch_rewards_output = cls.reward_model.reward(uids, labels_dict)

        # Return the ChallengeRewardEvent using the BatchRewardOutput
        return ChallengeRewardEvent(
            rewards=batch_rewards_output.rewards.tolist(),
            uids=uids,
        )
