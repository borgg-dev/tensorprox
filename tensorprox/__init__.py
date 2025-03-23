import os

def _version_to_int(version_str: str) -> int:
    version_split = version_str.split(".") + ["0", "0"]
    major = int(version_split[0])
    minor = int(version_split[1])
    patch = int(version_split[2])
    return (10000 * major) + (100 * minor) + patch

__version__ = "0.1.0" 

__spec_version__ = _version_to_int(__version__)

labels = ["BENIGN", "UDP_FLOOD", "TCP_SYN_FLOOD"]
node_types = ["attacker", "benign", "king", "moat"]

ROUND_TIMEOUT: int = 240 #150 blocks / 30 minutes
CHALLENGE_DURATION: int = 60 #15 minutes
EPSILON: int = 30
TASK_TYPES = ['initial_setup', 'lockdown', 'revert', 'challenge', 'gre_setup']

# Store the base path dynamically, assuming `tensorprox` is the base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#Temporary paths
SESSION_KEY_DIR = "/var/tmp/session_keys"
REMOTE_TRAFFIC_GEN_PATH: str = '/tmp/traffic_generator.py'

# ===== GRE CONFIGURATION =====
# Fixed overlay network IPs
BENIGN_OVERLAY_IP = "10.200.77.102"
ATTACKER_OVERLAY_IP = "10.200.77.103"
KING_OVERLAY_IP = "10.200.77.1"

