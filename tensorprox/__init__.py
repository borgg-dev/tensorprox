import os

def _version_to_int(version_str: str) -> int:
    version_split = version_str.split(".") + ["0", "0"]
    major = int(version_split[0])
    minor = int(version_split[1])
    patch = int(version_split[2])
    return (10000 * major) + (100 * minor) + patch

#Release version
__version__ = "0.1.0" 
__spec_version__ = _version_to_int(__version__)

#Inner parameters
EPSILON: int = 15
DELTA: int = 15
CHALLENGE_DURATION: int = 60 #15 minutes
NODE_TYPES = ["attacker", "benign", "king", "moat"]

#Timeouts
ROUND_TIMEOUT: int = 300 #150 blocks / 30 minutes
INITIAL_SETUP_TIMEOUT: int = 30 # 30 seconds
LOCKDOWN_TIMEOUT: int = 60
GRE_SETUP_TIMEOUT: int = 180
CHALLENGE_TIMEOUT: int = CHALLENGE_DURATION + DELTA
REVERT_TIMEOUT: int = 60

# Store the base path dynamically, assuming `tensorprox` is the base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#Default validator user on remote machines
RESTRICTED_USER = "valiops"

#Temporary path for session_keys storage
SESSION_KEY_DIR = "/var/tmp/session_keys"

# Fixed overlay network IPs
BENIGN_OVERLAY_IP = "10.200.77.102"
ATTACKER_OVERLAY_IP = "10.200.77.103"
KING_OVERLAY_IP = "10.200.77.1"
