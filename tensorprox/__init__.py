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
node_types = ["Attacker", "Benign", "King", "Moat"]

ROUND_TIMEOUT: int = 240 #150 blocks / 30 minutes
CHALLENGE_DURATION: int = 60 #15 minutes
EPSILON: int = 30

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

# Fixed GRE tunnel keys
BENIGN_MOAT_KEY = "77"
ATTACKER_MOAT_KEY = "79"
MOAT_KING_KEY = "88"

# MTU Sizing 
GRE_MTU = 1465  # Standard MTU 1500 - 25 GRE - 10 random Buffer
IPIP_MTU = 1445  # GRE_MTU - 20 for IPIP overhead

# Determine if running as root once at startup
IS_ROOT = os.geteuid() == 0

# Use user-specific paths for non-root users
if IS_ROOT:
    # Root user can use system paths
    XDP_PROGRAM_DIR = "/opt/af_xdp_tools"
    XDP_LOG_DIR = "/var/log/tunnel"
else:
    # Non-root user gets paths in home directory
    HOME_DIR = os.path.expanduser("~")
    XDP_PROGRAM_DIR = os.path.join(HOME_DIR, ".tensorprox", "af_xdp_tools")
    XDP_LOG_DIR = os.path.join(HOME_DIR, ".tensorprox", "logs", "tunnel")