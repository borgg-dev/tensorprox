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

# Store the path to the traffic generator script
TRAFFIC_GEN_PATH = os.path.join(BASE_DIR, "tensorprox", "core", "traffic_generator.py")

#Temporary paths
session_key_dir = "/var/tmp/session_keys"
REMOTE_TRAFFIC_GEN_PATH: str = '/tmp/traffic_generator.py'

#Miner global vars
ATTACKER_PUBLIC_IP: str = os.environ.get("ATTACKER_PUBLIC_IP")
BENIGN_PUBLIC_IP: str = os.environ.get("BENIGN_PUBLIC_IP")
KING_PUBLIC_IP: str = os.environ.get("KING_PUBLIC_IP")
ATTACKER_PRIVATE_IP: str = os.environ.get("ATTACKER_PRIVATE_IP")
BENIGN_PRIVATE_IP: str = os.environ.get("BENIGN_PRIVATE_IP")
KING_PRIVATE_IP: str = os.environ.get("KING_PRIVATE_IP")
MOAT_PRIVATE_IP: str = os.environ.get("MOAT_PRIVATE_IP")
FORWARD_PORT: int = os.environ.get("FORWARD_PORT", 8080)
ATTACKER_IFACE: str = os.environ.get("ATTACKER_IFACE", "eth0")
ATTACKER_USERNAME: str = os.environ.get("ATTACKER_USERNAME", "root")
BENIGN_IFACE: str = os.environ.get("BENIGN_IFACE", "eth0")
BENIGN_USERNAME: str = os.environ.get("BENIGN_USERNAME", "root")
KING_IFACE: str = os.environ.get("KING_IFACE", "eth0")
KING_USERNAME: str = os.environ.get("KING_USERNAME", "root")
MOAT_IFACE: str = os.environ.get("MOAT_IFACE", "eth0")

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

# XDP program paths
XDP_PROGRAM_DIR = "/opt/af_xdp_tools"
XDP_LOG_DIR = "/var/log/tunnel"