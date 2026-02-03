"""
TensorProx Subnet - Decentralized DDoS Protection Network

A Bittensor subnet for incentivized, distributed DDoS mitigation
using eBPF/XDP-based scrubbers competing on performance metrics.
"""

__version__ = "1.0.0"
__version_as_int__ = 10000

# Network constants
NETUID = 91  # TensorProx subnet ID
SPEC_VERSION = 1

# Timing constants (in seconds)
EPSILON = 180  # 3 minutes buffer
DELTA = 420  # 7 minutes base operation time

# Round timing
AVAILABILITY_CHECK_TIMEOUT = 60  # 60 seconds for ping (increased for cross-region miners)
SCRUBBER_SETUP_TIMEOUT = 480  # 8 minutes (scrubber bootstrap)
CHALLENGE_DURATION = 900  # 15 minutes
LOCKDOWN_TIMEOUT = 120  # 2 minutes

# Total round time
ROUND_TIMEOUT = (
    AVAILABILITY_CHECK_TIMEOUT
    + SCRUBBER_SETUP_TIMEOUT
    + CHALLENGE_DURATION
    + LOCKDOWN_TIMEOUT
)  # ~28 minutes

EPOCH_TIME = ROUND_TIMEOUT + EPSILON  # ~31 minutes

# Scrubber capacity
MIN_SCRUBBERS = 1
MAX_SCRUBBERS = 8
DEFAULT_SCRUBBERS = 2

# Health reporting
HEALTH_REPORT_INTERVAL = 30  # seconds
HEALTH_STALE_THRESHOLD = 120  # seconds

# BPF map names
BPF_MAP_NAMES = [
    "blacklist_map",
    "whitelist_map",
    "ratelimit_map",
    "quarantine_map",
    "eip_map",
    "challenge_level_map",
    "machine_limits_map",
    "xdp_wan_stats",
]

# Default machine types per provider
DEFAULT_SCRUBBER_INSTANCE_TYPES = {
    "aws": "t3.medium",
    "linode": "g6-standard-2",
}

DEFAULT_SCRUBBER_REGIONS = {
    "aws": "eu-central-1",
    "linode": "us-east",
}

#Burn parameters
BURN_UID = 0
BURN_WEIGHT = 0.8