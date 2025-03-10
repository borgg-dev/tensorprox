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
session_key_dir = "/var/tmp/session_keys"