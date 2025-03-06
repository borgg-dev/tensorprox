from requests import get
import subprocess
import re
import logging
import os
import asyncio
from typing import Tuple
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings

def is_valid_ip(ip: str) -> bool:
    """
    Validates whether the given string is a valid IPv4 address.

    Args:
        ip (str): The IP address to validate.

    Returns:
        bool: True if valid, False otherwise.
    """

    if not isinstance(ip, str):  # Check if ip is None or not a string
        return False
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?\d?\d?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?\d?\d?)$"
    return re.match(pattern, ip) is not None

def get_public_ip() -> str:
    """
    Retrieves the external machine's public IP address if available.
    Falls back to all IPs if the public IP cannot be retrieved.

    Returns:
        str: The detected IP address, or "0.0.0.0" if unavailable.
    """

    try:
        public_ip = get('https://api.ipify.org').text.strip()
        if is_valid_ip(public_ip):
            return public_ip
    except Exception:
        pass
    return "0.0.0.0"

def get_local_ip() -> str:
    """
    Retrieves the local machine's private IP address if available.
    Falls back to the default localhost IP if the public IP cannot be retrieved.

    Returns:
        str: The detected IP address, or "127.0.0.1" if unavailable.
    """

    try:
        local_ip = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
        if is_valid_ip(local_ip):
            return local_ip
    except:
        pass
    return "127.0.0.1"


def log_message(level: str, message: str):
    """
    Logs a message with the specified logging level.

    Args:
        level (str): The logging level (INFO, WARNING, ERROR, DEBUG).
        message (str): The message to log.
    """

    if level.upper() == "INFO":
        logging.info(message)
    elif level.upper() == "WARNING":
        logging.warning(message)
    elif level.upper() == "ERROR":
        logging.error(message)
    else:
        logging.debug(message)

def get_authorized_keys_dir(ssh_user: str) -> str:
    """
    Retrieves the correct .ssh directory path based on the SSH user.

    Args:
        ssh_user (str): The username of the SSH user.

    Returns:
        str: The absolute path to the .ssh directory.
    """

    return "/root/.ssh" if ssh_user == "root" else f"/home/{ssh_user}/.ssh"

def create_session_key_dir(path = settings.SESSION_KEY_DIR) :

    if not os.path.exists(path):
        try:
            os.makedirs(path, mode=0o700, exist_ok=True)
        except PermissionError as e:
            #log_message("ERROR", f"Permission denied while creating {SESSION_KEY_DIR}: {e}")
            raise
        except Exception as e:
            #log_message("ERROR", f"Unexpected error while creating {SESSION_KEY_DIR}: {e}")
            raise

def save_private_key(priv_key_str: str, path: str):
    """
    Saves a private SSH key to a specified file with secure permissions.

    Args:
        priv_key_str (str): The private key content.
        path (str): The file path where the private key should be stored.
    """

    try:
        with open(path, "w") as f:
            f.write(priv_key_str)
        os.chmod(path, 0o600)
        # log_message("INFO", f"Saved private key to {path}")
    except Exception as e:
        # log_message("ERROR", f"Error saving private key: {e}")
        pass
    
async def generate_local_session_keypair(key_path: str) -> Tuple[str, str]:
    """
    Asynchronously generates an ED25519 SSH key pair and stores it securely.

    Args:
        key_path (str): The file path where the private key should be stored.

    Returns:
        Tuple[str, str]: A tuple containing the private and public keys as strings.
    """

    if os.path.exists(key_path):
        os.remove(key_path)
    if os.path.exists(f"{key_path}.pub"):
        os.remove(f"{key_path}.pub")
    
    # log_message("INFO", "🚀 Generating session ED25519 keypair...")
    proc = await asyncio.create_subprocess_exec(
        "ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", "",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await proc.communicate()  # Wait for completion

    os.chmod(key_path, 0o600)
    if os.path.exists(f"{key_path}.pub"):
        os.chmod(f"{key_path}.pub", 0o644)
    
    with open(key_path, "r") as fk:
        priv = fk.read().strip()
    with open(f"{key_path}.pub", "r") as fpk:
        pub = fpk.read().strip()
    
    # log_message("INFO", "✅ Session keypair generated and secured.")
    return priv, pub
