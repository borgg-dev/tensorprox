from requests import get
import sys
from datetime import datetime
import subprocess
import re
import logging
import os
import asyncio
import random
import time
import asyncssh
from typing import Tuple, Optional
from loguru import logger

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

def create_session_key_dir(path = "/var/tmp/session_keys") :

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

def create_random_playlist(seed=None, total_minutes=15):
    """
    Create a random playlist totaling a specified duration.

    Generates a playlist consisting of random activities ('pause' or a class type)
    with durations summing up to the specified total minutes.

    Args:
        total_minutes (int): The total duration of the playlist in minutes. Defaults to 15.
        seed (int, optional): The seed for the random number generator. If None, the seed is not set. Defaults to None.

    Returns:
        list: A list of dictionaries, each containing 'name' and 'duration' keys.
    """
    
    if seed is not None:
        random.seed(seed)
    
    type_class_map = {'a': "ClassA", 'b': "ClassB", 'c': "ClassC", 'd': "ClassD"}
    playlist = []
    current_total = 0
    while current_total < total_minutes:
        name = "pause" if random.random() < 0.5 else random.choice(list(type_class_map.keys()))
        duration = min(random.randint(1, 3), total_minutes - current_total)
        playlist.append({"name": name, "duration": duration})
        current_total += duration

    return playlist
 
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

async def run_cmd_async(conn: asyncssh.SSHClientConnection, cmd: str, ignore_errors: bool = True, logging_output=False, use_sudo: bool = True) -> object:
    """
    Executes a command on a remote machine asynchronously using SSH.

    Args:
        conn (asyncssh.SSHClientConnection): An active SSH connection.
        cmd (str): The command to execute.
        ignore_errors (bool, optional): Whether to suppress command errors. Defaults to True.
        use_sudo (bool, optional): Whether to run the command with sudo. Defaults to True.

    Returns:
        object: A response object with stdout, stderr, and exit_status.
    """

    escaped = cmd.replace("'", "'\\''")
    if use_sudo:
        final_cmd = f"sudo -S bash -c '{escaped}'"
    else:
        final_cmd = f"bash -c '{escaped}'"

    result = await conn.run(final_cmd, check=True)
    out = result.stdout.strip()
    err = result.stderr.strip()

    if err and not ignore_errors:
        log_message("WARNING", f"⚠️ Command error '{cmd}': {err}")
    elif out and logging_output:
        log_message("INFO", f"🔎 Command '{cmd}' output: {out}")

    # Create an object-like response with exit_status, stdout, and stderr
    return type('Result', (object,), {'stdout': out, 'stderr': err, 'exit_status': result.exit_status})()


async def create_and_test_connection(ip: str, private_key_path: str, username: str) -> Optional[asyncssh.SSHClientConnection]:
    """
    Establishes and tests an SSH connection using asyncssh.

    Args:
        ip (str): The target machine's IP address.
        private_key_path (str): The path to the private key used for authentication.
        username (str): The SSH user to authenticate as.

    Returns:
        Optional[asyncssh.SSHClientConnection]: The active SSH connection if successful, otherwise None.
    """

    try:
        client = await asyncssh.connect(ip, username=username, client_keys=[private_key_path], known_hosts=None)
        return client
    except asyncssh.Error as e:
        logger.error(f"SSH connection failed for {ip}: {str(e)}")
        return None

# Debug level (0=minimal, 1=normal, 2=verbose)
DEBUG_LEVEL = 2

def log(message, level=1):
    """Log message if debug level is sufficient"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    if DEBUG_LEVEL >= level:
        print("[{0}] {1}".format(timestamp, message))

def run_cmd(cmd, show_output=False, check=False, quiet=False, timeout=360, shell=False, async_mode=False, conn=None):
    """Run command and return result with environment variables support."""
    
    cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
    if not quiet:
        log("[CMD] {0}".format(cmd_str), level=1)
    
    # Handle shell commands differently
    if shell and isinstance(cmd, list):
        cmd = cmd_str
    
    # Set environment variables for apt operations
    env = os.environ.copy()
    if any(x in cmd_str for x in ['apt-get', 'apt', 'dpkg']):
        env['DEBIAN_FRONTEND'] = 'noninteractive'
    
    # For SSH remote execution, call run_cmd_async (this should be handled outside of run_cmd)
    if async_mode:
        if conn is not None:
            # Call run_cmd_async but don't await here, since we want it synchronous
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(run_cmd_async(conn, cmd_str, check, quiet, show_output))
            return result
        else:
            log("[ERROR] SSH connection is required for async execution.", level=1)
            return None
    
    # Synchronous execution (local execution)
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=shell, timeout=timeout, env=env)
        
        if result.returncode != 0 and result.stderr and "Cannot find device" not in result.stderr and "File exists" not in result.stderr and not quiet:
            log("[ERROR] {0}".format(cmd_str), level=1)
            log("stderr: {0}".format(result.stderr.strip()), level=1)
            if check:
                sys.exit(1)
        
        if show_output and result.stdout and not quiet:
            log(result.stdout, level=2)
            
        return result
    except subprocess.TimeoutExpired:
        log("[ERROR] Command timed out after {0} seconds: {1}".format(timeout, cmd_str), level=1)
        return subprocess.CompletedProcess(cmd, -1, "", "Timeout occurred")
    
def get_remaining_time(duration):
    current_time = time.time()
    next_event_time = ((current_time // duration) + 1) * duration
    remaining_time = next_event_time - current_time
    remaining_minutes = int(remaining_time // 60)
    remaining_seconds = int(remaining_time % 60)

    return f"{remaining_minutes}m {remaining_seconds}s"