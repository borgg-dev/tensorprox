"""
================================================================================
TensorProx Miner Availability and SSH Session Setup

This script provides functionalities for managing miner availability, handling
SSH session setup, and automating firewall rule adjustments for Bittensor miners.
It utilizes asyncssh for efficient asynchronous SSH connections and ensures 
secure access control through key management.

--------------------------------------------------------------------------------
FEATURES:
- **Logging & Debugging:** Provides structured logging via Loguru and Python’s 
  built-in logging module.
- **SSH Session Management:** Supports key-based authentication, session key 
  generation, and automated secure key insertion.
- **Firewall & System Utilities:** Ensures miners have necessary dependencies 
  installed, configures firewall rules, and manages sudo privileges.
- **Miner Availability Tracking:** Maintains a live status of miners' readiness 
  using the PingSynapse protocol.
- **Resilient Command Execution:** Executes commands safely with error handling 
  to prevent system lockouts.
- **Asynchronous Execution:** Uses asyncio and asyncssh for efficient remote 
  command execution and key management.

--------------------------------------------------------------------------------
USAGE:
1. **Miner Availability Tracking**  
   The `MinerManagement` class tracks the status of miners via the 
   `PingSynapse` protocol.
   
2. **SSH Session Key Management**  
   - Generates an ED25519 session key pair.
   - Inserts the session key into the authorized_keys file of remote miners.
   - Establishes an SSH session using the generated key.
   - Automates firewall and system setup tasks.

3. **Remote Configuration Management**  
   - Installs missing packages required for network security.
   - Ensures `iptables` and other network security tools are available.
   - Configures passwordless sudo execution where necessary.

--------------------------------------------------------------------------------
DEPENDENCIES:
- Python 3.10
- `asyncssh`: For managing SSH connections asynchronously.
- `paramiko`: Fallback for SSH key handling.
- `pydantic`: For structured data validation.
- `loguru`: Advanced logging capabilities.

--------------------------------------------------------------------------------
SECURITY CONSIDERATIONS:
- The script enforces strict permissions on session keys.
- Firewall configurations and sudo privileges are managed carefully.
- SSH keys are handled securely to prevent exposure.

License:
This software is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0).
You are free to use, share, and modify the code for non-commercial purposes only.

Commercial Usage:
The only authorized commercial use of this software is for mining or validating within the TensorProx subnet.
For any other commercial licensing requests, please contact Shugo LTD.

See the full license terms here: https://creativecommons.org/licenses/by-nc/4.0/

Author: Shugo LTD
Version: 0.1.0

================================================================================
"""

#!/usr/bin/env python3

import asyncio
import os
import random
from typing import List, Dict, Tuple, Union, Optional, Callable
from loguru import logger
from pydantic import BaseModel
from datetime import datetime, timedelta
import time
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse, MachineDetails
from tensorprox.base.loop_runner import AsyncLoopRunner
from tensorprox.settings import settings
from tensorprox.utils.uids import get_uids, extract_axons_ips
from tensorprox.utils.timer import Timer
from tensorprox.base.protocol import MachineConfig
import dotenv
import paramiko
from paramiko import RSAKey
from paramiko.ed25519key import Ed25519Key
import io
import re
import logging
from functools import partial
import asyncssh
import traceback
from tensorprox.core.session_commands import (
    get_insert_key_cmd,
    get_sudo_setup_cmd,
    get_revert_script_cmd,
    get_lockdown_cmd,
    get_pcap_file_cmd
)


######################################################################
# 1) LOCAL FUNCTIONS / UTILITIES
######################################################################

dotenv.load_dotenv()

# Disable all asyncssh logging by setting its level to CRITICAL
asyncssh_logger = logging.getLogger('asyncssh')
asyncssh_logger.setLevel(logging.CRITICAL)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

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


def get_local_ip() -> str:
    """
    Retrieves the local machine's public IP address if available.
    Falls back to the internal IP if the public IP cannot be retrieved.

    Returns:
        str: The detected IP address, or "127.0.0.1" if unavailable.
    """

    try:
        import requests
        public_ip = requests.get('https://api.ipify.org').text.strip()
        if is_valid_ip(public_ip):
            return public_ip
    except Exception:
        pass
    try:
        import subprocess
        local_ip = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
        if is_valid_ip(local_ip):
            return local_ip
    except:
        pass
    return "127.0.0.1"

SESSION_KEY_DIR = "/var/tmp/session_keys"

if not os.path.exists(SESSION_KEY_DIR):
    try:
        os.makedirs(SESSION_KEY_DIR, mode=0o700, exist_ok=True)
        log_message("INFO", f"Created session key directory at {SESSION_KEY_DIR}")
    except PermissionError as e:
        log_message("ERROR", f"Permission denied while creating {SESSION_KEY_DIR}: {e}")
        raise
    except Exception as e:
        log_message("ERROR", f"Unexpected error while creating {SESSION_KEY_DIR}: {e}")
        raise

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
    
    log_message("INFO", "🚀 Generating session ED25519 keypair...")
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
    
    log_message("INFO", "✅ Session keypair generated and secured.")
    return priv, pub


######################################################################
# 2) SUPPORTING UTILS
######################################################################

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

async def install_packages_if_missing(client: asyncssh.SSHClientConnection, packages: List[str]):
    """
    Checks for missing system packages and installs them if necessary.

    Args:
        client (asyncssh.SSHClientConnection): An active SSH client connection.
        packages (List[str]): A list of package names to verify and install if missing.

    """

    for pkg in packages:
        check_cmd = f"dpkg -s {pkg} >/dev/null 2>&1"
        result = await client.run(check_cmd, check=False)

        if result.exit_status != 0:
            log_message("INFO", f"📦 Package '{pkg}' missing => installing now...")
            await client.run("DEBIAN_FRONTEND=noninteractive apt-get update -qq || true", check=False)
            await client.run(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg}", check=False)
            await asyncio.sleep(1)

def get_authorized_keys_dir(ssh_user: str) -> str:
    """
    Retrieves the correct .ssh directory path based on the SSH user.

    Args:
        ssh_user (str): The username of the SSH user.

    Returns:
        str: The absolute path to the .ssh directory.
    """

    return "/root/.ssh" if ssh_user == "root" else f"/home/{ssh_user}/.ssh"


        
######################################################################
# ASYNCHRONOUS WRAPPER & ADDITIONAL UTILITIES
######################################################################

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


class MinerManagement(BaseModel):
    """
    Tracks the availability of miners using the PingSynapse protocol.
    
    Attributes:
        miners (Dict[int, PingSynapse]): A dictionary mapping miner UIDs to their availability status.
        ip (str): The local IP address of the machine running this instance.
    """

    miners: Dict[int, 'PingSynapse'] = {}
    local_ip: str = get_local_ip()


    def check_machine_availability(self, machine_name: str = None, uid: int = None) -> bool:
        """
        Checks whether a specific miner machine is available.

        Args:
            machine_name (str, optional): The machine name to check. Defaults to None.
            uid (int, optional): The UID of the miner. Defaults to None.

        Returns:
            bool: True if the machine is available, False otherwise.
        """

        if machine_name == "Moat":
            return True  #Skip Moat
        ip_machine = self.miners[uid].machine_availabilities[machine_name]
        return bool(ip_machine)


    def is_miner_ready(self, uid: int = None) -> bool:
        """
        Checks if a miner is fully ready by verifying all associated machines.

        Args:
            uid (int, optional): The UID of the miner. Defaults to None.

        Returns:
            bool: True if all machines are available, False otherwise.
        """

        for machine_name in self.miners[uid].machine_availabilities.keys():
            if machine_name == "Moat":
                continue  #Skip Moat
            if not self.check_machine_availability(machine_name=machine_name, uid=uid):
                return False
        return True
    

    def get_uid_status_availability(self, k: int = None) -> List[int]:
        """
        Retrieves a list of available miners.

        Args:
            k (int, optional): The number of available miners to return. Defaults to None.

        Returns:
            List[int]: A list of UIDs of available miners.
        """

        available = [uid for uid in self.miners.keys() if self.is_miner_ready(uid)]
        if k:
            available = random.sample(available, min(len(available), k))
        return available

    async def async_setup(self, ip: str, ssh_user: str, key_path: str, machine_name: str, uid: int, user_commands: List[str], backup_suffix: str) -> bool:
        """
        Performs a single-pass SSH session setup on a remote miner. This includes generating session keys,
        configuring passwordless sudo, installing necessary packages, and executing user-defined commands.

        Args:
            ip (str): The IP address of the miner to set up.
            ssh_user (str): The SSH user account on the miner.
            key_path (str): Path to the original SSH key used for initial access.
            machine_name (str): Name of the machine being set up.
            uid (int): Unique identifier for the miner.
            user_commands (List[str]): List of custom user commands to execute during the setup.
            backup_suffix (str): Suffix used for backing up the SSH configuration files.

        Returns:
            bool: True if the setup was successful, False if an error occurred.
        """

        logger.info(f"⚙️ Single-pass session setup for {machine_name} with {ip} as '{ssh_user}' start...")

        # A) CONNECT WITH ORIGINAL KEY + PREPARE
        logger.info(f"🌐 Step A: Generating session key + connecting with original SSH key on {ip}...")
        session_key_path = os.path.join(SESSION_KEY_DIR, f"session_key_{uid}_{ip}")
        session_priv, session_pub = await generate_local_session_keypair(session_key_path)

        try:
            # Step A: Connect to the remote machine
            async with asyncssh.connect(ip, username=ssh_user, client_keys=[key_path], known_hosts=None) as conn:
                logger.info(f"✅ Connected to {ip} with original key.")

                # Test sudo availability
                await run_cmd_async(conn, "echo 'SUDO_TEST'")

                # Install necessary packages
                needed = ["net-tools", "iptables-persistent", "psmisc"]
                await install_packages_if_missing(conn, needed)

                # Set up sudoers file for no TTY
                no_tty_cmd = f"echo 'Defaults:{ssh_user} !requiretty' > /etc/sudoers.d/98_{ssh_user}_no_tty"
                await run_cmd_async(conn, no_tty_cmd)

                logger.info(f"🔐 Step B: Inserting session key into authorized_keys and refreshing backup.")
                ssh_dir = get_authorized_keys_dir(ssh_user)
                authorized_keys_path = f"{ssh_dir}/authorized_keys"
                authorized_keys_bak = f"{ssh_dir}/authorized_keys.bak_{backup_suffix}"
                insert_key_cmd = get_insert_key_cmd(ssh_user, ssh_dir, session_pub, authorized_keys_path, authorized_keys_bak)
                await run_cmd_async(conn, insert_key_cmd)
                logger.info(f"✅ Session key inserted. Backup stored at {authorized_keys_bak}.")

            logger.info(f"🔒 Original SSH connection closed for {ip} (user={ssh_user}).")

            # C) TEST SESSION KEY
            logger.info(f"🔑 Step C: Testing session SSH key on {ip} to confirm new session.")
            async with asyncssh.connect(ip, username=ssh_user, client_keys=[session_key_path], known_hosts=None) as ep_conn:
                logger.info(f"✨ Session key success for {ip}.")

                # D) PREPARE REVERT SCRIPT, CLEAN STALE SUDOERS, & SCHEDULE REVERT VIA SYSTEMD TIMER
                logger.info("🧩 Step D: Setting up passwordless sudo & running user commands.")
                revert_cleanup_cmd = f"rm -f /etc/sudoers.d/97_{ssh_user}_revert*"
                await run_cmd_async(ep_conn, revert_cleanup_cmd, ignore_errors=True)

                sudo_setup_cmd = get_sudo_setup_cmd(ssh_user)
                await run_cmd_async(ep_conn, sudo_setup_cmd)

                if user_commands:
                    logger.info(f"🛠 Running custom user commands for role on {ip}.")
                    for uc in user_commands:
                        await run_cmd_async(ep_conn, uc, ignore_errors=True)

                logger.info(f"✅ Done single-pass session setup for {ip}.")

            return True

        except Exception as e:
            logger.error(f"❌ Failed to complete session setup for {ip}: {e}")
            return False
    
    async def async_lockdown(self, ip: str, ssh_user: str, key_path: str, machine_name: str, ssh_dir: str, authorized_keys_path: str) -> bool:
        """
        Initiates a lockdown procedure on a remote miner by executing a lockdown command over SSH.

        Args:
            ip (str): The IP address of the miner to lock down.
            ssh_user (str): The SSH user account on the miner.
            key_path (str): Path to the SSH key used for authentication.
            machine_name (str): Name of the machine being locked down.
            ssh_dir (str): Path to the directory containing the authorized SSH keys.
            authorized_keys_path (str): Path to the authorized_keys file on the miner.

        Returns:
            bool: True if the lockdown was successfully executed, False if an error occurred.
        """

        logger.info(f"🔒 Lockdown for {ip} as '{ssh_user}' start...")

        try:

            # Use create_and_test_connection for SSH connection
            client = await create_and_test_connection(ip, key_path, ssh_user)

            if not client:
                logger.error(f"🚨 SSH connection failed for {machine_name} ({ip})")
                return False

            # Run lockdown command
            lockdown_cmd = get_lockdown_cmd(ssh_user, ssh_dir, self.local_ip, authorized_keys_path)
            result = await run_cmd_async(client, lockdown_cmd)

            if result.exit_status == 0:
                logger.info(f"✅ Lockdown command executed successfully on {ip}")
            else:
                logger.error(f"❌ Lockdown command failed on {ip}: {result.stderr}")
        
            return True

        except Exception as e:
            logger.error(f"🚨 Failed to revert machine {machine_name} for miner: {e}")
            return False


    async def async_revert(self, ip: str, ssh_user: str, key_path: str, machine_name: str, authorized_keys_path: str, authorized_keys_bak: str, revert_log: str) -> bool:
        """
        Reverts the SSH configuration changes on a remote miner by restoring the backup of authorized keys.

        Args:
            ip (str): The IP address of the miner to revert.
            ssh_user (str): The SSH user account on the miner.
            key_path (str): Path to the SSH key used for authentication.
            machine_name (str): Name of the machine being reverted.
            authorized_keys_path (str): Path to the authorized_keys file on the miner.
            authorized_keys_bak (str): Path to the backup of the authorized_keys file.
            revert_log (str): Path to the log file where revert actions are recorded.

        Returns:
            bool: True if the revert was successful, False if an error occurred.
        """ 

        try:

            revert_cmd = get_revert_script_cmd(ip, authorized_keys_bak, authorized_keys_path, revert_log)

            # Use create_and_test_connection for SSH connection
            client = await create_and_test_connection(ip, key_path, ssh_user)

            if not client:
                logger.error(f"🚨 SSH connection failed for {machine_name} ({ip})")
                return False

            # Run revert command
            result = await run_cmd_async(client, revert_cmd)
            if result.exit_status == 0:
                logger.info(f"✅ Revert command executed successfully on {ip}")
            else:
                logger.error(f"❌ Revert command failed on {ip}: {result.stderr}")
        
            return True

        except Exception as e:
            logger.error(f"🚨 Failed to revert machine {machine_name} for miner: {e}")
            return False


    async def async_challenge(self, ip: str, ssh_user: str, key_path: str, machine_name: str, uid:int, validator_key_path: str, validator_username: str, challenge_duration: int) -> bool:
        """
        Title: Run Challenge Commands on Miner

        Executes challenge-related commands on a remote miner. This involves reading the validator's private key,
        running the challenge script, and reporting the outcome.

        Args:
            ip (str): The IP address of the miner where the challenge commands will be run.
            ssh_user (str): The SSH user account on the miner.
            key_path (str): Path to the SSH key used for authentication.
            machine_name (str): Name of the machine to challenge.
            uid (int): Unique identifier for the miner.
            validator_key_path (str): Path to the validator's private key for authentication.
            validator_username (str): Username of the validator running the challenge.
            challenge_duration (int): Duration for which the challenge should run, in seconds.

        Returns:
            bool: True if the challenge was successfully executed, False if an error occurred.
        """

        try:

            try:
                # Open and read the private key file
                with open(validator_key_path, "r") as key_file:
                    validator_private_key = key_file.read()
            except Exception as e:
                logger.error(f"❌ Error reading private key: {e}")

            pcap_cmd = get_pcap_file_cmd(uid, validator_username, validator_private_key, self.local_ip, challenge_duration, machine_name)

            # Use create_and_test_connection for SSH connection
            client = await create_and_test_connection(ip, key_path, ssh_user)

            if not client:
                logger.error(f"🚨 SSH connection failed for {machine_name} ({ip})")
                return False

            # Run revert command
            result = await run_cmd_async(client, pcap_cmd)
            if result.exit_status == 0:
                logger.info(f"✅ Run challenge commands executed successfully on {ip}")
            else:
                logger.error(f"❌ Run challenged commands failed on {ip}: {result.stderr}")
        
            return True

        except Exception as e:
            logger.error(f"🚨 Failed to run commands on {machine_name} for miner {uid} : {e}")
            return False
    
    async def query_availability(self, uid: int) -> Tuple['PingSynapse', Dict[str, Union[int, str]]]:
        """Query the availability of a given UID.
        
        This function attempts to retrieve machine availability information for a miner
        identified by `uid`. It validates the response, checks for SSH key pairs, and 
        verifies SSH connectivity to each machine.
        
        Args:
            uid (int): The unique identifier of the miner.

        Returns:
            Tuple[PingSynapse, Dict[str, Union[int, str]]]:
                - A `PingSynapse` object containing the miner's availability details.
                - A dictionary with the UID's availability status, including status code and message.
        """

        # Initialize a dummy synapse for example purposes
        synapse = PingSynapse(machine_availabilities=MachineConfig())
        uid, synapse = await self.dendrite_call(uid, synapse)

        uid_status_availability = {"uid": uid, "ping_status_message" : None, "ping_status_code" : None}

        if synapse is None:
            uid_status_availability["ping_status_message"] = "Query failed."
            uid_status_availability["ping_status_code"] = 500
            return synapse, uid_status_availability

        if not synapse.machine_availabilities.key_pair:
            # logger.error(f"❌ Missing SSH Key Pair for UID {uid}, marking as unavailable.")
            uid_status_availability["ping_status_message"] = "Missing SSH Key Pair."
            uid_status_availability["ping_status_code"] = 400
            return synapse, uid_status_availability

        # Extract SSH key pair safely
        ssh_pub, ssh_priv = synapse.machine_availabilities.key_pair
        original_key_path = f"/var/tmp/original_key_{uid}.pem"
        save_private_key(ssh_priv, original_key_path)

        all_machines_available = True

        for machine_name, machine_details in synapse.machine_availabilities.machine_config.items():

            if machine_name == "Moat":
                continue  # Skip the Moat machine

            ip = machine_details.ip
            ssh_user = machine_details.username

            if not is_valid_ip(ip):
                # logger.error(f"🚨 Invalid IP {ip} for {machine_name}, marking UID {uid} as unavailable.")
                all_machines_available = False
                uid_status_availability["ping_status_message"] = "Invalid IP format."
                uid_status_availability["ping_status_code"] = 400
                break

            # Test SSH Connection with asyncssh
            client = await create_and_test_connection(ip, original_key_path, ssh_user)
            if not client:
                # logger.error(f"🚨 SSH connection failed for {machine_name} ({ip}) UID {uid}")
                all_machines_available = False
                uid_status_availability["ping_status_message"] = "SSH connection failed."
                uid_status_availability["ping_status_code"] = 500
                break

        if all_machines_available:
            uid_status_availability["ping_status_message"] = f"✅ All machines are accessible for UID {uid}."
            uid_status_availability["ping_status_code"] = 200

        return synapse, uid_status_availability


    async def dendrite_call(self, uid: int, synapse: Union[PingSynapse, ChallengeSynapse], timeout: int = settings.NEURON_TIMEOUT):
        """
        Query a single miner's availability.
            
        Args:
            uid (int): Unique identifier for the miner.
            synapse (Union[PingSynapse, ChallengeSynapse]): The synapse message to send.
            timeout (int, optional): Timeout duration in seconds. Defaults to settings.NEURON_TIMEOUT.
        
        Returns:
            Tuple[int, Optional[Response]]: The miner's UID and response, if available.
        """

        default_synapse = PingSynapse(key_pair = ("",""), machine_config = {name: MachineDetails() for name in ["Attacker", "King", "Moat"]})
        try:

            # Check if the uid is within the valid range for the axons list
            if uid < len(settings.METAGRAPH.axons):
                axon = settings.METAGRAPH.axons[uid]
            else:
                return uid, default_synapse

            response = await settings.DENDRITE(
                axons=[axon],
                synapse=synapse,
                timeout=timeout,
                deserialize=False,
            )
            return uid, response[0] if response else default_synapse

        except Exception as e:
            logger.error(f"❌ Failed to query miner {uid}: {e}\n{traceback.format_exc()}")
            return uid, default_synapse
            

    async def check_machines_availability(self, uids: List[int]) -> Tuple[List[PingSynapse], List[dict]]:
        """
        Asynchronously checks the availability of a list of miners by their unique IDs.

        This method queries each miner's status concurrently and aggregates the results.

        Args:
            uids (List[int]): A list of unique identifiers (UIDs) corresponding to the miners.

        Returns:
            Tuple[List[Synapse], List[dict]]: 
                - A list of Synapse responses from each miner.
                - A list of dictionaries containing availability status for each miner.
        """
        tasks = [self.check_miner(uid) for uid in uids]  # Call the existing check_miner method
        results = await asyncio.gather(*tasks)
        
        if results:
            synapses, all_miners_availability = zip(*results)
        else:
            synapses, all_miners_availability = [], []

        return list(synapses), list(all_miners_availability)

    async def check_miner(self, uid: int) -> Tuple[PingSynapse, dict]:
        """
        Checks the status and availability of a specific miner.

        Args:
            uid (int): Unique identifier of the miner.

        Returns:
            Tuple[Synapse, dict]: A tuple containing the synapse response and miner's availability status.
        """
        synapse, uid_status_availability = await self.query_availability(uid)  
        return synapse, uid_status_availability
    
    async def execute_task(
        self, 
        task: str,
        miners: List[Tuple[int, 'PingSynapse']],
        assigned_miners: list[int],
        task_function: Callable[..., bool],
        backup_suffix: str = '', 
        challenge_duration: int = 60,
        timeout: int = 240
    ) -> List[Dict[str, Union[int, str]]]:
        """
        A generic function to execute different tasks (such as setup, lockdown, revert, challenge) on miners. 
        This function orchestrates the process of executing the provided task on multiple miners in parallel, 
        handling individual machine configurations, and ensuring each miner completes the task within a specified timeout.

        Args:
            task (str): The type of task to perform. Possible values are:
                'setup': Setup the miner environment (e.g., install dependencies).
                'lockdown': Lockdown the miner, restricting access or making it inaccessible.
                'revert': Revert any changes made to the miner (restore to a previous state).
                'challenge': Run a challenge procedure on the miner.
            miners (List[Tuple[int, PingSynapse]]): List of miners represented as tuples containing the unique ID (`int`) 
                                                    and the `PingSynapse` object, which holds machine configuration details.
            assigned_miners (list[int]): List of miner IDs assigned for the task. Used for tracking miners not available 
                                        during the task execution.
            task_function (Callable[..., bool]): The function that should be used to perform the task on each miner.
                                                It will be passed additional arguments specific to each task type.
            backup_suffix (str, optional): A suffix for backup operations, typically used for reversion or setup purposes. 
                                            Defaults to an empty string.
            challenge_duration (int, optional): Duration (in seconds) for the challenge task to run. Defaults to 60 seconds.
            timeout (int, optional): Timeout duration for the task to complete for each miner, in seconds. Defaults to 30 seconds.

        Returns:
            List[Dict[str, Union[int, str]]]: A list of dictionaries containing the task status for each miner.
            Each dictionary includes the `uid` of the miner and the status code/message 
            indicating whether the task was successful or encountered an issue.
            200: Success.
            500: Failure (task failed on the miner).
            408: Timeout error (task did not complete in time).
            503: Service Unavailable (miner not available for the task).
        """
            
        task_status = {}
        role_cmds = {
            "Attacker": ["sudo apt-get update -qq || true"],
            "Benign": ["sudo apt update", "sudo apt install -y npm"],
            "King": ["sudo apt update", "sudo apt install -y npm"],
        }


        async def process_miner(uid, synapse, task_function):
            """
            Process all machines for a given miner and apply the specified task.

            Args:
                uid (int): Miner's unique ID.
                synapse (PingSynapse): Miner's machine configurations.
                task_function (Callable[..., bool]): Task function to apply to each machine.

            Returns:
                None: Updates task status for each machine.
            """

            async def process_machine(machine_name, machine_details, task_function):
                """
                Apply task to a specific machine.

                Args:
                    machine_name (str): Name of the machine (e.g., "Moat").
                    machine_details (object): Machine connection details.
                    task_function (Callable[..., bool]): Task function to apply.

                Returns:
                    bool: True if the task succeeds, False otherwise.
                """

                if machine_name == "Moat":
                    return True  # Skip Moat machine setup and consider it successful

                ip = machine_details.ip
                ssh_user = machine_details.username
                ssh_dir = get_authorized_keys_dir(ssh_user)
                authorized_keys_path = f"{ssh_dir}/authorized_keys"
                key_path = f"/var/tmp/original_key_{uid}.pem" if task == "setup" else os.path.join(SESSION_KEY_DIR, f"session_key_{uid}_{ip}")
                authorized_keys_bak = f"{ssh_dir}/authorized_keys.bak_{backup_suffix}"
                revert_log = f"/tmp/revert_log_{uid}_{backup_suffix}.log"
                user_commands = role_cmds.get(machine_name, [])
                validator_key_path = os.environ.get("VALIDATOR_KEY_PATH")    # Get the path of the private key from environment variable
                validator_username = os.getlogin()

                # Map task function to a version with specific arguments
                if task == "setup":
                    task_function = partial(task_function, uid=uid, user_commands=user_commands, backup_suffix=backup_suffix)
                elif task == "lockdown":
                    # Example for lockdown task - you can define the required arguments for each task
                    task_function = partial(task_function, ssh_dir=ssh_dir, authorized_keys_path=authorized_keys_path)
                elif task == "revert":
                    task_function = partial(task_function, authorized_keys_path=authorized_keys_path, authorized_keys_bak=authorized_keys_bak, revert_log=revert_log)
                elif task=="challenge":
                    task_function = partial(task_function, uid=uid, validator_key_path=validator_key_path, validator_username=validator_username, challenge_duration=challenge_duration)

                else:
                    raise ValueError(f"Unsupported task: {task}")   

                success = await task_function(ip=ip, ssh_user=ssh_user, key_path=key_path, machine_name=machine_name)

                return success
            
            # Run revert for all machines of the miner
            tasks = [process_machine(name, details, task_function) for name, details in synapse.machine_availabilities.machine_config.items() if name != "Moat"]
            results = await asyncio.gather(*tasks)
            all_success = all(results)  # Mark as success if all machines are successfully reverted

            task_status[uid] = {
                f"{task}_status_code": 200 if all_success else 500,
                f"{task}_status_message": f"All machines processed {task} successfully" if all_success else f"Failure: Some machines failed to process {task}",
            }

        async def setup_miner_with_timeout(uid, synapse, task_function):
            """
            Setup miner with a timeout.
            
            Args:
                uid (int): Unique identifier for the miner.
                synapse (PingSynapse): The synapse containing machine availability information.
            """

            try:
                # Apply timeout to the entire setup_miner function for each miner
                await asyncio.wait_for(process_miner(uid, synapse, task_function), timeout=timeout)
            except asyncio.TimeoutError:
                logger.error(f"⏰ Timeout reached for {task} with miner {uid}.")
                task_status[uid] = {
                    f"{task}_status_code": 408,
                    f"{task}_status_message": f"Timeout: Miner {task} aborted. Skipping miner {uid} for this round."
                }


        # Process all miners in parallel
        await asyncio.gather(*[setup_miner_with_timeout(uid, synapse, task_function) for uid, synapse in miners])

        # Mark assigned miners that are not in ready_miners as unavailable
        available_miner_ids = {uid for uid, _ in miners}
        for miner_id in assigned_miners:
            if miner_id not in available_miner_ids:
                task_status[miner_id] = {
                    f"{task}_status_code": 503,  # HTTP status code for Service Unavailable
                    f"{task}_status_message": "Unavailable: Miner not available in the current round."
                }

        return [{"uid": uid, **status} for uid, status in task_status.items()]




    async def get_ready(self, ready_uids: List[int]) -> Dict[int, ChallengeSynapse]:
        """
        Sends a "GET_READY" ChallengeSynapse to miners before the challenge starts and collects responses.

        Args:
            ready_uids (List[int]): A list of miner UIDs that need to receive the readiness signal.

        Returns:
            Dict[int, ChallengeSynapse]: A dictionary mapping miner UIDs to their response synapses or error messages.
        """

        ready_results = {}

        async def inform_miner(uid):
                
            try:
                get_ready_synapse = ChallengeSynapse(
                    task="Defend The King",
                    state="GET_READY",
                )
                await self.dendrite_call(uid, get_ready_synapse)

            except Exception as e:
                logger.error(f"Error sending synapse to miner {uid}: {e}")

        await asyncio.gather(*[inform_miner(uid) for uid in ready_uids])



# Start availability checking
miner_availabilities = MinerManagement()