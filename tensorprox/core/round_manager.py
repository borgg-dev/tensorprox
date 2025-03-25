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
import json
import random
from tensorprox import *
from typing import List, Dict, Tuple, Union, Callable
from loguru import logger
from pydantic import BaseModel
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse
from tensorprox.utils.utils import *
from tensorprox.settings import settings
from tensorprox.base.protocol import MachineConfig
import dotenv
import logging
from functools import partial
import shlex
import traceback

######################################################################
# LOGGING and ENVIRONMENT SETUP
######################################################################

dotenv.load_dotenv()

# # Disable all asyncssh logging by setting its level to CRITICAL
# asyncssh_logger = logging.getLogger('asyncssh')
# asyncssh_logger.setLevel(logging.CRITICAL)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

create_session_key_dir()

######################################################################
# CLASS ROUND MANAGER
######################################################################

class RoundManager(BaseModel):
    """
    Tracks the availability of miners using the PingSynapse protocol.
    
    Attributes:
        miners (Dict[int, PingSynapse]): A dictionary mapping miner UIDs to their availability status.
        ip (str): The local IP address of the machine running this instance.
    """

    miners: Dict[int, 'PingSynapse'] = {}
    validator_ip: str = get_public_ip()
    king_ips: Dict[int, str] = {}
    moat_private_ips: Dict[int, str] = {}

    def check_machine_availability(self, machine_name: str = None, uid: int = None) -> bool:
        """
        Checks whether a specific miner machine is available.

        Args:
            machine_name (str, optional): The machine name to check. Defaults to None.
            uid (int, optional): The UID of the miner. Defaults to None.

        Returns:
            bool: True if the machine is available, False otherwise.
        """

        if machine_name == "moat":
            return True  #Skip moat
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
            if machine_name == "moat":
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


    async def run(self, ip: str, ssh_user: str, key_path: str, args: list, files_to_verify: list, remote_base_directory: str) -> Union[bool, object]:
        """
        Performs a single-pass SSH session setup on a remote miner. This includes generating session keys,
        configuring passwordless sudo, installing necessary packages, and executing user-defined commands.

        Args:
            ip (str): The IP address of the miner to set up.
            ssh_user (str): The SSH user account on the miner.
            key_path (str): Path to the original SSH key used for initial access.
            paired_list (List[str]): List of paired items (purpose unclear from the context, needs adaptation).
        Returns:
            bool: True if the setup was successful, False if an error occurred.
        """

        paired_list = create_pairs_to_verify(files_to_verify, remote_base_directory)

        cmd = ' '.join(shlex.quote(arg) for arg in args)
        
        return await check_files_and_execute(ip, key_path, ssh_user, paired_list, cmd)
    

    async def extract_metrics(self, result: str, machine_name: str, label_hashes: dict) -> tuple:
        """
        Extracts label counts and average RTT (Round Trip Time) from the result output.

        This method processes the result string, which contains various metrics, and extracts the label counts
        and average RTT value. It then returns the parsed data along with the machine name.

        Args:
            result (str): The result string that contains the metric values (including label counts and RTT).
            machine_name (str): The name of the machine from which the metrics were collected.
            label_hashes (dict): A dictionary containing label hashes, which are used to match the labels in the result.

        Returns:
            tuple: A tuple containing:
                - `machine_name` (str): The name of the machine from the argument.
                - `label_counts` (dict): A dictionary with label names as keys and their corresponding counts as values.
                - `rtt_avg` (float or None): The average RTT value parsed from the result, or None if not found or invalid.
        
        If any errors occur during parsing (e.g., invalid result format or failed conversions), the method logs a warning
        and skips the invalid entries. In case of a general failure, the method logs the error and returns `None`.
        """

        try:
        
            # Parse the result to get the counts from stdout
            counts_and_rtt = result.stdout.strip().split(", ")

            # Initialize a dictionary to store counts using a for loop
            label_counts = {label: 0 for label in label_hashes.keys()}

            rtt_avg = None

            # Parse each label count from the result string
            for count in counts_and_rtt:
                
                if "AVG_RTT" in count:
                    extracted_rtt = count.split(":", maxsplit=1)[1].strip()
                    
                    # Check if extracted_rtt is a valid float before converting
                    try:
                        rtt_avg = float(extracted_rtt)
                    except ValueError:
                        logger.warning(f"Invalid RTT value: {extracted_rtt}")
                else:
                    try:
                        label, value = count.split(":", maxsplit=1)
                        value = value.strip()
                        
                        if label in label_counts:
                            label_counts[label] = int(value)  # Convert only if valid
                        
                    except ValueError:
                        logger.warning(f"Invalid label count entry: {count}")  # Log and skip invalid entries


            return machine_name, label_counts, rtt_avg

        except Exception as e:
            logger.error(f"Error occurred: {e}")
            return None

    
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
            uid_status_availability["ping_status_message"] = "Missing SSH Key Pair."
            uid_status_availability["ping_status_code"] = 400
            return synapse, uid_status_availability

        # Extract SSH key pair safely
        ssh_pub, ssh_priv = synapse.machine_availabilities.key_pair
        original_key_path = f"/var/tmp/original_key_{uid}.pem"
        save_file_with_permissions(ssh_priv, original_key_path)

        all_machines_available = True

        for machine_name, machine_details in synapse.machine_availabilities.machine_config.items():

            if machine_name == "moat":
                continue  # Skip the Moat machine

            ip = machine_details.ip
            ssh_user = machine_details.username

            if not is_valid_ip(ip):
                all_machines_available = False
                uid_status_availability["ping_status_message"] = "Invalid IP format."
                uid_status_availability["ping_status_code"] = 400
                break

            # Test SSH Connection with asyncssh
            client = await ssh_connect_execute(ip, original_key_path, ssh_user)

            if not client:
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

        try:

            # Check if the uid is within the valid range for the axons list
            if uid < len(settings.METAGRAPH.axons):
                axon = settings.METAGRAPH.axons[uid]
            else:
                return uid, PingSynapse()
        
            response = await settings.DENDRITE(
                axons=[axon],
                synapse=synapse,
                timeout=timeout,
                deserialize=False,
            )

            return uid, response[0] if response else PingSynapse()

        except Exception as e:
            logger.error(f"❌ Failed to query miner {uid}: {e}\n{traceback.format_exc()}")
            return uid, PingSynapse()
            

    async def process_initial_setup(
        self,
        ip: str,
        ssh_user: str,
        key_path: str,
        remote_base_directory: str,
        uid: int,
        ssh_dir: str,
        authorized_keys_path: str,
        authorized_keys_bak: str,
        script_name: str = "initial_setup.sh",
        linked_files: list = []
    ) -> bool:
        """
        Performs the initial setup process on the remote server.

        This method generates a session key pair, prepares the required arguments for
        running the setup script, and calls the `run` method to execute it on the remote server.

        Args:
            ip (str): The IP address of the remote server.
            ssh_user (str): The SSH username to access the server.
            key_path (str): The path to the SSH private key for authentication.
            remote_base_directory (str): The base directory on the remote server.
            uid (int): The user ID for creating a session key.
            ssh_dir (str): The directory where SSH keys are stored.
            authorized_keys_path (str): The path to the authorized keys file on the remote server.
            authorized_keys_bak (str): The backup path for the authorized keys file.
            script_name (str, optional): The name of the script to execute (default is "initial_setup.sh").
            linked_files (list, optional): List of linked files to verify along with the script (default is an empty list).

        Returns:
            bool: Returns `True` if the setup process was successful, otherwise `False`.
        """

        remote_script_path = get_immutable_path(remote_base_directory, script_name)
        files_to_verify = [script_name] + linked_files

        # Generate the session key pair
        session_key_path = os.path.join(SESSION_KEY_DIR, f"session_key_{uid}_{ip}")
        _, session_pub = await generate_local_session_keypair(session_key_path)

        session_pub = session_pub.replace(' ', '<TENSORPROX_SPACE>')

        args = [
            '/usr/bin/bash', 
            remote_script_path,
            ssh_user, 
            ssh_dir, 
            session_pub,
            authorized_keys_path, 
            authorized_keys_bak
        ]

        return await self.run(
            ip=ip,
            ssh_user=ssh_user,
            key_path=key_path,
            args=args,
            files_to_verify=files_to_verify,
            remote_base_directory=remote_base_directory
        )
    
    async def process_lockdown(
        self,
        ip: str,
        ssh_user: str,
        key_path: str,
        remote_base_directory: str,
        ssh_dir: str,
        authorized_keys_path: str,
        script_name: str = "lockdown.sh",
        linked_files: list = []
    ) -> bool:
        """
        Executes the lockdown script on the remote server.

        This method prepares the arguments for running the lockdown script and calls the `run` method
        to execute it on the remote server.

        Args:
            ip (str): The IP address of the remote server.
            ssh_user (str): The SSH username to access the server.
            key_path (str): The path to the SSH private key for authentication.
            remote_base_directory (str): The base directory on the remote server.
            ssh_dir (str): The directory where SSH keys are stored.
            authorized_keys_path (str): The path to the authorized keys file on the remote server.
            script_name (str, optional): The name of the script to execute (default is "lockdown.sh").
            linked_files (list, optional): List of linked files to verify along with the script (default is an empty list).

        Returns:
            bool: Returns `True` if the lockdown process was successful, otherwise `False`.
        """

        remote_script_path = get_immutable_path(remote_base_directory, script_name)
        files_to_verify = [script_name] + linked_files

        args = [
            '/usr/bin/bash', 
            remote_script_path,
            ssh_user, ssh_dir, 
            self.validator_ip,
            authorized_keys_path
        ]

        return await self.run(
            ip=ip,
            ssh_user=ssh_user,
            key_path=key_path,
            args=args,
            files_to_verify=files_to_verify,
            remote_base_directory=remote_base_directory
        )
    
    async def process_revert(
        self,
        ip: str,
        ssh_user: str,
        key_path: str,
        remote_base_directory: str,
        authorized_keys_bak: str,
        authorized_keys_path: str,
        revert_log: str,
        script_name: str = "revert.sh",
        linked_files: list = []
    ) -> bool:
        """
        Executes the revert script on the remote server.

        This method prepares the arguments for running the revert script and calls the `run` method
        to execute it on the remote server.

        Args:
            ip (str): The IP address of the remote server.
            ssh_user (str): The SSH username to access the server.
            key_path (str): The path to the SSH private key for authentication.
            remote_base_directory (str): The base directory on the remote server.
            authorized_keys_bak (str): The path to the backup authorized keys file.
            authorized_keys_path (str): The path to the authorized keys file on the remote server.
            revert_log (str): The path to the revert log.
            script_name (str, optional): The name of the script to execute (default is "revert.sh").
            linked_files (list, optional): List of linked files to verify along with the script (default is an empty list).

        Returns:
            bool: Returns `True` if the revert process was successful, otherwise `False`.
        """

        remote_script_path = get_immutable_path(remote_base_directory, script_name)
        files_to_verify = [script_name] + linked_files

        args = [
            '/usr/bin/bash', 
            remote_script_path,
            ip, 
            authorized_keys_bak, 
            authorized_keys_path,
            revert_log
        ]

        return await self.run(
            ip=ip,
            ssh_user=ssh_user,
            key_path=key_path,
            args=args,
            files_to_verify=files_to_verify,
            remote_base_directory=remote_base_directory
        )
    
    async def process_gre_setup(
        self,
        ip: str,
        ssh_user: str,
        key_path: str,
        remote_base_directory: str,
        machine_name: str,
        moat_private_ip: str,
        script_name: str = "gre_setup.py",
        linked_files: list = []
    ) -> bool:
        """
        Sets up the GRE tunnel on the remote server.

        This method prepares the arguments for running the GRE setup script and calls the `run` method
        to execute it on the remote server.

        Args:
            ip (str): The IP address of the remote server.
            ssh_user (str): The SSH username to access the server.
            key_path (str): The path to the SSH private key for authentication.
            remote_base_directory (str): The base directory on the remote server.
            machine_name (str): The name of the machine for the GRE setup.
            moat_private_ip (str): The private IP address of the Moat machine.
            script_name (str, optional): The name of the script to execute (default is "gre_setup.py").
            linked_files (list, optional): List of linked files to verify along with the script (default is an empty list).

        Returns:
            bool: Returns `True` if the GRE setup process was successful, otherwise `False`.
        """

        remote_script_path = get_immutable_path(remote_base_directory, script_name)
        files_to_verify = [script_name] + linked_files

        args = [
            '/usr/bin/python3.10', 
            remote_script_path,
            machine_name, 
            moat_private_ip
        ]

        return await self.run(
            ip=ip,
            ssh_user=ssh_user,
            key_path=key_path,
            args=args,
            files_to_verify=files_to_verify,
            remote_base_directory=remote_base_directory
        )
    
    async def process_challenge(
        self,
        ip: str,
        ssh_user: str,
        key_path: str,
        remote_base_directory: str,
        machine_name: str,
        challenge_duration: int,
        label_hashes: Dict[str, list],
        playlists: List[dict],
        script_name: str = "challenge.sh",
        linked_files: list = ["traffic_generator.py"]
    ) -> tuple:
        """
        Runs the challenge script on the remote server.

        This method prepares the arguments for running the challenge script and calls the `run` method
        to execute it on the remote server.

        Args:
            ip (str): The IP address of the remote server.
            ssh_user (str): The SSH username to access the server.
            key_path (str): The path to the SSH private key for authentication.
            remote_base_directory (str): The base directory on the remote server.
            machine_name (str): The name of the machine running the challenge.
            challenge_duration (int): The duration of the challenge in seconds.
            label_hashes (Dict[str, list]): A dictionary mapping labels to their corresponding hash values.
            playlists (List[dict]): A list of playlists to be used for the challenge.
            script_name (str, optional): The name of the script to execute (default is "challenge.sh").
            linked_files (list, optional): List of linked files to verify along with the script (default includes "traffic_generator.py").

        Returns:
            tuple: The result of the challenge execution.
        """

        remote_script_path = get_immutable_path(remote_base_directory, script_name)
        remote_traffic_gen = get_immutable_path(remote_base_directory, "traffic_generator.py")
        files_to_verify = [script_name] + linked_files

        playlist = json.dumps(playlists[machine_name]) if machine_name != "king" else "null"
        label_hashes = json.dumps(label_hashes)

        args = [
            "/usr/bin/bash",
            remote_script_path,
            machine_name,
            str(challenge_duration),
            str(label_hashes),  
            str(playlist),      
            KING_OVERLAY_IP,
            remote_traffic_gen,
        ]

        return await self.run(
            ip=ip,
            ssh_user=ssh_user,
            key_path=key_path,
            args=args,
            files_to_verify=files_to_verify,
            remote_base_directory=remote_base_directory
        )


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

        self.king_ips[uid] = synapse.machine_availabilities.machine_config["king"].ip
        self.moat_private_ips[uid] = synapse.machine_availabilities.machine_config["moat"].private_ip
        return synapse, uid_status_availability
    
    async def execute_task(
        self, 
        task: str,
        miners: List[Tuple[int, 'PingSynapse']],
        subset_miners: list[int],
        backup_suffix: str = "", 
        label_hashes: dict = None,
        playlists: dict = {},
        challenge_duration: int = CHALLENGE_DURATION,
        timeout: int = ROUND_TIMEOUT
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

        async def process_miner(uid, synapse):
            """
            Process all machines for a given miner and apply the specified task.

            Args:
                uid (int): Miner's unique ID.
                synapse (PingSynapse): Miner's machine configurations.

            Returns:
                None: Updates task status for each machine.
            """

            async def process_machine(machine_name, machine_details):
                """
                Apply task to a specific machine.

                Args:
                    machine_name (str): Name of the machine (e.g., "Moat").
                    machine_details (object): Machine connection details (contains `ip`, `username`, etc.).

                Returns:
                    bool: True if the task succeeds, False otherwise.
                """

                # If the machine is "Moat", skip the setup and immediately consider the task successful
                if machine_name == "moat":
                    return True  # Skip Moat machine setup and consider it successful

                # Retrieve necessary connection and task details
                ip = machine_details.ip
                ssh_user = machine_details.username
                ssh_dir = get_authorized_keys_dir(ssh_user)  # Get directory for authorized keys
                authorized_keys_path = f"{ssh_dir}/authorized_keys"  # Path to the authorized keys file
                key_path = f"/var/tmp/original_key_{uid}.pem" if task == "initial_setup" else os.path.join(SESSION_KEY_DIR, f"session_key_{uid}_{ip}")  # Set key path based on the task type
                authorized_keys_bak = f"{ssh_dir}/authorized_keys.bak_{backup_suffix}"  # Backup path for authorized keys
                revert_log = f"/tmp/revert_log_{uid}_{backup_suffix}.log"  # Log path for revert operations
                
                # Get machine-specific details like private IP and default directories
                moat_private_ip = self.moat_private_ips[uid]  # Private IP for the Moat machine
                default_dir = get_default_dir(ssh_user=ssh_user)  # Get the default directory for the user
                remote_base_directory = os.path.join(default_dir, "tensorprox")  # Define the remote base directory for tasks

                try:
                    if task == "initial_setup":
                        result = await self.process_initial_setup(
                            ip,
                            ssh_user,
                            key_path,
                            remote_base_directory,
                            uid,
                            ssh_dir,
                            authorized_keys_path,
                            authorized_keys_bak
                        )
                    elif task == "lockdown":
                        result = await self.process_lockdown(
                            ip,
                            ssh_user,
                            key_path,
                            remote_base_directory,
                            ssh_dir,
                            authorized_keys_path
                        )
                    elif task == "revert":
                        result = await self.process_revert(
                            ip,
                            ssh_user,
                            key_path,
                            remote_base_directory,
                            authorized_keys_bak,
                            authorized_keys_path,
                            revert_log
                        )
                    elif task == "gre_setup":
                        result = await self.process_gre_setup(
                            ip,
                            ssh_user,
                            key_path,
                            remote_base_directory,
                            machine_name,
                            moat_private_ip
                        )
                    elif task == "challenge":
                        result = await self.process_challenge(
                            ip,
                            ssh_user,
                            key_path,
                            remote_base_directory,
                            machine_name,
                            challenge_duration,
                            label_hashes,
                            playlists
                        )
                        result = await self.extract_metrics(result, machine_name, label_hashes)
                    else:
                        raise ValueError(f"Unsupported task: {task}")

                    return result

                except Exception as e:
                    logging.error(f"Error executing task on {machine_name} with ip {ip} for miner {uid}: {e}")
                    return False
            
            # Run revert for all machines of the miner
            tasks = [process_machine(name, details) for name, details in synapse.machine_availabilities.machine_config.items() if name != "moat"]
            results = await asyncio.gather(*tasks)

            if task == "challenge":
                # For each machine, collect its result and handle `label_counts` or `None`
                label_counts_results = []
                failed_machines = 0

                for result in results:
                    if isinstance(result, tuple):
                        label_counts_results.append(result)
                    else:
                        failed_machines += 1

                all_success = failed_machines == 0

                task_status[uid] = {
                    f"{task}_status_code": 200 if all_success else 500,
                    f"{task}_status_message": f"All machines processed {task} successfully with label counts" if all_success else f"Failure: {failed_machines} machines failed in processing {task}",
                    "label_counts_results": label_counts_results,  # Add the successful label counts
                }

            else:
                # For other tasks, just mark the status based on boolean success
                all_success = all(results)  # All machines should return True for success
                
                task_status[uid] = {
                    f"{task}_status_code": 200 if all_success else 500,
                    f"{task}_status_message": f"All machines processed {task} successfully" if all_success else f"Failure: Some machines failed to process {task}",
                }

        async def setup_miner_with_timeout(uid, synapse):
            """
            Setup miner with a timeout.
            
            Args:
                uid (int): Unique identifier for the miner.
                synapse (PingSynapse): The synapse containing machine availability information.
            """

            try:
                # Apply timeout to the entire setup_miner function for each miner
                await asyncio.wait_for(process_miner(uid, synapse), timeout=timeout)

                state = (
                    "GET_READY" if task == "gre_setup" 
                    else "END_ROUND" if task == "challenge" 
                    else None
                )
                
                if state :
                    try:
                        challenge_synapse = ChallengeSynapse(
                            task="Defend The King",
                            state=state,
                        )
                        await self.dendrite_call(uid, challenge_synapse)
                        
                    except Exception as e:
                        logger.error(f"Error sending synapse to miner {uid}: {e}")


            except asyncio.TimeoutError:
                logger.error(f"⏰ Timeout reached for {task} with miner {uid}.")
                task_status[uid] = {
                    f"{task}_status_code": 408,
                    f"{task}_status_message": f"Timeout: Miner {task} aborted. Skipping miner {uid} for this round."
                }
            

        # Process all miners in parallel
        await asyncio.gather(*[setup_miner_with_timeout(uid, synapse) for uid, synapse in miners])

        # Mark assigned miners that are not in ready_miners as unavailable
        available_miner_ids = {uid for uid, _ in miners}
        for miner_id in subset_miners:
            if miner_id not in available_miner_ids:
                task_status[miner_id] = {
                    f"{task}_status_code": 503,  # HTTP status code for Service Unavailable
                    f"{task}_status_message": "Unavailable: Miner not available in the current round."
                }
        
        return [{"uid": uid, **status} for uid, status in task_status.items()]


