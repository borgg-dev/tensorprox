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
import tensorprox
from typing import List, Dict, Tuple, Union, Callable
from loguru import logger
from pydantic import BaseModel
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse
from tensorprox.core.gre_setup import GRESetup
from tensorprox.utils.utils import *
from tensorprox.settings import settings
from tensorprox.base.protocol import MachineConfig
import dotenv
import logging
from functools import partial
import asyncssh
import traceback


######################################################################
# LOGGING and ENVIRONMENT SETUP
######################################################################

dotenv.load_dotenv()

# Disable all asyncssh logging by setting its level to CRITICAL
asyncssh_logger = logging.getLogger('asyncssh')
asyncssh_logger.setLevel(logging.CRITICAL)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

create_session_key_dir()

  
######################################################################
# ASYNCHRONOUS SUPPORTING UTILITIES
######################################################################

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
            #log_message("INFO", f"📦 Package '{pkg}' missing => installing now...")
            await client.run("DEBIAN_FRONTEND=noninteractive apt-get update -qq || true", check=False)
            await client.run(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg}", check=False)
            await asyncio.sleep(1)




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

    async def async_setup(self, ip: str, ssh_user: str, key_path: str, machine_name: str, uid: int, ssh_dir:str, authorized_keys_path:str, authorized_keys_bak:str) -> bool:
        """
        Performs a single-pass SSH session setup on a remote miner. This includes generating session keys,
        configuring passwordless sudo, installing necessary packages, and executing user-defined commands.

        Args:
            ip (str): The IP address of the miner to set up.
            ssh_user (str): The SSH user account on the miner.
            key_path (str): Path to the original SSH key used for initial access.
            machine_name (str): Name of the machine being set up.
            uid (int): Unique identifier for the miner.
            backup_suffix (str): Suffix used for backing up the SSH configuration files.

        Returns:
            bool: True if the setup was successful, False if an error occurred.
        """
        
        # Generate the session key pair
        session_key_path = os.path.join(tensorprox.session_key_dir, f"session_key_{uid}_{ip}")
        session_priv, session_pub = await generate_local_session_keypair(session_key_path)

        try:

            # Run the setup script
            default_dir = get_default_dir(ssh_user=ssh_user)
            setup_cmd = f'bash {default_dir}/tensorprox/tensorprox/bash/initial_setup.sh {ssh_user} {ssh_dir} "{session_pub}" {authorized_keys_path} {authorized_keys_bak}'
            await ssh_connect_execute(ip, key_path, ssh_user, setup_cmd)

            #Run passwordless sudo command
            default_dir = get_default_dir(ssh_user=ssh_user)
            sudo_cmd = f'bash {default_dir}/tensorprox/tensorprox/bash/pwdless_sudo.sh {ssh_user}'
            await ssh_connect_execute(ip, session_key_path, ssh_user, sudo_cmd)

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

        try:

            # Run lockdown command
            default_dir = get_default_dir(ssh_user=ssh_user)
            lockdown_cmd = f"bash {default_dir}/tensorprox/tensorprox/bash/lockdown.sh {ssh_user} {ssh_dir} {self.validator_ip} {authorized_keys_path}"
            await ssh_connect_execute(ip, key_path, ssh_user, lockdown_cmd)
        
            return True

        except Exception as e:
            logger.error(f"🚨 Failed to lockdown machine {machine_name} for miner: {e}")
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

            # Run revert command
            default_dir = get_default_dir(ssh_user=ssh_user)
            revert_cmd = f"bash {default_dir}/tensorprox/tensorprox/bash/revert.sh {ip} {authorized_keys_bak} {authorized_keys_path} {revert_log}"
            await ssh_connect_execute(ip, key_path, ssh_user, revert_cmd)

            return True

        except Exception as e:
            logger.error(f"🚨 Failed to revert machine {machine_name} for miner: {e}")
            return False


    async def async_gre_setup(self, ip: str, ssh_user: str, key_path: str, machine_name: str, moat_ip: str) -> bool:
        try:

            # Run revert command
            default_dir = get_default_dir(ssh_user=ssh_user)
            gre_cmd = f"python3 {default_dir}/tensorprox/tensorprox/core/gre_setup.py {machine_name.lower()} {moat_ip}"
            await ssh_connect_execute(ip, key_path, ssh_user, gre_cmd)

            return True

        except Exception as e:
            logger.error(f"🚨 Failed to run GRE command on {machine_name} for miner: {e}")
            return False


    async def async_challenge(self, ip: str, ssh_user: str, key_path: str, machine_name: str, label_hashes: dict, playlists: dict, challenge_duration: int) -> tuple:
        """
        Title: Run Challenge Commands on Miner

        Executes challenge-related commands on a remote miner. This involves reading the validator's private key,
        running the challenge script, and reporting the outcome.

        Args:
            ip (str): The IP address of the miner where the challenge commands will be run.
            ssh_user (str): The SSH user account on the miner.
            key_path (str): Path to the SSH key used for authentication.
            machine_name (str): Name of the machine to challenge.
            label_hashes (dict): Dictionary containing the encrypted labels for each label type.
            playlists: (dict): Dictionary containings two playlists for Attacker and Benign.
            challenge_duration (int): Duration for which the challenge should run, in seconds.

        Returns:
            bool: True if the challenge was successfully executed, False if an error occurred.
        """

        try:

            # Send traffic_generator.py to traffic gen remote machines
            if machine_name != "King":
                await send_file_via_scp(TRAFFIC_GEN_PATH, REMOTE_TRAFFIC_GEN_PATH, ip, key_path, ssh_user)

            # Run the challenge command
            playlist = json.dumps(playlists[machine_name]) if machine_name != "King" else "null"
            default_dir = get_default_dir(ssh_user=ssh_user)
            challenge_cmd = f"bash {default_dir}/tensorprox/tensorprox/bash/challenge.sh {machine_name.lower()} {challenge_duration} '{label_hashes}' '{playlist}' {KING_OVERLAY_IP}"
            result = await ssh_connect_execute(ip, key_path, ssh_user, challenge_cmd)

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

            if machine_name == "Moat":
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

        self.king_ips[uid] = synapse.machine_availabilities.machine_config["King"].ip
        self.moat_private_ips[uid] = synapse.machine_availabilities.machine_config["Moat"].private_ip
        return synapse, uid_status_availability
    
    async def execute_task(
        self, 
        task: str,
        miners: List[Tuple[int, 'PingSynapse']],
        subset_miners: list[int],
        task_function: Callable[..., bool],
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
                iface = machine_details.iface
                ssh_user = machine_details.username
                ssh_dir = get_authorized_keys_dir(ssh_user)
                authorized_keys_path = f"{ssh_dir}/authorized_keys"
                key_path = f"/var/tmp/original_key_{uid}.pem" if task == "setup" else os.path.join(tensorprox.session_key_dir, f"session_key_{uid}_{ip}")
                authorized_keys_bak = f"{ssh_dir}/authorized_keys.bak_{backup_suffix}"
                revert_log = f"/tmp/revert_log_{uid}_{backup_suffix}.log"
                king_ip = self.king_ips[uid]
                moat_private_ip = self.moat_private_ips[uid]

                # Map task function to a version with specific arguments
                if task == "setup":
                    task_function = partial(task_function, uid=uid, ssh_dir=ssh_dir, authorized_keys_path=authorized_keys_path, authorized_keys_bak=authorized_keys_bak)
                elif task == "lockdown":
                    task_function = partial(task_function, ssh_dir=ssh_dir, authorized_keys_path=authorized_keys_path)
                elif task == "revert":
                    task_function = partial(task_function, authorized_keys_path=authorized_keys_path, authorized_keys_bak=authorized_keys_bak, revert_log=revert_log)
                elif task=="gre":
                    task_function = partial(task_function, moat_ip=moat_private_ip)
                elif task=="challenge":
                    task_function = partial(task_function, label_hashes=label_hashes, playlists=playlists, challenge_duration=challenge_duration)

                else:
                    raise ValueError(f"Unsupported task: {task}")   

                success = await task_function(ip=ip, ssh_user=ssh_user, key_path=key_path, machine_name=machine_name)

                return success
            
            # Run revert for all machines of the miner
            tasks = [process_machine(name, details, task_function) for name, details in synapse.machine_availabilities.machine_config.items() if name != "Moat"]
            results = await asyncio.gather(*tasks)

            if task == "challenge":
                # For each machine, collect its result and handle `label_counts` or `None`
                label_counts_results = []
                failed_machines = 0

                for result in results:
                    if result is None:
                        failed_machines += 1
                    elif isinstance(result, tuple):  # Expected result type for successful challenge
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

                state = (
                    "GET_READY" if task == "gre" 
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
        await asyncio.gather(*[setup_miner_with_timeout(uid, synapse, task_function) for uid, synapse in miners])

        # Mark assigned miners that are not in ready_miners as unavailable
        available_miner_ids = {uid for uid, _ in miners}
        for miner_id in subset_miners:
            if miner_id not in available_miner_ids:
                task_status[miner_id] = {
                    f"{task}_status_code": 503,  # HTTP status code for Service Unavailable
                    f"{task}_status_message": "Unavailable: Miner not available in the current round."
                }

        return [{"uid": uid, **status} for uid, status in task_status.items()]


