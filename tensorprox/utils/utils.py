from requests import get
from tensorprox import *
import tensorprox
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
from typing import Tuple, Dict, Union, List
from loguru import logger
import string
import hashlib
import psutil
import ipaddress

def get_remaining_time(duration):
    current_time = time.time()
    next_event_time = ((current_time // duration) + 1) * duration
    remaining_time = next_event_time - current_time
    remaining_minutes = int(remaining_time // 60)
    remaining_seconds = int(remaining_time % 60)

    return f"{remaining_minutes}m {remaining_seconds}s"

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


def get_subnet(interface):
    interfaces = psutil.net_if_addrs()
    if interface not in interfaces:
        return None  # Interface not found
    for addr in interfaces[interface]:
        if addr.family == 2:  # AF_INET (IPv4)
            ip_network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            return str(ip_network)
    return None  # No IPv4 address found

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

def get_default_dir(ssh_user: str) -> str:
    """
    Retrieves the correct default directory path based on the SSH user.

    Args:
        ssh_user (str): The username of the SSH user.

    Returns:
        str: The absolute path to the default directory.
    """

    return "/root" if ssh_user == "root" else f"/home/{ssh_user}"


def create_session_key_dir(path = SESSION_KEY_DIR) :

    if not os.path.exists(path):
        try:
            os.makedirs(path, mode=0o700, exist_ok=True)
        except PermissionError as e:
            #log_message("ERROR", f"Permission denied while creating {SESSION_KEY_DIR}: {e}")
            raise
        except Exception as e:
            #log_message("ERROR", f"Unexpected error while creating {SESSION_KEY_DIR}: {e}")
            raise

# Define a helper function to generate file paths
def get_immutable_path(base_directory: str, filename: str) -> str:
    """
    Generates an absolute path by joining the base directory with the given relative path.

    Args:
        base_directory (str): The path of the the base directory.
        filename (str): The name of the file.

    Returns:
        str: The absolute path.
    """
    return os.path.join(base_directory, "tensorprox/core/immutable", filename)


def save_file_with_permissions(priv_key_str: str, path: str):
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

    
def get_attack_classes() -> Dict[str, list]:
    """Get all available attack classes.
    
    Returns:
        Dictionary mapping internal labels with the traffic vectors.
    """
    return {
        "BENIGN": ['udp_traffic', 'tcp_traffic'],

        "TCP_SYN_FLOOD": [
            'tcp_variable_window_syn_flood',
            'tcp_amplified_syn_flood_reflection',
            'tcp_async_slow_syn_flood',
            'tcp_batch_syn_flood',
            'tcp_randomized_syn_flood',
            'tcp_variable_ttl_syn_flood',
            'tcp_targeted_syn_flood_common_ports',
            'tcp_adaptive_flood',
            'tcp_batch_flood',
            'tcp_variable_syn_flood',
            'tcp_max_randomized_flood'
        ],

        "UDP_FLOOD": [
            'udp_malformed_packet',
            'udp_multi_protocol_amplification_attack',
            'udp_adaptive_payload_flood',
            'udp_compressed_encrypted_flood',
            'udp_max_randomized_flood',
            'udp_and_tcp_flood',
            'udp_single_ip_flood',
            'udp_ip_packet',
            'udp_reflection_attack',
            'udp_memcached_amplification_attack',
            'udp_hybrid_flood',
            'udp_dynamic_payload_flood',
            'udp_encrypted_payload_flood'
        ]
    }


def create_random_playlist(total_seconds, label_hashes, role=None, seed=None):
    """
    Create a random playlist totaling a specified duration, either for an 'attacker' or 'benign' role.
    Generates a playlist consisting of random activities ('pause' or a class type) with durations summing up to the specified total duration.

    Args:
        total_seconds (int): The total duration of the playlist in seconds.
        label_hashes (dict): Dictionary of labels and corresponding lists of random hashes.
        role (str, optional): The role for the playlist ('attacker' or 'benign'). Defaults to None.
        seed (int, optional): The seed for the random number generator. If None, the seed is not set.

    Returns:
        list: A list of dictionaries, each containing 'name', 'class_vector', 'label_identifier', and 'duration'.
    """

    if seed is not None:
        random.seed(seed)

    type_class_map = get_attack_classes()
    playlist = []
    current_total = 0
    attack_labels = [key for key in type_class_map.keys() if key != "BENIGN"]
    benign_labels = ["BENIGN"]

    # Role-specific weight calculation using a dictionary
    weights = {
        "attacker": (0.8, 0.2),
        "benign": (0.2, 0.8)
    }.get(role, (0.5, 0.5))  # Default to (0.5, 0.5) if role is neither 'attacker' nor 'benign'

    attack_weight, benign_weight = weights

    # Calculate individual weights
    attack_weight_per_label = attack_weight / len(attack_labels)
    combined_labels = attack_labels + benign_labels
    weights = [attack_weight_per_label] * len(attack_labels) + [benign_weight]

    while current_total < total_seconds:
        
        # Select label based on role-specific weight distribution
        name = random.choices(combined_labels, weights, k=1)[0]
        # Determine the duration for this step (ensuring we don't exceed total_seconds)
        duration = min(random.randint(60, 180), total_seconds - current_total)

        # If role is "Benign" and label "BENIGN" is chosen, output a grouped unit with two class_vectors.
        if role == "Benign" and name == "BENIGN":
            
            benign_unit = {
                "name": "BENIGN",
                "classes": [
                    {
                        "class_vector": "tcp_traffic",
                        "label_identifier": random.choice(label_hashes["BENIGN"]),
                        "duration": duration
                    },
                    {
                        "class_vector": "udp_traffic",
                        "label_identifier": random.choice(label_hashes["BENIGN"]),
                        "duration": duration
                    }
                ]
            }

            playlist.append(benign_unit)

        else :

            # For all other cases, use the existing logic
            # Note: For non-"pause" labels, select the class_vector and label_identifier
            class_vector = random.choice(type_class_map[name]) if name != "pause" else None
            label_identifier = random.choice(label_hashes[name]) if name != "pause" else None

            # Add activity to the playlist
            playlist.append({
                "name": name, 
                "class_vector": class_vector,
                "label_identifier": label_identifier, 
                "duration": duration
            })

        current_total += duration

    return playlist

 
def generate_random_hashes(n=10):
    # Function to generate a random hash
    def generate_random_string(length=16):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def generate_hash(value):
        return hashlib.sha256(value.encode()).hexdigest()
    
    # Create a dictionary to store the hashes for each label
    label_hashes = {
        "BENIGN": [],
        "TCP_SYN_FLOOD": [],
        "UDP_FLOOD": []
    }
    
    # Generate n random hashes for each label
    for label in label_hashes:
        for _ in range(n):
            random_string = generate_random_string()
            label_hashes[label].append(generate_hash(random_string))
    
    return label_hashes

def create_pairs_to_verify(
    files_to_verify: List[str], 
    remote_base_directory: str,
    base_directory: str = BASE_DIR
) -> Tuple[str, List[Tuple[str, str]]]:
    
    paired_list = []
    for file in files_to_verify:
        local_path = get_immutable_path(base_directory, file)  # Use the passed base_directory
        remote_path = get_immutable_path(remote_base_directory, file)
        paired_list.append((local_path, remote_path))

    return paired_list

def get_local_sha256_hash(file_path: str) -> str:
    """
    Calculates the SHA-256 hash of a local file.
    
    Args:
        file_path (str): Path to the local file.
        
    Returns:
        str: The SHA-256 hash of the local file.
    """
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        # Read the file in chunks
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()

async def check_files_and_execute(ip: str, key_path: str, ssh_user: str, pair_files_list: List[Tuple[str, str]], cmd: str) -> Union[bool, object]:

    try:
        
        for local_file, remote_file in pair_files_list:
            # Compare hashes
            if not await compare_file_hashes(ip, key_path, ssh_user, local_file, remote_file):
                return False
        
        # Run the script securely

        return await ssh_connect_execute(ip, key_path, ssh_user, cmd)
    
    except Exception as e:
        return False
    

async def get_remote_sha256_hash(ip: str, key_path: str, ssh_user: str, remote_file_path: str) -> str:
    """
    Calculates the SHA-256 hash of a remote file using SSH.
    
    Args:
        ip (str): The IP address of the remote machine.
        key_path (str): Path to the private SSH key.
        ssh_user (str): The SSH user on the remote machine.
        remote_file_path (str): The path to the file on the remote machine.
        
    Returns:
        str: The SHA-256 hash of the remote file.
    """
    
    # SSH command to calculate SHA-256 of the remote file
    cmd = f"sha256sum {remote_file_path} | awk '{{print $1}}'"

    remote_hash = await ssh_connect_execute(ip, key_path, ssh_user, cmd)
    return remote_hash.stdout.strip()


async def compare_file_hashes(ip: str, key_path: str, ssh_user: str, local_file_path: str, remote_file_path: str) -> bool:
    """
    Compares the SHA-256 hashes of a local file and a remote file.
    
    Args:
        ip (str): The IP address of the remote machine.
        key_path (str): Path to the private SSH key.
        ssh_user (str): The SSH user on the remote machine.
        local_file_path (str): Path to the local file.
        remote_file_path (str): Path to the remote file.
        
    Returns:
        bool: True if the hashes match, False otherwise.
    """
    # Calculate the SHA-256 hash of the local file
    local_hash = get_local_sha256_hash(local_file_path)

    # Calculate the SHA-256 hash of the remote file
    remote_hash = await get_remote_sha256_hash(ip, key_path, ssh_user, remote_file_path)

    # Compare the two hashes
    return local_hash == remote_hash


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

async def make_file_immutable(ip, key_path, ssh_user, remote_file_path, state=True):
    immutable_flag = "+i" if state == True else "-i"
    immutable_cmd = f"sudo chattr {immutable_flag} {remote_file_path}"
    await ssh_connect_execute(ip, key_path, ssh_user, immutable_cmd)

# Function to verify the remote file's signature
async def verify_remote_signature(ip, key_path, ssh_user, remote_signature_path, remote_file_path):
    verify_cmd = f"gpg --verify --trust-model always {remote_signature_path} {remote_file_path}"
    result = await ssh_connect_execute(ip, key_path, ssh_user, verify_cmd)
    return result
    
async def send_file_via_scp(local_file, remote_path, remote_ip, remote_key_path, remote_user):
    # Construct the SCP command
    scp_command = [
        'scp',
        '-i', remote_key_path,  # Specify the SSH private key
        '-o', 'StrictHostKeyChecking=no',  # Disable host key verification
        '-o', 'UserKnownHostsFile=/dev/null',  # Don't store the host key
        local_file,  # Local file to transfer
        f'{remote_user}@{remote_ip}:{remote_path}'  # Remote destination
    ]

    try:
        # Run the SCP command asynchronously using asyncio.subprocess
        process = await asyncio.create_subprocess_exec(*scp_command)

        # Wait for the SCP process to complete
        await process.wait()

        if process.returncode == 0:
            print(f"File {local_file} successfully sent to {remote_ip}:{remote_path}")
        else:
            print(f"SCP failed with return code {process.returncode}")

    except Exception as e:
        print(f"Error: {e}")


async def ssh_connect_execute(ip: str, private_key_path: str, username: str, cmd: Union[str, list] = None) -> Union[bool, object]:
    """
    Establishes an SSH connection, optionally executes a command, and closes the connection.

    Args:
        ip (str): The target machine's IP address.
        private_key_path (str): The path to the private key used for authentication.
        username (str): The SSH user to authenticate as.
        cmd (Union[str, list], optional): The command to execute.

    Returns:
        Union[bool, object]: 
            - If no command is provided, returns True if the connection is successful, False otherwise.
            - If a command is provided, returns the result.
    """
    try:
        # Establish the SSH connection
        async with asyncssh.connect(ip, username=username, client_keys=[private_key_path], known_hosts=None) as client:
            if cmd:
                try:
                    # Run the command and capture the result
                    result = await client.run(cmd, check=False, stderr=asyncssh.PIPE)
                    return result   
                except Exception as e:
                    # logger.error(f"Command execution failed: {e}, stderr: {e.stderr}")
                    return False  # Command execution failed

        # If no command is provided, return True for successful connection
        return True

    except asyncssh.Error as e:
        # Connection failed, log the error
        logger.error(f"SSH connection failed: {e}")
        return False

