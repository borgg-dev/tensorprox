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
from typing import Tuple, Optional, Dict, Union
from loguru import logger
import string
import hashlib
import psutil
import ipaddress


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
def generate_path(relative_path: str) -> str:
    """
    Generates an absolute path by joining the base directory with the given relative path.

    Args:
        relative_path (str): The relative path to the file or directory.

    Returns:
        str: The absolute path.
    """
    return os.path.join(BASE_DIR, "tensorprox", relative_path)


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
        "Attacker": (0.8, 0.2),
        "Benign": (0.2, 0.8)
    }.get(role, (0.5, 0.5))  # Default to (0.5, 0.5) if role is neither 'Attacker' nor 'Benign'

    attack_weight, benign_weight = weights

    # Calculate individual weights
    attack_weight_per_label = attack_weight / len(attack_labels)
    weights = [attack_weight_per_label] * len(attack_labels) + [benign_weight]

    while current_total < total_seconds:
        # Select label based on role-specific weight distribution
        name = random.choices(attack_labels + benign_labels, weights, k=1)[0]
        class_vector = random.choice(type_class_map[name]) if name != "pause" else None
        label_identifier = random.choice(label_hashes[name]) if name != "pause" else None
        duration = min(random.randint(60, 180), total_seconds - current_total)

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

async def verify_remote_file(ip: str, key_path: str, ssh_user: str, remote_script_path: str, signature_path: str, remote_signature_path: str, public_key_file: str) -> bool:
        
    #Add gpg public key to the remote machine
    await add_gpg_public_key_to_remote(ip, key_path, ssh_user, public_key_file, public_key_file)

    #Send signature to the remote machine
    await send_file_via_scp(signature_path, remote_signature_path, ip, key_path, ssh_user)

    #Get local and remote signatures
    remote_signature, local_signature = await get_signatures(ip, key_path, ssh_user, signature_path, remote_signature_path)
    
    # Compare the remote signature with the locally generated signature
    if remote_signature == local_signature :

        # Verify the signature
        verification_result = await verify_remote_signature(ip, key_path, ssh_user, remote_signature_path, remote_script_path)

        if "Good signature" in verification_result.stderr:
            # logger.info(f"Signature is valid!")
            return True
        else:
            # logger.info("Error: Signature verification failed! The file may have been tampered with.")
            return False
    else:
        # logger.info("Warning: The signature file appears to have been tampered with.")
        return False
    

async def add_gpg_public_key_to_remote(ip: str, key_path: str, ssh_user: str, public_key_file: str, remote_public_key_path: str = "/tmp/remote_public_key.asc"):

    # Upload the public key to the remote machine
    await send_file_via_scp(public_key_file, remote_public_key_path, ip, key_path, ssh_user)

    # Import the GPG public key on the remote machine
    import_gpg_key_cmd = f"gpg --import {remote_public_key_path}"
    await ssh_connect_execute(ip, key_path, ssh_user, import_gpg_key_cmd)


async def get_signatures(ip: str, key_path: str, ssh_user :str, signature_path: str, remote_signature_path: str):

    # Save the locally generated signature for later comparison
    with open(signature_path, 'r') as f:
        local_signature = f.read()
        local_signature = local_signature.strip().replace("\r\n", "\n")

    #Get remote signature
    remote_signature = await get_remote_file_contents(ip, key_path, ssh_user, remote_signature_path)
    remote_signature = remote_signature.strip().replace("\r\n", "\n")

    return remote_signature, local_signature

def generate_signature_from_file(file_path: str, signature_path: str, public_key_file: str):
    # Verify if GPG key exists, and if not, generate one
    gpg_key_check_command = "gpg --list-secret-keys"
    result = subprocess.run(gpg_key_check_command, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode != 0:  # No secret key available
        # logger.error("❌ No GPG secret key found. Generating RSA key...")

        # Generate the RSA key
        gpg_key_generate_command = """
        gpg --batch --gen-key <<EOF
        %no-protection
        %commit
        Key-Type: RSA
        Key-Length: 2048
        Name-Real: Your Name
        Name-Comment: key for signing
        Name-Email: your.email@example.com
        Expire-Date: 0
        EOF
        """

        # Execute the command
        subprocess.run(gpg_key_generate_command, shell=True, check=True)
        # logger.info("GPG RSA key generated successfully.")

    # Sign the setup script and save the signature to sig_setup_path
    sign_command = f'gpg --batch --yes --armor --detach-sign --output {signature_path} {file_path}'
    subprocess.run(sign_command, shell=True, check=True)

    # Retrieve the public key (for the associated email used during key generation)
    public_key_command = "gpg --armor --export your.email@example.com"
    result = subprocess.run(public_key_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Check if we successfully retrieved the public key
    if result.returncode == 0:
        public_key = result.stdout.decode('utf-8')
        # logger.info("Public key retrieved successfully.")
    else:
        # logger.error("❌ Failed to retrieve the GPG public key.")
        public_key = None

    # Save the public key to a file
    if public_key:
        with open(public_key_file, 'w') as f:
            f.write(public_key)
        # logger.info(f"Public key saved to {public_key_file}")

    return signature_path, public_key_file
    
async def get_remote_file_contents(ip: str, key_path: str, ssh_user: str, remote_file_path: str) -> str:
    """Retrieve the contents of a file from the remote machine via SSH."""
    command = f"cat {remote_file_path}"
    result = await ssh_connect_execute(ip, key_path, ssh_user, command)
    # Ensure that the result is being treated as the stdout from the Result object
    return result.stdout.strip()  # Access stdout and then apply strip

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


async def run_cmd_async(
    conn: asyncssh.SSHClientConnection,
    cmd: Union[str, list],
    ignore_errors: bool = True,
    logging_output: bool = False,
    use_sudo: bool = True,
) -> object:
    """
    Executes a command on a remote machine asynchronously using SSH.

    Args:
        conn (asyncssh.SSHClientConnection): An active SSH connection.
        cmd (Union[str, list]): The command to execute as a string or list.
        ignore_errors (bool, optional): Whether to suppress command errors. Defaults to True.
        logging_output (bool, optional): Whether to log the command output. Defaults to False.
        use_sudo (bool, optional): Whether to run the command with sudo. Defaults to True.
        timeout (int, optional): Timeout in seconds. Defaults to None (no timeout).

    Returns:
        object: A response object with stdout, stderr, exit_status, and returncode.
    """

    # Convert list to properly formatted command string
    cmd = ' '.join(cmd) if isinstance(cmd, list) else cmd

    # Set environment variables for apt operations
    env = os.environ.copy()
    if any(x in cmd for x in ['apt-get', 'apt', 'dpkg']):
        env['DEBIAN_FRONTEND'] = 'noninteractive'

    # Escape single quotes
    escaped = cmd.replace("'", "'\\''")

    # Construct final command with sudo if needed
    final_cmd = f"sudo -S bash -c '{escaped}'" if use_sudo else f"bash -c '{escaped}'"

    try:
        result = await conn.run(final_cmd, check=True)

        out = result.stdout.strip()
        err = result.stderr.strip()

        if err and not ignore_errors:
            log_message("WARNING", f"⚠️ Command error '{cmd}': {err}")
        elif out and logging_output:
            log_message("INFO", f"🔎 Command '{cmd}' output: {out}")

        # Return object with both exit_status and returncode
        return type('Result', (object,), {
            'stdout': out,
            'stderr': err,
            'exit_status': result.exit_status,
            'returncode': result.exit_status,  # Alias for compatibility
        })()

    except asyncssh.ProcessError as e:
        # log_message("ERROR", f"🚨 Command execution failed: {cmd} - {str(e)}")
        if not ignore_errors:
            raise

        return type('Result', (object,), {
            'stdout': '',
            'stderr': str(e),
            'exit_status': e.exit_status,
            'returncode': e.exit_status,
        })()


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
            - If a command is provided, returns the result of run_cmd_async.
    """

    try:
        async with asyncssh.connect(ip, username=username, client_keys=[private_key_path], known_hosts=None) as client:
            if cmd:
                try:
                    return await run_cmd_async(client, cmd)
                except Exception as e:
                    # logger.error(f"Command execution failed on {ip}: {str(e)}")
                    return False  # Command execution failed

        return True  # Connection (and command execution, if any) was successful

    except asyncssh.Error as e:
        # logger.error(f"SSH connection failed for {ip}: {str(e)}")
        return False

def get_remaining_time(duration):
    current_time = time.time()
    next_event_time = ((current_time // duration) + 1) * duration
    remaining_time = next_event_time - current_time
    remaining_minutes = int(remaining_time // 60)
    remaining_seconds = int(remaining_time % 60)

    return f"{remaining_minutes}m {remaining_seconds}s"