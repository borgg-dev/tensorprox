import numpy as np
from tensorprox.base.protocol import PingSynapse, MachineDetails
from pydantic import BaseModel, model_validator, ConfigDict
import paramiko
import io
import re
import logging
from datetime import datetime
import time

# Function to validate IPv4 format
def is_valid_ip(ip: str) -> bool:
    ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(ip_pattern, ip) is not None

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def log_message(level: str, message: str):
    if level.upper() == "INFO":
        logging.info(message)
    elif level.upper() == "WARNING":
        logging.warning(message)
    elif level.upper() == "ERROR":
        logging.error(message)
    else:
        logging.debug(message)

def create_and_test_connection(machine_name: str, machine_details: MachineDetails, private_key_str: str, retries: int = 3, timeout: int = 5) -> paramiko.SSHClient:
    ip = machine_details.ip
    attempt = 0

    while attempt < retries:
        try:
            log_message("INFO", f"Testing SSH connection for {machine_name} at {ip}, attempt {attempt + 1}/{retries}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            private_key = paramiko.RSAKey.from_private_key(io.StringIO(private_key_str))
            client.connect(ip, username="azureuser", pkey=private_key, timeout=timeout)
            log_message("INFO", f"SSH connection to {machine_name} ({ip}) succeeded.")
            return client
        except paramiko.AuthenticationException:
            log_message("ERROR", f"SSH authentication failed for {machine_name} ({ip}).")
        except paramiko.SSHException as e:
            log_message("ERROR", f"SSH error for {machine_name} ({ip}): {e}")
        except Exception as e:
            log_message("ERROR", f"Unexpected error for {machine_name} ({ip}): {e}")
        
        attempt += 1
        if attempt < retries:
            log_message("WARNING", f"Retrying SSH connection for {machine_name} ({ip})...")
            time.sleep(2)  # Optional: wait for a short period before retrying

    return None

def initiate_machine_setup(machine_name: str, machine_details: MachineDetails, private_key_str: str, setup_commands: list):
    ip = machine_details.ip
    client = create_and_test_connection(machine_name, machine_details, private_key_str)
    if not client:
        log_message("ERROR", f"Setup aborted for {machine_name} due to failed SSH connection.")
        return False  # Return False to indicate failure

    try:
        log_message("INFO", f"Starting setup for {machine_name} at {ip}")
        for command in setup_commands:
            stdin, stdout, stderr = client.exec_command(command)
            log_message("INFO", f"Output for {command}: {stdout.read().decode()}")
        log_message("INFO", f"Setup completed for {machine_name}.")
        return True  # Return True to indicate success
    except paramiko.SSHException as e:
        log_message("ERROR", f"SSH error during setup for {machine_name} ({ip}): {e}")
        return False  # Return False on error
    except Exception as e:
        log_message("ERROR", f"Unexpected error during setup for {machine_name} ({ip}): {e}")
        return False  # Return False on unexpected error
    finally:
        client.close()

class DendriteResponseEvent(BaseModel):
    uids: np.ndarray | list[float]
    results: list[PingSynapse]
    status_messages: list[str] = []
    status_codes: list[int] = []
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @staticmethod
    def save_private_key(private_key_str: str, file_path: str):
        try:
            with open(file_path, "w") as key_file:
                key_file.write(private_key_str)
            import os
            os.chmod(file_path, 0o600)
            log_message("INFO", f"Private key saved to {file_path}")
        except Exception as e:
            log_message("ERROR", f"Error saving private key: {e}")

    @model_validator(mode="after")
    def process_results(self) -> "DendriteResponseEvent":

        setup_commands = {
            "Attacker": ["sudo apt update", "sudo apt install -y npm"],
            "Benign": ["sudo apt update", "sudo apt install -y npm"],
            "King": ["sudo apt update", "sudo apt install -y npm"],
        }

        for synapse in self.results:

            ssh_public_key, ssh_private_key = synapse.machine_availabilities.key_pair
            machine_config = synapse.machine_availabilities.machine_config

            # Save private key
            self.save_private_key(ssh_private_key, "/tmp/private_key.pem")

            all_connections_successful = True
            all_setups_successful = True

            # Key pair check
            if not ssh_public_key or not ssh_private_key or ssh_public_key == '' or ssh_private_key == '':
                log_message("ERROR", "Missing SSH Key Pair. Skipping this synapse.")
                self.status_messages.append("Missing SSH Key Pair.")
                self.status_codes.append(400)
                continue

            # IP check
            if not machine_config or any(not is_valid_ip(md.ip) for md in machine_config.values()):
                log_message("ERROR", "Invalid IP format. Skipping this synapse.")
                self.status_messages.append("Invalid IP format.")
                self.status_codes.append(400)
                continue

            # Test SSH connections
            for machine_name, machine_details in machine_config.items():
                client = create_and_test_connection(machine_name, machine_details, ssh_private_key)
                if not client:
                    all_connections_successful = False
                    self.status_messages.append("One or more connections failed.")
                    self.status_codes.append(500)
                    break

            if all_connections_successful:
                # Proceed with setup
                for machine_name, machine_details in machine_config.items():
                    success = initiate_machine_setup(machine_name, machine_details, ssh_private_key, setup_commands.get(machine_name, []))
                    if not success:
                        all_setups_successful = False
                        self.status_messages.append("One or more setups failed.")
                        self.status_codes.append(500)
                        break

            if all_connections_successful and all_setups_successful:
                self.status_messages.append("All machines connected and setup successfully.")
                self.status_codes.append(200)

        return self
