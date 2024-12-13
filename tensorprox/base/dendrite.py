import numpy as np
from tensorprox.base.protocol import PingSynapse, MachineDetails
from pydantic import BaseModel, model_validator, ConfigDict
import paramiko
import io
import re

# Function to validate IPv4 format
def is_valid_ip(ip: str) -> bool:
    # Regex for valid IPv4 address
    ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    
    # Check if the IP matches the pattern
    return re.match(ip_pattern, ip) is not None

# Define the machine setup function after SSH connection
def initiate_machine_setup(machine_name: str, machine_details: MachineDetails, private_key_str: str):
    """
    Tests the SSH connection and, if successful, initiates the setup process for a given machine.
    """
    ip = machine_details.ip

    # Validate IP format
    if not is_valid_ip(ip):
        print(f"Error: Invalid IP format for {machine_name} at {ip}")
        return  # Exit early if IP format is invalid
    
    print(f"Testing SSH connection for {machine_name} at IP {ip}")
    
    try:
        # Set up SSH client for testing connection
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Convert private key string to key object
        private_key = paramiko.RSAKey.from_private_key(io.StringIO(private_key_str))

        # Attempt to connect via SSH
        client.connect(ip, username="azureuser", pkey=private_key, timeout=10)
        client.close()  # Close the connection after the test

        # If connection is successful, proceed with setup
        print(f"SSH connection to {machine_name} ({ip}) succeeded.")
        print(f"Initiating setup for {machine_name} at {ip}")

        # Setup commands to execute after SSH connection
        setup_commands = [
            "sudo apt update",
            "sudo apt install -y npm",
        ]

        # Establish SSH connection to execute setup commands
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(ip, username="azureuser", pkey=private_key, timeout=10)

        # Execute the setup commands
        for command in setup_commands:
            stdin, stdout, stderr = ssh_client.exec_command(command)
            print(stdout.read().decode())
        
        ssh_client.close()  # Close the connection after setup
        print(f"Setup completed for {machine_name}.")
    except paramiko.AuthenticationException:
        print(f"SSH authentication failed for {machine_name} ({ip}).")
    except paramiko.SSHException as e:
        print(f"SSH error for {machine_name} ({ip}): {e}")
    except Exception as e:
        print(f"Unexpected error for {machine_name} ({ip}): {e}")


class DendriteResponseEvent(BaseModel):
    uids: np.ndarray | list[float]
    results: list[PingSynapse]
    status_messages: list[str] = []
    status_codes: list[int] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @staticmethod
    def save_private_key(private_key_str: str, file_path: str):
        """
        Save the private key to a local file for future use.
        """
        try:
            with open(file_path, "w") as key_file:
                key_file.write(private_key_str)
            # Set appropriate file permissions
            import os
            os.chmod(file_path, 0o600)
            print(f"Private key saved to {file_path}")
        except Exception as e:
            print(f"Error saving private key: {e}")

    # Process and structure miner's responses
    @model_validator(mode="after")
    def process_results(self) -> "DendriteResponseEvent":
        for synapse in self.results:
            ssh_public_key, ssh_private_key = synapse.machine_availabilities.key_pair
            machine_config = synapse.machine_availabilities.machine_config

            for machine_name, machine_details in machine_config.items():
                
                ip = machine_details.ip

                # Save private key to file for testing SSH connection
                private_key_path = f"/tmp/{machine_name}_private_key.pem"
                self.save_private_key(ssh_private_key, private_key_path)

                try:
                    # Test SSH connection and initiate setup if successful
                    print(f"Attempting to connect to {machine_name} at {ip}")
                    initiate_machine_setup(machine_name, machine_details, ssh_private_key)

                    self.status_messages.append(f"Connection to {machine_name} at {ip} successful.")
                    self.status_codes.append(200)  # Success

                except TimeoutError:
                    print(f"SSH connection to {machine_name} ({ip}) timed out.")
                    self.status_messages.append(f"Connection to {machine_name} at {ip} timed out.")
                    self.status_codes.append(408)  # Request Timeout

                except paramiko.AuthenticationException:
                    print(f"SSH authentication failed for {machine_name} ({ip}).")
                    self.status_messages.append(f"Authentication failed for {machine_name} at {ip}.")
                    self.status_codes.append(403)  # Forbidden

                except paramiko.SSHException as e:
                    print(f"SSH error for {machine_name} ({ip}): {e}")
                    self.status_messages.append(f"SSH error for {machine_name} at {ip}: {e}")
                    self.status_codes.append(500)  # Internal Server Error

                except Exception as e:
                    print(f"Unexpected error for {machine_name} ({ip}): {e}")
                    self.status_messages.append(f"Unexpected error for {machine_name} at {ip}: {e}")
                    self.status_codes.append(520)  # Unknown Error (Custom Code)

        return self
