# ruff: noqa: E402
import sys
sys.path.append("/home/azureuser/tensorprox/")
import os
import paramiko
# This is an example miner that can respond to the inference task using a vllm model.
from tensorprox import settings

settings.settings = settings.Settings.load(mode="miner")
settings = settings.settings
import time
from loguru import logger
from tensorprox.base.miner import BaseMinerNeuron
from tensorprox.utils.logging import ErrorLoggingEvent, log_event
from tensorprox.base.protocol import PingSynapse, MachineDetails
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

NEURON_STOP_ON_FORWARD_EXCEPTION: bool = False

def generate_ssh_key_pair() -> tuple[str, str]:
    """
    Generates a random RSA SSH key pair and returns the private and public keys as strings.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Serialize private key
    private_key_str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    # Serialize public key
    public_key = private_key.public_key()
    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8")

    return public_key_str, private_key_str

def add_ssh_key_to_remote_machine(
    machine_ip: str,
    ssh_public_key: str,
    initial_private_key_path: str,
    username: str = os.environ.get("USERNAME"),
    timeout: int = 5,
    retries: int = 3,
):
    """
    Connects to a remote machine via SSH using the initial private key and appends the given SSH public key 
    to the authorized_keys file if it does not already exist. Includes retry mechanism in case of failure.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    attempt = 0
    while attempt < retries:
        try:
            # Step 1: Use the initial private key to connect
            print(f"Connecting to {machine_ip} using initial private key at {initial_private_key_path}...")

            ssh.connect(machine_ip, username=username, key_filename=initial_private_key_path, timeout=timeout)

            # Step 2: Ensure the .ssh directory exists
            ssh.exec_command(f"mkdir -p /home/{username}/.ssh")
            ssh.exec_command(f"chmod 700 /home/{username}/.ssh")

            # Step 3: Check if the public key already exists
            stdin, stdout, stderr = ssh.exec_command(
                f"grep -F '{ssh_public_key}' /home/{username}/.ssh/authorized_keys"
            )
            output = stdout.read().decode().strip()

            if ssh_public_key in output:
                print(f"SSH key already exists on {machine_ip}")
            else:
                # Step 4: Add the new public key to authorized_keys
                ssh.exec_command(f'echo "{ssh_public_key}" >> /home/{username}/.ssh/authorized_keys')
                ssh.exec_command(f"chmod 600 /home/{username}/.ssh/authorized_keys")
                print(f"SSH key added to {machine_ip}")
            break  # Exit loop if successful
        except paramiko.ssh_exception.SSHException as e:
            attempt += 1
            print(f"Error while connecting to {machine_ip} on attempt {attempt}/{retries}: {e}")
            if attempt == retries:
                print(f"Failed to connect to {machine_ip} after {retries} attempts.")
        finally:
            ssh.close()



class Miner(BaseMinerNeuron):
    should_exit: bool = False

    def forward(self, synapse: PingSynapse) -> PingSynapse:
        """The forward function predicts class output for a set of features and forwards it to the validator."""


        logger.debug(f"📧 Ping received from {synapse.dendrite.hotkey}, IP: {synapse.dendrite.ip}.")

        try:
            ssh_public_key, ssh_private_key = generate_ssh_key_pair()
            synapse.machine_availabilities.key_pair = (ssh_public_key, ssh_private_key)
            synapse.machine_availabilities.machine_config["Attacker"] = MachineDetails(ip=os.environ.get("ATTACKER_IP"))
            synapse.machine_availabilities.machine_config["Benign"] = MachineDetails(ip=os.environ.get("BENIGN_IP"))
            synapse.machine_availabilities.machine_config["King"] = MachineDetails(ip=os.environ.get("KING_IP"))
            

            # Use the initial private key for initial connection
            initial_private_key_path = os.environ.get("PRIVATE_KEY_PATH")

            # Add the public key to each machine
            for machine_name, machine_details in synapse.machine_availabilities.machine_config.items():
                machine_ip = machine_details.ip
                logger.debug(f"Adding SSH key to {machine_name} at IP {machine_ip}")
                add_ssh_key_to_remote_machine(
                    machine_ip=machine_ip,
                    ssh_public_key=ssh_public_key,
                    initial_private_key_path=initial_private_key_path,
                )

        except Exception as e:
            logger.exception(e)
            logger.error(f"Error in forward: {e}")
            log_event(ErrorLoggingEvent(error=str(e)))
            if NEURON_STOP_ON_FORWARD_EXCEPTION:
                self.should_exit = True


        logger.debug(f"⏩ Forwarding Ping synapse with machine details to validator {synapse.dendrite.hotkey}: {synapse}.")

        self.step += 1

        return synapse


if __name__ == "__main__":
    with Miner() as miner:
        while not miner.should_exit:
            miner.log_status()
            time.sleep(5)
        logger.warning("Ending miner...")