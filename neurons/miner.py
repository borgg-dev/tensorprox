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


def generate_ssh_key_pair():
    """
    Generates a random RSA SSH key pair and returns the public key as a string.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode("utf-8")

    return public_key_str

def add_ssh_key_to_remote_machine(machine_ip: str, ssh_public_key: str, private_key_path: str, username: str = os.environ.get("USERNAME")):
    """
    Connects to a remote machine via SSH and appends the given SSH public key to the authorized_keys file
    if it does not already exist.
    """
    # Set up SSH client with the private key
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Automatically add unknown host keys
    
    try:
        # Use the private key to authenticate
        print(f"Connecting to {machine_ip} using private key {private_key_path}...")
        ssh.connect(machine_ip, username=username, key_filename=private_key_path)

        # Ensure the .ssh directory exists on the remote machine
        ssh.exec_command(f"mkdir -p /home/{username}/.ssh")
        ssh.exec_command(f"chmod 700 /home/{username}/.ssh")

        # Check if the key already exists in authorized_keys
        stdin, stdout, stderr = ssh.exec_command(f"grep -F '{ssh_public_key}' /home/{username}/.ssh/authorized_keys")
        output = stdout.read().decode().strip()
        
        if ssh_public_key in output:
            print(f"SSH key already exists on {machine_ip}")
        else:
            # Append the SSH public key to authorized_keys
            command = f'echo "{ssh_public_key}" >> /home/{username}/.ssh/authorized_keys'
            ssh.exec_command(command)
            
            # Set the correct permissions
            ssh.exec_command(f"chmod 600 /home/{username}/.ssh/authorized_keys")
            print(f"SSH key added to {machine_ip}")
        
    except Exception as e:
        print(f"Error while connecting to {machine_ip}: {e}")
    finally:
        ssh.close()

class Miner(BaseMinerNeuron):
    should_exit: bool = False


    def forward(self, synapse: PingSynapse) -> PingSynapse:
        """The forward function predicts class output for a set of features and forwards it to the validator."""


        logger.debug(f"📧 Ping received from {synapse.dendrite.hotkey}, IP: {synapse.dendrite.ip}.")

        try:
            
            synapse.machine_availabilities.machine_config["Attacker"] = MachineDetails(ip=os.environ.get("ATTACKER_IP"))
            synapse.machine_availabilities.machine_config["Benign"] = MachineDetails(ip=os.environ.get("BENIGN_IP"))
            synapse.machine_availabilities.machine_config["King"] = MachineDetails(ip=os.environ.get("KING_IP"))

            ssh_public_key = generate_ssh_key_pair()
            synapse.ssh_public_key = ssh_public_key

            # Let's extract the public key from the response and update the King machine's authorized_keys
            for machine_name, machine_details in synapse.machine_availabilities.machine_config.items():
                machine_ip = machine_details.ip
                logger.debug(f"Received SSH public key for validator: {ssh_public_key}")
                private_key_path = os.environ.get("PRIVATE_KEY_PATH")
                add_ssh_key_to_remote_machine(machine_ip, ssh_public_key, private_key_path)

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