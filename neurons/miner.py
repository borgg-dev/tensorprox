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
    username: str,
    timeout: int = 5,
    retries: int = 3,
):
    """
    Connects to a remote machine via SSH using the initial private key, appends the given SSH public key 
    to the authorized_keys file if it does not already exist, and updates the sudoers file for passwordless sudo.
    Includes a retry mechanism in case of failure.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    prefix_path = f"/root" if username == "root" else f"/home/{username}"
    
    attempt = 0
    while attempt < retries:
        try:
            print(f"Connecting to {machine_ip} using initial private key at {initial_private_key_path}...")

            # Step 1: Connect using the private key
            ssh.connect(machine_ip, username=username, key_filename=initial_private_key_path, timeout=timeout)

            # Step 2: Ensure the .ssh directory exists
            commands = [
                f"mkdir -p {prefix_path}/.ssh",
                f"chmod 700 {prefix_path}/.ssh",
                f"touch {prefix_path}/.ssh/authorized_keys",
                f"chmod 600 {prefix_path}/.ssh/authorized_keys",
                f"chown -R {username}:{username} {prefix_path}/.ssh"
            ]
            for cmd in commands:
                ssh.exec_command(cmd)

            # Step 3: Check if the public key already exists
            stdin, stdout, stderr = ssh.exec_command(f"cat {prefix_path}/.ssh/authorized_keys")
            authorized_keys = stdout.read().decode().strip()

            if ssh_public_key.strip() in authorized_keys:
                print(f"SSH key already exists on {machine_ip}.")
            else:
                # Step 4: Add the new public key
                print(f"Adding SSH key to {machine_ip}...")
                stdin, stdout, stderr = ssh.exec_command(f'echo "{ssh_public_key.strip()}" >> {prefix_path}/.ssh/authorized_keys')
                error = stderr.read().decode().strip()
                if error:
                    print(f"Error adding SSH key: {error}")
                else:
                    print(f"SSH key successfully added to {machine_ip}.")
                
                # Ensure correct permissions again
                ssh.exec_command(f"chmod 600 {prefix_path}/.ssh/authorized_keys")

            # Step 5: Update sudoers file for passwordless sudo
            sudoers_entry = f"{username} ALL=(ALL) NOPASSWD: ALL"
            print(f"Updating sudoers file for user {username}...")
            stdin, stdout, stderr = ssh.exec_command(f'echo "{sudoers_entry}" | sudo EDITOR="tee -a" visudo')
            err = stderr.read().decode().strip()
            if err:
                print(f"Error updating sudoers file: {err}")
            else:
                print(f"Sudoers file updated on {machine_ip} for user {username}.")
                ssh.exec_command('sudo systemctl restart sudo || echo "Skipping sudo restart"')

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
            username = os.environ.get("USERNAME")
            synapse.machine_availabilities.ssh_user = username
            
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
                    username=username,
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