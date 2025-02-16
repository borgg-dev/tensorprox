# ruff: noqa: E402
import os, sys
sys.path.append(os.path.expanduser("~/tensorprox"))
import os
import paramiko
from tensorprox import settings
settings.settings = settings.Settings.load(mode="miner")
settings = settings.settings
import time
from loguru import logger
from tensorprox.base.miner import BaseMinerNeuron
from tensorprox.utils.logging import ErrorLoggingEvent, log_event
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse, MachineDetails
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from threading import Thread
import asyncio
import socket
import struct

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
            logger.info(f"Connecting to {machine_ip} using initial private key at {initial_private_key_path}...")

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
                logger.info(f"SSH key already exists on {machine_ip}.")
            else:
                # Step 4: Add the new public key
                logger.info(f"Adding SSH key to {machine_ip}...")
                stdin, stdout, stderr = ssh.exec_command(f'echo "{ssh_public_key.strip()}" >> {prefix_path}/.ssh/authorized_keys')
                error = stderr.read().decode().strip()
                if error:
                    logger.error(f"Error adding SSH key: {error}")
                else:
                    logger.info(f"SSH key successfully added to {machine_ip}.")
                
                # Ensure correct permissions again
                ssh.exec_command(f"chmod 600 {prefix_path}/.ssh/authorized_keys")

            # Step 5: Update sudoers file for passwordless sudo
            sudoers_entry = f"{username} ALL=(ALL) NOPASSWD: ALL"
            logger.info(f"Updating sudoers file for user {username}...")
            stdin, stdout, stderr = ssh.exec_command(f'echo "{sudoers_entry}" | sudo EDITOR="tee -a" visudo')
            err = stderr.read().decode().strip()
            if err:
                logger.error(f"Error updating sudoers file: {err}")
            else:
                logger.info(f"Sudoers file updated on {machine_ip} for user {username}.")
                ssh.exec_command('sudo systemctl restart sudo || echo "Skipping sudo restart"')

            break  # Exit loop if successful

        except paramiko.ssh_exception.SSHException as e:
            attempt += 1
            logger.error(f"Error while connecting to {machine_ip} on attempt {attempt}/{retries}: {e}")
            if attempt == retries:
                logger.error(f"Failed to connect to {machine_ip} after {retries} attempts.")

        except socket.error as e:
            logger.error(f"Network error while connecting to {machine_ip}: {e}")
            if attempt == retries:
                logger.error(f"Failed to connect to {machine_ip} after {retries} attempts.")

        finally:
            ssh.close()


# Moat logic: intercepts and forwards packets to King
async def moat_forward_packet(packet, destination_ip, destination_port, protocol):
    """
    Forward the packet to King based on its protocol (TCP/UDP).
    """
    try:
        if protocol == 6:  # TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((destination_ip, destination_port))
                s.sendall(packet)
                logger.info(f"Forwarded TCP packet to King at {destination_ip}:{destination_port}")
        elif protocol == 17:  # UDP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(packet, (destination_ip, destination_port))
                logger.info(f"Forwarded UDP packet to King at {destination_ip}:{destination_port}")
    except Exception as e:
        logger.error(f"Error forwarding packet to King: {e}")
        

async def handle_moat_connection(packet_data, king_private_ip, destination_port, protocol):
    """
    Handle the incoming packet, validate it, and forward to King.
    """
    if packet_data:
        logger.info("Received packet for validation")

        if is_allowed_packet(packet_data):
            logger.info("Packet allowed by Moat, forwarding to King...")
            # Forward to King (replace 'KING_IP_ADDRESS' with the real IP of King)
            await moat_forward_packet(packet_data, king_private_ip, destination_port, protocol)  # Example: King's IP and port 8080
        else:
            logger.warning("Packet blocked by Moat")

    # Respond with a simple acknowledgment message
    return b"Packet processed"


# Logic to check if packet is allowed (this can be customized)
def is_allowed_packet(packet):
    """
    This is where you define whether a packet should be allowed or blocked.
    For now, we just allow all packets.
    """
    return True  # Allow all packets (customize this with your logic)

# Sniff packets in a streamed manner and forward to Moat for processing
async def process_packet_stream(packet_data, king_private_ip):
    """
    Processes packets in a streamed fashion and forwards them to Moat for validation.
    """
    eth_header = packet_data[0:14]
    eth_protocol = struct.unpack('!H', eth_header[12:14])[0]

    if eth_protocol != 0x0800:
        return  # Ignore non-IPv4 packets

    ip_header = packet_data[14:34]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    protocol = iph[6]

    if protocol not in (6, 17):
        return  # Ignore non-TCP and non-UDP packets

    src_ip = socket.inet_ntoa(iph[8])  # Extract source IP

    if src_ip == king_private_ip:
        logger.info("Decision engine processing...")
        await handle_moat_connection(packet_data, king_private_ip, 8080, protocol)  # Moat listens on port 8081

# Function to continuously sniff packets and handle them in a stream
async def sniff_packets_stream(king_private_ip, iface='eth0'):
    """Sniffs packets in a continuous stream and forwards them to Moat for processing."""
    logger.info(f"Sniffing packets for King Private IP: {king_private_ip} on interface {iface}")

    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # Capture all layers
    raw_socket.bind((iface, 0))

    while True:
        packet_data = raw_socket.recv(65535)  # Receive raw packet
        await process_packet_stream(packet_data, king_private_ip)


def run_async_packet_stream(king_private_ip, iface='eth0'):
    """Runs the asyncio event loop for packet sniffing and handling in a streamed way."""
    loop = asyncio.new_event_loop()  # Create a new event loop
    asyncio.set_event_loop(loop)  # Set the loop for this thread
    loop.run_until_complete(sniff_packets_stream(king_private_ip, iface))  # Run the async function


class Miner(BaseMinerNeuron):
    should_exit: bool = False
    firewall_active: bool = False  # To prevent redundant setups

    def forward(self, synapse: PingSynapse) -> PingSynapse:
        """The forward function predicts class output for a set of features and forwards it to the validator."""

        logger.debug(f"📧 Ping received from {synapse.dendrite.hotkey}, IP: {synapse.dendrite.ip}.")

        try:
            ssh_public_key, ssh_private_key = generate_ssh_key_pair()
            attacker_username = os.environ.get("ATTACKER_USERNAME")
            benign_username = os.environ.get("BENIGN_USERNAME")
            king_username = os.environ.get("KING_USERNAME")
            
            synapse.machine_availabilities.key_pair = (ssh_public_key, ssh_private_key)
            synapse.machine_availabilities.machine_config["Attacker"] = MachineDetails(ip=os.environ.get("ATTACKER_IP"), username=attacker_username)
            synapse.machine_availabilities.machine_config["Benign"] = MachineDetails(ip=os.environ.get("BENIGN_IP"), username=benign_username)
            synapse.machine_availabilities.machine_config["King"] = MachineDetails(ip=os.environ.get("KING_IP"), username=king_username, private_ip=os.environ.get("KING_PRIVATE_IP"))
            synapse.machine_availabilities.machine_config["Moat"] = MachineDetails(private_ip=os.environ.get("MOAT_PRIVATE_IP"))

            
            # Use the initial private key for initial connection
            initial_private_key_path = os.environ.get("PRIVATE_KEY_PATH")

            # Add the public key to each machine
            for machine_name, machine_details in synapse.machine_availabilities.machine_config.items():
                if machine_name == "Moat":
                    continue  # Skip the Moat machine
                machine_ip = machine_details.ip
                machine_username = machine_details.username
                logger.debug(f"Adding SSH key to {machine_name} at IP {machine_ip}")
                add_ssh_key_to_remote_machine(
                    machine_ip=machine_ip,
                    ssh_public_key=ssh_public_key,
                    initial_private_key_path=initial_private_key_path,
                    username=machine_username,
                )

        except Exception as e:
            logger.exception(e)
            logger.error(f"Error in forward: {e}")
            log_event(ErrorLoggingEvent(error=str(e)))
            if NEURON_STOP_ON_FORWARD_EXCEPTION:
                self.should_exit = True


        logger.debug(f"⏩ Forwarding Ping synapse with machine details to validator {synapse.dendrite.hotkey}: {synapse}.")

        return synapse

    def handle_challenge(self, synapse: ChallengeSynapse) -> ChallengeSynapse:
        """The forward function for ChallengeSynapse, processing challenge details and responding back."""
        logger.debug(f"📧 Challenge received from {synapse.dendrite.hotkey}, IP: {synapse.dendrite.ip}.")

        try:
            # Extract challenge information from the synapse
            task = synapse.task
            state=synapse.state
            king_private_ip = os.environ.get("KING_PRIVATE_IP")
            challenge_start_time = synapse.challenge_start_time
            challenge_end_time = synapse.challenge_end_time
            challenge_duration = synapse.challenge_duration
            
            if state=="GET_READY" :
                logger.debug(f"Getting ready for Challenge.. Task received : {task}")

                if not self.firewall_active:
                    self.firewall_active = True
                    firewall_thread = Thread(target=run_async_packet_stream, args=(king_private_ip, "eth0"))
                    firewall_thread.daemon = True
                    firewall_thread.start()
                else :
                    logger.info("💥 Moat firewall already activated.")

            elif state=="END_ROUND" :
                logger.debug(f"🔚 Challenge ended . Summary - Start time : {challenge_start_time}, End time : {challenge_end_time}, Duration : {challenge_duration}.")

                if self.firewall_active:
                    self.firewall_active = False
                    self.stop_thread.set()  # Signal the thread to stop
                    if self.firewall_thread:
                        self.firewall_thread.join()  # Ensure the thread stops
                    logger.info("🛑 Moat firewall deactivated.")
                else :
                    logger.info("💥 Moat firewall already deactivated.")

                logger.debug(f"Waiting for the next round..")

        except Exception as e:
            logger.exception(e)
            logger.error(f"Error in challenge handling: {e}")
            log_event(ErrorLoggingEvent(error=str(e)))
            if NEURON_STOP_ON_FORWARD_EXCEPTION:
                self.should_exit = True

        return synapse

if __name__ == "__main__":
    with Miner() as miner:
        while not miner.should_exit:
            miner.log_status()
            time.sleep(5)
        logger.warning("Ending miner...")