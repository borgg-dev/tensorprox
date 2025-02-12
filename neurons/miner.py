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
import random
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

async def handle_client(king_private_ip, data, decision_engine):
    """
    Handles client connections, decides whether to forward or drop based on decision_engine.
    """

    decision = await decision_engine(data)
    decision = "allow"

    if decision == "allow":
        try:
            # Use King’s private IP for Moat to King connection
            logger.info(f"✅ allowed - data_length: {len(data)}")
            reader, writer = await asyncio.open_connection(king_private_ip, 8080)
            writer.write(data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.error(f"Error forwarding packet to King at Private IP: {e}")
            log_event(ErrorLoggingEvent(error=str(e)))
    else:
        logger.info(f"🚫 blocked - data_length: {len(data)}")

    return None  # If dropped, nothing is returned

async def decision_engine(packet_data):
    """
    Placeholder for decision engine logic based on packet data.
    """
    # Replace this with your actual decision-making logic
    return "allow" if random.choice([True, False]) else "attack"


async def process_packet(packet_data, king_private_ip):
    """
    Processes packet data using raw socket. This function filters for TCP and UDP packets,
    extracts the IP information, and forwards the packet or drops it based on the
    decision engine logic.
    """

    # Ethernet header is the first 14 bytes
    eth_header = packet_data[0:14]
    eth_protocol = struct.unpack('!H', eth_header[12:14])[0]

    # Check if the packet is an IPv4 packet (protocol 0x0800)
    if eth_protocol != 0x0800:
        return  # Ignore non-IPv4 packets

    # Extract the IP header (next 20 bytes after Ethernet header)
    ip_header = packet_data[14:34]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    # Extract protocol type from IP header (6 = TCP, 17 = UDP)
    protocol = iph[6]

    if protocol not in (6, 17):
        return  # Ignore non-TCP and non-UDP packets

    # Extract destination IP from IP header
    src_ip = socket.inet_ntoa(iph[8])  # Extract source IP (from the IP header)

    # Process the packet if it's destined for the King
    if src_ip == king_private_ip:
        
        # Call the async handle_client function
        await handle_client(king_private_ip, packet_data, decision_engine)

async def sniff_packets(king_private_ip, iface='eth0'):
    """Sniffs packets using raw socket and forwards them or drops them based on decision engine."""
    logger.info(f"Sniffing packets for King Public IP: {king_private_ip} on interface {iface}")

    # Create a raw socket to capture all packets on the network
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # 0x0003 to capture all layers (ETH_P_ALL)
    raw_socket.bind((iface, 0))  # Bind to the interface to start capturing

    while True:
        packet_data = raw_socket.recv(65535)  # Receive raw packet
        # We need to await the process_packet function here
        await process_packet(packet_data, king_private_ip)


def run_async_sniffer(king_private_ip, iface='eth0'):
    """Runs the asyncio event loop for packet sniffing."""
    loop = asyncio.new_event_loop()  # Create a new event loop for the thread
    asyncio.set_event_loop(loop)  # Set the loop for this thread
    loop.run_until_complete(sniff_packets(king_private_ip, iface))  # Run the async function
    
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
            king_private_ip = synapse.king_private_ip
            moat_ip = synapse.moat_private_ip
            challenge_duration = synapse.challenge_duration
            
            logger.debug(f"Challenge details: King IP: {king_private_ip}, Moat IP: {moat_ip}, Duration: {challenge_duration} sec")

            if not self.firewall_active:
                self.firewall_active = True
                firewall_thread = Thread(target=run_async_sniffer, args=(king_private_ip, "eth0"))
                firewall_thread.daemon = True
                firewall_thread.start()
            else :
                logger.info("💥 Moat firewall already activated.")

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