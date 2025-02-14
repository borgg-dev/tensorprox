#!/usr/bin/env python3

import asyncio
import os
import random
from typing import List, Dict, Tuple, Union, Optional
from loguru import logger
from pydantic import BaseModel
from datetime import datetime
import time
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse
from tensorprox.base.loop_runner import AsyncLoopRunner
from tensorprox.settings import settings
from tensorprox.utils.uids import get_uids, extract_axons_ips
from tensorprox.utils.timer import Timer
from tensorprox.base.protocol import MachineConfig
import dotenv
import paramiko
from paramiko import RSAKey
from paramiko.ed25519key import Ed25519Key
import io
import re
import logging
import string
import asyncssh
import traceback
from tensorprox.miner_availability.session_commands import (
    get_insert_key_cmd,
    get_sudo_setup_cmd,
    get_persist_revert_cmd,
    get_revert_script_cmd,
    get_lockdown_cmd,
)


######################################################################
# 1) LOCAL FUNCTIONS / UTILITIES
######################################################################

dotenv.load_dotenv()

def log(message: str, log_file_path: str = "/var/log/validator_session.log"):
    """
    Simple logger for local console + local log file.
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(message)
    print(f"{now} - {message}")

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

def is_valid_ip(ip: str) -> bool:
    if not isinstance(ip, str):  # Check if ip is None or not a string
        return False
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?\d?\d?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?\d?\d?)$"
    return re.match(pattern, ip) is not None

def get_local_ip() -> str:
    """
    Attempt to get IP for firewall rules on remote, using public IP first,
    then falling back to local IP if public IP check fails.
    """
    try:
        import requests
        public_ip = requests.get('https://api.ipify.org').text.strip()
        if is_valid_ip(public_ip):
            return public_ip
    except Exception:
        pass
    try:
        import subprocess
        local_ip = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
        if is_valid_ip(local_ip):
            return local_ip
    except:
        pass
    return "127.0.0.1"

SESSION_KEY_DIR = "/var/tmp/session_keys"

if not os.path.exists(SESSION_KEY_DIR):
    try:
        os.makedirs(SESSION_KEY_DIR, mode=0o700, exist_ok=True)
        log_message("INFO", f"Created session key directory at {SESSION_KEY_DIR}")
    except PermissionError as e:
        log_message("ERROR", f"Permission denied while creating {SESSION_KEY_DIR}: {e}")
        raise
    except Exception as e:
        log_message("ERROR", f"Unexpected error while creating {SESSION_KEY_DIR}: {e}")
        raise

def generate_local_session_keypair(key_path: str) -> (str, str):
    """
    Generate an ED25519 keypair. Return (private_key_str, public_key_str).
    Ensures correct file permissions for session keys.
    """
    import subprocess
    try:
        if os.path.exists(key_path):
            os.remove(key_path)
        if os.path.exists(f"{key_path}.pub"):
            os.remove(f"{key_path}.pub")
    except PermissionError as e:
        log_message("ERROR", f"Permission denied while removing {key_path}: {e}")
        raise
    except Exception as e:
        log_message("ERROR", f"Unexpected error while removing {key_path}: {e}")
        raise
    log_message("INFO", "🚀 Generating session ED25519 keypair...")
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""], check=True)
    os.chmod(key_path, 0o600)
    if os.path.exists(f"{key_path}.pub"):
        os.chmod(f"{key_path}.pub", 0o644)
    with open(key_path, "r") as fk:
        priv = fk.read().strip()
    with open(f"{key_path}.pub", "r") as fpk:
        pub = fpk.read().strip()
    log_message("INFO", "✅ Session keypair generated and secured.")
    return priv, pub

######################################################################
# 2) SUPPORTING UTILS
######################################################################

def create_and_test_connection(
    ip: str,
    private_key_str: str,
    ssh_user: str,
    retries: int = 3,
    timeout: int = 5
) -> paramiko.SSHClient | None:
    """
    Attempt SSH connection using exactly the correct key type.
    Retries with a short delay; sets keepalive to avoid abrupt closures.
    """
    attempt = 0
    while attempt < retries:
        try:
            log_message("INFO", f"🔗 Attempting SSH connect to {ip} as '{ssh_user}', attempt {attempt+1}/{retries}...")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if "BEGIN RSA PRIVATE KEY" in private_key_str or "RSA PRIVATE KEY" in private_key_str:
                pkey = RSAKey.from_private_key(io.StringIO(private_key_str))
                log_message("INFO", "🔑 Detected RSA private key format.")
            else:
                pkey = Ed25519Key.from_private_key(io.StringIO(private_key_str))
                log_message("INFO", "🔑 Detected ED25519 private key format.")
            client.connect(ip, username=ssh_user, pkey=pkey, timeout=timeout, look_for_keys=False, allow_agent=False)
            transport = client.get_transport()
            if transport:
                transport.set_keepalive(15)
            log_message("INFO", f"🟢 SSH connection to {ip} succeeded (user={ssh_user}).")
            return client
        except paramiko.AuthenticationException:
            log_message("ERROR", f"❌ SSH authentication failed for {ip} (user={ssh_user}).")
        except paramiko.SSHException as e:
            log_message("ERROR", f"⚠️ SSH error for {ip}: {e}")
        except Exception as e:
            log_message("ERROR", f"💥 Unexpected error for {ip}: {e}")
        attempt += 1
        if attempt < retries:
            time.sleep(2)
    return None

def run_cmd(client: paramiko.SSHClient, cmd: str, ignore_errors=False, use_sudo=True) -> (str, str):
    """
    Enhanced command execution with flexible sudo handling.
    """
    escaped = cmd.replace("'", "'\\''")
    if use_sudo:
        final_cmd = f"sudo -S bash -c '{escaped}'"
    else:
        final_cmd = f"bash -c '{escaped}'"
    stdin, stdout, stderr = client.exec_command(final_cmd)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if err and not ignore_errors:
        log_message("WARNING", f"⚠️ Command error '{cmd}': {err}")
    elif out:
        log_message("INFO", f"🔎 Command '{cmd}' output: {out}")
    return out, err



def install_packages_if_missing(client: paramiko.SSHClient, packages: list[str]):
    """
    Install missing packages via apt-get if not already installed.
    """
    for pkg in packages:
        check_cmd = f"dpkg -s {pkg} >/dev/null 2>&1"
        stdin, stdout, stderr = client.exec_command(check_cmd)
        code = stdout.channel.recv_exit_status()
        if code != 0:
            log_message("INFO", f"📦 Package '{pkg}' missing => installing now...")
            run_cmd(client, "DEBIAN_FRONTEND=noninteractive apt-get update -qq || true", ignore_errors=True)
            run_cmd(client, f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg}", ignore_errors=True)
            time.sleep(1)

def get_authorized_keys_dir(ssh_user: str) -> str:
    """
    Return the path to .ssh for the given user.
    """
    return "/root/.ssh" if ssh_user == "root" else f"/home/{ssh_user}/.ssh"

######################################################################
# 3) SINGLE-PASS SESSION SETUP
######################################################################

def single_pass_setup(
    uid: int,
    ip: str,
    original_priv_key: str,
    ssh_user: str,
    user_commands: list[str],
    backup_suffix : str,
) -> bool:
    """
    Single-pass session setup with proper sudo, ephemeral session key insertion,
    and guaranteed revert after the end of a round on Ubuntu 22.04 LTS.
    The revert is now scheduled via systemd timer units for robustness.
    Additionally, the authorized_keys backup is refreshed on every iteration
    using a unique filename and a hardcoded “open” iptables configuration is used
    for reliable revert.
    Any pending revert jobs and stale sudoers entries are removed before scheduling.
    """
    log_message("INFO", f"🔒 Single-pass session setup for {ip} as '{ssh_user}' start...")

    # A) CONNECT WITH ORIGINAL KEY + PREPARE
    log_message("INFO", f"🌐 Step A: Generating session key + connecting with original SSH key on {ip}...")
    session_key_path = os.path.join(SESSION_KEY_DIR, f"session_key_{uid}_{ip}")
    session_priv, session_pub = generate_local_session_keypair(session_key_path)
    client_orig = create_and_test_connection(ip, original_priv_key, ssh_user=ssh_user, retries=3, timeout=5)
    if not client_orig:
        log_message("ERROR", f"❌ Could NOT connect to {ip} as {ssh_user}. Aborting session setup.")
        return False
    run_cmd(client_orig, "echo 'SUDO_TEST'")
    needed = ["net-tools", "iptables-persistent", "psmisc"]
    install_packages_if_missing(client_orig, needed)
    no_tty_cmd = f"echo 'Defaults:{ssh_user} !requiretty' > /etc/sudoers.d/98_{ssh_user}_no_tty"
    run_cmd(client_orig, no_tty_cmd)
    time.sleep(1)

    # B) INSERT SESSION KEY + UPDATE UNIQUE BACKUP, then CLOSE ORIGINAL
    log_message("INFO", "🔐 Step B: Inserting session key into authorized_keys and refreshing backup.")
    ssh_dir = get_authorized_keys_dir(ssh_user)
    authorized_keys_path = f"{ssh_dir}/authorized_keys"
    authorized_keys_bak = f"{ssh_dir}/authorized_keys.bak_{backup_suffix}"
    
    insert_key_cmd = get_insert_key_cmd(ssh_user, ssh_dir, session_pub, authorized_keys_path, authorized_keys_bak)
    run_cmd(client_orig, insert_key_cmd)
    client_orig.close()
    log_message("INFO", f"🔒 Original SSH connection closed for {ip} (user={ssh_user}).")
    log_message("INFO", f"Backup of authorized_keys stored as: {authorized_keys_bak}")

    # C) TEST SESSION KEY
    log_message("INFO", f"🔑 Step C: Testing session SSH key on {ip} to confirm new session.")
    ep_client = create_and_test_connection(ip, session_priv, ssh_user=ssh_user, retries=3, timeout=5)
    if not ep_client:
        log_message("ERROR", f"❌ Session SSH test failed => skipping {ip}.")
        return False
    log_message("INFO", f"✨ Session key success for {ip}.")

    # D) PREPARE REVERT SCRIPT, CLEAN STALE SUDOERS, & SCHEDULE REVERT VIA SYSTEMD TIMER
    log_message("INFO", "🧩 Step D: Setting up passwordless sudo & running user commands.")

    # Remove any stale sudoers revert entries
    run_cmd(ep_client, f"rm -f /etc/sudoers.d/97_{ssh_user}_revert*", ignore_errors=True)
    
    sudo_setup_cmd = get_sudo_setup_cmd(ssh_user)

    run_cmd(ep_client, sudo_setup_cmd)
    time.sleep(1)
    if user_commands:
        log_message("INFO", f"🛠 Running custom user commands for role on {ip}.")
    for uc in user_commands:
        run_cmd(ep_client, uc, ignore_errors=True)

    log_message("INFO", f"✅ Done single-pass session setup for {ip}.")

    return True


######################################################################
# ASYNCHRONOUS WRAPPER & ADDITIONAL UTILITIES
######################################################################

async def run_cmd_async(conn, cmd: str, ignore_errors=True, use_sudo=True):
    """
    Asynchronous command execution with flexible sudo handling.
    """
    escaped = cmd.replace("'", "'\\''")
    if use_sudo:
        final_cmd = f"sudo -S bash -c '{escaped}'"
    else:
        final_cmd = f"bash -c '{escaped}'"

    result = await conn.run(final_cmd, check=True)
    out = result.stdout.strip()
    err = result.stderr.strip()

    if err and not ignore_errors:
        log_message("WARNING", f"⚠️ Command error '{cmd}': {err}")
    elif out:
        log_message("INFO", f"🔎 Command '{cmd}' output: {out}")

    # Create an object-like response with exit_status, stdout, and stderr
    return type('Result', (object,), {'stdout': out, 'stderr': err, 'exit_status': result.exit_status})()

async def async_single_pass_setup(uid, ip, original_priv_key, ssh_user, user_commands, backup_suffix):
    """
    A wrapper to execute single_pass_setup asynchronously.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None,single_pass_setup, uid, ip, original_priv_key, ssh_user, user_commands, backup_suffix)

    
def save_private_key(priv_key_str: str, path: str):
    """
    Optionally save the original private key locally (for debugging/logging).
    """
    try:
        with open(path, "w") as f:
            f.write(priv_key_str)
        os.chmod(path, 0o600)
        log_message("INFO", f"Saved private key to {path}")
    except Exception as e:
        log_message("ERROR", f"Error saving private key: {e}")

class MinerAvailabilities(BaseModel):
    """Tracks all miners' availability using PingSynapse."""
    miners: Dict[int, 'PingSynapse'] = {}

    def check_machine_availability(self, machine_name: str = None, uid: int = None) -> bool:
        if machine_name == "Moat":
            return True  #Skip Moat
        ip_machine = self.miners[uid].machine_availabilities[machine_name]
        return bool(ip_machine)

    def is_miner_ready(self, uid: int = None) -> bool:
        for machine_name in self.miners[uid].machine_availabilities.keys():
            if machine_name == "Moat":
                continue  #Skip Moat
            if not self.check_machine_availability(machine_name=machine_name, uid=uid):
                return False
        return True

    def get_uid_status_availability(self, k: int = None) -> List[int]:
        available = [uid for uid in self.miners.keys() if self.is_miner_ready(uid)]
        if k:
            available = random.sample(available, min(len(available), k))
        return available


def save_private_key(priv_key_str: str, path: str):
    """Optionally save the original private key locally (for debugging/logging)."""
    try:
        with open(path, "w") as f:
            f.write(priv_key_str)
        os.chmod(path, 0o600)
        logger.info(f"Saved private key to {path}")
    except Exception as e:
        logger.error(f"Error saving private key: {e}")


async def query_availability(uid: int) -> Tuple[PingSynapse, Dict[str, Union[int, str]]]:
    """Query availability for a given uid."""

    # Run all miner queries concurrently
    synapse = PingSynapse(machine_availabilities=MachineConfig())
    uid, synapse = await dendrite_call(uid, synapse)

    uid_status_availability = {"uid": uid, "ping_status_message" : None, "ping_status_code" : None}

    if synapse is None:
        logger.error(f"❌ Miner {uid} query failed.")
        uid_status_availability["ping_status_message"] = "Query failed."
        uid_status_availability["ping_status_code"] = 500

    if not synapse.machine_availabilities.key_pair:
        logger.error(f"❌ Missing SSH Key Pair for UID {uid}, marking as unavailable.")
        uid_status_availability["ping_status_message"] = "Missing SSH Key Pair."
        uid_status_availability["ping_status_code"] = 400

    # Extract SSH key pair safely
    ssh_pub, ssh_priv = synapse.machine_availabilities.key_pair
    save_private_key(ssh_priv, f"/var/tmp/original_key_{uid}.pem")

    all_machines_available = True

    for machine_name, machine_details in synapse.machine_availabilities.machine_config.items():

        if machine_name == "Moat":
            continue  # Skip the Moat machine

        ip = machine_details.ip
        ssh_user = machine_details.username

        if not is_valid_ip(ip):
            logger.error(f"🚨 Invalid IP {ip} for {machine_name}, marking UID {uid} as unavailable.")
            all_machines_available = False
            uid_status_availability["ping_status_message"] = "Invalid IP format."
            uid_status_availability["ping_status_code"] = 400
            break

        # Test SSH Connection (corrected return handling)
        client = create_and_test_connection(ip, ssh_priv, ssh_user)
        if not client:
            logger.error(f"🚨 SSH connection failed for {machine_name} ({ip}) UID {uid}")
            all_machines_available = False
            uid_status_availability["ping_status_message"] = "SSH connection failed."
            uid_status_availability["ping_status_code"] = 500
            break

    if all_machines_available:
        uid_status_availability["ping_status_message"] = f"✅ All machines are accessible for UID {uid}."
        uid_status_availability["ping_status_code"] = 200
    

    return synapse, uid_status_availability


async def dendrite_call(uid: int, synapse: Union[PingSynapse, ChallengeSynapse]):
    """Query a single miner's availability."""
    try:
        axon = settings.METAGRAPH.axons[uid]
        response = await settings.DENDRITE(
            axons=[axon],
            synapse=synapse,
            timeout=settings.NEURON_TIMEOUT,
            deserialize=False,
        )
        return uid, response[0] if response else None  

    except Exception as e:
        logger.error(f"❌ Failed to query miner {uid}: {e}\n{traceback.format_exc()}")
        return uid, None


async def setup_available_machines(available_miners: List[Tuple[int, 'PingSynapse']], backup_suffix: str) -> List[Dict[str, Union[int, str]]]:
    """Setup available machines based on the queried miner availability."""
    role_cmds = {
        "Attacker": ["sudo apt-get update -qq || true"],
        "Benign": ["sudo apt update", "sudo apt install -y npm"],
        "King": ["sudo apt update", "sudo apt install -y npm"],
    }
    local_ip = get_local_ip()
    setup_status = {}

    async def setup_miner(uid, synapse):
        """Setup each miner's machines."""
        ssh_pub, ssh_priv = synapse.machine_availabilities.key_pair
        async def setup_machine(machine_name, machine_details):
            """Perform the setup for a single machine."""
            if machine_name == "Moat":
                return True  # Skip Moat machine setup and consider it successful
            
            ip = machine_details.ip
            ssh_user = machine_details.username
            logger.info(f"🎯 Setting up '{machine_name}' at {ip}, user={ssh_user}.")
            success = await async_single_pass_setup(
                uid=uid,
                ip=ip,
                original_priv_key=ssh_priv,
                ssh_user=ssh_user,
                user_commands=role_cmds.get(machine_name, []),
                backup_suffix=backup_suffix
            )

            return success

        # Run setup tasks for all machines of a miner in parallel
        tasks = [setup_machine(name, details) for name, details in synapse.machine_availabilities.machine_config.items() if name != "Moat"]
        results = await asyncio.gather(*tasks)

        # Determine overall status
        all_success = all(results)
        setup_status[uid] = {
            "setup_status_code": 200 if all_success else 500,
            "setup_status_message": "All machines setup successfully" if all_success else "Failure: Some machines failed to setup",
        }

    # Process all miners in parallel
    await asyncio.gather(*[setup_miner(uid, synapse) for uid, synapse in available_miners])

    return [{"uid": uid, **status} for uid, status in setup_status.items()]

async def lockdown_machines(setup_complete_miners: List[Tuple[int, PingSynapse]]):
    """
    Executes the lockdown step for all given miners after setup is complete.
    """
    validator_ip = get_local_ip()
    lockdown_status = {}

    async def lockdown_miner(uid, synapse):
        """Lock down each miner's machines."""


        async def lockdown_machine(machine_name, machine_details):
            if machine_name == "Moat":
                return True  # Skip Moat machine setup and consider it successful

            ip = machine_details.ip
            ssh_user = machine_details.username
            ssh_dir = get_authorized_keys_dir(ssh_user)
            authorized_keys_path = f"{ssh_dir}/authorized_keys"
            ssh_priv_path = f"/var/tmp/original_key_{uid}.pem"

            logger.info(f"🔒 Locking down miner {uid} at {ip}.")

            try:
                # Establish an SSH connection using asyncssh
                async with asyncssh.connect(ip, username=ssh_user, client_keys=[ssh_priv_path], known_hosts=None) as conn:
                    # Run lockdown command
                    lockdown_cmd = get_lockdown_cmd(ssh_user, ssh_dir, validator_ip, authorized_keys_path)
                    result = await run_cmd_async(conn, lockdown_cmd)
                    if result.exit_status == 0:
                        logger.info(f"Lockdown command executed successfully on {ip}")
                    else:
                        logger.error(f"Lockdown command failed on {ip}: {result.stderr}")

                log_message("INFO", "🔒 Final lockdown step complete. Non-session processes + IPs are blocked.")
                return True

            except Exception as e:
                logger.error(f"🚨 Failed to lock down machine {machine_name} for miner: {e}")
                return False

        # Run lockdown for all machines of the miner
        tasks = [lockdown_machine(name, details) for name, details in synapse.machine_availabilities.machine_config.items() if name != "Moat"]
        results = await asyncio.gather(*tasks)
        all_success = all(results)  # Mark as success if all machines are successfully locked down

        lockdown_status[uid] = {
            "lockdown_status_code": 200 if all_success else 500,
            "lockdown_status_message": "All machines locked down successfully" if all_success else "Failure: Some machines failed to lockdown",
        }

    # Process all miners in parallel
    await asyncio.gather(*[lockdown_miner(uid, synapse) for uid, synapse in setup_complete_miners])

    return [{"uid": uid, **status} for uid, status in lockdown_status.items()]
    

async def revert_machines(ready_miners: List[Tuple[int, PingSynapse]], backup_suffix: str):
    """
    Executes the lockdown step for all given miners after setup is complete.
    """
    validator_ip = get_local_ip()
    revert_status = {}

    async def revert_miner(uid, synapse):
        """Lock down each miner's machines."""

        async def revert_machine(machine_name, machine_details):
            if machine_name == "Moat":
                return True  # Skip Moat machine setup and consider it successful

            ip = machine_details.ip
            ssh_user = machine_details.username
            ssh_dir = get_authorized_keys_dir(ssh_user)
            authorized_keys_path = f"{ssh_dir}/authorized_keys"
            session_key_path = os.path.join(SESSION_KEY_DIR, f"session_key_{uid}_{ip}")
            authorized_keys_bak = f"{ssh_dir}/authorized_keys.bak_{backup_suffix}"
            revert_script_path = f"/tmp/revert_privacy_{uid}_{backup_suffix}.sh"
            revert_log = f"/tmp/revert_log_{uid}_{backup_suffix}.log"

            logger.info(f"🔒 Reverting miner {uid} at {ip}.")

            try:
                # Establish an SSH connection using asyncssh
                async with asyncssh.connect(ip, username=ssh_user, client_keys=[session_key_path], known_hosts=None) as conn:
                    
                    #Run persist command
                    persist_revert_cmd = get_persist_revert_cmd(ssh_user, revert_script_path, backup_suffix)
                    persist_result = await run_cmd_async(conn, persist_revert_cmd)   
                    if persist_result.exit_status == 0:
                        logger.info(f"Persist revert executed successfully on {ip}")
                    else:
                        logger.error(f"Persist revert command failed on {ip}: {persist_result.stderr}")                 
                    
                    # Run revert command
                    revert_cmd = get_revert_script_cmd(ip, authorized_keys_bak, authorized_keys_path, revert_script_path, revert_log)
                    revert_result = await run_cmd_async(conn, revert_cmd) 
                    if revert_result.exit_status == 0:
                        logger.info(f"Revert command executed successfully on {ip}")
                    else:
                        logger.error(f"Revert command failed on {ip}: {revert_result.stderr}")

                return True

            except Exception as e:
                logger.error(f"🚨 Failed to revert machine {machine_name} for miner: {e}")
                return False

        # Run lockdown for all machines of the miner
        tasks = [revert_machine(name, details) for name, details in synapse.machine_availabilities.machine_config.items() if name != "Moat"]
        results = await asyncio.gather(*tasks)
        all_success = all(results)  # Mark as success if all machines are successfully locked down

        revert_status[uid] = {
            "revert_status_code": 200 if all_success else 500,
            "revert_status_message": "All machines reverted successfully" if all_success else "Failure: Some machines failed to revert",
        }

    # Process all miners in parallel
    await asyncio.gather(*[revert_miner(uid, synapse) for uid, synapse in ready_miners])

    return [{"uid": uid, **status} for uid, status in revert_status.items()]
    


async def start_challenge_phase(ready_miners: List[Tuple[int, PingSynapse]]) -> Dict[int, dict]:
    """Sends ChallengeSynapse to miners before the challenge starts and collects responses."""
    challenge_results = {}

    async def send_challenge(uid, synapse):
        try:
            moat_private_ip = synapse.machine_availabilities.machine_config["Moat"].private_ip
            king_private_ip = synapse.machine_availabilities.machine_config["King"].private_ip
            challenge_duration = 60
            challenge_synapse = ChallengeSynapse(
                king_private_ip=king_private_ip,
                moat_private_ip=moat_private_ip,
                challenge_duration=challenge_duration
            )
            uid, response = await dendrite_call(uid, challenge_synapse)

            challenge_results[uid] = response
        except Exception as e:
            logger.error(f"Error sending challenge to miner {uid}: {e}")
            challenge_results[uid] = {"error": str(e)}

    await asyncio.gather(*[send_challenge(uid, synapse) for uid, synapse in ready_miners])
    return challenge_results

# Start availability checking
miner_availabilities = MinerAvailabilities()