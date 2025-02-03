#!/usr/bin/env python3

import asyncio
import os
import random
from typing import List, Dict, Tuple, Union
from loguru import logger
from pydantic import BaseModel
from datetime import datetime
import time
from tensorprox.base.protocol import PingSynapse, MachineDetails
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

    # Remove old keys if present
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

    # Generate
    log_message("INFO", "🚀 Generating session ED25519 keypair...")
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""], check=True)

    # Fix permissions
    os.chmod(key_path, 0o600)
    if os.path.exists(f"{key_path}.pub"):
        os.chmod(f"{key_path}.pub", 0o644)

    # Read them in
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
    Attempt SSH connection using exactly the correct key type:
      - if the string says 'BEGIN RSA', parse as RSA
      - otherwise parse as Ed25519
    Retries with a short delay, sets keepalive to avoid abrupt closures.
    """

    attempt = 0
    while attempt < retries:
        try:
            log_message("INFO", f"🔗 Attempting SSH connect to {ip} as '{ssh_user}', attempt {attempt+1}/{retries}...")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Decide key type exactly once
            if "BEGIN RSA PRIVATE KEY" in private_key_str or "RSA PRIVATE KEY" in private_key_str:
                pkey = RSAKey.from_private_key(io.StringIO(private_key_str))
                log_message("INFO", "🔑 Detected RSA private key format.")
            else:
                pkey = Ed25519Key.from_private_key(io.StringIO(private_key_str))
                log_message("INFO", "🔑 Detected ED25519 private key format.")

            # Connect
            client.connect(ip, username=ssh_user, pkey=pkey, timeout=timeout, look_for_keys=False, allow_agent=False)

            # Keep alive
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
    else:
        if out:
            log_message("INFO", f"🔎 Command '{cmd}' output: {out}")
    return out, err

def get_authorized_keys_dir(ssh_user: str) -> str:
    """
    Return the path to .ssh for the given user.
    """
    if ssh_user == "root":
        return "/root/.ssh"
    else:
        return f"/home/{ssh_user}/.ssh"

def install_packages_if_missing(client: paramiko.SSHClient, packages: list[str]):
    """
    If any package is missing, do apt-get update + apt-get install. Non-blocking.
    """
    for pkg in packages:
        check_cmd = f"dpkg -s {pkg} >/dev/null 2>&1"
        stdin, stdout, stderr = client.exec_command(check_cmd)
        code = stdout.channel.recv_exit_status()
        if code != 0:  
            log_message("INFO", f"📦 Package '{pkg}' missing => installing now...")
            run_cmd(client, "DEBIAN_FRONTEND=noninteractive apt-get update -qq || true", ignore_errors=True)
            run_cmd(client, f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg}", ignore_errors=True)
            time.sleep(1)  # small wait after install


######################################################################
# 3) SINGLE-PASS SESSION SETUP
######################################################################

def single_pass_setup(
    uid: int,
    ip: str,
    original_priv_key: str,
    ssh_user: str,
    user_commands: list[str],
    validator_ip: str,
    test_duration_minutes: int
) -> bool:
    """
    Enhanced single-pass session setup with proper sudo elevation,
    session (session) key insertion for any user, plus a guaranteed
    revert after test_duration_minutes on Ubuntu 22.04 LTS.

    Logical Flow:
      1) Connect via ORIGINAL SSH key
      2) Generate session key & add to authorized_keys
      3) Close original connection, test session key
      4) With session session:
         - Give session user full NOPASSWD
         - Run user_commands
         - Create BOTH revert_privacy.sh + revert_launcher.sh
         - **Immediately** launch the revert launcher via nohup (detached)
      5) Now do the "lockdown" (remove original key lines, kill all extraneous processes,
         block all IP except validator_ip, etc.)
      6) Close session session.
      => The revert_launcher continues sleeping in the background, unaffected by the kill loop,
         and fires revert_privacy.sh exactly after `test_duration_minutes`.

    """

    log_message("INFO", f"🔒 Single-pass session setup for {ip} as '{ssh_user}' start...")

    ########################################################################
    # A) CONNECT WITH ORIGINAL KEY + PREPARE
    ########################################################################

    log_message("INFO", f"🌐 Step A: Generating session key + connecting with original SSH key on {ip}...")

    # 1) Generate session key
    session_key_path = os.path.join(SESSION_KEY_DIR, f"session_key_{uid}_{ip}")
    session_priv, session_pub = generate_local_session_keypair(session_key_path)

    # 2) Connect with original key
    client_orig = create_and_test_connection(ip, original_priv_key, ssh_user=ssh_user, retries=5, timeout=15)
    if not client_orig:
        log_message("ERROR", f"❌ Could NOT connect to {ip} as {ssh_user}. Aborting session setup.")
        return False

    # Ensure minimal packages
    run_cmd(client_orig, "echo 'SUDO_TEST'", use_sudo=True)
    needed = ["net-tools", "iptables-persistent", "psmisc"]
    install_packages_if_missing(client_orig, needed)

    # Avoid 'requiretty'
    no_tty_cmd = f"echo 'Defaults:{ssh_user} !requiretty' > /etc/sudoers.d/98_{ssh_user}_no_tty"
    run_cmd(client_orig, no_tty_cmd, use_sudo=True)
    time.sleep(1)

    ########################################################################
    # B) INSERT SESSION KEY + CLOSE ORIGINAL
    ########################################################################

    log_message("INFO", "🔐 Step B: Inserting session key into authorized_keys and closing original SSH.")
    ssh_dir = get_authorized_keys_dir(ssh_user)
    authorized_keys_path = f"{ssh_dir}/authorized_keys"
    authorized_keys_bak = f"{ssh_dir}/authorized_keys.bak"

    insert_key_cmd = f"""
        export TMPDIR=$(mktemp -d /tmp/.ssh_setup_XXXXXX)
        chmod 700 $TMPDIR
        chown {ssh_user}:{ssh_user} $TMPDIR

        # Backup existing keys if not already backed up
        mkdir -p {ssh_dir}
        if [ -f {authorized_keys_path} ] && [ ! -f {authorized_keys_bak} ]; then
            cp {authorized_keys_path} {authorized_keys_bak}
            chmod 600 {authorized_keys_bak}
        fi

        # Remove any existing session lines
        if [ -f {authorized_keys_path} ]; then
            grep -v '^# START SESSION KEY' {authorized_keys_path} | \\
            grep -v '^# END SESSION KEY' | \\
            grep -v '{session_pub}' > $TMPDIR/authorized_keys_clean || true
        else
            touch $TMPDIR/authorized_keys_clean
        fi

        echo '# START SESSION KEY' >> $TMPDIR/authorized_keys_clean
        echo '{session_pub}' >> $TMPDIR/authorized_keys_clean
        echo '# END SESSION KEY' >> $TMPDIR/authorized_keys_clean

        chown {ssh_user}:{ssh_user} $TMPDIR/authorized_keys_clean
        chmod 600 $TMPDIR/authorized_keys_clean
        mv $TMPDIR/authorized_keys_clean {authorized_keys_path}
        rm -rf $TMPDIR
        chown -R {ssh_user}:{ssh_user} {ssh_dir}
        chmod 700 {ssh_dir}
        chmod 600 {authorized_keys_path}
    """

    run_cmd(client_orig, insert_key_cmd)
    client_orig.close()
    log_message("INFO", f"🔒 Original SSH connection closed for {ip} (user={ssh_user}).")

    ########################################################################
    # C) TEST SESSION KEY
    ########################################################################

    log_message("INFO", f"🔑 Step C: Testing session SSH key on {ip} to confirm new session.")
    ep_client = create_and_test_connection(ip, session_priv, ssh_user=ssh_user, retries=5, timeout=15)
    if not ep_client:
        log_message("ERROR", f"❌ Session SSH test failed => skipping {ip}.")
        return False

    log_message("INFO", f"✨ Session session key success => proceeding to revert scheduling + lockdown for {ip}.")

    ########################################################################
    # D) PREPARE REVERT SCRIPTS, LAUNCH NOHUP, THEN LOCKDOWN
    ########################################################################

    log_message("INFO", "🧩 Step D: Setting up passwordless sudo, user commands, revert scripts, and nohup revert launcher...")

    # 1) Full NOPASSWD

    sudo_setup_cmd = f"""
        echo '{ssh_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/99_{ssh_user}_temp
        chmod 440 /etc/sudoers.d/99_{ssh_user}_temp
    """

    run_cmd(ep_client, sudo_setup_cmd)
    time.sleep(1)

    # 2) Execute user commands
    if user_commands:
        log_message("INFO", f"🛠 Running custom user commands for role on {ip}.")
    for uc in user_commands:
        out, err = run_cmd(ep_client, uc, ignore_errors=True, use_sudo=True)

    # 3) Additional rule for revert script
    persist_revert_cmd = f"""
        echo '{ssh_user} ALL=(ALL) NOPASSWD: /tmp/revert_privacy.sh' > /etc/sudoers.d/97_{ssh_user}_revert
        chmod 440 /etc/sudoers.d/97_{ssh_user}_revert
        chown root:root /etc/sudoers.d
        chmod 750 /etc/sudoers.d
    """
    run_cmd(ep_client, persist_revert_cmd)

    # 4) Create revert + launcher
    log_message("INFO", "📝 Creating revert_privacy.sh and revert_launcher.sh on the remote host...")
    revert_script = f"""
        cat <<'REVERT' > /tmp/revert_privacy.sh
        #!/bin/bash
        set -e
        echo "Reverting {ip} to normal..."

        # 1) Re-add TTY lines
        if [ -f /etc/securetty ]; then
        cat <<TTYS >> /etc/securetty
        tty1
        tty2
        tty3
        tty4
        tty5
        tty6
        ttyS0
        TTYS
        fi
        sudo systemctl unmask console-getty.service || true
        sudo systemctl enable console-getty.service || true
        sudo systemctl start console-getty.service || true
        sudo systemctl unmask serial-getty@ttyS0.service || true
        sudo systemctl enable serial-getty@ttyS0.service || true
        sudo systemctl start serial-getty@ttyS0.service || true

        # 2) Flush iptables
        sudo iptables -F
        sudo iptables -X
        sudo iptables -t nat -F
        sudo iptables -t nat -X
        sudo iptables -t mangle -F
        sudo iptables -t mangle -X
        sudo iptables -P INPUT ACCEPT
        sudo iptables -P FORWARD ACCEPT
        sudo iptables -P OUTPUT ACCEPT

        # 3) Restore user's authorized_keys
        if [ -f {authorized_keys_bak} ]; then
            sudo cp {authorized_keys_bak} {authorized_keys_path}
            sudo chmod 600 {authorized_keys_path}
        else
            sudo sed -i '/^# START SESSION KEY/,/^# END SESSION KEY/d' {authorized_keys_path} || true
        fi

        # 4) If there's /etc/ssh/sshd_config.bak, restore it, else remove appended lines
        if [ -f /etc/ssh/sshd_config.bak ]; then
            sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
            sudo chmod 644 /etc/ssh/sshd_config
        else
            sudo sed -i '/^Protocol 2$/d' /etc/ssh/sshd_config
            sudo sed -i '/^PubkeyAuthentication yes$/d' /etc/ssh/sshd_config
            sudo sed -i '/^PasswordAuthentication no$/d' /etc/ssh/sshd_config
            sudo sed -i '/^ChallengeResponseAuthentication no$/d' /etc/ssh/sshd_config
            sudo sed -i '/^UsePAM no$/d' /etc/ssh/sshd_config
            sudo sed -i '/^X11Forwarding no$/d' /etc/ssh/sshd_config
            sudo sed -i '/^AllowTcpForwarding no$/d' /etc/ssh/sshd_config
            sudo sed -i '/^PermitTunnel no$/d' /etc/ssh/sshd_config
            sudo sed -i '/^AllowUsers root$/d' /etc/ssh/sshd_config
            sudo sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config || true
            echo 'PermitRootLogin yes' | sudo tee -a /etc/ssh/sshd_config >/dev/null
        fi
        sudo passwd -u root 2>/dev/null || true
        sudo systemctl restart sshd

        # 5) Unlock all users
        for u in $(cut -f1 -d: /etc/passwd); do
            sudo usermod -U "$u" 2>/dev/null || true
        done
        sudo passwd -u root 2>/dev/null || true

        # 6) Restore kernel params
        sudo sysctl -w kernel.kptr_restrict=0
        sudo sysctl -w kernel.dmesg_restrict=0
        sudo sysctl -w kernel.perf_event_paranoid=2
        sudo sysctl -w net.ipv4.tcp_syncookies=1
        sudo sysctl -w net.ipv4.ip_forward=1
        sudo sysctl -w net.ipv4.conf.all.accept_redirects=1
        sudo sysctl -w net.ipv4.conf.all.send_redirects=1
        sudo sysctl -w net.ipv4.conf.all.accept_source_route=1
        sudo sysctl -w net.ipv4.conf.all.rp_filter=1
        sudo sysctl -p

        # 7) Re-enable masked or disabled services
        sudo systemctl daemon-reload
        for s in $(systemctl list-unit-files --type=service --state=masked | cut -d' ' -f1); do
            sudo systemctl unmask $s || true
        done
        for s in $(systemctl list-unit-files --type=service --state=disabled | cut -d' ' -f1); do
            sudo systemctl enable $s || true
            sudo systemctl start $s 2>/dev/null || true
        done

        # 8) Revert modules + networking
        echo 0 | sudo tee /proc/sys/kernel/modules_disabled >/dev/null
        sudo systemctl unmask systemd-networkd.service || true
        sudo systemctl enable systemd-networkd.service || true
        sudo systemctl start systemd-networkd.service || true
        sudo systemctl unmask systemd-resolved.service || true
        sudo systemctl enable systemd-resolved.service || true
        sudo systemctl start systemd-resolved.service || true

        echo "Done revert on {ip}"
        REVERT

        chmod +x /tmp/revert_privacy.sh

        cat <<'LAUNCH' > /tmp/revert_launcher.sh
        #!/bin/bash
        sleep {test_duration_minutes}m

        if [ -f /tmp/revert_privacy.sh ]; then
            if sudo -n true 2>/dev/null; then
                sudo /tmp/revert_privacy.sh
            else
                sudo -n /tmp/revert_privacy.sh
            fi
        else
            echo "Revert script missing - emergency fallback"
            sudo -n iptables -F
            sudo -n iptables -P INPUT ACCEPT
            sudo -n iptables -P OUTPUT ACCEPT
            sudo -n iptables -P FORWARD ACCEPT
        fi
        LAUNCH

        chmod +x /tmp/revert_privacy.sh
        chmod +x /tmp/revert_launcher.sh
    """

    run_cmd(ep_client, revert_script, ignore_errors=True)

    log_message("INFO", f"📝 Revert scripts created. test_duration_minutes={test_duration_minutes} => scheduling now...")

    # Launch revert_launcher via nohup BEFORE lockdown
    nohup_cmd = "nohup bash /tmp/revert_launcher.sh >/dev/null 2>&1 &"
    run_cmd(ep_client, nohup_cmd, ignore_errors=True)
    log_message("INFO", "⏰ Revert launcher started in background. We'll now do final lockdown...")

    ########################################################################
    # E) LOCKDOWN (FINAL)
    ########################################################################

    lockdown_cmd = f"""
        ############################################################
        # 1) Minimal services
        ############################################################
        allowed="apparmor.service
        dbus.service
        networkd-dispatcher.service
        polkit.service
        rsyslog.service
        snapd.service
        ssh.service
        systemd-journald.service
        systemd-logind.service
        systemd-networkd.service
        systemd-resolved.service
        systemd-timesyncd.service
        systemd-udevd.service"

        systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{{print $1}}' | while read s; do
            if echo "$allowed" | grep -qx "$s"; then
                :
            else
                echo "Stopping+masking $s"
                systemctl stop "$s" || true
                systemctl disable "$s" || true
                systemctl mask "$s" || true
            fi
        done

        ############################################################
        # 2) disable console TTY if /etc/securetty
        ############################################################
        if [ -f /etc/securetty ]; then
            sed -i '/^tty[0-9]/d' /etc/securetty || true
            sed -i '/^ttyS/d' /etc/securetty || true
        fi
        systemctl stop console-getty.service || true
        systemctl disable console-getty.service || true
        systemctl mask console-getty.service || true
        systemctl stop serial-getty@ttyS0.service || true
        systemctl disable serial-getty@ttyS0.service || true
        systemctl mask serial-getty@ttyS0.service || true

        ############################################################
        # 3) lock root
        ############################################################
        passwd -l root || true

        ############################################################
        # 4) firewall => only {validator_ip}
        ############################################################
        NIC=$(ip route | grep default | awk '{{print $5}}' | head -1)
        iptables -F
        iptables -X
        iptables -A INPUT -i $NIC -p tcp -s {validator_ip} -j ACCEPT
        iptables -A OUTPUT -o $NIC -p tcp -d {validator_ip} -j ACCEPT
        iptables -A INPUT -i $NIC -j DROP
        iptables -A OUTPUT -o $NIC -j DROP

        ############################################################
        # 5) kill processes except session session
        ############################################################
        ps -ef \\
        | grep -v systemd \\
        | grep -v '\\[.*\\]' \\
        | grep -v sshd \\
        | grep -v bash \\
        | grep -v ps \\
        | grep -v grep \\
        | grep -v awk \\
        | grep -v nohup \\
        | grep -v sleep \\
        | grep -v revert_launcher \\
        | grep -v revert_privacy \\
        | grep -v python \\
        | grep -v python3 \\
        | grep -v paramiko \\
        | awk '{{print $2}}' \\
        | while read pid; do
            kill -9 "$pid" 2>/dev/null || true
        done

        ############################################################
        # 6) remove original => keep session only
        ############################################################
        if [ -f {authorized_keys_path} ]; then
            TMPDIR=$(mktemp -d)
            chown {ssh_user}:{ssh_user} $TMPDIR
            awk '/# START SESSION KEY/,/# END SESSION KEY/' {authorized_keys_path} > $TMPDIR/session_only
            chown {ssh_user}:{ssh_user} $TMPDIR/session_only
            chmod 600 $TMPDIR/session_only
            mv $TMPDIR/session_only {authorized_keys_path}
            rm -rf $TMPDIR

            chown -R {ssh_user}:{ssh_user} {ssh_dir}
            chmod 700 {ssh_dir}
            chmod 600 {authorized_keys_path}
        fi
    """

    run_cmd(ep_client, lockdown_cmd, ignore_errors=True)
    log_message("INFO", "🔒 Final lockdown step complete. Non-session processes + IPs are blocked.")

    # Close session SSH
    ep_client.close()
    log_message("INFO", f"✅ Done single-pass session setup for {ip}. Revert scheduled in ~{test_duration_minutes}m!")
    return True

async def async_single_pass_setup(uid, ip, original_priv_key, ssh_user, user_commands, validator_ip, test_duration_minutes):
    """
    A wrapper to execute single_pass_setup asynchronously.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,  # Uses default executor (can be changed to a custom ThreadPoolExecutor)
        single_pass_setup, uid, ip, original_priv_key, ssh_user, user_commands, validator_ip, test_duration_minutes
    )
    
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
    
    miners: Dict[int, PingSynapse] = {}


    def check_machine_availability(self, machine_name: str = None, uid: int = None) -> bool:
        ip_machine = self.miners[uid].machine_availabilities[machine_name]
        if ip_machine :
            return True
        return False
    
    def is_miner_ready(self, uid: int = None) -> bool:
        """
        Check if a miner is ready by verifying all machines are available.

        Args:
            uid (int): The UID of the miner to check.

        Returns:
            bool: True if all machines are available for the miner, False otherwise.
        """
        for machine_name in self.miners[uid].machine_availabilities.keys():
            if not self.check_machine_availability(machine_name=machine_name, uid=uid):
                return False
        return True

    
def get_uid_status_availability(self, k: int = None) -> List[int]:
    """
    Get a list of miners where all machines are available.

    Args:
        k (int, optional): The number of miners to return. Defaults to None.

    Returns:
        List[int]: A list of miner UIDs with all machines marked as available (True).
    """
    available = [uid for uid in self.miners.keys() if self.is_miner_ready(uid)]

    if k:
        available = random.sample(available, min(len(available), k))

    return available

async def query_availabilities(uids: List[int]) -> Tuple[List[PingSynapse], List[Dict[str, Union[int, str]]]]:
    """
    Simulates querying miners for their availability.

    Args:
        uids (List[int]): A list of miner UIDs to query.

    Returns:
        List[PingSynapse]: Ping responses for each queried UID.
    """
    
    logger.debug(f"🔍 Querying uids machine's availabilities: {uids}")
    if len(uids) == 0:
        logger.debug("No available miners. Skipping step.")
        return [], []

    axons = [settings.METAGRAPH.axons[uid] for uid in uids]
    responses = []

    # Querying miners to see if they are ready
    try:
        responses = await settings.DENDRITE(
            axons=axons,
            synapse=PingSynapse(machine_availabilities=MachineConfig()),
            timeout=settings.NEURON_TIMEOUT,
            deserialize=False,
        )   
    except Exception as e:
        logger.error(f"Failed to query miners: {e}")
        return [], []

    all_miners_availability = []

    for uid, synapse in zip(uids, responses):
        uid_status_availability = {}
        ssh_pub, ssh_priv = synapse.machine_availabilities.key_pair

        # Save original key for debugging
        save_private_key(ssh_priv, f"/var/tmp/original_key_{uid}.pem")

        if not (ssh_pub and ssh_priv):
            logger.error(f"Missing SSH Key Pair for UID {uid}, marking as unavailable.")
            uid_status_availability["ping_status_message"] = "Missing SSH Key Pair."
            uid_status_availability["ping_status_code"] = 400
            all_miners_availability.append(uid_status_availability)  # ✅ Append before continuing
            continue

        all_machines_available = True

        # For each machine in the config
        for machine_name, machine_details in synapse.machine_availabilities.machine_config.items():
            ip = machine_details.ip
            ssh_user = machine_details.username

            if not is_valid_ip(ip):
                logger.error(f"Invalid IP {ip} for {machine_name}, marking UID {uid} as unavailable.")
                all_machines_available = False
                uid_status_availability["ping_status_message"] = "Invalid IP format."
                uid_status_availability["ping_status_code"] = 400
                break  # ✅ Don't skip adding status

            client = create_and_test_connection(ip, ssh_priv, ssh_user)
            if not client:
                logger.error(f"SSH connection failed for {machine_name} ({ip}) UID {uid}, marking as unavailable.")
                all_machines_available = False
                uid_status_availability["ping_status_message"] = f"One or more machine(s) are not accessible. Skipping UID {uid}."
                uid_status_availability["ping_status_code"] = 500
                break  # ✅ Don't skip adding status

        if all_machines_available:
            uid_status_availability["ping_status_message"] = f"All machines are accessible for UID {uid}."
            uid_status_availability["ping_status_code"] = 200

        all_miners_availability.append(uid_status_availability)  # ✅ Always append

    return responses, all_miners_availability
      

async def setup_available_machines(available_miners: List[Tuple[int, PingSynapse]], playlist: List[dict]) -> List[Dict[str, Union[int, str]]]:
    """
    Runs setup on miners that have all required machines available concurrently.
    """
    role_cmds = {
        "Attacker": ["sudo apt-get update -qq || true"],
        "Benign": ["sudo apt update", "sudo apt install -y npm"],
        "King": ["sudo apt update", "sudo apt install -y npm"],
    }
    
    local_ip = get_local_ip()  # Ensure this function is defined
    setup_status = []

    async def setup_miner(uid, synapse):
        """
        Asynchronous setup for a single miner.
        """
        uid_status_setup = {}
        ssh_pub, ssh_priv = synapse.machine_availabilities.key_pair

        async def setup_machine(machine_name, machine_details):
            """
            Asynchronously setup a single machine within a miner.
            """
            ip = machine_details.ip
            ssh_user = machine_details.username
            user_cmds = role_cmds.get(machine_name, [])
            logger.info(f"\U0001F3AF Setting up '{machine_name}' at {ip}, user={ssh_user}.")

            success = await async_single_pass_setup(
                uid=uid,
                ip=ip,
                original_priv_key=ssh_priv,
                ssh_user=ssh_user,
                user_commands=user_cmds,
                validator_ip=local_ip,
                test_duration_minutes=1
            )

            uid_status_setup[machine_name] = {
                "setup_status_message": f"Setup {'success' if success else 'failed'} for {machine_name} ({ip}).",
                "setup_status_code": 200 if success else 500,
            }

        # Run all machine setups concurrently
        await asyncio.gather(*(setup_machine(name, details) for name, details in synapse.machine_availabilities.machine_config.items()))
        return uid_status_setup

    # Run setup for all miners concurrently
    setup_status = await asyncio.gather(*(setup_miner(uid, synapse) for uid, synapse in available_miners))

    # **Process Playlist**
    if playlist:
        class_names = [p["name"] for p in playlist if p["name"] != "pause"]

        def generate_random_string(min_len=10, max_len=13):
            length = random.randint(min_len, max_len)
            return "".join(random.choices(string.ascii_letters + string.digits, k=length))

        mapping = {cn: generate_random_string() for cn in class_names}
        mapping["tcp_traffic"] = generate_random_string()
        mapping["udp_traffic"] = generate_random_string()

        shuffled_playlist = random.sample(playlist, len(playlist))
        for item in shuffled_playlist:
            if item["name"] != "pause":
                item["identifier"] = mapping.get(item["name"], generate_random_string())

    return setup_status



# Start availability checking
miner_availabilities = MinerAvailabilities()