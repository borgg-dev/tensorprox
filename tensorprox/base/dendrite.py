#!/usr/bin/env python3

import numpy as np
from tensorprox.base.protocol import PingSynapse, MachineDetails
from pydantic import BaseModel, model_validator, ConfigDict
import paramiko
from paramiko import RSAKey
from paramiko.ed25519key import Ed25519Key
import io
import re
import logging
from datetime import datetime
import time
import os
import random
import string
import dotenv

######################################################################
# 1) LOCAL FUNCTIONS / UTILITIES
######################################################################

dotenv.load_dotenv()

def _ensure_logfile_writable(log_file_path: str) -> str:
    """
    Ensure the local log file is writable; fallback to /tmp if not.
    """
    try:
        with open(log_file_path, "a"):
            pass
        return log_file_path
    except Exception:
        return "/tmp/validator_session.log"

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

# Add this near the top of dendrite.py
SESSION_KEY_DIR = "/var/tmp/session_keys"

# Add this after defining SESSION_KEY_DIR
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
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""], check=True)

    # Fix permissions on the newly created files
    os.chmod(key_path, 0o600)
    if os.path.exists(f"{key_path}.pub"):
        os.chmod(f"{key_path}.pub", 0o644)

    # Read them in
    with open(key_path, "r") as fk:
        priv = fk.read().strip()
    with open(f"{key_path}.pub", "r") as fpk:
        pub = fpk.read().strip()

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
            log_message("INFO", f"SSH connect to {ip} as {ssh_user}, attempt {attempt+1}/{retries}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Decide key type exactly once
            if "BEGIN RSA PRIVATE KEY" in private_key_str or "RSA PRIVATE KEY" in private_key_str:
                pkey = RSAKey.from_private_key(io.StringIO(private_key_str))
            else:
                # Assume Ed25519 (covers 'OPENSSH PRIVATE KEY' and typical ED25519 markers)
                pkey = Ed25519Key.from_private_key(io.StringIO(private_key_str))

            # Connect
            client.connect(ip, username=ssh_user, pkey=pkey, timeout=timeout, look_for_keys=False, allow_agent=False)

            # Keep alive so session changes won't drop us too fast
            transport = client.get_transport()
            if transport:
                transport.set_keepalive(15)

            log_message("INFO", f"SSH connection to {ip} succeeded (user={ssh_user}).")
            return client

        except paramiko.AuthenticationException:
            log_message("ERROR", f"SSH authentication failed for {ip} (user={ssh_user}).")
        except paramiko.SSHException as e:
            log_message("ERROR", f"SSH error for {ip}: {e}")
        except Exception as e:
            log_message("ERROR", f"Unexpected error for {ip}: {e}")

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
        log_message("WARNING", f"Command error '{cmd}': {err}")
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
        if code != 0:  # missing
            log_message("INFO", f"Package '{pkg}' missing => installing.")
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
    # user_commands: list[str],
    validator_ip: str,
    test_duration_minutes: int
) -> bool:
    """
    Single-pass setup with reliable process management and state transitions.
    """
    log_message("INFO", f"--- Single-pass session setup for {ip} as {ssh_user} start ---")

    # 1) Generate session key
    session_key_path = os.path.join(SESSION_KEY_DIR, f"session_key_{uid}")
    session_priv, session_pub = generate_local_session_keypair(session_key_path)

    # 2) Connect with original key
    client_orig = create_and_test_connection(ip, original_priv_key, ssh_user=ssh_user, retries=5, timeout=15)
    if not client_orig:
        log_message("ERROR", f"[Phase1] Could NOT connect to {ip} as {ssh_user} => abort session setup.")
        return False

    # 3) Prepare sudo access and session key
    ssh_dir = get_authorized_keys_dir(ssh_user)
    authorized_keys_path = f"{ssh_dir}/authorized_keys"
    authorized_keys_bak = f"{ssh_dir}/authorized_keys.bak"

    setup_cmd = f"""
        echo '{ssh_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/99_{ssh_user}_temp
        chmod 440 /etc/sudoers.d/99_{ssh_user}_temp

        mkdir -p {ssh_dir}
        if [ -f {authorized_keys_path} ]; then
            cp {authorized_keys_path} {authorized_keys_bak}
        fi

        echo '# START SESSION KEY' > {authorized_keys_path}
        echo '{session_pub}' >> {authorized_keys_path}
        echo '# END SESSION KEY' >> {authorized_keys_path}
        if [ -f {authorized_keys_bak} ]; then
            cat {authorized_keys_bak} >> {authorized_keys_path}
        fi
        chmod 600 {authorized_keys_path}
        chown {ssh_user}:{ssh_user} {authorized_keys_path}
    """
    run_cmd(client_orig, setup_cmd)
    client_orig.close()

    # 4) Test session connection
    ep_client = create_and_test_connection(ip, session_priv, ssh_user=ssh_user, retries=5, timeout=15)
    if not ep_client:
        log_message("ERROR", f"[Phase1.5] session test failed => skip {ip}.")
        return False

    # 5) Create revert script first
    revert_script = f"""#!/bin/bash
set -e

# Restore firewall
if [ -f /tmp/iptables.bak ]; then
    iptables-restore < /tmp/iptables.bak
    rm /tmp/iptables.bak
else
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
fi

# Restore SSH keys
if [ -f {authorized_keys_bak} ]; then
    mv {authorized_keys_bak} {authorized_keys_path}
    chmod 600 {authorized_keys_path}
    chown {ssh_user}:{ssh_user} {authorized_keys_path}
fi

# Restore sshd config
if [ -f /etc/ssh/sshd_config.bak ]; then
    mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    systemctl restart sshd
fi

# Unlock users
for user in $(cut -f1 -d: /etc/passwd); do
    passwd -u "$user" 2>/dev/null || true
done

# Unmask and start services
systemctl daemon-reload
systemctl list-unit-files --state=masked --type=service | 
awk '{{print $1}}' | while read service; do
    systemctl unmask "$service"
    systemctl start "$service" 2>/dev/null || true
done

# Clean up
rm -f /etc/sudoers.d/99_{ssh_user}_temp
rm -f /tmp/revert_privacy.sh
rm -f /etc/systemd/system/revert-privacy.timer
rm -f /etc/systemd/system/revert-privacy.service

echo "Revert completed on $(date)"
"""

    # 6) Deploy revert mechanism
    run_cmd(ep_client, f"""
cat > /tmp/revert_privacy.sh << 'EOFMARKER'
{revert_script}
EOFMARKER

chmod 700 /tmp/revert_privacy.sh

cat > /etc/systemd/system/revert-privacy.service << 'EOFMARKER'
[Unit]
Description=Privacy revert service
After=network.target

[Service]
Type=oneshot
ExecStart=/tmp/revert_privacy.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOFMARKER

cat > /etc/systemd/system/revert-privacy.timer << 'EOFMARKER'
[Unit]
Description=Schedule privacy revert

[Timer]
OnBootSec=1min
OnUnitActiveSec={test_duration_minutes}m
AccuracySec=1s

[Install]
WantedBy=timers.target
EOFMARKER

systemctl daemon-reload
systemctl enable revert-privacy.service
systemctl start revert-privacy.timer
""")

    # 7) Execute lockdown
    lockdown_script = f"""#!/bin/bash
set -e

# Backup sshd config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Configure firewall
NIC=$(ip route | grep default | awk '{{print $5}}' | head -1)
iptables-save > /tmp/iptables.bak
iptables -F
iptables -X
iptables -A INPUT -i $NIC -p tcp -s {validator_ip} -j ACCEPT
iptables -A OUTPUT -o $NIC -p tcp -d {validator_ip} -j ACCEPT
iptables -A INPUT -i $NIC -j DROP
iptables -A OUTPUT -o $NIC -j DROP

# Lock users except current
for user in $(cut -f1 -d: /etc/passwd); do
    if [ "$user" != "{ssh_user}" ]; then
        passwd -l "$user" 2>/dev/null || true
    fi
done

# Stop and mask non-essential services
essential="ssh.service systemd-journald.service systemd-networkd.service systemd-resolved.service revert-privacy.service"
systemctl list-units --type=service --state=running --no-pager --no-legend | 
awk '{{print $1}}' | while read service; do
    if ! echo "$essential" | grep -q "$service"; then
        systemctl stop "$service" 2>/dev/null || true
        systemctl mask "$service" 2>/dev/null || true
    fi
done

# Kill non-essential processes
ps -ef | grep -v "sshd\|systemd\|bash\|sudo\|revert-privacy" | 
awk '{{if ($1 != "root" && $1 != "{ssh_user}") print $2}}' |
while read pid; do
    kill -9 "$pid" 2>/dev/null || true
done
"""
    run_cmd(ep_client, lockdown_script)
    ep_client.close()

    log_message("INFO", f"--- Done single-pass session setup for {ip} ---")
    return True

    

######################################################################
# 5) MODEL CLASS
######################################################################

class DendriteResponseEvent(BaseModel):
    uids: np.ndarray | list[int]
    results: list[PingSynapse]
    playlist: list[dict]
    status_messages: list[str] = []
    status_codes: list[int] = []
    test_list: list[dict] = []
    benign_list: list[dict] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @staticmethod
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

    @model_validator(mode="after")
    def process_results(self) -> "DendriteResponseEvent":
        """
        For each synapse, run session setup on each machine in the machine_config,
        using optional user commands based on role, then shuffle the playlist.
        """
        # # Example commands by machine name
        # role_cmds = {
        #     "Attacker": ["sudo apt-get update -qq || true"],
        #     "Benign":   ["sudo apt update", "sudo apt install -y npm"],
        #     "King":     ["sudo apt update", "sudo apt install -y npm"],
        # }

        local_ip = get_local_ip()

        for uid, synapse in zip(self.uids, self.results) :
            ssh_pub, ssh_priv = synapse.machine_availabilities.key_pair

            if not (ssh_pub and ssh_priv):
                log_message("ERROR", "Missing SSH Key Pair => skipping synapse.")
                self.status_messages.append("Missing SSH Key Pair.")
                self.status_codes.append(400)
                continue

            # Save original key for debugging
            self.save_private_key(ssh_priv, "/var/tmp/original_key_"+str(uid)+".pem")

            # For each machine in the config
            for machine_name, machine_details in synapse.machine_availabilities.machine_config.items():
                ip = machine_details.ip
                ssh_user = machine_details.username
                if not is_valid_ip(ip):
                    log_message("ERROR", f"Invalid IP {ip} => skipping machine.")
                    self.status_messages.append("Invalid IP format.")
                    self.status_codes.append(400)
                    continue

                # # Gather role-based commands
                # user_cmds = role_cmds.get(machine_name, [])

                log_message("INFO", f"Starting session single-pass setup for machine '{machine_name}' at {ip}, user={ssh_user}.")

                success = single_pass_setup(
                    uid=uid,
                    ip=ip,
                    original_priv_key=ssh_priv,
                    ssh_user=ssh_user,
                    # user_commands=user_cmds,
                    validator_ip=local_ip,
                    test_duration_minutes=1
                )
                if success:
                    self.status_messages.append(f"Session setup success for {machine_name} ({ip}) as {ssh_user}.")
                    self.status_codes.append(200)
                else:
                    self.status_messages.append(f"Session setup failed for {machine_name} ({ip}) as {ssh_user}.")
                    self.status_codes.append(500)

        # Shuffle / transform playlist
        if self.playlist:
            class_names = [p["name"] for p in self.playlist if p["name"] != "pause"]

            def random_str(min_len=10, max_len=13):
                length = random.randint(min_len, max_len)
                return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

            mapping = {}
            for cn in class_names:
                mapping[cn] = random_str()

            # Also for tcp/udp
            mapping["tcp_traffic"] = random_str()
            mapping["udp_traffic"] = random_str()

            # For example usage
            self.benign_list = [
                {"name": "tcp_traffic", "identifier": mapping["tcp_traffic"]},
                {"name": "udp_traffic", "identifier": mapping["udp_traffic"]}
            ]

            shuffled = self.playlist.copy()
            random.shuffle(shuffled)
            for item in shuffled:
                if item["name"] != "pause":
                    item["identifier"] = mapping.get(item["name"], random_str())

            self.test_list = shuffled

        return self
