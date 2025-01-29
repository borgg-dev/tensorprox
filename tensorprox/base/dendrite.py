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

def generate_local_ephemeral_keypair(key_path="/tmp/session_key") -> (str, str):
    """
    Generate an ED25519 keypair. Return (private_key_str, public_key_str).
    Ensures correct file permissions for ephemeral keys.
    """
    import subprocess

    # Remove old keys if present
    if os.path.exists(key_path):
        os.remove(key_path)
    if os.path.exists(f"{key_path}.pub"):
        os.remove(f"{key_path}.pub")

    # Generate
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""], check=True)

    # Fix perms on the newly created files
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

            # Keep alive so ephemeral changes won't drop us too fast
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
# 3) SINGLE-PASS EPHEMERAL SETUP
######################################################################

def single_pass_setup(
    uid : int,
    ip: str,
    original_priv_key: str,
    ssh_user: str,
    user_commands: list[str],
    validator_ip: str,
    test_duration_minutes: int = 1
) -> bool:
    """
    Enhanced single-pass ephemeral setup with proper sudo elevation
    and ephemeral key insertion for any user.
    """
    log_message("INFO", f"--- Single-pass ephemeral setup for {ip} as {ssh_user} start ---")

    # 1) Generate ephemeral key
    ephemeral_priv, ephemeral_pub = generate_local_ephemeral_keypair("/tmp/session_key_"+str(uid))


    # 2) Connect with the "original" key
    client_orig = create_and_test_connection(ip, original_priv_key, ssh_user=ssh_user, retries=5, timeout=15)
    if not client_orig:
        log_message("ERROR", f"[Phase1] Could NOT connect to {ip} as {ssh_user} => abort ephemeral setup.")
        return False

    # 3) Ensure sudo access + needed pkgs
    run_cmd(client_orig, "echo 'SUDO_TEST'", use_sudo=True)
    needed = ["net-tools", "iptables-persistent", "psmisc"]
    install_packages_if_missing(client_orig, needed)

    # 4) Avoid requiretty for this user
    no_tty_cmd = f"echo 'Defaults:{ssh_user} !requiretty' > /etc/sudoers.d/98_{ssh_user}_no_tty"
    run_cmd(client_orig, no_tty_cmd, use_sudo=True)
    time.sleep(1)  # give sudoers a moment

    # 5) Insert ephemeral key
    ssh_dir = get_authorized_keys_dir(ssh_user)
    authorized_keys_path = f"{ssh_dir}/authorized_keys"
    authorized_keys_bak = f"{ssh_dir}/authorized_keys.bak"

    setup_cmd = f"""
export TMPDIR=$(mktemp -d /tmp/.ssh_setup_XXXXXX)
chmod 700 $TMPDIR
chown {ssh_user}:{ssh_user} $TMPDIR

# Backup existing keys with proper permissions
mkdir -p {ssh_dir}
if [ -f {authorized_keys_path} ] && [ ! -f {authorized_keys_bak} ]; then
    cp {authorized_keys_path} {authorized_keys_bak}
    chmod 600 {authorized_keys_bak}
fi

# Remove any existing ephemeral lines before re-adding
if [ -f {authorized_keys_path} ]; then
    grep -v '^# START EPHEMERAL KEY' {authorized_keys_path} | \\
    grep -v '^# END EPHEMERAL KEY' | \\
    grep -v '{ephemeral_pub}' > $TMPDIR/authorized_keys_clean || true
else
    touch $TMPDIR/authorized_keys_clean
fi

echo '# START EPHEMERAL KEY' >> $TMPDIR/authorized_keys_clean
echo '{ephemeral_pub}' >> $TMPDIR/authorized_keys_clean
echo '# END EPHEMERAL KEY' >> $TMPDIR/authorized_keys_clean

# Set correct permissions
chown {ssh_user}:{ssh_user} $TMPDIR/authorized_keys_clean
chmod 600 $TMPDIR/authorized_keys_clean

mv $TMPDIR/authorized_keys_clean {authorized_keys_path}
rm -rf $TMPDIR

chown -R {ssh_user}:{ssh_user} {ssh_dir}
chmod 700 {ssh_dir}
chmod 600 {authorized_keys_path}
"""
    run_cmd(client_orig, setup_cmd)
    client_orig.close()

    # 6) Test ephemeral connection
    ep_client = create_and_test_connection(ip, ephemeral_priv, ssh_user=ssh_user, retries=5, timeout=15)
    if not ep_client:
        log_message("ERROR", f"[Phase1.5] ephemeral test failed => skip {ip}.")
        return False
    log_message("INFO", f"[Phase1.5] ephemeral key success => lockdown + revert scheduling for {ip}.")

    # 7) Configure passwordless sudo for ephemeral session
    sudo_setup = f"""
echo '{ssh_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/99_{ssh_user}_temp
chmod 440 /etc/sudoers.d/99_{ssh_user}_temp
"""
    run_cmd(ep_client, sudo_setup)
    time.sleep(1)

    try:
        # 8) Execute user commands with ephemeral session
        for uc in user_commands:
            out, err = run_cmd(ep_client, uc, ignore_errors=True, use_sudo=True)
            if out:
                log_message("INFO", f"[{ip}] user_cmd => {out}")
            if err:
                log_message("WARNING", f"[{ip}] user_cmd error => {err}")

        # 9) Additional sudo rule for revert
        sudo_persist_cmd = f"""
echo '{ssh_user} ALL=(ALL) NOPASSWD: /tmp/revert_privacy.sh' > /etc/sudoers.d/97_{ssh_user}_revert
chmod 440 /etc/sudoers.d/97_{ssh_user}_revert
chown root:root /etc/sudoers.d
chmod 750 /etc/sudoers.d
"""
        run_cmd(ep_client, sudo_persist_cmd)

        # 10) Lockdown script
        lockdown_script = f"""
############################################################
# 0) Sudo persistence block (already handled)
############################################################

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
# 5) kill processes except ephemeral session
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
 | awk '{{print $2}}' \\
 | while read pid; do
    kill -9 "$pid" 2>/dev/null || true
done

############################################################
# 6) remove original => keep ephemeral only
############################################################
if [ -f {authorized_keys_path} ]; then
   TMPDIR=$(mktemp -d)
   chown {ssh_user}:{ssh_user} $TMPDIR

   awk '/# START EPHEMERAL KEY/,/# END EPHEMERAL KEY/' {authorized_keys_path} > $TMPDIR/ephemeral_only
   chown {ssh_user}:{ssh_user} $TMPDIR/ephemeral_only
   chmod 600 $TMPDIR/ephemeral_only

   mv $TMPDIR/ephemeral_only {authorized_keys_path}
   rm -rf $TMPDIR

   chown -R {ssh_user}:{ssh_user} {ssh_dir}
   chmod 700 {ssh_dir}
   chmod 600 {authorized_keys_path}
fi
"""
        run_cmd(ep_client, lockdown_script)

        # 11) Revert script for after test_duration
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

# 3) Restore user's authorized_keys if .bak, else remove ephemeral
if [ -f {authorized_keys_bak} ]; then
    sudo cp {authorized_keys_bak} {authorized_keys_path}
    sudo chmod 600 {authorized_keys_path}
else
    sudo sed -i '/^# START EPHEMERAL KEY/,/^# END EPHEMERAL KEY/d' {authorized_keys_path} || true
fi

# 4) If there's an /etc/ssh/sshd_config.bak, restore it, else remove appended lines
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

# 8) Revert kernel modules
echo 0 | sudo tee /proc/sys/kernel/modules_disabled >/dev/null

# 9) Re-enable networking
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

# Attempt direct sudo first
if [ -f /tmp/revert_privacy.sh ]; then
    if sudo -n true 2>/dev/null; then
        sudo /tmp/revert_privacy.sh
    else
        # fallback to the more specific sudo rule
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

chmod +x /tmp/revert_launcher.sh
nohup bash /tmp/revert_launcher.sh >/dev/null 2>&1 &
"""
        run_cmd(ep_client, revert_script)

        # Close ephemeral client
        ep_client.close()

    except Exception as e:
        log_message("ERROR", f"[Phase2] error for {ip}: {e}")
        ep_client.close()
        return False

    log_message("INFO", f"--- Done single-pass ephemeral setup for {ip} ---")
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
        For each synapse, run ephemeral setup on each machine in the machine_config,
        using optional user commands based on role, then shuffle the playlist.
        """
        # Example commands by machine name
        role_cmds = {
            "Attacker": ["sudo apt-get update -qq || true"],
            "Benign":   ["sudo apt update", "sudo apt install -y npm"],
            "King":     ["sudo apt update", "sudo apt install -y npm"],
        }

        local_ip = get_local_ip()

        for uid, synapse in zip(self.uids, self.results) :
            ssh_pub, ssh_priv = synapse.machine_availabilities.key_pair
            ssh_user = synapse.machine_availabilities.ssh_user

            if not (ssh_pub and ssh_priv):
                log_message("ERROR", "Missing SSH Key Pair => skipping synapse.")
                self.status_messages.append("Missing SSH Key Pair.")
                self.status_codes.append(400)
                continue

            # Save original key for debugging
            self.save_private_key(ssh_priv, "/tmp/original_key_"+str(uid)+".pem")

            # For each machine in the config
            for machine_name, machine_details in synapse.machine_availabilities.machine_config.items():
                ip = machine_details.ip
                if not is_valid_ip(ip):
                    log_message("ERROR", f"Invalid IP {ip} => skipping machine.")
                    self.status_messages.append("Invalid IP format.")
                    self.status_codes.append(400)
                    continue

                # Gather role-based commands
                user_cmds = role_cmds.get(machine_name, [])

                log_message("INFO", f"Starting ephemeral single-pass setup for machine '{machine_name}' at {ip}, user={ssh_user}.")

                success = single_pass_setup(
                    uid=uid,
                    ip=ip,
                    original_priv_key=ssh_priv,
                    ssh_user=ssh_user,
                    user_commands=user_cmds,
                    validator_ip=local_ip,
                    test_duration_minutes=5
                )
                if success:
                    self.status_messages.append(f"Ephemeral setup success for {machine_name} ({ip}) as {ssh_user}.")
                    self.status_codes.append(200)
                else:
                    self.status_messages.append(f"Ephemeral setup failed for {machine_name} ({ip}) as {ssh_user}.")
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
