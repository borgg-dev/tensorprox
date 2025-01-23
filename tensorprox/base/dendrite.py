import numpy as np
from tensorprox.base.protocol import PingSynapse, MachineDetails
from pydantic import BaseModel, model_validator, ConfigDict
import paramiko
import io
import re
import logging
from datetime import datetime
import time
import os

# NEW: Additional imports for random string generation
import random
import string

######################################################################
# 1) LOCAL FUNCTIONS/ACTIONS (not integrated but listed in full)
######################################################################

def _ensure_logfile_writable(log_file_path: str) -> str:
    """
    Ensure the local log file is writable; fallback to /tmp if not.
    Returns the final, possibly updated log file path.
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


def get_local_ip() -> str:
    """
    Attempt to get the local machine's IP (for firewall rules on remote).
    """
    try:
        import subprocess
        return subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
    except subprocess.CalledProcessError:
        return "127.0.0.1"


def setup_dynamic_ssh_key_locally(temp_ssh_key_path: str = "/tmp/session_key") -> (str, str):
    """
    Generate a new dynamic SSH keypair *LOCALLY* for remote access.
    Return (temp_private_key_path, public_key_str).
    This function:
       1) Removes any existing key with the same name.
       2) Calls ssh-keygen to create a new ED25519 key.
       3) Reads and returns the public key content.
    """
    if os.path.exists(temp_ssh_key_path):
        os.remove(temp_ssh_key_path)
    if os.path.exists(f"{temp_ssh_key_path}.pub"):
        os.remove(f"{temp_ssh_key_path}.pub")

    import subprocess
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", temp_ssh_key_path, "-N", ""], check=True)

    with open(f"{temp_ssh_key_path}.pub", "r") as f_pub:
        public_key_str = f_pub.read().strip()

    return temp_ssh_key_path, public_key_str


######################################################################
# 2) SUPPORTING UTILS (log_message, create_and_test_connection, etc.)
######################################################################

# Validate IPv4 format
def is_valid_ip(ip: str) -> bool:
    ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(ip_pattern, ip) is not None

# Configure logging for this local environment
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

def create_and_test_connection(
    machine_name: str,
    machine_details: MachineDetails,
    private_key_str: str,
    retries: int = 3,
    timeout: int = 5
) -> paramiko.SSHClient:
    """
    Test SSH connectivity to the remote machine, returning the established SSHClient
    if successful, or None if connection fails after all retries.
    """
    ip = machine_details.ip
    attempt = 0

    while attempt < retries:
        try:
            log_message("INFO", f"Testing SSH connection for {machine_name} at {ip}, attempt {attempt + 1}/{retries}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Here we assume RSAKey - adapt if your keys differ
            private_key = paramiko.RSAKey.from_private_key(io.StringIO(private_key_str))
            client.connect(ip, username="azureuser", pkey=private_key, timeout=timeout)

            log_message("INFO", f"SSH connection to {machine_name} ({ip}) succeeded.")
            return client
        except paramiko.AuthenticationException:
            log_message("ERROR", f"SSH authentication failed for {machine_name} ({ip}).")
        except paramiko.SSHException as e:
            log_message("ERROR", f"SSH error for {machine_name} ({ip}): {e}")
        except Exception as e:
            log_message("ERROR", f"Unexpected error for {machine_name} ({ip}): {e}")
        
        attempt += 1
        if attempt < retries:
            log_message("WARNING", f"Retrying SSH connection for {machine_name} ({ip})...")
            time.sleep(2)

    return None


######################################################################
# 3) NEW/UPDATED "initiate_machine_setup" WITH ALL REMOTE ACTIONS
######################################################################
def initiate_machine_setup(
    machine_name: str,
    machine_details: MachineDetails,
    private_key_str: str,
    setup_commands: list,
    validator_ip: str,
    temp_ssh_pub_key: str,
    test_duration_minutes: int = 5
):
    """
    Updated version that integrates all remote actions from <privacy_setup.py> in the
    original sequence, preserving param chaining and commands.
    All commands are executed with root privileges.
    """
    ip = machine_details.ip
    client = create_and_test_connection(machine_name, machine_details, private_key_str, timeout=5)
    if not client:
        log_message("ERROR", f"Setup aborted for {machine_name} due to failed SSH connection.")
        return False

    # EXACT remote commands from <privacy_setup.py>, in the same run() order.
    remote_commands = []

    # (1) validate_remote_environment
    remote_commands.append("id -u")
    remote_commands.append("apt-get update -qq || true")
    remote_commands.append(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y "
        "-o Dpkg::Options::=--force-confdef "
        "-o Dpkg::Options::=--force-confold "
        "iptables-persistent net-tools psmisc"
    )
    remote_commands.append("which ssh-keygen")
    remote_commands.append("which iptables")
    remote_commands.append("which netstat")
    remote_commands.append("which kill")

    # (2) kill_all_other_sessions
    kill_sessions_cmd = """
        for line in $(who | "awk '{print \$1}'"); do \
            if [ "$line" != "azureuser" ]; then \
                pkill -KILL -u "$line" 2>/dev/null || true; \
            fi; \
        done
    """
    remote_commands.append(kill_sessions_cmd)

    # (3) enforce_ubuntu2204_minimal_services
    enforce_services_cmd = r"""
allowed_services="apparmor.service
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

systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}' | while read service_name; do
    if echo "$allowed_services" | grep -qx "$service_name"; then
        :
    else
        echo "Stopping and disabling non-base service on REMOTE: $service_name"
        systemctl stop "$service_name" || true
        systemctl disable "$service_name" || true
    fi
done
"""
    remote_commands.append(enforce_services_cmd)

    # (4) configure_nic (detect the main NIC)
    configure_nic_cmd = r"ip route | grep default | awk '{print $5}' | head -1"
    remote_commands.append(configure_nic_cmd)

    # (5) setup_dynamic_ssh_key (remote portion only: append pub key)
    setup_dynamic_key_cmd = f"""
mkdir -p /root/.ssh
grep -v '{temp_ssh_pub_key}' /root/.ssh/authorized_keys > /tmp/authorized_keys_temp || true
echo '{temp_ssh_pub_key}' >> /tmp/authorized_keys_temp
mv /tmp/authorized_keys_temp /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
"""
    remote_commands.append(setup_dynamic_key_cmd)
    remote_commands.append(r"echo 'Dynamic SSH key setup complete!'")

    # (6) harden_system
    harden_ssh_cmd = r"""
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak || true
echo 'Protocol 2' > /etc/ssh/sshd_config
echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config
echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
echo 'ChallengeResponseAuthentication no' >> /etc/ssh/sshd_config
echo 'UsePAM no' >> /etc/ssh/sshd_config
echo 'X11Forwarding no' >> /etc/ssh/sshd_config
echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config
echo 'PermitTunnel no' >> /etc/ssh/sshd_config
echo 'AllowUsers azureuser' >> /etc/ssh/sshd_config
systemctl restart sshd
"""
    remote_commands.append(harden_ssh_cmd)

    kernel_cmds = r"""
sysctl -w kernel.kptr_restrict=1
sysctl -w kernel.dmesg_restrict=1
sysctl -w kernel.perf_event_paranoid=2
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -p
"""
    remote_commands.append(kernel_cmds)

    firewall_cmd = r"""
iptables -F
iptables -A INPUT -i MAIN_NIC_PLACEHOLDER -p tcp -s VALIDATOR_IP_PLACEHOLDER -j ACCEPT
iptables -A OUTPUT -o MAIN_NIC_PLACEHOLDER -p tcp -d VALIDATOR_IP_PLACEHOLDER -j ACCEPT
iptables -A INPUT -i MAIN_NIC_PLACEHOLDER -j DROP
iptables -A OUTPUT -o MAIN_NIC_PLACEHOLDER -j DROP
"""
    remote_commands.append(firewall_cmd)

    kill_processes_cmd = r"""
for pid in $(ps -ef | awk '!/systemd|\[.*\]|sshd|bash|ps|awk/ {print $2}'); do
    kill -9 "$pid" 2>/dev/null || true
done
"""
    remote_commands.append(kill_processes_cmd)

    # (7) create_revert_script
    revert_script_cmd = r"""
cat <<'EOF' > /tmp/revert_privacy.sh
#!/bin/bash
set -e
echo "Starting complete system reversion on remote..."

# 1. Stop all non-essential services
for service in $(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'); do
    if [[ "$service" != "ssh.service" && "$service" != systemd-* ]]; then
        systemctl stop "$service" || true
    fi
done

# 2. Reset iptables rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# 3. Restore sshd_config if backup exists; else keep root logins key-only
if [ -f /etc/ssh/sshd_config.bak ]; then
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    chmod 644 /etc/ssh/sshd_config
else
    echo "No sshd_config.bak found. Keeping 'PermitRootLogin prohibit-password' to avoid miner's password access."
    sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config || true
    echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
fi
systemctl restart sshd

# 4. Re-enable all system users (including root)
for user in $(cut -f1 -d: /etc/passwd); do
    usermod -U "$user" || true
done
passwd -u root || true

# 5. Restore kernel parameters to default-ish
sysctl -w kernel.kptr_restrict=0
sysctl -w kernel.dmesg_restrict=0
sysctl -w kernel.perf_event_paranoid=2
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.accept_redirects=1
sysctl -w net.ipv4.conf.all.send_redirects=1
sysctl -w net.ipv4.conf.all.accept_source_route=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -p

# 6. Re-enable minimal systemd services
systemctl daemon-reload
for service in $(systemctl list-unit-files --type=service --state=disabled --no-legend | cut -d' ' -f1); do
    systemctl enable "$service" || true
    systemctl start "$service" 2>/dev/null || true
done

# 7. Revert kernel module restrictions
echo 0 > /proc/sys/kernel/modules_disabled

# 8. Start/enable networking & DNS
systemctl unmask systemd-networkd.service || true
systemctl enable systemd-networkd.service || true
systemctl start systemd-networkd.service || true

systemctl unmask systemd-resolved.service || true
systemctl enable systemd-resolved.service || true
systemctl start systemd-resolved.service || true

# 9. Cleanup any leftover SSH keys
rm -f /tmp/session_key*
rm -f /tmp/authorized_keys_temp

echo "Remote system fully reverted."
EOF
chmod +x /tmp/revert_privacy.sh
"""
    remote_commands.append(revert_script_cmd)

    # (8) schedule_revert
    schedule_revert_cmd = rf"""
cat <<'LAUNCHER' > /tmp/revert_launcher.sh
#!/bin/bash
# Run entirely on remote, sleeping for {test_duration_minutes} min, then revert

sleep {test_duration_minutes}*60

if ! bash /tmp/revert_privacy.sh; then
    echo "Remote revert failed. Forcing partial restore but no root password access..."

    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT

    if [ -f /etc/ssh/sshd_config.bak ]; then
        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        chmod 644 /etc/ssh/sshd_config
    else
        sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config || true
        echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
    fi

    systemctl restart sshd
fi
LAUNCHER
chmod +x /tmp/revert_launcher.sh
nohup bash /tmp/revert_launcher.sh >/dev/null 2>&1 &
"""
    remote_commands.append(schedule_revert_cmd)

    all_commands = (setup_commands or []) + remote_commands

    main_nic = None
    try:
        log_message("INFO", f"Starting remote-based privacy setup for {machine_name} at {ip}.")
        for cmd in all_commands:
            cmd_stripped = cmd.strip()
            if not cmd_stripped:
                continue

            # Prefix the command with 'sudo' to ensure it runs as root
            if "\n" in cmd_stripped:
                # Multi-line command/script
                sudo_cmd = f"sudo bash -c '{cmd_stripped}'"
            else:
                sudo_cmd = f"sudo {cmd_stripped}"

            # Capture MAIN_NIC from the nic detection command
            if cmd_stripped == configure_nic_cmd:
                stdin, stdout, stderr = client.exec_command(sudo_cmd)
                main_nic = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
                if err:
                    log_message("WARNING", f"[{machine_name}] Error/Warning: {err}")
                if not main_nic:
                    log_message("ERROR", f"No network interface detected on remote {machine_name}!")
                    client.close()
                    return False
                log_message("INFO", f"[{machine_name}] MAIN_NIC detected: {main_nic}")
                continue

            # If we see the firewall script, replace placeholders
            if 'MAIN_NIC_PLACEHOLDER' in cmd_stripped or 'VALIDATOR_IP_PLACEHOLDER' in cmd_stripped:
                if not main_nic:
                    log_message("ERROR", f"Cannot apply firewall script on {machine_name} - MAIN_NIC not set.")
                    client.close()
                    return False
                cmd_stripped_updated = cmd_stripped.replace('MAIN_NIC_PLACEHOLDER', main_nic)
                cmd_stripped_updated = cmd_stripped_updated.replace('VALIDATOR_IP_PLACEHOLDER', validator_ip)

                # Handle multi-line firewall script
                if "\n" in cmd_stripped_updated:
                    sudo_cmd = f"sudo bash -c '{cmd_stripped_updated}'"
                else:
                    sudo_cmd = f"sudo {cmd_stripped_updated}"

                stdin, stdout, stderr = client.exec_command(sudo_cmd)
                out = stdout.read().decode()
                err = stderr.read().decode()

                if out.strip():
                    log_message("INFO", f"[{machine_name}] Output: {out.strip()}")
                if err.strip():
                    log_message("WARNING", f"[{machine_name}] Error/Warning: {err.strip()}")

                continue

            # Execute the command with sudo
            stdin, stdout, stderr = client.exec_command(sudo_cmd)
            out = stdout.read().decode()
            err = stderr.read().decode()

            if out.strip():
                log_message("INFO", f"[{machine_name}] Output: {out.strip()}")
            if err.strip():
                log_message("WARNING", f"[{machine_name}] Error/Warning: {err.strip()}")

        log_message("INFO", f"Privacy setup completed on {machine_name}.")
        return True
    except paramiko.SSHException as e:
        log_message("ERROR", f"SSH error during setup for {machine_name} ({ip}): {e}")
        return False
    except Exception as e:
        log_message("ERROR", f"Unexpected error during setup for {machine_name} ({ip}): {e}")
        return False
    finally:
        client.close()


######################################################################
# 4) MODEL CLASS USING THE NEW INITIATE_MACHINE_SETUP
######################################################################
class DendriteResponseEvent(BaseModel):
    uids: np.ndarray | list[float]
    results: list[PingSynapse]
    playlist: list[dict]
    status_messages: list[str] = []
    status_codes: list[int] = []

    # NEW: Additional containers for mapped and shuffled content
    test_list: list[dict] = []
    benign_list: list[dict] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @staticmethod
    def save_private_key(private_key_str: str, file_path: str):
        try:
            with open(file_path, "w") as key_file:
                key_file.write(private_key_str)
            os.chmod(file_path, 0o600)
            log_message("INFO", f"Private key saved to {file_path}")
        except Exception as e:
            log_message("ERROR", f"Error saving private key: {e}")

    @model_validator(mode="after")
    def process_results(self) -> "DendriteResponseEvent":
        """
        Orchestrate machine connections and remote setup.
        Then (a–d) handle the playlist: map classes to random strings,
        add tcp/udp traffic, shuffle, and store.
        """
        # Example user-supplied commands:
        setup_commands_map = {
            "Attacker": ["sudo apt update", "sudo apt install -y npm"],
            "Benign":   ["sudo apt update", "sudo apt install -y npm"],
            "King":     ["sudo apt update", "sudo apt install -y npm"],
        }

        # 1) For each synapse, attempt the connection tests & apply remote setup
        for synapse in self.results:
            ssh_public_key, ssh_private_key = synapse.machine_availabilities.key_pair
            machine_config = synapse.machine_availabilities.machine_config

            # Save private key locally (optional)
            self.save_private_key(ssh_private_key, "/tmp/private_key.pem")

            if not ssh_public_key or not ssh_private_key:
                log_message("ERROR", "Missing SSH Key Pair. Skipping this synapse.")
                self.status_messages.append("Missing SSH Key Pair.")
                self.status_codes.append(400)
                continue

            if not machine_config or any(not is_valid_ip(md.ip) for md in machine_config.values()):
                log_message("ERROR", "Invalid IP format. Skipping this synapse.")
                self.status_messages.append("Invalid IP format.")
                self.status_codes.append(400)
                continue

            all_connections_successful = True
            for machine_name, machine_details in machine_config.items():
                test_client = create_and_test_connection(machine_name, machine_details, ssh_private_key, timeout=15)
                if not test_client:
                    all_connections_successful = False
                    self.status_messages.append("One or more connections failed.")
                    self.status_codes.append(500)
                    break
                test_client.close()

            if not all_connections_successful:
                continue

            # All connections good, do remote setup
            all_setups_successful = True
            local_ip = get_local_ip()

            for machine_name, machine_details in machine_config.items():
                success = initiate_machine_setup(
                    machine_name=machine_name,
                    machine_details=machine_details,
                    private_key_str=ssh_private_key,
                    setup_commands=setup_commands_map.get(machine_name, []),
                    validator_ip=local_ip,
                    temp_ssh_pub_key=ssh_public_key,
                    test_duration_minutes=5
                )
                if not success:
                    all_setups_successful = False
                    self.status_messages.append("One or more setups failed.")
                    self.status_codes.append(500)
                    break

            if all_setups_successful:
                self.status_messages.append("All machines connected and setup successfully.")
                self.status_codes.append(200)

        # PROCESS THE PLAYLIST a-d AFTER WE'VE SET UP THE REMOTE MACHINES        
        if self.playlist:
            # (a) Identify actual classes (non-"pause")
            class_names = [item['name'] for item in self.playlist if item['name'] != 'pause']

            # (b) Create random mapping for each class + 2 special keys
            def random_str(min_len=10, max_len=13):
                length = random.randint(min_len, max_len)
                chars = string.ascii_letters + string.digits
                return "".join(random.choice(chars) for _ in range(length))

            mapping = {}
            for cls in class_names:
                mapping[cls] = random_str()

            mapping['tcp_traffic'] = random_str()
            mapping['udp_traffic'] = random_str()

            # benign_list for tcp and udp
            self.benign_list = [
                {"name": "tcp_traffic", "identifier": mapping['tcp_traffic']},
                {"name": "udp_traffic", "identifier": mapping['udp_traffic']}
            ]

            # (c) Shuffle the original playlist order (duration/class pairs intact)
            shuffled = self.playlist.copy()
            random.shuffle(shuffled)

            # (d) For each item, if it's a class (not pause), add the random string as identifier
            for item in shuffled:
                if item['name'] != 'pause':
                    item['identifier'] = mapping.get(item['name'], random_str())

            # Final result stored
            self.test_list = shuffled

        return self
