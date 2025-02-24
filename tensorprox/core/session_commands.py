"""
================================================================================

SSH Security Command Generator

This module provides functions to generate shell commands for managing SSH security,
including inserting session keys, setting up sudo permissions, reverting security
changes, and locking down SSH access.

Functions:
    - get_insert_key_cmd: Generates a command to insert a session key into authorized_keys.
    - get_sudo_setup_cmd: Generates a command to allow passwordless sudo for a temporary period.
    - get_revert_script_cmd: Generates a revert script for restoring SSH and system configurations.
    - get_lockdown_cmd: Generates a command to restrict SSH access to a specific validator IP.

License:
This software is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0).
You are free to use, share, and modify the code for non-commercial purposes only.

Commercial Usage:
The only authorized commercial use of this software is for mining or validating within the TensorProx subnet.
For any other commercial licensing requests, please contact Shugo LTD.

See the full license terms here: https://creativecommons.org/licenses/by-nc/4.0/

Author: Shugo LTD
Version: 0.1.0

================================================================================
"""

import tempfile
import os


def get_insert_key_cmd(ssh_user: str, ssh_dir: str, session_pub: str, authorized_keys_path: str, authorized_keys_bak: str) -> str:
    """
    Generates the command to insert the session key into authorized_keys.

    Args:
        ssh_user (str): The SSH username.
        ssh_dir (str): The SSH directory path.
        session_pub (str): The public session key to be added.
        authorized_keys_path (str): The path to the authorized_keys file.
        authorized_keys_bak (str): The backup path for the authorized_keys file.

    Returns:
        str: The shell command to insert the session key.
    """
    
    return f"""
        export TMPDIR=$(mktemp -d /tmp/.ssh_setup_XXXXXX)
        chmod 700 $TMPDIR
        chown {ssh_user}:{ssh_user} $TMPDIR

        mkdir -p {ssh_dir}
        if [ -f {authorized_keys_path} ]; then
            cp {authorized_keys_path} {authorized_keys_bak}
            chmod 600 {authorized_keys_bak}
        fi

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

def get_sudo_setup_cmd(ssh_user: str) -> str:
    """
    Generates the sudo setup command to allow passwordless sudo for a temporary period.

    Args:
        ssh_user (str): The SSH username.

    Returns:
        str: The shell command to configure passwordless sudo.
    """

    return f"""
        echo '{ssh_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/99_{ssh_user}_temp
        chmod 440 /etc/sudoers.d/99_{ssh_user}_temp
    """


def get_revert_script_cmd(ip: str, authorized_keys_bak: str, authorized_keys_path: str, revert_log: str) -> str:
    """
    Generates the revert script content to restore SSH and system configurations.

    Args:
        ip (str): The IP address of the system being reverted.
        authorized_keys_bak (str): The path to the backup authorized_keys file.
        authorized_keys_path (str): The path to the authorized_keys file.
        revert_log (str): The path to the revert log file.

    Returns:
        str: The shell script for reverting security changes.
    """

    return f"""
#!/bin/bash
# Revert script for {ip}
# Logging to {revert_log}
exec > {revert_log} 2>&1
echo "=== Revert started for {ip} ==="

# --- Restore critical services ---
sudo systemctl unmask console-getty.service || echo "Failed to unmask console-getty"
sudo systemctl enable console-getty.service || echo "Failed to enable console-getty"
sudo systemctl start console-getty.service || echo "Failed to start console-getty"
sudo systemctl unmask serial-getty@ttyS0.service || echo "Failed to unmask serial-getty@ttyS0"
sudo systemctl enable serial-getty@ttyS0.service || echo "Failed to enable serial-getty@ttyS0"
sudo systemctl start serial-getty@ttyS0.service || echo "Failed to start serial-getty@ttyS0"
sudo systemctl unmask atd.service || echo "Failed to unmask atd"
sudo systemctl enable atd.service || echo "Failed to enable atd"
sudo systemctl restart atd.service || echo "Failed to restart atd"

# --- Nuclear Firewall Flush: flush all tables ---
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t raw -F
sudo iptables -t raw -X
sudo iptables -t security -F
sudo iptables -t security -X
cat <<EOF | sudo iptables-restore
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
EOF

# --- Restore authorized_keys ---
if [ -f {authorized_keys_bak} ]; then
    sudo cp {authorized_keys_bak} {authorized_keys_path}
    sudo chmod 600 {authorized_keys_path}
    rm -f {authorized_keys_bak}
    echo "Authorized_keys restored from backup."
else
    sudo sed -i '/^# START SESSION KEY/,/^# END SESSION KEY/d' {authorized_keys_path} || echo "Failed to remove session key block."
    echo "No backup file found; removed session key block."
fi

# --- Restore sshd configuration ---
if [ -f /etc/ssh/sshd_config.bak ]; then
    sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    sudo chmod 644 /etc/ssh/sshd_config
    echo "sshd_config restored from backup."
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
    echo "sshd_config modified."
fi
sudo passwd -u root 2>/dev/null || echo "Failed to unlock root password."
sudo systemctl restart sshd || echo "Failed to restart sshd."

for u in $(cut -f1 -d: /etc/passwd); do
    sudo usermod -U "$u" 2>/dev/null || echo "Failed to unmask user $u"
done
sudo passwd -u root 2>/dev/null || echo "Failed to unlock root password (second attempt)."

sudo sysctl -w kernel.kptr_restrict=0 || echo "Failed to set kptr_restrict"
sudo sysctl -w kernel.dmesg_restrict=0 || echo "Failed to set dmesg_restrict"
sudo sysctl -w kernel.perf_event_paranoid=2 || echo "Failed to set perf_event_paranoid"
sudo sysctl -w net.ipv4.tcp_syncookies=1 || echo "Failed to set tcp_syncookies"
sudo sysctl -w net.ipv4.ip_forward=1 || echo "Failed to set ip_forward"
sudo sysctl -w net.ipv4.conf.all.accept_redirects=1 || echo "Failed to set accept_redirects"
sudo sysctl -w net.ipv4.conf.all.send_redirects=1 || echo "Failed to set send_redirects"
sudo sysctl -w net.ipv4.conf.all.accept_source_route=1 || echo "Failed to set accept_source_route"
sudo sysctl -w net.ipv4.conf.all.rp_filter=1 || echo "Failed to set rp_filter"
sudo sysctl -p || echo "Failed to load sysctl settings"

sudo systemctl daemon-reload || echo "Failed to daemon-reload"
for s in $(systemctl list-unit-files --type=service --state=masked | cut -d' ' -f1); do
    sudo systemctl unmask $s || echo "Failed to unmask $s"
done
for s in $(systemctl list-unit-files --type=service --state=disabled | cut -d' ' -f1); do
    sudo systemctl enable $s || echo "Failed to enable $s"
    sudo systemctl start $s 2>/dev/null || echo "Failed to start $s"
done

echo 0 | sudo tee /proc/sys/kernel/modules_disabled >/dev/null || echo "Failed to reset modules_disabled"
sudo systemctl unmask systemd-networkd.service || echo "Failed to unmask systemd-networkd"
sudo systemctl enable systemd-networkd.service || echo "Failed to enable systemd-networkd"
sudo systemctl start systemd-networkd.service || echo "Failed to start systemd-networkd"
sudo systemctl unmask systemd-resolved.service || echo "Failed to unmask systemd-resolved"
sudo systemctl enable systemd-resolved.service || echo "Failed to enable systemd-resolved"
sudo systemctl start systemd-resolved.service || echo "Failed to start systemd-resolved"

echo "Done revert on {ip}"
    """


def get_lockdown_cmd(ssh_user:str, ssh_dir: str, validator_ip:str, authorized_keys_path: str) -> str:
    """
    Generates the command to persist the revert script in sudoers and lock down SSH.

    Args:
        ssh_user (str): The SSH username.
        ssh_dir (str): The SSH directory path.
        validator_ip (str): The IP address allowed for SSH access.
        authorized_keys_path (str): The path to the authorized_keys file.

    Returns:
        str: The shell command to restrict SSH access and lock down the system.
    """

    return f"""
        ############################################################
        # 1) Minimal services
        ############################################################
        allowed="apparmor.service dbus.service networkd-dispatcher.service polkit.service rsyslog.service snapd.service ssh.service systemd-journald.service systemd-logind.service systemd-networkd.service systemd-resolved.service systemd-timesyncd.service systemd-udevd.service atd.service"
        for s in $(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{{print $1}}'); do
            if echo "$allowed" | grep -wq "$s"; then
                :
            else
                echo "Stopping+masking $s"
                systemctl stop "$s" || true
                systemctl disable "$s" || true
                systemctl mask "$s" || true
            fi
        done

        ############################################################
        # 2) Disable console TTY if /etc/securetty
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
        # 3) Lock root
        ############################################################
        passwd -l root || true

        ############################################################
        # 4) Firewall => only {validator_ip}
        ############################################################
        NIC=$(ip route | grep default | awk '{{print $5}}' | head -1)
        iptables -F
        iptables -X
        iptables -A INPUT -i $NIC -p tcp -s {validator_ip} -j ACCEPT
        iptables -A OUTPUT -o $NIC -p tcp -d {validator_ip} -j ACCEPT
        iptables -A INPUT -i $NIC -j DROP
        iptables -A OUTPUT -o $NIC -j DROP

        ############################################################
        # 5) Kill processes except session process
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
        | grep -v paramiko \\
        | awk '{{print $2}}' \\
        | while read pid; do
            kill -9 "$pid" 2>/dev/null || true
        done

        ############################################################
        # 6) Remove original => keep session only
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

def get_pcap_file_cmd(uid: int, validator_username: str, validator_private_key: str, validator_ip: str, challenge_duration: str, capture_file: str, iface: str = "eth0") -> str:
    """
    Generates the command string to capture pcap analysis on a remote machine and transfer it via SCP.

    Args:
        validator_username (str): The SSH username for the validator.
        validator_private_key (str): The private key content as a string.
        validator_ip (str): The IP address of the remote validator.
        challenge_duration (str): Duration of the pcap capture.
        capture_file (str): The name of the pcap file.
        iface (str, optional): The network interface to capture traffic. Defaults to "eth0".

    Returns:
        str: The command string to execute on the remote machine.
    """

    # Generate the remote command
    cmd = f"""
    # Ensure tcpdump is installed
    if ! command -v tcpdump &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y tcpdump
    fi

    # Capture network traffic for a duration
    sudo tcpdump -i {iface} -w {capture_file} -G {challenge_duration} -W 1 'tcp or udp'

    # Create a temporary private key file
    echo -e "{validator_private_key}" > /tmp/validator_key
    chmod 600 /tmp/validator_key  # Set correct permissions

    # Ensure the destination directories exist on the remote machine
    ssh -i /tmp/validator_key {validator_username}@{validator_ip} "mkdir -p ~/tensorprox/tensorprox/rewards/pcap_files/{uid}/"

    # Securely transfer the pcap file via SCP
    scp -C -i /tmp/validator_key {capture_file} {validator_username}@{validator_ip}:~/tensorprox/tensorprox/rewards/pcap_files/{uid}/

    # Cleanup
    rm -f {capture_file}
    rm -f /tmp/validator_key  # Remove original key
    """

    return cmd




