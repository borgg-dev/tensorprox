#!/bin/bash

# Lock down the system and configure services securely.
#
# Arguments:
#   ssh_user - The SSH username (e.g., 'user').
#   ssh_dir  - The SSH directory path (e.g., '/home/user/.ssh').
#   validator_ip - The IP address allowed for SSH access (e.g., '192.168.1.100').
#   authorized_keys_path - The path to the authorized_keys file (e.g., '/home/user/.ssh/authorized_keys').

# Set variables based on script arguments (you can modify or provide these values).
ssh_user="$1"
ssh_dir="$2"
validator_ip="$3"
authorized_keys_path="$4"

if [ -z "$ssh_user" ] || [ -z "$ssh_dir" ] || [ -z "$validator_ip" ] || [ -z "$authorized_keys_path" ]; then
    echo "Missing required arguments. Usage: $0 <ssh_user> <ssh_dir> <validator_ip> <authorized_keys_path>"
    exit 1
fi

############################################################
# 1) Minimal services
############################################################
allowed="apparmor.service dbus.service networkd-dispatcher.service polkit.service rsyslog.service snapd.service ssh.service systemd-journald.service systemd-logind.service systemd-networkd.service systemd-resolved.service systemd-timesyncd.service systemd-udevd.service atd.service"
for s in $(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'); do
    if echo "$allowed" | grep -wq "$s"; then
        :
    else
        echo "Stopping+masking $s"
        systemctl stop "$s" || echo "Failed to stop $s"
        systemctl disable "$s" || echo "Failed to disable $s"
        systemctl mask "$s" || echo "Failed to mask $s"
    fi
done

############################################################
# 2) Disable console TTY if /etc/securetty
############################################################
if [ -f "/etc/securetty" ]; then
    sed -i '/^tty[0-9]/d' "/etc/securetty" || echo "Failed to modify /etc/securetty"
    sed -i '/^ttyS/d' "/etc/securetty" || echo "Failed to modify /etc/securetty"
fi
systemctl stop console-getty.service || echo "Failed to stop console-getty"
systemctl disable console-getty.service || echo "Failed to disable console-getty"
systemctl mask console-getty.service || echo "Failed to mask console-getty"
systemctl stop serial-getty@ttyS0.service || echo "Failed to stop serial-getty@ttyS0"
systemctl disable serial-getty@ttyS0.service || echo "Failed to disable serial-getty@ttyS0"
systemctl mask serial-getty@ttyS0.service || echo "Failed to mask serial-getty@ttyS0"

############################################################
# 3) Lock root account
############################################################
echo "Locking the root account."
passwd -l root || echo "Failed to lock root account"

############################################################
# 4) Configure Firewall => only allow $validator_ip
############################################################
NIC=$(ip route | grep default | awk '{print $5}' | head -1)
iptables -F
iptables -X
iptables -A INPUT -i "$NIC" -p tcp -s "$validator_ip" -j ACCEPT
iptables -A OUTPUT -o "$NIC" -p tcp -d "$validator_ip" -j ACCEPT
iptables -A INPUT -i "$NIC" -j DROP
iptables -A OUTPUT -o "$NIC" -j DROP

# Ensure rules persist across reboots if using iptables
# This might require additional setup depending on your system.

############################################################
# 5) Kill non-essential processes
############################################################
echo "Killing non-essential processes."
ps -ef \
| grep -v systemd \
| grep -v '\[.*\]' \
| grep -v sshd \
| grep -v bash \
| grep -v ps \
| grep -v grep \
| grep -v awk \
| grep -v nohup \
| grep -v sleep \
| grep -v revert_launcher \
| grep -v revert_privacy \
| grep -v paramiko \
| awk '{print $2}' \
| while read pid; do
    kill "$pid" 2>/dev/null || echo "Failed to kill $pid"
done

############################################################
# 6) Keep only session keys in authorized_keys file
############################################################
echo "Cleaning up authorized_keys file to keep only session keys."
if [ -f "$authorized_keys_path" ]; then
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    chown "$ssh_user:$ssh_user" "$TMPDIR"
    awk '/# START SESSION KEY/,/# END SESSION KEY/' "$authorized_keys_path" > "$TMPDIR/session_only"
    chown "$ssh_user:$ssh_user" "$TMPDIR/session_only"
    chmod 600 "$TMPDIR/session_only"
    mv "$TMPDIR/session_only" "$authorized_keys_path"
    chown -R "$ssh_user:$ssh_user" "$ssh_dir"
    chmod 700 "$ssh_dir"
    chmod 600 "$authorized_keys_path"
fi

echo "Lockdown completed successfully."
