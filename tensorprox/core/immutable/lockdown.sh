#!/bin/bash

# Lock down the system and configure services securely.
#
# Arguments:
#   ssh_user - The SSH username (e.g., 'user').
#   ssh_dir  - The SSH directory path (e.g., '/home/user/.ssh').
#   validator_ip - The IP address allowed for SSH access (e.g., '192.168.1.100').
#   authorized_keys_path - The path to the authorized_keys file (e.g., '/home/user/.ssh/authorized_keys').

# Set variables based on script arguments
ssh_user="$1"
ssh_dir="$2"
validator_ip="$3"
authorized_keys_path="$4"

if [ -z "$ssh_user" ] || [ -z "$ssh_dir" ] || [ -z "$validator_ip" ] || [ -z "$authorized_keys_path" ]; then
    echo "Missing required arguments. Usage: $0 <ssh_user> <ssh_dir> <validator_ip> <authorized_keys_path>"
    exit 1
fi

############################################################
# 1) Configure Firewall - Allow only validator IP and GRE
############################################################
NIC=$(ip route | grep default | awk '{print $5}' | head -1)
iptables -F
iptables -X

# Allow SSH from validator only
iptables -A INPUT -i "$NIC" -p tcp --dport 22 -s "$validator_ip" -j ACCEPT
iptables -A OUTPUT -o "$NIC" -p tcp --sport 22 -d "$validator_ip" -j ACCEPT

# Allow local loopback (critical for many services)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow GRE protocol (protocol 47) for tunneling
iptables -A INPUT -i "$NIC" -p gre -j ACCEPT
iptables -A OUTPUT -o "$NIC" -p gre -j ACCEPT

# Allow IPIP protocol (protocol 4) for tunneling
iptables -A INPUT -i "$NIC" -p ipencap -j ACCEPT
iptables -A OUTPUT -o "$NIC" -p ipencap -j ACCEPT

# Allow UDP for DNS resolution
iptables -A OUTPUT -o "$NIC" -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i "$NIC" -p udp --sport 53 -j ACCEPT

# Default drop all other traffic
iptables -A INPUT -i "$NIC" -j DROP
iptables -A OUTPUT -o "$NIC" -j DROP

############################################################
# 2) Lock all user accounts except the validator user
############################################################
# Lock all user accounts with UID >= 1000 except the restricted user
for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
    if [ "$user" != "$ssh_user" ]; then
        passwd -l "$user" || echo "Failed to lock account: $user"
        # Kill any processes owned by non-validator users
        pkill -9 -u "$user" || true
    fi
done

# Lock root account
passwd -l root || echo "Failed to lock root account"

############################################################
# 3) Disable most services - only allow minimum required
############################################################
allowed="apparmor.service dbus.service networkd-dispatcher.service polkit.service rsyslog.service ssh.service systemd-journald.service systemd-logind.service systemd-networkd.service systemd-resolved.service systemd-timesyncd.service systemd-udevd.service atd.service"
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
# 4) Disable console TTY access
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
# 5) Kill all potentially dangerous processes
############################################################
# Get our own process tree to protect it
MYPID=$$
MYPIDS=$(pstree -p $MYPID | grep -o '([0-9]\+)' | tr -d '()')

# Kill all processes except essential ones
ps -ef \
| grep -v systemd \
| grep -v '\[.*\]' \
| grep -v sshd \
| grep -v "^$ssh_user.*bash" \
| grep -v ps \
| grep -v grep \
| grep -v awk \
| grep -v "$MYPIDS" \
| grep -v nohup \
| grep -v sleep \
| grep -v revert_launcher \
| grep -v revert_privacy \
| grep -v paramiko \
| awk '{print $2}' \
| while read pid; do
    kill -9 "$pid" 2>/dev/null || echo "Failed to kill $pid"
done

############################################################
# 6) Restrict SSH keys to validator session key only
############################################################
if [ -f "$authorized_keys_path" ]; then
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    chown "$ssh_user:$ssh_user" "$TMPDIR"
    # Extract only the validator session key
    awk '/# START SESSION KEY/,/# END SESSION KEY/' "$authorized_keys_path" > "$TMPDIR/session_only"
    chown "$ssh_user:$ssh_user" "$TMPDIR/session_only"
    chmod 600 "$TMPDIR/session_only"
    mv "$TMPDIR/session_only" "$authorized_keys_path"
    chown -R "$ssh_user:$ssh_user" "$ssh_dir"
    chmod 700 "$ssh_dir"
    chmod 600 "$authorized_keys_path"
fi

############################################################
# 7) Terminate existing sessions other than validator
############################################################
# Find current session to preserve it
MYSESS=$(who | grep "$ssh_user" | grep -v "^$ssh_user.*pts" | awk '{print $2}')

# Kill all other sessions
w -h | grep -v "$ssh_user.*$MYSESS" | awk '{print $2}' | xargs -r pkill -9 -t

# Kill any X sessions or GUI components
pkill -9 -f Xorg || true
pkill -9 -f gnome || true
pkill -9 -f kde || true

echo "Lockdown completed successfully."