#!/bin/bash

# Generates the revert script content to restore SSH and system configurations.
#
# Arguments:
#   ip (str): The IP address of the system being reverted.
#   authorized_keys_bak (str): The path to the backup authorized_keys file.
#   authorized_keys_path (str): The path to the authorized_keys file.
#   revert_log (str): The path to the revert log file.
#
# Returns:
#   str: The shell script for reverting security changes, including restoring services,
#        clearing firewall settings, restoring SSH configurations, and system settings.
#
# Usage:
#   ./revert_script.sh <ip> <authorized_keys_bak_path> <authorized_keys_path> <revert_log_path>
# Example:
#   ./revert_script.sh 192.168.1.100 /path/to/authorized_keys.bak /path/to/authorized_keys /path/to/revert.log

# Assign arguments to variables
ip="$1"
authorized_keys_bak="$2"
authorized_keys_path="$3"
revert_log="$4"


# Revert script for $ip
# Logging to $revert_log
exec > $revert_log 2>&1
echo "=== Revert started for $ip ==="

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
if [ -f $authorized_keys_bak ]; then
    sudo cp $authorized_keys_bak $authorized_keys_path
    sudo chmod 600 $authorized_keys_path
    rm -f $authorized_keys_bak
    echo "Authorized_keys restored from backup."
else
    sudo sed -i '/^# START SESSION KEY/,/^# END SESSION KEY/d' $authorized_keys_path || echo "Failed to remove session key block."
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

echo "Done revert on $ip"

