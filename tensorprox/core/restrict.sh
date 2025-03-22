#!/bin/bash
# Complete setup script for whitelist-agent configuration

# Exit on any error
set -e

echo "Starting setup process..."

# Main Task 1: Prepare the Environment
echo "Creating dedicated system user (if not exists)..."
if ! id -u valiops &>/dev/null; then
    sudo adduser --disabled-password --gecos "" valiops || { echo "Failed to create user valiops. Exiting."; exit 1; }
else
    echo "User valiops already exists, skipping creation."
fi

echo "Creating SSH directory..."
sudo mkdir -p /home/valiops/.ssh
sudo chown -R valiops:valiops /home/valiops/.ssh
sudo chmod 700 /home/valiops/.ssh

sudo touch /home/valiops/.ssh/authorized_keys
sudo chown valiops:valiops /home/valiops/.ssh/authorized_keys
sudo chmod 600 /home/valiops/.ssh/authorized_keys

echo "Restricting password authentication..."
sudo passwd -l valiops || echo "Password already locked or error occurred, continuing..."

# Install SSH server if not already installed
echo "Installing SSH server if not already installed..."
sudo apt update
sudo apt install -y openssh-server || { echo "Failed to install SSH server. Exiting."; exit 1; }

# Ensure SSH service is enabled and running
echo "Ensuring SSH service is enabled and running..."
if systemctl list-unit-files | grep -q "ssh.service"; then
    sudo systemctl enable ssh
    sudo systemctl start ssh
elif systemctl list-unit-files | grep -q "sshd.service"; then
    sudo systemctl enable sshd
    sudo systemctl start sshd
else
    # Fallback for older Ubuntu versions
    sudo service ssh start || sudo service sshd start || echo "Could not start SSH service, please check manually."
fi

# Configure Passwordless Sudo for the Agent
echo "Configuring sudo permissions..."
sudo bash -c "cat > /etc/sudoers.d/90-valiops << 'EOF'
valiops ALL=(ALL) NOPASSWD: /usr/local/bin/whitelist-agent
EOF"
sudo chmod 440 /etc/sudoers.d/90-valiops

# Main Task 2: Install and Configure the Whitelist Agent
echo "Creating allowlist directory and file..."
sudo mkdir -p /etc/whitelist-agent
sudo touch /etc/whitelist-agent/allowlist.txt

echo "Populating allowlist with whitelisted commands..."
cat << 'EOF' | sudo tee /etc/whitelist-agent/allowlist.txt
/usr/bin/ssh
/usr/bin/sudo /usr/bin/bash /home/valiops/tensorprox/tensorprox/core/immutable/initial_setup.sh
/usr/bin/sudo /usr/bin/bash /home/valiops/tensorprox/tensorprox/core/immutable/challenge.sh
/usr/bin/sudo /usr/bin/bash /home/valiops/tensorprox/tensorprox/core/immutable/lockdown.sh
/usr/bin/sudo /usr/bin/bash /home/valiops/tensorprox/tensorprox/core/immutable/pwdless_sudo.sh
/usr/bin/sudo /usr/bin/bash /home/valiops/tensorprox/tensorprox/core/immutable/revert.sh 
/usr/bin/sudo /usr/bin/python3 /home/valiops/tensorprox/tensorprox/core/immutable/gre_setup.py
EOF

# Create audit log directory
echo "Creating audit log directory..."
sudo mkdir -p /var/log/whitelist-agent
sudo touch /var/log/whitelist-agent/audit.log
sudo chown root:root /var/log/whitelist-agent/audit.log
sudo chmod 644 /var/log/whitelist-agent/audit.log

echo "Setting proper permissions for allowlist..."
sudo chmod 644 /etc/whitelist-agent/allowlist.txt
sudo chmod 755 /etc/whitelist-agent

echo "Writing the agent script..."
cat << 'EOF' | sudo tee /usr/local/bin/whitelist-agent
#!/usr/bin/env bash

ALLOWLIST="/etc/whitelist-agent/allowlist.txt"
AUDIT_LOG="/var/log/whitelist-agent/audit.log"

# Function to log actions
log_action() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local user="$USER"
    local action="$1"
    local status="$2"
    local command="$3"
    
    echo "$timestamp | User: $user | Action: $action | Status: $status | Command: $command" >> "$AUDIT_LOG"
}

# Function to normalize path
normalize_path() {
    local path="$1"
    # Convert to absolute path and resolve symlinks
    if [[ -e "$path" ]]; then
        readlink -f "$path"
    else
        echo "$path"
    fi
}

# Function to check if a command is allowed
is_command_allowed() {
    local full_cmd="$1"
    
    # Normalize the full command to its absolute path
    local full_cmd_path=$(normalize_path "$full_cmd")
    
    # Iterate over each line in the allowlist and check if the full command path starts with any of the allowed paths
    while IFS= read -r allowed_cmd; do
        if [[ "$full_cmd_path" == "$allowed_cmd"* ]]; then
            return 0  # If the command path starts with an allowed path, it's allowed
        fi
    done < "$ALLOWLIST"
    
    return 1  # Command is not allowed
}

# Execute the command safely
execute_command() {
    local cmd="$1"
    local cmd_array=()
    
    # Parse command into array to avoid command injection
    read -ra cmd_array <<< "$cmd"
    
    # Execute the command
    "${cmd_array[@]}"
    return $?
}

# Main logic: handle SSH commands or interactive shell
if [[ -z "$SSH_ORIGINAL_COMMAND" ]]; then
    echo "Restricted shell enabled. Type 'exit' to leave."
    log_action "SHELL_START" "SUCCESS" "Interactive shell started"
    
    while true; do
        read -p "> " input_cmd
        
        # Handle exit command specially
        if [[ "$input_cmd" == "exit" ]]; then
            log_action "SHELL_EXIT" "SUCCESS" "Interactive shell exited"
            exit 0
        fi
        
        # Check if command exists
        base_cmd=$(command -v ${input_cmd%% *} 2>/dev/null)
        if [[ -z "$base_cmd" ]]; then
            echo "Command not found: ${input_cmd%% *}"
            log_action "COMMAND" "FAILED" "Command not found: ${input_cmd%% *}"
            continue
        fi
        
        # Normalize the base command path
        base_cmd=$(normalize_path "$base_cmd")
        
        # Replace base command with full path
        if [[ "$input_cmd" == *" "* ]]; then
            full_cmd="$base_cmd ${input_cmd#* }"
        else
            full_cmd="$base_cmd"
        fi

        # Check if command is allowed
        if is_command_allowed "$full_cmd"; then
            log_action "COMMAND" "ALLOWED" "$full_cmd"
            execute_command "$full_cmd"
            exit_code=$?
            log_action "COMMAND" "COMPLETED" "Exit code: $exit_code for command: $full_cmd"
        else
            echo "Command '$full_cmd' not allowed."
            log_action "COMMAND" "DENIED" "$full_cmd"
        fi
    done
else

    cmd = "$1"

    # Log the received command for debugging purposes
    echo "Received command: $cmd" >> /tmp/whitelist-agent.log

    # Extract the base command and check if it exists
    base_cmd=$(command -v ${cmd%% *} 2>/dev/null)
    if [[ -z "$base_cmd" ]]; then
        echo "Command not found: ${cmd%% *}"
        log_action "SSH_COMMAND" "FAILED" "Command not found: ${cmd%% *}"
        exit 1
    fi
    
    # Normalize the base command path
    base_cmd=$(normalize_path "$base_cmd")
    
    # Replace base command with full path
    if [[ "$SSH_ORIGINAL_COMMAND" == *" "* ]]; then
        full_cmd="$base_cmd ${cmd#* }"
    else
        full_cmd="$base_cmd"
    fi

    # Check if command is allowed
    if is_command_allowed "$full_cmd"; then
        log_action "SSH_COMMAND" "ALLOWED" "$full_cmd"
        execute_command "$full_cmd"
        exit_code=$?
        log_action "SSH_COMMAND" "COMPLETED" "Exit code: $exit_code for command: $full_cmd"
        exit $exit_code
    else
        echo "Command '$full_cmd' not allowed."
        log_action "SSH_COMMAND" "DENIED" "$full_cmd"
        exit 1
    fi
fi
EOF

echo "Setting proper permissions for the agent script..."
sudo chmod 755 /usr/local/bin/whitelist-agent
sudo chown root:root /usr/local/bin/whitelist-agent

echo "Configuring SSH to use the agent..."
sudo mkdir -p /etc/ssh/sshd_config.d
sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.conf << 'EOF'
Match User valiops
    ForceCommand /usr/local/bin/whitelist-agent
EOF"

echo "Creating active/inactive mode configurations..."
sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.active.conf << 'EOF'
Match User valiops
    ForceCommand /usr/local/bin/whitelist-agent
EOF"

sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.inactive.conf << 'EOF'
# No ForceCommand line, so the user gets a normal shell
EOF"

# Create logrotate configuration for audit logs
echo "Setting up log rotation for audit logs..."
sudo bash -c "cat > /etc/logrotate.d/whitelist-agent << 'EOF'
/var/log/whitelist-agent/audit.log {
    weekly
    missingok
    rotate 13
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF"

echo "Reloading SSH to apply changes..."
if systemctl list-unit-files | grep -q "ssh.service"; then
    sudo systemctl reload ssh || sudo systemctl restart ssh
elif systemctl list-unit-files | grep -q "sshd.service"; then
    sudo systemctl reload sshd || sudo systemctl restart sshd
else
    # Fallback for older Ubuntu versions
    sudo service ssh reload || sudo service ssh restart || 
    sudo service sshd reload || sudo service sshd restart ||
    echo "Could not reload SSH service, please restart it manually."
fi

echo "Setup complete!"
echo ""
echo "To activate whitelist enforcement:"
echo "sudo cp /etc/ssh/sshd_config.d/whitelist.active.conf /etc/ssh/sshd_config.d/whitelist.conf"
echo "sudo systemctl reload ssh || sudo systemctl reload sshd"
echo ""
echo "To deactivate whitelist enforcement:"
echo "sudo cp /etc/ssh/sshd_config.d/whitelist.inactive.conf /etc/ssh/sshd_config.d/whitelist.conf"
echo "sudo systemctl reload ssh || sudo systemctl reload sshd"
echo ""
echo "Audit logs are available at: /var/log/whitelist-agent/audit.log"
