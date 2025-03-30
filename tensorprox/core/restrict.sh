#!/bin/bash
# Complete setup script for whitelist-agent configuration

restricted_user="$1"

# Check if user argument is provided
if [[ -z "$restricted_user" ]]; then
    echo "Error: Username must be provided as the first argument."
    echo "Usage: $0 <username>"
    exit 1
fi

# Exit on any error
set -e

echo "Starting setup process..."

# Main Task 1: Prepare the Environment
echo "Creating dedicated system user (if not exists)..."
if ! id -u "$restricted_user" &>/dev/null; then
    sudo adduser --disabled-password --gecos "" "$restricted_user" || { echo "Failed to create user $restricted_user. Exiting."; exit 1; }
else
    echo "User $restricted_user already exists, skipping creation."
fi

echo "Creating SSH directory..."
sudo mkdir -p "/home/$restricted_user/.ssh"
sudo chown -R "$restricted_user:$restricted_user" "/home/$restricted_user/.ssh"
sudo chmod 700 "/home/$restricted_user/.ssh"

sudo touch "/home/$restricted_user/.ssh/authorized_keys"
sudo chown "$restricted_user:$restricted_user" "/home/$restricted_user/.ssh/authorized_keys"
sudo chmod 600 "/home/$restricted_user/.ssh/authorized_keys"

echo "Restricting password authentication..."
sudo passwd -l "$restricted_user" || echo "Password already locked or error occurred, continuing..."

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

# Define the sudoers file name (use a fixed name for simplicity)
sudoers_file="/etc/sudoers.d/90-$restricted_user"

# Create the sudoers file with proper syntax
sudo bash -c "cat <<EOF > '$sudoers_file'
Defaults!/usr/local/bin/whitelist-agent !requiretty
$restricted_user ALL=(ALL) NOPASSWD: /usr/local/bin/whitelist-agent
EOF"

sudo chmod 440 "$sudoers_file"

echo "Writing the agent script..."
# Using double quotes for EOF to allow variable expansion
sudo bash -c "cat << EOF > /usr/local/bin/whitelist-agent
#!/usr/bin/env bash

# Function to normalize path
normalize_path() {
    local path=\"\$1\"
    if command -v realpath &>/dev/null; then
        realpath \"\$path\" 2>/dev/null || echo \"\$path\"
    else
        readlink -f \"\$path\" 2>/dev/null || echo \"\$path\"
    fi
}

# Define allowed commands with proper user path expansion
ALLOWED_COMMANDS=(
    \"/usr/bin/ssh\"
    \"/usr/bin/sha256sum /home/$restricted_user/tensorprox/tensorprox/core/immutable/initial_setup.sh\"
    \"/usr/bin/sha256sum /home/$restricted_user/tensorprox/tensorprox/core/immutable/challenge.sh\"
    \"/usr/bin/sha256sum /home/$restricted_user/tensorprox/tensorprox/core/immutable/lockdown.sh\"
    \"/usr/bin/sha256sum /home/$restricted_user/tensorprox/tensorprox/core/immutable/revert.sh\"
    \"/usr/bin/sha256sum /home/$restricted_user/tensorprox/tensorprox/core/immutable/gre_setup.py\"
    \"/usr/bin/sha256sum /home/$restricted_user/tensorprox/tensorprox/core/immutable/traffic_generator.py\"
    \"/usr/bin/bash /home/$restricted_user/tensorprox/tensorprox/core/immutable/initial_setup.sh\"
    \"/usr/bin/bash /home/$restricted_user/tensorprox/tensorprox/core/immutable/challenge.sh\"
    \"/usr/bin/bash /home/$restricted_user/tensorprox/tensorprox/core/immutable/lockdown.sh\"
    \"/usr/bin/bash /home/$restricted_user/tensorprox/tensorprox/core/immutable/revert.sh\"
    \"/usr/bin/python3.10 /home/$restricted_user/tensorprox/tensorprox/core/immutable/gre_setup.py\"
)

# Improved command validation function
is_command_allowed() {
    local full_cmd=\"\$1\"
    
    # Extract the base command and its arguments
    read -ra cmd_parts <<< \"\$full_cmd\"
    
    # Need at least one part
    if [[ \${#cmd_parts[@]} -lt 1 ]]; then
        return 1
    fi

    # Extract main parts
    local base_cmd=\$(normalize_path \"\${cmd_parts[0]}\")
    
    # If we have more parts, get the script path
    local script_path=\"\"
    if [[ \${#cmd_parts[@]} -gt 1 ]]; then
        script_path=\$(normalize_path \"\${cmd_parts[1]}\")
    fi
    
    # Build normalized command for comparison
    local normalized_cmd=\"\$base_cmd\"
    if [[ -n \"\$script_path\" ]]; then
        normalized_cmd=\"\$base_cmd \$script_path\"
    fi
    
    # Check against allowed commands
    for allowed_cmd in \"\${ALLOWED_COMMANDS[@]}\"; do
        # First, normalize the allowed command for comparison
        local allowed_base=\$(echo \"\$allowed_cmd\" | cut -d' ' -f1)
        local allowed_base_norm=\$(normalize_path \"\$allowed_base\")
        
        # If allowed command has arguments, extract and normalize the script path
        if [[ \"\$allowed_cmd\" == *\" \"* ]]; then
            local allowed_script=\$(echo \"\$allowed_cmd\" | cut -d' ' -f2)
            local allowed_script_norm=\$(normalize_path \"\$allowed_script\")
            local allowed_norm=\"\$allowed_base_norm \$allowed_script_norm\"
            
            # Match beginning of command (to allow for additional arguments)
            if [[ \"\$normalized_cmd\" == \"\$allowed_norm\"* ]]; then
                return 0
            fi
        else
            # Just compare the base command
            if [[ \"\$normalized_cmd\" == \"\$allowed_base_norm\"* ]]; then
                return 0
            fi
        fi
    done

    return 1  # Not allowed
}

# Safer command execution
execute_command() {
    # Use arrays to handle arguments properly and prevent injection
    local cmd_array=()
    
    # Read command into array
    read -ra cmd_array <<< \"\$1\"
    
    # Execute with sudo using array to preserve argument structure
    sudo \"\${cmd_array[@]}\"
    return \$?
}

# The command passed by SSH will be the first argument to this script
cmd=\"\$1\"

# Check if a command was provided
if [[ -z \"\$cmd\" ]]; then
    echo \"No command provided.\"
    exit 1
fi

# Get the base command (first word)
base_cmd_name=\"\${cmd%% *}\"

# If it's a relative path or just a command name, try to find the full path
if [[ \"\$base_cmd_name\" != /* ]]; then
    base_cmd=\$(command -v \"\$base_cmd_name\" 2>/dev/null)
    if [[ -z \"\$base_cmd\" ]]; then
        echo \"Command not found: \$base_cmd_name\"
        exit 1
    fi
else
    base_cmd=\"\$base_cmd_name\"
fi

# Replace base command with full path in the original command
if [[ \"\$cmd\" == *\" \"* ]]; then
    full_cmd=\"\$base_cmd \${cmd#* }\"
else
    full_cmd=\"\$base_cmd\"
fi

# Check if command is allowed
if is_command_allowed \"\$full_cmd\"; then
    # Use a safer execution method
    execute_command \"\$full_cmd\"
    exit_code=\$?
    if [[ \"\$exit_code\" -eq 0 ]]; then
        exit \$exit_code
    else
        echo \"Command '\$full_cmd' executed with errors. Exit code: \$exit_code\"
        exit 1
    fi
else
    echo \"Command '\$full_cmd' not allowed.\"
    exit 1
fi
EOF"

echo "Writing the agent wrapper..."
sudo bash -c "cat << 'EOF' > /usr/local/bin/whitelist-agent-wrapper
#!/bin/bash

if [ -n \"\$SSH_ORIGINAL_COMMAND\" ]; then
    /usr/local/bin/whitelist-agent \"\$SSH_ORIGINAL_COMMAND\"
else
    echo \"No command specified\"
    exit 1
fi
EOF"

echo "Setting proper permissions for the agent script..."
sudo chmod 755 /usr/local/bin/whitelist-agent
sudo chown root:root /usr/local/bin/whitelist-agent

sudo chmod 755 /usr/local/bin/whitelist-agent-wrapper
sudo chown root:root /usr/local/bin/whitelist-agent-wrapper

echo "Configuring SSH to use the agent..."
sudo mkdir -p /etc/ssh/sshd_config.d
sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.conf << EOF
Match User $restricted_user
    ForceCommand /usr/local/bin/whitelist-agent-wrapper
EOF"

echo "Creating active/inactive mode configurations..."
sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.active.conf << EOF
Match User $restricted_user
    ForceCommand /usr/local/bin/whitelist-agent-wrapper
EOF"

sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.inactive.conf << EOF
# No ForceCommand line, so the user gets a normal shell
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