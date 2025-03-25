#!/bin/bash

# Merged script to insert session key and set up passwordless sudo for a specific SSH user.

# Arguments:
#   ssh_user (str): The SSH username.
#   ssh_dir (str): The SSH directory path.
#   session_pub (str): The public session key to be added.
#   authorized_keys_path (str): The path to the authorized_keys file.
#   authorized_keys_bak (str): The backup path for the authorized_keys file.

# Extract arguments
ssh_user="$1"
ssh_dir="$2"
session_pub="$3"
authorized_keys_path="$4"
authorized_keys_bak="$5"

# Replace TENSORPROX_SPACE with a space in session_pub
session_pub=${session_pub//<TENSORPROX_SPACE>/ }

# Check if all arguments are provided
if [ -z "$ssh_user" ] || [ -z "$ssh_dir" ] || [ -z "$session_pub" ] || [ -z "$authorized_keys_path" ] || [ -z "$authorized_keys_bak" ]; then
    echo "All arguments must be provided."
    exit 1
fi

# Install missing packages
echo "Checking and installing missing packages..."
needed=("net-tools" "iptables-persistent" "psmisc")
for pkg in "${needed[@]}"; do
    dpkg -s $pkg >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Package '$pkg' missing. Installing..."
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y $pkg || echo "Failed to install package $pkg"
    fi
done

# Disable TTY requirement for sudo for the SSH user
echo "Disabling TTY requirement for $ssh_user..."
echo "Defaults:$ssh_user !requiretty" > /etc/sudoers.d/98_${ssh_user}_no_tty
chmod 440 /etc/sudoers.d/98_${ssh_user}_no_tty

# Define temporary directory for SSH setup
export TMPDIR=$(mktemp -d /tmp/.ssh_setup_XXXXXX)

chmod 700 $TMPDIR
chown $ssh_user:$ssh_user $TMPDIR

# Ensure SSH directory exists
mkdir -p $ssh_dir

# Backup the current authorized_keys file if it exists
if [ -f $authorized_keys_path ]; then
    cp $authorized_keys_path $authorized_keys_bak
    chmod 600 $authorized_keys_bak
fi

# Clean up authorized_keys by removing any session key
if [ -f $authorized_keys_path ]; then
    grep -v '^# START SESSION KEY' $authorized_keys_path | \
    grep -v '^# END SESSION KEY' | \
    grep -v "$session_pub" > "$TMPDIR/authorized_keys_clean" || true
else
    touch $TMPDIR/authorized_keys_clean
fi

# Add the new session key
echo '# START SESSION KEY' >> $TMPDIR/authorized_keys_clean
echo "$session_pub" >> $TMPDIR/authorized_keys_clean
echo '# END SESSION KEY' >> $TMPDIR/authorized_keys_clean

# Set proper permissions and move the cleaned file back
chown $ssh_user:$ssh_user $TMPDIR/authorized_keys_clean
chmod 600 $TMPDIR/authorized_keys_clean
mv $TMPDIR/authorized_keys_clean $authorized_keys_path

rm -rf $TMPDIR

# Ensure the SSH directory and authorized_keys have correct ownership and permissions
chown -R $ssh_user:$ssh_user $ssh_dir
chmod 700 $ssh_dir
chmod 600 $authorized_keys_path

