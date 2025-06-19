#!/bin/bash
set -e

# Ensure we are in the challenge_gramine directory
cd "$(dirname "$0")"

# Create lib and tmp directories if they don't exist
mkdir -p lib tmp

# Copy required binaries into the current directory
for bin in python3 jq ip grep ping tcpdump timeout gawk awk nohup tc; do
    which $bin | xargs -I{} cp {} .
    ldd $(which $bin) | grep '=>' | awk '{print $3}' | xargs -I{} cp -n {} lib/
done

# Install Python dependencies into ./lib
pip3 install --upgrade pip --quiet
pip3 install --target=./lib faker scapy pycryptodome --quiet

echo "Setup complete. You can now run the enclave." 