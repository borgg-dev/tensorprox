#!/bin/bash
set -e

# Ensure we are in the challenge_gramine directory
cd "$(dirname "$0")"

# Create lib and tmp directories if they don't exist
mkdir -p lib tmp

# Copy required binaries into the current directory
echo "Copying binaries..."
for bin in python3 jq ip grep ping tcpdump timeout gawk awk nohup tc; do
    if command -v $bin > /dev/null 2>&1; then
        cp $(which $bin) . || echo "Failed to copy $bin"
        echo "Copied $bin"
    else
        echo "WARNING: $bin not found"
    fi
done

# Copy library dependencies
echo "Copying library dependencies..."
for bin in python3 jq ip grep ping tcpdump timeout gawk awk nohup tc; do
    if [ -f "./$bin" ]; then
        ldd ./$bin 2>/dev/null | grep '=>' | awk '{print $3}' | while read lib; do
            if [ -f "$lib" ] && [ ! -f "lib/$(basename $lib)" ]; then
                cp "$lib" lib/ || echo "Failed to copy library: $lib"
            fi
        done
    fi
done

# Copy Python standard library
echo "Copying Python standard library..."
python3_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [ -d "/usr/lib/python${python3_version}" ]; then
    cp -r /usr/lib/python${python3_version} lib/ || echo "Failed to copy Python standard library"
    echo "Copied Python ${python3_version} standard library"
fi

# Install Python dependencies into ./lib
echo "Installing Python packages..."
pip3 install --upgrade pip --quiet
pip3 install --target=./lib faker scapy pycryptodome --quiet

# Copy additional system files that might be needed
echo "Copying system configuration files..."
for f in /etc/protocols /etc/services; do
    if [ -f "$f" ]; then
        cp "$f" . || echo "Failed to copy $f"
    fi
done

echo "Setup complete. You can now run the enclave."