import asyncio
import os
from tensorprox import *

async def send_file_via_scp(local_file, remote_path, remote_host, remote_user, remote_key_path):
    # Construct the SCP command
    scp_command = [
        'scp',
        '-i', remote_key_path,  # Specify the SSH private key
        local_file,  # Local file to transfer
        f'{remote_user}@{remote_host}:{remote_path}'  # Remote destination
    ]

    try:
        # Run the SCP command asynchronously using asyncio.subprocess
        process = await asyncio.create_subprocess_exec(*scp_command)

        # Wait for the SCP process to complete
        await process.wait()

        if process.returncode == 0:
            print(f"File {local_file} successfully sent to {remote_host}:{remote_path}")
        else:
            print(f"SCP failed with return code {process.returncode}")

    except Exception as e:
        print(f"Error: {e}")

# Usage Example
async def main():


    # Construct the path to 'traffic_generator.py' relative to the script's directory
    local_file = TRAFFIC_GEN_PATH
    remote_host = "192.168.122.72"
    remote_user = "borgg"
    remote_key_path = "/home/borgg/.ssh/rsa-new"
    remote_path = "/tmp/traffic_generator.py"

    await send_file_via_scp(local_file, remote_path, remote_host, remote_user, remote_key_path)

# Run the async function
asyncio.run(main())

