import requests
import subprocess

def get_local_ip() -> str:
    """
    Retrieves the local machine's public IP address if available.
    Falls back to the internal IP if the public IP cannot be retrieved.

    Returns:
        str: The detected IP address, or "127.0.0.1" if unavailable.
    """

    try:
        local_ip = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
        print(local_ip)
        if is_valid_ip(local_ip):
            return local_ip
    except:
        pass

    
    
print(get_local_ip())
