import numpy as np
from tensorprox.base.protocol import PingSynapse
from pydantic import BaseModel, model_validator, ConfigDict
import paramiko

class DendriteResponseEvent(BaseModel):
    uids: np.ndarray | list[float]
    results: list[PingSynapse]
    status_messages: list[str] = []
    status_codes: list[int] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @staticmethod
    def test_ssh_connection(ip: str, ssh_public_key: str) -> bool:
        """
        Test SSH connection using the given IP and public key.
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Convert public key string to key object
            pkey = paramiko.RSAKey(file_obj=ssh_public_key)

            # Attempt connection
            client.connect(
                hostname=ip,
                username="azureuser",  # Replace with the actual username
                pkey=pkey,
                timeout=10  # Timeout for the connection
            )
            client.close()
            return True
        except Exception as e:
            print(f"SSH connection to {ip} failed: {e}")
            return False

    #Process and structure miner's responses
    @model_validator(mode="after")
    def process_results(self) -> "DendriteResponseEvent":
        if len(self.machine_details) > 0:
            return self

        for synapse in self.results:
            machine_detail = synapse.machine_availabilities.machine_config
            ssh_public_key = synapse.ssh_public_key

            ip = machine_detail.get("ip")  # Assuming the IP is in this key
            self.status_messages.append(synapse.dendrite.status_message)
            status_code = synapse.dendrite.status_code

            for machine in machine_detail :
                ip = machine.get("ip")
                # Test SSH connection
                if ip and ssh_public_key:
                    connection_success = self.test_ssh_connection(ip, ssh_public_key)
                    if connection_success:
                        print(f"Connection to {machine} with  IP {ip} succeeded.")
                        self.machine_details.append(machine_detail)
                    else:
                        print(f"Connection to {machine} with IP failed.")
                        status_code = 204  # Adjust status code if connection fails

            self.status_codes.append(status_code)

        return self