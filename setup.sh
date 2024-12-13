#!/bin/bash

# # Update system packages and install Python pip/venv
# sudo apt update && sudo apt install python3-pip -y && apt install python3-venv -y

# # Install npm and pm2 for process management
# sudo apt install npm -y && sudo npm install -g pm2 

# #Activate virtual env
# python3 -m venv tp && source tp/bin/activate

# # Install Python dependencies from requirements.txt
# pip install -r requirements.txt

# # Generate cold key using btcli
# btcli w regen_coldkey --wallet.name borgg --mnemonic "actress dirt board drop envelope cricket link energy book case deal giant"

# Generate hot key using btcli
# btcli w regen_hotkey --wallet.name borgg --wallet.hotkey hotkey-test --mnemonic "two oven toy elevator cargo certain bird connect sport tip soda rebel"


pm2 kill && pm2 flush

# Start validator and miner services with pm2
pm2 start "python3 ~/tensorprox/neurons/miner.py" --name miner
pm2 start "python3 ~/tensorprox/neurons/validator.py" --name validator
# pm2 start "python3 ~/TensorProx/TrafficLogger/websocket_server.py" --name websocket_server

# Display the logs of pm2 processes
pm2 logs validator
