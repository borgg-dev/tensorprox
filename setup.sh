#!/bin/bash

# Update system packages and install Python pip
sudo apt update && sudo apt install python3-pip -y

# Install Python dependencies from requirements.txt
pip install -r requirements.txt

# # Generate cold key using btcli
# btcli w regen_coldkey --wallet.name borgg --mnemonic actress dirt board drop envelope cricket link energy book case deal giant

# # Generate hot key using btcli
# btcli w regen_hotkey --wallet.name borgg --wallet.hotkey default --mnemonic two oven toy elevator cargo certain bird connect sport tip soda rebel

# Install npm and pm2 for process management
sudo apt install npm -y && sudo npm install -g pm2 

pm2 kill && pm2 flush

# Start validator and miner services with pm2
pm2 start "python3 neurons/validator.py" --name validator
pm2 start "python3 neurons/miner.py" --name miner

# Display the logs of pm2 processes
pm2 logs validator
