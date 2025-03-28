# #!/bin/bash

# # Update system packages and install Python pip/venv
# sudo apt update && sudo apt install python3-pip -y && apt install python3-venv -y

# # Install npm and pm2 for process management
# sudo apt install npm -y && sudo npm install -g pm2 

# #Activate virtual env
# python3 -m venv tp && source tp/bin/activate

# #Clone main repository
# git clone http://github.com/borgg-dev/tensorprox.git
# cd tensorprox/

# # Install Python dependencies from requirements.txt
# pip install -r requirements.txt

# # Generate cold key using btcli
# btcli w regen_coldkey --wallet.name borgg --mnemonic "actress dirt board drop envelope cricket link energy book case deal giant"

# #Generate hot key using btcli
# btcli w regen_hotkey --wallet.name borgg --wallet.hotkey validator1 --mnemonic "two oven toy elevator cargo certain bird connect sport tip soda rebel"

# #Generate hot key using btcli
# btcli w regen_hotkey --wallet.name borgg --wallet.hotkey validator2 --mnemonic "brick jelly unable coral during warm pyramid blame loop tunnel kind transfer"

# #Generate hot key using btcli
# btcli w regen_hotkey --wallet.name borgg --wallet.hotkey miner --mnemonic "permit fragile index outer vintage purse divert hotel fee few burger drama"


pm2 kill && pm2 flush

# Start validator and miner services with pm2
pm2 start "python3 ~/tensorprox/neurons/miner.py" --name miner
pm2 start "python3 ~/tensorprox/neurons/validator.py" --name validator

# Display the logs of pm2 processes
pm2 logs miner