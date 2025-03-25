# #!/bin/bash

# # Update system packages and install Python pip/venv
# sudo apt update && sudo apt install python3-pip -y && apt install python3-venv -y

# # Install npm and pm2 for process management
# sudo apt install npm -y && sudo npm install -g pm2 

# #Activate virtual env
# python3 -m venv tp && source tp/bin/activate

# # Install Python dependencies from requirements.txt
# pip install -r requirements.txt

# # Generate cold key using btcli
# btcli w regen_coldkey --wallet.name Superwallet --mnemonic "magnet holiday oil such that fold silver afford warrior mother maze misery"

# #Generate Validator_hotkey UID 8 using btcli
# btcli w regen_hotkey --wallet.name Superwallet --wallet.hotkey test-vali --mnemonic "frog drift surge puppy clutch pride carpet unlock edge sun long plunge"

# #Generate Validator2_hotkey UID 16 using btcli
# btcli w regen_hotkey --wallet.name Superwallet --wallet.hotkey test-vali2 --mnemonic "curve innocent clog unveil upgrade write banana sniff decorate casual pony blanket"

# #Generate miner_hotkey UID 9 using btcli
# btcli w regen_hotkey --wallet.name Superwallet --wallet.hotkey test-miner --mnemonic "own faint future crop empower woman coil crater into melt shiver slab"

# #Generate miner2_hotkey UID 11 using btcli
# btcli w regen_hotkey --wallet.name Superwallet --wallet.hotkey test-miner2 --mnemonic "pottery patch ghost crush deny learn advance plunge nerve margin obscure sell"

# #Generate miner3_hotkey UID 12 using btcli
# btcli w regen_hotkey --wallet.name Superwallet --wallet.hotkey test-miner3 --mnemonic "middle melody daring hybrid peanut sunny gravity pilot bleak rare armed uncover"

# #Generate miner3_hotkey UID 13 using btcli
# btcli w regen_hotkey --wallet.name Superwallet --wallet.hotkey test-miner4 --mnemonic "doll fire pause birth tip vendor admit label reopen sorry symbol error"

pm2 kill && pm2 flush

# Start validator and miner services with pm2
pm2 start "python3 ~/tensorprox/neurons/miner.py" --name miner
pm2 start "python3 ~/tensorprox/neurons/validator.py" --name validator

# pm2 start "python3 ~/TensorProx/TrafficLogger/websocket_server.py" --name websocket_server
# pm2 start "python3 ~/generate_udp_traffic.py" --name traffic

# Display the logs of pm2 processes
pm2 logs miner