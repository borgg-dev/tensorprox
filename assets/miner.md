# **Miners**

## Compute Requirements

| Resource      | Requirement       |
|---------------|-------------------|
| **VRAM**      | None              |
| **vCPU**      | 8 vCPU            |
| **RAM**       | 8 GB              |
| **Storage**   | 80 GB             |

## Installation

Update system packages and install Python pip

```bash
sudo apt update && sudo apt install python3-pip -y && apt install python3-venv -y
```

Install npm and pm2 for process management

```bash
sudo apt install npm -y && sudo npm install -g pm2 
```

Create and activate virtual environment

```bash
python3 -m venv tp && source tp/bin/activate
```

Clone the repository and install the required pip dependencies

```bash
git clone https://github.com/borgg-dev/tensorprox.git
cd tensorprox
pip install -r requirements.txt
```

## Configuration

Before running a miner, you will need to create a .env.miner environment file. It is necessary for you to provide the following :

```text
NETUID= #[234, X]
SUBTENSOR_NETWORK= #The network name [test, finney, local]
SUBTENSOR_CHAIN_ENDPOINT= #The chain endpoint [test if running on test, finney if running on main, custom endpoint if running on local] 
WALLET_NAME= #Name of your wallet(coldkey) 
MINER_HOTKEY= #Name of your hotkey associated with above wallet
MINER_AXON_PORT= #TCP Port Number. The port must be open
```

## Running

After creating the above environment file, run 

```bash
pm2 start "python3 neurons/miner.py" --name miner
```

Check if the instance is correctly running

```bash
pm2 list 
```

To see logs

```bash
pm2 logs miner
```