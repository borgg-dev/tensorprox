# **VALIDATORS**

## Compute Requirements

| Resource      | Requirement       |
|---------------|-------------------|
| **VRAM**      | 62 GB             |
| **vCPU**      | 24 vCPU           |
| **RAM**       | 60 GB             |
| **Storage**   | 150 GB            |

## Installation


```bash
git clone https://github.com/borgg-dev/tensorprox.git
cd tensorprox
pip install -r requirements.txt
```

## Configuration

Before running a validator, you will need to create a .env.validator environment file. It is necessary for you to provide the following 

```text
NETUID= #[234, X]
SUBTENSOR_NETWORK= #The network name [test, main, local]
SUBTENSOR_CHAIN_ENDPOINT= #The chain endpoint [test if running on test, main if running on main, custom endpoint if running on local] 
WALLET_NAME= #Name of your wallet(coldkey) 
VALIDATOR_HOTKEY= #Name of your hotkey associated with above wallet
VALIDATOR_AXON_PORT= #Number of the open tcp port
```

## Running

After creating the above environment file, run 

```bash
pm2 start "python3 neurons/validator.py" --name validator
```

