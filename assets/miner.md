# **Miners**

## Compute Requirements

| Resource      | Requirement       |
|---------------|-------------------|
| **VRAM**      | None              |
| **vCPU**      | 8 vCPU            |
| **RAM**       | 8 GB              |
| **Storage**   | 80 GB             |

## Installation

```bash
git clone https://github.com/borgg-dev/tensorprox.git
cd tensorprox
pip install -r requirements.txt
```

## Configuration

Before running a miner, you will need to create a .env.miner environment file. It is necessary for you to provide the following 

```text
NETUID= #[234, X]
SUBTENSOR_NETWORK= #The network name [test, main, local]
SUBTENSOR_CHAIN_ENDPOINT= #The chain endpoint [test if running on test, main if running on main, custom endpoint if running on local] 
WALLET_NAME= #Name of your wallet(coldkey) 
MINER_HOTKEY= #Name of your hotkey associated with above wallet
MINER_AXON_PORT= #Number of the open tcp port
```
## Testnet - RECOMMENDED
We highly recommend that you run your miners on testnet before deploying on main. This is give you an opportunity to debug your systems, and ensure that you will not lose valuable immunity time. The SNX testnet is **netuid 234**.

In order to run on testnet, you will need to go through the same hotkey registration proceure as on main, but using **testtao**. You will need to ask for some in the community discord if you do not have any.

Then, simply set test=True in your .env file and execute all other steps as before.

Then post in the Subnet 1 channel on discord so we can activate a validator for your miner to respond to.

You can use wandb to see how successful your miner would be on mainnet, an example notebook is pinned in the channel.

## Running

After creating the above environment file, run 

```bash
pm2 start "python3 neurons/miner.py" --name miner
```