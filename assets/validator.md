# Running a TensorProx Validator

Validators audit miner performance and set on-chain weights to distribute ALPHA rewards on the TensorProx subnet (netuid set via TP_NETUID).

## Requirements

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Ubuntu/Debian | 22.04+ | Recommended OS |
| Python | 3.10 - 3.12 | Runtime |
| PostgreSQL | 14+ | State storage |
| Redis | 7+ | Real-time messaging |
| WireGuard | Latest | Audit tunnels |
| libcap2-bin | Latest | Network capabilities |
| AWS Account | - | Exit hub deployment |

## Installation

### 1. Install System Dependencies

```bash
# Update package lists
sudo apt update && sudo apt upgrade -y

# Install Python
sudo apt install -y python3 python3-pip python3-venv

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Install Redis
sudo apt install -y redis-server

# Install WireGuard
sudo apt install -y wireguard wireguard-tools

# Install libcap for network capabilities (required for audit packets)
sudo apt install -y libcap2-bin

# Install PM2 for process management (recommended)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
sudo npm install -g pm2
```

> **Note:** If pip fails to install packages, you may need build dependencies:
> `sudo apt install -y python3-dev build-essential libffi-dev libssl-dev`

### 2. Configure PostgreSQL

```bash
# Start PostgreSQL
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Set postgres user password (needed for db_setup.sh)
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'your_postgres_password';"
```

### 3. Configure Redis

```bash
# Edit Redis config to set a password and allow external connections
sudo nano /etc/redis/redis.conf
# Find and set:
#   requirepass your_redis_password
#   bind 0.0.0.0
#   protected-mode no

# Restart Redis
sudo systemctl restart redis-server
sudo systemctl enable redis-server
```

> **Security Note:** After setup, restrict Redis access using firewall rules (e.g., `ufw allow from <exit_hub_ip> to any port 6379`) rather than leaving it fully open. Only your exit hub IPs need Redis access.

### 4. Clone and Install TensorProx

```bash
# Clone the repository
git clone https://github.com/shugo-labs/tensorprox.git
cd tensorprox

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -e .

# Initialize the TPM database
# Set TP_DB_PASS before running (must match TP_DB_PASS in your .env)
export TP_DB_PASS=your_secure_password
sudo -E ./database/tpm_db_setup.sh
```

## Bittensor Wallet Setup

If you don't have a Bittensor wallet yet:

```bash
# Install btcli
pip install bittensor-cli

# Create a new coldkey
btcli wallet new_coldkey --wallet.name <your_wallet_name>

# Create a new hotkey
btcli wallet new_hotkey --wallet.name <your_wallet_name> --wallet.hotkey <your_hotkey_name>

# Register on the subnet (mainnet)
btcli subnet register --wallet.name <your_wallet_name> --wallet.hotkey <your_hotkey_name> --netuid <netuid>
```

> **Note:** Registration requires TAO. Check current registration costs with `btcli subnet list`.

> **Validators** require a minimum stake to set weights. Ensure your coldkey has sufficient TAO staked to your hotkey.

## Configuration

### 1. Create Environment File

```bash
cp .env.validator.example .env.validator
nano .env.validator
```

### 2. Required Environment Variables

These variables **MUST** be set for the validator to function:

#### Bittensor Identity

```bash
# Your Bittensor wallet name
TP_WALLET_NAME=your-wallet

# Your validator hotkey name
TP_WALLET_HOTKEY=your-validator-hotkey

# Path to wallets directory
TP_WALLET_PATH=~/.bittensor/wallets

# Network: "finney" for mainnet, "test" for testnet
TP_SUBTENSOR_NETWORK=finney

# Subnet UID (set to your subnet's netuid)
TP_NETUID=<netuid>
```

#### Network Ports

```bash
# Axon port for Bittensor communication
TP_AXON_PORT=8191

# TPM-Lite API port (internal management service)
TP_TPM_PORT=5001
```

#### PostgreSQL Database

```bash
# Database name for validator state
TP_DB_NAME=tp_state

# Database credentials
TP_DB_USER=tp_api
TP_DB_PASS=your_secure_password

# Database connection
TP_DB_HOST=localhost
TP_DB_PORT=5432
```

#### Redis

```bash
# Redis URL with password
TP_REDIS_URL=redis://:your_redis_password@127.0.0.1:6379

# Redis password (separate for some services)
TP_REDIS_PASSWORD=your_redis_password

# External Redis access for exit hubs to connect back
# This should be your validator's PUBLIC IP address
TP_REDIS_EXTERNAL_HOST=your.public.ip.address
TP_REDIS_EXTERNAL_PORT=6379
```

#### AWS Credentials (for Exit Hub Deployment)

Exit hubs are deployed by validators to route clean traffic to origins.

```bash
# AWS IAM credentials with EC2 permissions
TP_AWS_ACCESS_KEY_ID=AKIA...
TP_AWS_SECRET_ACCESS_KEY=your_secret_key

# AWS region for exit hub deployment
TP_AWS_REGION=us-east-1

# SSH key name (must exist in AWS)
TP_AWS_SSH_KEY_NAME=your-ssh-key-name
```

#### SSH Key

```bash
# Path to SSH private key (matching AWS key)
TP_SSH_KEY_PATH=~/.ssh/your-key.pem
```

#### TPM Configuration

```bash
# Public URL where miners can reach your TPM
# Use your public IP or domain
TPM_PUBLIC_URL=http://your.public.ip:5001

# Internal secret for TPM authentication
# Generate with: openssl rand -hex 32
TPM_INTERNAL_SECRET=your_random_secret_string
```

### 3. Recommended Environment Variables

These improve functionality but have sensible defaults:

#### MaxMind GeoIP (for Distance-Based Latency Scoring)

Without this, latency normalization uses fallback values.

```bash
# Get free license at: https://www.maxmind.com/en/geolite2/signup
TPM_MAXMIND_LICENSE_KEY=your_maxmind_license_key

# Path where GeoLite2 database will be stored
TPM_GEOLITE2_DB_PATH=~/.tensorprox/GeoLite2-City.mmdb
```

#### Weights & Biases (Public Audit Dashboard)

Miners can view their scores at https://wandb.ai/shugo-labs/tensorprox

```bash
# Enable W&B reporting
TP_WANDB_ENABLED=true

# W&B project and entity
TP_WANDB_PROJECT=tensorprox
TP_WANDB_ENTITY=shugo-labs

# Your W&B API key
TP_WANDB_API_KEY=your_wandb_api_key
```

### 4. Web App Backend

Validators report independently to the TensorProx web application for origin sync, metrics forwarding, and heartbeats.

```bash
# Single URL for all webapp communication (origin sync, metrics, heartbeats)
TP_WEBAPP_URL=https://api.tensorprox.io

# Shared secret matching webapp's TPM_INTERNAL_SECRET
TP_WEBAPP_API_KEY=your_webapp_api_key
```

### 5. TP Data - Centralized Metrics

Validators report metrics to a centralized database for the TensorProx dashboard. Shugo Labs will provide these credentials during onboarding:

```bash
# Akamai/Linode managed PostgreSQL
TP_DATA_DB_HOST=lin-xxxxx-xxxxx-pgsql-primary.servers.linodedb.net
TP_DATA_DB_PORT=5432
TP_DATA_DB_NAME=tp_data
TP_DATA_DB_USER=tp_validator
TP_DATA_DB_PASSWORD=provided_password
TP_DATA_DB_SSLMODE=require
TP_DATA_DB_SSLROOTCERT=/path/to/linode-ca-certificate.crt
```

### 6. Linode (Optional)

If using Linode for exit hub deployment instead of (or in addition to) AWS:

```bash
LINODE_TOKEN=your-linode-personal-access-token
```

### 7. Complete Example

Here's a minimal working configuration:

```bash
# === BITTENSOR ===
TP_WALLET_NAME=validator
TP_WALLET_HOTKEY=default
TP_WALLET_PATH=~/.bittensor/wallets
TP_SUBTENSOR_NETWORK=finney
TP_NETUID=<netuid>

# === PORTS ===
TP_AXON_PORT=8191
TP_TPM_PORT=5001

# === DATABASE ===
TP_DB_NAME=tp_state
TP_DB_USER=tp_api
TP_DB_PASS=secure_password_here
TP_DB_HOST=localhost
TP_DB_PORT=5432

# === REDIS ===
TP_REDIS_URL=redis://:redis_password@127.0.0.1:6379
TP_REDIS_PASSWORD=redis_password
TP_REDIS_EXTERNAL_HOST=203.0.113.50
TP_REDIS_EXTERNAL_PORT=6379

# === TPM ===
TPM_PUBLIC_URL=http://203.0.113.50:5001
TPM_INTERNAL_SECRET=generate_with_openssl_rand_hex_32

# === AWS ===
TP_AWS_ACCESS_KEY_ID=AKIA...
TP_AWS_SECRET_ACCESS_KEY=your_secret
TP_AWS_REGION=us-east-1
TP_AWS_SSH_KEY_NAME=tensorprox-key

# === SSH ===
TP_SSH_KEY_PATH=~/.ssh/tensorprox-key.pem

# === GEOIP ===
TPM_MAXMIND_LICENSE_KEY=your_key
TPM_GEOLITE2_DB_PATH=~/.tensorprox/GeoLite2-City.mmdb

# === WANDB ===
TP_WANDB_ENABLED=true
TP_WANDB_PROJECT=tensorprox
TP_WANDB_ENTITY=shugo-labs
TP_WANDB_API_KEY=your_wandb_key

# === WEB APP BACKEND ===
TP_WEBAPP_URL=https://api.tensorprox.io
TP_WEBAPP_API_KEY=your_webapp_api_key

# === TP DATA (Time-Series Metrics - credentials provided by Shugo Labs) ===
TP_DATA_DB_HOST=lin-xxxxx-xxxxx-pgsql-primary.servers.linodedb.net
TP_DATA_DB_PORT=5432
TP_DATA_DB_NAME=tp_data
TP_DATA_DB_USER=tp_validator
TP_DATA_DB_PASSWORD=provided_password
TP_DATA_DB_SSLMODE=require
TP_DATA_DB_SSLROOTCERT=~/.tensorprox/linode-ca-certificate.crt
```

## Running the Validator

### 1. Setup Network Capabilities

Validators need `CAP_NET_RAW` for sending audit packets:

```bash
sudo ./scripts/setup-validator-caps.sh
```

### 2. Start the Validator

```bash
source .venv/bin/activate

pm2 start .venv/bin/python \
  --name validator \
  --interpreter none \
  -- -m neurons.validator \
  --env-file .env.validator \
  --wallet.name validator \
  --wallet.hotkey default \
  --subtensor.network finney \
  --netuid <netuid> \
  --tpm-port 5001

# Save for auto-restart
pm2 save
pm2 startup
```

### Stopping the Validator

```bash
pm2 stop tensorprox-validator
```

### Restarting the Validator

```bash
pm2 restart tensorprox-validator
```

### Viewing Logs

```bash
pm2 logs tensorprox-validator
```

### 3. Verify It's Running

```bash
# Check PM2 status
pm2 status

# View logs
pm2 logs validator

# Check TPM is responding
curl http://localhost:5001/health
```

## Firewall Configuration

Ensure these ports are accessible:

| Port | Protocol | Purpose | Access |
|------|----------|---------|--------|
| 8191 | TCP | Axon (Bittensor) | Public |
| 5001 | TCP | TPM API | Public (for miners) |
| 6379 | TCP | Redis | Public (for exit hubs) |
| 51820+ | UDP | WireGuard tunnels | Public |

## Monitoring

### Weights & Biases Dashboard

View audit scores and miner performance:
https://wandb.ai/shugo-labs/tensorprox

### Key Metrics to Watch

- **Audit Score**: Per-audit accuracy (target: > 0.9)
- **EMA Score**: Smoothed performance over time
- **Weight Updates**: Successful on-chain submissions
- **TPM Health**: Exit hub deployments, miner assignments

## Updating to a New Version

```bash
cd ~/tensorprox
git pull origin main
source .venv/bin/activate
pip install -r requirements.txt
pm2 restart tensorprox-validator
```

## Troubleshooting

### Validator not setting weights

1. Check stake: `btcli wallet overview --wallet.name validator`
2. Verify CAP_NET_RAW: `getcap .venv/bin/python3`
3. Check logs: `pm2 logs validator --lines 100`

### Audit failures

1. Check WireGuard: `sudo wg show`
2. Verify miner connectivity: Check TPM logs for tunnel errors
3. Review audit logs for specific errors

### Exit hub deployment failures

1. Verify AWS credentials: `aws sts get-caller-identity`
2. Check EC2 limits in your region
3. Ensure SSH key exists in AWS

### GeoIP not working

1. Download GeoLite2: Register at MaxMind and download the database
2. Verify path: `ls -la ~/.tensorprox/GeoLite2-City.mmdb`
3. Check license key is valid

## Security Best Practices

1. **Never commit** `.env` files or wallet keys to git
2. **Use strong passwords** for PostgreSQL and Redis
3. **Firewall** Redis to only allow exit hub IPs
4. **Rotate** TPM_INTERNAL_SECRET periodically
5. **Monitor** AWS costs for exit hub instances
