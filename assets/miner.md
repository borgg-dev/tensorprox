# Running a TensorProx Miner

Miners deploy and operate scrubber infrastructure to provide DDoS protection services on the TensorProx subnet (netuid set via TP_NETUID).

## Requirements

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Ubuntu/Debian | 22.04+ | Recommended OS |
| Python | 3.10 - 3.12 | Runtime |
| PostgreSQL | 14+ | State storage |
| Redis | 7+ | Metrics aggregation |
| WireGuard | Latest | Audit & production tunnels |
| AWS | Account | Scrubber deployment (only provider currently supported) |

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 20 GB SSD | 50+ GB SSD |
| Network | 100 Mbps | 1 Gbps |

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
# Edit Redis config to set a password
sudo nano /etc/redis/redis.conf
# Find and set: requirepass your_redis_password

# Restart Redis
sudo systemctl restart redis-server
sudo systemctl enable redis-server
```

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

# Initialize the miner control plane database
# Set DB_PASS before running (must match TP_DB_PASS in your .env)
export DB_PASS=your_secure_password
sudo -E ./database/db_setup.sh
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

## Configuration

### 1. Create Environment File

```bash
cp .env.miner.example .env.miner
nano .env.miner
```

### 2. Required Environment Variables

These variables **MUST** be set for the miner to function:

#### Bittensor Identity

```bash
# Your Bittensor wallet name
TP_WALLET_NAME=your-wallet

# Your miner hotkey name
TP_WALLET_HOTKEY=your-miner-hotkey

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
TP_AXON_PORT=8091

# Miner control plane API port
TP_MINER_PORT=8000
```

#### PostgreSQL Database

```bash
# Database name for miner state
TP_DB_NAME=ecp_state

# Database credentials
TP_DB_USER=ecp_api
TP_DB_PASS=your_secure_password

# Database connection
TP_DB_HOST=localhost
TP_DB_PORT=5432
```

#### Redis

```bash
# Redis URL with password
TP_REDIS_URL=redis://:your_redis_password@127.0.0.1:6379
```

#### Scrubber Configuration

```bash
# Cloud provider for scrubber deployment.
# Currently only "aws" is supported. Additional providers planned for future releases.
TP_SCRUBBER_PROVIDER=aws

# AWS region for scrubber deployment
# Examples: us-east-1, us-west-2, eu-central-1, ap-northeast-1
TP_SCRUBBER_REGION=us-east-1

# AWS instance type
# Minimum: t3.medium | Recommended: t3.large | Production: c5.large
TP_SCRUBBER_INSTANCE_TYPE=t3.medium
```

#### SSH Key

```bash
# Path to SSH private key for scrubber access
TP_SSH_KEY_PATH=~/.ssh/your-key.pem
```

### 3. AWS Credentials

AWS credentials are required for scrubber deployment:

```bash
# AWS IAM credentials with EC2 permissions
TP_AWS_ACCESS_KEY_ID=AKIA...
TP_AWS_SECRET_ACCESS_KEY=your_secret_key

# AWS region (should match TP_SCRUBBER_REGION)
TP_AWS_REGION=us-east-1

# SSH key name (must exist in AWS in the specified region)
TP_AWS_SSH_KEY_NAME=your-ssh-key-name
```

### 4. Optional Environment Variables

These are optional and have sensible defaults:

#### Advanced AWS Configuration

```bash
# Use specific VPC (optional, auto-created if not specified)
TP_AWS_VPC_ID=vpc-xxx

# Use specific subnet
TP_AWS_SUBNET_ID=subnet-xxx

# Use specific security group
TP_AWS_SECURITY_GROUP_ID=sg-xxx

# EIP quota per region (request increase from AWS if needed)
TP_AWS_EIP_QUOTA_PER_REGION=5
```

### 5. Complete Example

Here's a minimal working configuration for AWS:

```bash
# === BITTENSOR ===
TP_WALLET_NAME=miner
TP_WALLET_HOTKEY=default
TP_WALLET_PATH=~/.bittensor/wallets
TP_SUBTENSOR_NETWORK=finney
TP_NETUID=<netuid>

# === PORTS ===
TP_AXON_PORT=8091
TP_MINER_PORT=8000

# === DATABASE ===
TP_DB_NAME=ecp_state
TP_DB_USER=ecp_api
TP_DB_PASS=secure_password_here
TP_DB_HOST=localhost
TP_DB_PORT=5432

# === REDIS ===
TP_REDIS_URL=redis://:redis_password@127.0.0.1:6379

# === SCRUBBER ===
TP_SCRUBBER_PROVIDER=aws
TP_SCRUBBER_REGION=us-east-1
TP_SCRUBBER_INSTANCE_TYPE=t3.medium

# === AWS ===
TP_AWS_ACCESS_KEY_ID=AKIA...
TP_AWS_SECRET_ACCESS_KEY=your_secret
TP_AWS_REGION=us-east-1
TP_AWS_SSH_KEY_NAME=tensorprox-key

# === SSH ===
TP_SSH_KEY_PATH=~/.ssh/tensorprox-key.pem
```

## Running the Miner

### 1. Start the Miner

```bash
source .venv/bin/activate

pm2 start .venv/bin/python \
  --name miner \
  --interpreter none \
  -- -m neurons.miner \
  --env-file .env.miner \
  --wallet.name miner \
  --wallet.hotkey default \
  --subtensor.network finney \
  --netuid <netuid>

# Save for auto-restart
pm2 save
pm2 startup
```

### Stopping the Miner

```bash
pm2 stop tensorprox-miner
```

### Restarting the Miner

```bash
pm2 restart tensorprox-miner
```

### Viewing Logs

```bash
pm2 logs tensorprox-miner
```

### 2. Verify It's Running

```bash
# Check PM2 status
pm2 status

# View logs
pm2 logs miner

# Check axon is responding
curl http://localhost:8091/ping

# Check miner control plane
curl http://localhost:8000/health
```

### 3. Verify Scrubber Deployment

On first run, the miner will deploy a scrubber. Check the logs:

```bash
pm2 logs miner --lines 200 | grep -i scrubber
```

You should see:
- "Deploying scrubber..."
- "Scrubber deployed: scrubber-001 (IP_ADDRESS)"
- "XDP program loaded"

## Firewall Configuration

Ensure these ports are accessible:

| Port | Protocol | Purpose | Access |
|------|----------|---------|--------|
| 8091 | TCP | Axon (Bittensor) | Public |
| 8000 | TCP | Miner Control Plane | Validators only |
| 51820+ | UDP | WireGuard tunnels | Public |

## Monitoring

### View Your Scores

Check your audit scores at: https://wandb.ai/shugo-labs/tensorprox

### Key Metrics

- **Audit Score**: Per-audit accuracy (target: > 0.9)
- **EMA Score**: Determines weight and origin assignment eligibility (need > 0.8)
- **Volume**: Bytes processed (tracked for monitoring; rewards are currently audit-based only)

### Check Scrubber Health

```bash
# SSH to scrubber
ssh -i ~/.ssh/your-key.pem ubuntu@SCRUBBER_IP

# Check XDP is loaded
sudo bpftool prog list | grep xdp

# Check BPF maps
sudo bpftool map list
```

## Updating to a New Version

```bash
cd ~/tensorprox
git pull origin main
source .venv/bin/activate
pip install -r requirements.txt
pm2 restart tensorprox-miner
```

## Troubleshooting

### Miner not receiving audits

1. Check registration:
   ```bash
   btcli wallet overview --wallet.name miner
   ```

2. Verify axon is serving:
   ```bash
   curl http://localhost:8091/ping
   ```

3. Check scrubber is healthy:
   ```bash
   pm2 logs miner | grep -i "health\|scrubber"
   ```

### Low audit scores

1. Verify XDP program is loaded on scrubber:
   ```bash
   ssh ubuntu@SCRUBBER_IP "sudo bpftool prog list"
   ```

2. Check BPF maps are populated:
   ```bash
   ssh ubuntu@SCRUBBER_IP "sudo bpftool map show"
   ```

3. Review miner logs for specific attack categories failing

### Scrubber deployment failures

1. Verify AWS credentials:
   ```bash
   aws sts get-caller-identity
   ```

2. Check vCPU limits in your region:
   ```bash
   aws service-quotas get-service-quota \
     --service-code ec2 \
     --quota-code L-1216C47A
   ```

3. Ensure SSH key exists:
   ```bash
   aws ec2 describe-key-pairs --key-names your-key-name
   ```

4. Check security group allows SSH (port 22) and WireGuard (51820)

### WireGuard tunnel failures

1. Check WireGuard on scrubber:
   ```bash
   ssh ubuntu@SCRUBBER_IP "sudo wg show"
   ```

2. Verify UDP port 51820 is open

3. Check miner logs for tunnel setup errors

## Costs

### AWS Estimated Costs (per scrubber)

| Resource | Monthly Cost |
|----------|--------------|
| t3.medium instance | ~$30 |
| Elastic IP | ~$3.65 |
| Data transfer | Variable |
| **Total** | ~$35+ |

## Security Best Practices

1. **Never commit** `.env` files or wallet keys to git
2. **Use IAM roles** with minimal EC2 permissions
3. **Rotate** AWS credentials periodically
4. **Monitor** cloud costs to detect anomalies
5. **Use separate regions** for each miner to avoid rate limits
