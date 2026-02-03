#!/bin/bash
# Miner Control Plane Database Setup Script
# Run this on fresh MINER deployments to initialize the database with correct schema
#
# For VALIDATORS, use: ./database/tpm_db_setup.sh instead
#
# Usage: sudo -E ./database/db_setup.sh
#
# This script:
# 1. Creates the ecp_api user (if not exists)
# 2. Creates the ecp_state database (drops if exists)
# 3. Applies the full schema from schema.sql (shards, nodes, origins for miner)
# 4. Applies any additional migrations not in schema.sql
# 5. Grants proper permissions

set -e

DB_NAME="${DB_NAME:-ecp_state}"
DB_USER="${DB_USER:-ecp_api}"
DB_PASS="${DB_PASS:?ERROR: DB_PASS environment variable must be set}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="${SCRIPT_DIR}/schema.sql"

echo "=== Miner Database Setup ==="
echo "Database: ${DB_NAME}"
echo "User: ${DB_USER}"
echo "Schema: ${SCHEMA_FILE}"
echo ""

# Check if running as root or can sudo to postgres
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (for postgres access)"
    exit 1
fi

# Check schema file exists
if [[ ! -f "${SCHEMA_FILE}" ]]; then
    echo "ERROR: Schema file not found: ${SCHEMA_FILE}"
    exit 1
fi

echo "Step 1: Creating database user (if not exists)..."
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname = '${DB_USER}'" | grep -q 1 ||     sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}'"

echo "Step 2: Terminating existing connections..."
sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();" 2>/dev/null || true

echo "Step 3: Dropping existing database (if exists)..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS ${DB_NAME}"

echo "Step 4: Creating fresh database..."
sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}"

echo "Step 5: Applying schema from schema.sql..."
sudo -u postgres psql -d ${DB_NAME} -f "${SCHEMA_FILE}"

echo "Step 6: Applying additional migrations..."
# These columns/tables may not be in schema.sql but are required
sudo -u postgres psql -d ${DB_NAME} << 'MIGRATIONS'
-- Additional columns not in schema.sql (from alembic migrations)
ALTER TABLE anomaly_detection_config ADD COLUMN IF NOT EXISTS blacklist_spike_level INTEGER;
ALTER TABLE anomaly_detection_config ADD COLUMN IF NOT EXISTS blacklist_spike_threshold REAL;
ALTER TABLE origin_bandwidth_usage ADD COLUMN IF NOT EXISTS bytes_passed BIGINT;
ALTER TABLE origins ADD COLUMN IF NOT EXISTS bogon_baseline BIGINT DEFAULT 0;
ALTER TABLE origins ADD COLUMN IF NOT EXISTS cumulative_bytes_processed BIGINT DEFAULT 0;
ALTER TABLE origins ADD COLUMN IF NOT EXISTS exit_hub_wg_ip VARCHAR(45);
ALTER TABLE shards ADD COLUMN IF NOT EXISTS id SERIAL;

-- Ensure FK constraint for deployment_jobs
ALTER TABLE deployment_jobs DROP CONSTRAINT IF EXISTS fk_deployment_job_shard;
ALTER TABLE deployment_jobs ADD CONSTRAINT fk_deployment_job_shard 
    FOREIGN KEY (shard_id) REFERENCES shards(shard_id) ON DELETE SET NULL;

-- Create missing tables if not in schema.sql
CREATE TABLE IF NOT EXISTS alembic_version (
    version_num VARCHAR(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

CREATE TABLE IF NOT EXISTS egress_billing_metrics (
    id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) NOT NULL REFERENCES origins(origin_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    node_id VARCHAR(50),
    to_origin_packets BIGINT DEFAULT 0,
    to_origin_bytes BIGINT DEFAULT 0,
    to_client_packets BIGINT DEFAULT 0,
    to_client_bytes BIGINT DEFAULT 0,
    total_egress_packets BIGINT DEFAULT 0,
    total_egress_bytes BIGINT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS origin_counter_state (
    origin_id VARCHAR(50) PRIMARY KEY REFERENCES origins(origin_id) ON DELETE CASCADE,
    cumulative_bytes_processed BIGINT DEFAULT 0,
    cumulative_packets_processed BIGINT DEFAULT 0,
    cumulative_egress_bytes BIGINT DEFAULT 0,
    last_bytes_total BIGINT DEFAULT 0,
    last_packets_total BIGINT DEFAULT 0,
    last_egress_bytes BIGINT DEFAULT 0,
    last_reporting_node VARCHAR(50),
    last_counter_update TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
MIGRATIONS

echo "Step 7: Granting permissions..."
sudo -u postgres psql -d ${DB_NAME} -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ${DB_USER}"
sudo -u postgres psql -d ${DB_NAME} -c "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ${DB_USER}"
sudo -u postgres psql -d ${DB_NAME} -c "GRANT USAGE ON SCHEMA public TO ${DB_USER}"

echo ""
echo "=== Database setup complete ==="
echo ""
echo "Verify with: PGPASSWORD=${DB_PASS} psql -U ${DB_USER} -h localhost -d ${DB_NAME} -c '\dt'"
