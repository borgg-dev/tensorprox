#!/bin/bash
# TPM Database Setup Script for Validator
# Run this on fresh validator deployments to initialize the TPM database
#
# Usage: sudo -E ./database/tpm_db_setup.sh
#
# This script:
# 1. Creates the tp_api user (if not exists)
# 2. Creates the tp_state database (drops if exists)
# 3. Applies the TPM schema from subnet_schema.sql
# 4. Grants proper permissions

set -e

DB_NAME="${TP_DB_NAME:-tp_state}"
DB_USER="${TP_DB_USER:-tp_api}"
DB_PASS="${TP_DB_PASS:?ERROR: TP_DB_PASS environment variable must be set}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="${SCRIPT_DIR}/../tensorprox/tpm/database/subnet_schema.sql"

echo "=== TPM (Validator) Database Setup ==="
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
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname = '${DB_USER}'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}'"

echo "Step 2: Terminating existing connections..."
sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();" 2>/dev/null || true

echo "Step 3: Dropping existing database (if exists)..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS ${DB_NAME}"

echo "Step 4: Creating fresh database..."
sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}"

echo "Step 5: Applying TPM schema from subnet_schema.sql..."
sudo -u postgres psql -d ${DB_NAME} -f "${SCHEMA_FILE}"

echo "Step 6: Granting permissions..."
sudo -u postgres psql -d ${DB_NAME} -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ${DB_USER}"
sudo -u postgres psql -d ${DB_NAME} -c "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ${DB_USER}"
sudo -u postgres psql -d ${DB_NAME} -c "GRANT USAGE ON SCHEMA public TO ${DB_USER}"
sudo -u postgres psql -d ${DB_NAME} -c "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ${DB_USER}"

echo ""
echo "=== TPM Database setup complete ==="
echo ""
echo "Verify with: PGPASSWORD=${DB_PASS} psql -U ${DB_USER} -h localhost -d ${DB_NAME} -c '\dt'"
