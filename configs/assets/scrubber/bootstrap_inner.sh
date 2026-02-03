#!/bin/bash
# Scrubber bootstrap orchestrator for the WireGuard dataplane
set -euo pipefail

exec > >(tee -a /var/log/scrubber-bootstrap.log)
exec 2>&1

echo "========================================="
echo "Scrubber Bootstrap (modular) - $(date)"
echo "========================================="

# Wait for outbound connectivity
while ! ping -c 1 8.8.8.8 >/dev/null 2>&1; do
    sleep 2
done

# Export critical environment variables so modules can access them
# These are passed from the miner via: sudo env EMN_IP=... bash bootstrap_inner.sh
export EMN_IP="${EMN_IP:-}"
export EMN_PORT="${EMN_PORT:-8000}"
export INSTANCE_ID="${INSTANCE_ID:-}"

echo "Environment: EMN_IP=${EMN_IP}, EMN_PORT=${EMN_PORT}, INSTANCE_ID=${INSTANCE_ID}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRUBBER_ROOT="$SCRIPT_DIR"

MODULE_DIR="${SCRIPT_DIR}/modules"

if [[ ! -d "$MODULE_DIR" ]]; then
    echo "Module directory missing: $MODULE_DIR" >&2
    exit 1
fi

run_module() {
    local module_path="$1"
    local module_name
    module_name="$(basename "$module_path")"
    echo ">>> Running module ${module_name}"
    bash "$module_path"
    echo ">>> Module ${module_name} complete"
}

mapfile -t MODULES < <(find "$MODULE_DIR" -maxdepth 1 -type f -name "*.sh" | sort)

if [[ "${#MODULES[@]}" -eq 0 ]]; then
    echo "No modules found in ${MODULE_DIR}" >&2
    exit 1
fi

for module in "${MODULES[@]}"; do
    run_module "$module"
done

# Attach XDP at end of bootstrap (as root, no sudo needed)
# This MUST happen after all modules (especially 35-xdp.sh which builds the BPF program)
echo "========================================="
echo "Attaching XDP (during bootstrap as root)..."
if [[ -n "$EMN_IP" ]]; then
    # Save miner IP for later use (scripts expect it at /opt/tensorprox/)
    mkdir -p /opt/tensorprox
    echo "$EMN_IP" > /opt/tensorprox/miner_ip
    # Attach XDP with miner IP whitelist
    # Script is in bootstrap dir (${SCRIPT_DIR}/scripts/)
    "${SCRIPT_DIR}/scripts/attach-xdp.sh" "$EMN_IP" 2>&1 || {
        echo "ERROR: XDP attach failed!" >&2
        exit 1
    }
    echo "XDP attached successfully with miner $EMN_IP whitelisted"
else
    echo "WARNING: EMN_IP not set, skipping XDP attach (will need manual attach)"
fi
echo "========================================="
echo "✅ Bootstrap Complete"
echo "========================================="
