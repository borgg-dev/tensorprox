#!/bin/bash
# Module: install and configure nginx for layer 7 rate limiting
# This enables testing of slowloris and HTTP flood attacks
set -euo pipefail

echo "[module 45] Installing nginx for layer 7 protection..."

export DEBIAN_FRONTEND=noninteractive

# Install nginx
apt-get install -y -qq nginx

# Create nginx rate limiting configuration
# This provides protection against:
# - Slowloris (connection limiting)
# - HTTP flood (request rate limiting)

cat > /etc/nginx/conf.d/rate-limiting.conf <<'EONFG'
# ============================================================================
# TensorProx Layer 7 Rate Limiting Configuration
# ============================================================================

# Request rate limiting zone (10 requests/sec per IP)
# Used to detect HTTP flood attacks
limit_req_zone $binary_remote_addr zone=http_flood:10m rate=10r/s;

# Connection limiting zone (10 concurrent connections per IP)
# Used to detect slowloris attacks
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# Log format for rate limiting events
log_format ratelimit '$time_iso8601 $remote_addr $status '
                     '$request_length $bytes_sent '
                     '$limit_req_status $limit_conn_status';
EONFG

# Create the main server configuration for audit testing
# NOTE: Using try_files instead of 'return' because 'return' bypasses rate limiting
cat > /etc/nginx/sites-available/tensorprox-audit <<'EOSITE'
# TensorProx Audit Server - Layer 7 Attack Testing
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name _;

    # Rate limiting (10 req/s base rate, 20 burst allowed)
    limit_req zone=http_flood burst=20;
    limit_conn conn_limit 10;

    # Return 429 when rate limited (instead of 503)
    limit_req_status 429;
    limit_conn_status 429;

    # Log rate limiting events
    access_log /var/log/nginx/ratelimit.log ratelimit;

    # Root location - serve static file (rate limiting works with try_files)
    root /var/www/html;
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Stats endpoint for monitoring (internal only)
    location /nginx_status {
        stub_status on;
        allow 127.0.0.1;
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
    }
}
EOSITE

# Create the default response file
mkdir -p /var/www/html
echo "TensorProx Scrubber OK" > /var/www/html/index.html

# The server config above works with all nginx versions (no lua, no 'off' params)

# Enable the site
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/tensorprox-audit /etc/nginx/sites-enabled/

# Create rate limit log file with proper permissions
touch /var/log/nginx/ratelimit.log
chmod 644 /var/log/nginx/ratelimit.log

# Create a helper script to get rate limit stats
cat > /opt/tensorprox/bin/get-nginx-ratelimit-stats.sh <<'EOSTATS'
#!/bin/bash
# Get nginx rate limiting stats for audit reporting

LOGFILE="/var/log/nginx/ratelimit.log"

# Count 429 responses (rate limited requests)
if [[ -f "$LOGFILE" ]]; then
    BLOCKED=$(grep -c ' 429 ' "$LOGFILE" 2>/dev/null || echo 0)
else
    BLOCKED=0
fi

# Output as JSON
echo "{\"ratelimit_app_blocked\": $BLOCKED}"
EOSTATS
chmod +x /opt/tensorprox/bin/get-nginx-ratelimit-stats.sh

# Create a script to reset rate limit stats (called before each audit)
cat > /opt/tensorprox/bin/reset-nginx-ratelimit-stats.sh <<'EORESET'
#!/bin/bash
# Reset nginx rate limit stats for new audit round
> /var/log/nginx/ratelimit.log
EORESET
chmod +x /opt/tensorprox/bin/reset-nginx-ratelimit-stats.sh

# Test nginx configuration
nginx -t

# Restart nginx to apply configuration
systemctl restart nginx
systemctl enable nginx

echo "[module 45] nginx installed and configured for layer 7 rate limiting"
echo "[module 45] Rate limits: 10 req/s, 10 concurrent connections per IP"
echo "[module 45] Stats available at: /opt/tensorprox/bin/get-nginx-ratelimit-stats.sh"
