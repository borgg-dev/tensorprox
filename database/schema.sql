-- TensorProx MVP Database Schema
-- PostgreSQL 14+
-- Per dev-plan.md Section 10.5

-- Shards table (multi-region support)
-- Each shard represents an HA pair (active + standby) in a specific AWS region
-- shard_type: 'audit' = used for validator scoring, 'production' = used for customer origins
CREATE TABLE IF NOT EXISTS shards (
    shard_id VARCHAR(50) PRIMARY KEY,
    region VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'deploying',
    shard_type VARCHAR(20) DEFAULT 'audit',  -- 'audit' or 'production'
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    miner_id UUID  -- Multi-miner isolation: each miner owns its shards
);

-- Ensure exactly one audit shard per miner (enforced at application level, index for queries)
CREATE INDEX IF NOT EXISTS idx_shards_miner_type ON shards(miner_id, shard_type);

CREATE INDEX IF NOT EXISTS idx_shards_region ON shards(region);
CREATE INDEX IF NOT EXISTS idx_shards_miner_id ON shards(miner_id);
CREATE INDEX IF NOT EXISTS idx_shards_miner_region ON shards(miner_id, region);

COMMENT ON TABLE shards IS 'Multi-region shards - each shard is an HA pair in one AWS region';
COMMENT ON COLUMN shards.region IS 'AWS region (e.g., eu-central-1, us-east-1)';

-- Nodes table (scrubber instances)
-- Each node belongs to a shard and operates in the shard's region
CREATE TABLE IF NOT EXISTS nodes (
    node_id VARCHAR(50) PRIMARY KEY,
    shard_id VARCHAR(50) REFERENCES shards(shard_id) ON DELETE CASCADE,
    region VARCHAR(50) NOT NULL,
    role VARCHAR(20) DEFAULT 'standby',  -- 'active' or 'standby'
    instance_name VARCHAR(50),
    hostname VARCHAR(100),
    provider VARCHAR(20),
    az VARCHAR(50),
    status VARCHAR(20),
    current_public_ip VARCHAR(45),
    current_public_ip_updated_at TIMESTAMP,
    last_seen TIMESTAMP,
    conntrack_max INTEGER DEFAULT 262144,
    instance_type VARCHAR(50),           -- e.g., 't3.medium', 'c5.large'
    bandwidth_bps BIGINT DEFAULT 0,      -- Baseline bandwidth from AWS API (bits/sec)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    miner_id UUID  -- Multi-miner isolation: inherited from parent shard
);

CREATE INDEX IF NOT EXISTS idx_nodes_shard ON nodes(shard_id);
CREATE INDEX IF NOT EXISTS idx_nodes_region ON nodes(region);
CREATE INDEX IF NOT EXISTS idx_nodes_miner_id ON nodes(miner_id);
CREATE INDEX IF NOT EXISTS idx_nodes_miner_shard ON nodes(miner_id, shard_id);

COMMENT ON TABLE nodes IS 'Scrubber instances - each belongs to a shard in a specific region';
COMMENT ON COLUMN nodes.shard_id IS 'The shard this node belongs to';
COMMENT ON COLUMN nodes.role IS 'Current role: active (handles traffic) or standby (hot spare)';

-- ENIs table (network interfaces per node)
CREATE TABLE IF NOT EXISTS enis (
    eni_id VARCHAR(50) PRIMARY KEY,
    node_id VARCHAR(50) REFERENCES nodes(node_id) ON DELETE CASCADE,
    region VARCHAR(50) NOT NULL,
    subnet_id VARCHAR(50),
    az VARCHAR(50),
    primary_private_ip INET,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_enis_region ON enis(region);

COMMENT ON COLUMN enis.region IS 'AWS region where ENI is provisioned';

-- Origins table (protected services)
-- Each origin is assigned to a shard for multi-region support
CREATE TABLE IF NOT EXISTS origins (
    origin_id VARCHAR(50) PRIMARY KEY,
    shard_id VARCHAR(50) NOT NULL REFERENCES shards(shard_id) ON DELETE CASCADE,
    origin_num INTEGER UNIQUE NOT NULL,
    eip VARCHAR(45) NOT NULL,
    eip_alloc_id VARCHAR(100) NOT NULL,
    private_ip VARCHAR(45) NOT NULL,
    private_ip_standby VARCHAR(45) NOT NULL,
    origin_ip VARCHAR(45) NOT NULL,
    exit_hub_ip VARCHAR(45) NOT NULL,
    exit_hub_id VARCHAR(100),
    shared_secret VARCHAR(100),
    required_ports JSONB DEFAULT '{"tcp": [], "udp": []}'::jsonb,
    wg_interface VARCHAR(50) NOT NULL,
    wg_port INTEGER NOT NULL,
    edge_priv_key TEXT NOT NULL,
    edge_pub_key TEXT NOT NULL,
    hub_priv_key TEXT NOT NULL,
    hub_pub_key TEXT NOT NULL,
    state VARCHAR(50) NOT NULL DEFAULT 'NEW',
    policy_bits INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    miner_id UUID  -- Multi-miner isolation: inherited from parent shard
);

CREATE INDEX IF NOT EXISTS idx_origins_eip ON origins(eip);
CREATE INDEX IF NOT EXISTS idx_origins_state ON origins(state);
CREATE INDEX IF NOT EXISTS idx_origins_shard ON origins(shard_id);
CREATE INDEX IF NOT EXISTS idx_origins_miner_id ON origins(miner_id);
CREATE INDEX IF NOT EXISTS idx_origins_miner_shard ON origins(miner_id, shard_id);
CREATE INDEX IF NOT EXISTS idx_origins_miner_state ON origins(miner_id, state);

COMMENT ON COLUMN origins.shard_id IS 'Shard handling this origin (determines region and scrubber nodes)';

-- Add last_bpf_values column for lifetime counter tracking
ALTER TABLE origins ADD COLUMN IF NOT EXISTS last_bpf_values JSONB DEFAULT '{}';

COMMENT ON COLUMN origins.last_bpf_values IS 'Last-seen BPF counter values for delta calculation - enables lifetime tracking across failovers';

-- Add bogon baseline tracking for per-origin bogon packet calculation
ALTER TABLE origins ADD COLUMN IF NOT EXISTS bogon_baseline BIGINT DEFAULT 0;

COMMENT ON COLUMN origins.bogon_baseline IS 'Global bogon counter at origin creation - enables per-origin bogon calculation';

-- Add cumulative bytes processed for billing/stats
ALTER TABLE origins ADD COLUMN IF NOT EXISTS cumulative_bytes_processed BIGINT DEFAULT 0;

-- Add exit hub WireGuard IP for tunnel configuration
ALTER TABLE origins ADD COLUMN IF NOT EXISTS exit_hub_wg_ip VARCHAR(45);

-- EIPs table (Elastic IPs are region-specific)
CREATE TABLE IF NOT EXISTS eips (
    eip_allocation_id VARCHAR(100) PRIMARY KEY,
    public_ip VARCHAR(45) UNIQUE NOT NULL,
    region VARCHAR(50) NOT NULL,
    provider_owner_account VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_eips_region ON eips(region);

COMMENT ON COLUMN eips.region IS 'AWS region where EIP is allocated';

-- Identities table (Origin to Node mapping)
CREATE TABLE IF NOT EXISTS identities (
    origin_id VARCHAR(50) UNIQUE NOT NULL REFERENCES origins(origin_id) ON DELETE CASCADE,
    eip_allocation_id VARCHAR(100) REFERENCES eips(eip_allocation_id),
    private_ip INET NOT NULL,
    private_ip_standby INET NOT NULL,
    eni_id VARCHAR(50),
    node_id VARCHAR(50),
    mark_id INTEGER UNIQUE NOT NULL,
    in_service BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (origin_id)
);

-- Tunnels table (WireGuard configs)
CREATE TABLE IF NOT EXISTS tunnels (
    origin_id VARCHAR(50) PRIMARY KEY REFERENCES origins(origin_id) ON DELETE CASCADE,
    wg_ifname VARCHAR(50) NOT NULL,
    local_pubkey TEXT NOT NULL,
    peer_pubkey TEXT NOT NULL,
    endpoint VARCHAR(100) NOT NULL,
    allowed_ips TEXT,
    mtu INTEGER DEFAULT 1420,
    keepalive INTEGER DEFAULT 15,
    mode VARCHAR(20) DEFAULT 'snat',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Health Origin table
CREATE TABLE IF NOT EXISTS health_origin (
    origin_id VARCHAR(50) PRIMARY KEY REFERENCES origins(origin_id) ON DELETE CASCADE,
    last_icmp_ok BOOLEAN,
    last_tcp_ok BOOLEAN,
    last_udp_ok BOOLEAN,
    last_probe_ts TIMESTAMP,
    notes TEXT
);

-- Health Node table
CREATE TABLE IF NOT EXISTS health_node (
    node_id VARCHAR(50) PRIMARY KEY,
    bpf_loaded BOOLEAN DEFAULT false,
    cpu_pct NUMERIC,
    memory_pct NUMERIC,
    conntrack_count INTEGER,
    interface_rx_bytes BIGINT,
    interface_tx_bytes BIGINT,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);

-- Layer 3 rate limit statistics from ecp-agent
CREATE TABLE IF NOT EXISTS ratelimit_stats (
    id SERIAL PRIMARY KEY,
    node_id VARCHAR(50) NOT NULL,
    ip_address INET NOT NULL,
    blocked_count BIGINT NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ratelimit_stats_node ON ratelimit_stats(node_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ratelimit_stats_ip ON ratelimit_stats(ip_address, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ratelimit_stats_timestamp ON ratelimit_stats(timestamp);

COMMENT ON TABLE ratelimit_stats IS 'Layer 3: Rate limit blocking statistics (7-day retention)';
COMMENT ON COLUMN ratelimit_stats.blocked_count IS 'Number of times this IP was rate-limited';

-- Shard State table (per-shard active/standby tracking)
-- Replaces global single-row shard_state with per-shard state
CREATE TABLE IF NOT EXISTS shard_state (
    shard_id VARCHAR(50) PRIMARY KEY REFERENCES shards(shard_id) ON DELETE CASCADE,
    active_node VARCHAR(50) REFERENCES nodes(node_id),
    standby_node VARCHAR(50) REFERENCES nodes(node_id),
    last_failover TIMESTAMP,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE shard_state IS 'Per-shard active/standby node tracking for independent failover';
COMMENT ON COLUMN shard_state.active_node IS 'Node currently handling traffic for this shard';
COMMENT ON COLUMN shard_state.standby_node IS 'Hot standby node ready for failover';

-- Operations Journal table
CREATE TABLE IF NOT EXISTS operations_journal (
    op_id SERIAL PRIMARY KEY,
    op_type VARCHAR(50) NOT NULL,
    origin_id VARCHAR(50),
    shard_id VARCHAR(50),
    requested_by VARCHAR(100),
    idempotency_key VARCHAR(255) UNIQUE,
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    status VARCHAR(20),
    error_text TEXT
);

-- Audit Log table
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    origin_id VARCHAR(50),
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for origins table
DROP TRIGGER IF EXISTS update_origins_updated_at ON origins;
CREATE TRIGGER update_origins_updated_at
    BEFORE UPDATE ON origins
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Note: Database user creation should be handled by setup scripts with proper secrets management
-- The ecp_api user must be created manually or via db_setup.sh with DB_PASS environment variable

-- Blacklist entries from threat intelligence feeds
CREATE TABLE IF NOT EXISTS blacklist_entries (
    network CIDR PRIMARY KEY,
    source VARCHAR(100),
    reputation_score SMALLINT CHECK (reputation_score BETWEEN 0 AND 100),
    added_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_blacklist_source ON blacklist_entries(source);
CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON blacklist_entries(expires_at)
    WHERE expires_at IS NOT NULL;

-- Whitelist entries (global scope - bypasses all checks)
CREATE TABLE IF NOT EXISTS whitelist_entries (
    ip_address INET PRIMARY KEY,
    origin_id VARCHAR(50),
    reason VARCHAR(200),
    added_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_whitelist_origin ON whitelist_entries(origin_id)
    WHERE origin_id IS NOT NULL;

-- DDoS Metrics (separate from health - analytics-focused, 90-day retention)
CREATE TABLE IF NOT EXISTS ddos_metrics (
    id SERIAL PRIMARY KEY,
    node_id VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW(),

    -- XDP Statistics (counters from xdp_wan_stats map)
    xdp_pass BIGINT DEFAULT 0,
    xdp_whitelist_bypass BIGINT DEFAULT 0,
    xdp_drop_blacklist BIGINT DEFAULT 0,
    xdp_drop_invalid_ip BIGINT DEFAULT 0,
    xdp_drop_invalid_tcp BIGINT DEFAULT 0,
    xdp_drop_ratelimit BIGINT DEFAULT 0,
    xdp_drop_temp_blacklist BIGINT DEFAULT 0,
    xdp_drop_bogon BIGINT DEFAULT 0,

    -- Future: TC stats, connection counts, etc. can be added here
    tc_dnat BIGINT DEFAULT 0,
    tc_snat BIGINT DEFAULT 0,

    CONSTRAINT fk_ddos_metrics_node FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ddos_metrics_node ON ddos_metrics(node_id);
CREATE INDEX IF NOT EXISTS idx_ddos_metrics_timestamp ON ddos_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_ddos_metrics_recent ON ddos_metrics(timestamp DESC);

COMMENT ON TABLE ddos_metrics IS 'DDoS mitigation metrics from XDP/TC layers (90-day retention for analytics)';
COMMENT ON COLUMN ddos_metrics.xdp_pass IS 'Packets that passed all XDP checks';
COMMENT ON COLUMN ddos_metrics.xdp_whitelist_bypass IS 'Packets bypassed via whitelist';
COMMENT ON COLUMN ddos_metrics.xdp_drop_blacklist IS 'Packets dropped by blacklist (threat intel)';
COMMENT ON COLUMN ddos_metrics.xdp_drop_invalid_ip IS 'Packets dropped for invalid IP headers';
COMMENT ON COLUMN ddos_metrics.xdp_drop_invalid_tcp IS 'Packets dropped for invalid TCP flags';
COMMENT ON COLUMN ddos_metrics.xdp_drop_bogon IS 'Layer 2: Packets dropped for bogon source addresses (RFC 1918, TEST-NET, multicast, reserved)';

-- Origin Metrics (lifetime counters with rate calculations, 90-day retention)
CREATE TABLE IF NOT EXISTS origin_metrics (
    id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) REFERENCES origins(origin_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL,

    -- Calculated rates from lifetime counter deltas
    pps BIGINT,                       -- Packets per second
    cps INTEGER,                      -- Connections per second
    bps BIGINT,                       -- Bytes per second
    active_connections INTEGER,       -- conn_opened - conn_closed (self-healing)
    syn_synack_ratio NUMERIC(10,2),  -- SYN flood indicator (syn_count / synack_count)

    -- Raw lifetime counters (for debugging and validation)
    conn_opened_total BIGINT,
    conn_closed_total BIGINT,
    packets_total BIGINT,
    bytes_total BIGINT,                    -- DEPRECATED: Use volume_ingress + volume_egress instead
    ingress_syn_count BIGINT,      -- PHASE 1: Client → Origin SYNs
    egress_synack_count BIGINT,    -- PHASE 1: Origin → Client SYN-ACKs (REAL indicator)
    fin_count BIGINT,
    rst_count BIGINT,

    -- Security drop counters (per-origin, from eip_security_stats_map)
    drop_blacklist BIGINT DEFAULT 0,
    drop_temp_blacklist BIGINT DEFAULT 0,
    drop_ratelimit BIGINT DEFAULT 0,
    drop_quarantine BIGINT DEFAULT 0,
    drop_bogon BIGINT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_origin_metrics_origin_time ON origin_metrics(origin_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_origin_metrics_timestamp ON origin_metrics(timestamp);

COMMENT ON TABLE origin_metrics IS 'Per-origin lifetime statistics with calculated rates (90-day retention for analytics)';
COMMENT ON COLUMN origin_metrics.pps IS 'Packets per second (calculated from lifetime counter delta)';
COMMENT ON COLUMN origin_metrics.cps IS 'Connections per second (calculated from conn_opened_total delta)';
COMMENT ON COLUMN origin_metrics.bps IS 'Bytes per second (calculated from volume_ingress + volume_egress deltas, bidirectional)';
COMMENT ON COLUMN origin_metrics.active_connections IS 'Current active connections (conn_opened - conn_closed)';
COMMENT ON COLUMN origin_metrics.syn_synack_ratio IS 'SYN/SYN-ACK ratio (attack indicator, >10 = potential SYN flood)';
COMMENT ON COLUMN origin_metrics.drop_blacklist IS 'Layer 1: Packets dropped by permanent blacklist (threat intel)';
COMMENT ON COLUMN origin_metrics.drop_temp_blacklist IS 'Layer 1: Packets dropped by temporary blacklist (auto-mitigation)';
COMMENT ON COLUMN origin_metrics.drop_ratelimit IS 'Layer 3: Packets dropped by rate limiter';
COMMENT ON COLUMN origin_metrics.drop_quarantine IS 'Layer 4: Packets dropped by quarantine (cookie failures)';
COMMENT ON COLUMN origin_metrics.drop_bogon IS 'Layer 2: Packets dropped for bogon source addresses';

-- Extend origin_metrics with infrastructure metrics
ALTER TABLE origin_metrics ADD COLUMN IF NOT EXISTS cpu_pct NUMERIC;
ALTER TABLE origin_metrics ADD COLUMN IF NOT EXISTS memory_pct NUMERIC;
ALTER TABLE origin_metrics ADD COLUMN IF NOT EXISTS disk_io_wait_pct NUMERIC;

COMMENT ON COLUMN origin_metrics.cpu_pct IS 'Scrubber CPU % (shared across origins on same node)';
COMMENT ON COLUMN origin_metrics.memory_pct IS 'Scrubber memory % (shared across origins on same node)';

-- AWS Egress Billing: Volume tracking for cost attribution
ALTER TABLE origin_metrics ADD COLUMN IF NOT EXISTS volume_ingress BIGINT DEFAULT 0;
ALTER TABLE origin_metrics ADD COLUMN IF NOT EXISTS volume_egress BIGINT DEFAULT 0;

COMMENT ON COLUMN origin_metrics.volume_ingress IS 'Bytes to origin (client requests, from egress_billing_map.to_origin_bytes)';
COMMENT ON COLUMN origin_metrics.volume_egress IS 'Bytes to client (origin responses, from egress_billing_map.to_client_bytes)';

-- Per-origin reputation security counters (from eip_security_stats_map)
ALTER TABLE origin_metrics ADD COLUMN IF NOT EXISTS drop_origin_blacklist BIGINT DEFAULT 0;
ALTER TABLE origin_metrics ADD COLUMN IF NOT EXISTS origin_whitelist_bypass BIGINT DEFAULT 0;
ALTER TABLE origin_metrics ADD COLUMN IF NOT EXISTS origin_override_used BIGINT DEFAULT 0;

COMMENT ON COLUMN origin_metrics.drop_origin_blacklist IS 'Per-origin blacklist drops (client-controlled)';
COMMENT ON COLUMN origin_metrics.origin_whitelist_bypass IS 'Per-origin whitelist bypasses (client VPN/office IPs)';
COMMENT ON COLUMN origin_metrics.origin_override_used IS 'Per-origin override usage (skip global blacklist)';

-- LAYER 5: Hourly aggregated metrics (pre-computed for fast baseline queries - Layer 6)
CREATE TABLE IF NOT EXISTS origin_metrics_hourly (
    origin_id VARCHAR(50) REFERENCES origins(origin_id) ON DELETE CASCADE,
    hour_start TIMESTAMPTZ NOT NULL,

    -- Aggregated PPS values
    avg_pps BIGINT,
    min_pps BIGINT,
    max_pps BIGINT,
    p50_pps BIGINT,
    p95_pps BIGINT,
    p99_pps BIGINT,

    -- Aggregated CPS values
    avg_cps INTEGER,
    min_cps INTEGER,
    max_cps INTEGER,
    p95_cps INTEGER,

    -- Aggregated BPS values
    avg_bps BIGINT,
    p95_bps BIGINT,

    -- Aggregated SYN/SYN-ACK ratio
    avg_syn_synack_ratio NUMERIC(10,2),
    max_syn_synack_ratio NUMERIC(10,2),

    -- Aggregated active connections
    avg_active_connections INTEGER,
    max_active_connections INTEGER,

    -- Metadata
    sample_count INTEGER NOT NULL,  -- Number of 30s samples in this hour
    computed_at TIMESTAMPTZ DEFAULT NOW(),

    PRIMARY KEY (origin_id, hour_start)
);

CREATE INDEX IF NOT EXISTS idx_hourly_origin_time ON origin_metrics_hourly(origin_id, hour_start DESC);
CREATE INDEX IF NOT EXISTS idx_hourly_computed ON origin_metrics_hourly(computed_at);

COMMENT ON TABLE origin_metrics_hourly IS 'Pre-computed hourly aggregates for fast baseline queries (Layer 6 preparation)';
COMMENT ON COLUMN origin_metrics_hourly.p95_pps IS '95th percentile packets/sec (baseline for anomaly detection)';
COMMENT ON COLUMN origin_metrics_hourly.sample_count IS 'Number of 30s samples aggregated (typically ~120 per hour)';

-- LAYER 6: Traffic baselines (statistical foundation for adaptive behavior)
CREATE TABLE IF NOT EXISTS traffic_baselines (
    baseline_id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) REFERENCES origins(origin_id) ON DELETE CASCADE,

    -- Observation period
    lookback_days INTEGER NOT NULL DEFAULT 7,
    observation_start TIMESTAMPTZ NOT NULL,
    observation_end TIMESTAMPTZ NOT NULL,
    sample_count INTEGER NOT NULL,

    -- PPS statistics
    pps_mean BIGINT,
    pps_stddev BIGINT,
    pps_p50 BIGINT,
    pps_p95 BIGINT,
    pps_p99 BIGINT,
    pps_min BIGINT,
    pps_max BIGINT,

    -- CPS statistics
    cps_mean INTEGER,
    cps_stddev INTEGER,
    cps_p95 INTEGER,

    -- BPS statistics
    bps_mean BIGINT,
    bps_p95 BIGINT,

    -- SYN/SYN-ACK ratio statistics (critical for SYN flood detection)
    syn_ratio_mean NUMERIC(10,2),
    syn_ratio_stddev NUMERIC(10,2),
    syn_ratio_p95 NUMERIC(10,2),
    syn_ratio_max NUMERIC(10,2),

    -- Active connections statistics
    active_conn_mean INTEGER,
    active_conn_p95 INTEGER,
    active_conn_max INTEGER,

    -- Metadata
    computed_at TIMESTAMPTZ DEFAULT NOW(),
    is_current BOOLEAN DEFAULT TRUE,
    outliers_removed INTEGER DEFAULT 0,

    -- Quality indicators
    confidence_score NUMERIC(3,2),
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_baselines_origin ON traffic_baselines(origin_id, is_current);
CREATE INDEX IF NOT EXISTS idx_baselines_computed ON traffic_baselines(computed_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_baselines_current ON traffic_baselines(origin_id) WHERE is_current = TRUE;

COMMENT ON TABLE traffic_baselines IS 'Layer 6: Statistical baselines for each origin (7-day lookback default)';
COMMENT ON COLUMN traffic_baselines.is_current IS 'Only one baseline per origin should be current';
COMMENT ON COLUMN traffic_baselines.confidence_score IS 'Based on sample count and variance (0.0=insufficient, 1.0=excellent)';
COMMENT ON COLUMN traffic_baselines.outliers_removed IS 'Number of outlier samples dropped during calculation';

-- LAYER 6: Baseline configuration (per-origin runtime parameters)
CREATE TABLE IF NOT EXISTS baseline_config (
    origin_id VARCHAR(50) PRIMARY KEY REFERENCES origins(origin_id) ON DELETE CASCADE,

    -- Calculation parameters
    lookback_days INTEGER DEFAULT 7,
    min_samples INTEGER DEFAULT 100,
    outlier_removal_pct NUMERIC(3,1) DEFAULT 1.0,

    -- Scheduling
    recalc_schedule VARCHAR(20) DEFAULT 'daily',
    recalc_hour INTEGER DEFAULT 2,
    last_recalc_at TIMESTAMPTZ,
    next_recalc_at TIMESTAMPTZ,

    -- Dynamic threshold parameters
    syn_threshold_multiplier NUMERIC(3,1) DEFAULT 3.0,
    syn_threshold_min NUMERIC(5,1) DEFAULT 10.0,

    -- Flags
    auto_recalc_enabled BOOLEAN DEFAULT TRUE,
    dynamic_thresholds_enabled BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE baseline_config IS 'Layer 6: Per-origin baseline calculation configuration and scheduling';
COMMENT ON COLUMN baseline_config.lookback_days IS 'Number of days of historical data to analyze (7, 14, or 30)';
COMMENT ON COLUMN baseline_config.min_samples IS 'Minimum hourly samples required for baseline calculation';
COMMENT ON COLUMN baseline_config.outlier_removal_pct IS 'Percentage of top/bottom outliers to remove (e.g., 1.0 = top 1% and bottom 1%)';
COMMENT ON COLUMN baseline_config.syn_threshold_multiplier IS 'Multiplier applied to baseline p95 for dynamic SYN flood threshold';
COMMENT ON COLUMN baseline_config.dynamic_thresholds_enabled IS 'Enable dynamic thresholds (requires valid baseline)';

-- PHASE 3: Temporary blacklist with auto-expiration (Layer 2 mitigation)
CREATE TABLE IF NOT EXISTS temp_blacklist (
    ip_address INET PRIMARY KEY,
    origin_id VARCHAR(50) REFERENCES origins(origin_id) ON DELETE CASCADE,
    attack_score INTEGER,
    attack_types TEXT[],
    reason VARCHAR(200),
    expires_at TIMESTAMPTZ NOT NULL,
    added_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_temp_blacklist_expires ON temp_blacklist(expires_at);
CREATE INDEX IF NOT EXISTS idx_temp_blacklist_origin ON temp_blacklist(origin_id);

COMMENT ON TABLE temp_blacklist IS 'Temporary blacklist with auto-expiration for automated DDoS mitigation';
COMMENT ON COLUMN temp_blacklist.attack_score IS 'Composite attack score 0-100 from behavioral analysis';
COMMENT ON COLUMN temp_blacklist.attack_types IS 'Array of detected attack patterns: syn_flood, rst_flood, volumetric, scan, burst';

-- PHASE 3: IP attack signatures (behavioral fingerprinting)
CREATE TABLE IF NOT EXISTS ip_attack_signatures (
    id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL,
    origin_id VARCHAR(50) REFERENCES origins(origin_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL,
    syn_count BIGINT,
    rst_count BIGINT,
    packets_total BIGINT,
    burst_rate INTEGER,
    attack_score INTEGER,
    attack_types TEXT[],
    confidence NUMERIC(5,2)
);

CREATE INDEX IF NOT EXISTS idx_signatures_ip_time ON ip_attack_signatures(ip_address, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_signatures_score ON ip_attack_signatures(attack_score DESC, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_signatures_timestamp ON ip_attack_signatures(timestamp);

COMMENT ON TABLE ip_attack_signatures IS 'Historical IP attack signatures for behavioral analysis (90-day retention)';
COMMENT ON COLUMN ip_attack_signatures.attack_score IS 'Composite score 0-100 from pattern matching';
COMMENT ON COLUMN ip_attack_signatures.confidence IS 'Detection confidence 0.0-1.0';

-- PHASE 3: Mitigation actions audit log
CREATE TABLE IF NOT EXISTS mitigation_actions (
    id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL,
    origin_id VARCHAR(50),
    action_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20),
    attack_score INTEGER,
    duration_seconds INTEGER,
    expires_at TIMESTAMPTZ,
    auto_triggered BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_actions_ip ON mitigation_actions(ip_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_expires ON mitigation_actions(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_actions_auto ON mitigation_actions(auto_triggered, created_at DESC);

COMMENT ON TABLE mitigation_actions IS 'Audit log of all mitigation actions (manual and automated)';
COMMENT ON COLUMN mitigation_actions.action_type IS 'ratelimit_penalty, temp_blacklist, perm_blacklist, origin_challenge, global_challenge';
COMMENT ON COLUMN mitigation_actions.severity IS 'soft, medium, hard';

-- PHASE 3: Auto-mitigation configuration
CREATE TABLE IF NOT EXISTS auto_mitigation_config (
    id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) REFERENCES origins(origin_id) ON DELETE CASCADE UNIQUE,
    enabled BOOLEAN DEFAULT true,
    sensitivity VARCHAR(20) DEFAULT 'medium',
    soft_threshold INTEGER DEFAULT 20,
    temp_blacklist_threshold INTEGER DEFAULT 40,
    perm_blacklist_threshold INTEGER DEFAULT 70,
    max_temp_blacklist_per_hour INTEGER DEFAULT 1000,
    max_perm_blacklist_per_day INTEGER DEFAULT 100,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE auto_mitigation_config IS 'Per-origin auto-mitigation configuration (NULL origin_id = global defaults)';
COMMENT ON COLUMN auto_mitigation_config.sensitivity IS 'low, medium, high (adjusts all thresholds)';

-- LAYER 0: VIP state tracking history
CREATE TABLE IF NOT EXISTS vip_state_history (
    id SERIAL PRIMARY KEY,
    origin_ip INET NOT NULL,
    flags INTEGER NOT NULL,
    challenge_level INTEGER NOT NULL,
    changed_at BIGINT NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vip_state_time ON vip_state_history(origin_ip, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_vip_state_flags ON vip_state_history(flags, changed_at DESC);

COMMENT ON TABLE vip_state_history IS 'Historical VIP state transitions for SYN cookie activation tracking';
COMMENT ON COLUMN vip_state_history.flags IS 'Bit 0: COOKIE_ON, Bit 1: UNDER_ATTACK, Bit 2: ESCALATED';
COMMENT ON COLUMN vip_state_history.changed_at IS 'Unix timestamp (seconds) when state changed';

-- LAYER 0: Quarantine log
CREATE TABLE IF NOT EXISTS quarantine_log (
    id SERIAL PRIMARY KEY,
    src_ip INET NOT NULL,
    vip_ip INET NOT NULL,
    reason INTEGER NOT NULL,
    ttl INTEGER NOT NULL,
    score INTEGER DEFAULT 1,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_quarantine_lookup ON quarantine_log(src_ip, vip_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_quarantine_reason ON quarantine_log(reason, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_quarantine_expires ON quarantine_log(expires_at);

COMMENT ON TABLE quarantine_log IS 'Audit log of quarantine actions (cookie failures, protocol anomalies)';
COMMENT ON COLUMN quarantine_log.reason IS '1=cookie_fail, 2=protocol_anomaly, 3=behavioral';
COMMENT ON COLUMN quarantine_log.ttl IS 'Time-to-live in seconds (doubles on repeat offenses)';
COMMENT ON COLUMN quarantine_log.created_at IS 'Unix timestamp (seconds) when quarantined';

-- Layer 4: Per-source cookie validation state (for analytics and reward calculations)
CREATE TABLE IF NOT EXISTS source_state (
    id SERIAL PRIMARY KEY,
    src_ip INET NOT NULL,
    vip_ip INET NOT NULL,
    score INTEGER DEFAULT 0,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    quarantine_expiry BIGINT,
    cookie_failures INTEGER DEFAULT 0,
    cookie_successes INTEGER DEFAULT 0,
    UNIQUE(src_ip, vip_ip)
);

CREATE INDEX IF NOT EXISTS idx_source_state_lookup ON source_state(src_ip, vip_ip);
CREATE INDEX IF NOT EXISTS idx_source_state_expiry ON source_state(quarantine_expiry) WHERE quarantine_expiry IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_source_state_score ON source_state(score DESC, last_seen DESC);

COMMENT ON TABLE source_state IS 'Per-source cookie validation tracking for audit trail and reward calculations';
COMMENT ON COLUMN source_state.score IS 'Quarantine score (increments on each quarantine, max prevents indefinite lockout)';
COMMENT ON COLUMN source_state.cookie_failures IS 'Cumulative cookie validation failures';
COMMENT ON COLUMN source_state.cookie_successes IS 'Cumulative successful cookie validations';
COMMENT ON COLUMN source_state.quarantine_expiry IS 'Unix timestamp (nanoseconds) when current quarantine expires';

-- Layer 4: Syncookie telemetry reported by scrubbers (ingested via /api/v1/metrics)
CREATE TABLE IF NOT EXISTS syncookie_metrics (
    id SERIAL PRIMARY KEY,
    node_id VARCHAR(64) NOT NULL,
    vip_ip INET NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    incoming_syn BIGINT DEFAULT 0,
    cookie_validates BIGINT DEFAULT 0,
    cookie_rejects BIGINT DEFAULT 0,
    handshake_completes BIGINT DEFAULT 0,
    challenged_clients BIGINT DEFAULT 0,
    pending_cookies BIGINT DEFAULT 0,
    allow_list_size BIGINT DEFAULT 0,
    syn_retransmits BIGINT DEFAULT 0,
    false_positives BIGINT DEFAULT 0,
    outgoing_synack BIGINT DEFAULT 0,
    last_update_ts INTEGER DEFAULT 0,
    cookie_mode INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_syncookie_metrics_time ON syncookie_metrics(vip_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_syncookie_metrics_node ON syncookie_metrics(node_id, timestamp DESC);

COMMENT ON TABLE syncookie_metrics IS 'Scrubber-reported SYN cookie counters per VIP (ingress SYNs, validates, rejects, etc.)';
COMMENT ON COLUMN syncookie_metrics.node_id IS 'Scrubber identifier reporting the telemetry';

-- ============================================================================
-- LAYER 7: Anomaly Detection and Challenge Level
-- ============================================================================

-- Layer 7 Table 1: Attack Events (detection logging)
CREATE TABLE IF NOT EXISTS attack_events (
    event_id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) NOT NULL REFERENCES origins(origin_id) ON DELETE CASCADE,
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMP NULL,
    attack_type VARCHAR(50) NOT NULL,
    peak_pps BIGINT,
    peak_cps INTEGER,
    peak_active_connections INTEGER,
    confidence REAL NOT NULL,
    challenge_level_peak INTEGER,
    mitigation_active BOOLEAN DEFAULT true,
    baseline_deviation_zscore REAL,
    samples_breached INTEGER,
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_attack_events_origin ON attack_events(origin_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_events_active ON attack_events(mitigation_active, ended_at);
CREATE INDEX IF NOT EXISTS idx_attack_events_type ON attack_events(attack_type, detected_at DESC);

COMMENT ON TABLE attack_events IS 'Layer 7: Attack detection events with start/end timestamps and confidence scoring';
COMMENT ON COLUMN attack_events.attack_type IS 'PPS_SPIKE, SYN_FLOOD, CPS_SPIKE, STATE_EXHAUSTION, APPLICATION_ATTACK';
COMMENT ON COLUMN attack_events.confidence IS 'Detection confidence 0.7-0.99 based on conditions met';
COMMENT ON COLUMN attack_events.challenge_level_peak IS 'Highest challenge level (0-4) reached during attack';
COMMENT ON COLUMN attack_events.baseline_deviation_zscore IS 'Z-score at detection time';
COMMENT ON COLUMN attack_events.samples_breached IS 'Number of consecutive samples that triggered detection';

-- Layer 7 Table 2: Anomaly Detection State (per-origin state tracking)
CREATE TABLE IF NOT EXISTS anomaly_detection_state (
    origin_id VARCHAR(50) PRIMARY KEY REFERENCES origins(origin_id) ON DELETE CASCADE,
    pps_breach_count INTEGER DEFAULT 0,
    cps_breach_count INTEGER DEFAULT 0,
    ratio_breach_count INTEGER DEFAULT 0,
    state_exhaust_breach_count INTEGER DEFAULT 0,
    last_breach_timestamp TIMESTAMP,
    current_challenge_level INTEGER DEFAULT 0,
    escalation_timestamp TIMESTAMP,
    deescalation_eligible_at TIMESTAMP,
    last_check_timestamp TIMESTAMP DEFAULT NOW(),
    active_attack_event_id INTEGER REFERENCES attack_events(event_id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_anomaly_state_attack ON anomaly_detection_state(active_attack_event_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_state_level ON anomaly_detection_state(current_challenge_level, last_check_timestamp DESC);

COMMENT ON TABLE anomaly_detection_state IS 'Layer 7: Per-origin anomaly detection state for consecutive breach tracking and hysteresis';
COMMENT ON COLUMN anomaly_detection_state.pps_breach_count IS 'Consecutive samples breaching PPS threshold (reset to 0 when below threshold)';
COMMENT ON COLUMN anomaly_detection_state.deescalation_eligible_at IS 'Timestamp when next de-escalation step is allowed (hysteresis timer)';
COMMENT ON COLUMN anomaly_detection_state.active_attack_event_id IS 'Reference to ongoing attack event (NULL when no active attack)';

-- Layer 7 Table 3: Anomaly Detection Configuration (27 runtime parameters)
CREATE TABLE IF NOT EXISTS anomaly_detection_config (
    config_id INTEGER PRIMARY KEY DEFAULT 1,
    z_score_threshold REAL DEFAULT 3.0,
    pps_multiplier_threshold REAL DEFAULT 2.0,
    cps_multiplier_threshold REAL DEFAULT 3.0,
    syn_ratio_threshold REAL DEFAULT 10.0,
    active_conn_threshold REAL DEFAULT 0.9,
    consecutive_samples_to_activate INTEGER DEFAULT 3,
    level_3_to_2_delay INTEGER DEFAULT 300,
    level_2_to_1_delay INTEGER DEFAULT 600,
    level_1_to_0_delay INTEGER DEFAULT 1200,
    escalation_cooldown INTEGER DEFAULT 60,
    level_1_multiplier REAL DEFAULT 0.8,
    level_2_multiplier REAL DEFAULT 0.5,
    level_3_multiplier REAL DEFAULT 0.2,
    level_4_multiplier REAL DEFAULT 0.1,
    pps_spike_level INTEGER DEFAULT 2,
    syn_flood_level INTEGER DEFAULT 3,
    cps_spike_level INTEGER DEFAULT 2,
    state_exhaustion_level INTEGER DEFAULT 3,
    multi_origin_threshold INTEGER DEFAULT 3,
    enable_auto_escalation BOOLEAN DEFAULT true,
    enable_auto_deescalation BOOLEAN DEFAULT true,
    enable_global_escalation BOOLEAN DEFAULT true,
    baseline_required BOOLEAN DEFAULT false,
    static_threshold_fallback BOOLEAN DEFAULT true,
    loop_interval INTEGER DEFAULT 30,
    min_samples_before_detection INTEGER DEFAULT 3,
    config_reload_interval INTEGER DEFAULT 60,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(100),
    notes TEXT,
    CONSTRAINT single_row_config CHECK (config_id = 1)
);

INSERT INTO anomaly_detection_config (config_id) VALUES (1)
    ON CONFLICT (config_id) DO NOTHING;

COMMENT ON TABLE anomaly_detection_config IS 'Layer 7: Runtime-configurable anomaly detection parameters (27 total)';
COMMENT ON COLUMN anomaly_detection_config.z_score_threshold IS 'Standard deviation threshold for anomaly detection (default: 3-sigma rule)';
COMMENT ON COLUMN anomaly_detection_config.baseline_required IS 'If true, detection fails when no baseline available (no static fallback)';
COMMENT ON COLUMN anomaly_detection_config.enable_auto_escalation IS 'Enable automatic challenge level increases on attack detection';

-- Layer 7 Table 4: Configuration Change Log (audit trail)
CREATE TABLE IF NOT EXISTS config_change_log (
    log_id SERIAL PRIMARY KEY,
    config_type VARCHAR(50) NOT NULL,
    origin_id VARCHAR(50),
    parameter_name VARCHAR(100) NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_by VARCHAR(100),
    changed_via VARCHAR(50),
    reason TEXT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_config_change_time ON config_change_log(changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_config_change_origin ON config_change_log(origin_id, changed_at DESC);

COMMENT ON TABLE config_change_log IS 'Audit trail for all anomaly detection configuration changes';
COMMENT ON COLUMN config_change_log.config_type IS 'global or per_origin';
COMMENT ON COLUMN config_change_log.changed_via IS 'api, preset, script, cli';

-- Extend baseline_config table with Layer 7 per-origin overrides
ALTER TABLE baseline_config ADD COLUMN IF NOT EXISTS z_score_threshold REAL DEFAULT NULL;
ALTER TABLE baseline_config ADD COLUMN IF NOT EXISTS pps_multiplier_threshold REAL DEFAULT NULL;
ALTER TABLE baseline_config ADD COLUMN IF NOT EXISTS cps_multiplier_threshold REAL DEFAULT NULL;
ALTER TABLE baseline_config ADD COLUMN IF NOT EXISTS syn_ratio_threshold REAL DEFAULT NULL;
ALTER TABLE baseline_config ADD COLUMN IF NOT EXISTS level_3_to_2_delay INTEGER DEFAULT NULL;
ALTER TABLE baseline_config ADD COLUMN IF NOT EXISTS level_2_to_1_delay INTEGER DEFAULT NULL;
ALTER TABLE baseline_config ADD COLUMN IF NOT EXISTS level_1_to_0_delay INTEGER DEFAULT NULL;

COMMENT ON COLUMN baseline_config.z_score_threshold IS 'Per-origin Z-score override (NULL = use global default from anomaly_detection_config)';
COMMENT ON COLUMN baseline_config.level_3_to_2_delay IS 'Per-origin de-escalation delay override (seconds)';

-- Latency measurements (scrubber → exit hub)
CREATE TABLE IF NOT EXISTS latency_measurements (
    id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) REFERENCES origins(origin_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    latency_ms NUMERIC
);

CREATE INDEX IF NOT EXISTS idx_latency_origin_time ON latency_measurements(origin_id, timestamp DESC);

COMMENT ON TABLE latency_measurements IS 'Scrubber→exit hub latency (30-day retention)';
COMMENT ON COLUMN latency_measurements.latency_ms IS 'RTT from scrubber to exit hub via WireGuard tunnel';

-- Activity events for web app
CREATE TABLE IF NOT EXISTS activity_events (
    id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) REFERENCES origins(origin_id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) DEFAULT 'info',
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activity_origin_time ON activity_events(origin_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_severity_time ON activity_events(severity, created_at DESC);

COMMENT ON TABLE activity_events IS 'Activity log for web app - tiered retention (30d/90d/180d)';
COMMENT ON COLUMN activity_events.event_type IS 'origin_started, origin_stopped, attack_detected, mitigation_triggered';

-- ============================================================================
-- BANDWIDTH QoS: Per-Origin and Per-Node Bandwidth Management
-- ============================================================================

-- Bandwidth QoS: Per-node capacity configuration
CREATE TABLE IF NOT EXISTS node_bandwidth_capacity (
    node_id VARCHAR(50) PRIMARY KEY REFERENCES nodes(node_id) ON DELETE CASCADE,
    instance_type VARCHAR(50),
    bandwidth_bps BIGINT NOT NULL,
    usable_bps BIGINT NOT NULL,
    buffer_percent INTEGER DEFAULT 20,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE node_bandwidth_capacity IS 'Per-scrubber bandwidth capacity from AWS API';

-- Bandwidth QoS: Per-origin quota configuration
CREATE TABLE IF NOT EXISTS origin_bandwidth_quota (
    origin_id VARCHAR(50) PRIMARY KEY REFERENCES origins(origin_id) ON DELETE CASCADE,
    quota_bps BIGINT NOT NULL,
    burst_bytes BIGINT NOT NULL,
    is_override BOOLEAN DEFAULT FALSE,  -- TRUE if manually set, FALSE if calculated
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE origin_bandwidth_quota IS 'Per-origin bandwidth quota (calculated or override)';

-- Bandwidth QoS: Usage metrics history (for trending/alerting)
CREATE TABLE IF NOT EXISTS origin_bandwidth_usage (
    id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) NOT NULL REFERENCES origins(origin_id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    bytes_exceeded BIGINT DEFAULT 0,
    packets_dropped BIGINT DEFAULT 0,
    quota_bps BIGINT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_bandwidth_usage_origin_time
    ON origin_bandwidth_usage(origin_id, timestamp DESC);

COMMENT ON TABLE origin_bandwidth_usage IS 'Historical bandwidth usage for trending';

-- Bandwidth QoS: Alerts/events when quota exceeded
CREATE TABLE IF NOT EXISTS bandwidth_quota_events (
    id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) NOT NULL REFERENCES origins(origin_id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,  -- 'quota_exceeded', 'quota_warning', 'packets_dropped'
    severity VARCHAR(20) NOT NULL,     -- 'info', 'warning', 'critical'
    quota_bps BIGINT,
    exceeded_bytes BIGINT,
    dropped_packets BIGINT,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_bandwidth_events_origin_time
    ON bandwidth_quota_events(origin_id, created_at DESC);

COMMENT ON TABLE bandwidth_quota_events IS 'Bandwidth quota violation events for alerting';

-- ============================================================================
-- PER-ORIGIN REPUTATION CONTROL: Client-Controlled Whitelist/Blacklist
-- ============================================================================

-- Per-origin whitelist (client-controlled, bypasses all checks for this origin)
CREATE TABLE IF NOT EXISTS origin_whitelist (
    id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) NOT NULL REFERENCES origins(origin_id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    cidr_prefix INTEGER DEFAULT 32,  -- Support /24, /16, etc.
    reason VARCHAR(200),
    created_by VARCHAR(100) DEFAULT 'api',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    UNIQUE(origin_id, ip_address, cidr_prefix)
);

CREATE INDEX IF NOT EXISTS idx_origin_whitelist_origin ON origin_whitelist(origin_id);
CREATE INDEX IF NOT EXISTS idx_origin_whitelist_ip ON origin_whitelist(ip_address);
CREATE INDEX IF NOT EXISTS idx_origin_whitelist_expires ON origin_whitelist(expires_at)
    WHERE expires_at IS NOT NULL;

COMMENT ON TABLE origin_whitelist IS 'Per-origin whitelist: client-controlled bypass for specific IPs to this origin';
COMMENT ON COLUMN origin_whitelist.cidr_prefix IS 'CIDR prefix length (32=/32, 24=/24, etc.)';
COMMENT ON COLUMN origin_whitelist.expires_at IS 'Optional expiration timestamp (NULL=permanent)';


-- Per-origin blacklist (client-controlled, blocks IP for this origin only)
CREATE TABLE IF NOT EXISTS origin_blacklist (
    id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) NOT NULL REFERENCES origins(origin_id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    cidr_prefix INTEGER DEFAULT 32,
    reason VARCHAR(200),
    created_by VARCHAR(100) DEFAULT 'api',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    UNIQUE(origin_id, ip_address, cidr_prefix)
);

CREATE INDEX IF NOT EXISTS idx_origin_blacklist_origin ON origin_blacklist(origin_id);
CREATE INDEX IF NOT EXISTS idx_origin_blacklist_ip ON origin_blacklist(ip_address);
CREATE INDEX IF NOT EXISTS idx_origin_blacklist_expires ON origin_blacklist(expires_at)
    WHERE expires_at IS NOT NULL;

COMMENT ON TABLE origin_blacklist IS 'Per-origin blacklist: client-controlled block for specific IPs to this origin';
COMMENT ON COLUMN origin_blacklist.cidr_prefix IS 'CIDR prefix length (32=/32, 24=/24, etc.)';
COMMENT ON COLUMN origin_blacklist.expires_at IS 'Optional expiration timestamp (NULL=permanent)';


-- Per-origin blacklist override (client unblocks global threat for their origin)
CREATE TABLE IF NOT EXISTS origin_blacklist_override (
    id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) NOT NULL REFERENCES origins(origin_id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    cidr_prefix INTEGER DEFAULT 32,
    reason VARCHAR(200) NOT NULL,  -- REQUIRED: Must justify override
    created_by VARCHAR(100) DEFAULT 'api',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(origin_id, ip_address, cidr_prefix)
);

CREATE INDEX IF NOT EXISTS idx_origin_override_origin ON origin_blacklist_override(origin_id);
CREATE INDEX IF NOT EXISTS idx_origin_override_ip ON origin_blacklist_override(ip_address);

COMMENT ON TABLE origin_blacklist_override IS 'Per-origin override: allows globally-blacklisted IP for this origin';
COMMENT ON COLUMN origin_blacklist_override.reason IS 'Required justification for overriding global blacklist';


-- Audit log for all per-origin reputation changes
CREATE TABLE IF NOT EXISTS origin_reputation_log (
    id SERIAL PRIMARY KEY,
    origin_id VARCHAR(50) NOT NULL,
    list_type VARCHAR(20) NOT NULL,  -- 'whitelist', 'blacklist', 'override'
    action VARCHAR(20) NOT NULL,     -- 'add', 'remove', 'expire', 'cleanup'
    ip_address INET NOT NULL,
    cidr_prefix INTEGER DEFAULT 32,
    reason VARCHAR(200),
    performed_by VARCHAR(100),
    scrubbers_updated TEXT[],
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    performed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reputation_log_origin ON origin_reputation_log(origin_id);
CREATE INDEX IF NOT EXISTS idx_reputation_log_time ON origin_reputation_log(performed_at DESC);

COMMENT ON TABLE origin_reputation_log IS 'Audit trail for all per-origin reputation changes (whitelist/blacklist/override)';
COMMENT ON COLUMN origin_reputation_log.list_type IS 'Type of list: whitelist, blacklist, or override';
COMMENT ON COLUMN origin_reputation_log.action IS 'Action performed: add, remove, expire, cleanup';
COMMENT ON COLUMN origin_reputation_log.scrubbers_updated IS 'Array of scrubber node IDs that were updated';

-- ============================================================================
-- DEPLOYMENT JOBS: Non-blocking Shard Deployment Tracking
-- ============================================================================

-- Deployment jobs for async shard operations
CREATE TABLE IF NOT EXISTS deployment_jobs (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL,
    state VARCHAR(20) NOT NULL DEFAULT 'pending',
    progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    progress_message TEXT,
    shard_id VARCHAR(50),
    region VARCHAR(50),
    error TEXT,
    result JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    miner_id UUID,  -- Multi-miner isolation: jobs belong to a specific miner
    CONSTRAINT fk_deployment_job_shard FOREIGN KEY (shard_id)
        REFERENCES shards(shard_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_deployment_jobs_state ON deployment_jobs(state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deployment_jobs_shard ON deployment_jobs(shard_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deployment_jobs_type ON deployment_jobs(type, state);
CREATE INDEX IF NOT EXISTS idx_deployment_jobs_created ON deployment_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deployment_jobs_miner_id ON deployment_jobs(miner_id);
CREATE INDEX IF NOT EXISTS idx_deployment_jobs_miner_state ON deployment_jobs(miner_id, state);

COMMENT ON TABLE deployment_jobs IS 'Async deployment job tracking for non-blocking shard operations';
COMMENT ON COLUMN deployment_jobs.type IS 'Job type: deploy_shard, destroy_shard, scale_shard, etc.';
COMMENT ON COLUMN deployment_jobs.state IS 'Job state: pending, running, completed, failed, cancelled';
COMMENT ON COLUMN deployment_jobs.progress IS 'Progress percentage 0-100';
COMMENT ON COLUMN deployment_jobs.progress_message IS 'Human-readable progress description for UI display';
COMMENT ON COLUMN deployment_jobs.shard_id IS 'Target shard (NULL if job failed before shard creation)';
COMMENT ON COLUMN deployment_jobs.region IS 'AWS region for deployment';
COMMENT ON COLUMN deployment_jobs.error IS 'Error message if state=failed';
COMMENT ON COLUMN deployment_jobs.result IS 'Job result data on completion (node IDs, endpoints, etc.)';
COMMENT ON COLUMN deployment_jobs.completed_at IS 'Timestamp when job reached terminal state (completed/failed/cancelled)';

-- Trigger for deployment_jobs updated_at
DROP TRIGGER IF EXISTS update_deployment_jobs_updated_at ON deployment_jobs;
CREATE TRIGGER update_deployment_jobs_updated_at
    BEFORE UPDATE ON deployment_jobs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ecp_api;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ecp_api;
