-- ============================================================================
-- TensorProx Data (tp_data) - Time-Series Metrics Schema
-- ============================================================================
-- Optimized for:
--   - High-frequency inserts (every 30s per origin)
--   - Fast dashboard queries (real-time + historical)
--   - Scalable to millions of rows
--   - Flexible JSON querying
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pg_partman;
CREATE EXTENSION IF NOT EXISTS btree_gin;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Origin registry (denormalized reference for fast joins)
CREATE TABLE IF NOT EXISTS origins (
    origin_id TEXT PRIMARY KEY,
    miner_id TEXT,
    shard_id TEXT,
    region TEXT,
    eip TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_origins_miner ON origins(miner_id);
CREATE INDEX idx_origins_region ON origins(region);

-- ============================================================================
-- TIME-SERIES METRICS (Partitioned by day)
-- ============================================================================
-- Hybrid design: indexed columns for common queries + JSONB for flexibility

CREATE TABLE origin_metrics (
    -- Partition key (must be first for efficient pruning)
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Primary dimensions (indexed for fast filtering)
    origin_id TEXT NOT NULL,
    miner_id TEXT,

    -- Key metrics (extracted for fast aggregations without JSON parsing)
    status TEXT,                    -- 'active', 'stopped'
    pps BIGINT,                     -- packets per second
    cps INTEGER,                    -- connections per second
    bps BIGINT,                     -- bytes per second
    bandwidth_mbps NUMERIC(10,2),   -- Mbps (derived)

    -- Attack indicators (critical for dashboards)
    syn_synack_ratio NUMERIC(8,4),
    events_count INTEGER,

    -- Infrastructure metrics
    cpu_usage NUMERIC(5,2),
    memory_usage NUMERIC(5,2),
    latency_ms NUMERIC(10,2),
    active_connections INTEGER,

    -- Billing metrics
    volume_ingress_bytes BIGINT,
    volume_egress_bytes BIGINT,

    -- Full payload for detailed queries (JSONB with GIN index)
    payload JSONB NOT NULL,

    -- Composite primary key for upsert capability
    PRIMARY KEY (ts, origin_id)
) PARTITION BY RANGE (ts);

-- Create initial partitions (pg_partman will manage going forward)
-- Daily partitions for 30-day retention
CREATE TABLE origin_metrics_default PARTITION OF origin_metrics DEFAULT;

-- ============================================================================
-- INDEXES (Critical for query performance)
-- ============================================================================

-- BRIN index on timestamp (extremely efficient for time-series, tiny size)
CREATE INDEX idx_metrics_ts_brin ON origin_metrics USING BRIN (ts) WITH (pages_per_range = 32);

-- B-tree for origin lookups
CREATE INDEX idx_metrics_origin ON origin_metrics (origin_id, ts DESC);

-- GIN index on JSONB for flexible queries (e.g., payload->>'status' = 'active')
CREATE INDEX idx_metrics_payload_gin ON origin_metrics USING GIN (payload jsonb_path_ops);

-- Composite index for common dashboard query: recent metrics per origin
CREATE INDEX idx_metrics_origin_recent ON origin_metrics (origin_id, ts DESC)
    INCLUDE (status, pps, bps, events_count);

-- ============================================================================
-- AGGREGATED VIEWS (Pre-computed for fast dashboards)
-- ============================================================================

-- Hourly aggregations (materialized, refreshed by pg_cron)
CREATE MATERIALIZED VIEW IF NOT EXISTS origin_metrics_hourly AS
SELECT
    date_trunc('hour', ts) AS hour,
    origin_id,
    miner_id,
    -- Aggregated traffic
    AVG(pps)::BIGINT AS avg_pps,
    MAX(pps) AS max_pps,
    AVG(bps)::BIGINT AS avg_bps,
    MAX(bps) AS max_bps,
    AVG(bandwidth_mbps)::NUMERIC(10,2) AS avg_bandwidth_mbps,
    -- Aggregated connections
    AVG(cps)::INTEGER AS avg_cps,
    MAX(cps) AS max_cps,
    AVG(active_connections)::INTEGER AS avg_connections,
    MAX(active_connections) AS max_connections,
    -- Attack indicators
    AVG(syn_synack_ratio)::NUMERIC(8,4) AS avg_syn_ratio,
    MAX(syn_synack_ratio)::NUMERIC(8,4) AS max_syn_ratio,
    SUM(events_count) AS total_events,
    -- Infrastructure
    AVG(cpu_usage)::NUMERIC(5,2) AS avg_cpu,
    MAX(cpu_usage)::NUMERIC(5,2) AS max_cpu,
    AVG(memory_usage)::NUMERIC(5,2) AS avg_memory,
    AVG(latency_ms)::NUMERIC(10,2) AS avg_latency,
    -- Billing
    MAX(volume_ingress_bytes) - MIN(volume_ingress_bytes) AS ingress_bytes,
    MAX(volume_egress_bytes) - MIN(volume_egress_bytes) AS egress_bytes,
    -- Metadata
    COUNT(*) AS sample_count,
    MAX(ts) AS last_updated
FROM origin_metrics
WHERE ts > NOW() - INTERVAL '90 days'
GROUP BY date_trunc('hour', ts), origin_id, miner_id
WITH NO DATA;

CREATE UNIQUE INDEX idx_hourly_origin_hour
    ON origin_metrics_hourly (origin_id, hour DESC);
CREATE INDEX idx_hourly_hour
    ON origin_metrics_hourly (hour DESC);

-- Daily aggregations (for historical dashboards)
CREATE MATERIALIZED VIEW IF NOT EXISTS origin_metrics_daily AS
SELECT
    date_trunc('day', ts) AS day,
    origin_id,
    miner_id,
    -- Traffic
    AVG(pps)::BIGINT AS avg_pps,
    MAX(pps) AS max_pps,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY pps)::BIGINT AS p95_pps,
    AVG(bps)::BIGINT AS avg_bps,
    MAX(bps) AS max_bps,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY bps)::BIGINT AS p95_bps,
    -- Attack summary
    MAX(syn_synack_ratio)::NUMERIC(8,4) AS max_syn_ratio,
    SUM(events_count) AS total_events,
    -- Uptime calculation
    COUNT(*) FILTER (WHERE status = 'active') AS active_samples,
    COUNT(*) AS total_samples,
    ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'active') / NULLIF(COUNT(*), 0), 2) AS uptime_pct,
    -- Billing
    MAX(volume_ingress_bytes) AS max_ingress_bytes,
    MAX(volume_egress_bytes) AS max_egress_bytes,
    MAX(ts) AS last_updated
FROM origin_metrics
WHERE ts > NOW() - INTERVAL '365 days'
GROUP BY date_trunc('day', ts), origin_id, miner_id
WITH NO DATA;

CREATE UNIQUE INDEX idx_daily_origin_day
    ON origin_metrics_daily (origin_id, day DESC);
CREATE INDEX idx_daily_day
    ON origin_metrics_daily (day DESC);

-- ============================================================================
-- LATEST METRICS VIEW (Real-time dashboard - no materialization needed)
-- ============================================================================

CREATE OR REPLACE VIEW origin_metrics_latest AS
SELECT DISTINCT ON (origin_id)
    origin_id,
    ts,
    miner_id,
    status,
    pps,
    cps,
    bps,
    bandwidth_mbps,
    syn_synack_ratio,
    events_count,
    cpu_usage,
    memory_usage,
    latency_ms,
    active_connections,
    volume_ingress_bytes,
    volume_egress_bytes,
    payload
FROM origin_metrics
WHERE ts > NOW() - INTERVAL '5 minutes'
ORDER BY origin_id, ts DESC;

-- ============================================================================
-- SECURITY EVENTS (Separate table for event-based queries)
-- ============================================================================

CREATE TABLE security_events (
    id BIGSERIAL,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    origin_id TEXT NOT NULL,
    event_type TEXT NOT NULL,  -- 'blacklist', 'ratelimit', 'quarantine', 'syn_flood'
    count INTEGER NOT NULL DEFAULT 0,
    details JSONB,
    PRIMARY KEY (ts, id)
) PARTITION BY RANGE (ts);

CREATE TABLE security_events_default PARTITION OF security_events DEFAULT;

CREATE INDEX idx_security_events_origin ON security_events (origin_id, ts DESC);
CREATE INDEX idx_security_events_type ON security_events (event_type, ts DESC);

-- ============================================================================
-- PARTITION MANAGEMENT (pg_partman)
-- ============================================================================

-- Configure pg_partman to create daily partitions
SELECT partman.create_parent(
    p_parent_table := 'public.origin_metrics',
    p_control := 'ts',
    p_interval := 'daily',
    p_premake := 7,           -- Create 7 days ahead
    p_start_partition := (CURRENT_DATE - INTERVAL '7 days')::TEXT
);

SELECT partman.create_parent(
    p_parent_table := 'public.security_events',
    p_control := 'ts',
    p_interval := 'daily',
    p_premake := 7,
    p_start_partition := (CURRENT_DATE - INTERVAL '7 days')::TEXT
);

-- Set retention policy (30 days for raw metrics, drop older partitions)
UPDATE partman.part_config
SET retention = '30 days',
    retention_keep_table = false,
    retention_keep_index = false
WHERE parent_table = 'public.origin_metrics';

UPDATE partman.part_config
SET retention = '90 days',
    retention_keep_table = false
WHERE parent_table = 'public.security_events';

-- ============================================================================
-- SCHEDULED JOBS (pg_cron)
-- ============================================================================

-- Partition maintenance every hour
SELECT cron.schedule('partition-maintenance', '0 * * * *',
    $$CALL partman.run_maintenance_proc()$$);

-- Refresh hourly materialized view every 5 minutes
SELECT cron.schedule('refresh-hourly-metrics', '*/5 * * * *',
    $$REFRESH MATERIALIZED VIEW CONCURRENTLY origin_metrics_hourly$$);

-- Refresh daily materialized view every hour
SELECT cron.schedule('refresh-daily-metrics', '5 * * * *',
    $$REFRESH MATERIALIZED VIEW CONCURRENTLY origin_metrics_daily$$);

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Fast upsert function for metrics ingestion
CREATE OR REPLACE FUNCTION upsert_origin_metric(
    p_origin_id TEXT,
    p_miner_id TEXT,
    p_payload JSONB
) RETURNS VOID AS $$
BEGIN
    INSERT INTO origin_metrics (
        ts, origin_id, miner_id, status, pps, cps, bps, bandwidth_mbps,
        syn_synack_ratio, events_count, cpu_usage, memory_usage, latency_ms,
        active_connections, volume_ingress_bytes, volume_egress_bytes, payload
    ) VALUES (
        NOW(),
        p_origin_id,
        p_miner_id,
        p_payload->>'status',
        (p_payload->>'pps')::BIGINT,
        (p_payload->>'cps')::INTEGER,
        (p_payload->>'bps')::BIGINT,
        (p_payload->>'bandwidth_usage')::NUMERIC(10,2),
        (p_payload->>'syn_synack_ratio')::NUMERIC(8,4),
        (p_payload->>'events_count')::INTEGER,
        (p_payload->>'cpu_usage')::NUMERIC(5,2),
        (p_payload->>'memory_usage')::NUMERIC(5,2),
        (p_payload->>'latency')::NUMERIC(10,2),
        (p_payload->>'active_connections')::INTEGER,
        ((p_payload->>'volume_ingress')::NUMERIC * 1000000000)::BIGINT,
        ((p_payload->>'volume_egress')::NUMERIC * 1000000000)::BIGINT,
        p_payload
    );
END;
$$ LANGUAGE plpgsql;

-- Function to extract security events from payload
CREATE OR REPLACE FUNCTION extract_security_events(
    p_origin_id TEXT,
    p_payload JSONB
) RETURNS VOID AS $$
DECLARE
    event JSONB;
BEGIN
    FOR event IN SELECT * FROM jsonb_array_elements(p_payload->'events')
    LOOP
        IF (event->>'count')::INTEGER > 0 THEN
            INSERT INTO security_events (origin_id, event_type, count, details)
            VALUES (
                p_origin_id,
                event->>'type',
                (event->>'count')::INTEGER,
                event
            );
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- COMMON DASHBOARD QUERIES (Examples)
-- ============================================================================

-- Example 1: Get latest metrics for all origins (real-time dashboard)
-- SELECT * FROM origin_metrics_latest;

-- Example 2: Get hourly traffic for specific origin (sparkline chart)
-- SELECT hour, avg_pps, avg_bps, total_events
-- FROM origin_metrics_hourly
-- WHERE origin_id = 'xxx' AND hour > NOW() - INTERVAL '24 hours'
-- ORDER BY hour;

-- Example 3: Get top origins by traffic
-- SELECT origin_id, pps, bps, events_count
-- FROM origin_metrics_latest
-- ORDER BY bps DESC LIMIT 10;

-- Example 4: Search events in JSONB payload
-- SELECT * FROM origin_metrics
-- WHERE payload @> '{"status": "active"}'
--   AND ts > NOW() - INTERVAL '1 hour';

-- Example 5: Full-text search in payload (requires pg_trgm for fuzzy)
-- SELECT * FROM origin_metrics
-- WHERE payload->>'region' = 'eu-central-1'
--   AND ts > NOW() - INTERVAL '1 hour';

-- ============================================================================
-- INITIAL MATERIALIZED VIEW REFRESH
-- ============================================================================
-- Run these after inserting initial data:
-- REFRESH MATERIALIZED VIEW origin_metrics_hourly;
-- REFRESH MATERIALIZED VIEW origin_metrics_daily;

