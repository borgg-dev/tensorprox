-- ============================================================================
-- TensorProx Subnet Integration Schema
-- ============================================================================
-- Adds validator scoring and miner assignment tables to support the
-- Bittensor subnet (SN91) integration with TPM.
--
-- This schema extends the existing TPM state database (tp_state) with:
-- - Validator score storage
-- - Score aggregation and historical tracking
-- - Miner-to-origin assignment management
-- - Miner failure tracking
-- ============================================================================

-- ============================================================================
-- SUBNET MINERS TABLE
-- ============================================================================
-- Tracks miners registered in the Bittensor subnet
-- Links subnet UIDs to TPM miner_ids

CREATE TABLE IF NOT EXISTS subnet_miners (
    miner_uid INTEGER PRIMARY KEY,
    miner_id TEXT,  -- TPM miner_id (may be NULL for new miners)
    hotkey TEXT NOT NULL UNIQUE,
    coldkey TEXT,

    -- Miner state in subnet
    state VARCHAR(20) DEFAULT 'pre_assignment',  -- 'pre_assignment', 'active', 'flagged'

    -- Aggregated score (median of validator scores)
    aggregated_score NUMERIC(5, 3) DEFAULT 0.0,
    last_score_update TIMESTAMPTZ,

    -- Assignment capacity
    origins_assigned INTEGER DEFAULT 0,
    max_origins INTEGER DEFAULT 10,

    -- Performance tracking
    consecutive_failures INTEGER DEFAULT 0,
    last_failure TIMESTAMPTZ,

    -- Infrastructure info
    scrubber_ip TEXT,
    exit_hub_ip TEXT,
    exit_hub_tunnel_name TEXT,

    -- Region and availability (for smart assignment)
    region TEXT,  -- e.g., 'us-east-1', 'eu-west-1', 'ap-southeast-1'
    is_available BOOLEAN DEFAULT FALSE,  -- Miner is online and responding
    last_heartbeat TIMESTAMPTZ,  -- Last time miner was seen online
    ema_score NUMERIC(5, 3) DEFAULT 0.0,  -- EMA score from validator (for leaderboard sync)
    last_audit_score NUMERIC(5, 3) DEFAULT 0.0,  -- Latest raw audit score (fallback for deployment when EMA is warming up)

    -- Metadata
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_subnet_miners_state ON subnet_miners(state);
CREATE INDEX idx_subnet_miners_score ON subnet_miners(aggregated_score DESC);
CREATE INDEX idx_subnet_miners_hotkey ON subnet_miners(hotkey);
CREATE INDEX idx_subnet_miners_region ON subnet_miners(region);
CREATE INDEX idx_subnet_miners_available ON subnet_miners(is_available, state);

COMMENT ON TABLE subnet_miners IS 'Bittensor subnet miners - tracks UIDs, scores, and assignments';
COMMENT ON COLUMN subnet_miners.state IS 'Miner lifecycle state: pre_assignment (testing), active (protecting origins), flagged (poor performance)';
COMMENT ON COLUMN subnet_miners.aggregated_score IS 'Aggregated score from all validators (median of last 5 reports)';
COMMENT ON COLUMN subnet_miners.region IS 'AWS/cloud region where miner scrubber is deployed (for geo-aware assignment)';
COMMENT ON COLUMN subnet_miners.is_available IS 'Whether miner is currently online and responding to requests';
COMMENT ON COLUMN subnet_miners.ema_score IS 'EMA audit score synced from validator leaderboard';
COMMENT ON COLUMN subnet_miners.last_audit_score IS 'Latest raw audit score - used as deployment fallback when EMA is warming up from cold start';

-- ============================================================================
-- VALIDATOR SCORES TABLE
-- ============================================================================
-- Stores raw scores reported by validators for each miner
-- Used to calculate aggregated scores and track validator consensus

CREATE TABLE IF NOT EXISTS validator_scores (
    id BIGSERIAL PRIMARY KEY,

    -- Validator identification
    validator_uid INTEGER NOT NULL,
    validator_hotkey TEXT NOT NULL,

    -- Miner being scored
    miner_uid INTEGER NOT NULL REFERENCES subnet_miners(miner_uid) ON DELETE CASCADE,

    -- Score and components
    score NUMERIC(5, 3) NOT NULL CHECK (score >= 0.0 AND score <= 1.0),
    score_components JSONB,  -- Breakdown: volume, latency, availability, mitigation

    -- Timestamp
    reported_at TIMESTAMPTZ DEFAULT NOW(),

    -- Metadata
    audit_type VARCHAR(20),  -- 'pre_assignment' or 'production'
    validator_version TEXT
);

CREATE INDEX idx_validator_scores_miner ON validator_scores(miner_uid, reported_at DESC);
CREATE INDEX idx_validator_scores_validator ON validator_scores(validator_uid, reported_at DESC);
CREATE INDEX idx_validator_scores_time ON validator_scores(reported_at DESC);

COMMENT ON TABLE validator_scores IS 'Raw scores reported by validators during audits';
COMMENT ON COLUMN validator_scores.score_components IS 'JSON breakdown of score: {"volume": 0.4, "latency": 0.28, "availability": 0.2, "mitigation": 0.095}';

-- ============================================================================
-- VALIDATOR HEARTBEATS TABLE (Multi-Validator Support)
-- ============================================================================
-- Tracks per-validator availability reports for each miner.
-- Used to determine miner availability via consensus (ANY validator sees online).
-- Also stores EMA scores per validator for aggregation.

CREATE TABLE IF NOT EXISTS validator_heartbeats (
    id BIGSERIAL PRIMARY KEY,

    -- Validator identification
    validator_uid INTEGER NOT NULL,
    validator_hotkey TEXT NOT NULL,

    -- Miner being reported
    miner_uid INTEGER NOT NULL REFERENCES subnet_miners(miner_uid) ON DELETE CASCADE,

    -- Availability report
    is_available BOOLEAN NOT NULL,
    ema_score NUMERIC(5, 3),  -- Validator's EMA score for this miner
    region TEXT,  -- Region reported by this validator

    -- Timestamp
    reported_at TIMESTAMPTZ DEFAULT NOW(),

    -- Unique constraint: one report per validator per miner (upsert pattern)
    UNIQUE(validator_uid, miner_uid)
);

CREATE INDEX idx_validator_heartbeats_miner ON validator_heartbeats(miner_uid, reported_at DESC);
CREATE INDEX idx_validator_heartbeats_validator ON validator_heartbeats(validator_uid, reported_at DESC);
CREATE INDEX idx_validator_heartbeats_available ON validator_heartbeats(miner_uid, is_available, reported_at DESC);

COMMENT ON TABLE validator_heartbeats IS 'Per-validator availability reports - aggregated for consensus-based availability';
COMMENT ON COLUMN validator_heartbeats.is_available IS 'Whether this validator sees the miner as online';
COMMENT ON COLUMN validator_heartbeats.ema_score IS 'This validators EMA audit score for the miner';

-- ============================================================================
-- AGGREGATED AVAILABILITY VIEW (Multi-Validator Consensus)
-- ============================================================================
-- Miner is considered AVAILABLE if:
-- - ANY validator has seen it online in the last 15 minutes
--
-- EMA score is aggregated as MEDIAN across validators (like aggregated_score)

CREATE OR REPLACE VIEW miner_availability_consensus AS
SELECT
    miner_uid,
    -- Available if ANY validator saw it online recently (last 15 min)
    BOOL_OR(is_available AND reported_at > NOW() - INTERVAL '15 minutes') AS is_available,
    -- Median EMA score across validators
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY ema_score) AS consensus_ema_score,
    -- Most common region (mode)
    MODE() WITHIN GROUP (ORDER BY region) AS consensus_region,
    -- Metadata
    COUNT(DISTINCT validator_uid) AS validator_count,
    MAX(reported_at) AS last_report,
    COUNT(*) FILTER (WHERE is_available AND reported_at > NOW() - INTERVAL '15 minutes') AS validators_seeing_online
FROM validator_heartbeats
WHERE reported_at > NOW() - INTERVAL '1 hour'  -- Only consider recent reports
GROUP BY miner_uid;

COMMENT ON VIEW miner_availability_consensus IS 'Aggregated availability from multiple validators - miner is available if ANY validator sees it online';

-- ============================================================================
-- MINER ASSIGNMENTS TABLE
-- ============================================================================
-- Tracks which origins are assigned to which miners
-- Links TPM origin_id to subnet miner_uid

CREATE TABLE IF NOT EXISTS miner_assignments (
    assignment_id BIGSERIAL PRIMARY KEY,

    -- Assignment mapping
    origin_id TEXT NOT NULL,  -- TPM origin_id
    miner_uid INTEGER NOT NULL REFERENCES subnet_miners(miner_uid) ON DELETE CASCADE,

    -- Origin details
    origin_ip TEXT NOT NULL,
    scrubber_ip TEXT NOT NULL,
    exit_hub_ip TEXT NOT NULL,
    tunnel_name TEXT NOT NULL,

    -- Assignment metadata
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    reassigned_count INTEGER DEFAULT 0,
    last_reassignment_reason TEXT,

    -- Traffic profile
    expected_bandwidth_mbps INTEGER,
    traffic_type TEXT,
    preferred_region TEXT,

    -- Status
    status VARCHAR(20) DEFAULT 'active',  -- 'active', 'draining', 'terminated'
    terminated_at TIMESTAMPTZ,

    UNIQUE(origin_id)  -- One origin can only be assigned to one miner
);

CREATE INDEX idx_assignments_miner ON miner_assignments(miner_uid);
CREATE INDEX idx_assignments_origin ON miner_assignments(origin_id);
CREATE INDEX idx_assignments_status ON miner_assignments(status);

COMMENT ON TABLE miner_assignments IS 'Origin-to-miner assignments - tracks which miners protect which origins';
COMMENT ON COLUMN miner_assignments.reassigned_count IS 'Number of times this origin has been reassigned (due to miner failures)';

-- ============================================================================
-- MINER FAILURE EVENTS TABLE
-- ============================================================================
-- Tracks miner failures reported by validators
-- Used for reassignment decisions and miner reputation

CREATE TABLE IF NOT EXISTS miner_failure_events (
    id BIGSERIAL PRIMARY KEY,

    -- Miner that failed
    miner_uid INTEGER NOT NULL REFERENCES subnet_miners(miner_uid) ON DELETE CASCADE,

    -- Failure details
    reason TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,  -- 'low', 'medium', 'high', 'critical'

    -- Reporter
    reported_by_validator_uid INTEGER,
    reported_by_validator_hotkey TEXT,

    -- Metadata
    reported_at TIMESTAMPTZ DEFAULT NOW(),
    details JSONB
);

CREATE INDEX idx_failure_events_miner ON miner_failure_events(miner_uid, reported_at DESC);
CREATE INDEX idx_failure_events_severity ON miner_failure_events(severity, reported_at DESC);

COMMENT ON TABLE miner_failure_events IS 'Miner failure events - triggers for reassignment and flagging';

-- ============================================================================
-- SCORE HISTORY VIEW
-- ============================================================================
-- Aggregates validator scores per miner over time
-- Used for calculating median scores and tracking trends

CREATE OR REPLACE VIEW miner_score_history AS
SELECT
    miner_uid,
    date_trunc('hour', reported_at) AS hour,
    COUNT(DISTINCT validator_uid) AS validator_count,
    AVG(score) AS avg_score,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY score) AS median_score,
    MIN(score) AS min_score,
    MAX(score) AS max_score,
    STDDEV(score) AS score_stddev,
    MAX(reported_at) AS last_updated
FROM validator_scores
WHERE reported_at > NOW() - INTERVAL '7 days'
GROUP BY miner_uid, date_trunc('hour', reported_at);

COMMENT ON VIEW miner_score_history IS 'Hourly aggregated scores per miner - for trend analysis';

-- ============================================================================
-- CURRENT ASSIGNMENTS VIEW
-- ============================================================================
-- Shows active assignments with miner details

CREATE OR REPLACE VIEW current_assignments AS
SELECT
    ma.assignment_id,
    ma.origin_id,
    ma.origin_ip,
    ma.miner_uid,
    sm.hotkey AS miner_hotkey,
    sm.aggregated_score,
    sm.state AS miner_state,
    ma.scrubber_ip,
    ma.exit_hub_ip,
    ma.tunnel_name,
    ma.assigned_at,
    ma.reassigned_count,
    ma.expected_bandwidth_mbps,
    ma.traffic_type
FROM miner_assignments ma
JOIN subnet_miners sm ON ma.miner_uid = sm.miner_uid
WHERE ma.status = 'active';

COMMENT ON VIEW current_assignments IS 'Active origin assignments with miner details';

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to update aggregated miner score
-- Called after new validator scores are reported
CREATE OR REPLACE FUNCTION update_miner_aggregated_score(p_miner_uid INTEGER)
RETURNS NUMERIC AS $$
DECLARE
    v_median_score NUMERIC;
BEGIN
    -- Calculate median of last 5 validator reports (different validators)
    SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY score)
    INTO v_median_score
    FROM (
        SELECT DISTINCT ON (validator_uid) score
        FROM validator_scores
        WHERE miner_uid = p_miner_uid
        ORDER BY validator_uid, reported_at DESC
        LIMIT 5
    ) recent_scores;

    -- Update miner's aggregated score
    UPDATE subnet_miners
    SET aggregated_score = COALESCE(v_median_score, 0.0),
        last_score_update = NOW(),
        updated_at = NOW()
    WHERE miner_uid = p_miner_uid;

    RETURN COALESCE(v_median_score, 0.0);
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION update_miner_aggregated_score IS 'Recalculates miner aggregated score (median of last 5 validator reports)';

-- Function to get available miners for assignment
-- Returns miners in 'active' state with available capacity, sorted by score
CREATE OR REPLACE FUNCTION get_available_miners(
    p_min_score NUMERIC DEFAULT 0.8,
    p_limit INTEGER DEFAULT 10
)
RETURNS TABLE (
    miner_uid INTEGER,
    aggregated_score NUMERIC,
    origins_assigned INTEGER,
    max_origins INTEGER,
    scrubber_ip TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        sm.miner_uid,
        sm.aggregated_score,
        sm.origins_assigned,
        sm.max_origins,
        sm.scrubber_ip
    FROM subnet_miners sm
    WHERE sm.state = 'active'
      AND sm.aggregated_score >= p_min_score
      AND sm.origins_assigned < sm.max_origins
    ORDER BY sm.aggregated_score DESC, sm.origins_assigned ASC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_available_miners IS 'Returns miners eligible for new assignments (active, score >= threshold, has capacity)';

-- Function to record miner failure and check if should be flagged
CREATE OR REPLACE FUNCTION record_miner_failure(
    p_miner_uid INTEGER,
    p_reason TEXT,
    p_severity TEXT,
    p_validator_uid INTEGER DEFAULT NULL
)
RETURNS BOOLEAN AS $$
DECLARE
    v_consecutive_failures INTEGER;
    v_should_flag BOOLEAN;
BEGIN
    -- Insert failure event
    INSERT INTO miner_failure_events (
        miner_uid, reason, severity,
        reported_by_validator_uid, reported_at
    ) VALUES (
        p_miner_uid, p_reason, p_severity,
        p_validator_uid, NOW()
    );

    -- Update miner consecutive failures
    UPDATE subnet_miners
    SET consecutive_failures = consecutive_failures + 1,
        last_failure = NOW(),
        updated_at = NOW()
    WHERE miner_uid = p_miner_uid
    RETURNING consecutive_failures INTO v_consecutive_failures;

    -- Flag if >= 3 consecutive failures
    v_should_flag := v_consecutive_failures >= 3;

    IF v_should_flag THEN
        UPDATE subnet_miners
        SET state = 'flagged',
            updated_at = NOW()
        WHERE miner_uid = p_miner_uid;
    END IF;

    RETURN v_should_flag;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION record_miner_failure IS 'Records failure event and flags miner if >= 3 consecutive failures';

-- Function to assign origin to miner
CREATE OR REPLACE FUNCTION assign_origin_to_miner(
    p_origin_id TEXT,
    p_miner_uid INTEGER,
    p_origin_ip TEXT,
    p_scrubber_ip TEXT,
    p_exit_hub_ip TEXT,
    p_tunnel_name TEXT,
    p_expected_bandwidth_mbps INTEGER DEFAULT NULL,
    p_traffic_type TEXT DEFAULT NULL
)
RETURNS BIGINT AS $$
DECLARE
    v_assignment_id BIGINT;
BEGIN
    -- Insert assignment
    INSERT INTO miner_assignments (
        origin_id, miner_uid, origin_ip, scrubber_ip,
        exit_hub_ip, tunnel_name, expected_bandwidth_mbps,
        traffic_type, status, assigned_at
    ) VALUES (
        p_origin_id, p_miner_uid, p_origin_ip, p_scrubber_ip,
        p_exit_hub_ip, p_tunnel_name, p_expected_bandwidth_mbps,
        p_traffic_type, 'active', NOW()
    )
    RETURNING assignment_id INTO v_assignment_id;

    -- Increment miner's assignment count
    UPDATE subnet_miners
    SET origins_assigned = origins_assigned + 1,
        updated_at = NOW()
    WHERE miner_uid = p_miner_uid;

    RETURN v_assignment_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION assign_origin_to_miner IS 'Assigns origin to miner and increments assignment count';

-- ============================================================================
-- INITIAL DATA
-- ============================================================================
-- No initial data needed - validators and miners will register via API
