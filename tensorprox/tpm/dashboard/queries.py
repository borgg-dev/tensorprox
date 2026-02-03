"""Query registry for the dashboard.

Provides a registry of predefined SQL queries that can be executed via the API.
Each query is registered with a name and description, and returns a tuple of
(sql, params) when called.
"""

from typing import Callable

# Each query: name -> (sql_builder function, description)
# sql_builder takes params dict, returns (sql, params) tuple
QueryDef = tuple[Callable[[dict], tuple[str, dict]], str]
QUERIES: dict[str, QueryDef] = {}


def register(name: str, description: str):
    """Decorator to register a query.

    Args:
        name: Unique identifier for the query.
        description: Human-readable description of what the query does.

    Returns:
        Decorator function that registers the query builder.

    Example:
        @register("my_query", "Description of my query")
        def my_query(params: dict) -> tuple[str, dict]:
            return ("SELECT 1", {})
    """

    def decorator(fn: Callable[[dict], tuple[str, dict]]):
        QUERIES[name] = (fn, description)
        return fn

    return decorator


# =============================================================================
# Phase A: Predefined queries (no parameters)
# =============================================================================


@register("exit_hubs_summary", "Count of exit hubs by status")
def exit_hubs_summary(params: dict) -> tuple[str, dict]:
    """Get count of exit hubs grouped by status."""
    return (
        """
        SELECT status, COUNT(*) as count
        FROM tensorprox_exit_hubs
        GROUP BY status
        """,
        {},
    )


@register("active_miners", "List of registered miners")
def active_miners(params: dict) -> tuple[str, dict]:
    """Get all registered miners with their basic info."""
    return (
        """
        SELECT miner_id, current_ip, created_at
        FROM tensorprox_miners
        """,
        {},
    )


@register("recent_deployments", "Last 20 deployments")
def recent_deployments(params: dict) -> tuple[str, dict]:
    """Get the 20 most recent exit hub deployments."""
    return (
        """
        SELECT exit_hub_id, status, origin_id, created_at, last_error
        FROM tensorprox_exit_hubs
        ORDER BY created_at DESC
        LIMIT 20
        """,
        {},
    )


# =============================================================================
# Phase B Preview: Parameterized queries
# =============================================================================


@register("hubs_by_status", "Exit hubs filtered by status")
def hubs_by_status(params: dict) -> tuple[str, dict]:
    """Get exit hubs filtered by a specific status.

    Args:
        params: Dict with optional 'status' key. Defaults to 'active'.

    Returns:
        SQL query and parameters for filtering exit hubs by status.
    """
    return (
        """
        SELECT exit_hub_id, origin_id, created_at
        FROM tensorprox_exit_hubs
        WHERE status = %(status)s
        """,
        {"status": params.get("status", "active")},
    )


# =============================================================================
# ERRORS SECTION
# =============================================================================


@register("error_categories_summary", "Error counts by category (error_source)")
def error_categories_summary(params: dict) -> tuple[str, dict]:
    """Get error counts grouped by error_source category."""
    return (
        """
        SELECT
            error_source,
            COUNT(*) as total_errors,
            COUNT(DISTINCT miner_id) as affected_miners,
            COUNT(DISTINCT exit_hub_id) as affected_exit_hubs,
            MAX(created_at) as last_occurrence
        FROM tensorprox_system_errors
        GROUP BY error_source
        ORDER BY total_errors DESC
        """,
        {},
    )


@register("error_codes_by_category", "Error codes breakdown within each category")
def error_codes_by_category(params: dict) -> tuple[str, dict]:
    """Get error code counts grouped by source and code."""
    return (
        """
        SELECT
            error_source,
            error_code,
            COUNT(*) as count,
            MAX(created_at) as latest_occurrence
        FROM tensorprox_system_errors
        GROUP BY error_source, error_code
        ORDER BY error_source, count DESC
        """,
        {},
    )


@register("last_5_errors", "Last 5 errors across all sources")
def last_5_errors(params: dict) -> tuple[str, dict]:
    """Get the 5 most recent errors from system errors, exit hubs, and operations."""
    return (
        """
        WITH system_errors AS (
            SELECT
                'system' AS error_category,
                error_source,
                error_code,
                error_message,
                created_at AS error_timestamp,
                exit_hub_id::TEXT,
                origin_id,
                miner_id::TEXT
            FROM tensorprox_system_errors
        ),
        deployment_errors AS (
            SELECT
                'deployment' AS error_category,
                'deployment' AS error_source,
                status AS error_code,
                last_error AS error_message,
                updated_at AS error_timestamp,
                exit_hub_id::TEXT,
                origin_id,
                NULL AS miner_id
            FROM tensorprox_exit_hubs
            WHERE last_error IS NOT NULL
        ),
        operation_errors AS (
            SELECT
                'operation' AS error_category,
                'miner_operation' AS error_source,
                operation_type AS error_code,
                error AS error_message,
                completed_at AS error_timestamp,
                exit_hub_id::TEXT,
                origin_id,
                miner_id::TEXT
            FROM tensorprox_miner_operations
            WHERE status = 'failed' AND error IS NOT NULL
        ),
        all_errors AS (
            SELECT * FROM system_errors
            UNION ALL
            SELECT * FROM deployment_errors
            UNION ALL
            SELECT * FROM operation_errors
        )
        SELECT
            error_category,
            error_source,
            error_code,
            error_message,
            error_timestamp,
            exit_hub_id,
            origin_id,
            miner_id
        FROM all_errors
        ORDER BY error_timestamp DESC
        LIMIT 5
        """,
        {},
    )


@register("errors_by_category_last_7_days", "Errors in a category for last 7 days")
def errors_by_category_last_7_days(params: dict) -> tuple[str, dict]:
    """Get all errors for a specific category in the last 7 days.

    Args:
        params: Dict with 'error_source' key (e.g., 'target_selection', 'geolocation').
    """
    return (
        """
        SELECT
            id,
            error_source,
            error_code,
            error_message,
            context,
            exit_hub_id::TEXT,
            origin_id,
            miner_id::TEXT,
            created_at
        FROM tensorprox_system_errors
        WHERE error_source = %(error_source)s
          AND created_at >= NOW() - INTERVAL '7 days'
        ORDER BY created_at DESC
        """,
        {"error_source": params.get("error_source", "target_selection")},
    )


@register("errors_over_time_daily", "Error counts per day for last 30 days")
def errors_over_time_daily(params: dict) -> tuple[str, dict]:
    """Get daily error counts for time series chart."""
    return (
        """
        SELECT
            DATE(created_at) as date,
            COUNT(*) as error_count
        FROM tensorprox_system_errors
        WHERE created_at >= NOW() - INTERVAL '30 days'
        GROUP BY DATE(created_at)
        ORDER BY date ASC
        """,
        {},
    )


@register("errors_over_time_by_source", "Error counts per day by source for last 30 days")
def errors_over_time_by_source(params: dict) -> tuple[str, dict]:
    """Get daily error counts broken down by error_source for stacked chart."""
    return (
        """
        SELECT
            DATE(created_at) as date,
            error_source,
            COUNT(*) as error_count
        FROM tensorprox_system_errors
        WHERE created_at >= NOW() - INTERVAL '30 days'
        GROUP BY DATE(created_at), error_source
        ORDER BY date ASC, error_source
        """,
        {},
    )


@register("shard_sweeper_errors", "Shard sweeper errors (last 7 days)")
def shard_sweeper_errors(params: dict) -> tuple[str, dict]:
    """Get shard sweeper errors from the last 7 days.

    Shows verification failures, deletion failures, and exceptions
    that occurred during background shard cleanup.
    """
    return (
        """
        SELECT
            id,
            error_code,
            error_message,
            miner_id::TEXT,
            context->>'shard_id' AS shard_id,
            context->>'http_status' AS http_status,
            context->>'exception_type' AS exception_type,
            created_at
        FROM tensorprox_system_errors
        WHERE error_source = 'shard_sweeper'
          AND created_at >= NOW() - INTERVAL '7 days'
        ORDER BY created_at DESC
        """,
        {},
    )


# =============================================================================
# MINER / ORIGIN SECTION
# =============================================================================


@register("active_shards_with_origins", "Active shards with origin count per shard")
def active_shards_with_origins(params: dict) -> tuple[str, dict]:
    """Get all active shards with their origin counts and utilization."""
    return (
        """
        SELECT
            ms.miner_id::TEXT,
            ms.shard_id,
            ms.region,
            ms.status AS shard_status,
            COUNT(o.origin_id) AS origin_count,
            5 AS max_origins,
            ROUND((COUNT(o.origin_id)::numeric / 5) * 100, 2) AS utilization_percent,
            (5 - COUNT(o.origin_id)) AS available_slots,
            ms.last_synced_at
        FROM tensorprox_miner_shards ms
        LEFT JOIN tensorprox_origins o
            ON ms.miner_id::TEXT = o.miner_id
            AND ms.shard_id = o.shard_id
            AND o.status IN ('active', 'provisioning')
        WHERE ms.status = 'active'
        GROUP BY ms.miner_id, ms.shard_id, ms.region, ms.status, ms.last_synced_at
        ORDER BY ms.region, origin_count DESC
        """,
        {},
    )


@register("active_regions_with_origins", "Active regions with origin count per region")
def active_regions_with_origins(params: dict) -> tuple[str, dict]:
    """Get all active regions with aggregated origin counts."""
    return (
        """
        SELECT
            ms.region,
            COUNT(DISTINCT ms.shard_id) AS shard_count,
            COUNT(DISTINCT ms.miner_id) AS miner_count,
            COUNT(o.origin_id) AS total_origins,
            COUNT(DISTINCT o.client_id) AS unique_clients,
            SUM(CASE WHEN o.status = 'active' THEN 1 ELSE 0 END) AS active_origins,
            SUM(CASE WHEN o.status = 'provisioning' THEN 1 ELSE 0 END) AS provisioning_origins,
            MAX(ms.last_synced_at) AS last_sync
        FROM tensorprox_miner_shards ms
        LEFT JOIN tensorprox_origins o
            ON ms.miner_id::TEXT = o.miner_id
            AND ms.shard_id = o.shard_id
        WHERE ms.status = 'active'
        GROUP BY ms.region
        ORDER BY total_origins DESC
        """,
        {},
    )


@register("active_miners_detailed", "Active miners with shard and origin counts")
def active_miners_detailed(params: dict) -> tuple[str, dict]:
    """Get all active miners with their shard and origin counts."""
    return (
        """
        SELECT
            m.miner_id::TEXT,
            m.name,
            m.current_ip,
            m.created_at,
            m.last_seen,
            COUNT(DISTINCT ms.shard_id) AS shard_count,
            COUNT(DISTINCT o.origin_id) AS origin_count
        FROM tensorprox_miners m
        LEFT JOIN tensorprox_miner_shards ms ON m.miner_id = ms.miner_id
        LEFT JOIN tensorprox_origins o
            ON ms.miner_id::TEXT = o.miner_id
            AND ms.shard_id = o.shard_id
        WHERE m.status = 'active'
        GROUP BY m.miner_id, m.name, m.current_ip, m.created_at, m.last_seen
        ORDER BY m.created_at DESC
        """,
        {},
    )


@register("origin_trace", "Origin lifecycle trace (deployed, active, deleted)")
def origin_trace(params: dict) -> tuple[str, dict]:
    """Get origin lifecycle status breakdown."""
    return (
        """
        SELECT
            CASE
                WHEN o.status = 'active' THEN 'ACTIVE'
                WHEN o.status IN ('terminated', 'failed') THEN 'DELETED'
                WHEN o.status = 'provisioning' THEN 'DEPLOYING'
                ELSE 'UNKNOWN'
            END AS lifecycle_state,
            COUNT(*) AS count
        FROM tensorprox_origins o
        GROUP BY lifecycle_state
        ORDER BY count DESC
        """,
        {},
    )


@register("origin_trace_detailed", "Detailed origin lifecycle with all fields")
def origin_trace_detailed(params: dict) -> tuple[str, dict]:
    """Get detailed origin records with lifecycle information."""
    return (
        """
        SELECT
            o.origin_id,
            o.client_id,
            o.status AS origin_status,
            CASE
                WHEN o.status = 'active' THEN 'ACTIVE'
                WHEN o.status IN ('terminated', 'failed') THEN 'DELETED'
                WHEN o.status = 'provisioning' THEN 'DEPLOYING'
                ELSE 'UNKNOWN'
            END AS lifecycle_state,
            o.miner_id,
            o.shard_id,
            o.tensorprox_ip,
            o.egress_enabled,
            o.created_at,
            o.updated_at,
            o.deletion_error
        FROM tensorprox_origins o
        ORDER BY o.updated_at DESC
        LIMIT 100
        """,
        {},
    )


@register("origin_lifetime_stats", "Origin lifetime duration statistics")
def origin_lifetime_stats(params: dict) -> tuple[str, dict]:
    """Get statistics on how long origins stay active."""
    return (
        """
        WITH origin_lifetime AS (
            SELECT
                origin_id,
                status,
                CASE
                    WHEN status = 'terminated' THEN
                        EXTRACT(EPOCH FROM (updated_at - created_at))::int
                    ELSE
                        EXTRACT(EPOCH FROM (NOW() - created_at))::int
                END AS lifetime_seconds
            FROM tensorprox_origins
        )
        SELECT
            COUNT(*) AS total_origins,
            COUNT(CASE WHEN status = 'terminated' THEN 1 END) AS terminated_count,
            COUNT(CASE WHEN status != 'terminated' THEN 1 END) AS active_count,
            ROUND((AVG(lifetime_seconds) / 3600.0)::numeric, 2) AS avg_lifetime_hours,
            ROUND((PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY lifetime_seconds) / 3600.0)::numeric, 2) AS median_lifetime_hours,
            ROUND((MIN(lifetime_seconds) / 3600.0)::numeric, 2) AS min_lifetime_hours,
            ROUND((MAX(lifetime_seconds) / 86400.0)::numeric, 2) AS max_lifetime_days
        FROM origin_lifetime
        """,
        {},
    )


@register("origin_lifetime_distribution", "Origin lifetime distribution by buckets")
def origin_lifetime_distribution(params: dict) -> tuple[str, dict]:
    """Get origin lifetime distribution across time buckets."""
    return (
        """
        WITH origin_lifetime AS (
            SELECT
                origin_id,
                status,
                EXTRACT(EPOCH FROM (
                    CASE
                        WHEN status = 'terminated' THEN updated_at
                        ELSE NOW()
                    END - created_at
                ))::int AS lifetime_seconds
            FROM tensorprox_origins
        )
        SELECT
            CASE
                WHEN lifetime_seconds < 3600 THEN '< 1 hour'
                WHEN lifetime_seconds < 86400 THEN '1-24 hours'
                WHEN lifetime_seconds < 604800 THEN '1-7 days'
                WHEN lifetime_seconds < 2592000 THEN '7-30 days'
                WHEN lifetime_seconds < 7776000 THEN '30-90 days'
                ELSE '> 90 days'
            END AS lifetime_bucket,
            COUNT(*) AS count,
            ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS percentage
        FROM origin_lifetime
        GROUP BY
            CASE
                WHEN lifetime_seconds < 3600 THEN '< 1 hour'
                WHEN lifetime_seconds < 86400 THEN '1-24 hours'
                WHEN lifetime_seconds < 604800 THEN '1-7 days'
                WHEN lifetime_seconds < 2592000 THEN '7-30 days'
                WHEN lifetime_seconds < 7776000 THEN '30-90 days'
                ELSE '> 90 days'
            END
        ORDER BY
            MIN(lifetime_seconds)
        """,
        {},
    )


@register("egress_status_by_origin", "Egress enabled/disabled status per origin")
def egress_status_by_origin(params: dict) -> tuple[str, dict]:
    """Get egress configuration status for all origins."""
    return (
        """
        SELECT
            origin_id,
            client_id,
            status AS origin_status,
            egress_enabled,
            egress_activated_at,
            created_at
        FROM tensorprox_origins
        ORDER BY egress_enabled DESC, created_at DESC
        """,
        {},
    )


@register("egress_summary", "Egress enabled/disabled summary counts")
def egress_summary(params: dict) -> tuple[str, dict]:
    """Get summary of egress status across all origins."""
    return (
        """
        SELECT
            COUNT(*) AS total_origins,
            COUNT(*) FILTER (WHERE egress_enabled = TRUE) AS egress_enabled_count,
            COUNT(*) FILTER (WHERE egress_enabled = FALSE OR egress_enabled IS NULL) AS egress_disabled_count,
            COUNT(*) FILTER (WHERE egress_activated_at IS NOT NULL) AS egress_activated_count
        FROM tensorprox_origins
        """,
        {},
    )


@register("origin_count_over_time", "Daily new origin count for last 30 days")
def origin_count_over_time(params: dict) -> tuple[str, dict]:
    """Get daily count of new origins created."""
    return (
        """
        SELECT
            DATE(created_at) AS date,
            COUNT(*) AS new_origins
        FROM tensorprox_origins
        WHERE created_at >= NOW() - INTERVAL '30 days'
        GROUP BY DATE(created_at)
        ORDER BY date ASC
        """,
        {},
    )


@register("shard_count_over_time", "Daily new shard count for last 30 days")
def shard_count_over_time(params: dict) -> tuple[str, dict]:
    """Get daily count of new shards created."""
    return (
        """
        SELECT
            DATE(created_at) AS date,
            COUNT(*) AS new_shards
        FROM tensorprox_miner_shards
        WHERE created_at >= NOW() - INTERVAL '30 days'
        GROUP BY DATE(created_at)
        ORDER BY date ASC
        """,
        {},
    )


@register("origins_per_shard", "Origin count distribution across shards")
def origins_per_shard(params: dict) -> tuple[str, dict]:
    """Get origin count per shard with utilization metrics."""
    return (
        """
        WITH shard_counts AS (
            SELECT
                ms.miner_id::TEXT,
                ms.shard_id,
                ms.region,
                COUNT(o.origin_id) AS origin_count
            FROM tensorprox_miner_shards ms
            LEFT JOIN tensorprox_origins o
                ON ms.miner_id::TEXT = o.miner_id
                AND ms.shard_id = o.shard_id
            WHERE ms.status = 'active'
            GROUP BY ms.miner_id, ms.shard_id, ms.region
        )
        SELECT
            origin_count,
            COUNT(*) AS num_shards,
            ROUND((COUNT(*)::numeric / (SELECT COUNT(*) FROM shard_counts)) * 100, 2) AS percent_of_shards,
            CASE
                WHEN origin_count = 0 THEN 'Empty'
                WHEN origin_count < 3 THEN 'Low (1-2)'
                WHEN origin_count < 5 THEN 'Medium (3-4)'
                WHEN origin_count = 5 THEN 'Full (5/5)'
                ELSE 'Over-capacity'
            END AS capacity_band
        FROM shard_counts
        GROUP BY origin_count
        ORDER BY origin_count
        """,
        {},
    )


# =============================================================================
# QUICK OVERVIEW / TOP SECTIONS
# =============================================================================


@register("miner_overview", "Quick overview: miners, shards, origins (active)")
def miner_overview(params: dict) -> tuple[str, dict]:
    """Get a quick overview of active miners with their shards and origins."""
    return (
        """
        SELECT
            m.miner_id::TEXT,
            m.name AS miner_name,
            m.current_ip,
            m.last_seen,
            COUNT(DISTINCT ms.shard_id) AS total_shards,
            COUNT(DISTINCT CASE WHEN ms.status = 'active' THEN ms.shard_id END) AS active_shards,
            COUNT(DISTINCT o.origin_id) AS total_origins,
            COUNT(DISTINCT CASE WHEN o.status = 'active' THEN o.origin_id END) AS active_origins,
            STRING_AGG(DISTINCT ms.region, ', ' ORDER BY ms.region) AS regions
        FROM tensorprox_miners m
        LEFT JOIN tensorprox_miner_shards ms ON m.miner_id = ms.miner_id
        LEFT JOIN tensorprox_origins o
            ON ms.miner_id::TEXT = o.miner_id
            AND ms.shard_id = o.shard_id
        WHERE m.status = 'active'
        GROUP BY m.miner_id, m.name, m.current_ip, m.last_seen
        ORDER BY active_origins DESC, m.miner_id
        """,
        {},
    )


@register("top_3_regions", "Top 3 regions by origin count")
def top_3_regions(params: dict) -> tuple[str, dict]:
    """Get top 3 regions ranked by origin count."""
    return (
        """
        SELECT
            ms.region,
            COUNT(DISTINCT ms.shard_id) AS shard_count,
            COUNT(DISTINCT ms.miner_id) AS miner_count,
            COUNT(o.origin_id) AS origin_count,
            COUNT(CASE WHEN o.status = 'active' THEN 1 END) AS active_origins
        FROM tensorprox_miner_shards ms
        LEFT JOIN tensorprox_origins o
            ON ms.miner_id::TEXT = o.miner_id
            AND ms.shard_id = o.shard_id
        WHERE ms.status = 'active'
        GROUP BY ms.region
        ORDER BY origin_count DESC
        LIMIT 3
        """,
        {},
    )


@register("top_10_shards", "Top 10 shards by origin count")
def top_10_shards(params: dict) -> tuple[str, dict]:
    """Get top 10 shards ranked by origin count with miner info."""
    return (
        """
        SELECT
            ms.miner_id::TEXT,
            ms.shard_id,
            ms.region,
            COUNT(o.origin_id) AS origin_count,
            5 AS max_origins,
            ROUND((COUNT(o.origin_id)::numeric / 5) * 100, 2) AS utilization_percent,
            COUNT(CASE WHEN o.status = 'active' THEN 1 END) AS active_origins,
            COUNT(CASE WHEN o.status = 'provisioning' THEN 1 END) AS provisioning_origins
        FROM tensorprox_miner_shards ms
        LEFT JOIN tensorprox_origins o
            ON ms.miner_id::TEXT = o.miner_id
            AND ms.shard_id = o.shard_id
        WHERE ms.status = 'active'
        GROUP BY ms.miner_id, ms.shard_id, ms.region
        ORDER BY origin_count DESC
        LIMIT 10
        """,
        {},
    )
