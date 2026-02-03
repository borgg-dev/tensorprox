// LandingStats.js - Landing Stats Overview Section
// Displays aggregated overview cards that summarize key metrics from multiple queries
// Clicking a card navigates to the relevant tab for detailed information

const { useMemo } = React;

/**
 * LandingStats Component
 *
 * Top section of the dashboard showing quick overview cards that aggregate data
 * from multiple queries. Each card is clickable and navigates to the relevant tab.
 *
 * Layout:
 * ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
 * │ 5 Errors │ │ 3 Miners │ │ 89 Origin│ │ 67 Active│ │ 24 Shards│
 * │ last 24h │ │ online   │ │ total    │ │ origins  │ │ in use   │
 * │ [red]    │ │ [green]  │ │ [blue]   │ │ [green]  │ │ [purple] │
 * └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘
 *
 * @param {Object} props - Component props
 * @param {Function} props.onNavigate - Function to navigate to a tab (receives tab id)
 *                                      Valid tab ids: 'errors', 'infrastructure', 'origins', 'analytics'
 *
 * @example
 * <LandingStats onNavigate={(tabId) => setActiveTab(tabId)} />
 */
function LandingStats({ onNavigate }) {
    // Fetch error categories summary for total error count (last 24 hours)
    const { data: errorData, loading: errorsLoading } = useQuery(
        'error_categories_summary',
        {},
        { refreshInterval: REFRESH_INTERVALS.error_categories_summary }
    );

    // Fetch miner overview for miner count
    const { data: minerData, loading: minersLoading } = useQuery(
        'miner_overview',
        {},
        { refreshInterval: REFRESH_INTERVALS.miner_overview }
    );

    // Fetch origin trace for origin counts by lifecycle state
    const { data: originData, loading: originsLoading } = useQuery(
        'origin_trace',
        {},
        { refreshInterval: REFRESH_INTERVALS.origin_trace }
    );

    // Fetch top 10 shards for shard count
    const { data: shardData, loading: shardsLoading } = useQuery(
        'top_10_shards',
        {},
        { refreshInterval: REFRESH_INTERVALS.top_10_shards }
    );

    // Calculate aggregated values from all query results
    const stats = useMemo(() => {
        // Total errors from all categories
        const totalErrors = errorData?.reduce(
            (sum, cat) => sum + (cat.total_errors || 0),
            0
        ) || 0;

        // Miner count
        const minerCount = minerData?.length || 0;

        // Origin counts by lifecycle state
        const originCounts = {
            total: 0,
            active: 0,
            deploying: 0,
            deleted: 0
        };
        originData?.forEach(item => {
            originCounts.total += item.count || 0;
            if (item.lifecycle_state === 'ACTIVE') {
                originCounts.active = item.count || 0;
            }
            if (item.lifecycle_state === 'DEPLOYING') {
                originCounts.deploying = item.count || 0;
            }
            if (item.lifecycle_state === 'DELETED') {
                originCounts.deleted = item.count || 0;
            }
        });

        // Shard count
        const shardCount = shardData?.length || 0;

        return {
            errors: totalErrors,
            miners: minerCount,
            totalOrigins: originCounts.total,
            activeOrigins: originCounts.active,
            shards: shardCount
        };
    }, [errorData, minerData, originData, shardData]);

    // Handle navigation with fallback for missing callback
    const handleNavigate = (tabId) => {
        if (typeof onNavigate === 'function') {
            onNavigate(tabId);
        }
    };

    return (
        <div className="stat-grid" style={{ marginBottom: '1.5rem' }}>
            {/* Errors Card - shows total errors in last 24 hours */}
            <StatCard
                title="Errors"
                value={stats.errors}
                subtitle="last 24 hours"
                icon="!"
                variant={stats.errors > 0 ? 'error' : 'muted'}
                loading={errorsLoading}
                onClick={() => handleNavigate('errors')}
            />

            {/* Miners Card - shows count of registered miners */}
            <StatCard
                title="Miners"
                value={stats.miners}
                subtitle="online"
                icon="#"
                variant="success"
                loading={minersLoading}
                onClick={() => handleNavigate('infrastructure')}
            />

            {/* Total Origins Card - shows all origins across all states */}
            <StatCard
                title="Total Origins"
                value={stats.totalOrigins}
                subtitle="all time"
                icon="@"
                variant="info"
                loading={originsLoading}
                onClick={() => handleNavigate('origins')}
            />

            {/* Active Origins Card - shows currently active origins */}
            <StatCard
                title="Active Origins"
                value={stats.activeOrigins}
                subtitle="currently active"
                icon="*"
                variant="success"
                loading={originsLoading}
                onClick={() => handleNavigate('origins')}
            />

            {/* Shards Card - shows shards in use */}
            <StatCard
                title="Shards"
                value={stats.shards}
                subtitle="in use"
                icon="%"
                variant="info"
                loading={shardsLoading}
                onClick={() => handleNavigate('infrastructure')}
            />
        </div>
    );
}
