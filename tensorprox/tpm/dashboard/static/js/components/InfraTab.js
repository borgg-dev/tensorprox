// InfraTab.js - Infrastructure Tab Component
// Displays miners, shards, regions - the physical/logical infrastructure
// Includes Quick Stats, Top Regions, Top Shards, Miner Overview with expandable rows,
// and Origins Per Shard distribution chart

const { useState, useMemo, useCallback } = React;

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Utilization color mapping based on capacity percentage
 * Matches CHART_COLORS from Charts.js
 */
const UTIL_COLORS = {
    empty: 'hsl(215, 14%, 34%)',      // Gray - 0%
    low: 'hsl(142, 76%, 36%)',        // Green - 1-40%
    medium: 'hsl(48, 96%, 53%)',      // Yellow - 41-80%
    high: 'hsl(25, 95%, 53%)',        // Orange - 81-99%
    full: 'hsl(0, 84%, 60%)'          // Red - 100%
};

/**
 * Region color palette for charts
 */
const REGION_COLORS = [
    'hsl(222, 47%, 31%)',   // Primary blue
    'hsl(142, 76%, 36%)',   // Success green
    'hsl(217, 91%, 60%)',   // Info blue
    'hsl(271, 81%, 56%)',   // Purple
    'hsl(25, 95%, 53%)'     // Orange
];

/**
 * Maximum origins per shard (for utilization calculation)
 */
const MAX_ORIGINS_PER_SHARD = 5;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Gets utilization color based on percentage
 * @param {number} percent - Utilization percentage (0-100)
 * @returns {string} HSL color string
 */
function getUtilizationColor(percent) {
    if (percent === 0) return UTIL_COLORS.empty;
    if (percent <= 40) return UTIL_COLORS.low;
    if (percent <= 80) return UTIL_COLORS.medium;
    if (percent < 100) return UTIL_COLORS.high;
    return UTIL_COLORS.full;
}

/**
 * Calculates utilization percentage from origin count
 * @param {number} origins - Current origin count
 * @param {number} max - Maximum capacity (default: 5)
 * @returns {number} Percentage (0-100)
 */
function calculateUtilization(origins, max = MAX_ORIGINS_PER_SHARD) {
    if (!max || max <= 0) return 0;
    return Math.round((origins / max) * 100);
}

/**
 * Truncates a string with ellipsis
 * @param {string} str - String to truncate
 * @param {number} maxLen - Maximum length
 * @returns {string} Truncated string
 */
function truncateString(str, maxLen = 8) {
    if (!str) return '-';
    if (str.length <= maxLen) return str;
    return str.substring(0, maxLen) + '...';
}

/**
 * Formats region list for display (comma-separated, truncated)
 * @param {string|Array} regions - Regions as string or array
 * @param {number} maxShow - Maximum regions to show
 * @returns {string} Formatted region string
 */
function formatRegions(regions, maxShow = 3) {
    if (!regions) return '-';
    const regionArray = Array.isArray(regions) ? regions : regions.split(',').map(r => r.trim());
    if (regionArray.length <= maxShow) {
        return regionArray.join(', ');
    }
    return regionArray.slice(0, maxShow).join(', ') + ` +${regionArray.length - maxShow}`;
}

// =============================================================================
// UTILIZATION BAR COMPONENT
// =============================================================================

/**
 * Visual bar showing capacity utilization
 * @param {number} percent - Utilization percentage
 * @param {number} current - Current count
 * @param {number} max - Maximum capacity
 */
function UtilizationBar({ percent, current, max }) {
    const color = getUtilizationColor(percent);

    return React.createElement('div', {
        style: {
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-2)'
        }
    },
        // Bar container
        React.createElement('div', {
            style: {
                flex: 1,
                height: '8px',
                backgroundColor: 'hsl(var(--muted))',
                borderRadius: '4px',
                overflow: 'hidden',
                minWidth: '60px'
            }
        },
            // Fill
            React.createElement('div', {
                style: {
                    width: `${percent}%`,
                    height: '100%',
                    backgroundColor: color,
                    borderRadius: '4px',
                    transition: 'width 0.3s ease'
                }
            })
        ),
        // Label
        React.createElement('span', {
            style: {
                fontSize: '0.75rem',
                color: 'hsl(var(--muted-foreground))',
                minWidth: '45px',
                textAlign: 'right'
            }
        }, `${current}/${max}`)
    );
}

// =============================================================================
// QUICK STATS ROW COMPONENT
// =============================================================================

/**
 * Renders the quick stats row with 4 stat cards
 */
function QuickStatsRow({ minerData, shardData, regionData, loading }) {
    // Calculate totals from miner overview data
    const stats = useMemo(() => {
        if (!minerData || minerData.length === 0) {
            return { miners: 0, shards: 0, origins: 0, regions: 0 };
        }

        const miners = minerData.length;
        const shards = minerData.reduce((sum, m) => sum + (m.total_shards || 0), 0);
        const origins = minerData.reduce((sum, m) => sum + (m.total_origins || 0), 0);

        // Get unique regions from shards data if available, otherwise estimate
        let regions = 0;
        if (regionData && regionData.length > 0) {
            regions = regionData.length;
        } else if (shardData && shardData.length > 0) {
            const uniqueRegions = new Set(shardData.map(s => s.region).filter(Boolean));
            regions = uniqueRegions.size;
        }

        return { miners, shards, origins, regions };
    }, [minerData, shardData, regionData]);

    return React.createElement('div', {
        style: {
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: 'var(--space-4)',
            marginBottom: 'var(--space-6)'
        }
    },
        React.createElement(StatCard, {
            title: 'Miners',
            value: stats.miners,
            icon: '#',
            variant: 'default',
            loading: loading
        }),
        React.createElement(StatCard, {
            title: 'Shards',
            value: stats.shards,
            icon: '=',
            variant: 'info',
            loading: loading
        }),
        React.createElement(StatCard, {
            title: 'Origins',
            value: stats.origins,
            icon: '@',
            variant: 'success',
            loading: loading
        }),
        React.createElement(StatCard, {
            title: 'Regions',
            value: stats.regions,
            icon: '*',
            variant: 'muted',
            loading: loading
        })
    );
}

// =============================================================================
// TOP REGIONS COMPONENT
// =============================================================================

/**
 * Displays top 3 regions in a podium/ranked style
 */
function TopRegionsCard({ data, loading }) {
    if (loading) {
        return React.createElement('div', { className: 'card' },
            React.createElement('div', { className: 'card-header' },
                React.createElement('div', { className: 'skeleton', style: { width: '50%', height: '1.25rem' } })
            ),
            React.createElement('div', { className: 'card-content' },
                [...Array(3)].map((_, i) =>
                    React.createElement('div', {
                        key: i,
                        className: 'skeleton',
                        style: {
                            height: '3.5rem',
                            marginBottom: 'var(--space-3)',
                            borderRadius: 'var(--radius)'
                        }
                    })
                )
            )
        );
    }

    const regions = data || [];

    return React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-header' },
            React.createElement('div', { className: 'card-title' }, 'Top 3 Regions'),
            React.createElement('p', { className: 'card-description' }, 'By origin count')
        ),
        React.createElement('div', { className: 'card-content' },
            regions.length === 0
                ? React.createElement('div', { className: 'empty-state' },
                    React.createElement('div', { className: 'empty-state-title' }, 'No regions available')
                )
                : regions.slice(0, 3).map((region, idx) =>
                    React.createElement('div', {
                        key: region.region || idx,
                        style: {
                            display: 'flex',
                            alignItems: 'center',
                            padding: 'var(--space-3)',
                            marginBottom: 'var(--space-2)',
                            background: 'hsl(var(--muted))',
                            borderRadius: 'var(--radius)',
                            borderLeft: `4px solid ${REGION_COLORS[idx] || REGION_COLORS[0]}`
                        }
                    },
                        // Rank badge
                        React.createElement('span', {
                            style: {
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                width: '1.75rem',
                                height: '1.75rem',
                                backgroundColor: REGION_COLORS[idx] || REGION_COLORS[0],
                                color: 'white',
                                borderRadius: '50%',
                                fontWeight: 600,
                                fontSize: '0.875rem',
                                marginRight: 'var(--space-3)'
                            }
                        }, idx + 1),
                        // Region name
                        React.createElement('span', {
                            style: {
                                flex: 1,
                                fontWeight: 500,
                                color: 'hsl(var(--foreground))'
                            }
                        }, region.region || 'Unknown'),
                        // Stats
                        React.createElement('div', {
                            style: {
                                display: 'flex',
                                gap: 'var(--space-4)',
                                fontSize: '0.8125rem'
                            }
                        },
                            React.createElement('span', {
                                className: 'badge',
                                title: 'Origins'
                            }, `${region.origin_count || region.total_origins || 0} origins`),
                            region.shard_count !== undefined && React.createElement('span', {
                                className: 'badge badge-outline',
                                title: 'Shards'
                            }, `${region.shard_count || 0} shards`)
                        )
                    )
                )
        )
    );
}

// =============================================================================
// TOP SHARDS TABLE COMPONENT
// =============================================================================

/**
 * Table showing top 10 shards by utilization
 */
function TopShardsTable({ data, loading }) {
    const columns = useMemo(() => [
        {
            key: 'shard_id',
            header: 'Shard',
            width: '140px',
            render: (val) => React.createElement('span', {
                className: 'tooltip tooltip-top',
                style: { fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }
            },
                React.createElement('span', { className: 'tooltip-trigger' }, truncateString(val, 8)),
                React.createElement('span', { className: 'tooltip-content' }, val)
            )
        },
        {
            key: 'region',
            header: 'Region',
            width: '120px',
            render: (val) => React.createElement('span', {
                style: { fontSize: '0.8125rem' }
            }, val || '-')
        },
        {
            key: 'origin_count',
            header: 'Origins',
            width: '130px',
            render: (val, row) => {
                const count = val || row.total_origins || 0;
                const max = row.max_origins || MAX_ORIGINS_PER_SHARD;
                const percent = calculateUtilization(count, max);
                return React.createElement(UtilizationBar, {
                    percent,
                    current: count,
                    max
                });
            }
        },
        {
            key: 'utilization',
            header: 'Util %',
            width: '80px',
            sortable: true,
            render: (val, row) => {
                const count = row.origin_count || row.total_origins || 0;
                const max = row.max_origins || MAX_ORIGINS_PER_SHARD;
                const percent = val || calculateUtilization(count, max);
                const color = getUtilizationColor(percent);
                return React.createElement('span', {
                    className: 'badge',
                    style: {
                        backgroundColor: color,
                        color: percent <= 40 ? 'white' : 'hsl(var(--foreground))'
                    }
                }, `${percent}%`);
            }
        }
    ], []);

    // Sort data by utilization descending
    const sortedData = useMemo(() => {
        if (!data) return [];
        return [...data].map(shard => ({
            ...shard,
            utilization: calculateUtilization(
                shard.origin_count || shard.total_origins || 0,
                shard.max_origins || MAX_ORIGINS_PER_SHARD
            )
        })).sort((a, b) => b.utilization - a.utilization).slice(0, 10);
    }, [data]);

    return React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-header' },
            React.createElement('div', { className: 'card-title' }, 'Top 10 Shards'),
            React.createElement('p', { className: 'card-description' }, 'By utilization')
        ),
        React.createElement('div', { className: 'card-content' },
            React.createElement(DataTable, {
                columns,
                data: sortedData,
                loading,
                emptyMessage: 'No shards available',
                compact: true,
                sortable: true,
                defaultSort: { key: 'utilization', direction: 'desc' }
            })
        )
    );
}

// =============================================================================
// MINER SHARD DETAILS COMPONENT (for expandable row)
// =============================================================================

/**
 * Expanded content showing shards for a miner
 */
function MinerShardDetails({ minerId, shards }) {
    // Filter shards for this miner
    const minerShards = useMemo(() => {
        if (!shards) return [];
        return shards.filter(s => s.miner_id === minerId);
    }, [shards, minerId]);

    if (minerShards.length === 0) {
        return React.createElement('div', {
            style: {
                padding: 'var(--space-4)',
                color: 'hsl(var(--muted-foreground))',
                fontSize: '0.8125rem'
            }
        }, 'No shard details available');
    }

    return React.createElement('div', {
        style: {
            padding: 'var(--space-2)'
        }
    },
        minerShards.map((shard, idx) => {
            const originCount = shard.origin_count || shard.total_origins || 0;
            const percent = calculateUtilization(originCount);
            const color = getUtilizationColor(percent);

            return React.createElement('div', {
                key: shard.shard_id || idx,
                style: {
                    display: 'flex',
                    alignItems: 'center',
                    padding: 'var(--space-2) var(--space-3)',
                    marginBottom: idx < minerShards.length - 1 ? 'var(--space-2)' : 0,
                    background: 'hsl(var(--background))',
                    borderRadius: 'var(--radius)',
                    borderLeft: `3px solid ${color}`,
                    fontSize: '0.8125rem'
                }
            },
                // Indent indicator
                React.createElement('span', {
                    style: {
                        color: 'hsl(var(--muted-foreground))',
                        marginRight: 'var(--space-2)'
                    }
                }, '\u2514'),
                // Shard ID
                React.createElement('span', {
                    style: {
                        fontFamily: 'var(--font-mono)',
                        marginRight: 'var(--space-3)',
                        minWidth: '80px'
                    },
                    title: shard.shard_id
                }, truncateString(shard.shard_id, 8)),
                // Region badge
                React.createElement('span', {
                    className: 'badge badge-outline',
                    style: { marginRight: 'var(--space-3)' }
                }, shard.region || 'unknown'),
                // Origin count
                React.createElement('span', {
                    style: {
                        color: 'hsl(var(--muted-foreground))'
                    }
                }, `${originCount} origin${originCount !== 1 ? 's' : ''}`)
            );
        })
    );
}

// =============================================================================
// MINER OVERVIEW TABLE COMPONENT
// =============================================================================

/**
 * Main miner overview table with expandable rows
 */
function MinerOverviewTable({ minerData, shardData, loading }) {
    const columns = useMemo(() => [
        {
            key: 'miner_id',
            header: 'Miner ID',
            width: '120px',
            render: (val) => React.createElement('span', {
                className: 'tooltip tooltip-top',
                style: { fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }
            },
                React.createElement('span', { className: 'tooltip-trigger' }, truncateString(val, 8)),
                React.createElement('span', { className: 'tooltip-content' }, val)
            )
        },
        {
            key: 'current_ip',
            header: 'IP',
            width: '130px',
            render: (val) => React.createElement('span', {
                style: { fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }
            }, val || '-')
        },
        {
            key: 'total_shards',
            header: 'Shards',
            width: '80px',
            sortable: true,
            render: (val) => React.createElement('span', {
                className: 'badge badge-secondary'
            }, val || 0)
        },
        {
            key: 'total_origins',
            header: 'Origins',
            width: '80px',
            sortable: true,
            render: (val) => React.createElement('span', {
                className: 'badge',
                style: {
                    backgroundColor: val > 0 ? 'hsl(var(--state-active))' : 'hsl(var(--muted))',
                    color: val > 0 ? 'white' : 'hsl(var(--muted-foreground))'
                }
            }, val || 0)
        },
        {
            key: 'regions',
            header: 'Regions',
            render: (val, row) => {
                // Regions might be in different formats
                const regions = val || row.unique_regions || row.region_list;
                return React.createElement('span', {
                    style: { fontSize: '0.8125rem' },
                    title: Array.isArray(regions) ? regions.join(', ') : regions
                }, formatRegions(regions));
            }
        },
        {
            key: 'last_seen',
            header: 'Last Seen',
            width: '100px',
            sortable: true,
            render: (val) => React.createElement('span', {
                style: { fontSize: '0.8125rem' },
                title: val ? new Date(val).toLocaleString() : ''
            }, DataTableUtils.formatRelativeTime(val))
        }
    ], []);

    // Expandable row renderer
    const expandableRenderer = useCallback((row) => {
        return React.createElement(MinerShardDetails, {
            minerId: row.miner_id,
            shards: shardData
        });
    }, [shardData]);

    return React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-header' },
            React.createElement('div', { className: 'card-title' }, 'Miner Overview'),
            React.createElement('p', { className: 'card-description' },
                'Click row to expand shard details'
            )
        ),
        React.createElement('div', { className: 'card-content' },
            React.createElement(DataTable, {
                columns,
                data: minerData || [],
                loading,
                emptyMessage: 'No miners registered',
                expandable: expandableRenderer,
                compact: true,
                sortable: true,
                defaultSort: { key: 'total_origins', direction: 'desc' }
            })
        )
    );
}

// =============================================================================
// ORIGINS PER SHARD DISTRIBUTION CHART
// =============================================================================

/**
 * Bar chart showing distribution of origins across shards
 * Shows how many shards have 0, 1, 2, 3, 4, 5 origins
 */
function OriginsPerShardChart({ data, loading }) {
    // Transform data into distribution format
    const distributionData = useMemo(() => {
        if (!data || data.length === 0) {
            // Return empty distribution
            return [0, 1, 2, 3, 4, 5].map(count => ({
                origins: count.toString(),
                count: 0
            }));
        }

        // Group shards by origin count
        const distribution = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
        data.forEach(shard => {
            const originCount = shard.origin_count || shard.total_origins || 0;
            const bucket = Math.min(originCount, 5);
            distribution[bucket] = (distribution[bucket] || 0) + 1;
        });

        return Object.entries(distribution).map(([origins, count]) => ({
            origins: origins,
            count
        }));
    }, [data]);

    // Color function for bars based on capacity level
    const getBarColor = useCallback((entry) => {
        const originCount = parseInt(entry.origins, 10);
        const percent = calculateUtilization(originCount);
        return getUtilizationColor(percent);
    }, []);

    return React.createElement(SimpleBarChart, {
        title: 'Origins Per Shard Distribution',
        description: 'Number of shards at each capacity level',
        data: distributionData,
        xKey: 'origins',
        yKey: 'count',
        color: getBarColor,
        loading,
        height: 250,
        xFormatter: (val) => `${val} origins`,
        yFormatter: (val) => Math.round(val).toString()
    });
}

// =============================================================================
// MAIN INFRA TAB COMPONENT
// =============================================================================

/**
 * InfraTab Component
 *
 * Main infrastructure monitoring view with sections:
 * 1. Quick Stats - Miners, Shards, Origins, Regions totals
 * 2. Top 3 Regions - Ranked by origin count
 * 3. Top 10 Shards - By utilization percentage
 * 4. Miner Overview - Expandable table with shard details
 * 5. Origins Per Shard Distribution - Capacity distribution chart
 */
function InfraTab() {
    // Fetch miner overview data
    const {
        data: minerData,
        loading: minerLoading,
        error: minerError
    } = useQuery('miner_overview', {}, {
        refreshInterval: REFRESH_INTERVALS.miner_overview
    });

    // Fetch top 3 regions
    const {
        data: regionData,
        loading: regionLoading,
        error: regionError
    } = useQuery('top_3_regions', {}, {
        refreshInterval: REFRESH_INTERVALS.top_3_regions
    });

    // Fetch top 10 shards
    const {
        data: shardData,
        loading: shardLoading,
        error: shardError
    } = useQuery('top_10_shards', {}, {
        refreshInterval: REFRESH_INTERVALS.top_10_shards
    });

    // Fetch active shards with origins (for expandable details)
    const {
        data: activeShards,
        loading: activeShardsLoading
    } = useQuery('active_shards_with_origins', {}, {
        refreshInterval: REFRESH_INTERVALS.active_shards_with_origins
    });

    // Fetch origins per shard (for distribution chart)
    const {
        data: originsPerShard,
        loading: originsLoading
    } = useQuery('origins_per_shard', {}, {
        refreshInterval: REFRESH_INTERVALS.origins_per_shard
    });

    return React.createElement('div', null,
        // Quick Stats Row
        React.createElement(QuickStatsRow, {
            minerData,
            shardData,
            regionData,
            loading: minerLoading
        }),

        // Two column layout for Top Regions and Top Shards
        React.createElement('div', {
            style: {
                display: 'grid',
                gridTemplateColumns: 'minmax(280px, 1fr) minmax(400px, 2fr)',
                gap: 'var(--space-6)',
                marginBottom: 'var(--space-6)'
            }
        },
            // Top 3 Regions
            regionError
                ? React.createElement('div', { className: 'card' },
                    React.createElement('div', { className: 'card-content' },
                        React.createElement('div', {
                            className: 'text-destructive',
                            style: { padding: 'var(--space-4)' }
                        }, 'Failed to load regions: ', regionError)
                    )
                )
                : React.createElement(TopRegionsCard, {
                    data: regionData,
                    loading: regionLoading
                }),

            // Top 10 Shards Table
            shardError
                ? React.createElement('div', { className: 'card' },
                    React.createElement('div', { className: 'card-content' },
                        React.createElement('div', {
                            className: 'text-destructive',
                            style: { padding: 'var(--space-4)' }
                        }, 'Failed to load shards: ', shardError)
                    )
                )
                : React.createElement(TopShardsTable, {
                    data: shardData,
                    loading: shardLoading
                })
        ),

        // Miner Overview Table
        React.createElement('div', {
            style: { marginBottom: 'var(--space-6)' }
        },
            minerError
                ? React.createElement('div', { className: 'card' },
                    React.createElement('div', { className: 'card-content' },
                        React.createElement('div', {
                            className: 'text-destructive',
                            style: { padding: 'var(--space-4)' }
                        }, 'Failed to load miners: ', minerError)
                    )
                )
                : React.createElement(MinerOverviewTable, {
                    minerData,
                    shardData: activeShards,
                    loading: minerLoading || activeShardsLoading
                })
        ),

        // Origins Per Shard Distribution Chart
        React.createElement('div', {
            style: {
                display: 'grid',
                gridTemplateColumns: '1fr',
                gap: 'var(--space-6)'
            }
        },
            React.createElement(OriginsPerShardChart, {
                data: originsPerShard || activeShards,
                loading: originsLoading || activeShardsLoading
            })
        )
    );
}

// =============================================================================
// EXPORTS
// =============================================================================

// Export for use by Layout.js
if (typeof window !== 'undefined') {
    window.InfraTab = InfraTab;
}
