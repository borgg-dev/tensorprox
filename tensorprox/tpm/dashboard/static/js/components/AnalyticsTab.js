// AnalyticsTab.js - Analytics Tab Component
// Displays origin lifetime statistics, distribution charts, and time-series data
// Includes LifetimeStats cards, Distribution chart, and Origins/Shards over time charts

const { useState, useMemo, useCallback } = React;

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Bucket ordering for lifetime distribution chart
 */
const BUCKET_ORDER = [
    '< 1 hour',
    '1-24 hours',
    '1-7 days',
    '7-30 days',
    '30-90 days',
    '> 90 days'
];

/**
 * Color palette for lifetime buckets (gradient from short to long)
 */
const BUCKET_COLORS = {
    '< 1 hour': 'hsl(0, 84%, 60%)',        // Red - very short
    '1-24 hours': 'hsl(25, 95%, 53%)',      // Orange - short
    '1-7 days': 'hsl(48, 96%, 53%)',        // Yellow - moderate
    '7-30 days': 'hsl(142, 76%, 36%)',      // Green - good
    '30-90 days': 'hsl(199, 89%, 48%)',     // Cyan - great
    '> 90 days': 'hsl(217, 91%, 60%)'       // Blue - long-term
};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Formats duration from hours to a human-readable string
 * @param {number} hours - Duration in hours
 * @returns {string} Formatted duration string
 */
function formatDuration(hours) {
    if (hours === null || hours === undefined || isNaN(hours)) {
        return '-';
    }
    if (hours < 1) {
        return `${Math.round(hours * 60)} min`;
    }
    if (hours < 24) {
        return `${hours.toFixed(1)} hrs`;
    }
    const days = hours / 24;
    if (days < 1) {
        return `${hours.toFixed(1)} hrs`;
    }
    return `${days.toFixed(1)} days`;
}

/**
 * Formats days to a human-readable string
 * @param {number} days - Duration in days
 * @returns {string} Formatted duration string
 */
function formatDays(days) {
    if (days === null || days === undefined || isNaN(days)) {
        return '-';
    }
    if (days < 1) {
        return formatDuration(days * 24);
    }
    if (days < 30) {
        return `${days.toFixed(1)} days`;
    }
    if (days < 365) {
        const months = days / 30;
        return `${months.toFixed(1)} mo`;
    }
    const years = days / 365;
    return `${years.toFixed(1)} yr`;
}

/**
 * Formats a date for chart x-axis labels (e.g., "Dec 15")
 * @param {string} dateStr - ISO date string
 * @returns {string} Formatted date
 */
function formatChartDate(dateStr) {
    if (!dateStr) return '';
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return dateStr;
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

/**
 * Gets color for a lifetime bucket
 * @param {string} bucket - Lifetime bucket label
 * @returns {string} HSL color string
 */
function getBucketColor(bucket) {
    return BUCKET_COLORS[bucket] || 'hsl(215, 14%, 34%)';
}

// =============================================================================
// LIFETIME STAT CARD COMPONENT
// =============================================================================

/**
 * LifetimeStatCard - Individual stat card for lifetime metrics
 * Styled similar to StatCard but optimized for lifetime display
 */
function LifetimeStatCard({ label, value, subtitle, loading }) {
    if (loading) {
        return React.createElement('div', {
            className: 'stat-card',
            role: 'status',
            'aria-busy': 'true'
        },
            React.createElement('div', {
                className: 'skeleton',
                style: { width: '50%', height: '0.875rem', marginBottom: 'var(--space-2)' }
            }),
            React.createElement('div', {
                className: 'skeleton',
                style: { width: '70%', height: '1.75rem' }
            })
        );
    }

    return React.createElement('div', {
        className: 'stat-card',
        style: {
            borderTop: '3px solid hsl(var(--primary))'
        }
    },
        React.createElement('div', {
            className: 'stat-card-header'
        },
            React.createElement('span', {
                className: 'stat-card-title',
                style: { fontSize: '0.8125rem' }
            }, label)
        ),
        React.createElement('div', {
            className: 'stat-card-value',
            style: {
                fontSize: '1.5rem',
                color: 'hsl(var(--foreground))'
            }
        }, value),
        subtitle && React.createElement('div', {
            className: 'text-muted',
            style: { fontSize: '0.75rem', marginTop: 'var(--space-1)' }
        }, subtitle)
    );
}

// =============================================================================
// LIFETIME STATS SECTION COMPONENT
// =============================================================================

/**
 * LifetimeStatsSection - Row of 4 stat cards showing lifetime statistics
 */
function LifetimeStatsSection({ data, loading }) {
    // Extract first row from query results (aggregate query returns single row)
    const stats = useMemo(() => {
        if (!data || data.length === 0) return null;
        return data[0];
    }, [data]);

    const avgValue = stats?.avg_lifetime_hours;
    const medValue = stats?.median_lifetime_hours;
    const minValue = stats?.min_lifetime_hours;
    const maxDays = stats?.max_lifetime_days;

    return React.createElement('div', {
        className: 'card',
        style: { marginBottom: 'var(--space-6)' }
    },
        React.createElement('div', { className: 'card-header' },
            React.createElement('div', { className: 'card-title' }, 'Origin Lifetime Stats'),
            React.createElement('p', { className: 'card-description' },
                stats
                    ? `Based on ${stats.total_origins || 0} origins (${stats.terminated_count || 0} terminated, ${stats.active_count || 0} active)`
                    : 'Loading origin statistics...'
            )
        ),
        React.createElement('div', { className: 'card-content' },
            React.createElement('div', {
                style: {
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                    gap: 'var(--space-4)'
                }
            },
                React.createElement(LifetimeStatCard, {
                    label: 'Average',
                    value: formatDuration(avgValue),
                    subtitle: 'mean lifetime',
                    loading: loading
                }),
                React.createElement(LifetimeStatCard, {
                    label: 'Median',
                    value: formatDuration(medValue),
                    subtitle: '50th percentile',
                    loading: loading
                }),
                React.createElement(LifetimeStatCard, {
                    label: 'Minimum',
                    value: formatDuration(minValue),
                    subtitle: 'shortest lived',
                    loading: loading
                }),
                React.createElement(LifetimeStatCard, {
                    label: 'Maximum',
                    value: formatDays(maxDays),
                    subtitle: 'longest lived',
                    loading: loading
                })
            )
        )
    );
}

// =============================================================================
// LIFETIME DISTRIBUTION COMPONENT
// =============================================================================

/**
 * LifetimeDistributionChart - Horizontal bar chart showing distribution buckets
 */
function LifetimeDistributionChart({ data, loading }) {
    // Sort data according to bucket order and prepare for chart
    const chartData = useMemo(() => {
        if (!data || data.length === 0) return [];

        // Create a map for easy lookup
        const dataMap = new Map();
        data.forEach(item => {
            dataMap.set(item.lifetime_bucket, item);
        });

        // Return in correct order
        return BUCKET_ORDER.map(bucket => {
            const item = dataMap.get(bucket);
            return {
                bucket: bucket,
                count: item?.count || 0,
                percentage: item?.percentage || 0
            };
        }).filter(item => item.count > 0 || data.length === 0);
    }, [data]);

    // Color function for bars
    const getBarColor = useCallback((entry) => {
        return getBucketColor(entry.bucket);
    }, []);

    return React.createElement(HorizontalBarChart, {
        title: 'Lifetime Distribution',
        description: 'Origins grouped by how long they stay active',
        data: chartData,
        nameKey: 'bucket',
        valueKey: 'count',
        color: getBarColor,
        loading: loading,
        height: 280,
        valueFormatter: (value) => value.toLocaleString()
    });
}

// =============================================================================
// CUSTOM DISTRIBUTION VISUAL (Alternative to chart)
// =============================================================================

/**
 * LifetimeDistributionBars - Custom horizontal bar visualization with percentages
 * Provides cleaner display matching the spec design
 */
function LifetimeDistributionBars({ data, loading }) {
    // Sort data according to bucket order
    const sortedData = useMemo(() => {
        if (!data || data.length === 0) return [];

        const dataMap = new Map();
        data.forEach(item => {
            dataMap.set(item.lifetime_bucket, item);
        });

        return BUCKET_ORDER.map(bucket => {
            const item = dataMap.get(bucket);
            return {
                bucket: bucket,
                count: item?.count || 0,
                percentage: item?.percentage || 0
            };
        });
    }, [data]);

    if (loading) {
        return React.createElement('div', { className: 'card' },
            React.createElement('div', { className: 'card-header' },
                React.createElement('div', { className: 'skeleton', style: { width: '40%', height: '1.25rem' } })
            ),
            React.createElement('div', { className: 'card-content' },
                [...Array(6)].map((_, i) =>
                    React.createElement('div', {
                        key: i,
                        className: 'skeleton',
                        style: {
                            height: '2rem',
                            marginBottom: 'var(--space-2)',
                            borderRadius: 'var(--radius)'
                        }
                    })
                )
            )
        );
    }

    const maxPercentage = Math.max(...sortedData.map(d => d.percentage), 1);

    return React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-header' },
            React.createElement('div', { className: 'card-title' }, 'Lifetime Distribution'),
            React.createElement('p', { className: 'card-description' },
                'Origins grouped by how long they stay active'
            )
        ),
        React.createElement('div', { className: 'card-content' },
            sortedData.map(item =>
                React.createElement('div', {
                    key: item.bucket,
                    style: {
                        display: 'flex',
                        alignItems: 'center',
                        gap: 'var(--space-3)',
                        marginBottom: 'var(--space-3)'
                    }
                },
                    // Label
                    React.createElement('div', {
                        style: {
                            width: '90px',
                            fontSize: '0.8125rem',
                            color: 'hsl(var(--foreground))',
                            flexShrink: 0
                        }
                    }, item.bucket),
                    // Bar container
                    React.createElement('div', {
                        style: {
                            flex: 1,
                            height: '1.25rem',
                            background: 'hsl(var(--muted))',
                            borderRadius: 'var(--radius)',
                            overflow: 'hidden'
                        }
                    },
                        // Bar fill
                        React.createElement('div', {
                            style: {
                                width: `${(item.percentage / maxPercentage) * 100}%`,
                                height: '100%',
                                background: getBucketColor(item.bucket),
                                borderRadius: 'var(--radius)',
                                transition: 'width 0.3s ease'
                            }
                        })
                    ),
                    // Percentage
                    React.createElement('div', {
                        style: {
                            width: '50px',
                            fontSize: '0.8125rem',
                            color: 'hsl(var(--muted-foreground))',
                            textAlign: 'right',
                            flexShrink: 0
                        }
                    }, `${parseFloat(item.percentage).toFixed(0)}%`)
                )
            ),
            // Empty state
            sortedData.every(d => d.count === 0) && React.createElement('div', {
                className: 'empty-state',
                style: { padding: 'var(--space-6)' }
            },
                React.createElement('div', { className: 'empty-state-title' },
                    'No lifetime data available'
                )
            )
        )
    );
}

// =============================================================================
// TIME SERIES CHARTS SECTION
// =============================================================================

/**
 * TimeSeriesSection - Contains Origins and Shards over time charts
 */
function TimeSeriesSection({ originsData, shardsData, originsLoading, shardsLoading }) {
    // Format origins data for chart
    const originsChartData = useMemo(() => {
        if (!originsData) return [];
        return originsData.map(item => ({
            date: item.date,
            count: item.new_origins || 0
        })).sort((a, b) => new Date(a.date) - new Date(b.date));
    }, [originsData]);

    // Format shards data for chart
    const shardsChartData = useMemo(() => {
        if (!shardsData) return [];
        return shardsData.map(item => ({
            date: item.date,
            count: item.new_shards || 0
        })).sort((a, b) => new Date(a.date) - new Date(b.date));
    }, [shardsData]);

    return React.createElement('div', {
        style: {
            display: 'flex',
            flexDirection: 'column',
            gap: 'var(--space-4)'
        }
    },
        // Origins Over Time Chart
        React.createElement(SimpleAreaChart, {
            title: 'Origins Over Time',
            description: 'Daily new origins created (30 days)',
            data: originsChartData,
            xKey: 'date',
            yKey: 'count',
            color: CHART_COLORS.success,
            loading: originsLoading,
            height: 200,
            xFormatter: formatChartDate,
            tooltipFormatter: (value) => [`${value} origin${value !== 1 ? 's' : ''}`, 'New']
        }),

        // Shards Over Time Chart
        React.createElement(SimpleAreaChart, {
            title: 'Shards Over Time',
            description: 'Daily new shards created (30 days)',
            data: shardsChartData,
            xKey: 'date',
            yKey: 'count',
            color: CHART_COLORS.info,
            loading: shardsLoading,
            height: 200,
            xFormatter: formatChartDate,
            tooltipFormatter: (value) => [`${value} shard${value !== 1 ? 's' : ''}`, 'New']
        })
    );
}

// =============================================================================
// MAIN ANALYTICS TAB COMPONENT
// =============================================================================

/**
 * AnalyticsTab Component
 *
 * Main analytics view with three sections:
 * 1. Origin Lifetime Stats - 4 stat cards (Avg, Median, Min, Max)
 * 2. Lifetime Distribution - Horizontal bar chart with buckets
 * 3. Time Series - Origins and Shards over time (30 days)
 */
function AnalyticsTab() {
    // Fetch origin lifetime statistics
    const {
        data: lifetimeStats,
        loading: statsLoading,
        error: statsError
    } = useQuery('origin_lifetime_stats', {}, {
        refreshInterval: REFRESH_INTERVALS.SLOW
    });

    // Fetch lifetime distribution data
    const {
        data: distributionData,
        loading: distributionLoading,
        error: distributionError
    } = useQuery('origin_lifetime_distribution', {}, {
        refreshInterval: REFRESH_INTERVALS.SLOW
    });

    // Fetch origins over time
    const {
        data: originsOverTime,
        loading: originsLoading,
        error: originsError
    } = useQuery('origin_count_over_time', {}, {
        refreshInterval: REFRESH_INTERVALS.SLOW
    });

    // Fetch shards over time
    const {
        data: shardsOverTime,
        loading: shardsLoading,
        error: shardsError
    } = useQuery('shard_count_over_time', {}, {
        refreshInterval: REFRESH_INTERVALS.SLOW
    });

    // Check for any errors
    const hasError = statsError || distributionError || originsError || shardsError;

    return React.createElement('div', null,
        // Error banner if any query failed
        hasError && React.createElement('div', {
            className: 'card',
            style: {
                marginBottom: 'var(--space-6)',
                borderColor: 'hsl(var(--destructive))',
                background: 'hsl(var(--destructive) / 0.1)'
            }
        },
            React.createElement('div', { className: 'card-content' },
                React.createElement('div', {
                    style: {
                        display: 'flex',
                        alignItems: 'center',
                        gap: 'var(--space-2)',
                        color: 'hsl(var(--destructive))'
                    }
                },
                    React.createElement('span', { style: { fontWeight: 500 } }, 'Error loading data:'),
                    React.createElement('span', null,
                        statsError || distributionError || originsError || shardsError
                    )
                )
            )
        ),

        // Lifetime Stats Section (4 cards in a row)
        React.createElement(LifetimeStatsSection, {
            data: lifetimeStats,
            loading: statsLoading
        }),

        // Two column layout: Distribution + Time Series
        React.createElement('div', {
            className: 'content-grid',
            style: {
                display: 'grid',
                gridTemplateColumns: 'minmax(300px, 1fr) minmax(400px, 1.5fr)',
                gap: 'var(--space-6)'
            }
        },
            // Lifetime Distribution Chart (left column)
            React.createElement(LifetimeDistributionBars, {
                data: distributionData,
                loading: distributionLoading
            }),

            // Time Series Charts (right column)
            React.createElement(TimeSeriesSection, {
                originsData: originsOverTime,
                shardsData: shardsOverTime,
                originsLoading: originsLoading,
                shardsLoading: shardsLoading
            })
        )
    );
}

// =============================================================================
// EXPORTS
// =============================================================================

// Export for use by Layout.js
if (typeof window !== 'undefined') {
    window.AnalyticsTab = AnalyticsTab;
}
