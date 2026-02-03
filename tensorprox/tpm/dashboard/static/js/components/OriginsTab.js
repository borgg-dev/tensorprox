// OriginsTab.js - Origins Tab Component
// Displays customer deployments - lifecycle, configuration, status
// Includes Lifecycle Summary (donut chart), Egress Summary stats, and Origin List table with filters

const { useState, useMemo, useCallback } = React;

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Color mapping for lifecycle states - matches CHART_COLORS from Charts.js
 */
const LIFECYCLE_COLORS = {
    ACTIVE: CHART_COLORS.active,       // Green
    DEPLOYING: CHART_COLORS.deploying, // Cyan/Blue
    DELETED: CHART_COLORS.deleted,     // Gray
    FAILED: CHART_COLORS.failed,       // Red
    UNKNOWN: CHART_COLORS.muted        // Muted gray
};

/**
 * Human-readable labels for lifecycle states
 */
const LIFECYCLE_LABELS = {
    ACTIVE: 'Active',
    DEPLOYING: 'Deploying',
    DELETED: 'Deleted',
    FAILED: 'Failed',
    UNKNOWN: 'Unknown'
};

/**
 * Filter options for lifecycle state
 */
const LIFECYCLE_FILTERS = [
    { value: 'all', label: 'All' },
    { value: 'ACTIVE', label: 'Active' },
    { value: 'DEPLOYING', label: 'Deploying' },
    { value: 'DELETED', label: 'Deleted' },
    { value: 'FAILED', label: 'Failed' }
];

/**
 * Filter options for egress status
 */
const EGRESS_FILTERS = [
    { value: 'all', label: 'All' },
    { value: 'enabled', label: 'Enabled' },
    { value: 'disabled', label: 'Disabled' }
];

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Truncates a string (typically UUID) with ellipsis
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
 * Gets the badge variant class for a lifecycle state
 * @param {string} state - Lifecycle state
 * @returns {string} CSS class for badge styling
 */
function getLifecycleBadgeClass(state) {
    switch (state) {
        case 'ACTIVE':
            return 'badge-success';
        case 'DEPLOYING':
            return 'badge-info';
        case 'FAILED':
            return 'badge-destructive';
        case 'DELETED':
            return 'badge-secondary';
        default:
            return 'badge-outline';
    }
}

/**
 * Gets the color for a lifecycle state
 * @param {string} state - Lifecycle state
 * @returns {string} HSL color string
 */
function getLifecycleColor(state) {
    return LIFECYCLE_COLORS[state] || LIFECYCLE_COLORS.UNKNOWN;
}

// =============================================================================
// FILTER BUTTON COMPONENT
// =============================================================================

/**
 * Individual filter button for filter groups
 */
function FilterButton({ label, active, onClick }) {
    return React.createElement('button', {
        className: `btn btn-sm ${active ? 'btn-primary' : 'btn-outline'}`,
        onClick: onClick,
        style: {
            transition: 'all 0.15s ease'
        }
    }, label);
}

/**
 * Filter button group component
 */
function FilterGroup({ label, filters, activeValue, onChange }) {
    return React.createElement('div', {
        style: {
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-2)'
        }
    },
        label && React.createElement('span', {
            style: {
                fontSize: '0.8125rem',
                color: 'hsl(var(--muted-foreground))',
                marginRight: 'var(--space-2)'
            }
        }, label),
        React.createElement('div', {
            style: {
                display: 'flex',
                gap: 'var(--space-1)'
            }
        },
            filters.map(filter =>
                React.createElement(FilterButton, {
                    key: filter.value,
                    label: filter.label,
                    active: activeValue === filter.value,
                    onClick: () => onChange(filter.value)
                })
            )
        )
    );
}

// =============================================================================
// LIFECYCLE SUMMARY COMPONENT
// =============================================================================

/**
 * Displays lifecycle state summary as a donut chart with counts
 */
function LifecycleSummary({ data, loading }) {
    // Transform data for donut chart
    const chartData = useMemo(() => {
        if (!data || data.length === 0) return [];
        return data.map(item => ({
            lifecycle_state: item.lifecycle_state || 'UNKNOWN',
            count: item.count || 0
        }));
    }, [data]);

    // Calculate total for center display
    const total = useMemo(() => {
        return chartData.reduce((sum, item) => sum + item.count, 0);
    }, [chartData]);

    // Create color mapping for donut chart
    const colorMapping = useMemo(() => {
        const colors = {};
        chartData.forEach(item => {
            colors[item.lifecycle_state] = getLifecycleColor(item.lifecycle_state);
        });
        return colors;
    }, [chartData]);

    // Center content for donut
    const centerContent = React.createElement('div', null,
        React.createElement('div', {
            style: {
                fontSize: '1.5rem',
                fontWeight: 600,
                color: 'hsl(var(--foreground))'
            }
        }, total),
        React.createElement('div', {
            style: {
                fontSize: '0.75rem',
                color: 'hsl(var(--muted-foreground))'
            }
        }, 'Total Origins')
    );

    return React.createElement(DonutChart, {
        data: chartData,
        nameKey: 'lifecycle_state',
        valueKey: 'count',
        colors: colorMapping,
        title: 'Lifecycle Summary',
        description: 'Origins by deployment state',
        loading: loading,
        height: 250,
        innerRadius: 50,
        outerRadius: 80,
        showLegend: true,
        showLabels: false,
        centerContent: centerContent
    });
}

// =============================================================================
// EGRESS SUMMARY COMPONENT
// =============================================================================

/**
 * Displays egress configuration summary as stat cards
 */
function EgressSummary({ data, loading }) {
    // Extract stats from data (single row returned from egress_summary query)
    const stats = useMemo(() => {
        if (!data || data.length === 0) {
            return {
                total: 0,
                enabled: 0,
                disabled: 0,
                activated: 0
            };
        }
        const row = data[0];
        return {
            total: row.total_origins || 0,
            enabled: row.egress_enabled_count || 0,
            disabled: row.egress_disabled_count || 0,
            activated: row.egress_activated_count || 0
        };
    }, [data]);

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
                            height: '2.5rem',
                            marginBottom: 'var(--space-3)',
                            borderRadius: 'var(--radius)'
                        }
                    })
                )
            )
        );
    }

    return React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-header' },
            React.createElement('div', { className: 'card-title' }, 'Egress Status'),
            React.createElement('p', { className: 'card-description' }, 'Egress routing configuration')
        ),
        React.createElement('div', { className: 'card-content' },
            // Enabled stat
            React.createElement('div', {
                style: {
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: 'var(--space-3)',
                    marginBottom: 'var(--space-2)',
                    background: 'hsl(var(--muted))',
                    borderRadius: 'var(--radius)',
                    borderLeft: `4px solid ${CHART_COLORS.active}`
                }
            },
                React.createElement('span', {
                    style: {
                        fontWeight: 500,
                        color: 'hsl(var(--foreground))'
                    }
                }, 'Enabled'),
                React.createElement('span', {
                    className: 'badge badge-success'
                }, stats.enabled)
            ),
            // Disabled stat
            React.createElement('div', {
                style: {
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: 'var(--space-3)',
                    marginBottom: 'var(--space-2)',
                    background: 'hsl(var(--muted))',
                    borderRadius: 'var(--radius)',
                    borderLeft: `4px solid ${CHART_COLORS.muted}`
                }
            },
                React.createElement('span', {
                    style: {
                        fontWeight: 500,
                        color: 'hsl(var(--foreground))'
                    }
                }, 'Disabled'),
                React.createElement('span', {
                    className: 'badge badge-secondary'
                }, stats.disabled)
            ),
            // Activated stat
            React.createElement('div', {
                style: {
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: 'var(--space-3)',
                    background: 'hsl(var(--muted))',
                    borderRadius: 'var(--radius)',
                    borderLeft: `4px solid ${CHART_COLORS.info}`
                }
            },
                React.createElement('span', {
                    style: {
                        fontWeight: 500,
                        color: 'hsl(var(--foreground))'
                    }
                }, 'Activated'),
                React.createElement('span', {
                    className: 'badge badge-info',
                    title: 'Origins with egress activation timestamp'
                }, stats.activated)
            )
        )
    );
}

// =============================================================================
// EGRESS TOGGLE INDICATOR COMPONENT
// =============================================================================

/**
 * Visual indicator for egress enabled/disabled status
 */
function EgressIndicator({ enabled }) {
    return React.createElement('div', {
        style: {
            display: 'inline-flex',
            alignItems: 'center',
            gap: 'var(--space-2)'
        }
    },
        React.createElement('span', {
            style: {
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: enabled ? CHART_COLORS.active : CHART_COLORS.muted,
                flexShrink: 0
            }
        }),
        React.createElement('span', {
            style: {
                fontSize: '0.8125rem',
                color: enabled ? 'hsl(var(--foreground))' : 'hsl(var(--muted-foreground))'
            }
        }, enabled ? 'ON' : 'OFF')
    );
}

// =============================================================================
// ORIGIN DETAIL COMPONENT (for expandable row)
// =============================================================================

/**
 * Expanded content showing full origin details
 */
function OriginDetail({ origin }) {
    const hasError = origin.deletion_error;

    return React.createElement('div', {
        style: {
            padding: 'var(--space-4)',
            background: 'hsl(var(--muted))',
            borderRadius: 'var(--radius)',
            fontSize: '0.8125rem'
        }
    },
        // Two column layout for details
        React.createElement('div', {
            style: {
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 'var(--space-4)'
            }
        },
            // Left column
            React.createElement('div', null,
                // Origin ID (full)
                React.createElement('div', { style: { marginBottom: 'var(--space-3)' } },
                    React.createElement('strong', { style: { color: 'hsl(var(--foreground))' } }, 'Origin ID:'),
                    React.createElement('p', {
                        style: {
                            marginTop: 'var(--space-1)',
                            fontFamily: 'var(--font-mono)',
                            fontSize: '0.75rem',
                            wordBreak: 'break-all'
                        }
                    }, origin.origin_id || '-')
                ),
                // TensorProx IP
                React.createElement('div', { style: { marginBottom: 'var(--space-3)' } },
                    React.createElement('strong', { style: { color: 'hsl(var(--foreground))' } }, 'TensorProx IP:'),
                    React.createElement('p', {
                        style: {
                            marginTop: 'var(--space-1)',
                            fontFamily: 'var(--font-mono)'
                        }
                    }, origin.tensorprox_ip || '-')
                ),
                // Miner ID (full)
                React.createElement('div', null,
                    React.createElement('strong', { style: { color: 'hsl(var(--foreground))' } }, 'Miner ID:'),
                    React.createElement('p', {
                        style: {
                            marginTop: 'var(--space-1)',
                            fontFamily: 'var(--font-mono)',
                            fontSize: '0.75rem',
                            wordBreak: 'break-all'
                        }
                    }, origin.miner_id || '-')
                )
            ),
            // Right column
            React.createElement('div', null,
                // Status
                React.createElement('div', { style: { marginBottom: 'var(--space-3)' } },
                    React.createElement('strong', { style: { color: 'hsl(var(--foreground))' } }, 'Raw Status:'),
                    React.createElement('p', {
                        style: { marginTop: 'var(--space-1)' }
                    },
                        React.createElement('span', {
                            className: 'badge badge-outline'
                        }, origin.origin_status || '-')
                    )
                ),
                // Egress enabled
                React.createElement('div', { style: { marginBottom: 'var(--space-3)' } },
                    React.createElement('strong', { style: { color: 'hsl(var(--foreground))' } }, 'Egress Enabled:'),
                    React.createElement('p', {
                        style: { marginTop: 'var(--space-1)' }
                    }, origin.egress_enabled ? 'Yes' : 'No')
                ),
                // Timestamps
                React.createElement('div', null,
                    React.createElement('strong', { style: { color: 'hsl(var(--foreground))' } }, 'Created:'),
                    React.createElement('p', {
                        style: {
                            marginTop: 'var(--space-1)',
                            color: 'hsl(var(--muted-foreground))'
                        }
                    }, origin.created_at ? new Date(origin.created_at).toLocaleString() : '-')
                )
            )
        ),

        // Deletion error (if present)
        hasError && React.createElement('div', {
            style: {
                marginTop: 'var(--space-4)',
                padding: 'var(--space-3)',
                background: 'hsl(var(--destructive) / 0.1)',
                borderRadius: 'var(--radius)',
                borderLeft: `4px solid ${CHART_COLORS.failed}`
            }
        },
            React.createElement('strong', {
                style: { color: 'hsl(var(--destructive))' }
            }, 'Deletion Error:'),
            React.createElement('p', {
                style: {
                    marginTop: 'var(--space-1)',
                    color: 'hsl(var(--foreground))',
                    wordBreak: 'break-word'
                }
            }, origin.deletion_error)
        )
    );
}

// =============================================================================
// ORIGIN LIST TABLE COMPONENT
// =============================================================================

/**
 * Main origin list table with filters and sorting
 */
function OriginListTable({ data, loading }) {
    // Filter state
    const [lifecycleFilter, setLifecycleFilter] = useState('all');
    const [egressFilter, setEgressFilter] = useState('all');

    // Table columns
    const columns = useMemo(() => [
        {
            key: 'origin_id',
            header: 'Origin ID',
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
            key: 'client_id',
            header: 'Client',
            width: '90px',
            sortable: true,
            render: (val) => React.createElement('span', {
                className: 'badge badge-outline',
                style: { fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }
            }, val || '-')
        },
        {
            key: 'lifecycle_state',
            header: 'Status',
            width: '110px',
            sortable: true,
            render: (val) => React.createElement('span', {
                className: `badge ${getLifecycleBadgeClass(val)}`,
                style: {
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 'var(--space-1)'
                }
            },
                React.createElement('span', {
                    style: {
                        width: '6px',
                        height: '6px',
                        borderRadius: '50%',
                        backgroundColor: 'currentColor'
                    }
                }),
                LIFECYCLE_LABELS[val] || val || 'Unknown'
            )
        },
        {
            key: 'egress_enabled',
            header: 'Egress',
            width: '80px',
            sortable: true,
            render: (val) => React.createElement(EgressIndicator, { enabled: val })
        },
        {
            key: 'miner_id',
            header: 'Miner',
            width: '100px',
            render: (val) => val
                ? React.createElement('span', {
                    className: 'tooltip tooltip-top',
                    style: { fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }
                },
                    React.createElement('span', { className: 'tooltip-trigger' }, truncateString(val, 8)),
                    React.createElement('span', { className: 'tooltip-content' }, val)
                )
                : React.createElement('span', { className: 'text-muted' }, '-')
        },
        {
            key: 'shard_id',
            header: 'Shard',
            width: '100px',
            render: (val) => val
                ? React.createElement('span', {
                    style: { fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' },
                    title: val
                }, truncateString(val, 8))
                : React.createElement('span', { className: 'text-muted' }, '-')
        },
        {
            key: 'created_at',
            header: 'Age',
            width: '100px',
            sortable: true,
            render: (val) => React.createElement('span', {
                style: { fontSize: '0.8125rem' },
                title: val ? new Date(val).toLocaleString() : ''
            }, DataTableUtils.formatRelativeTime(val))
        }
    ], []);

    // Apply filters to data
    const filteredData = useMemo(() => {
        if (!data) return [];

        return data.filter(origin => {
            // Lifecycle filter
            if (lifecycleFilter !== 'all') {
                if (origin.lifecycle_state !== lifecycleFilter) {
                    return false;
                }
            }

            // Egress filter
            if (egressFilter !== 'all') {
                const egressEnabled = origin.egress_enabled;
                if (egressFilter === 'enabled' && !egressEnabled) {
                    return false;
                }
                if (egressFilter === 'disabled' && egressEnabled) {
                    return false;
                }
            }

            return true;
        });
    }, [data, lifecycleFilter, egressFilter]);

    // Expandable row renderer
    const expandableRenderer = useCallback((row) => {
        return React.createElement(OriginDetail, { origin: row });
    }, []);

    // Calculate filter counts for display
    const filterCounts = useMemo(() => {
        if (!data) return {};
        return {
            all: data.length,
            ACTIVE: data.filter(o => o.lifecycle_state === 'ACTIVE').length,
            DEPLOYING: data.filter(o => o.lifecycle_state === 'DEPLOYING').length,
            DELETED: data.filter(o => o.lifecycle_state === 'DELETED').length,
            FAILED: data.filter(o => o.lifecycle_state === 'FAILED').length,
            enabled: data.filter(o => o.egress_enabled).length,
            disabled: data.filter(o => !o.egress_enabled).length
        };
    }, [data]);

    return React.createElement('div', { className: 'card' },
        React.createElement('div', { className: 'card-header' },
            React.createElement('div', {
                style: {
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'flex-start',
                    flexWrap: 'wrap',
                    gap: 'var(--space-4)'
                }
            },
                React.createElement('div', null,
                    React.createElement('div', { className: 'card-title' }, 'Origin List'),
                    React.createElement('p', { className: 'card-description' },
                        `Showing ${filteredData.length} of ${data?.length || 0} origins`
                    )
                ),
                // Filters
                React.createElement('div', {
                    style: {
                        display: 'flex',
                        gap: 'var(--space-6)',
                        flexWrap: 'wrap'
                    }
                },
                    // Lifecycle filter
                    React.createElement(FilterGroup, {
                        label: 'Status:',
                        filters: LIFECYCLE_FILTERS.map(f => ({
                            ...f,
                            label: f.value === 'all' ? 'All' : `${f.label} (${filterCounts[f.value] || 0})`
                        })),
                        activeValue: lifecycleFilter,
                        onChange: setLifecycleFilter
                    }),
                    // Egress filter
                    React.createElement(FilterGroup, {
                        label: 'Egress:',
                        filters: EGRESS_FILTERS.map(f => ({
                            ...f,
                            label: f.value === 'all' ? 'All' : `${f.label} (${filterCounts[f.value] || 0})`
                        })),
                        activeValue: egressFilter,
                        onChange: setEgressFilter
                    })
                )
            )
        ),
        React.createElement('div', { className: 'card-content' },
            React.createElement(DataTable, {
                columns: columns,
                data: filteredData,
                loading: loading,
                emptyMessage: lifecycleFilter === 'all' && egressFilter === 'all'
                    ? 'No origins found'
                    : 'No origins match the current filters',
                expandable: expandableRenderer,
                compact: true,
                sortable: true,
                defaultSort: { key: 'created_at', direction: 'desc' }
            })
        )
    );
}

// =============================================================================
// MAIN ORIGINS TAB COMPONENT
// =============================================================================

/**
 * OriginsTab Component
 *
 * Main origins monitoring view with sections:
 * 1. Lifecycle Summary - Donut chart showing ACTIVE, DEPLOYING, DELETED counts
 * 2. Egress Summary - Stats showing enabled/disabled/activated counts
 * 3. Origin List - Filterable/sortable table with all origin details
 */
function OriginsTab() {
    // Fetch lifecycle summary (origin_trace)
    const {
        data: lifecycleData,
        loading: lifecycleLoading,
        error: lifecycleError
    } = useQuery('origin_trace', {}, {
        refreshInterval: REFRESH_INTERVALS.origin_trace
    });

    // Fetch egress summary
    const {
        data: egressData,
        loading: egressLoading,
        error: egressError
    } = useQuery('egress_summary', {}, {
        refreshInterval: REFRESH_INTERVALS.egress_summary
    });

    // Fetch detailed origin list
    const {
        data: originData,
        loading: originLoading,
        error: originError
    } = useQuery('origin_trace_detailed', {}, {
        refreshInterval: REFRESH_INTERVALS.origin_trace_detailed
    });

    return React.createElement('div', null,
        // Summary row - Lifecycle donut and Egress stats side by side
        React.createElement('div', {
            style: {
                display: 'grid',
                gridTemplateColumns: 'minmax(320px, 1fr) minmax(280px, 1fr)',
                gap: 'var(--space-6)',
                marginBottom: 'var(--space-6)'
            }
        },
            // Lifecycle Summary (Donut Chart)
            lifecycleError
                ? React.createElement('div', { className: 'card' },
                    React.createElement('div', { className: 'card-content' },
                        React.createElement('div', {
                            className: 'text-destructive',
                            style: { padding: 'var(--space-4)' }
                        }, 'Failed to load lifecycle summary: ', lifecycleError)
                    )
                )
                : React.createElement(LifecycleSummary, {
                    data: lifecycleData,
                    loading: lifecycleLoading
                }),

            // Egress Summary (Stats)
            egressError
                ? React.createElement('div', { className: 'card' },
                    React.createElement('div', { className: 'card-content' },
                        React.createElement('div', {
                            className: 'text-destructive',
                            style: { padding: 'var(--space-4)' }
                        }, 'Failed to load egress summary: ', egressError)
                    )
                )
                : React.createElement(EgressSummary, {
                    data: egressData,
                    loading: egressLoading
                })
        ),

        // Origin List Table (full width)
        originError
            ? React.createElement('div', { className: 'card' },
                React.createElement('div', { className: 'card-content' },
                    React.createElement('div', {
                        className: 'text-destructive',
                        style: { padding: 'var(--space-4)' }
                    }, 'Failed to load origin list: ', originError)
                )
            )
            : React.createElement(OriginListTable, {
                data: originData,
                loading: originLoading
            })
    );
}

// =============================================================================
// EXPORTS
// =============================================================================

// Export for use by Layout.js
if (typeof window !== 'undefined') {
    window.OriginsTab = OriginsTab;
}
