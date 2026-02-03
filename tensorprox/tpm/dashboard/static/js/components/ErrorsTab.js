// ErrorsTab.js - Errors Tab Component
// Displays system errors with Last 5 Errors table, Error Categories summary, and Errors Over Time chart
// Includes drill-down sheet for viewing errors by category

const { useState, useMemo, useCallback } = React;

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Color mapping for error sources - matches CHART_COLORS from Charts.js
 */
const ERROR_SOURCE_COLORS = {
    target_selection: 'hsl(0, 84%, 60%)',      // Red - critical path errors
    capacity_check: 'hsl(25, 95%, 53%)',       // Orange - resource constraints
    api_validation: 'hsl(48, 96%, 53%)',       // Yellow - client errors
    geolocation: 'hsl(271, 81%, 56%)',         // Purple - external service
    queue: 'hsl(217, 91%, 60%)',               // Blue - internal system
    metrics: 'hsl(215, 14%, 34%)'              // Gray - observability
};

/**
 * Human-readable labels for error sources
 */
const ERROR_SOURCE_LABELS = {
    target_selection: 'Target Selection',
    capacity_check: 'Capacity Check',
    api_validation: 'API Validation',
    geolocation: 'Geolocation',
    queue: 'Queue',
    metrics: 'Metrics'
};

/**
 * Descriptions for error sources (shown in drill-down)
 */
const ERROR_SOURCE_DESCRIPTIONS = {
    target_selection: 'Errors when selecting miners for deployment',
    capacity_check: 'Errors checking miner capacity and node availability',
    api_validation: 'Invalid API requests (400 errors)',
    geolocation: 'MaxMind database download, load, or lookup failures',
    queue: 'Validation queue overflow errors',
    metrics: 'Metrics forwarder failures'
};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

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
 * Gets the badge variant class for an error category
 * @param {string} category - Error category (system or deployment)
 * @returns {string} CSS class for badge styling
 */
function getCategoryBadgeClass(category) {
    if (category === 'system') {
        return 'badge-destructive';
    }
    return 'badge-secondary';
}

/**
 * Gets the color for an error source
 * @param {string} source - Error source name
 * @returns {string} HSL color string
 */
function getSourceColor(source) {
    return ERROR_SOURCE_COLORS[source] || 'hsl(215, 14%, 34%)';
}

// =============================================================================
// ERROR ROW DETAIL COMPONENT
// =============================================================================

/**
 * Expandable detail view for an error row in the drill-down sheet
 */
function ErrorRowDetail({ error }) {
    const hasContext = error.context && Object.keys(error.context).length > 0;
    const hasRelatedEntities = error.miner_id || error.origin_id || error.exit_hub_id;

    return React.createElement('div', {
        style: {
            padding: 'var(--space-4)',
            background: 'hsl(var(--muted))',
            borderRadius: 'var(--radius)',
            fontSize: '0.8125rem'
        }
    },
        // Error message (full)
        React.createElement('div', { style: { marginBottom: 'var(--space-3)' } },
            React.createElement('strong', { style: { color: 'hsl(var(--foreground))' } }, 'Message:'),
            React.createElement('p', {
                style: {
                    marginTop: 'var(--space-1)',
                    color: 'hsl(var(--muted-foreground))',
                    wordBreak: 'break-word'
                }
            }, error.error_message)
        ),

        // Related entities
        hasRelatedEntities && React.createElement('div', { style: { marginBottom: 'var(--space-3)' } },
            React.createElement('strong', { style: { color: 'hsl(var(--foreground))' } }, 'Related Entities:'),
            React.createElement('div', {
                style: {
                    marginTop: 'var(--space-1)',
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: 'var(--space-2)'
                }
            },
                error.miner_id && React.createElement('span', {
                    className: 'badge',
                    style: { fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }
                }, 'Miner: ', error.miner_id.substring(0, 8)),
                error.origin_id && React.createElement('span', {
                    className: 'badge',
                    style: { fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }
                }, 'Origin: ', error.origin_id.substring(0, 8)),
                error.exit_hub_id && React.createElement('span', {
                    className: 'badge',
                    style: { fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }
                }, 'Exit Hub: ', error.exit_hub_id.substring(0, 8))
            )
        ),

        // Context JSON
        hasContext && React.createElement('div', null,
            React.createElement('strong', { style: { color: 'hsl(var(--foreground))' } }, 'Context:'),
            React.createElement('pre', {
                style: {
                    marginTop: 'var(--space-1)',
                    padding: 'var(--space-3)',
                    background: 'hsl(var(--background))',
                    borderRadius: 'var(--radius)',
                    fontSize: '0.75rem',
                    overflow: 'auto',
                    maxHeight: '200px',
                    border: '1px solid hsl(var(--border))'
                }
            }, JSON.stringify(error.context, null, 2))
        ),

        // Timestamp (full)
        React.createElement('div', { style: { marginTop: 'var(--space-3)' } },
            React.createElement('span', {
                style: { color: 'hsl(var(--muted-foreground))', fontSize: '0.75rem' }
            }, 'Occurred: ', new Date(error.created_at).toLocaleString())
        )
    );
}

// =============================================================================
// ERROR DETAILS SHEET CONTENT
// =============================================================================

/**
 * Content for the error category drill-down sheet
 * Shows all errors for a selected category
 */
function ErrorCategoryDetails({ category, errors, loading }) {
    // Table columns for drill-down
    const columns = useMemo(() => [
        {
            key: 'created_at',
            header: 'When',
            width: '120px',
            render: (val) => DataTableUtils.formatRelativeTime(val)
        },
        {
            key: 'error_code',
            header: 'Code',
            width: '150px',
            render: (val) => React.createElement('span', {
                className: 'badge badge-outline',
                style: { fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }
            }, val || 'unknown')
        },
        {
            key: 'error_message',
            header: 'Message',
            render: (val) => React.createElement('span', {
                style: {
                    maxWidth: '350px',
                    display: 'block',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                },
                title: val
            }, val)
        }
    ], []);

    // Expandable row renderer
    const expandableRenderer = useCallback((row) => {
        return React.createElement(ErrorRowDetail, { error: row });
    }, []);

    return React.createElement('div', null,
        // Category info header
        React.createElement('div', {
            style: {
                marginBottom: 'var(--space-4)',
                padding: 'var(--space-3)',
                background: 'hsl(var(--muted))',
                borderRadius: 'var(--radius)',
                borderLeft: `4px solid ${getSourceColor(category)}`
            }
        },
            React.createElement('div', {
                style: {
                    fontWeight: 500,
                    marginBottom: 'var(--space-1)',
                    color: 'hsl(var(--foreground))'
                }
            }, ERROR_SOURCE_LABELS[category] || category),
            React.createElement('div', {
                style: {
                    fontSize: '0.8125rem',
                    color: 'hsl(var(--muted-foreground))'
                }
            }, ERROR_SOURCE_DESCRIPTIONS[category] || 'System errors for this category')
        ),

        // Errors table
        React.createElement(DataTable, {
            columns: columns,
            data: errors || [],
            loading: loading,
            emptyMessage: 'No errors in this category',
            expandable: expandableRenderer,
            compact: true,
            sortable: true,
            defaultSort: { key: 'created_at', direction: 'desc' }
        })
    );
}

// =============================================================================
// ERROR CATEGORY CARD COMPONENT
// =============================================================================

/**
 * Individual error category card in the categories list
 * Shows error source name and count, clickable to open drill-down
 */
function ErrorCategoryCard({ category, onClick }) {
    const [isHovered, setIsHovered] = useState(false);
    const color = getSourceColor(category.error_source);
    const label = ERROR_SOURCE_LABELS[category.error_source] || category.error_source;
    const count = category.total_errors || 0;

    return React.createElement('div', {
        onClick: () => onClick(category),
        onMouseEnter: () => setIsHovered(true),
        onMouseLeave: () => setIsHovered(false),
        style: {
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: 'var(--space-3)',
            marginBottom: 'var(--space-2)',
            background: isHovered ? 'hsl(var(--accent))' : 'hsl(var(--muted))',
            borderRadius: 'var(--radius)',
            borderLeft: `4px solid ${color}`,
            cursor: 'pointer',
            transition: 'background 0.2s ease'
        },
        role: 'button',
        tabIndex: 0,
        onKeyDown: (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onClick(category);
            }
        },
        'aria-label': `View ${label} errors (${count} total)`
    },
        React.createElement('span', {
            style: {
                fontWeight: 500,
                color: 'hsl(var(--foreground))'
            }
        }, label),
        React.createElement('span', {
            className: count > 0 ? 'badge badge-secondary' : 'badge badge-outline',
            style: {
                minWidth: '2.5rem',
                textAlign: 'center'
            }
        }, count)
    );
}

// =============================================================================
// MAIN ERRORS TAB COMPONENT
// =============================================================================

/**
 * ErrorsTab Component
 *
 * Main errors monitoring view with three sections:
 * 1. Last 5 Errors - Recent errors across all sources
 * 2. Error Categories - Summary counts by error source (clickable for drill-down)
 * 3. Errors Over Time - 30-day area chart showing error volume
 */
function ErrorsTab() {
    // Sheet state for drill-down
    const sheet = useSheet();
    const [selectedCategory, setSelectedCategory] = useState(null);

    // Fetch last 5 errors (real-time refresh)
    const {
        data: last5Errors,
        loading: errorsLoading,
        error: errorsError
    } = useQuery('last_5_errors', {}, {
        refreshInterval: REFRESH_INTERVALS.REALTIME
    });

    // Fetch error categories summary (normal refresh)
    const {
        data: categorySummary,
        loading: categoryLoading,
        error: categoryError
    } = useQuery('error_categories_summary', {}, {
        refreshInterval: REFRESH_INTERVALS.NEAR_REALTIME
    });

    // Fetch errors over time for chart (slow refresh)
    const {
        data: errorsOverTime,
        loading: chartLoading,
        error: chartError
    } = useQuery('errors_over_time_daily', {}, {
        refreshInterval: REFRESH_INTERVALS.SLOW
    });

    // Fetch drill-down data only when a category is selected
    const {
        data: categoryErrors,
        loading: drillLoading
    } = useQuery(
        'errors_by_category_last_7_days',
        { error_source: selectedCategory },
        {
            enabled: !!selectedCategory,
            refreshInterval: REFRESH_INTERVALS.NEAR_REALTIME
        }
    );

    // Handle category click - open drill-down sheet
    const handleCategoryClick = useCallback((category) => {
        setSelectedCategory(category.error_source);
        sheet.open(category);
    }, [sheet]);

    // Handle sheet close
    const handleSheetClose = useCallback(() => {
        sheet.close();
        // Clear selection after animation
        setTimeout(() => setSelectedCategory(null), 300);
    }, [sheet]);

    // Table columns for last 5 errors
    const errorColumns = useMemo(() => [
        {
            key: 'error_timestamp',
            header: 'When',
            width: '100px',
            sortable: true,
            render: (val) => React.createElement('span', {
                title: val ? new Date(val).toLocaleString() : '',
                style: { whiteSpace: 'nowrap' }
            }, DataTableUtils.formatRelativeTime(val))
        },
        {
            key: 'error_category',
            header: 'Category',
            width: '100px',
            render: (val) => React.createElement('span', {
                className: `badge ${getCategoryBadgeClass(val)}`
            }, val || 'unknown')
        },
        {
            key: 'error_source',
            header: 'Source',
            width: '130px',
            render: (val) => React.createElement('span', {
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
                        backgroundColor: getSourceColor(val),
                        flexShrink: 0
                    }
                }),
                ERROR_SOURCE_LABELS[val] || val
            )
        },
        {
            key: 'error_code',
            header: 'Code',
            width: '120px',
            render: (val) => React.createElement('span', {
                className: 'badge badge-outline',
                style: {
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.75rem'
                }
            }, val || '-')
        },
        {
            key: 'error_message',
            header: 'Message',
            render: (val) => React.createElement('span', {
                style: {
                    maxWidth: '300px',
                    display: 'block',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                },
                title: val
            }, val || '-')
        }
    ], []);

    // Sort categories by error count descending
    const sortedCategories = useMemo(() => {
        if (!categorySummary) return [];
        return [...categorySummary].sort((a, b) =>
            (b.total_errors || 0) - (a.total_errors || 0)
        );
    }, [categorySummary]);

    // Format chart data - ensure dates are sortable
    const chartData = useMemo(() => {
        if (!errorsOverTime) return [];
        return errorsOverTime.map(item => ({
            ...item,
            date: item.date || item.day || item.error_date,
            error_count: item.error_count || item.count || 0
        })).sort((a, b) => new Date(a.date) - new Date(b.date));
    }, [errorsOverTime]);

    return React.createElement('div', null,
        // Last 5 Errors Section
        React.createElement('div', {
            className: 'card',
            style: { marginBottom: 'var(--space-6)' }
        },
            React.createElement('div', { className: 'card-header' },
                React.createElement('div', { className: 'card-title' }, 'Recent Errors'),
                React.createElement('p', { className: 'card-description' },
                    'Last 5 errors across all sources'
                )
            ),
            React.createElement('div', { className: 'card-content' },
                errorsError
                    ? React.createElement('div', {
                        className: 'text-destructive',
                        style: { padding: 'var(--space-4)' }
                    }, 'Failed to load errors: ', errorsError)
                    : React.createElement(DataTable, {
                        columns: errorColumns,
                        data: last5Errors || [],
                        loading: errorsLoading,
                        emptyMessage: 'No recent errors - system is healthy!',
                        compact: true,
                        sortable: true,
                        defaultSort: { key: 'error_timestamp', direction: 'desc' }
                    })
            )
        ),

        // Two column layout for Categories and Chart
        React.createElement('div', {
            className: 'content-grid',
            style: {
                display: 'grid',
                gridTemplateColumns: 'minmax(280px, 1fr) minmax(400px, 2fr)',
                gap: 'var(--space-6)'
            }
        },
            // Error Categories Card
            React.createElement('div', { className: 'card' },
                React.createElement('div', { className: 'card-header' },
                    React.createElement('div', { className: 'card-title' }, 'Error Categories'),
                    React.createElement('p', { className: 'card-description' },
                        'Click to view details'
                    )
                ),
                React.createElement('div', { className: 'card-content' },
                    categoryError
                        ? React.createElement('div', {
                            className: 'text-destructive',
                            style: { padding: 'var(--space-4)' }
                        }, 'Failed to load categories')
                        : categoryLoading
                            ? React.createElement('div', null,
                                [...Array(6)].map((_, i) =>
                                    React.createElement('div', {
                                        key: i,
                                        className: 'skeleton',
                                        style: {
                                            height: '2.75rem',
                                            marginBottom: 'var(--space-2)',
                                            borderRadius: 'var(--radius)'
                                        }
                                    })
                                )
                            )
                            : sortedCategories.length === 0
                                ? React.createElement('div', {
                                    className: 'empty-state',
                                    style: { padding: 'var(--space-6)' }
                                },
                                    React.createElement('div', { className: 'empty-state-title' },
                                        'No error categories'
                                    )
                                )
                                : React.createElement('div', null,
                                    sortedCategories.map(cat =>
                                        React.createElement(ErrorCategoryCard, {
                                            key: cat.error_source,
                                            category: cat,
                                            onClick: handleCategoryClick
                                        })
                                    )
                                )
                )
            ),

            // Errors Over Time Chart
            React.createElement(SimpleAreaChart, {
                title: 'Errors Over Time',
                description: 'Daily error count (30 days)',
                data: chartData,
                xKey: 'date',
                yKey: 'error_count',
                color: CHART_COLORS.error,
                loading: chartLoading,
                height: 280,
                xFormatter: formatChartDate,
                tooltipFormatter: (value) => [`${value} error${value !== 1 ? 's' : ''}`, 'Count']
            })
        ),

        // Drill-down Sheet
        React.createElement(Sheet, {
            open: sheet.isOpen,
            onClose: handleSheetClose,
            title: selectedCategory
                ? `${ERROR_SOURCE_LABELS[selectedCategory] || selectedCategory} Errors`
                : 'Error Details',
            description: 'Last 7 days',
            size: 'lg',
            side: 'right'
        },
            React.createElement(ErrorCategoryDetails, {
                category: selectedCategory,
                errors: categoryErrors,
                loading: drillLoading
            })
        )
    );
}

// =============================================================================
// EXPORTS
// =============================================================================

// Export for use by Layout.js
if (typeof window !== 'undefined') {
    window.ErrorsTab = ErrorsTab;
}
