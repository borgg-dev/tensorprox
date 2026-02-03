// DataTable.js - Reusable Data Table Component
// Displays tabular data with sorting, filtering, expandable rows, and loading states

const { useState, useMemo } = React;

// =============================================================================
// UTILITY FUNCTIONS (exported for use by other components)
// =============================================================================

/**
 * Formats a UUID to show first 8 characters with full value accessible via title attribute
 * @param {string} uuid - The UUID to format
 * @returns {string} Truncated UUID or '-' if empty
 */
function formatUUID(uuid) {
    if (!uuid) return '-';
    return uuid.substring(0, 8);
}

/**
 * Formats a timestamp as relative time (e.g., "2 min ago", "1 hour ago")
 * @param {string|Date} timestamp - The timestamp to format
 * @returns {string} Relative time string or '-' if empty
 */
function formatRelativeTime(timestamp) {
    if (!timestamp) return '-';

    const date = new Date(timestamp);
    if (isNaN(date.getTime())) return '-';

    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    // Handle future dates
    if (diff < 0) {
        const absDiff = Math.abs(diff);
        if (absDiff < 60) return 'in a moment';
        if (absDiff < 3600) return `in ${Math.floor(absDiff / 60)} min`;
        if (absDiff < 86400) {
            const hours = Math.floor(absDiff / 3600);
            return `in ${hours} hour${hours > 1 ? 's' : ''}`;
        }
        return date.toLocaleDateString();
    }

    // Past dates
    if (diff < 60) return 'just now';
    if (diff < 3600) {
        const mins = Math.floor(diff / 60);
        return `${mins} min${mins > 1 ? 's' : ''} ago`;
    }
    if (diff < 86400) {
        const hours = Math.floor(diff / 3600);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    }
    if (diff < 604800) {
        const days = Math.floor(diff / 86400);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }

    return date.toLocaleDateString();
}

/**
 * Formats a timestamp as a readable date string
 * @param {string|Date} timestamp - The timestamp to format
 * @returns {string} Formatted date string or '-' if empty
 */
function formatDate(timestamp) {
    if (!timestamp) return '-';

    const date = new Date(timestamp);
    if (isNaN(date.getTime())) return '-';

    return date.toLocaleString();
}

/**
 * Formats a number with appropriate suffix (K, M, B)
 * @param {number} num - The number to format
 * @returns {string} Formatted number string
 */
function formatNumber(num) {
    if (num === null || num === undefined) return '-';
    if (typeof num !== 'number') return String(num);

    if (num >= 1000000000) {
        return (num / 1000000000).toFixed(1).replace(/\.0$/, '') + 'B';
    }
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
    }
    if (num >= 1000) {
        return (num / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
    }
    return num.toLocaleString();
}

// =============================================================================
// UUID CELL COMPONENT
// =============================================================================

/**
 * Renders a truncated UUID with tooltip showing the full value
 * Uses CSS tooltip for accessibility
 */
function UUIDCell({ uuid }) {
    if (!uuid) return React.createElement('span', { className: 'text-muted' }, '-');

    const truncated = formatUUID(uuid);

    return React.createElement('span', {
        className: 'tooltip tooltip-top',
        style: { fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }
    },
        React.createElement('span', { className: 'tooltip-trigger' }, truncated),
        React.createElement('span', { className: 'tooltip-content' }, uuid)
    );
}

// =============================================================================
// SORT HEADER COMPONENT
// =============================================================================

/**
 * Renders a sortable table header with sort direction indicator
 */
function SortHeader({ column, sortConfig, onSort, sortable }) {
    const isActive = sortConfig.key === column.key;
    const isSortable = sortable && column.sortable !== false;

    const handleClick = () => {
        if (isSortable) {
            onSort(column.key);
        }
    };

    const handleKeyDown = (e) => {
        if (isSortable && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            onSort(column.key);
        }
    };

    const getSortIndicator = () => {
        if (!isActive) return null;
        // Unicode arrows for sort direction
        const arrow = sortConfig.direction === 'asc' ? '\u2191' : '\u2193';
        return React.createElement('span', {
            style: { marginLeft: 'var(--space-2)', color: 'hsl(var(--primary))' },
            'aria-label': sortConfig.direction === 'asc' ? 'sorted ascending' : 'sorted descending'
        }, arrow);
    };

    return React.createElement('th', {
        style: {
            width: column.width,
            cursor: isSortable ? 'pointer' : 'default',
            userSelect: isSortable ? 'none' : 'auto'
        },
        onClick: handleClick,
        onKeyDown: handleKeyDown,
        tabIndex: isSortable ? 0 : undefined,
        role: isSortable ? 'button' : undefined,
        'aria-sort': isActive ? (sortConfig.direction === 'asc' ? 'ascending' : 'descending') : undefined
    },
        React.createElement('span', { className: 'flex items-center gap-1' },
            column.header,
            getSortIndicator()
        )
    );
}

// =============================================================================
// EXPAND BUTTON COMPONENT
// =============================================================================

/**
 * Renders an expand/collapse button for expandable rows
 */
function ExpandButton({ expanded, onClick }) {
    return React.createElement('button', {
        className: 'btn btn-ghost btn-sm btn-icon',
        onClick: (e) => {
            e.stopPropagation();
            onClick();
        },
        'aria-expanded': expanded,
        'aria-label': expanded ? 'Collapse row' : 'Expand row',
        style: {
            width: '1.5rem',
            height: '1.5rem',
            padding: 0,
            transition: 'transform 0.15s ease'
        }
    },
        React.createElement('span', {
            style: {
                display: 'inline-block',
                transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)',
                transition: 'transform 0.15s ease',
                fontSize: '0.75rem'
            }
        }, '\u25B6') // Right-pointing triangle
    );
}

// =============================================================================
// LOADING SKELETON COMPONENT
// =============================================================================

/**
 * Renders a loading skeleton state for the table
 */
function TableSkeleton({ columns, rowCount = 5, compact, expandable }) {
    const colCount = columns.length + (expandable ? 1 : 0);

    return React.createElement('div', { className: 'table-container' },
        React.createElement('table', {
            className: `table ${compact ? 'table-compact' : ''}`,
            role: 'status',
            'aria-busy': 'true',
            'aria-label': 'Loading table data'
        },
            React.createElement('thead', null,
                React.createElement('tr', null,
                    expandable && React.createElement('th', { style: { width: '40px' } },
                        React.createElement('div', { className: 'skeleton', style: { height: '1rem', width: '1rem' } })
                    ),
                    columns.map((col) =>
                        React.createElement('th', { key: col.key, style: { width: col.width } },
                            React.createElement('div', {
                                className: 'skeleton',
                                style: { height: '1rem', width: '60%' }
                            })
                        )
                    )
                )
            ),
            React.createElement('tbody', null,
                [...Array(rowCount)].map((_, rowIdx) =>
                    React.createElement('tr', { key: rowIdx },
                        expandable && React.createElement('td', null,
                            React.createElement('div', { className: 'skeleton', style: { height: '1rem', width: '1rem' } })
                        ),
                        columns.map((col) =>
                            React.createElement('td', { key: col.key },
                                React.createElement('div', {
                                    className: 'skeleton',
                                    style: { height: '1rem', width: `${60 + Math.random() * 30}%` }
                                })
                            )
                        )
                    )
                )
            )
        )
    );
}

// =============================================================================
// EMPTY STATE COMPONENT
// =============================================================================

/**
 * Renders an empty state when no data is available
 */
function TableEmptyState({ message, icon }) {
    return React.createElement('div', { className: 'empty-state' },
        icon && React.createElement('div', {
            className: 'empty-state-icon',
            'aria-hidden': 'true'
        }, icon),
        React.createElement('div', { className: 'empty-state-title' }, message)
    );
}

// =============================================================================
// DATA TABLE COMPONENT
// =============================================================================

/**
 * DataTable Component
 *
 * A reusable table component for displaying data with sorting, expandable rows,
 * loading states, and empty states.
 *
 * @param {Object} props - Component props
 * @param {Array} props.columns - Column definitions: { key, header, render?, sortable?, width? }
 * @param {Array} props.data - Array of row objects
 * @param {boolean} [props.loading=false] - Show loading skeleton
 * @param {string} [props.emptyMessage='No data available'] - Message when no data
 * @param {boolean|Function} [props.expandable=false] - Enable expandable rows or render function
 * @param {Function} [props.onRowClick] - Optional row click handler
 * @param {boolean} [props.sortable=true] - Enable column sorting
 * @param {boolean} [props.compact=false] - Use compact styling
 * @param {string} [props.className] - Additional CSS class for container
 * @param {Function} [props.getRowKey] - Function to get unique key for row (default: index)
 * @param {Object} [props.defaultSort] - Default sort config: { key, direction }
 *
 * @example
 * const columns = [
 *     { key: 'id', header: 'ID', width: '100px' },
 *     { key: 'status', header: 'Status', render: (val) => <Badge>{val}</Badge> },
 *     { key: 'created_at', header: 'Created', sortable: true, render: formatRelativeTime }
 * ];
 *
 * <DataTable
 *     columns={columns}
 *     data={items}
 *     loading={isLoading}
 *     expandable={(row) => <pre>{JSON.stringify(row, null, 2)}</pre>}
 *     onRowClick={(row) => console.log('Clicked:', row)}
 * />
 */
function DataTable({
    columns,
    data = [],
    loading = false,
    emptyMessage = 'No data available',
    emptyIcon = null,
    expandable = false,
    onRowClick,
    sortable = true,
    compact = false,
    className = '',
    getRowKey,
    defaultSort = { key: null, direction: 'asc' }
}) {
    // State for sorting
    const [sortConfig, setSortConfig] = useState(defaultSort);

    // State for expanded rows (using Set of indices)
    const [expandedRows, setExpandedRows] = useState(new Set());

    // Memoized sorted data
    const sortedData = useMemo(() => {
        if (!sortConfig.key) return data;

        return [...data].sort((a, b) => {
            const aVal = a[sortConfig.key];
            const bVal = b[sortConfig.key];

            // Handle null/undefined values
            if (aVal == null && bVal == null) return 0;
            if (aVal == null) return 1;
            if (bVal == null) return -1;

            // Handle date strings
            const aDate = new Date(aVal);
            const bDate = new Date(bVal);
            if (!isNaN(aDate.getTime()) && !isNaN(bDate.getTime())) {
                const result = aDate.getTime() - bDate.getTime();
                return sortConfig.direction === 'asc' ? result : -result;
            }

            // Handle numbers
            if (typeof aVal === 'number' && typeof bVal === 'number') {
                return sortConfig.direction === 'asc' ? aVal - bVal : bVal - aVal;
            }

            // Handle strings (case-insensitive)
            const aStr = String(aVal).toLowerCase();
            const bStr = String(bVal).toLowerCase();

            if (aStr < bStr) return sortConfig.direction === 'asc' ? -1 : 1;
            if (aStr > bStr) return sortConfig.direction === 'asc' ? 1 : -1;
            return 0;
        });
    }, [data, sortConfig]);

    // Handle sort column click
    function handleSort(key) {
        if (!sortable) return;

        setSortConfig((prev) => ({
            key,
            direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc'
        }));
    }

    // Toggle row expansion
    function toggleExpand(index) {
        setExpandedRows((prev) => {
            const next = new Set(prev);
            if (next.has(index)) {
                next.delete(index);
            } else {
                next.add(index);
            }
            return next;
        });
    }

    // Get unique key for a row
    function getKey(row, index) {
        if (getRowKey) return getRowKey(row, index);
        if (row.id) return row.id;
        if (row.key) return row.key;
        return index;
    }

    // Render loading skeleton
    if (loading) {
        return React.createElement(TableSkeleton, {
            columns,
            rowCount: 5,
            compact,
            expandable: Boolean(expandable)
        });
    }

    // Render empty state
    if (!data.length) {
        return React.createElement(TableEmptyState, {
            message: emptyMessage,
            icon: emptyIcon
        });
    }

    // Render cell content
    function renderCell(row, col) {
        const value = row[col.key];

        if (col.render) {
            return col.render(value, row);
        }

        if (value === null || value === undefined) {
            return React.createElement('span', { className: 'text-muted' }, '-');
        }

        return value;
    }

    // Calculate colspan for expanded row
    const colSpan = columns.length + (expandable ? 1 : 0);

    return React.createElement('div', {
        className: `table-container scroll-area ${className}`.trim()
    },
        React.createElement('table', {
            className: `table table-striped ${compact ? 'table-compact' : ''}`.trim()
        },
            React.createElement('thead', null,
                React.createElement('tr', null,
                    expandable && React.createElement('th', {
                        style: { width: '40px' },
                        'aria-label': 'Expand column'
                    }),
                    columns.map((col) =>
                        React.createElement(SortHeader, {
                            key: col.key,
                            column: col,
                            sortConfig,
                            onSort: handleSort,
                            sortable
                        })
                    )
                )
            ),
            React.createElement('tbody', null,
                sortedData.map((row, idx) => {
                    const rowKey = getKey(row, idx);
                    const isExpanded = expandedRows.has(idx);
                    const isClickable = Boolean(onRowClick);

                    return React.createElement(React.Fragment, { key: rowKey },
                        React.createElement('tr', {
                            onClick: () => onRowClick && onRowClick(row),
                            style: { cursor: isClickable ? 'pointer' : 'default' },
                            className: isClickable ? 'cursor-pointer' : '',
                            role: isClickable ? 'button' : undefined,
                            tabIndex: isClickable ? 0 : undefined,
                            onKeyDown: isClickable ? (e) => {
                                if (e.key === 'Enter' || e.key === ' ') {
                                    e.preventDefault();
                                    onRowClick(row);
                                }
                            } : undefined
                        },
                            expandable && React.createElement('td', {
                                style: { width: '40px', padding: 'var(--space-2)' }
                            },
                                React.createElement(ExpandButton, {
                                    expanded: isExpanded,
                                    onClick: () => toggleExpand(idx)
                                })
                            ),
                            columns.map((col) =>
                                React.createElement('td', { key: col.key },
                                    renderCell(row, col)
                                )
                            )
                        ),
                        // Expanded row content
                        expandable && isExpanded && React.createElement('tr', {
                            className: 'expanded-row',
                            key: `${rowKey}-expanded`
                        },
                            React.createElement('td', {
                                colSpan,
                                style: {
                                    background: 'hsl(var(--muted))',
                                    padding: 'var(--space-4)',
                                    borderTop: 'none'
                                }
                            },
                                typeof expandable === 'function'
                                    ? expandable(row)
                                    : null
                            )
                        )
                    );
                })
            )
        )
    );
}

// =============================================================================
// EXPORTS
// =============================================================================

// Export utility functions for use by other components
if (typeof window !== 'undefined') {
    window.DataTableUtils = {
        formatUUID,
        formatRelativeTime,
        formatDate,
        formatNumber
    };
}
