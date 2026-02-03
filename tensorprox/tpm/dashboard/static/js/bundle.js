// TPM Dashboard - Consolidated Bundle
(function() {
    'use strict';
    
    // Global React hooks
    const { useState, useEffect, useCallback, useMemo, useRef, createContext, useContext } = React;
    
    // Global Recharts components
    let RechartsArea, RechartsBar, RechartsLine, RechartsPie;
    let ResponsiveContainer, Area, Bar, Line, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend;
    
    if (typeof Recharts !== 'undefined') {
        ResponsiveContainer = Recharts.ResponsiveContainer;
        RechartsArea = Recharts.AreaChart;
        Area = Recharts.Area;
        RechartsBar = Recharts.BarChart;
        Bar = Recharts.Bar;
        RechartsLine = Recharts.LineChart;
        Line = Recharts.Line;
        RechartsPie = Recharts.PieChart;
        Pie = Recharts.Pie;
        Cell = Recharts.Cell;
        XAxis = Recharts.XAxis;
        YAxis = Recharts.YAxis;
        CartesianGrid = Recharts.CartesianGrid;
        Tooltip = Recharts.Tooltip;
        Legend = Recharts.Legend;
    }

    // ===== components/Charts.js =====

/**
 * Chart color constants matching the dashboard CSS design system.
 * Use these for consistent coloring across all charts.
 */
const CHART_COLORS = {
    // Base semantic colors
    primary: 'hsl(222, 47%, 31%)',
    success: 'hsl(142, 76%, 36%)',
    warning: 'hsl(48, 96%, 53%)',
    error: 'hsl(0, 84%, 60%)',
    info: 'hsl(217, 91%, 60%)',
    muted: 'hsl(215, 14%, 34%)',

    // Error category colors (matching CSS variables)
    target_selection: 'hsl(0, 84%, 60%)',
    capacity_check: 'hsl(25, 95%, 53%)',
    api_validation: 'hsl(48, 96%, 53%)',
    geolocation: 'hsl(271, 81%, 56%)',
    queue: 'hsl(217, 91%, 60%)',
    metrics: 'hsl(215, 14%, 34%)',

    // Lifecycle state colors
    active: 'hsl(142, 76%, 36%)',
    deploying: 'hsl(199, 89%, 48%)',
    deleted: 'hsl(215, 14%, 34%)',
    failed: 'hsl(0, 84%, 60%)',

    // Utilization colors
    empty: 'hsl(215, 14%, 34%)',
    low: 'hsl(142, 76%, 36%)',
    medium: 'hsl(48, 96%, 53%)',
    high: 'hsl(25, 95%, 53%)',
    full: 'hsl(0, 84%, 60%)'
};

/**
 * Default color palette for multi-series charts
 */
const DEFAULT_PALETTE = [
    CHART_COLORS.primary,
    CHART_COLORS.success,
    CHART_COLORS.info,
    CHART_COLORS.warning,
    CHART_COLORS.error,
    CHART_COLORS.geolocation,
    CHART_COLORS.muted
];

/**
 * Common tooltip styles matching shadcn popover design
 */
const TOOLTIP_STYLE = {
    background: 'hsl(0, 0%, 100%)',
    border: '1px solid hsl(214.3, 31.8%, 91.4%)',
    borderRadius: '0.5rem',
    boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)',
    padding: '0.5rem 0.75rem',
    fontSize: '0.875rem'
};

/**
 * Common axis styling
 */
const AXIS_STYLE = {
    fontSize: 12,
    fill: 'hsl(215.4, 16.3%, 46.9%)'
};

/**
 * Grid stroke color
 */
const GRID_STROKE = 'hsl(214.3, 31.8%, 91.4%)';

// ============================================================================
// ChartCard - Wrapper with card styling and loading state
// ============================================================================

/**
 * ChartCard Component
 *
 * Wraps charts in a consistent card container with optional title and loading state.
 *
 * @param {Object} props
 * @param {string} [props.title] - Optional card title
 * @param {React.ReactNode} props.children - Chart content
 * @param {boolean} [props.loading=false] - Show skeleton loading state
 * @param {number} [props.height=300] - Height of the chart area
 * @param {string} [props.description] - Optional description below title
 */
function ChartCard({ title, children, loading = false, height = 300, description }) {
    if (loading) {
        return (
            <div className="card" role="status" aria-busy="true" aria-label="Loading chart">
                {title && (
                    <div className="card-header">
                        <div className="skeleton" style={{ width: '40%', height: '1.25rem' }} />
                        {description && (
                            <div className="skeleton" style={{ width: '60%', height: '0.875rem', marginTop: 'var(--space-1)' }} />
                        )}
                    </div>
                )}
                <div className="card-content">
                    <div className="skeleton" style={{ width: '100%', height }} />
                </div>
            </div>
        );
    }

    return (
        <div className="card">
            {title && (
                <div className="card-header">
                    <div className="card-title">{title}</div>
                    {description && (
                        <div className="card-description">{description}</div>
                    )}
                </div>
            )}
            <div className="card-content">
                {children}
            </div>
        </div>
    );
}

/**
 * EmptyChart Component
 *
 * Displayed when chart has no data.
 *
 * @param {Object} props
 * @param {number} [props.height=300] - Height to match chart area
 * @param {string} [props.message='No data available'] - Message to display
 */
function EmptyChart({ height = 300, message = 'No data available' }) {
    return (
        <div
            className="empty-state"
            style={{
                height,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                padding: 'var(--space-6)'
            }}
        >
            <div className="text-muted text-sm">{message}</div>
        </div>
    );
}

// ============================================================================
// SimpleAreaChart - For time series like "Errors over time"
// ============================================================================

/**
 * SimpleAreaChart Component
 *
 * Renders a single-series area chart, ideal for time series data.
 *
 * @param {Object} props
 * @param {Array} props.data - Array of data points
 * @param {string} props.xKey - Key for x-axis values
 * @param {string} props.yKey - Key for y-axis values
 * @param {string} [props.color] - Fill/stroke color
 * @param {number} [props.height=300] - Chart height
 * @param {string} [props.title] - Optional card title
 * @param {string} [props.description] - Optional card description
 * @param {boolean} [props.loading=false] - Loading state
 * @param {Function} [props.xFormatter] - Custom x-axis tick formatter
 * @param {Function} [props.yFormatter] - Custom y-axis tick formatter
 * @param {Function} [props.tooltipFormatter] - Custom tooltip value formatter
 *
 * @example
 * <SimpleAreaChart
 *   data={[{ date: '2024-01', count: 10 }, { date: '2024-02', count: 15 }]}
 *   xKey="date"
 *   yKey="count"
 *   color={CHART_COLORS.error}
 *   title="Errors Over Time"
 * />
 */
function SimpleAreaChart({
    data,
    xKey,
    yKey,
    color = CHART_COLORS.primary,
    height = 300,
    title,
    description,
    loading = false,
    xFormatter,
    yFormatter,
    tooltipFormatter
}) {
    const hasData = Array.isArray(data) && data.length > 0;

    return (
        <ChartCard title={title} description={description} loading={loading} height={height}>
            {!hasData ? (
                <EmptyChart height={height} />
            ) : (
                <ResponsiveContainer width="100%" height={height}>
                    <RechartsArea data={data}>
                        <defs>
                            <linearGradient id={`gradient-${yKey}`} x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                                <stop offset="95%" stopColor={color} stopOpacity={0.05} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} vertical={false} />
                        <XAxis
                            dataKey={xKey}
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={{ stroke: GRID_STROKE }}
                            tickFormatter={xFormatter}
                        />
                        <YAxis
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={false}
                            tickFormatter={yFormatter}
                        />
                        <Tooltip
                            contentStyle={TOOLTIP_STYLE}
                            formatter={tooltipFormatter}
                            labelStyle={{ fontWeight: 500, marginBottom: '0.25rem' }}
                        />
                        <Area
                            type="monotone"
                            dataKey={yKey}
                            fill={`url(#gradient-${yKey})`}
                            stroke={color}
                            strokeWidth={2}
                        />
                    </RechartsArea>
                </ResponsiveContainer>
            )}
        </ChartCard>
    );
}

// ============================================================================
// StackedAreaChart - For "Errors by source over time"
// ============================================================================

/**
 * StackedAreaChart Component
 *
 * Renders a stacked area chart for multiple series over time.
 *
 * @param {Object} props
 * @param {Array} props.data - Array of data points
 * @param {string} props.xKey - Key for x-axis values
 * @param {Array} props.stacks - Array of stack configurations
 * @param {string} props.stacks[].key - Data key for this stack
 * @param {string} props.stacks[].color - Color for this stack
 * @param {string} [props.stacks[].label] - Display label (defaults to key)
 * @param {number} [props.height=300] - Chart height
 * @param {string} [props.title] - Optional card title
 * @param {string} [props.description] - Optional card description
 * @param {boolean} [props.loading=false] - Loading state
 * @param {boolean} [props.percentage=false] - Show as percentage (stackOffset="expand")
 * @param {Function} [props.xFormatter] - Custom x-axis tick formatter
 *
 * @example
 * <StackedAreaChart
 *   data={timeSeriesData}
 *   xKey="date"
 *   stacks={[
 *     { key: 'target_selection', color: CHART_COLORS.target_selection, label: 'Target Selection' },
 *     { key: 'capacity_check', color: CHART_COLORS.capacity_check, label: 'Capacity Check' }
 *   ]}
 *   title="Errors by Category"
 * />
 */
function StackedAreaChart({
    data,
    xKey,
    stacks,
    height = 300,
    title,
    description,
    loading = false,
    percentage = false,
    xFormatter
}) {
    const hasData = Array.isArray(data) && data.length > 0 && Array.isArray(stacks) && stacks.length > 0;

    return (
        <ChartCard title={title} description={description} loading={loading} height={height}>
            {!hasData ? (
                <EmptyChart height={height} />
            ) : (
                <ResponsiveContainer width="100%" height={height}>
                    <RechartsArea data={data} stackOffset={percentage ? 'expand' : 'none'}>
                        <defs>
                            {stacks.map(s => (
                                <linearGradient key={`gradient-${s.key}`} id={`gradient-stack-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor={s.color} stopOpacity={0.4} />
                                    <stop offset="95%" stopColor={s.color} stopOpacity={0.1} />
                                </linearGradient>
                            ))}
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} vertical={false} />
                        <XAxis
                            dataKey={xKey}
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={{ stroke: GRID_STROKE }}
                            tickFormatter={xFormatter}
                        />
                        <YAxis
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={false}
                            tickFormatter={percentage ? (v) => `${(v * 100).toFixed(0)}%` : undefined}
                        />
                        <Tooltip
                            contentStyle={TOOLTIP_STYLE}
                            labelStyle={{ fontWeight: 500, marginBottom: '0.25rem' }}
                            formatter={percentage ? (v) => `${(v * 100).toFixed(1)}%` : undefined}
                        />
                        <Legend
                            wrapperStyle={{ fontSize: '0.75rem', paddingTop: 'var(--space-2)' }}
                        />
                        {stacks.map(s => (
                            <Area
                                key={s.key}
                                type="monotone"
                                dataKey={s.key}
                                name={s.label || s.key}
                                fill={`url(#gradient-stack-${s.key})`}
                                stroke={s.color}
                                strokeWidth={1.5}
                                stackId="1"
                            />
                        ))}
                    </RechartsArea>
                </ResponsiveContainer>
            )}
        </ChartCard>
    );
}

// ============================================================================
// SimpleBarChart - For distributions like "Error categories"
// ============================================================================

/**
 * SimpleBarChart Component
 *
 * Renders a vertical bar chart for categorical data.
 *
 * @param {Object} props
 * @param {Array} props.data - Array of data points
 * @param {string} props.xKey - Key for x-axis categories
 * @param {string} props.yKey - Key for y-axis values
 * @param {string|Function} [props.color] - Bar color (string or function(entry, index) => color)
 * @param {number} [props.height=300] - Chart height
 * @param {string} [props.title] - Optional card title
 * @param {string} [props.description] - Optional card description
 * @param {boolean} [props.loading=false] - Loading state
 * @param {Function} [props.xFormatter] - Custom x-axis tick formatter
 * @param {Function} [props.yFormatter] - Custom y-axis tick formatter
 * @param {number} [props.barRadius=4] - Bar corner radius
 *
 * @example
 * <SimpleBarChart
 *   data={[{ category: 'API', count: 24 }, { category: 'Target', count: 18 }]}
 *   xKey="category"
 *   yKey="count"
 *   color={CHART_COLORS.error}
 *   title="Errors by Category"
 * />
 */
function SimpleBarChart({
    data,
    xKey,
    yKey,
    color = CHART_COLORS.primary,
    height = 300,
    title,
    description,
    loading = false,
    xFormatter,
    yFormatter,
    barRadius = 4
}) {
    const hasData = Array.isArray(data) && data.length > 0;

    // Determine if color is a function or static
    const getColor = typeof color === 'function' ? color : () => color;

    return (
        <ChartCard title={title} description={description} loading={loading} height={height}>
            {!hasData ? (
                <EmptyChart height={height} />
            ) : (
                <ResponsiveContainer width="100%" height={height}>
                    <RechartsBar data={data}>
                        <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} vertical={false} />
                        <XAxis
                            dataKey={xKey}
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={{ stroke: GRID_STROKE }}
                            tickFormatter={xFormatter}
                        />
                        <YAxis
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={false}
                            tickFormatter={yFormatter}
                        />
                        <Tooltip
                            contentStyle={TOOLTIP_STYLE}
                            labelStyle={{ fontWeight: 500, marginBottom: '0.25rem' }}
                            cursor={{ fill: 'hsl(210, 40%, 96.1%)', opacity: 0.5 }}
                        />
                        <Bar
                            dataKey={yKey}
                            radius={[barRadius, barRadius, 0, 0]}
                        >
                            {data.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={getColor(entry, index)} />
                            ))}
                        </Bar>
                    </RechartsBar>
                </ResponsiveContainer>
            )}
        </ChartCard>
    );
}

// ============================================================================
// HorizontalBarChart - For ranked lists like "Top regions"
// ============================================================================

/**
 * HorizontalBarChart Component
 *
 * Renders a horizontal bar chart for ranked/sorted data.
 *
 * @param {Object} props
 * @param {Array} props.data - Array of data points
 * @param {string} props.nameKey - Key for category names
 * @param {string} props.valueKey - Key for values
 * @param {string|Function} [props.color] - Bar color (string or function(entry, index) => color)
 * @param {number} [props.height=300] - Chart height
 * @param {string} [props.title] - Optional card title
 * @param {string} [props.description] - Optional card description
 * @param {boolean} [props.loading=false] - Loading state
 * @param {Function} [props.valueFormatter] - Custom value axis formatter
 * @param {number} [props.barRadius=4] - Bar corner radius
 *
 * @example
 * <HorizontalBarChart
 *   data={[{ region: 'us-east', origins: 45 }, { region: 'eu-west', origins: 32 }]}
 *   nameKey="region"
 *   valueKey="origins"
 *   title="Top Regions"
 * />
 */
function HorizontalBarChart({
    data,
    nameKey,
    valueKey,
    color = CHART_COLORS.primary,
    height = 300,
    title,
    description,
    loading = false,
    valueFormatter,
    barRadius = 4
}) {
    const hasData = Array.isArray(data) && data.length > 0;

    // Determine if color is a function or static
    const getColor = typeof color === 'function' ? color : () => color;

    return (
        <ChartCard title={title} description={description} loading={loading} height={height}>
            {!hasData ? (
                <EmptyChart height={height} />
            ) : (
                <ResponsiveContainer width="100%" height={height}>
                    <RechartsBar data={data} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} horizontal={false} />
                        <XAxis
                            type="number"
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={{ stroke: GRID_STROKE }}
                            tickFormatter={valueFormatter}
                        />
                        <YAxis
                            type="category"
                            dataKey={nameKey}
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={false}
                            width={100}
                        />
                        <Tooltip
                            contentStyle={TOOLTIP_STYLE}
                            labelStyle={{ fontWeight: 500, marginBottom: '0.25rem' }}
                            cursor={{ fill: 'hsl(210, 40%, 96.1%)', opacity: 0.5 }}
                        />
                        <Bar
                            dataKey={valueKey}
                            radius={[0, barRadius, barRadius, 0]}
                        >
                            {data.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={getColor(entry, index)} />
                            ))}
                        </Bar>
                    </RechartsBar>
                </ResponsiveContainer>
            )}
        </ChartCard>
    );
}

// ============================================================================
// DonutChart - For proportions like "Lifecycle summary"
// ============================================================================

/**
 * DonutChart Component
 *
 * Renders a donut/pie chart for showing proportions.
 *
 * @param {Object} props
 * @param {Array} props.data - Array of data points
 * @param {string} props.nameKey - Key for segment names
 * @param {string} props.valueKey - Key for segment values
 * @param {Object|Array} [props.colors] - Color mapping { name: color } or array of colors
 * @param {number} [props.height=300] - Chart height
 * @param {string} [props.title] - Optional card title
 * @param {string} [props.description] - Optional card description
 * @param {boolean} [props.loading=false] - Loading state
 * @param {number} [props.innerRadius=60] - Inner radius (0 for pie chart)
 * @param {number} [props.outerRadius=80] - Outer radius
 * @param {boolean} [props.showLabels=true] - Show segment labels
 * @param {boolean} [props.showLegend=true] - Show legend
 * @param {React.ReactNode} [props.centerContent] - Content for center of donut
 *
 * @example
 * <DonutChart
 *   data={[{ state: 'active', count: 120 }, { state: 'failed', count: 8 }]}
 *   nameKey="state"
 *   valueKey="count"
 *   colors={{ active: CHART_COLORS.active, failed: CHART_COLORS.failed }}
 *   title="Exit Hub Status"
 * />
 */
function DonutChart({
    data,
    nameKey,
    valueKey,
    colors = {},
    height = 300,
    title,
    description,
    loading = false,
    innerRadius = 60,
    outerRadius = 80,
    showLabels = false,
    showLegend = true,
    centerContent
}) {
    const hasData = Array.isArray(data) && data.length > 0;

    // Calculate total for percentage display
    const total = useMemo(() => {
        if (!hasData) return 0;
        return data.reduce((sum, item) => sum + (item[valueKey] || 0), 0);
    }, [data, valueKey, hasData]);

    // Get color for a segment
    const getColor = (entry, index) => {
        const name = entry[nameKey];
        if (colors && typeof colors === 'object' && !Array.isArray(colors) && colors[name]) {
            return colors[name];
        }
        if (Array.isArray(colors) && colors[index]) {
            return colors[index];
        }
        return DEFAULT_PALETTE[index % DEFAULT_PALETTE.length];
    };

    // Custom label renderer
    const renderLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, name }) => {
        if (percent < 0.05) return null; // Hide labels for very small segments
        const RADIAN = Math.PI / 180;
        const radius = innerRadius + (outerRadius - innerRadius) * 1.4;
        const x = cx + radius * Math.cos(-midAngle * RADIAN);
        const y = cy + radius * Math.sin(-midAngle * RADIAN);
        return (
            <text
                x={x}
                y={y}
                fill={AXIS_STYLE.fill}
                fontSize={AXIS_STYLE.fontSize}
                textAnchor={x > cx ? 'start' : 'end'}
                dominantBaseline="central"
            >
                {name} ({(percent * 100).toFixed(0)}%)
            </text>
        );
    };

    return (
        <ChartCard title={title} description={description} loading={loading} height={height}>
            {!hasData ? (
                <EmptyChart height={height} />
            ) : (
                <div style={{ position: 'relative', width: '100%', height }}>
                    <ResponsiveContainer width="100%" height={height}>
                        <RechartsPie>
                            <Pie
                                data={data}
                                dataKey={valueKey}
                                nameKey={nameKey}
                                cx="50%"
                                cy="50%"
                                innerRadius={innerRadius}
                                outerRadius={outerRadius}
                                paddingAngle={2}
                                label={showLabels ? renderLabel : false}
                                labelLine={showLabels}
                            >
                                {data.map((entry, index) => (
                                    <Cell
                                        key={`cell-${index}`}
                                        fill={getColor(entry, index)}
                                        stroke="hsl(0, 0%, 100%)"
                                        strokeWidth={2}
                                    />
                                ))}
                            </Pie>
                            <Tooltip
                                contentStyle={TOOLTIP_STYLE}
                                formatter={(value, name) => [
                                    `${value} (${total > 0 ? ((value / total) * 100).toFixed(1) : 0}%)`,
                                    name
                                ]}
                            />
                            {showLegend && (
                                <Legend
                                    layout="vertical"
                                    align="right"
                                    verticalAlign="middle"
                                    wrapperStyle={{ fontSize: '0.75rem', paddingLeft: 'var(--space-4)' }}
                                    formatter={(value, entry) => (
                                        <span style={{ color: 'hsl(222.2, 84%, 4.9%)' }}>{value}</span>
                                    )}
                                />
                            )}
                        </RechartsPie>
                    </ResponsiveContainer>
                    {centerContent && innerRadius > 0 && (
                        <div
                            style={{
                                position: 'absolute',
                                top: '50%',
                                left: '50%',
                                transform: 'translate(-50%, -50%)',
                                textAlign: 'center',
                                pointerEvents: 'none'
                            }}
                        >
                            {centerContent}
                        </div>
                    )}
                </div>
            )}
        </ChartCard>
    );
}

// ============================================================================
// SimpleLineChart - For trends like "Origins over time"
// ============================================================================

/**
 * SimpleLineChart Component
 *
 * Renders a line chart for trend visualization.
 *
 * @param {Object} props
 * @param {Array} props.data - Array of data points
 * @param {string} props.xKey - Key for x-axis values
 * @param {string} props.yKey - Key for y-axis values
 * @param {string} [props.color] - Line color
 * @param {number} [props.height=300] - Chart height
 * @param {string} [props.title] - Optional card title
 * @param {string} [props.description] - Optional card description
 * @param {boolean} [props.loading=false] - Loading state
 * @param {Function} [props.xFormatter] - Custom x-axis tick formatter
 * @param {Function} [props.yFormatter] - Custom y-axis tick formatter
 * @param {boolean} [props.showDots=true] - Show data point dots
 * @param {string} [props.curveType='monotone'] - Line curve type
 *
 * @example
 * <SimpleLineChart
 *   data={[{ month: 'Jan', origins: 100 }, { month: 'Feb', origins: 120 }]}
 *   xKey="month"
 *   yKey="origins"
 *   color={CHART_COLORS.success}
 *   title="Origins Growth"
 * />
 */
function SimpleLineChart({
    data,
    xKey,
    yKey,
    color = CHART_COLORS.primary,
    height = 300,
    title,
    description,
    loading = false,
    xFormatter,
    yFormatter,
    showDots = true,
    curveType = 'monotone'
}) {
    const hasData = Array.isArray(data) && data.length > 0;

    return (
        <ChartCard title={title} description={description} loading={loading} height={height}>
            {!hasData ? (
                <EmptyChart height={height} />
            ) : (
                <ResponsiveContainer width="100%" height={height}>
                    <RechartsLine data={data}>
                        <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} vertical={false} />
                        <XAxis
                            dataKey={xKey}
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={{ stroke: GRID_STROKE }}
                            tickFormatter={xFormatter}
                        />
                        <YAxis
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={false}
                            tickFormatter={yFormatter}
                        />
                        <Tooltip
                            contentStyle={TOOLTIP_STYLE}
                            labelStyle={{ fontWeight: 500, marginBottom: '0.25rem' }}
                        />
                        <Line
                            type={curveType}
                            dataKey={yKey}
                            stroke={color}
                            strokeWidth={2}
                            dot={showDots ? {
                                fill: color,
                                stroke: 'hsl(0, 0%, 100%)',
                                strokeWidth: 2,
                                r: 4
                            } : false}
                            activeDot={{
                                fill: color,
                                stroke: 'hsl(0, 0%, 100%)',
                                strokeWidth: 2,
                                r: 6
                            }}
                        />
                    </RechartsLine>
                </ResponsiveContainer>
            )}
        </ChartCard>
    );
}

// ============================================================================
// MultiLineChart - For comparing multiple trends
// ============================================================================

/**
 * MultiLineChart Component
 *
 * Renders multiple line series for comparison.
 *
 * @param {Object} props
 * @param {Array} props.data - Array of data points
 * @param {string} props.xKey - Key for x-axis values
 * @param {Array} props.lines - Array of line configurations
 * @param {string} props.lines[].key - Data key for this line
 * @param {string} props.lines[].color - Color for this line
 * @param {string} [props.lines[].label] - Display label (defaults to key)
 * @param {number} [props.height=300] - Chart height
 * @param {string} [props.title] - Optional card title
 * @param {string} [props.description] - Optional card description
 * @param {boolean} [props.loading=false] - Loading state
 * @param {Function} [props.xFormatter] - Custom x-axis tick formatter
 * @param {Function} [props.yFormatter] - Custom y-axis tick formatter
 * @param {boolean} [props.showDots=false] - Show data point dots
 *
 * @example
 * <MultiLineChart
 *   data={timeSeriesData}
 *   xKey="date"
 *   lines={[
 *     { key: 'active', color: CHART_COLORS.active, label: 'Active' },
 *     { key: 'deploying', color: CHART_COLORS.deploying, label: 'Deploying' }
 *   ]}
 *   title="Exit Hub States"
 * />
 */
function MultiLineChart({
    data,
    xKey,
    lines,
    height = 300,
    title,
    description,
    loading = false,
    xFormatter,
    yFormatter,
    showDots = false
}) {
    const hasData = Array.isArray(data) && data.length > 0 && Array.isArray(lines) && lines.length > 0;

    return (
        <ChartCard title={title} description={description} loading={loading} height={height}>
            {!hasData ? (
                <EmptyChart height={height} />
            ) : (
                <ResponsiveContainer width="100%" height={height}>
                    <RechartsLine data={data}>
                        <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} vertical={false} />
                        <XAxis
                            dataKey={xKey}
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={{ stroke: GRID_STROKE }}
                            tickFormatter={xFormatter}
                        />
                        <YAxis
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={false}
                            tickFormatter={yFormatter}
                        />
                        <Tooltip
                            contentStyle={TOOLTIP_STYLE}
                            labelStyle={{ fontWeight: 500, marginBottom: '0.25rem' }}
                        />
                        <Legend
                            wrapperStyle={{ fontSize: '0.75rem', paddingTop: 'var(--space-2)' }}
                        />
                        {lines.map(l => (
                            <Line
                                key={l.key}
                                type="monotone"
                                dataKey={l.key}
                                name={l.label || l.key}
                                stroke={l.color}
                                strokeWidth={2}
                                dot={showDots ? {
                                    fill: l.color,
                                    stroke: 'hsl(0, 0%, 100%)',
                                    strokeWidth: 2,
                                    r: 3
                                } : false}
                                activeDot={{
                                    fill: l.color,
                                    stroke: 'hsl(0, 0%, 100%)',
                                    strokeWidth: 2,
                                    r: 5
                                }}
                            />
                        ))}
                    </RechartsLine>
                </ResponsiveContainer>
            )}
        </ChartCard>
    );
}

// ============================================================================
// StackedBarChart - For grouped comparisons
// ============================================================================

/**
 * StackedBarChart Component
 *
 * Renders a stacked vertical bar chart for grouped data.
 *
 * @param {Object} props
 * @param {Array} props.data - Array of data points
 * @param {string} props.xKey - Key for x-axis categories
 * @param {Array} props.stacks - Array of stack configurations
 * @param {string} props.stacks[].key - Data key for this stack
 * @param {string} props.stacks[].color - Color for this stack
 * @param {string} [props.stacks[].label] - Display label (defaults to key)
 * @param {number} [props.height=300] - Chart height
 * @param {string} [props.title] - Optional card title
 * @param {string} [props.description] - Optional card description
 * @param {boolean} [props.loading=false] - Loading state
 * @param {number} [props.barRadius=4] - Bar corner radius
 *
 * @example
 * <StackedBarChart
 *   data={regionData}
 *   xKey="region"
 *   stacks={[
 *     { key: 'active', color: CHART_COLORS.active, label: 'Active' },
 *     { key: 'deploying', color: CHART_COLORS.deploying, label: 'Deploying' }
 *   ]}
 *   title="Origins by Region and Status"
 * />
 */
function StackedBarChart({
    data,
    xKey,
    stacks,
    height = 300,
    title,
    description,
    loading = false,
    barRadius = 4
}) {
    const hasData = Array.isArray(data) && data.length > 0 && Array.isArray(stacks) && stacks.length > 0;

    return (
        <ChartCard title={title} description={description} loading={loading} height={height}>
            {!hasData ? (
                <EmptyChart height={height} />
            ) : (
                <ResponsiveContainer width="100%" height={height}>
                    <RechartsBar data={data}>
                        <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} vertical={false} />
                        <XAxis
                            dataKey={xKey}
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={{ stroke: GRID_STROKE }}
                        />
                        <YAxis
                            tick={AXIS_STYLE}
                            tickLine={false}
                            axisLine={false}
                        />
                        <Tooltip
                            contentStyle={TOOLTIP_STYLE}
                            labelStyle={{ fontWeight: 500, marginBottom: '0.25rem' }}
                            cursor={{ fill: 'hsl(210, 40%, 96.1%)', opacity: 0.5 }}
                        />
                        <Legend
                            wrapperStyle={{ fontSize: '0.75rem', paddingTop: 'var(--space-2)' }}
                        />
                        {stacks.map((s, idx) => (
                            <Bar
                                key={s.key}
                                dataKey={s.key}
                                name={s.label || s.key}
                                fill={s.color}
                                stackId="a"
                                radius={idx === stacks.length - 1 ? [barRadius, barRadius, 0, 0] : 0}
                            />
                        ))}
                    </RechartsBar>
                </ResponsiveContainer>
            )}
        </ChartCard>
    );
}

    // ===== hooks/useQuery.js =====
// useQuery.js - Data Fetching Hook for TPM Dashboard

// Simple hash for params to use as cache key
function hashParams(params) {
    return JSON.stringify(params);
}

// Global cache for query results
const queryCache = new Map();

// Cache entry TTL (5 minutes default)
const CACHE_TTL = 5 * 60 * 1000;

/**
 * Get cached data if still valid
 * @param {string} cacheKey - The cache key
 * @returns {object|null} - Cached data or null if expired/missing
 */
function getCachedData(cacheKey) {
    const cached = queryCache.get(cacheKey);
    if (!cached) return null;

    const now = Date.now();
    if (now - cached.timestamp > CACHE_TTL) {
        queryCache.delete(cacheKey);
        return null;
    }

    return cached.data;
}

/**
 * Set data in cache
 * @param {string} cacheKey - The cache key
 * @param {object} data - Data to cache
 */
function setCachedData(cacheKey, data) {
    queryCache.set(cacheKey, {
        data,
        timestamp: Date.now()
    });
}

/**
 * Clear all cached data (useful on logout or manual refresh)
 */
function clearQueryCache() {
    queryCache.clear();
}

/**
 * useQuery - Main data fetching hook
 *
 * @param {string} queryName - Name of the query to execute
 * @param {object} params - Query parameters
 * @param {object} options - Configuration options
 * @param {number} options.refreshInterval - Auto-refresh interval in ms (0 = disabled)
 * @param {boolean} options.enabled - Whether to fetch (default: true)
 * @param {function} options.onSuccess - Callback on successful fetch
 * @param {function} options.onError - Callback on error
 * @param {any} options.initialData - Initial data before first fetch
 * @param {boolean} options.useCache - Whether to use cached data (default: true)
 *
 * @returns {object} Query result with data, loading, error, refetch, etc.
 */
function useQuery(queryName, params = {}, options = {}) {
    const {
        refreshInterval = 0,
        enabled = true,
        onSuccess,
        onError,
        initialData = null,
        useCache = true
    } = options;

    // State
    const [data, setData] = useState(initialData);
    const [count, setCount] = useState(0);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [lastUpdated, setLastUpdated] = useState(null);

    // Refs for tracking first load vs refresh and cleanup
    const isFirstLoad = useRef(true);
    const intervalRef = useRef(null);
    const abortControllerRef = useRef(null);
    const isMountedRef = useRef(true);

    // Memoize params hash to avoid unnecessary re-fetches
    const paramsHash = useMemo(() => hashParams(params), [params]);
    const cacheKey = useMemo(() => `${queryName}:${paramsHash}`, [queryName, paramsHash]);

    // Stable reference for callbacks
    const onSuccessRef = useRef(onSuccess);
    const onErrorRef = useRef(onError);
    useEffect(() => {
        onSuccessRef.current = onSuccess;
        onErrorRef.current = onError;
    }, [onSuccess, onError]);

    /**
     * Fetch data from the API
     * @param {boolean} isManualRefetch - Whether this is a manual refetch (shows loading)
     */
    const fetchData = useCallback(async (isManualRefetch = false) => {
        if (!enabled) {
            setLoading(false);
            return;
        }

        // Cancel any in-flight request
        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
        }
        abortControllerRef.current = new AbortController();

        // Only show loading spinner on first load or manual refetch
        // Background auto-refreshes should not show loading state
        const shouldShowLoading = isFirstLoad.current || isManualRefetch;
        if (shouldShowLoading) {
            setLoading(true);
        }
        setError(null);

        // Check cache first (only on first load)
        if (isFirstLoad.current && useCache) {
            const cachedData = getCachedData(cacheKey);
            if (cachedData) {
                setData(cachedData.results);
                setCount(cachedData.count);
                setLoading(false);
                isFirstLoad.current = false;
                // Still fetch fresh data in background
            }
        }

        try {
            const response = await fetch('/api/v1/dashboard/query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: queryName, params }),
                signal: abortControllerRef.current.signal
            });

            // Check if component is still mounted
            if (!isMountedRef.current) return;

            if (response.status === 401) {
                // Session expired, trigger re-auth
                window.location.reload();
                return;
            }

            if (!response.ok) {
                let errMessage = 'Query failed';
                try {
                    const errData = await response.json();
                    errMessage = errData.error || errMessage;
                } catch {
                    // Response wasn't JSON
                }
                throw new Error(errMessage);
            }

            const result = await response.json();

            // Check again after await
            if (!isMountedRef.current) return;

            const results = result.results || [];
            const resultCount = result.count ?? results.length;

            setData(results);
            setCount(resultCount);
            setLastUpdated(new Date());
            isFirstLoad.current = false;

            // Cache the result
            if (useCache) {
                setCachedData(cacheKey, { results, count: resultCount });
            }

            // Call success callback
            onSuccessRef.current?.(results);

        } catch (err) {
            // Ignore abort errors
            if (err.name === 'AbortError') return;

            // Check if component is still mounted
            if (!isMountedRef.current) return;

            setError(err.message);
            onErrorRef.current?.(err);
        } finally {
            if (isMountedRef.current) {
                setLoading(false);
            }
        }
    }, [queryName, paramsHash, enabled, cacheKey, useCache]);

    /**
     * Manual refetch function (always shows loading state)
     */
    const refetch = useCallback(() => {
        fetchData(true);
    }, [fetchData]);

    // Initial fetch on mount and when dependencies change
    useEffect(() => {
        isFirstLoad.current = true;
        fetchData(false);

        return () => {
            // Cleanup: abort any pending request
            if (abortControllerRef.current) {
                abortControllerRef.current.abort();
            }
        };
    }, [fetchData]);

    // Auto-refresh interval
    useEffect(() => {
        if (refreshInterval > 0 && enabled) {
            intervalRef.current = setInterval(() => {
                fetchData(false); // Background refresh, no loading state
            }, refreshInterval);

            return () => {
                if (intervalRef.current) {
                    clearInterval(intervalRef.current);
                    intervalRef.current = null;
                }
            };
        }
    }, [fetchData, refreshInterval, enabled]);

    // Cleanup on unmount
    useEffect(() => {
        isMountedRef.current = true;

        return () => {
            isMountedRef.current = false;
            if (intervalRef.current) {
                clearInterval(intervalRef.current);
            }
            if (abortControllerRef.current) {
                abortControllerRef.current.abort();
            }
        };
    }, []);

    return {
        data,
        count,
        loading,
        error,
        refetch,
        lastUpdated,
        // Additional helpers
        isFirstLoad: isFirstLoad.current && loading,
        isEmpty: !loading && !error && (!data || data.length === 0)
    };
}

/**
 * useQueries - Fetch multiple queries in parallel
 *
 * @param {Array} queries - Array of query configurations
 * @param {string} queries[].name - Query name
 * @param {object} queries[].params - Query parameters
 * @param {object} queries[].options - Query options (same as useQuery)
 *
 * @returns {Array} Array of query results in same order as input
 *
 * @example
 * const results = useQueries([
 *   { name: 'last_5_errors', options: { refreshInterval: 15000 } },
 *   { name: 'error_categories_summary', options: { refreshInterval: 60000 } },
 *   { name: 'hubs_by_status', params: { status: 'failed' } }
 * ]);
 *
 * const [errorsResult, categoriesResult, failedHubsResult] = results;
 */
function useQueries(queries) {
    const [results, setResults] = useState(() =>
        queries.map(() => ({
            data: null,
            count: 0,
            loading: true,
            error: null,
            lastUpdated: null,
            isFirstLoad: true,
            isEmpty: false
        }))
    );

    const isMountedRef = useRef(true);
    const abortControllersRef = useRef([]);
    const intervalsRef = useRef([]);
    const isFirstLoadRef = useRef(queries.map(() => true));

    // Serialize queries for dependency tracking
    const queriesKey = useMemo(() =>
        JSON.stringify(queries.map(q => ({
            name: q.name,
            params: q.params || {},
            enabled: q.options?.enabled ?? true
        }))),
        [queries]
    );

    /**
     * Fetch a single query and update its result
     */
    const fetchQuery = useCallback(async (index, query, isManualRefetch = false) => {
        const { name, params = {}, options = {} } = query;
        const { enabled = true, onSuccess, onError, useCache = true } = options;

        if (!enabled) {
            setResults(prev => {
                const updated = [...prev];
                updated[index] = { ...updated[index], loading: false };
                return updated;
            });
            return;
        }

        // Cancel any existing request for this query
        if (abortControllersRef.current[index]) {
            abortControllersRef.current[index].abort();
        }
        abortControllersRef.current[index] = new AbortController();

        const shouldShowLoading = isFirstLoadRef.current[index] || isManualRefetch;

        if (shouldShowLoading) {
            setResults(prev => {
                const updated = [...prev];
                updated[index] = { ...updated[index], loading: true, error: null };
                return updated;
            });
        }

        const cacheKey = `${name}:${hashParams(params)}`;

        // Check cache first
        if (isFirstLoadRef.current[index] && useCache) {
            const cachedData = getCachedData(cacheKey);
            if (cachedData) {
                setResults(prev => {
                    const updated = [...prev];
                    updated[index] = {
                        ...updated[index],
                        data: cachedData.results,
                        count: cachedData.count,
                        loading: false,
                        isFirstLoad: false
                    };
                    return updated;
                });
            }
        }

        try {
            const response = await fetch('/api/v1/dashboard/query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: name, params }),
                signal: abortControllersRef.current[index].signal
            });

            if (!isMountedRef.current) return;

            if (response.status === 401) {
                window.location.reload();
                return;
            }

            if (!response.ok) {
                let errMessage = 'Query failed';
                try {
                    const errData = await response.json();
                    errMessage = errData.error || errMessage;
                } catch {}
                throw new Error(errMessage);
            }

            const result = await response.json();

            if (!isMountedRef.current) return;

            const resultData = result.results || [];
            const resultCount = result.count ?? resultData.length;

            isFirstLoadRef.current[index] = false;

            // Cache the result
            if (useCache) {
                setCachedData(cacheKey, { results: resultData, count: resultCount });
            }

            setResults(prev => {
                const updated = [...prev];
                updated[index] = {
                    data: resultData,
                    count: resultCount,
                    loading: false,
                    error: null,
                    lastUpdated: new Date(),
                    isFirstLoad: false,
                    isEmpty: resultData.length === 0
                };
                return updated;
            });

            onSuccess?.(resultData);

        } catch (err) {
            if (err.name === 'AbortError') return;
            if (!isMountedRef.current) return;

            setResults(prev => {
                const updated = [...prev];
                updated[index] = {
                    ...updated[index],
                    loading: false,
                    error: err.message
                };
                return updated;
            });

            onError?.(err);
        }
    }, []);

    // Initial fetch and setup intervals
    useEffect(() => {
        // Reset state for new queries
        isFirstLoadRef.current = queries.map(() => true);

        // Initial fetch for all queries
        queries.forEach((query, index) => {
            fetchQuery(index, query, false);
        });

        // Setup intervals for auto-refresh
        intervalsRef.current.forEach(clearInterval);
        intervalsRef.current = queries.map((query, index) => {
            const { options = {} } = query;
            const { refreshInterval = 0, enabled = true } = options;

            if (refreshInterval > 0 && enabled) {
                return setInterval(() => {
                    fetchQuery(index, query, false);
                }, refreshInterval);
            }
            return null;
        });

        return () => {
            // Cleanup intervals
            intervalsRef.current.forEach(interval => {
                if (interval) clearInterval(interval);
            });
            // Cleanup abort controllers
            abortControllersRef.current.forEach(controller => {
                if (controller) controller.abort();
            });
        };
    }, [queriesKey, fetchQuery]);

    // Cleanup on unmount
    useEffect(() => {
        isMountedRef.current = true;

        return () => {
            isMountedRef.current = false;
        };
    }, []);

    // Return results with refetch functions attached
    return useMemo(() =>
        results.map((result, index) => ({
            ...result,
            refetch: () => fetchQuery(index, queries[index], true)
        })),
        [results, fetchQuery, queries]
    );
}

/**
 * Recommended refresh intervals based on data type
 * From FRONTEND_SPEC.md
 */
const REFRESH_INTERVALS = {
    // Real-time monitoring (10-30 seconds)
    REALTIME: 15000,
    REALTIME_FAST: 10000,
    REALTIME_SLOW: 30000,

    // Near real-time (60 seconds)
    NEAR_REALTIME: 60000,

    // Moderate (30-60 seconds)
    MODERATE: 45000,
    MODERATE_FAST: 30000,
    MODERATE_SLOW: 60000,

    // Slow (5 minutes)
    SLOW: 300000,

    // Mapping for specific query types
    last_5_errors: 15000,
    error_categories_summary: 60000,
    error_codes_by_category: 60000,
    errors_by_category_last_7_days: 60000,
    errors_over_time_daily: 300000,
    errors_over_time_by_source: 300000,

    miner_overview: 60000,
    top_3_regions: 60000,
    top_10_shards: 60000,
    active_miners_detailed: 60000,
    active_shards_with_origins: 60000,
    active_regions_with_origins: 60000,
    origins_per_shard: 60000,

    origin_trace: 45000,
    origin_trace_detailed: 45000,
    egress_summary: 45000,
    egress_status_by_origin: 45000,

    origin_lifetime_stats: 300000,
    origin_lifetime_distribution: 300000,
    origin_count_over_time: 300000,
    shard_count_over_time: 300000,

    exit_hubs_summary: 60000,
    active_miners: 60000,
    recent_deployments: 30000,
    hubs_by_status: 45000
};

/**
 * Get recommended refresh interval for a query
 * @param {string} queryName - Name of the query
 * @returns {number} Refresh interval in milliseconds
 */
function getRefreshInterval(queryName) {
    return REFRESH_INTERVALS[queryName] || REFRESH_INTERVALS.MODERATE;
}

// Export for use in other modules
// Note: In a non-module environment, these are globally available
if (typeof window !== 'undefined') {
    window.useQuery = useQuery;
    window.useQueries = useQueries;
    window.clearQueryCache = clearQueryCache;
    window.getRefreshInterval = getRefreshInterval;
    window.REFRESH_INTERVALS = REFRESH_INTERVALS;
}

    // ===== components/StatCard.js =====
// StatCard.js - Reusable Stat Card Component
// Displays aggregated metrics with optional click navigation and color variants

/**
 * Color variant mapping to CSS HSL variables
 * Maps semantic variant names to their corresponding CSS custom properties
 */
const VARIANT_COLORS = {
    default: 'hsl(var(--primary))',
    success: 'hsl(var(--state-active))',
    warning: 'hsl(var(--error-capacity-check))',
    error: 'hsl(var(--state-failed))',
    info: 'hsl(var(--error-queue))',
    muted: 'hsl(var(--muted-foreground))'
};

/**
 * StatCard Component
 *
 * A reusable card component for displaying statistics with visual hierarchy.
 * Supports color variants, loading states, change indicators, and click navigation.
 *
 * @param {Object} props - Component props
 * @param {string} props.title - Card title displayed in header
 * @param {string|number} props.value - Main value (large, prominent display)
 * @param {string} [props.subtitle] - Description below the value
 * @param {string} [props.icon] - Icon character/emoji displayed before title
 * @param {string} [props.variant='default'] - Color variant: 'default', 'success', 'warning', 'error', 'info', 'muted'
 * @param {Object} [props.change] - Optional trend indicator
 * @param {number} props.change.value - Numeric change value (positive = increase, negative = decrease)
 * @param {string} props.change.label - Label for the change (e.g., "from avg", "vs yesterday")
 * @param {Function} [props.onClick] - Click handler for navigation
 * @param {boolean} [props.loading=false] - Show skeleton loading state
 *
 * @example
 * // Basic usage
 * <StatCard title="Total Errors" value={24} subtitle="last 24h" icon="!" variant="error" />
 *
 * @example
 * // With click navigation and change indicator
 * <StatCard
 *   title="Active Origins"
 *   value={156}
 *   icon="@"
 *   variant="success"
 *   change={{ value: -3, label: "from yesterday" }}
 *   onClick={() => navigateTo('origins')}
 * />
 */
function StatCard({
    title,
    value,
    subtitle,
    icon,
    variant = 'default',
    change,
    onClick,
    loading = false
}) {
    const color = VARIANT_COLORS[variant] || VARIANT_COLORS.default;
    const isClickable = typeof onClick === 'function';

    // Render loading skeleton state
    if (loading) {
        return (
            <div className="stat-card" role="status" aria-busy="true" aria-label="Loading statistics">
                <div className="stat-card-header">
                    <div className="skeleton" style={{ width: '60%', height: '1rem' }} />
                </div>
                <div className="skeleton" style={{ width: '40%', height: '2rem', marginTop: 'var(--space-2)' }} />
                <div className="skeleton" style={{ width: '80%', height: '0.875rem', marginTop: 'var(--space-2)' }} />
            </div>
        );
    }

    // Determine change indicator styling
    // Positive change uses destructive (red) badge - indicates increase in errors/issues
    // Negative change uses success (green) badge - indicates decrease/improvement
    const getChangeBadgeClass = () => {
        if (!change) return '';
        return change.value > 0 ? 'badge-destructive' : 'badge-success';
    };

    const getChangeArrow = () => {
        if (!change) return '';
        return change.value > 0 ? '\u2191' : '\u2193'; // Unicode arrows: up and down
    };

    return (
        <div
            className={`stat-card${isClickable ? ' stat-card-clickable' : ''}`}
            onClick={onClick}
            role={isClickable ? 'button' : undefined}
            tabIndex={isClickable ? 0 : undefined}
            onKeyDown={isClickable ? (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onClick();
                }
            } : undefined}
            style={{
                cursor: isClickable ? 'pointer' : 'default',
                borderTop: `3px solid ${color}`,
                transition: 'transform 0.2s ease, box-shadow 0.2s ease'
            }}
            onMouseEnter={(e) => {
                if (isClickable) {
                    e.currentTarget.style.transform = 'translateY(-2px)';
                    e.currentTarget.style.boxShadow = 'var(--shadow-md)';
                }
            }}
            onMouseLeave={(e) => {
                if (isClickable) {
                    e.currentTarget.style.transform = '';
                    e.currentTarget.style.boxShadow = '';
                }
            }}
            onFocus={(e) => {
                if (isClickable) {
                    e.currentTarget.style.transform = 'translateY(-2px)';
                    e.currentTarget.style.boxShadow = 'var(--shadow-md)';
                }
            }}
            onBlur={(e) => {
                if (isClickable) {
                    e.currentTarget.style.transform = '';
                    e.currentTarget.style.boxShadow = '';
                }
            }}
        >
            {/* Header with icon and title */}
            <div className="stat-card-header">
                <span className="stat-card-title">
                    {icon && (
                        <span
                            style={{ marginRight: 'var(--space-2)' }}
                            aria-hidden="true"
                        >
                            {icon}
                        </span>
                    )}
                    {title}
                </span>
            </div>

            {/* Main value - large and prominent */}
            <div
                className="stat-card-value"
                style={{ color }}
                aria-label={`${title}: ${value}`}
            >
                {value}
            </div>

            {/* Subtitle/description */}
            {subtitle && (
                <div
                    className="text-muted"
                    style={{ fontSize: '0.875rem', marginTop: 'var(--space-1)' }}
                >
                    {subtitle}
                </div>
            )}

            {/* Change indicator badge */}
            {change && (
                <div style={{ marginTop: 'var(--space-2)' }}>
                    <span
                        className={`badge ${getChangeBadgeClass()}`}
                        aria-label={`Change: ${change.value > 0 ? 'increased' : 'decreased'} by ${Math.abs(change.value)} ${change.label}`}
                    >
                        {getChangeArrow()} {Math.abs(change.value)} {change.label}
                    </span>
                </div>
            )}
        </div>
    );
}

    // ===== components/DataTable.js =====
// DataTable.js - Reusable Data Table Component
// Displays tabular data with sorting, filtering, expandable rows, and loading states


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

    // ===== components/Sheet.js =====
// Sheet.js - Slide-out Panel Component
// A reusable sheet/drawer component for displaying details in a slide-out panel
// Used for drill-down views like error category details, miner details, origin details


// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Size presets for the sheet panel
 * Maps size names to CSS width/height values
 */
const SIZES = {
    sm: '320px',
    md: '480px',
    lg: '640px',
    xl: '800px',
    full: '100%'
};

/**
 * Animation class mapping based on slide direction
 */
const SLIDE_ANIMATIONS = {
    right: 'animate-slide-in-right',
    left: 'animate-slide-in-left',
    top: 'animate-slide-in-top',
    bottom: 'animate-slide-in-bottom'
};

// =============================================================================
// HELPER HOOK - useSheet
// =============================================================================

/**
 * Custom hook for managing sheet state
 * Provides a simple API for opening/closing sheets with optional data
 *
 * @returns {Object} Sheet state and control methods
 * @returns {boolean} return.isOpen - Whether the sheet is currently open
 * @returns {*} return.data - Data associated with the currently open sheet
 * @returns {Function} return.open - Opens the sheet with optional data
 * @returns {Function} return.close - Closes the sheet and clears data
 *
 * @example
 * function MyComponent() {
 *     const errorSheet = useSheet();
 *
 *     return (
 *         <>
 *             <button onClick={() => errorSheet.open({ category: 'api_validation' })}>
 *                 View Details
 *             </button>
 *             <Sheet
 *                 open={errorSheet.isOpen}
 *                 onClose={errorSheet.close}
 *                 title={`Error Details: ${errorSheet.data?.category}`}
 *             >
 *                 <ErrorDetails data={errorSheet.data} />
 *             </Sheet>
 *         </>
 *     );
 * }
 */
function useSheet() {
    const [isOpen, setIsOpen] = useState(false);
    const [data, setData] = useState(null);

    const open = useCallback((newData = null) => {
        setData(newData);
        setIsOpen(true);
    }, []);

    const close = useCallback(() => {
        setIsOpen(false);
        // Clear data after animation completes
        setTimeout(() => setData(null), 300);
    }, []);

    return {
        isOpen,
        data,
        open,
        close
    };
}

// =============================================================================
// SHEET CLOSE BUTTON COMPONENT
// =============================================================================

/**
 * Close button for the sheet header
 * Renders an X icon with hover effects
 */
function SheetCloseButton({ onClick }) {
    return React.createElement('button', {
        className: 'sheet-close',
        onClick: onClick,
        'aria-label': 'Close panel',
        type: 'button'
    }, '\u2715'); // Unicode multiplication sign (X)
}

// =============================================================================
// SHEET HEADER COMPONENT
// =============================================================================

/**
 * Sheet header with title, optional description, and close button
 */
function SheetHeader({ title, description, onClose }) {
    return React.createElement('div', { className: 'sheet-header' },
        React.createElement('div', { style: { paddingRight: 'var(--space-8)' } },
            React.createElement('h2', {
                id: 'sheet-title',
                className: 'sheet-title'
            }, title),
            description && React.createElement('p', {
                id: 'sheet-description',
                className: 'sheet-description',
                style: { marginTop: 'var(--space-2)' }
            }, description)
        ),
        React.createElement(SheetCloseButton, { onClick: onClose })
    );
}

// =============================================================================
// SHEET COMPONENT
// =============================================================================

/**
 * Sheet Component
 *
 * A slide-out panel component for displaying detailed content.
 * Slides in from the specified side with overlay backdrop.
 * Supports keyboard navigation (Escape to close), focus trapping,
 * and prevents body scroll when open.
 *
 * @param {Object} props - Component props
 * @param {boolean} props.open - Whether the sheet is visible
 * @param {Function} props.onClose - Callback to close the sheet
 * @param {string} props.title - Sheet title displayed in header
 * @param {string} [props.description] - Optional subtitle/description
 * @param {React.ReactNode} props.children - Content to render in the sheet body
 * @param {string} [props.side='right'] - Side to slide in from: 'right', 'left', 'top', 'bottom'
 * @param {string} [props.size='md'] - Sheet size: 'sm', 'md', 'lg', 'xl', 'full'
 * @param {React.ReactNode} [props.footer] - Optional footer content
 *
 * @example
 * // Basic usage
 * <Sheet
 *     open={isOpen}
 *     onClose={() => setIsOpen(false)}
 *     title="Error Details"
 *     description="View detailed error information"
 * >
 *     <ErrorList errors={errors} />
 * </Sheet>
 *
 * @example
 * // With footer and custom size
 * <Sheet
 *     open={isOpen}
 *     onClose={handleClose}
 *     title="Miner Configuration"
 *     side="right"
 *     size="lg"
 *     footer={
 *         <div className="flex gap-2 justify-end">
 *             <button className="btn btn-secondary" onClick={handleClose}>Cancel</button>
 *             <button className="btn btn-primary" onClick={handleSave}>Save</button>
 *         </div>
 *     }
 * >
 *     <MinerForm miner={selectedMiner} />
 * </Sheet>
 */
function Sheet({
    open,
    onClose,
    title,
    description,
    children,
    side = 'right',
    size = 'md',
    footer
}) {
    const sheetRef = useRef(null);
    const previousActiveElement = useRef(null);

    // Handle escape key to close
    useEffect(() => {
        if (!open) return;

        function handleEscape(e) {
            if (e.key === 'Escape') {
                e.preventDefault();
                onClose();
            }
        }

        document.addEventListener('keydown', handleEscape);
        return () => document.removeEventListener('keydown', handleEscape);
    }, [open, onClose]);

    // Prevent body scroll when open
    useEffect(() => {
        if (open) {
            // Store current overflow setting
            const originalOverflow = document.body.style.overflow;
            document.body.style.overflow = 'hidden';

            return () => {
                document.body.style.overflow = originalOverflow || '';
            };
        }
    }, [open]);

    // Focus management
    useEffect(() => {
        if (open) {
            // Store reference to previously focused element
            previousActiveElement.current = document.activeElement;

            // Focus the sheet container
            if (sheetRef.current) {
                // Small delay to ensure the sheet is rendered
                requestAnimationFrame(() => {
                    if (sheetRef.current) {
                        sheetRef.current.focus();
                    }
                });
            }
        } else {
            // Restore focus to previous element when closing
            if (previousActiveElement.current && typeof previousActiveElement.current.focus === 'function') {
                previousActiveElement.current.focus();
            }
        }
    }, [open]);

    // Focus trap - keep focus within the sheet
    useEffect(() => {
        if (!open || !sheetRef.current) return;

        function handleTabKey(e) {
            if (e.key !== 'Tab') return;

            const focusableElements = sheetRef.current.querySelectorAll(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );

            if (focusableElements.length === 0) return;

            const firstElement = focusableElements[0];
            const lastElement = focusableElements[focusableElements.length - 1];

            if (e.shiftKey) {
                // Shift + Tab: if on first element, go to last
                if (document.activeElement === firstElement) {
                    e.preventDefault();
                    lastElement.focus();
                }
            } else {
                // Tab: if on last element, go to first
                if (document.activeElement === lastElement) {
                    e.preventDefault();
                    firstElement.focus();
                }
            }
        }

        document.addEventListener('keydown', handleTabKey);
        return () => document.removeEventListener('keydown', handleTabKey);
    }, [open]);

    // Don't render if not open
    if (!open) return null;

    // Determine if horizontal or vertical slide
    const isHorizontal = side === 'left' || side === 'right';

    // Calculate size styles based on side
    const sizeValue = SIZES[size] || SIZES.md;
    const sizeStyle = isHorizontal
        ? { width: sizeValue, maxWidth: sizeValue }
        : { height: sizeValue, maxHeight: sizeValue };

    // Handle backdrop click
    function handleOverlayClick(e) {
        // Only close if clicking the overlay itself, not the sheet
        if (e.target === e.currentTarget) {
            onClose();
        }
    }

    return React.createElement('div', {
        className: 'sheet-overlay open animate-fade-in',
        onClick: handleOverlayClick,
        'aria-hidden': 'true'
    },
        React.createElement('div', {
            ref: sheetRef,
            className: `sheet sheet-${side} open ${SLIDE_ANIMATIONS[side]}`,
            style: {
                ...sizeStyle,
                display: 'flex',
                flexDirection: 'column'
            },
            onClick: (e) => e.stopPropagation(),
            tabIndex: -1,
            role: 'dialog',
            'aria-modal': 'true',
            'aria-labelledby': 'sheet-title',
            'aria-describedby': description ? 'sheet-description' : undefined
        },
            // Header
            React.createElement(SheetHeader, {
                title,
                description,
                onClose
            }),

            // Content area (scrollable)
            React.createElement('div', {
                className: 'sheet-content scroll-area',
                style: { flex: 1 }
            }, children),

            // Optional footer
            footer && React.createElement('div', {
                className: 'sheet-footer'
            }, footer)
        )
    );
}

// =============================================================================
// COMPOUND COMPONENTS (for flexibility)
// =============================================================================

/**
 * Sheet.Header - Standalone header component for custom layouts
 */
Sheet.Header = function SheetHeaderStandalone({ children, className = '' }) {
    return React.createElement('div', {
        className: `sheet-header ${className}`.trim()
    }, children);
};

/**
 * Sheet.Title - Title element for custom headers
 */
Sheet.Title = function SheetTitle({ children, className = '' }) {
    return React.createElement('h2', {
        id: 'sheet-title',
        className: `sheet-title ${className}`.trim()
    }, children);
};

/**
 * Sheet.Description - Description element for custom headers
 */
Sheet.Description = function SheetDescription({ children, className = '' }) {
    return React.createElement('p', {
        id: 'sheet-description',
        className: `sheet-description ${className}`.trim()
    }, children);
};

/**
 * Sheet.Content - Content area component for custom layouts
 */
Sheet.Content = function SheetContent({ children, className = '' }) {
    return React.createElement('div', {
        className: `sheet-content scroll-area ${className}`.trim()
    }, children);
};

/**
 * Sheet.Footer - Footer component for actions
 */
Sheet.Footer = function SheetFooter({ children, className = '' }) {
    return React.createElement('div', {
        className: `sheet-footer ${className}`.trim()
    }, children);
};

// =============================================================================
// EXPORTS
// =============================================================================

// Export for use by other components
if (typeof window !== 'undefined') {
    window.Sheet = Sheet;
    window.useSheet = useSheet;
}

    // ===== components/Login.js =====
// Login.js - Login Component

function Login() {
    const { login } = useAuth();
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    async function handleSubmit(e) {
        e.preventDefault();
        setError('');
        setIsLoading(true);

        try {
            await login(username, password);
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    }

    return (
        <div className="dashboard-layout flex items-center justify-center" style={{ background: 'hsl(var(--muted))' }}>
            <div className="card" style={{ width: '100%', maxWidth: '400px' }}>
                <div className="card-header" style={{ textAlign: 'center' }}>
                    <div className="card-title" style={{ fontSize: '1.5rem' }}>
                        TPM Dashboard
                    </div>
                    <p className="text-muted" style={{ marginTop: '0.5rem' }}>
                        TensorProx Management Console
                    </p>
                </div>
                <div className="card-content">
                    <form onSubmit={handleSubmit}>
                        {error && (
                            <div className="alert alert-destructive" style={{ marginBottom: '1rem' }}>
                                {error}
                            </div>
                        )}

                        <div style={{ marginBottom: '1rem' }}>
                            <label className="label" htmlFor="username">Username</label>
                            <input
                                id="username"
                                type="text"
                                className="input"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                placeholder="Enter username"
                                autoComplete="username"
                                disabled={isLoading}
                                autoFocus
                            />
                        </div>

                        <div style={{ marginBottom: '1.5rem' }}>
                            <label className="label" htmlFor="password">Password</label>
                            <input
                                id="password"
                                type="password"
                                className="input"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Enter password"
                                autoComplete="current-password"
                                disabled={isLoading}
                            />
                        </div>

                        <button
                            type="submit"
                            className="btn btn-primary"
                            style={{ width: '100%' }}
                            disabled={isLoading || !username || !password}
                        >
                            {isLoading ? (
                                <>
                                    <span className="animate-spin" style={{
                                        display: 'inline-block',
                                        width: '1rem',
                                        height: '1rem',
                                        border: '2px solid transparent',
                                        borderTopColor: 'currentColor',
                                        borderRadius: '50%',
                                        marginRight: '0.5rem'
                                    }} />
                                    Signing in...
                                </>
                            ) : 'Sign In'}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
}

    // ===== components/LandingStats.js =====
// LandingStats.js - Landing Stats Overview Section
// Displays aggregated overview cards that summarize key metrics from multiple queries
// Clicking a card navigates to the relevant tab for detailed information


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

    // ===== components/ErrorsTab.js =====
// ErrorsTab.js - Errors Tab Component
// Displays system errors with Last 5 Errors table, Error Categories summary, and Errors Over Time chart
// Includes drill-down sheet for viewing errors by category


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

    // ===== components/InfraTab.js =====
// InfraTab.js - Infrastructure Tab Component
// Displays miners, shards, regions - the physical/logical infrastructure
// Includes Quick Stats, Top Regions, Top Shards, Miner Overview with expandable rows,
// and Origins Per Shard distribution chart


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

    // ===== components/OriginsTab.js =====
// OriginsTab.js - Origins Tab Component
// Displays customer deployments - lifecycle, configuration, status
// Includes Lifecycle Summary (donut chart), Egress Summary stats, and Origin List table with filters


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

    // ===== components/AnalyticsTab.js =====
// AnalyticsTab.js - Analytics Tab Component
// Displays origin lifetime statistics, distribution charts, and time-series data
// Includes LifetimeStats cards, Distribution chart, and Origins/Shards over time charts


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

    // ===== components/Layout.js =====
// Layout.js - Main Dashboard Layout Component
// Provides header with logout, landing stats section, and tab navigation

// Tab configuration - each tab has an id, display label, and icon
const TABS = [
    { id: 'errors', label: 'Errors', icon: '!' },
    { id: 'infrastructure', label: 'Infrastructure', icon: '#' },
    { id: 'origins', label: 'Origins', icon: '@' },
    { id: 'analytics', label: 'Analytics', icon: '%' }
];

function Layout() {
    const { logout } = useAuth();

    // Initialize tab from URL hash or default to 'errors'
    const getInitialTab = () => {
        const hash = window.location.hash.slice(1);
        const validTab = TABS.find(tab => tab.id === hash);
        return validTab ? hash : 'errors';
    };

    const [activeTab, setActiveTab] = useState(getInitialTab);

    // Sync tab state with URL hash for deep linking
    useEffect(() => {
        const handleHashChange = () => {
            const hash = window.location.hash.slice(1);
            const validTab = TABS.find(tab => tab.id === hash);
            if (validTab) {
                setActiveTab(hash);
            }
        };

        window.addEventListener('hashchange', handleHashChange);
        return () => window.removeEventListener('hashchange', handleHashChange);
    }, []);

    // Update URL hash when tab changes
    function handleTabChange(tabId) {
        setActiveTab(tabId);
        window.location.hash = tabId;
    }

    // Navigate to a tab (used by LandingStats cards)
    function handleNavigate(tabId) {
        handleTabChange(tabId);
    }

    // Render the content for the active tab
    function renderTabContent() {
        switch (activeTab) {
            case 'errors':
                return <ErrorsTab />;
            case 'infrastructure':
                return <InfraTab />;
            case 'origins':
                return <OriginsTab />;
            case 'analytics':
                return <AnalyticsTab />;
            default:
                return null;
        }
    }

    return (
        <div className="dashboard-layout">
            {/* Header - sticky at top with shadow */}
            <header className="header">
                <div className="header-brand">
                    <span className="header-logo" style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        width: '2rem',
                        height: '2rem',
                        backgroundColor: 'hsl(var(--primary))',
                        color: 'hsl(var(--primary-foreground))',
                        borderRadius: 'var(--radius)',
                        fontWeight: 700,
                        fontSize: '1rem'
                    }}>T</span>
                    <span style={{ fontWeight: 600, fontSize: '1.125rem' }}>TPM Dashboard</span>
                </div>
                <div className="header-actions">
                    <button
                        className="btn btn-destructive btn-sm"
                        onClick={logout}
                    >
                        Logout
                    </button>
                </div>
            </header>

            {/* Main Content Area - scrollable */}
            <main className="main-content">
                {/* Landing Stats - overview cards always visible above tabs */}
                <LandingStats onNavigate={handleNavigate} />

                {/* Tab Navigation */}
                <div className="tabs" style={{ marginTop: 'var(--space-6)' }}>
                    <div className="tabs-list" role="tablist" aria-label="Dashboard sections">
                        {TABS.map(tab => (
                            <button
                                key={tab.id}
                                role="tab"
                                aria-selected={activeTab === tab.id}
                                aria-controls={`tabpanel-${tab.id}`}
                                className={`tab-trigger ${activeTab === tab.id ? 'active' : ''}`}
                                onClick={() => handleTabChange(tab.id)}
                            >
                                <span style={{
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    width: '1.25rem',
                                    height: '1.25rem',
                                    marginRight: 'var(--space-2)',
                                    fontSize: '0.75rem',
                                    fontWeight: 600,
                                    opacity: activeTab === tab.id ? 1 : 0.7
                                }}>{tab.icon}</span>
                                {tab.label}
                            </button>
                        ))}
                    </div>

                    {/* Tab Content */}
                    <div
                        className="tab-content"
                        role="tabpanel"
                        id={`tabpanel-${activeTab}`}
                        aria-labelledby={activeTab}
                    >
                        {renderTabContent()}
                    </div>
                </div>
            </main>
        </div>
    );
}

    // ===== app.js =====
// TPM Dashboard - Main App Entry

// Auth Context for sharing authentication state
const AuthContext = createContext(null);

function useAuth() {
    return useContext(AuthContext);
}

// Main App Component
function App() {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isLoading, setIsLoading] = useState(true);

    // Check auth on mount
    useEffect(() => {
        checkAuth();
    }, []);

    async function checkAuth() {
        try {
            const response = await fetch('/api/v1/dashboard/queries');
            if (response.ok) {
                setIsAuthenticated(true);
            }
        } catch (err) {
            console.error('Auth check failed:', err);
        } finally {
            setIsLoading(false);
        }
    }

    async function login(username, password) {
        const response = await fetch('/api/v1/dashboard/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Login failed');
        }

        setIsAuthenticated(true);
    }

    async function logout() {
        try {
            await fetch('/api/v1/dashboard/logout', { method: 'POST' });
        } catch (err) {
            console.error('Logout error:', err);
        }
        setIsAuthenticated(false);
    }

    if (isLoading) {
        return (
            <div className="dashboard-layout flex items-center justify-center">
                <div className="skeleton-card" style={{ width: 300, height: 200 }} />
            </div>
        );
    }

    return (
        <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
            {isAuthenticated ? <Layout /> : <Login />}
        </AuthContext.Provider>
    );
}

// Render the app
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);

})();
