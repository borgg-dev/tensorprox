// Charts.js - Recharts Wrapper Components
// Provides reusable chart components with shadcn-inspired styling

// Extract React hooks and Recharts components from globals
const { useState, useMemo } = React;
const {
    ResponsiveContainer,
    AreaChart: RechartsArea,
    Area,
    BarChart: RechartsBar,
    Bar,
    LineChart: RechartsLine,
    Line,
    PieChart: RechartsPie,
    Pie,
    Cell,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend
} = Recharts;

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
