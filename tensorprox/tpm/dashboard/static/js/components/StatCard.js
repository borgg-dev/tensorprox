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
