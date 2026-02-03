// Sheet.js - Slide-out Panel Component
// A reusable sheet/drawer component for displaying details in a slide-out panel
// Used for drill-down views like error category details, miner details, origin details

const { useState, useEffect, useRef, useCallback } = React;

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
