// Layout.js - Main Dashboard Layout Component
// Provides header with logout, landing stats section, and tab navigation
const { useState, useEffect } = React;

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
