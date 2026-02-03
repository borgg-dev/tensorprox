// TPM Dashboard - Main App Entry
const { useState, useEffect, createContext, useContext } = React;

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
