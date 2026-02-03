// Login.js - Login Component
const { useState } = React;

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
