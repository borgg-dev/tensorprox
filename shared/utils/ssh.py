"""SSH utilities - Remote command execution and file transfer

Provides:
- ssh_exec() and scp_to_host() for remote operations
- SSHConnectionPool for connection reuse (critical for 256-miner scalability)
- Provider-aware SSH user resolution (single source of truth)
- Centralized provider → SSH user mapping

Design:
Provider classes import PROVIDER_SSH_USERS from this module, ensuring
a single source of truth. When adding a new provider, update the dict
here and provider classes automatically inherit the correct user.

Scalability:
For auditing 256 miners concurrently, use SSHConnectionPool to avoid
spawning 512+ SSH processes. The pool maintains persistent connections
and reuses them across commands.
"""
import subprocess
import logging
import os
import time
import threading
import asyncio
from typing import Dict, Tuple, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ============================================================================
# Provider → SSH User Mapping
# ============================================================================
# Provider classes import this dict to set their default_ssh_user.
# When adding a new provider, add ONE entry here and it propagates everywhere.

PROVIDER_SSH_USERS = {
    'aws': 'ubuntu',           # AWS EC2 Ubuntu AMIs
    'linode': 'root',          # Linode default
    'gcp': 'ubuntu',           # GCP Ubuntu images (future)
    'azure': 'azureuser',      # Azure Ubuntu images (future)
    'digitalocean': 'root',    # DigitalOcean default (future)
    'vultr': 'root',           # Vultr default (future)
    'hetzner': 'root',         # Hetzner Cloud (future)
    'ovh': 'ubuntu',           # OVH Cloud (future)
}


def get_ssh_user_for_provider(provider: str) -> str:
    """
    Get default SSH user for a cloud provider.

    Eliminates hardcoded 'ubuntu' or 'root' throughout codebase.
    Provider classes use this to set their default_ssh_user attribute.

    Args:
        provider: Provider identifier ('aws', 'linode', 'gcp', etc.)

    Returns:
        SSH username (e.g., 'ubuntu', 'root', 'azureuser')

    Example:
        >>> get_ssh_user_for_provider('aws')
        'ubuntu'

        >>> get_ssh_user_for_provider('linode')
        'root'

        >>> get_ssh_user_for_provider('unknown')
        'root'  # Safe default
    """
    return PROVIDER_SSH_USERS.get(provider.lower(), 'root')


def get_ssh_user_for_node(node_data: dict) -> str:
    """
    Get SSH user for a node from edge_nodes_db or similar structure.

    Args:
        node_data: Node dictionary with 'provider' key
                  (from state_manager.edge_nodes_db or database query)

    Returns:
        SSH username for the node

    Example:
        >>> node = state_manager.edge_nodes_db['edge-a']
        >>> user = get_ssh_user_for_node(node)
        'ubuntu'  # If node['provider'] == 'aws'
    """
    provider = node_data.get('provider', 'aws')  # Default to aws for backward compat
    return get_ssh_user_for_provider(provider)


def add_provider_to_mapping(provider: str, ssh_user: str) -> None:
    """
    Add a new provider → SSH user mapping at runtime.

    Useful for plugins/extensions that add provider support dynamically.

    Args:
        provider: Provider identifier (e.g., 'oracle', 'ibm')
        ssh_user: Default SSH user (e.g., 'opc', 'ubuntu')

    Example:
        >>> add_provider_to_mapping('oracle', 'opc')
        >>> get_ssh_user_for_provider('oracle')
        'opc'
    """
    PROVIDER_SSH_USERS[provider.lower()] = ssh_user


# ============================================================================
# SSH Command Execution
# ============================================================================


def ssh_exec(
    host: str,
    command: str,
    ssh_key_path: str,
    user: str = None,
    nodes_db: Dict = None,
    timeout: int = 30
) -> Tuple[int, str, str]:
    """
    Execute command on remote host.
    """
    import os
    # Expand ~ to home directory
    ssh_key_path = os.path.expanduser(ssh_key_path)

    # Auto-detect user: AWS instances use ubuntu, Linode instances use root
    if user is None and nodes_db:
        # Check if it's an Edge node (AWS)
        is_edge = any(node['public_ip'] == host for node in nodes_db.values())
        if is_edge:
            user = 'ubuntu'
        else:
            user = 'root'  # Linode instances (Exit Hubs, Origins)
    elif user is None:
        user = 'root'  # Default

    cmd = [
        'ssh', '-i', ssh_key_path,
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR',
        '-o', 'ConnectTimeout=10',
        f'{user}@{host}',
        command
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            # Log at DEBUG - callers interpret return codes contextually
            # (e.g., bpftool "No such file" is expected during cleanup)
            logger.debug(f"SSH command on {host}: rc={result.returncode}, stderr={result.stderr}")
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        logger.error(f"SSH exception on {host}: {e}")
        return 1, "", str(e)


def scp_to_host(
    host: str,
    source: str,
    destination: str,
    ssh_key_path: str,
    user: str = None,
    nodes_db: Dict = None
) -> Tuple[int, str, str]:
    """
    Copy file to remote host via SCP.

    Logic preserved - only adapted to take ssh_key_path as parameter.
    """
    import os
    # Expand ~ to home directory
    ssh_key_path = os.path.expanduser(ssh_key_path)

    if user is None and nodes_db:
        is_edge = any(node['public_ip'] == host for node in nodes_db.values())
        user = 'ubuntu' if is_edge else 'root'
    elif user is None:
        user = 'root'  # Default

    cmd = [
        'scp',
        '-i', ssh_key_path,
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR',
        source,
        f'{user}@{host}:{destination}'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            logger.error(f"SCP to {host} failed: rc={result.returncode}, stderr={result.stderr}")
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        logger.error(f"SCP exception to {host}: {e}")
        return 1, "", str(e)


# ============================================================================
# Paramiko SSH Helpers (for node.py and complex operations)
# ============================================================================


def create_ssh_client(
    host: str,
    username: str,
    key_filename: str,
    timeout: int = 30
):
    """
    Create and connect paramiko SSH client with standard settings.

    Centralizes repetitive paramiko connection code from node.py.

    Args:
        host: Remote host IP
        username: SSH username
        key_filename: Path to SSH private key
        timeout: Connection timeout in seconds

    Returns:
        Connected paramiko.SSHClient instance

    Raises:
        Exception if connection fails
    """
    import os
    import paramiko

    # Expand ~ to home directory (paramiko doesn't handle tilde)
    key_filename = os.path.expanduser(key_filename)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        host,
        username=username,
        key_filename=key_filename,
        timeout=timeout
    )
    return ssh


def sftp_upload(
    host: str,
    username: str,
    key_filename: str,
    local_path: str,
    remote_path: str,
    timeout: int = 30
) -> Tuple[bool, Optional[str]]:
    """
    Upload file via SFTP using paramiko.

    Centralizes SFTP upload pattern from node.py post_provision.

    Args:
        host: Remote host IP
        username: SSH username
        key_filename: Path to SSH private key
        local_path: Local file path to upload
        remote_path: Remote destination path
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (success, error_message). error_message is None on success.
    """
    try:
        ssh = create_ssh_client(host, username, key_filename, timeout)
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        ssh.close()
        return True, None
    except Exception as e:
        error_msg = f"SFTP upload failed: {local_path} -> {host}:{remote_path}: {e}"
        logger.error(error_msg)
        return False, error_msg


def ssh_check_service_running(
    host: str,
    username: str,
    key_filename: str,
    service_name: str,
    timeout: int = 30
) -> bool:
    """
    Check if a systemd service is running on a remote host.

    Args:
        host: Remote host IP
        username: SSH username
        key_filename: Path to SSH private key
        service_name: Name of the systemd service to check
        timeout: Connection timeout in seconds

    Returns:
        True if the service is active/running, False otherwise
    """
    # Use systemctl is-active which returns 0 for active services
    command = f"systemctl is-active {service_name}"

    exit_code, stdout, stderr = ssh_exec(
        host=host,
        command=command,
        ssh_key_path=key_filename,
        user=username,
        timeout=timeout
    )

    # systemctl is-active returns 0 if service is active
    if exit_code == 0 and stdout.strip() == "active":
        return True

    return False


# ============================================================================
# SSH Connection Pool - For 256-Miner Scalability
# ============================================================================


@dataclass
class PooledConnection:
    """A pooled SSH connection with metadata."""
    client: Any  # paramiko.SSHClient
    host: str
    username: str
    key_filename: str
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    in_use: bool = False

    def is_alive(self) -> bool:
        """Check if the connection is still alive."""
        try:
            transport = self.client.get_transport()
            if transport is None or not transport.is_active():
                return False
            # Send a keepalive to verify connection
            transport.send_ignore()
            return True
        except Exception:
            return False


class SSHConnectionPool:
    """
    Thread-safe SSH connection pool using paramiko.

    Maintains persistent SSH connections to scrubbers, allowing connection
    reuse across multiple commands. Critical for 256-miner audits where
    spawning 512+ SSH processes would exhaust system resources.

    Usage:
        # Get global pool instance
        pool = SSHConnectionPool.get_instance()

        # Execute command using pooled connection
        exit_code, stdout, stderr = pool.exec(
            host="1.2.3.4",
            command="echo hello",
            ssh_key_path="/path/to/key",
            user="ubuntu"
        )

        # Async version for use in async code
        exit_code, stdout, stderr = await pool.exec_async(...)

        # Close all connections when done
        pool.close_all()

    Configuration:
        - max_connections_per_host: Maximum pooled connections per host (default 4)
        - connection_timeout: Connection establishment timeout (default 30s)
        - command_timeout: Command execution timeout (default 30s)
        - max_idle_time: Close connections idle longer than this (default 300s)
    """

    _instance: Optional["SSHConnectionPool"] = None
    _lock = threading.Lock()

    def __init__(
        self,
        max_connections_per_host: int = 4,
        connection_timeout: int = 30,
        command_timeout: int = 30,
        max_idle_time: int = 300,
    ):
        self.max_connections_per_host = max_connections_per_host
        self.connection_timeout = connection_timeout
        self.command_timeout = command_timeout
        self.max_idle_time = max_idle_time

        # Pool storage: {(host, user, key_path): [PooledConnection, ...]}
        self._pool: Dict[Tuple[str, str, str], list] = {}
        self._pool_lock = threading.Lock()

        # Stats for monitoring
        self._stats = {
            "connections_created": 0,
            "connections_reused": 0,
            "connections_closed": 0,
            "commands_executed": 0,
        }

    @classmethod
    def get_instance(cls) -> "SSHConnectionPool":
        """Get or create the global pool instance (singleton)."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = SSHConnectionPool()
                    logger.info("SSH connection pool initialized")
        return cls._instance

    def _get_pool_key(self, host: str, user: str, key_path: str) -> Tuple[str, str, str]:
        """Generate pool key from connection parameters."""
        return (host, user, os.path.expanduser(key_path))

    def _create_connection(self, host: str, user: str, key_path: str) -> PooledConnection:
        """Create a new SSH connection."""
        import paramiko

        key_path = os.path.expanduser(key_path)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host,
            username=user,
            key_filename=key_path,
            timeout=self.connection_timeout,
            allow_agent=False,
            look_for_keys=False,
        )

        conn = PooledConnection(
            client=client,
            host=host,
            username=user,
            key_filename=key_path,
        )

        self._stats["connections_created"] += 1
        logger.debug(f"SSH pool: created new connection to {user}@{host}")

        return conn

    def _get_connection(self, host: str, user: str, key_path: str) -> PooledConnection:
        """Get an available connection from pool or create new one."""
        pool_key = self._get_pool_key(host, user, key_path)

        with self._pool_lock:
            # Initialize pool for this host if needed
            if pool_key not in self._pool:
                self._pool[pool_key] = []

            connections = self._pool[pool_key]

            # Try to find an available connection
            for conn in connections:
                if not conn.in_use and conn.is_alive():
                    conn.in_use = True
                    conn.last_used = time.time()
                    self._stats["connections_reused"] += 1
                    logger.debug(f"SSH pool: reusing connection to {user}@{host}")
                    return conn

            # Clean up dead connections
            alive_conns = []
            for conn in connections:
                if conn.is_alive() or conn.in_use:
                    alive_conns.append(conn)
                else:
                    try:
                        conn.client.close()
                    except Exception:
                        pass
                    self._stats["connections_closed"] += 1
            self._pool[pool_key] = alive_conns

            # Create new connection if under limit
            if len(alive_conns) < self.max_connections_per_host:
                try:
                    conn = self._create_connection(host, user, key_path)
                    conn.in_use = True
                    self._pool[pool_key].append(conn)
                    return conn
                except Exception as e:
                    logger.warning(f"SSH pool: failed to create connection to {host}: {e}")
                    raise

            # All connections in use, wait and retry or create temporary connection
            # For now, create a temporary connection (will be closed after use)
            logger.debug(f"SSH pool: all {self.max_connections_per_host} connections busy to {host}, creating temporary")
            conn = self._create_connection(host, user, key_path)
            conn.in_use = True
            # Don't add to pool - will be closed after use
            return conn

    def _release_connection(self, conn: PooledConnection, pool_key: Tuple[str, str, str]) -> None:
        """Release a connection back to the pool."""
        with self._pool_lock:
            if pool_key in self._pool and conn in self._pool[pool_key]:
                conn.in_use = False
                conn.last_used = time.time()
            else:
                # Temporary connection - close it
                try:
                    conn.client.close()
                except Exception:
                    pass
                self._stats["connections_closed"] += 1

    def exec(
        self,
        host: str,
        command: str,
        ssh_key_path: str,
        user: str = "root",
        timeout: int = None,
    ) -> Tuple[int, str, str]:
        """
        Execute command on remote host using pooled connection.

        Args:
            host: Remote host IP
            command: Command to execute
            ssh_key_path: Path to SSH private key
            user: SSH username (default 'root')
            timeout: Command timeout in seconds (default: pool's command_timeout)

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        if timeout is None:
            timeout = self.command_timeout

        pool_key = self._get_pool_key(host, user, ssh_key_path)
        conn = None

        try:
            conn = self._get_connection(host, user, ssh_key_path)

            # Execute command
            stdin, stdout, stderr = conn.client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            stdout_str = stdout.read().decode('utf-8', errors='replace')
            stderr_str = stderr.read().decode('utf-8', errors='replace')

            self._stats["commands_executed"] += 1

            return exit_code, stdout_str, stderr_str

        except Exception as e:
            logger.debug(f"SSH pool exec error on {host}: {e}")
            # Connection may be dead, close it
            if conn:
                try:
                    conn.client.close()
                except Exception:
                    pass
                with self._pool_lock:
                    if pool_key in self._pool and conn in self._pool[pool_key]:
                        self._pool[pool_key].remove(conn)
                self._stats["connections_closed"] += 1
            return 1, "", str(e)

        finally:
            if conn:
                self._release_connection(conn, pool_key)

    async def exec_async(
        self,
        host: str,
        command: str,
        ssh_key_path: str,
        user: str = "root",
        timeout: int = None,
    ) -> Tuple[int, str, str]:
        """
        Execute command on remote host using pooled connection (async version).

        Runs the synchronous exec() in a thread pool to avoid blocking.

        Args:
            host: Remote host IP
            command: Command to execute
            ssh_key_path: Path to SSH private key
            user: SSH username (default 'root')
            timeout: Command timeout in seconds

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,  # Use default executor
            lambda: self.exec(host, command, ssh_key_path, user, timeout)
        )

    def cleanup_idle(self) -> int:
        """
        Close connections that have been idle too long.

        Returns number of connections closed.
        """
        closed = 0
        now = time.time()

        with self._pool_lock:
            for pool_key, connections in list(self._pool.items()):
                active_conns = []
                for conn in connections:
                    if conn.in_use:
                        active_conns.append(conn)
                    elif (now - conn.last_used) > self.max_idle_time:
                        try:
                            conn.client.close()
                        except Exception:
                            pass
                        closed += 1
                        self._stats["connections_closed"] += 1
                        logger.debug(f"SSH pool: closed idle connection to {conn.host}")
                    else:
                        active_conns.append(conn)
                self._pool[pool_key] = active_conns

        return closed

    def close_all(self) -> None:
        """Close all pooled connections."""
        with self._pool_lock:
            for pool_key, connections in self._pool.items():
                for conn in connections:
                    try:
                        conn.client.close()
                    except Exception:
                        pass
                    self._stats["connections_closed"] += 1
            self._pool.clear()
        logger.info("SSH pool: all connections closed")

    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics."""
        with self._pool_lock:
            total_connections = sum(len(conns) for conns in self._pool.values())
            in_use = sum(
                sum(1 for c in conns if c.in_use)
                for conns in self._pool.values()
            )

        return {
            **self._stats,
            "current_connections": total_connections,
            "connections_in_use": in_use,
            "hosts_connected": len(self._pool),
        }


def ssh_exec_pooled(
    host: str,
    command: str,
    ssh_key_path: str,
    user: str = None,
    nodes_db: Dict = None,
    timeout: int = 30,
) -> Tuple[int, str, str]:
    """
    Execute command on remote host using pooled SSH connection.

    This is a drop-in replacement for ssh_exec() that uses connection pooling.
    Use this for high-concurrency scenarios (e.g., 256-miner audits).

    Args:
        host: Remote host IP
        command: Command to execute
        ssh_key_path: Path to SSH private key
        user: SSH username (auto-detected if None)
        nodes_db: Optional node database for user auto-detection
        timeout: Command timeout in seconds

    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    # Auto-detect user (same logic as ssh_exec)
    if user is None and nodes_db:
        is_edge = any(node.get('public_ip') == host for node in nodes_db.values())
        user = 'ubuntu' if is_edge else 'root'
    elif user is None:
        user = 'root'

    pool = SSHConnectionPool.get_instance()
    return pool.exec(host, command, ssh_key_path, user, timeout)


async def ssh_exec_pooled_async(
    host: str,
    command: str,
    ssh_key_path: str,
    user: str = None,
    nodes_db: Dict = None,
    timeout: int = 30,
) -> Tuple[int, str, str]:
    """
    Execute command on remote host using pooled SSH connection (async).

    Async version of ssh_exec_pooled() for use in async code.

    Args:
        host: Remote host IP
        command: Command to execute
        ssh_key_path: Path to SSH private key
        user: SSH username (auto-detected if None)
        nodes_db: Optional node database for user auto-detection
        timeout: Command timeout in seconds

    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    # Auto-detect user
    if user is None and nodes_db:
        is_edge = any(node.get('public_ip') == host for node in nodes_db.values())
        user = 'ubuntu' if is_edge else 'root'
    elif user is None:
        user = 'root'

    pool = SSHConnectionPool.get_instance()
    return await pool.exec_async(host, command, ssh_key_path, user, timeout)
