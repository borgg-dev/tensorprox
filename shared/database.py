"""Database connection management with connection pooling for scalability."""
import sqlite3
import threading
import atexit
from pathlib import Path
import psycopg2
import psycopg2.extras
import psycopg2.pool
from typing import Optional, Dict, List, Any, Iterable, Union
from functools import lru_cache
from contextlib import contextmanager
from loguru import logger
from shared.config import get_settings, get_tp_management_settings


# === CONNECTION POOL CONFIGURATION ===
# These settings are tuned for multi-miner/multi-validator scalability
# Increased from 5/20 to 10/50 to handle 10+ concurrent background services
# and burst operations like scrubber deployments
POOL_MIN_CONNECTIONS = 10      # Minimum connections to keep in pool
POOL_MAX_CONNECTIONS = 50      # Maximum connections (PostgreSQL default max=100)
CONNECTION_TIMEOUT = 30        # Seconds to wait for connection from pool
STATEMENT_TIMEOUT_MS = 30000   # 30 second query timeout to prevent blocking


# Global connection pools (thread-safe)
_db_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None
_tp_db_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None
_pool_lock = threading.Lock()


def _init_db_pool() -> psycopg2.pool.ThreadedConnectionPool:
    """Initialize the main database connection pool (thread-safe singleton)."""
    global _db_pool
    with _pool_lock:
        if _db_pool is None:
            settings = get_settings()
            logger.info(
                f"Initializing DB connection pool: min={POOL_MIN_CONNECTIONS}, "
                f"max={POOL_MAX_CONNECTIONS}, host={settings.db_host}"
            )
            _db_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=POOL_MIN_CONNECTIONS,
                maxconn=POOL_MAX_CONNECTIONS,
                host=settings.db_host,
                port=settings.db_port,
                database=settings.db_name,
                user=settings.db_user,
                password=settings.db_pass,
                # Connection options for reliability
                connect_timeout=CONNECTION_TIMEOUT,
                options=f'-c statement_timeout={STATEMENT_TIMEOUT_MS}',
            )
        return _db_pool


def _init_tp_db_pool() -> psycopg2.pool.ThreadedConnectionPool:
    """Initialize the TPM database connection pool (thread-safe singleton)."""
    global _tp_db_pool
    with _pool_lock:
        if _tp_db_pool is None:
            settings = get_tp_management_settings()
            logger.info(
                f"Initializing TPM DB connection pool: min={POOL_MIN_CONNECTIONS}, "
                f"max={POOL_MAX_CONNECTIONS}, host={settings.tp_db_host}"
            )
            _tp_db_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=POOL_MIN_CONNECTIONS,
                maxconn=POOL_MAX_CONNECTIONS,
                host=settings.tp_db_host,
                port=settings.tp_db_port,
                database=settings.tp_db_name,
                user=settings.tp_db_user,
                password=settings.tp_db_pass,
                connect_timeout=CONNECTION_TIMEOUT,
                options=f'-c statement_timeout={STATEMENT_TIMEOUT_MS}',
            )
        return _tp_db_pool


def _cleanup_pools():
    """Cleanup connection pools on program exit."""
    global _db_pool, _tp_db_pool
    with _pool_lock:
        if _db_pool is not None:
            try:
                _db_pool.closeall()
                logger.info("Main DB connection pool closed")
            except Exception as e:
                logger.warning(f"Error closing main DB pool: {e}")
            _db_pool = None
        if _tp_db_pool is not None:
            try:
                _tp_db_pool.closeall()
                logger.info("TPM DB connection pool closed")
            except Exception as e:
                logger.warning(f"Error closing TPM DB pool: {e}")
            _tp_db_pool = None


# Register cleanup on program exit
atexit.register(_cleanup_pools)


class DatabaseConnection:
    """Database connection wrapper with helper methods"""

    def __init__(self, conn):
        self.conn = conn

    def execute(self, query: str, params: tuple = ()) -> None:
        """Execute INSERT/UPDATE/DELETE query"""
        with self.conn.cursor() as cursor:
            cursor.execute(query, params)
        self.conn.commit()

    def cursor(self, *args, **kwargs):
        """Proxy cursor creation to underlying psycopg2 connection."""
        return self.conn.cursor(*args, **kwargs)

    def query_one(self, query: str, params: tuple = ()) -> Optional[Dict]:
        """Execute SELECT query and return one row as dict"""
        with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(query, params)
            row = cursor.fetchone()
            return dict(row) if row else None

    def execute_returning_one(self, query: str, params: tuple = ()) -> Optional[Dict]:
        """
        Execute INSERT/UPDATE/DELETE ... RETURNING and commit the transaction.
        Keeps query_one() read-only while allowing repositories to fetch rows
        from write operations without relying on autocommit.
        """
        with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(query, params)
            row = cursor.fetchone()
        self.conn.commit()
        return dict(row) if row else None

    def query_all(self, query: str, params: tuple = ()) -> List[Dict]:
        """Execute SELECT query and return all rows as list of dicts"""
        with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def commit(self):
        """Commit the current transaction"""
        self.conn.commit()

    def rollback(self):
        """Rollback the current transaction"""
        self.conn.rollback()

    def close(self):
        """Close database connection"""
        self.conn.close()


class PooledDatabaseConnection(DatabaseConnection):
    """
    Database connection wrapper that returns connection to pool on close.

    This class extends DatabaseConnection to work with connection pooling.
    When close() is called, the connection is returned to the pool instead
    of being actually closed, enabling connection reuse.
    """

    def __init__(self, conn, pool: psycopg2.pool.ThreadedConnectionPool):
        super().__init__(conn)
        self._pool = pool
        self._returned = False

    def close(self):
        """Return connection to pool instead of closing it."""
        if not self._returned and self._pool is not None:
            try:
                # Rollback any uncommitted transaction before returning
                self.conn.rollback()
                self._pool.putconn(self.conn)
                self._returned = True
            except Exception as e:
                logger.warning(f"Error returning connection to pool: {e}")
                # Try to actually close the connection if pool return fails
                try:
                    self.conn.close()
                except Exception:
                    pass

    def __del__(self):
        """Ensure connection is returned to pool on garbage collection."""
        self.close()

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Return connection to pool on context exit."""
        self.close()
        return False


def get_db_connection() -> PooledDatabaseConnection:
    """
    Get database connection from the connection pool.

    Returns a pooled connection that will be returned to the pool when closed.
    This is thread-safe and supports high concurrency.

    IMPORTANT: Always close the connection when done (use context manager or try/finally).

    Usage:
        # Option 1: Context manager (recommended)
        with get_db_connection() as db:
            db.execute("SELECT * FROM ...")

        # Option 2: Manual close
        db = get_db_connection()
        try:
            db.execute("SELECT * FROM ...")
        finally:
            db.close()
    """
    pool = _init_db_pool()
    max_retries = 3
    last_error = None

    for attempt in range(max_retries):
        try:
            conn = pool.getconn()

            # Verify connection is usable
            if conn.closed:
                try:
                    pool.putconn(conn, close=True)
                except Exception:
                    pass
                continue

            # Ensure clean transaction state
            try:
                conn.rollback()
            except Exception as e:
                # Connection is broken, discard and retry
                try:
                    pool.putconn(conn, close=True)
                except Exception:
                    pass
                last_error = e
                continue

            # Verify again after rollback
            if conn.closed:
                try:
                    pool.putconn(conn, close=True)
                except Exception:
                    pass
                continue

            conn.autocommit = False
            return PooledDatabaseConnection(conn, pool)

        except psycopg2.pool.PoolError as e:
            logger.error(f"Connection pool exhausted: {e}")
            raise RuntimeError(
                f"Database connection pool exhausted (max={POOL_MAX_CONNECTIONS}). "
                "This indicates too many concurrent database operations. "
                "Ensure connections are being properly closed."
            ) from e
        except Exception as e:
            last_error = e
            continue

    # All retries exhausted
    logger.error(f"Failed to get valid database connection after {max_retries} attempts: {last_error}")
    raise RuntimeError(f"Failed to get valid database connection: {last_error}")


def get_tp_db_connection() -> PooledDatabaseConnection:
    """
    Get TensorProx management database connection from pool.

    Returns a pooled connection for the TPM database.
    See get_db_connection() for usage details.
    """
    pool = _init_tp_db_pool()
    max_retries = 3
    last_error = None

    for attempt in range(max_retries):
        try:
            conn = pool.getconn()

            if conn.closed:
                try:
                    pool.putconn(conn, close=True)
                except Exception:
                    pass
                continue

            try:
                conn.rollback()
            except Exception as e:
                try:
                    pool.putconn(conn, close=True)
                except Exception:
                    pass
                last_error = e
                continue

            if conn.closed:
                try:
                    pool.putconn(conn, close=True)
                except Exception:
                    pass
                continue

            conn.autocommit = False
            return PooledDatabaseConnection(conn, pool)

        except psycopg2.pool.PoolError as e:
            logger.error(f"TPM connection pool exhausted: {e}")
            raise RuntimeError(
                f"TPM database connection pool exhausted (max={POOL_MAX_CONNECTIONS}). "
                "Ensure connections are being properly closed."
            ) from e
        except Exception as e:
            last_error = e
            continue

    logger.error(f"Failed to get valid TPM database connection after {max_retries} attempts: {last_error}")
    raise RuntimeError(f"Failed to get valid TPM database connection: {last_error}")


@contextmanager
def db_connection():
    """
    Context manager for database connection with automatic cleanup.

    Usage:
        with db_connection() as db:
            result = db.query_one("SELECT * FROM ...")
    """
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def tp_db_connection():
    """
    Context manager for TPM database connection with automatic cleanup.

    Usage:
        with tp_db_connection() as db:
            result = db.query_one("SELECT * FROM ...")
    """
    conn = get_tp_db_connection()
    try:
        yield conn
    finally:
        conn.close()


def get_pool_status() -> Dict[str, Any]:
    """
    Get connection pool status for monitoring.

    Returns dict with pool statistics for debugging and monitoring.
    """
    status = {
        "db_pool_initialized": _db_pool is not None,
        "tp_db_pool_initialized": _tp_db_pool is not None,
        "pool_min_connections": POOL_MIN_CONNECTIONS,
        "pool_max_connections": POOL_MAX_CONNECTIONS,
    }
    return status


def get_dict_cursor(conn):
    """
    Return a RealDictCursor for the given psycopg2 connection.

    Central helper so services don't have to repeat cursor_factory wiring.
    """
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


# Alias for backward compatibility with subnet.py
get_connection = get_tp_db_connection


class SQLiteDatabase:
    """
    Lightweight SQLite wrapper for services that need local persistence.

    Designed for Traffic Manager state tracking, fully independent from
    the Postgres database used by Miner.
    """

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path).expanduser()
        if self.db_path.parent:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Single shared connection guarded by a lock to support Flask threads
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def execute(self, query: str, params: tuple = ()) -> None:
        """Execute INSERT/UPDATE/DELETE statement."""
        with self._lock:
            self._conn.execute(query, params)
            self._conn.commit()

    def executemany(self, query: str, param_list: Iterable[tuple]) -> None:
        """Execute statement with multiple parameter sets."""
        with self._lock:
            self._conn.executemany(query, param_list)
            self._conn.commit()

    def query_one(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        """Execute SELECT statement and return a single row as dict."""
        with self._lock:
            cursor = self._conn.execute(query, params)
            row = cursor.fetchone()
            return dict(row) if row else None

    def query_all(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute SELECT statement and return all rows as list of dicts."""
        with self._lock:
            cursor = self._conn.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def close(self) -> None:
        """Close SQLite connection."""
        with self._lock:
            self._conn.close()
