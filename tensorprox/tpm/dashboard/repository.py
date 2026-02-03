"""Dashboard repository for read-only database access.

Uses the tp_dashboard Postgres user which has SELECT-only permissions.
"""

from contextlib import contextmanager
from typing import Iterator

import psycopg2
from psycopg2.extras import RealDictCursor

from .config import DashboardConfig


class DashboardRepository:
    """Read-only database access for the dashboard.

    Uses the dashboard-specific configuration with a read-only database user.
    All connections are set to readonly mode for additional safety.
    """

    @contextmanager
    def connection(self) -> Iterator[psycopg2.extensions.connection]:
        """Create a read-only database connection.

        Yields:
            A psycopg2 connection configured for read-only access.

        Example:
            with repo.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
        """
        conn = psycopg2.connect(
            host=DashboardConfig.db_host,
            port=DashboardConfig.db_port,
            dbname=DashboardConfig.db_name,
            user=DashboardConfig.db_user,
            password=DashboardConfig.db_password,
        )
        try:
            conn.set_session(readonly=True)
            yield conn
        finally:
            conn.close()

    def execute(self, sql: str, params: dict = None) -> list[dict]:
        """Execute a SQL query and return results as a list of dicts.

        Args:
            sql: SQL query string. Use %(name)s for named parameters.
            params: Optional dict of parameters for the query.

        Returns:
            List of rows as plain dicts (not RealDictRow).

        Example:
            rows = repo.execute(
                "SELECT * FROM miners WHERE status = %(status)s",
                {"status": "active"}
            )
        """
        with self.connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
                # Convert RealDictRow to plain dict
                return [dict(row) for row in rows]
