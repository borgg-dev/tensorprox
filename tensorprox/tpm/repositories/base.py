"""Base repository helpers for TensorProx Management."""
from contextlib import contextmanager
from typing import Callable, Iterator

from shared.database import DatabaseConnection, get_tp_db_connection


class BaseRepository:
    """Provides connection management for repositories."""

    def __init__(self, connection_factory: Callable[[], DatabaseConnection] = get_tp_db_connection):
        self._connection_factory = connection_factory

    @contextmanager
    def connection(self) -> Iterator[DatabaseConnection]:
        """Yield a new database connection and close it afterwards."""
        conn = self._connection_factory()
        try:
            yield conn
        finally:
            conn.close()
