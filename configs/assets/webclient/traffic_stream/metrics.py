"""
Metrics storage and aggregation for traffic stream client.

SQLite-based metrics database with automatic hourly and daily aggregation.
Stores raw request data and provides time-windowed statistics.
"""

import time
from pathlib import Path
from typing import Optional

import aiosqlite


class MetricsDB:
    """SQLite metrics storage with aggregation.

    Stores individual request metrics and provides automatic aggregation
    into hourly and daily statistics. Supports time-windowed queries
    and automatic pruning of old data.
    """

    def __init__(self, db_path: str = "/var/lib/traffic_stream/metrics.db"):
        """Initialize database, create tables if needed.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None
        self._initialized = False

    async def _ensure_initialized(self):
        """Ensure database is initialized and tables exist."""
        if self._initialized:
            return

        # Create parent directory if needed
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        # Connect to database
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row

        # Create tables
        await self._create_tables()
        self._initialized = True

    async def _create_tables(self):
        """Create database tables if they don't exist."""
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY,
                timestamp REAL NOT NULL,
                origin_ip TEXT NOT NULL,
                service TEXT NOT NULL,
                port INTEGER NOT NULL,
                success INTEGER NOT NULL,
                latency_ms REAL,
                error TEXT,
                pattern TEXT
            )
        """)

        await self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_requests_timestamp
            ON requests(timestamp)
        """)

        await self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_requests_origin
            ON requests(origin_ip, timestamp)
        """)

        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS hourly_stats (
                id INTEGER PRIMARY KEY,
                hour_start REAL NOT NULL,
                origin_ip TEXT NOT NULL,
                service TEXT NOT NULL,
                request_count INTEGER NOT NULL,
                success_count INTEGER NOT NULL,
                latency_min REAL,
                latency_max REAL,
                latency_avg REAL,
                latency_p95 REAL,
                UNIQUE(hour_start, origin_ip, service)
            )
        """)

        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS daily_stats (
                id INTEGER PRIMARY KEY,
                day_start REAL NOT NULL,
                origin_ip TEXT NOT NULL,
                service TEXT NOT NULL,
                request_count INTEGER NOT NULL,
                success_count INTEGER NOT NULL,
                latency_min REAL,
                latency_max REAL,
                latency_avg REAL,
                latency_p95 REAL,
                UNIQUE(day_start, origin_ip, service)
            )
        """)

        await self._conn.commit()

    async def record_request(
        self,
        origin_ip: str,
        service: str,
        port: int,
        success: bool,
        latency_ms: float,
        error: Optional[str] = None,
        pattern: Optional[str] = None
    ):
        """Record a single request result.

        Args:
            origin_ip: Origin server IP address
            service: Service name (e.g., "tcp_echo", "http")
            port: Port number
            success: Whether request succeeded
            latency_ms: Request latency in milliseconds
            error: Error message if request failed
            pattern: Traffic pattern name (e.g., "burst", "steady")
        """
        await self._ensure_initialized()

        timestamp = time.time()
        success_int = 1 if success else 0

        await self._conn.execute("""
            INSERT INTO requests (
                timestamp, origin_ip, service, port, success,
                latency_ms, error, pattern
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, origin_ip, service, port, success_int,
              latency_ms, error, pattern))

        await self._conn.commit()

    async def aggregate_hourly(self):
        """Roll up raw requests into hourly_stats table.

        Groups requests by hour, origin IP, and service, calculating:
        - Request count
        - Success count
        - Min/max/avg latency
        - P95 latency

        Uses INSERT OR REPLACE to update existing hourly aggregates.
        """
        await self._ensure_initialized()

        # Get the oldest unaggregated request
        cursor = await self._conn.execute("""
            SELECT MIN(timestamp) as min_ts FROM requests
        """)
        row = await cursor.fetchone()

        if not row or row["min_ts"] is None:
            return  # No requests to aggregate

        min_timestamp = row["min_ts"]

        # Calculate hour boundaries
        # Start from the beginning of the hour containing min_timestamp
        current_hour = int(min_timestamp / 3600) * 3600
        current_time = time.time()

        # Aggregate up to the previous completed hour
        last_complete_hour = int(current_time / 3600) * 3600

        while current_hour < last_complete_hour:
            hour_end = current_hour + 3600

            # Get all origin/service combinations for this hour
            cursor = await self._conn.execute("""
                SELECT DISTINCT origin_ip, service
                FROM requests
                WHERE timestamp >= ? AND timestamp < ?
            """, (current_hour, hour_end))

            combinations = await cursor.fetchall()

            for combo in combinations:
                origin_ip = combo["origin_ip"]
                service = combo["service"]

                # Get latencies for p95 calculation
                cursor = await self._conn.execute("""
                    SELECT latency_ms
                    FROM requests
                    WHERE timestamp >= ? AND timestamp < ?
                    AND origin_ip = ? AND service = ?
                    AND latency_ms IS NOT NULL
                    ORDER BY latency_ms
                """, (current_hour, hour_end, origin_ip, service))

                latencies = [row["latency_ms"] for row in await cursor.fetchall()]

                # Calculate p95
                p95 = self._calculate_p95(latencies) if latencies else None

                # Calculate aggregates
                cursor = await self._conn.execute("""
                    INSERT OR REPLACE INTO hourly_stats (
                        hour_start, origin_ip, service,
                        request_count, success_count,
                        latency_min, latency_max, latency_avg, latency_p95
                    )
                    SELECT
                        ? as hour_start,
                        origin_ip,
                        service,
                        COUNT(*) as request_count,
                        SUM(success) as success_count,
                        MIN(latency_ms) as latency_min,
                        MAX(latency_ms) as latency_max,
                        AVG(latency_ms) as latency_avg,
                        ? as latency_p95
                    FROM requests
                    WHERE timestamp >= ? AND timestamp < ?
                    AND origin_ip = ? AND service = ?
                """, (current_hour, p95, current_hour, hour_end, origin_ip, service))

            current_hour = hour_end

        await self._conn.commit()

    async def aggregate_daily(self):
        """Roll up hourly_stats into daily_stats table.

        Groups hourly stats by day, origin IP, and service, calculating:
        - Total request count
        - Total success count
        - Min/max/avg latency across all hourly aggregates
        - P95 latency (calculated from hourly p95 values)

        Uses INSERT OR REPLACE to update existing daily aggregates.
        """
        await self._ensure_initialized()

        # Get the oldest unaggregated hourly stat
        cursor = await self._conn.execute("""
            SELECT MIN(hour_start) as min_hour FROM hourly_stats
        """)
        row = await cursor.fetchone()

        if not row or row["min_hour"] is None:
            return  # No hourly stats to aggregate

        min_hour = row["min_hour"]

        # Calculate day boundaries
        # Start from the beginning of the day containing min_hour
        current_day = int(min_hour / 86400) * 86400
        current_time = time.time()

        # Aggregate up to the previous completed day
        last_complete_day = int(current_time / 86400) * 86400

        while current_day < last_complete_day:
            day_end = current_day + 86400

            # Get all origin/service combinations for this day
            cursor = await self._conn.execute("""
                SELECT DISTINCT origin_ip, service
                FROM hourly_stats
                WHERE hour_start >= ? AND hour_start < ?
            """, (current_day, day_end))

            combinations = await cursor.fetchall()

            for combo in combinations:
                origin_ip = combo["origin_ip"]
                service = combo["service"]

                # Get p95 values for this day's calculation
                cursor = await self._conn.execute("""
                    SELECT latency_p95
                    FROM hourly_stats
                    WHERE hour_start >= ? AND hour_start < ?
                    AND origin_ip = ? AND service = ?
                    AND latency_p95 IS NOT NULL
                    ORDER BY latency_p95
                """, (current_day, day_end, origin_ip, service))

                p95_values = [row["latency_p95"] for row in await cursor.fetchall()]

                # Calculate p95 from hourly p95 values
                daily_p95 = self._calculate_p95(p95_values) if p95_values else None

                # Calculate aggregates
                await self._conn.execute("""
                    INSERT OR REPLACE INTO daily_stats (
                        day_start, origin_ip, service,
                        request_count, success_count,
                        latency_min, latency_max, latency_avg, latency_p95
                    )
                    SELECT
                        ? as day_start,
                        origin_ip,
                        service,
                        SUM(request_count) as request_count,
                        SUM(success_count) as success_count,
                        MIN(latency_min) as latency_min,
                        MAX(latency_max) as latency_max,
                        AVG(latency_avg) as latency_avg,
                        ? as latency_p95
                    FROM hourly_stats
                    WHERE hour_start >= ? AND hour_start < ?
                    AND origin_ip = ? AND service = ?
                """, (current_day, daily_p95, current_day, day_end, origin_ip, service))

            current_day = day_end

        await self._conn.commit()

    async def prune_old_data(self):
        """Delete raw requests > 48h, hourly stats > 30 days.

        Automatically removes old data to keep database size manageable:
        - Raw requests older than 48 hours
        - Hourly stats older than 30 days
        - Daily stats are kept indefinitely
        """
        await self._ensure_initialized()

        current_time = time.time()

        # Delete raw requests older than 48 hours
        cutoff_48h = current_time - (48 * 3600)
        await self._conn.execute("""
            DELETE FROM requests WHERE timestamp < ?
        """, (cutoff_48h,))

        # Delete hourly stats older than 30 days
        cutoff_30d = current_time - (30 * 86400)
        await self._conn.execute("""
            DELETE FROM hourly_stats WHERE hour_start < ?
        """, (cutoff_30d,))

        await self._conn.commit()

    async def get_stats(
        self,
        origin_ip: Optional[str] = None,
        window: str = "1h"  # 1h, 8h, 24h, 7d, 30d
    ) -> dict:
        """Get aggregated statistics for time window.

        Args:
            origin_ip: Filter by origin IP, or None for all origins
            window: Time window - "1h", "8h", "24h", "7d", "30d"

        Returns:
            Dictionary with aggregated statistics:
            {
                "window": "1h",
                "start_time": 1234567890.0,
                "end_time": 1234571490.0,
                "origins": {
                    "192.0.2.1": {
                        "services": {
                            "tcp_echo": {
                                "request_count": 1000,
                                "success_count": 995,
                                "success_rate": 0.995,
                                "latency_min": 1.2,
                                "latency_max": 45.6,
                                "latency_avg": 3.4,
                                "latency_p95": 12.3
                            },
                            ...
                        },
                        "total": {
                            "request_count": 5000,
                            "success_count": 4950,
                            "success_rate": 0.99
                        }
                    },
                    ...
                },
                "total": {
                    "request_count": 10000,
                    "success_count": 9900,
                    "success_rate": 0.99
                }
            }
        """
        await self._ensure_initialized()

        # Parse time window
        window_seconds = self._parse_window(window)
        end_time = time.time()
        start_time = end_time - window_seconds

        # Determine which table to query based on window
        if window_seconds <= 24 * 3600:  # Up to 24 hours - use hourly stats
            table = "hourly_stats"
            time_column = "hour_start"
        else:  # More than 24 hours - use daily stats
            table = "daily_stats"
            time_column = "day_start"

        # Build query
        query = f"""
            SELECT
                origin_ip,
                service,
                SUM(request_count) as request_count,
                SUM(success_count) as success_count,
                MIN(latency_min) as latency_min,
                MAX(latency_max) as latency_max,
                AVG(latency_avg) as latency_avg,
                AVG(latency_p95) as latency_p95
            FROM {table}
            WHERE {time_column} >= ?
        """

        params = [start_time]

        if origin_ip:
            query += " AND origin_ip = ?"
            params.append(origin_ip)

        query += " GROUP BY origin_ip, service"

        cursor = await self._conn.execute(query, params)
        rows = await cursor.fetchall()

        # Build response structure
        origins = {}
        total_requests = 0
        total_success = 0

        for row in rows:
            origin = row["origin_ip"]
            service = row["service"]
            request_count = row["request_count"]
            success_count = row["success_count"]

            if origin not in origins:
                origins[origin] = {
                    "services": {},
                    "total": {
                        "request_count": 0,
                        "success_count": 0,
                        "success_rate": 0.0
                    }
                }

            # Service stats
            success_rate = success_count / request_count if request_count > 0 else 0.0
            origins[origin]["services"][service] = {
                "request_count": request_count,
                "success_count": success_count,
                "success_rate": round(success_rate, 4),
                "latency_min": round(row["latency_min"], 2) if row["latency_min"] else None,
                "latency_max": round(row["latency_max"], 2) if row["latency_max"] else None,
                "latency_avg": round(row["latency_avg"], 2) if row["latency_avg"] else None,
                "latency_p95": round(row["latency_p95"], 2) if row["latency_p95"] else None,
            }

            # Update origin totals
            origins[origin]["total"]["request_count"] += request_count
            origins[origin]["total"]["success_count"] += success_count

            # Update global totals
            total_requests += request_count
            total_success += success_count

        # Calculate success rates for origin totals
        for origin in origins.values():
            total = origin["total"]
            if total["request_count"] > 0:
                total["success_rate"] = round(
                    total["success_count"] / total["request_count"], 4
                )

        # Calculate global success rate
        global_success_rate = (
            round(total_success / total_requests, 4) if total_requests > 0 else 0.0
        )

        return {
            "window": window,
            "start_time": start_time,
            "end_time": end_time,
            "origins": origins,
            "total": {
                "request_count": total_requests,
                "success_count": total_success,
                "success_rate": global_success_rate
            }
        }

    async def close(self):
        """Close database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None
            self._initialized = False

    @staticmethod
    def _calculate_p95(values: list[float]) -> float:
        """Calculate 95th percentile from sorted values.

        Args:
            values: List of numeric values (should be pre-sorted)

        Returns:
            95th percentile value
        """
        if not values:
            return 0.0

        # Ensure values are sorted
        sorted_values = sorted(values)

        # Calculate p95 index
        n = len(sorted_values)
        idx = int(n * 0.95)

        # Handle edge case where idx equals n
        if idx >= n:
            idx = n - 1

        return sorted_values[idx]

    @staticmethod
    def _parse_window(window: str) -> int:
        """Parse time window string into seconds.

        Args:
            window: Window string like "1h", "24h", "7d", "30d"

        Returns:
            Number of seconds in the window

        Raises:
            ValueError: If window format is invalid
        """
        window = window.lower().strip()

        if window.endswith('h'):
            hours = int(window[:-1])
            return hours * 3600
        elif window.endswith('d'):
            days = int(window[:-1])
            return days * 86400
        else:
            raise ValueError(
                f"Invalid window format: {window}. Expected format like '1h', '24h', '7d', '30d'"
            )
