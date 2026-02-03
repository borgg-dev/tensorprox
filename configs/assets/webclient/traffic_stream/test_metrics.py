"""
Tests for metrics storage and aggregation.
"""

import os
import tempfile
import time
from pathlib import Path

import pytest
import pytest_asyncio

from .metrics import MetricsDB


@pytest_asyncio.fixture
async def metrics_db():
    """Create a temporary metrics database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_metrics.db")
        db = MetricsDB(db_path=db_path)
        yield db
        await db.close()


@pytest.mark.asyncio
async def test_database_initialization():
    """Test database initialization creates tables."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = MetricsDB(db_path=db_path)

        # Record a request to trigger initialization
        await db.record_request(
            origin_ip="192.0.2.1",
            service="tcp_echo",
            port=7777,
            success=True,
            latency_ms=5.2
        )

        # Verify database file was created
        assert Path(db_path).exists()

        await db.close()


@pytest.mark.asyncio
async def test_record_request(metrics_db):
    """Test recording individual requests."""
    await metrics_db.record_request(
        origin_ip="192.0.2.1",
        service="tcp_echo",
        port=7777,
        success=True,
        latency_ms=5.2,
        pattern="burst"
    )

    await metrics_db.record_request(
        origin_ip="192.0.2.1",
        service="http",
        port=8080,
        success=False,
        latency_ms=100.5,
        error="Connection timeout",
        pattern="steady"
    )

    # Verify requests were stored
    await metrics_db._ensure_initialized()
    cursor = await metrics_db._conn.execute("SELECT COUNT(*) as count FROM requests")
    row = await cursor.fetchone()
    assert row["count"] == 2


@pytest.mark.asyncio
async def test_hourly_aggregation(metrics_db):
    """Test hourly aggregation of requests."""
    # Record multiple requests in the past hour
    current_time = time.time()
    one_hour_ago = current_time - 3600

    # Manually insert requests with specific timestamps
    await metrics_db._ensure_initialized()

    for i in range(10):
        timestamp = one_hour_ago - 100 - (i * 60)  # Spread across previous hour
        latency = 5.0 + (i * 2.0)
        await metrics_db._conn.execute("""
            INSERT INTO requests (
                timestamp, origin_ip, service, port, success, latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, "192.0.2.1", "tcp_echo", 7777, 1, latency))

    await metrics_db._conn.commit()

    # Run hourly aggregation
    await metrics_db.aggregate_hourly()

    # Verify hourly stats were created
    cursor = await metrics_db._conn.execute(
        "SELECT * FROM hourly_stats WHERE origin_ip = ? AND service = ?",
        ("192.0.2.1", "tcp_echo")
    )
    row = await cursor.fetchone()

    assert row is not None
    assert row["request_count"] == 10
    assert row["success_count"] == 10
    assert row["latency_min"] == 5.0
    assert row["latency_max"] == 23.0
    assert row["latency_avg"] == 14.0
    assert row["latency_p95"] is not None


@pytest.mark.asyncio
async def test_daily_aggregation(metrics_db):
    """Test daily aggregation from hourly stats."""
    # Insert hourly stats for the previous day
    current_time = time.time()
    yesterday_start = int((current_time - 86400) / 86400) * 86400

    await metrics_db._ensure_initialized()

    # Insert 24 hourly stats for yesterday
    for hour in range(24):
        hour_start = yesterday_start + (hour * 3600)
        await metrics_db._conn.execute("""
            INSERT INTO hourly_stats (
                hour_start, origin_ip, service,
                request_count, success_count,
                latency_min, latency_max, latency_avg, latency_p95
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (hour_start, "192.0.2.1", "tcp_echo", 100, 95, 2.0, 50.0, 10.0, 25.0))

    await metrics_db._conn.commit()

    # Run daily aggregation
    await metrics_db.aggregate_daily()

    # Verify daily stats were created
    cursor = await metrics_db._conn.execute(
        "SELECT * FROM daily_stats WHERE origin_ip = ? AND service = ?",
        ("192.0.2.1", "tcp_echo")
    )
    row = await cursor.fetchone()

    assert row is not None
    assert row["request_count"] == 2400  # 100 * 24
    assert row["success_count"] == 2280  # 95 * 24


@pytest.mark.asyncio
async def test_prune_old_data(metrics_db):
    """Test pruning of old data."""
    current_time = time.time()
    old_timestamp = current_time - (72 * 3600)  # 72 hours ago

    await metrics_db._ensure_initialized()

    # Insert old request
    await metrics_db._conn.execute("""
        INSERT INTO requests (timestamp, origin_ip, service, port, success)
        VALUES (?, ?, ?, ?, ?)
    """, (old_timestamp, "192.0.2.1", "tcp_echo", 7777, 1))

    # Insert recent request
    await metrics_db._conn.execute("""
        INSERT INTO requests (timestamp, origin_ip, service, port, success)
        VALUES (?, ?, ?, ?, ?)
    """, (current_time - 3600, "192.0.2.1", "tcp_echo", 7777, 1))

    await metrics_db._conn.commit()

    # Verify both requests exist
    cursor = await metrics_db._conn.execute("SELECT COUNT(*) as count FROM requests")
    row = await cursor.fetchone()
    assert row["count"] == 2

    # Run pruning
    await metrics_db.prune_old_data()

    # Verify old request was deleted
    cursor = await metrics_db._conn.execute("SELECT COUNT(*) as count FROM requests")
    row = await cursor.fetchone()
    assert row["count"] == 1


@pytest.mark.asyncio
async def test_get_stats(metrics_db):
    """Test getting statistics for a time window."""
    # Insert hourly stats for recent hours
    current_time = time.time()

    await metrics_db._ensure_initialized()

    # Insert stats for the last 2 complete hours
    # Use current_time - 1800 (30 min ago) to ensure we're in the past hour window
    for i in range(2):
        hour_start = current_time - (1800 + (i * 3600))  # 30 min ago, 1h 30min ago
        await metrics_db._conn.execute("""
            INSERT INTO hourly_stats (
                hour_start, origin_ip, service,
                request_count, success_count,
                latency_min, latency_max, latency_avg, latency_p95
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (hour_start, "192.0.2.1", "tcp_echo", 100, 95, 2.0, 50.0, 10.0, 25.0))

    await metrics_db._conn.commit()

    # Get stats for last hour (should include first entry only)
    stats = await metrics_db.get_stats(origin_ip="192.0.2.1", window="1h")

    assert stats["window"] == "1h"
    assert "192.0.2.1" in stats["origins"]
    assert "tcp_echo" in stats["origins"]["192.0.2.1"]["services"]

    service_stats = stats["origins"]["192.0.2.1"]["services"]["tcp_echo"]
    assert service_stats["request_count"] == 100
    assert service_stats["success_count"] == 95
    assert service_stats["success_rate"] == 0.95


@pytest.mark.asyncio
async def test_calculate_p95():
    """Test p95 calculation."""
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    p95 = MetricsDB._calculate_p95(values)

    # For 10 values, p95 should be at index 9 (95% of 10 = 9.5, int = 9)
    assert p95 == 10.0

    # Test with fewer values
    values = [1.0, 2.0, 3.0]
    p95 = MetricsDB._calculate_p95(values)
    assert p95 == 3.0

    # Test with empty list
    p95 = MetricsDB._calculate_p95([])
    assert p95 == 0.0


@pytest.mark.asyncio
async def test_parse_window():
    """Test time window parsing."""
    assert MetricsDB._parse_window("1h") == 3600
    assert MetricsDB._parse_window("8h") == 8 * 3600
    assert MetricsDB._parse_window("24h") == 24 * 3600
    assert MetricsDB._parse_window("7d") == 7 * 86400
    assert MetricsDB._parse_window("30d") == 30 * 86400

    # Test case insensitivity
    assert MetricsDB._parse_window("1H") == 3600
    assert MetricsDB._parse_window("7D") == 7 * 86400

    # Test invalid format
    with pytest.raises(ValueError):
        MetricsDB._parse_window("invalid")


@pytest.mark.asyncio
async def test_multiple_origins(metrics_db):
    """Test stats with multiple origins."""
    await metrics_db._ensure_initialized()

    current_time = time.time()
    # Use a recent time to ensure it's within the query window
    hour_start = current_time - 1800  # 30 minutes ago

    # Insert stats for multiple origins
    for origin_ip in ["192.0.2.1", "192.0.2.2"]:
        await metrics_db._conn.execute("""
            INSERT INTO hourly_stats (
                hour_start, origin_ip, service,
                request_count, success_count,
                latency_min, latency_max, latency_avg, latency_p95
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (hour_start, origin_ip, "tcp_echo", 100, 95, 2.0, 50.0, 10.0, 25.0))

    await metrics_db._conn.commit()

    # Get stats for all origins
    stats = await metrics_db.get_stats(window="1h")

    assert len(stats["origins"]) == 2
    assert "192.0.2.1" in stats["origins"]
    assert "192.0.2.2" in stats["origins"]
    assert stats["total"]["request_count"] == 200
    assert stats["total"]["success_count"] == 190
    assert stats["total"]["success_rate"] == 0.95

    # Get stats for specific origin
    stats_single = await metrics_db.get_stats(origin_ip="192.0.2.1", window="1h")
    assert len(stats_single["origins"]) == 1
    assert stats_single["total"]["request_count"] == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
