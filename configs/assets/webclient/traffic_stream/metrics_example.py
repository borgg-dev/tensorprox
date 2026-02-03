"""
Example usage of the MetricsDB class for traffic stream metrics.

This demonstrates how to use the metrics database for recording
and aggregating traffic stream statistics.
"""

import asyncio
from metrics import MetricsDB


async def example_usage():
    """Demonstrate metrics database usage."""
    # Initialize database
    db = MetricsDB(db_path="/tmp/traffic_metrics.db")

    # Record individual requests
    await db.record_request(
        origin_ip="192.0.2.1",
        service="tcp_echo",
        port=7777,
        success=True,
        latency_ms=5.2,
        pattern="burst"
    )

    await db.record_request(
        origin_ip="192.0.2.1",
        service="http",
        port=8080,
        success=False,
        latency_ms=100.5,
        error="Connection timeout",
        pattern="steady"
    )

    # Aggregate hourly statistics (run periodically)
    await db.aggregate_hourly()

    # Aggregate daily statistics (run once per day)
    await db.aggregate_daily()

    # Get statistics for the last hour
    stats_1h = await db.get_stats(origin_ip="192.0.2.1", window="1h")
    print("Last hour stats:", stats_1h)

    # Get statistics for the last 24 hours
    stats_24h = await db.get_stats(origin_ip="192.0.2.1", window="24h")
    print("Last 24 hours stats:", stats_24h)

    # Get statistics for all origins in the last 7 days
    stats_7d = await db.get_stats(window="7d")
    print("Last 7 days stats (all origins):", stats_7d)

    # Prune old data (run periodically)
    await db.prune_old_data()

    # Close database
    await db.close()


async def background_aggregation_task():
    """Background task to run aggregation periodically."""
    db = MetricsDB()

    while True:
        # Run hourly aggregation every 5 minutes
        await db.aggregate_hourly()

        # Run daily aggregation every hour
        await db.aggregate_daily()

        # Prune old data every hour
        await db.prune_old_data()

        # Wait 5 minutes
        await asyncio.sleep(300)


if __name__ == "__main__":
    asyncio.run(example_usage())
