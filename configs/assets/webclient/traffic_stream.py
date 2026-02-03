#!/usr/bin/env python3
"""
Traffic Stream Client - Continuous synthetic traffic generator.

Generates realistic web client traffic patterns against multiple origins
with comprehensive logging and metrics collection.
"""

import argparse
import asyncio
import logging
import random
import signal
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from traffic_stream.config import load_config, StreamConfig, OriginConfig
from traffic_stream.patterns import PatternEngine
from traffic_stream.testers import (
    TCPEchoTester, TCPHTTPTester, TCPCustomTester,
    UDPEchoTester, UDPDatagramTester, UDPCustomTester, TestResult
)
from traffic_stream.metrics import MetricsDB
from traffic_stream.logging_setup import setup_logging, log_request


class ServiceSelector:
    """Selects services based on configured weights."""

    def __init__(self, weights: Dict[str, int]):
        """Initialize with service weights.

        Args:
            weights: Dict mapping service names to weights (must sum to 100)
        """
        self.services = list(weights.keys())
        self.weights = list(weights.values())

    def select(self) -> str:
        """Select a service based on weights.

        Returns:
            Service name (e.g., "tcp_http", "udp_echo")
        """
        return random.choices(self.services, weights=self.weights, k=1)[0]


class OriginStream:
    """Independent traffic stream for a single origin."""

    def __init__(
        self,
        origin: OriginConfig,
        config: StreamConfig,
        metrics_db: MetricsDB,
        logger: logging.Logger
    ):
        """Initialize origin stream.

        Args:
            origin: Origin configuration with IP and ports
            config: Stream configuration with patterns and weights
            metrics_db: Metrics database for recording results
            logger: Logger instance for JSON logging
        """
        self.origin = origin
        self.config = config
        self.metrics_db = metrics_db
        self.logger = logger

        # Initialize pattern engine
        self.pattern_engine = PatternEngine(config.patterns, config.time_of_day)

        # Initialize service selector
        self.service_selector = ServiceSelector(config.service_weights)

        # Initialize testers
        self.testers = {
            "tcp_echo": TCPEchoTester(),
            "tcp_http": TCPHTTPTester(),
            "tcp_custom": TCPCustomTester(),
            "udp_echo": UDPEchoTester(),
            "udp_dgram": UDPDatagramTester(),
            "udp_custom": UDPCustomTester(),
        }

        # Running state
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def _get_port_for_service(self, service: str) -> int:
        """Get port number for a service.

        Args:
            service: Service name

        Returns:
            Port number for the service
        """
        if service == "tcp_echo":
            return self.origin.tcp_ports.echo
        elif service == "tcp_http":
            return self.origin.tcp_ports.http
        elif service == "tcp_custom":
            return self.origin.tcp_ports.custom
        elif service == "udp_echo":
            return self.origin.udp_ports.echo
        elif service == "udp_dgram":
            return self.origin.udp_ports.dgram
        elif service == "udp_custom":
            return self.origin.udp_ports.custom
        else:
            raise ValueError(f"Unknown service: {service}")

    async def _run_test(self, service: str) -> TestResult:
        """Run a single test for a service.

        Args:
            service: Service name to test

        Returns:
            Test result
        """
        port = self._get_port_for_service(service)
        tester = self.testers[service]
        return await tester.test(self.origin.ip, port)

    async def _stream_loop(self):
        """Main loop for generating traffic to this origin."""
        self.logger.info(f"Starting traffic stream to {self.origin.ip}")

        while self._running:
            try:
                # Get delay from pattern engine
                delay = await self.pattern_engine.get_next_delay()
                pattern = self.pattern_engine.current_state

                # Wait for the delay
                await asyncio.sleep(delay)

                if not self._running:
                    break

                # Select and test a service
                service = self.service_selector.select()
                result = await self._run_test(service)

                # Record metrics
                await self.metrics_db.record_request(
                    origin_ip=self.origin.ip,
                    service=result.service,
                    port=result.port,
                    success=result.success,
                    latency_ms=result.latency_ms,
                    error=result.error,
                    pattern=pattern
                )

                # Log request
                log_request(
                    logger=self.logger,
                    origin_ip=self.origin.ip,
                    service=result.service,
                    port=result.port,
                    success=result.success,
                    latency_ms=result.latency_ms,
                    error=result.error,
                    pattern=pattern
                )

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in stream to {self.origin.ip}: {e}")
                # Back off on errors
                await asyncio.sleep(5)

        self.logger.info(f"Stopped traffic stream to {self.origin.ip}")

    def start(self):
        """Start the traffic stream."""
        self._running = True
        self._task = asyncio.create_task(self._stream_loop())

    async def stop(self):
        """Stop the traffic stream."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


class TrafficStreamManager:
    """Manages all origin streams and background tasks."""

    def __init__(self, config: StreamConfig, log_dir: str, db_path: str):
        """Initialize traffic stream manager.

        Args:
            config: Stream configuration
            log_dir: Directory for log files
            db_path: Path to metrics database
        """
        self.config = config
        self.logger = setup_logging(log_dir=log_dir)
        self.metrics_db = MetricsDB(db_path=db_path)
        self.streams: List[OriginStream] = []
        self._running = False
        self._aggregation_task: Optional[asyncio.Task] = None

    async def _aggregation_loop(self):
        """Background task for metrics aggregation and pruning."""
        while self._running:
            try:
                # Run every hour
                await asyncio.sleep(3600)

                if not self._running:
                    break

                self.logger.info("Running metrics aggregation")
                await self.metrics_db.aggregate_hourly()
                await self.metrics_db.aggregate_daily()
                await self.metrics_db.prune_old_data()
                self.logger.info("Metrics aggregation complete")

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in aggregation: {e}")

    async def start(self):
        """Start all origin streams and background tasks."""
        self._running = True
        self.logger.info(f"Starting traffic stream manager with {len(self.config.origins)} origins")

        # Create and start origin streams
        for origin in self.config.origins:
            stream = OriginStream(origin, self.config, self.metrics_db, self.logger)
            stream.start()
            self.streams.append(stream)

        # Start aggregation task
        self._aggregation_task = asyncio.create_task(self._aggregation_loop())

        self.logger.info("Traffic stream manager started")

    async def stop(self):
        """Stop all origin streams and cleanup."""
        self._running = False
        self.logger.info("Stopping traffic stream manager")

        # Stop all origin streams
        for stream in self.streams:
            await stream.stop()

        # Cancel aggregation task
        if self._aggregation_task:
            self._aggregation_task.cancel()
            try:
                await self._aggregation_task
            except asyncio.CancelledError:
                pass

        # Close metrics database
        await self.metrics_db.close()

        self.logger.info("Traffic stream manager stopped")

    async def run_forever(self):
        """Run until interrupted."""
        await self.start()
        try:
            while self._running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()


async def query_stats(db_path: str, origin: Optional[str], window: str, format: str):
    """Query and display statistics.

    Args:
        db_path: Path to metrics database
        origin: Origin IP to filter (or "all")
        window: Time window (1h, 8h, 24h, 7d, 30d)
        format: Output format (text or json)
    """
    import json

    db = MetricsDB(db_path=db_path)
    origin_ip = None if origin == "all" else origin

    try:
        stats = await db.get_stats(origin_ip=origin_ip, window=window)

        if format == "json":
            print(json.dumps(stats, indent=2))
        else:
            print(f"\n=== Traffic Stream Statistics ({window}) ===\n")
            print(f"Time range: {stats['start_time']:.0f} - {stats['end_time']:.0f}")
            print(f"Total requests: {stats['total']['request_count']}")
            print(f"Total success: {stats['total']['success_count']}")
            print(f"Success rate: {stats['total']['success_rate']:.2%}\n")

            for origin_ip, origin_data in stats["origins"].items():
                print(f"Origin: {origin_ip}")
                print(f"  Total: {origin_data['total']['request_count']} requests, "
                      f"{origin_data['total']['success_rate']:.2%} success")

                for service, svc_data in origin_data["services"].items():
                    print(f"  {service}:")
                    print(f"    Requests: {svc_data['request_count']}")
                    print(f"    Success rate: {svc_data['success_rate']:.2%}")
                    if svc_data['latency_avg']:
                        print(f"    Latency: {svc_data['latency_avg']:.1f}ms avg, "
                              f"{svc_data['latency_p95']:.1f}ms p95")
                print()
    finally:
        await db.close()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Traffic Stream Client - Continuous synthetic traffic generator"
    )
    parser.add_argument(
        "--config", "-c",
        default="/root/assets/traffic_stream_config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--origins",
        help="Comma-separated list of origin IPs (overrides config file)"
    )
    parser.add_argument(
        "--log-dir",
        default="/var/log/traffic_stream",
        help="Directory for log files"
    )
    parser.add_argument(
        "--db-path",
        default="/var/lib/traffic_stream/metrics.db",
        help="Path to metrics database"
    )
    parser.add_argument(
        "--query",
        action="store_true",
        help="Query mode - display statistics instead of generating traffic"
    )
    parser.add_argument(
        "--origin",
        default="all",
        help="Origin to query (use with --query)"
    )
    parser.add_argument(
        "--window",
        default="1h",
        choices=["1h", "8h", "24h", "7d", "30d"],
        help="Time window for query"
    )
    parser.add_argument(
        "--format",
        default="text",
        choices=["text", "json"],
        help="Output format for query"
    )

    args = parser.parse_args()

    # Query mode
    if args.query:
        asyncio.run(query_stats(args.db_path, args.origin, args.window, args.format))
        return

    # Load configuration
    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print(f"Error: Configuration file not found: {args.config}")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        sys.exit(1)

    # Override origins if specified on command line
    if args.origins:
        from traffic_stream.config import OriginConfig
        origin_ips = [ip.strip() for ip in args.origins.split(",")]
        config.origins = [
            OriginConfig(ip=ip).merge_with_defaults(
                config.defaults.tcp_ports,
                config.defaults.udp_ports
            )
            for ip in origin_ips
        ]

    print(f"Traffic Stream Client starting")
    print(f"Origins: {[o.ip for o in config.origins]}")
    print(f"Log directory: {args.log_dir}")
    print(f"Metrics database: {args.db_path}")

    # Create manager
    manager = TrafficStreamManager(config, args.log_dir, args.db_path)

    # Handle signals
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def signal_handler():
        print("\nShutting down...")
        loop.create_task(manager.stop())

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    # Run
    try:
        loop.run_until_complete(manager.run_forever())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()

    print("Traffic Stream Client stopped")


if __name__ == "__main__":
    main()
