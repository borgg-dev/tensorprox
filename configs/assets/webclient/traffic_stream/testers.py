"""Service testers for traffic stream client.

Each tester performs actual network requests to origin servers and returns
test results including success status, latency, and error information.
"""

import asyncio
import json
import socket
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class TestResult:
    """Result of a single test request."""

    service: str
    port: int
    success: bool
    latency_ms: float
    error: Optional[str] = None


class TCPEchoTester:
    """Test TCP echo server - send data, verify echo."""

    TIMEOUT = 5.0
    TEST_MESSAGE = b"ECHO_TEST_MESSAGE"

    async def test(self, ip: str, port: int) -> TestResult:
        """
        Test TCP echo service.

        Args:
            ip: Target IP address
            port: Target port (typically 7011)

        Returns:
            TestResult with success/error information
        """
        start_time = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.TIMEOUT
            )

            try:
                # Send test message
                writer.write(self.TEST_MESSAGE)
                await writer.drain()

                # Read echo response
                response = await asyncio.wait_for(
                    reader.read(len(self.TEST_MESSAGE)), timeout=self.TIMEOUT
                )

                latency_ms = (time.perf_counter() - start_time) * 1000

                # Verify echo matches
                if response == self.TEST_MESSAGE:
                    return TestResult(
                        service="tcp_echo",
                        port=port,
                        success=True,
                        latency_ms=latency_ms,
                    )
                else:
                    return TestResult(
                        service="tcp_echo",
                        port=port,
                        success=False,
                        latency_ms=latency_ms,
                        error=f"Echo mismatch: sent {len(self.TEST_MESSAGE)} "
                        f"bytes, got {len(response)} bytes",
                    )
            finally:
                writer.close()
                await writer.wait_closed()

        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="tcp_echo",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error="Timeout",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="tcp_echo",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error=str(e),
            )


class TCPHTTPTester:
    """Test HTTP server - GET /, verify 200 OK."""

    TIMEOUT = 5.0

    async def test(self, ip: str, port: int) -> TestResult:
        """
        Test TCP HTTP service.

        Args:
            ip: Target IP address
            port: Target port (typically 7022)

        Returns:
            TestResult with success/error information
        """
        start_time = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.TIMEOUT
            )

            try:
                # Send HTTP GET request
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()

                # Read response
                response = await asyncio.wait_for(
                    reader.read(4096), timeout=self.TIMEOUT
                )

                latency_ms = (time.perf_counter() - start_time) * 1000

                # Parse response
                response_text = response.decode("utf-8", errors="ignore")

                # Check for 200 OK
                if "200 OK" in response_text or '"status":"ok"' in response_text:
                    return TestResult(
                        service="tcp_http",
                        port=port,
                        success=True,
                        latency_ms=latency_ms,
                    )
                else:
                    return TestResult(
                        service="tcp_http",
                        port=port,
                        success=False,
                        latency_ms=latency_ms,
                        error=f"Invalid response: {response_text[:100]}",
                    )
            finally:
                writer.close()
                await writer.wait_closed()

        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="tcp_http",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error="Timeout",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="tcp_http",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error=str(e),
            )


class TCPCustomTester:
    """Test custom protocol - send PING/TIME/INFO, verify JSON response."""

    TIMEOUT = 5.0
    COMMANDS = ["PING", "TIME", "INFO"]

    async def test(self, ip: str, port: int) -> TestResult:
        """
        Test TCP custom protocol service.

        Args:
            ip: Target IP address
            port: Target port (typically 7033)

        Returns:
            TestResult with success/error information
        """
        start_time = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.TIMEOUT
            )

            try:
                # Read welcome message first (server sends it on connect)
                await asyncio.wait_for(reader.readline(), timeout=self.TIMEOUT)

                # Now send PING command
                command = "PING\n"
                writer.write(command.encode())
                await writer.drain()

                # Read PING response
                response = await asyncio.wait_for(reader.readline(), timeout=self.TIMEOUT)

                latency_ms = (time.perf_counter() - start_time) * 1000

                # Parse JSON response
                try:
                    data = json.loads(response.decode().strip())
                    # Verify response structure - server returns {"status": "pong", ...}
                    if "status" in data:
                        return TestResult(
                            service="tcp_custom",
                            port=port,
                            success=True,
                            latency_ms=latency_ms,
                        )
                    else:
                        return TestResult(
                            service="tcp_custom",
                            port=port,
                            success=False,
                            latency_ms=latency_ms,
                            error=f"Missing status in response: {data}",
                        )
                except json.JSONDecodeError as e:
                    return TestResult(
                        service="tcp_custom",
                        port=port,
                        success=False,
                        latency_ms=latency_ms,
                        error=f"JSON decode error: {e}",
                    )
            finally:
                writer.close()
                await writer.wait_closed()

        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="tcp_custom",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error="Timeout",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="tcp_custom",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error=str(e),
            )


class UDPEchoTester:
    """Test UDP echo - send data, verify echo."""

    TIMEOUT = 5.0
    TEST_MESSAGE = b"UDP_ECHO_TEST"

    async def test(self, ip: str, port: int) -> TestResult:
        """
        Test UDP echo service.

        Args:
            ip: Target IP address
            port: Target port (typically 7111)

        Returns:
            TestResult with success/error information
        """
        start_time = time.perf_counter()

        class UDPEchoProtocol(asyncio.DatagramProtocol):
            def __init__(self):
                self.response = None
                self.response_event = asyncio.Event()
                self.transport = None

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                self.response = data
                self.response_event.set()

            def error_received(self, exc):
                pass

        try:
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPEchoProtocol(), remote_addr=(ip, port)
            )

            try:
                # Send test message
                transport.sendto(self.TEST_MESSAGE)

                # Wait for response
                await asyncio.wait_for(protocol.response_event.wait(), timeout=self.TIMEOUT)

                latency_ms = (time.perf_counter() - start_time) * 1000

                # Verify echo matches
                if protocol.response == self.TEST_MESSAGE:
                    return TestResult(
                        service="udp_echo",
                        port=port,
                        success=True,
                        latency_ms=latency_ms,
                    )
                else:
                    return TestResult(
                        service="udp_echo",
                        port=port,
                        success=False,
                        latency_ms=latency_ms,
                        error=f"Echo mismatch: sent {len(self.TEST_MESSAGE)} "
                        f"bytes, got {len(protocol.response)} bytes",
                    )
            finally:
                transport.close()

        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="udp_echo",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error="Timeout",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="udp_echo",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error=str(e),
            )


class UDPDatagramTester:
    """Test UDP datagram - send data, verify ACK response."""

    TIMEOUT = 5.0
    TEST_MESSAGE = b"UDP_DATAGRAM_TEST"

    async def test(self, ip: str, port: int) -> TestResult:
        """
        Test UDP datagram service.

        Args:
            ip: Target IP address
            port: Target port (typically 7112)

        Returns:
            TestResult with success/error information
        """
        start_time = time.perf_counter()

        class UDPDatagramProtocol(asyncio.DatagramProtocol):
            def __init__(self):
                self.response = None
                self.response_event = asyncio.Event()
                self.transport = None

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                self.response = data
                self.response_event.set()

            def error_received(self, exc):
                pass

        try:
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPDatagramProtocol(), remote_addr=(ip, port)
            )

            try:
                # Send test message
                transport.sendto(self.TEST_MESSAGE)

                # Wait for ACK response
                await asyncio.wait_for(protocol.response_event.wait(), timeout=self.TIMEOUT)

                latency_ms = (time.perf_counter() - start_time) * 1000

                # Verify ACK response format: ACK:count:timestamp:bytes
                response_text = protocol.response.decode("utf-8", errors="ignore")
                if response_text.startswith("ACK:"):
                    return TestResult(
                        service="udp_datagram",
                        port=port,
                        success=True,
                        latency_ms=latency_ms,
                    )
                else:
                    return TestResult(
                        service="udp_datagram",
                        port=port,
                        success=False,
                        latency_ms=latency_ms,
                        error=f"Invalid ACK format: {response_text[:50]}",
                    )
            finally:
                transport.close()

        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="udp_datagram",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error="Timeout",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="udp_datagram",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error=str(e),
            )


class UDPCustomTester:
    """Test UDP custom protocol - send command, verify JSON."""

    TIMEOUT = 5.0
    COMMANDS = ["PING", "TIME", "STATUS"]

    async def test(self, ip: str, port: int) -> TestResult:
        """
        Test UDP custom protocol service.

        Args:
            ip: Target IP address
            port: Target port (typically 7113)

        Returns:
            TestResult with success/error information
        """
        start_time = time.perf_counter()

        class UDPCustomProtocol(asyncio.DatagramProtocol):
            def __init__(self):
                self.response = None
                self.response_event = asyncio.Event()
                self.transport = None

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                self.response = data
                self.response_event.set()

            def error_received(self, exc):
                pass

        try:
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPCustomProtocol(), remote_addr=(ip, port)
            )

            try:
                # Send PING command
                command = b"PING"
                transport.sendto(command)

                # Wait for response
                await asyncio.wait_for(protocol.response_event.wait(), timeout=self.TIMEOUT)

                latency_ms = (time.perf_counter() - start_time) * 1000

                # Parse JSON response
                try:
                    data = json.loads(protocol.response.decode().strip())
                    # Verify response structure - server returns {"status": "pong", ...}
                    if "status" in data:
                        return TestResult(
                            service="udp_custom",
                            port=port,
                            success=True,
                            latency_ms=latency_ms,
                        )
                    else:
                        return TestResult(
                            service="udp_custom",
                            port=port,
                            success=False,
                            latency_ms=latency_ms,
                            error=f"Missing status in response: {data}",
                        )
                except json.JSONDecodeError as e:
                    return TestResult(
                        service="udp_custom",
                        port=port,
                        success=False,
                        latency_ms=latency_ms,
                        error=f"JSON decode error: {e}",
                    )
            finally:
                transport.close()

        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="udp_custom",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error="Timeout",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TestResult(
                service="udp_custom",
                port=port,
                success=False,
                latency_ms=latency_ms,
                error=str(e),
            )
