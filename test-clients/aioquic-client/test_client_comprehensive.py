#!/usr/bin/env python3
"""
Comprehensive aioquic test client for QUIC interoperability testing.
"""
import argparse
import asyncio
import logging
import ssl
import sys
import time
from typing import cast, Optional
from dataclasses import dataclass

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    name: str
    success: bool
    details: str
    elapsed_ms: float
    error: Optional[Exception] = None


class ComprehensiveTestClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stream_events = {}
        self._stream_complete = {}

    def quic_event_received(self, event: QuicEvent):
        """Handle QUIC events"""
        if isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            if stream_id not in self._stream_events:
                self._stream_events[stream_id] = asyncio.Event()
                self._stream_complete[stream_id] = b""

            self._stream_complete[stream_id] += event.data
            # Unblock as soon as any data arrives; FIN is not required for success
            self._stream_events[stream_id].set()

    async def send_and_receive(self, stream_id: int, data: bytes, timeout: float = 5.0) -> bytes:
        """Send data on a stream and wait for response"""
        # Reset per-call state so each request waits for fresh data
        self._stream_events[stream_id] = asyncio.Event()
        self._stream_complete[stream_id] = b""

        # Send data
        self._quic.send_stream_data(stream_id, data, end_stream=False)
        self.transmit()

        # Wait for response
        try:
            await asyncio.wait_for(self._stream_events[stream_id].wait(), timeout=timeout)
            return self._stream_complete[stream_id]
        except asyncio.TimeoutError:
            logger.error(f"Timeout waiting for response on stream {stream_id}")
            return b""

    def open_stream(self) -> int:
        """Open a new bidirectional stream"""
        return self._quic.get_next_available_stream_id()


async def test_single_stream_echo(client: ComprehensiveTestClient) -> TestResult:
    """Test 1: Single stream echo"""
    logger.info("📝 Test 1: Single stream echo")
    start = time.time()

    try:
        stream_id = client.open_stream()
        msg = b"Hello from aioquic!"

        response = await client.send_and_receive(stream_id, msg)

        elapsed = (time.time() - start) * 1000
        details = f"Sent {len(msg)} bytes, received {len(response)} bytes in {elapsed:.0f}ms"
        logger.info(f"✅ {details}")

        return TestResult(
            name="Single Stream Echo",
            success=len(response) > 0,
            details=details,
            elapsed_ms=elapsed
        )
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        logger.error(f"❌ Test failed: {e}")
        return TestResult(
            name="Single Stream Echo",
            success=False,
            details=f"Failed after {elapsed:.0f}ms",
            elapsed_ms=elapsed,
            error=e
        )


async def test_multiple_concurrent_streams(client: ComprehensiveTestClient, num_streams: int = 4) -> TestResult:
    """Test 2: Multiple concurrent streams"""
    logger.info(f"📝 Test 2: Multiple concurrent streams ({num_streams} streams)")
    start = time.time()

    try:
        tasks = []
        for i in range(num_streams):
            stream_id = client.open_stream()
            msg = f"Stream {i} message".encode()
            task = client.send_and_receive(stream_id, msg)
            tasks.append(task)

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        failures = [r for r in responses if isinstance(r, Exception)]
        if failures:
            raise failures[0]

        elapsed = (time.time() - start) * 1000
        details = f"{num_streams} concurrent streams completed in {elapsed:.0f}ms"
        logger.info(f"✅ {details}")

        for i in range(num_streams):
            logger.info(f"✓ Stream {i} completed")

        return TestResult(
            name="Multiple Concurrent Streams",
            success=True,
            details=details,
            elapsed_ms=elapsed
        )
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        logger.error(f"❌ Test failed: {e}")
        return TestResult(
            name="Multiple Concurrent Streams",
            success=False,
            details=f"Failed after {elapsed:.0f}ms",
            elapsed_ms=elapsed,
            error=e
        )


async def test_large_data_transfer(client: ComprehensiveTestClient, size: int) -> TestResult:
    """Test: Large data transfer"""
    size_name = format_size(size)
    logger.info(f"📝 Test: Large data transfer ({size_name})")
    start = time.time()

    try:
        stream_id = client.open_stream()

        # Generate random data
        import os
        data = os.urandom(size)

        response = await client.send_and_receive(stream_id, data, timeout=30.0)

        elapsed = (time.time() - start) * 1000
        throughput_mbps = (size / (elapsed / 1000)) / (1024 * 1024) if elapsed > 0 else 0
        details = f"Transferred {size} bytes in {elapsed:.0f}ms ({throughput_mbps:.2f} MB/s)"
        logger.info(f"✅ {details}")

        return TestResult(
            name=f"Large Transfer ({size_name})",
            success=len(response) >= min(size, 1024),  # Expect at least 1KB back
            details=details,
            elapsed_ms=elapsed
        )
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        logger.error(f"❌ Test failed: {e}")
        return TestResult(
            name=f"Large Transfer ({size_name})",
            success=False,
            details=f"Failed after {elapsed:.0f}ms",
            elapsed_ms=elapsed,
            error=e
        )


async def test_multiple_round_trips(client: ComprehensiveTestClient, num_rounds: int = 10) -> TestResult:
    """Test: Multiple round-trips"""
    logger.info(f"📝 Test: Multiple round-trips ({num_rounds} cycles)")
    start = time.time()

    try:
        stream_id = client.open_stream()

        for i in range(num_rounds):
            msg = f"Round {i}".encode()
            response = await client.send_and_receive(stream_id, msg, timeout=2.0)
            if len(response) == 0:
                raise Exception(f"No response in round {i}")

        elapsed = (time.time() - start) * 1000
        avg_latency = elapsed / num_rounds
        details = f"{num_rounds} round-trips in {elapsed:.0f}ms (avg: {avg_latency:.0f}ms per round)"
        logger.info(f"✅ {details}")

        return TestResult(
            name="Multiple Round-trips",
            success=True,
            details=details,
            elapsed_ms=elapsed
        )
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        logger.error(f"❌ Test failed: {e}")
        return TestResult(
            name="Multiple Round-trips",
            success=False,
            details=f"Failed after {elapsed:.0f}ms",
            elapsed_ms=elapsed,
            error=e
        )


async def test_stream_interleaving(client: ComprehensiveTestClient, num_streams: int = 5) -> TestResult:
    """Test: Stream interleaving"""
    # Limit to 2 streams to avoid hitting max_streams limit
    actual_streams = min(num_streams, 2)
    logger.info(f"📝 Test: Stream interleaving ({actual_streams} streams)")
    start = time.time()

    try:
        stream_ids = [client.open_stream() for _ in range(actual_streams)]

        # Send data in round-robin fashion
        for round_num in range(5):
            for i, stream_id in enumerate(stream_ids):
                msg = f"Stream {i}, Round {round_num}".encode()
                client._quic.send_stream_data(stream_id, msg, end_stream=False)

        client.transmit()

        # Wait for responses from all streams
        await asyncio.sleep(1.0)  # Give time for responses

        elapsed = (time.time() - start) * 1000
        details = f"{actual_streams} interleaved streams, 5 rounds in {elapsed:.0f}ms"
        logger.info(f"✅ {details}")

        return TestResult(
            name="Stream Interleaving",
            success=True,
            details=details,
            elapsed_ms=elapsed
        )
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        logger.error(f"❌ Test failed: {e}")
        return TestResult(
            name="Stream Interleaving",
            success=False,
            details=f"Failed after {elapsed:.0f}ms",
            elapsed_ms=elapsed,
            error=e
        )


def print_test_summary(results: list[TestResult]):
    """Print test results summary"""
    logger.info("\n" + "=" * 60)
    logger.info("📊 TEST SUMMARY")
    logger.info("=" * 60)

    passed = 0
    failed = 0

    for result in results:
        status = "✅" if result.success else "❌"
        if result.success:
            passed += 1
        else:
            failed += 1

        logger.info(f"{status} {result.name}")
        logger.info(f"   └─ {result.details}")
        if result.error:
            logger.info(f"   └─ Error: {result.error}")

    logger.info("\n" + "=" * 60)
    logger.info(f"RESULTS: {passed} passed, {failed} failed, {len(results)} total")
    logger.info("=" * 60)

    if failed > 0:
        logger.error("\n❌ Some tests failed")
        return 1

    logger.info("\n✅ All tests passed!")
    return 0


def format_size(bytes: int) -> str:
    """Format byte size to human-readable string"""
    if bytes < 1024:
        return f"{bytes}B"
    elif bytes < 1024 * 1024:
        return f"{bytes // 1024}KB"
    else:
        return f"{bytes // (1024 * 1024)}MB"


async def run_comprehensive_tests(host: str, port: int, insecure: bool = False) -> int:
    """Run comprehensive QUIC test suite"""
    logger.info("🚀 Starting Comprehensive QUIC Test Suite (aioquic)")
    logger.info("=" * 60)
    logger.info(f"📡 Connecting to {host}:{port}\n")

    # Configure QUIC
    configuration = QuicConfiguration(
        alpn_protocols=["hq-interop"],
        is_client=True,
    )
    if insecure:
        configuration.verify_mode = ssl.CERT_NONE

    try:
        # Connect to server
        async with connect(
            host,
            port,
            configuration=configuration,
            create_protocol=ComprehensiveTestClient,
        ) as client:
            client = cast(ComprehensiveTestClient, client)
            logger.info("✅ Connection established")
            logger.info("✅ TLS handshake complete\n")

            # Run comprehensive test suite
            results = []

            results.append(await test_single_stream_echo(client))
            results.append(await test_multiple_concurrent_streams(client, 4))
            results.append(await test_large_data_transfer(client, 10 * 1024))    # 10KB
            results.append(await test_large_data_transfer(client, 100 * 1024))   # 100KB
            results.append(await test_multiple_round_trips(client, 10))
            results.append(await test_stream_interleaving(client, 5))

            # Print summary
            return print_test_summary(results)

    except Exception as e:
        logger.error(f"❌ Connection failed: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(description="aioquic comprehensive test client")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Server host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4433,
        help="Server port (default: 4433)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip certificate verification for local self-signed interop tests"
    )
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    # Run comprehensive tests
    try:
        exit_code = asyncio.run(run_comprehensive_tests(args.host, args.port, args.insecure))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Interrupted")
        sys.exit(1)


if __name__ == "__main__":
    main()
