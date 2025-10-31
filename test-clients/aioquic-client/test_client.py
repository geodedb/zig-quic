#!/usr/bin/env python3
"""
Simple aioquic test client for QUIC interoperability testing.
"""
import argparse
import asyncio
import logging
import sys
from typing import cast

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

logger = logging.getLogger(__name__)


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._request_complete = asyncio.Event()
        self._response_data = b""
        self._stream_id = None

    async def send_request(self):
        """Send HTTP/0.9 request"""
        # Open bidirectional stream
        self._stream_id = self._quic.get_next_available_stream_id()
        logger.info(f"Opening stream {self._stream_id}")

        # Send HTTP/0.9 GET request
        request = b"GET /\r\n"
        self._quic.send_stream_data(self._stream_id, request, end_stream=True)
        logger.info(f"Sent request: {request!r}")

        # Transmit packets
        self.transmit()

    def quic_event_received(self, event: QuicEvent):
        """Handle QUIC events"""
        if isinstance(event, StreamDataReceived):
            logger.info(f"Received {len(event.data)} bytes on stream {event.stream_id}")
            self._response_data += event.data
            if event.end_stream:
                logger.info("Stream closed by server")
                self._request_complete.set()

    async def wait_for_response(self):
        """Wait for response to complete"""
        await self._request_complete.wait()
        return self._response_data


async def run_client(host: str, port: int, verbose: bool = False):
    """Run the QUIC client test"""
    logger.info(f"Connecting to {host}:{port}")

    # Configure QUIC
    configuration = QuicConfiguration(
        alpn_protocols=["quic-zig/1"],
        is_client=True,
        verify_mode=0,  # Don't verify certificates for testing
    )

    try:
        # Connect to server
        async with connect(
            host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)
            logger.info("✓ Connection established")

            # Wait for handshake complete event
            # The connection is established when context manager succeeds
            logger.info("✓ TLS handshake complete")

            # Send request
            await client.send_request()
            logger.info("✓ Request sent")

            # Wait for response
            try:
                response = await asyncio.wait_for(
                    client.wait_for_response(),
                    timeout=5.0
                )
                logger.info(f"✓ Received response ({len(response)} bytes)")

                if response:
                    print("\n--- Response ---")
                    print(response.decode('utf-8', errors='replace'))
                    print("--- End ---\n")

                logger.info("✓ Test completed successfully!")
                return 0

            except asyncio.TimeoutError:
                logger.error("Timeout waiting for response")
                return 1

    except Exception as e:
        logger.error(f"Connection failed: {e}", exc_info=verbose)
        return 1


def main():
    parser = argparse.ArgumentParser(description="aioquic test client")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Server host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=3141,
        help="Server port (default: 3141)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    # Run client
    try:
        exit_code = asyncio.run(run_client(args.host, args.port, args.verbose))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Interrupted")
        sys.exit(1)


if __name__ == "__main__":
    main()
