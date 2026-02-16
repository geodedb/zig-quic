#!/usr/bin/env python3

import asyncio
import logging
import ssl
import argparse
from pathlib import Path

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, ConnectionTerminated

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=logging.DEBUG,
)

class QuicTestClient:
    def __init__(self):
        self.received_data = []

    async def run_client(self, host, port, message, insecure=True):
        """Connect to QUIC server and send/receive message."""

        # Configure QUIC
        configuration = QuicConfiguration(
            alpn_protocols=["quic-zig/1", "h3", "http/0.9"],
            is_client=True,
            max_datagram_frame_size=65536,
        )

        if insecure:
            configuration.verify_mode = ssl.CERT_NONE

        logging.info(f"Connecting to {host}:{port}")

        try:
            async with connect(
                host,
                port,
                configuration=configuration,
                session_ticket_handler=None,
                stream_handler=self.stream_handler,
            ) as client:
                logging.info("Connected successfully")

                # Send message on stream 0
                stream_id = client._quic.get_next_available_stream_id()
                logging.info(f"Opening stream {stream_id}")

                client._quic.send_stream_data(stream_id, message.encode(), end_stream=True)
                logging.info(f"Sent message: {message}")

                # Wait for response
                await asyncio.sleep(2)

                if self.received_data:
                    logging.info(f"Received: {b''.join(self.received_data).decode()}")
                else:
                    logging.warning("No response received")

        except Exception as e:
            logging.error(f"Connection failed: {e}")
            raise

    def stream_handler(self, stream_id, data, end_stream):
        """Handle incoming stream data."""
        logging.info(f"Received data on stream {stream_id}: {data} (end={end_stream})")
        self.received_data.append(data)

async def main():
    parser = argparse.ArgumentParser(description="QUIC Test Client")
    parser.add_argument("--host", default="localhost", help="Server host")
    parser.add_argument("--port", type=int, default=4433, help="Server port")
    parser.add_argument("--message", default="Hello from Python aioquic!", help="Message to send")
    parser.add_argument("--insecure", action="store_true", help="Skip certificate verification")

    args = parser.parse_args()

    client = QuicTestClient()
    await client.run_client(args.host, args.port, args.message, args.insecure)

    print("✓ QUIC connection test completed")

if __name__ == "__main__":
    asyncio.run(main())