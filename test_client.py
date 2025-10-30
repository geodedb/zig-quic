#!/usr/bin/env python3

import asyncio
import ssl
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
import argparse
import logging

logging.basicConfig(level=logging.DEBUG)

async def main(host, port):
    configuration = QuicConfiguration(
        alpn_protocols=["hq-interop"],
        is_client=True,
        verify_mode=ssl.CERT_NONE,  # Skip certificate verification for testing
    )

    print(f"Connecting to {host}:{port}...")

    try:
        async with connect(
            host,
            port,
            configuration=configuration,
        ) as client:
            print("Connected successfully!")

            # Open a stream
            stream_id = client._quic.get_next_available_stream_id()
            print(f"Opened stream {stream_id}")

            # Send data
            message = b"Hello from Python client!"
            client._quic.send_stream_data(stream_id, message, end_stream=False)

            print(f"Sent: {message}")

            # Give some time for response
            await asyncio.sleep(2)

            # Try to receive data
            events = []
            for event in client._quic.events:
                events.append(event)
                print(f"Event: {event}")

            print("Test completed!")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=4433, help="Server port")
    args = parser.parse_args()

    asyncio.run(main(args.host, args.port))