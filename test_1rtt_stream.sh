#!/usr/bin/env bash
# Test script for 1-RTT streaming after transcript hash fix

set -e

echo "=== Testing 1-RTT Streaming ==="
echo

# Build the server
echo "Building server..."
zig build 2>&1 | tail -5

# Start server in background
echo "Starting server on port 4433..."
timeout 30 ./zig-out/bin/test_quic_server 2>&1 | tee server_test.log &
SERVER_PID=$!
sleep 2

# Test with Python aioquic client
echo
echo "Testing with aioquic client..."
if command -v python3 &> /dev/null; then
    timeout 10 python3 -c "
import asyncio
import logging
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.client import connect

logging.basicConfig(level=logging.DEBUG)

async def test():
    configuration = QuicConfiguration(is_client=True, alpn_protocols=['hq-interop'])
    configuration.verify_mode = 0  # Disable cert verification
    
    async with connect('127.0.0.1', 4433, configuration=configuration) as client:
        # Wait for handshake
        await asyncio.sleep(0.5)
        
        # Send HTTP/0.9 request
        stream_id = client._quic.get_next_available_stream_id()
        client._quic.send_stream_data(stream_id, b'GET /\r\n', end_stream=True)
        
        # Try to read response
        print('Waiting for response...')
        for _ in range(10):
            for event in client._quic._events:
                print(f'Event: {event}')
            await asyncio.sleep(0.1)

asyncio.run(test())
" 2>&1 || echo "aioquic test failed or not installed"
fi

# Cleanup
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo
echo "=== Test Complete ==="
echo "Check server_test.log for details"
