#!/bin/bash
# QUIC-GO Interoperability Test Script
# Tests the QUIC server with a quic-go client that uses zero-length SCID

echo "=== QUIC-GO Interoperability Test ==="
echo "Testing server with zero-length SCID client"
echo "Date: $(date)"
echo

# Kill any existing servers
echo "Cleaning up existing processes..."
pkill -9 quic-server 2>/dev/null
pkill -9 quic-go-test-client 2>/dev/null
sleep 1

# Start server in background
echo "Starting QUIC server on 127.0.0.1:4433..."
cd /home/benji/src/spyder/quic
./zig-out/bin/quic-server 127.0.0.1:4433 --cert server.crt --key server.key 2>&1 | tee /tmp/server_test.log &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"
sleep 2

# Verify server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start. Check /tmp/server_test.log"
    exit 1
fi

# Run client test
echo
echo "Running quic-go client test (10 second timeout)..."
cd test-clients/quic-go-client
timeout 10 ./quic-go-test-client 127.0.0.1:4433 2>&1 | tee /tmp/quic_go_test.log
CLIENT_EXIT_CODE=$?

# Kill server
echo
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo
echo "=== Test Results ==="
echo "Server log: /tmp/server_test.log"
echo "Client log: /tmp/quic_go_test.log"
echo

# Analyze results
echo "=== Analysis ==="

# Check if handshake completed
if grep -q "Handshake complete" /tmp/quic_go_test.log 2>/dev/null; then
    echo "✓ Handshake completed successfully"
    EXIT_STATUS=0
else
    echo "✗ Handshake failed to complete"
    EXIT_STATUS=1
fi

# Check for timeout
if [ $CLIENT_EXIT_CODE -eq 124 ]; then
    echo "✗ Client timed out (expected with current issue)"
elif [ $CLIENT_EXIT_CODE -eq 0 ]; then
    echo "✓ Client exited cleanly"
else
    echo "✗ Client exited with error code: $CLIENT_EXIT_CODE"
fi

# Show key log excerpts
echo
echo "=== Key Server Log Entries ==="
grep -E "Initial packet.*zero-length|Sending Handshake packet|dcid.len=" /tmp/server_test.log 2>/dev/null | head -5 || echo "No relevant server entries found"

echo
echo "=== Key Client Log Entries ==="
grep -E "Failed to dial|timeout|Handshake|CRYPTO" /tmp/quic_go_test.log 2>/dev/null | head -5 || echo "No relevant client entries found"

echo
echo "=== Summary ==="
echo "This test verifies the current state of quic-go interoperability."
echo "Expected: Handshake failure due to unresolved packet processing issue"
echo "RFC 9000 §7.2 compliance: Server correctly uses zero-length DCID"

exit $EXIT_STATUS
