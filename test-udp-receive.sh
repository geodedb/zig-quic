#!/usr/bin/env bash
set -e

echo "Starting server with debug logging..."
LOG_LEVEL=debug ./zig-out/bin/quic-server --bind 127.0.0.1:4433 --insecure > /tmp/udp-test.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

sleep 2

echo "Sending simple UDP packet..."
echo "test packet" | nc -u -w1 127.0.0.1 4433 || true

sleep 2

echo "Killing server..."
kill $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Checking if epoll triggered ==="
grep -E "epoll_wait returned|drainReadable|processIncoming" /tmp/udp-test.log | head -10 || echo "No events found"

echo ""
echo "=== Full log (first 50 lines) ==="
head -50 /tmp/udp-test.log
