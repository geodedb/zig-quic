#!/usr/bin/env bash
set -e

killall quic-server 2>/dev/null || true
sleep 1

echo "Starting server with debug logging..."
LOG_LEVEL=debug ./zig-out/bin/quic-server --bind 127.0.0.1:4433 --insecure > /tmp/go-client-debug.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

sleep 2

echo "Checking if server is listening..."
ss -uln | grep 4433 || echo "Port not showing in ss"

echo ""
echo "Testing with Go client..."
timeout 8 go run -mod=mod test-go-client.go 2>&1 || true

echo ""
echo "Killing server..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Checking if packets were received ==="
grep -E "epoll_wait returned|drainReadable|processIncoming" /tmp/go-client-debug.log | head -10 || echo "No packets received"

echo ""
echo "=== Last 30 lines of server log ==="
tail -30 /tmp/go-client-debug.log
