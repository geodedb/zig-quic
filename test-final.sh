#!/usr/bin/env bash
set -e

killall quic-server 2>/dev/null || true
sleep 1

echo "Starting server..."
./zig-out/bin/quic-server --bind 127.0.0.1:4433 --insecure > /tmp/final-test.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

sleep 3

echo "Testing with Go client..."
timeout 10 go run -mod=mod test-go-client.go 2>&1 || true

echo ""
echo "=== Server Log (first 50 lines) ==="
head -50 /tmp/final-test.log

echo ""
echo "=== Checking for key caching logs ==="
grep -E "Derived and cached|listening|accepted|stream 0" /tmp/final-test.log | head -20

killall quic-server 2>/dev/null || true
