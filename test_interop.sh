#!/bin/bash
set -e

echo "Building QUIC server..."
zig build cli

echo "Starting QUIC server..."
./zig-out/bin/quic-server --bind 127.0.0.1:4433 --insecure &
SERVER_PID=$!
sleep 1

echo "Running Go client..."
cd examples/quic-go
go run ./interop/client --connect 127.0.0.1:4433 --insecure &
CLIENT_PID=$!

# Wait for client to finish or timeout
sleep 5

# Kill processes
kill $CLIENT_PID 2>/dev/null || true
kill $SERVER_PID 2>/dev/null || true

echo "Test complete"