#!/bin/bash
# Test local QUIC client/server without Docker

cd /home/benji/src/spyder/quic || exit 1

# Start server in background
./zig-out/bin/quic-server --bind 127.0.0.1:7567 --alpn h3 2>&1 | tee /tmp/quic-server.log &
SERVER_PID=$!

sleep 2

# Connect with client
timeout 5 ./zig-out/bin/quic-client --connect 127.0.0.1:7567 --sni test.local --alpn h3 2>&1 | tee /tmp/quic-client.log

# Clean up
kill "$SERVER_PID" 2>/dev/null
