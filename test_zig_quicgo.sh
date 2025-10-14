#!/usr/bin/env bash
set -e

SERVER_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')

echo "=== Test: Zig Server with quic-go Client ==="
echo "Starting Zig server on 127.0.0.1:$SERVER_PORT"

timeout 15 ./zig-out/bin/quic-server --bind 127.0.0.1:$SERVER_PORT --alpn hq-interop --insecure --real-tls --cert examples/interop/certs/cert.pem --key examples/interop/certs/key.pem > /tmp/zig_server_interop2.log 2>&1 &
SERVER_PID=$!

sleep 2

echo "Testing with quic-go client connecting to 127.0.0.1:$SERVER_PORT..."
timeout 5 ./quic-test/quicgo-client 127.0.0.1:$SERVER_PORT hello 2>&1
CLIENT_RC=$?

kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "Client exit code: $CLIENT_RC"
echo ""
echo "=== Server Log (non-DEBUG lines) ==="
grep -v "^DEBUG:" /tmp/zig_server_interop2.log | tail -20
