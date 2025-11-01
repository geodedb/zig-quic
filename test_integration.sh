#!/bin/bash
# Comprehensive QUIC/TLS integration test

set -e

echo "=== QUIC/TLS Integration Test ==="
echo "1. Building server..."
cd /home/benji/src/spyder/quic
zig build || exit 1

echo ""
echo "2. Starting server with verbose logging..."
pkill -9 quic-server 2>/dev/null || true
./zig-out/bin/quic-server \
  --bind 127.0.0.1:4433 \
  --alpn hq-interop \
  --cert examples/interop/certs/cert.pem \
  --key examples/interop/certs/key.pem \
  --insecure \
  > /tmp/quic-server-test.log 2>&1 &

SERVER_PID=$!
echo "Server PID: $SERVER_PID"
sleep 2

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    cat /tmp/quic-server-test.log
    exit 1
fi

echo "Server started successfully"
echo ""

echo "3. Testing Python (aioquic) client..."
cd /home/benji/src/spyder/quic/clients/python
source venv/bin/activate
timeout 10 python test_client.py --host 127.0.0.1 --port 4433 -v 2>&1 | tee /tmp/python-client-test.log || {
    echo "Python client test failed or timed out"
}

echo ""
echo "=== Server logs ==="
tail -50 /tmp/quic-server-test.log

echo ""
echo "=== Client logs (last 30 lines) ==="
tail -30 /tmp/python-client-test.log

echo ""
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "Test complete"
