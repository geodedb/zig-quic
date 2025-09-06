#!/usr/bin/env bash
set -euo pipefail

# Simple Docker test for QUIC implementation
# Works around Docker Compose network issues

echo "=== QUIC Docker Test ==="

# Clean up any existing containers/networks
echo "Cleaning up..."
docker stop test-server test-client 2>/dev/null || true
docker rm test-server test-client 2>/dev/null || true
docker network rm quic-test 2>/dev/null || true

# Create test network
echo "Creating test network..."
docker network create --subnet=172.30.0.0/16 quic-test

# Start server
echo "Starting QUIC server..."
docker run -d --rm \
    --name test-server \
    --network quic-test \
    --hostname server \
    --ip 172.30.0.10 \
    -e ROLE=server \
    -e TESTCASE=handshake \
    zig-qns:local

# Wait for server to start
sleep 2

# Run client test
echo "Running client test..."
docker run --rm \
    --network quic-test \
    --entrypoint /bin/bash \
    zig-qns:local \
    -c "cd /quic && zig build cli && timeout 3 ./zig-out/bin/quic-client --connect 172.30.0.10:443 --sni server || true"

# Check server logs
echo ""
echo "=== Server Logs ==="
docker logs test-server 2>&1 | grep -E "(accepted connection|handshake complete|stream .* opened)" || echo "No handshake completed"

# Cleanup
echo ""
echo "Cleaning up..."
docker stop test-server 2>/dev/null || true
docker network rm quic-test 2>/dev/null || true

echo "=== Test Complete ==="