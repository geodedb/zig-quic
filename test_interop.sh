#!/usr/bin/env bash
# Simple Zig QUIC Client <-> Server Interop Test
# Tests internal Zig-to-Zig communication

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Zig QUIC Internal Interop Test ===${NC}"

# Build the project
echo "Building QUIC implementation..."
zig build -Doptimize=ReleaseFast 2>&1 | grep -E "error|warning" || true

if [ ! -f "zig-out/bin/quic-server" ] || [ ! -f "zig-out/bin/quic-client" ]; then
    echo -e "${RED}✗ Build failed - binaries not found${NC}"
    exit 1
fi

# Find a free port
SERVER_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')
SERVER_ADDR="127.0.0.1:$SERVER_PORT"

echo "Starting QUIC server on $SERVER_ADDR..."

# Start server in background
./zig-out/bin/quic-server "$SERVER_ADDR" > /tmp/quic_server_test.log 2>&1 &
SERVER_PID=$!

# Give server time to start
sleep 1

# Check if server is still running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}✗ Server failed to start${NC}"
    cat /tmp/quic_server_test.log
    exit 1
fi

echo "Running QUIC client..."

# Run client with timeout
if timeout 5 ./zig-out/bin/quic-client "https://$SERVER_ADDR" "hello" > /tmp/quic_client_test.log 2>&1; then
    CLIENT_RC=0
else
    CLIENT_RC=$?
fi

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Test Results ==="

# Check client output
if [ $CLIENT_RC -eq 0 ] && grep -q "echo: hello" /tmp/quic_client_test.log; then
    echo -e "${GREEN}✓ PASSED${NC} - Client received correct echo response"
    
    # Show packet stats from server log
    if grep -q "recvfrom got" /tmp/quic_server_test.log; then
        PACKET_COUNT=$(grep -c "recvfrom got" /tmp/quic_server_test.log)
        echo "  Server received $PACKET_COUNT packets"
    fi
    
    exit 0
else
    echo -e "${RED}✗ FAILED${NC}"
    echo ""
    echo "Client log:"
    tail -20 /tmp/quic_client_test.log
    echo ""
    echo "Server log:"
    tail -20 /tmp/quic_server_test.log
    exit 1
fi
