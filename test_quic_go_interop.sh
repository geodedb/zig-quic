#!/usr/bin/env bash
# QUIC Interop Test with quic-go
# Tests Zig server with quic-go client and vice versa

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== QUIC Interop Test (Zig <-> quic-go) ===${NC}"

# Check if quic-go is installed
if ! command -v quic-interop-client &> /dev/null && ! command -v quic-interop-server &> /dev/null; then
    echo -e "${RED}✗ quic-go interop tools not found${NC}"
    echo ""
    echo "To install quic-go interop tools:"
    echo "  git clone https://github.com/marten-seemann/quic-go.git"
    echo "  cd quic-go/interop"
    echo "  go build -o quic-interop-server ./server"
    echo "  go build -o quic-interop-client ./client"
    echo "  sudo cp quic-interop-* /usr/local/bin/"
    echo ""
    echo "Or use Docker: martenseemann/quic-go-interop:latest"
    exit 1
fi

# Build Zig QUIC implementation
echo "Building Zig QUIC implementation..."
zig build -Doptimize=ReleaseFast 2>&1 | grep -E "error|warning" || true

if [ ! -f "zig-out/bin/quic-server" ] || [ ! -f "zig-out/bin/quic-client" ]; then
    echo -e "${RED}✗ Build failed - binaries not found${NC}"
    exit 1
fi

# Find free ports
SERVER_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')
SERVER_ADDR="127.0.0.1:$SERVER_PORT"

TEST_PASSED=0
TEST_FAILED=0

# Test 1: Zig Server with quic-go Client
echo ""
echo -e "${BLUE}Test 1: Zig Server <-> quic-go Client${NC}"
echo "Starting Zig server on $SERVER_ADDR..."

./zig-out/bin/quic-server "$SERVER_ADDR" > /tmp/zig_server_interop.log 2>&1 &
ZIG_SERVER_PID=$!
sleep 1

if ! kill -0 $ZIG_SERVER_PID 2>/dev/null; then
    echo -e "${RED}✗ Zig server failed to start${NC}"
    cat /tmp/zig_server_interop.log
    TEST_FAILED=$((TEST_FAILED + 1))
else
    echo "Running quic-go client..."
    
    if timeout 10 quic-interop-client --address "$SERVER_ADDR" > /tmp/quicgo_client_interop.log 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC} - quic-go client successfully connected to Zig server"
        TEST_PASSED=$((TEST_PASSED + 1))
    else
        echo -e "${RED}✗ FAILED${NC} - quic-go client could not connect"
        echo "Client log:"
        tail -10 /tmp/quicgo_client_interop.log
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
    
    kill $ZIG_SERVER_PID 2>/dev/null || true
    wait $ZIG_SERVER_PID 2>/dev/null || true
fi

# Test 2: quic-go Server with Zig Client
echo ""
echo -e "${BLUE}Test 2: quic-go Server <-> Zig Client${NC}"

GO_SERVER_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')
GO_SERVER_ADDR="127.0.0.1:$GO_SERVER_PORT"

echo "Starting quic-go server on $GO_SERVER_ADDR..."

quic-interop-server -addr "$GO_SERVER_ADDR" > /tmp/quicgo_server_interop.log 2>&1 &
GO_SERVER_PID=$!
sleep 1

if ! kill -0 $GO_SERVER_PID 2>/dev/null; then
    echo -e "${RED}✗ quic-go server failed to start${NC}"
    cat /tmp/quicgo_server_interop.log
    TEST_FAILED=$((TEST_FAILED + 1))
else
    echo "Running Zig client..."
    
    if timeout 10 ./zig-out/bin/quic-client "https://$GO_SERVER_ADDR" "hello" > /tmp/zig_client_interop.log 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC} - Zig client successfully connected to quic-go server"
        TEST_PASSED=$((TEST_PASSED + 1))
    else
        echo -e "${RED}✗ FAILED${NC} - Zig client could not connect"
        echo "Client log:"
        tail -10 /tmp/zig_client_interop.log
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
    
    kill $GO_SERVER_PID 2>/dev/null || true
    wait $GO_SERVER_PID 2>/dev/null || true
fi

# Summary
echo ""
echo "=== Test Summary ==="
echo -e "Passed: ${GREEN}$TEST_PASSED${NC}"
echo -e "Failed: ${RED}$TEST_FAILED${NC}"

if [ $TEST_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
