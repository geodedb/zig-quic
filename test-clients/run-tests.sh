#!/bin/bash
#
# Interoperability Test Script for Zig QUIC Server
# Tests connectivity with quic-go, aioquic, and quinn clients
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
SERVER_HOST="127.0.0.1"
SERVER_PORT="4433"
SERVER_BINARY="/home/benji/src/spyder/quic/zig-out/bin/quic-server"
CERT_PATH="/home/benji/src/spyder/quic/examples/interop/certs/cert.pem"
KEY_PATH="/home/benji/src/spyder/quic/examples/interop/certs/key.pem"

# Test result tracking
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

echo "========================================"
echo "QUIC Interoperability Test Suite"
echo "========================================"
echo ""
echo "Testing Zig QUIC server with Length field fixes"
echo "Server: ${SERVER_HOST}:${SERVER_PORT}"
echo ""

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    echo ""
    echo "----------------------------------------"
    echo "Test ${TESTS_RUN}: ${test_name}"
    echo "----------------------------------------"

    if eval "$test_command" 2>&1 | tee "/tmp/test-${TESTS_RUN}.log"; then
        echo -e "${GREEN}✓ PASS${NC}: ${test_name}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}: ${test_name}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Start server
echo "Starting Zig QUIC server..."
if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
    "$SERVER_BINARY" --bind "${SERVER_HOST}:${SERVER_PORT}" \
        --cert "$CERT_PATH" --key "$KEY_PATH" \
        > /tmp/zig-server-test.log 2>&1 &
else
    # Try without explicit cert paths (server may have defaults)
    "$SERVER_BINARY" --bind "${SERVER_HOST}:${SERVER_PORT}" \
        > /tmp/zig-server-test.log 2>&1 &
fi

SERVER_PID=$!
echo "Server started with PID: $SERVER_PID"

# Wait for server to start
sleep 2

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}ERROR: Server failed to start${NC}"
    echo "Server log:"
    cat /tmp/zig-server-test.log
    exit 1
fi

echo -e "${GREEN}Server is running${NC}"
echo ""

# Test 1: quic-go client
run_test "quic-go (Go) client" \
    "/home/benji/src/spyder/quic/test-clients/quic-go-client/quic-go-test-client --addr ${SERVER_HOST}:${SERVER_PORT}"

# Test 2: aioquic client
run_test "aioquic (Python) client" \
    "python3 /home/benji/src/spyder/quic/test-clients/aioquic-client/test_client.py --host ${SERVER_HOST} --port ${SERVER_PORT}"

# Test 3: quinn client
run_test "quinn (Rust) client" \
    "/home/benji/src/spyder/quic/test-clients/quinn-client/target/release/quinn-test-client --addr ${SERVER_HOST}:${SERVER_PORT} --server-name localhost"

# Stop server
echo ""
echo "Stopping server (PID: $SERVER_PID)..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Tests Run:    $TESTS_RUN"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
else
    echo -e "Tests Failed: $TESTS_FAILED"
fi
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Check logs in /tmp/test-*.log${NC}"
    exit 1
fi
