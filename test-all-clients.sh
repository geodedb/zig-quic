#!/usr/bin/env bash
set -e

echo "========================================="
echo "QUIC Server Interoperability Test Suite"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Find the server binary
echo "Finding server binary..."
SERVER_BIN=$(find .zig-cache -type f -name "quic-server" 2>/dev/null | head -1)

if [ -z "$SERVER_BIN" ]; then
    echo -e "${RED}❌ Server binary not found in .zig-cache${NC}"
    echo "Run 'zig build' first"
    exit 1
fi

echo -e "${GREEN}✓ Found server: $SERVER_BIN${NC}"
echo ""

# Stop any existing servers
killall quic-server 2>/dev/null || true
sleep 1

# Test function
run_test() {
    local test_name=$1
    local test_cmd=$2
    local log_file=$3

    echo "========================================="
    echo "Test: $test_name"
    echo "========================================="

    # Start server
    echo "Starting server..."
    $SERVER_BIN --bind 127.0.0.1:4433 --cert certs/cert.pem --key certs/key.pem --insecure > "$log_file" 2>&1 &
    SERVER_PID=$!
    echo "Server PID: $SERVER_PID"
    sleep 2

    # Check if server is running
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo -e "${RED}❌ Server failed to start${NC}"
        cat "$log_file"
        return 1
    fi

    echo -e "${GREEN}✓ Server started successfully${NC}"
    echo ""

    # Run client test
    echo "Running client: $test_name"
    echo "Command: $test_cmd"
    echo ""

    if eval "$test_cmd"; then
        echo -e "${GREEN}✓ Client test PASSED${NC}"
        TEST_RESULT="PASS"
    else
        echo -e "${RED}❌ Client test FAILED${NC}"
        TEST_RESULT="FAIL"
    fi

    echo ""
    echo "--- Server Log Analysis ---"

    # Check for key caching
    KEY_CACHE_COUNT=$(grep -c "Derived and cached Initial keys" "$log_file" 2>/dev/null || echo "0")
    KEY_DERIV_COUNT=$(grep -c "deriveKeyIvHp" "$log_file" 2>/dev/null || echo "0")

    echo "Key cache messages: $KEY_CACHE_COUNT"
    echo "Key derivation calls: $KEY_DERIV_COUNT"

    if [ "$KEY_CACHE_COUNT" -eq "0" ]; then
        echo -e "${YELLOW}⚠ Warning: No 'Derived and cached' messages found${NC}"
    elif [ "$KEY_CACHE_COUNT" -eq "1" ]; then
        echo -e "${GREEN}✓ Keys cached exactly once (expected)${NC}"
    else
        echo -e "${YELLOW}⚠ Warning: Keys cached $KEY_CACHE_COUNT times (expected 1)${NC}"
    fi

    if [ "$KEY_DERIV_COUNT" -gt "4" ]; then
        echo -e "${YELLOW}⚠ Warning: Many key derivations ($KEY_DERIV_COUNT) - possible loop${NC}"
    fi

    # Check for successful connection
    if grep -q "accepted connection" "$log_file"; then
        echo -e "${GREEN}✓ Connection accepted${NC}"
    else
        echo -e "${RED}❌ No connection accepted${NC}"
    fi

    # Check for data exchange
    if grep -q "stream 0 received" "$log_file" || grep -q "stream 0 opened" "$log_file"; then
        echo -e "${GREEN}✓ Data exchange detected${NC}"
    else
        echo -e "${YELLOW}⚠ No data exchange detected${NC}"
    fi

    echo ""
    echo "--- First 30 lines of server log ---"
    head -30 "$log_file"

    echo ""

    # Stop server
    kill $SERVER_PID 2>/dev/null || true
    sleep 1

    return 0
}

# Test 1: Go client (quic-go)
echo ""
echo "═══════════════════════════════════════"
echo "TEST 1: Go Client (quic-go)"
echo "═══════════════════════════════════════"
if [ -f "test-go-client.go" ]; then
    run_test "Go/quic-go" "timeout 10 go run -mod=mod test-go-client.go 2>&1" "/tmp/test-go.log"
else
    echo -e "${YELLOW}⚠ test-go-client.go not found, skipping${NC}"
fi

# Test 2: Rust client (quinn)
echo ""
echo "═══════════════════════════════════════"
echo "TEST 2: Rust Client (quinn)"
echo "═══════════════════════════════════════"
if [ -f "test-clients/quinn-client/target/release/quinn-test-client" ]; then
    run_test "Rust/quinn" \
        "timeout 10 ./test-clients/quinn-client/target/release/quinn-test-client --addr 127.0.0.1:4433 --server-name localhost 2>&1" \
        "/tmp/test-quinn.log"
else
    echo -e "${YELLOW}⚠ quinn-test-client not found, skipping${NC}"
fi

# Test 3: Python client (aioquic)
echo ""
echo "═══════════════════════════════════════"
echo "TEST 3: Python Client (aioquic)"
echo "═══════════════════════════════════════"
if [ -f "test-clients/aioquic-client/client.py" ]; then
    run_test "Python/aioquic" \
        "timeout 10 python test-clients/aioquic-client/client.py https://127.0.0.1:4433 2>&1" \
        "/tmp/test-aioquic.log"
else
    echo -e "${YELLOW}⚠ aioquic client.py not found, skipping${NC}"
fi

# Final cleanup
killall quic-server 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════"
echo "Test Suite Complete"
echo "═══════════════════════════════════════"
echo ""
echo "Next steps:"
echo "1. Review logs in /tmp/test-*.log"
echo "2. Verify 'Derived and cached' appears once per test"
echo "3. Check for successful data exchange"
echo ""
echo "For manual testing, run:"
echo "  $SERVER_BIN --bind 127.0.0.1:4433 --insecure"
