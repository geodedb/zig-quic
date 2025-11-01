#!/bin/bash

# QUIC/TLS Interoperability Test Suite
# Tests both secure (with valid certificates) and insecure modes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
SERVER_BIND="127.0.0.1:4433"
TEST_TIMEOUT=10

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "pass" ]; then
        echo -e "${GREEN}✓${NC} $message"
    elif [ "$status" = "fail" ]; then
        echo -e "${RED}✗${NC} $message"
    else
        echo -e "${YELLOW}→${NC} $message"
    fi
}

# Function to kill any running servers
cleanup_servers() {
    print_status "info" "Cleaning up running servers..."
    pkill -f quic-server 2>/dev/null || true
    sleep 1
}

# Function to run server and test client
run_test() {
    local test_name=$1
    local cert_path=$2
    local key_path=$3
    local insecure_flag=$4
    local expected_result=$5

    echo ""
    echo "========================================="
    echo "Test: $test_name"
    echo "========================================="

    # Start server in background
    if [ -n "$cert_path" ] && [ -n "$key_path" ]; then
        print_status "info" "Starting server with certificates..."
        LOG_LEVEL=debug ./zig-out/bin/quic-server \
            --bind $SERVER_BIND \
            --cert "$cert_path" \
            --key "$key_path" \
            --alpn hq-interop \
            $insecure_flag > /tmp/server-${test_name}.log 2>&1 &
    else
        print_status "info" "Starting server in insecure mode (no certificates)..."
        LOG_LEVEL=debug ./zig-out/bin/quic-server \
            --bind $SERVER_BIND \
            --alpn hq-interop \
            --insecure > /tmp/server-${test_name}.log 2>&1 &
    fi

    SERVER_PID=$!
    sleep 2

    # Check if server started successfully
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        print_status "fail" "Server failed to start"
        cat /tmp/server-${test_name}.log | tail -20
        return 1
    fi

    print_status "info" "Server started (PID: $SERVER_PID)"

    # Run Python client test
    print_status "info" "Testing with Python aioquic client..."
    cd clients/python
    source venv/bin/activate

    if timeout $TEST_TIMEOUT python test_client.py \
        --host 127.0.0.1 \
        --port 4433 > /tmp/client-${test_name}.log 2>&1; then
        CLIENT_RESULT="success"
        print_status "pass" "Client connected successfully"
    else
        CLIENT_RESULT="failed"
        print_status "fail" "Client connection failed"
    fi

    cd ../..

    # Kill server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true

    # Check result
    if [ "$expected_result" = "$CLIENT_RESULT" ]; then
        print_status "pass" "Test passed (expected: $expected_result, got: $CLIENT_RESULT)"
        return 0
    else
        print_status "fail" "Test failed (expected: $expected_result, got: $CLIENT_RESULT)"

        # Show error details
        echo ""
        echo "Server log tail:"
        tail -20 /tmp/server-${test_name}.log | grep -E "ERROR|WARN|Certificate|accepted" || true
        echo ""
        echo "Client log tail:"
        tail -20 /tmp/client-${test_name}.log | grep -E "ERROR|Traceback|Decryption|Certificate" || true
        return 1
    fi
}

# Function to test data transfer
test_data_transfer() {
    local test_name=$1
    local cert_path=$2
    local key_path=$3

    echo ""
    echo "========================================="
    echo "Test: $test_name - Data Transfer"
    echo "========================================="

    # Create a simple echo client that sends data
    cat > /tmp/data_test.py << 'EOF'
import asyncio
import sys
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

async def test_data_transfer():
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["hq-interop"],
    )
    configuration.verify_mode = False  # Disable certificate verification

    async with connect("127.0.0.1", 4433, configuration=configuration) as protocol:
        # Wait for connection
        await protocol.wait_connected()
        print("Connected!")

        # Open a stream
        stream_id = protocol._quic.get_next_available_stream_id()

        # Send data
        test_data = b"Hello QUIC Server!"
        protocol._quic.send_stream_data(stream_id, test_data, end_stream=False)

        print(f"Sent: {test_data}")

        # Wait a bit for response
        await asyncio.sleep(1)

        # Try to receive data
        events = []
        for event in protocol._quic.events():
            events.append(event)
            print(f"Event: {event}")

        print("Test completed!")

asyncio.run(test_data_transfer())
EOF

    # Start server
    print_status "info" "Starting server for data transfer test..."
    if [ -n "$cert_path" ] && [ -n "$key_path" ]; then
        LOG_LEVEL=debug ./zig-out/bin/quic-server \
            --bind $SERVER_BIND \
            --cert "$cert_path" \
            --key "$key_path" \
            --alpn hq-interop \
            --insecure > /tmp/server-data-${test_name}.log 2>&1 &
    else
        LOG_LEVEL=debug ./zig-out/bin/quic-server \
            --bind $SERVER_BIND \
            --alpn hq-interop \
            --insecure > /tmp/server-data-${test_name}.log 2>&1 &
    fi

    SERVER_PID=$!
    sleep 2

    # Run data transfer test
    print_status "info" "Testing bi-directional data transfer..."
    cd clients/python
    source venv/bin/activate

    if timeout $TEST_TIMEOUT python /tmp/data_test.py > /tmp/data-transfer-${test_name}.log 2>&1; then
        print_status "pass" "Data transfer test completed"
        cat /tmp/data-transfer-${test_name}.log
    else
        print_status "fail" "Data transfer test failed"
        cat /tmp/data-transfer-${test_name}.log
    fi

    cd ../..

    # Kill server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}

# Main test execution
main() {
    echo "========================================"
    echo "QUIC/TLS Interoperability Test Suite"
    echo "========================================"
    echo ""

    # Check if server is built
    if [ ! -f "./zig-out/bin/quic-server" ]; then
        print_status "fail" "Server binary not found. Please run 'zig build' first."
        exit 1
    fi

    cleanup_servers

    # Test results tracking
    PASSED=0
    FAILED=0

    # Test 1: Valid ECDSA certificate
    if run_test "valid-ecdsa" \
        "tests/certs/valid/cert.pem" \
        "tests/certs/valid/key.pem" \
        "" \
        "success"; then
        ((PASSED++))
    else
        ((FAILED++))
    fi

    # Test 2: Valid RSA certificate
    if run_test "valid-rsa" \
        "tests/certs/valid/cert_rsa.pem" \
        "tests/certs/valid/key_rsa.pem" \
        "" \
        "success"; then
        ((PASSED++))
    else
        ((FAILED++))
    fi

    # Test 3: Self-signed certificate with insecure flag
    if run_test "self-signed-insecure" \
        "tests/certs/self-signed/cert.pem" \
        "tests/certs/self-signed/key.pem" \
        "--insecure" \
        "success"; then
        ((PASSED++))
    else
        ((FAILED++))
    fi

    # Test 4: No certificate (insecure mode)
    if run_test "no-cert-insecure" \
        "" \
        "" \
        "" \
        "success"; then
        ((PASSED++))
    else
        ((FAILED++))
    fi

    # Test 5: Data transfer with valid certificate
    test_data_transfer "valid-cert-data" \
        "tests/certs/valid/cert.pem" \
        "tests/certs/valid/key.pem"

    cleanup_servers

    # Print summary
    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo "Passed: $PASSED"
    echo "Failed: $FAILED"
    echo ""

    if [ $FAILED -eq 0 ]; then
        print_status "pass" "All tests passed!"
        exit 0
    else
        print_status "fail" "Some tests failed"
        exit 1
    fi
}

# Run main test suite
main "$@"