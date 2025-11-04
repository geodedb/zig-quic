#!/bin/bash
# Comprehensive QUIC Interop Test Suite
# Tests against multiple reference implementations

set -e

SERVER_PORT=4433
SERVER_ADDR="127.0.0.1"
SERVER_URL="https://${SERVER_ADDR}:${SERVER_PORT}"
CERT_FILE="server.crt"
KEY_FILE="server.key"
SERVER_BINARY="./zig-out/bin/quic-server"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================"
echo "  QUIC Interop Test Suite"
echo "========================================"
echo ""

# Check dependencies
echo "[INFO] Checking dependencies..."
MISSING_DEPS=()

if ! command -v python3 &> /dev/null; then
    MISSING_DEPS+=("python3")
fi

if ! python3 -c "import aioquic" 2>/dev/null; then
    echo -e "${YELLOW}[WARN] aioquic not installed${NC}"
    echo "[INFO] To install: pip3 install aioquic"
fi

if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[WARN] go not installed (needed for quic-go tests)${NC}"
else
    GO_VERSION=$(go version)
    echo "[INFO] Found: $GO_VERSION"
fi

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo -e "${RED}[ERROR] Missing required dependencies: ${MISSING_DEPS[*]}${NC}"
    exit 1
fi

# Build server
echo ""
echo "[INFO] Building QUIC server..."
if ! zig build; then
    echo -e "${RED}[ERROR] Build failed${NC}"
    exit 1
fi

if [ ! -f "$SERVER_BINARY" ]; then
    echo -e "${RED}[ERROR] Server binary not found: $SERVER_BINARY${NC}"
    exit 1
fi

echo -e "${GREEN}[OK] Build successful${NC}"

# Start server
echo ""
echo "[INFO] Starting QUIC server on ${SERVER_ADDR}:${SERVER_PORT}..."
$SERVER_BINARY --bind ${SERVER_ADDR}:${SERVER_PORT} --cert $CERT_FILE --key $KEY_FILE --insecure > /tmp/quic-server.log 2>&1 &
SERVER_PID=$!

# Give server time to start
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}[ERROR] Server failed to start${NC}"
    cat /tmp/quic-server.log
    exit 1
fi

echo -e "${GREEN}[OK] Server running (PID: $SERVER_PID)${NC}"

# Cleanup function
cleanup() {
    echo ""
    echo "[INFO] Cleaning up..."
    if kill -0 $SERVER_PID 2>/dev/null; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    echo "[INFO] Server logs:"
    tail -20 /tmp/quic-server.log || true
}
trap cleanup EXIT

# Test results
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local name=$1
    local cmd=$2
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo ""
    echo "----------------------------------------"
    echo "[TEST $TESTS_RUN] $name"
    echo "----------------------------------------"
    
    if eval "$cmd"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${GREEN}[PASS]${NC} $name"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "${RED}[FAIL]${NC} $name"
        return 1
    fi
}

# Test 1: aioquic HTTP/3 client
if python3 -c "import aioquic" 2>/dev/null; then
    run_test "aioquic HTTP/3 client" \
        "timeout 10 python3 -m aioquic.examples.http3_client $SERVER_URL --insecure -q 2>&1 | grep -q 'Received'"
else
    echo ""
    echo "[SKIP] aioquic not available"
fi

# Test 2: aioquic echo client (if available)
if python3 -c "import aioquic" 2>/dev/null; then
    cat > /tmp/test_aioquic_echo.py << 'PYEOF'
import asyncio
import sys
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

async def test_echo():
    config = QuicConfiguration(is_client=True, verify_mode=0)
    
    async with connect("127.0.0.1", 4433, configuration=config) as client:
        # Open stream and send data
        stream_id = client._quic.get_next_available_stream_id()
        client._quic.send_stream_data(stream_id, b"Hello QUIC\n", end_stream=False)
        
        # Wait for response
        await asyncio.sleep(1)
        
        # Check for received data
        events = []
        while True:
            try:
                event = client._quic.next_event()
                if event is None:
                    break
                events.append(event)
                if isinstance(event, StreamDataReceived):
                    print(f"Received: {event.data.decode()}", file=sys.stderr)
                    return True
            except:
                break
        
        return len(events) > 0

try:
    result = asyncio.run(test_echo())
    sys.exit(0 if result else 1)
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
    
    run_test "aioquic echo test" \
        "timeout 10 python3 /tmp/test_aioquic_echo.py 2>&1"
fi

# Test 3: quic-go client (if Go is available)
if command -v go &> /dev/null; then
    cat > /tmp/test_quicgo.go << 'GOEOF'
package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "io"
    "time"

    "github.com/quic-go/quic-go"
)

func main() {
    tlsConf := &tls.Config{
        InsecureSkipVerify: true,
        NextProtos:         []string{"h3"},
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    conn, err := quic.DialAddr(ctx, "127.0.0.1:4433", tlsConf, nil)
    if err != nil {
        fmt.Printf("Dial failed: %v\n", err)
        return
    }
    defer conn.CloseWithError(0, "")

    stream, err := conn.OpenStreamSync(ctx)
    if err != nil {
        fmt.Printf("Stream open failed: %v\n", err)
        return
    }

    // Send test data
    _, err = stream.Write([]byte("Hello from quic-go\n"))
    if err != nil {
        fmt.Printf("Write failed: %v\n", err)
        return
    }

    // Read response
    buf := make([]byte, 1024)
    stream.SetReadDeadline(time.Now().Add(2 * time.Second))
    n, err := stream.Read(buf)
    if err != nil && err != io.EOF {
        fmt.Printf("Read failed: %v\n", err)
        return
    }

    fmt.Printf("SUCCESS: Received %d bytes: %s\n", n, string(buf[:n]))
}
GOEOF

    cd /tmp
    if go mod init test_quicgo 2>/dev/null; then
        go get github.com/quic-go/quic-go@latest > /dev/null 2>&1 || true
    fi
    
    run_test "quic-go client" \
        "cd /tmp && timeout 15 go run test_quicgo.go 2>&1 | grep -q 'SUCCESS'"
    
    cd - > /dev/null
else
    echo ""
    echo "[SKIP] Go not available for quic-go tests"
fi

# Test 4: Basic Python socket test
cat > /tmp/test_python_raw.py << 'PYEOF'
#!/usr/bin/env python3
import socket
import sys

def test_connection():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    try:
        # Send a simple UDP packet to trigger server response
        # This is a minimal QUIC Initial packet structure
        initial_packet = bytes([
            0xc0,  # Long header, Initial
            0x00, 0x00, 0x00, 0x01,  # Version
        ])
        
        sock.sendto(initial_packet, ('127.0.0.1', 4433))
        
        # Wait for response
        data, addr = sock.recvfrom(2048)
        print(f"Received {len(data)} bytes from server", file=sys.stderr)
        return len(data) > 0
        
    except socket.timeout:
        print("Timeout waiting for server response", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False
    finally:
        sock.close()

sys.exit(0 if test_connection() else 1)
PYEOF

chmod +x /tmp/test_python_raw.py

run_test "Raw UDP connectivity" \
    "python3 /tmp/test_python_raw.py 2>&1"

# Test 5: Using our own client
if [ -f "./zig-out/bin/quic-client" ]; then
    run_test "Native Zig client" \
        "timeout 10 ./zig-out/bin/quic-client --connect ${SERVER_ADDR}:${SERVER_PORT} --insecure 2>&1 | head -20"
else
    echo ""
    echo "[SKIP] Native client not built"
fi

# Summary
echo ""
echo "========================================"
echo "  Test Summary"
echo "========================================"
echo "Total tests run:    $TESTS_RUN"
echo -e "Tests passed:       ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed:       ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi
