#!/usr/bin/env bash
set -e

echo "========================================"
echo "Simple 1-RTT Diagnostic Test"
echo "========================================"
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Cleanup
cleanup() {
    echo ""
    echo "Cleaning up..."
    pkill -f test_quic_server || true
    pkill -f diag_test_client || true
    sleep 1
}
trap cleanup EXIT

# Use existing test server
SERVER_BIN="./test_quic_server"

if [ ! -f "$SERVER_BIN" ]; then
    echo -e "${YELLOW}Compiling test server...${NC}"
    zig build-exe test_quic_server.zig \
        -Isrc \
        -Iforks/boringssl/include \
        -Lforks/boringssl/build/crypto \
        -Lforks/boringssl/build/ssl \
        -lcrypto \
        -lssl \
        -lc
fi

if [ ! -f "$SERVER_BIN" ]; then
    echo -e "${RED}✗ Server binary not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Server binary ready${NC}"

# Build Go client
echo -e "${BLUE}Building diagnostic client...${NC}"
go build -o diag_test_client diag_test_client.go
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Client build failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Client built${NC}"
echo ""

# Start server
echo -e "${BLUE}Starting server...${NC}"
$SERVER_BIN --port 4433 > /tmp/simple_diag_server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}✗ Server failed to start${NC}"
    cat /tmp/simple_diag_server.log
    exit 1
fi
echo -e "${GREEN}✓ Server started${NC}"
echo ""

# Run client
echo -e "${BLUE}Running client test...${NC}"
echo "========================================"
./diag_test_client 2>&1 | tee /tmp/simple_diag_client.log
echo "========================================"
echo ""

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# Analysis
echo ""
echo "========================================"
echo "ANALYSIS"
echo "========================================"
echo ""

# Check client result
if grep -q "SUCCESS! Received" /tmp/simple_diag_client.log; then
    echo -e "${GREEN}✓✓✓ CLIENT RECEIVED RESPONSE${NC}"
    grep "SUCCESS" /tmp/simple_diag_client.log
    echo ""
    echo -e "${GREEN}TEST PASSED: Bi-directional communication works!${NC}"
    exit 0
else
    echo -e "${RED}✗ Client did not receive response${NC}"
fi

# Check what server received
echo ""
echo -e "${YELLOW}Server RX Status:${NC}"
if grep -q "stream0 opened rx\|STREAM frame\|readStream" /tmp/simple_diag_server.log; then
    echo -e "${GREEN}✓ Server received STREAM data${NC}"
    grep -E "stream0 opened rx|STREAM frame|readStream" /tmp/simple_diag_server.log | head -5
else
    echo -e "${RED}✗ Server did NOT receive STREAM data${NC}"
fi

# Check what server sent
echo ""
echo -e "${YELLOW}Server TX Status:${NC}"
if grep -q "writeStream\|Sending control frames\|encodeShortProtected" /tmp/simple_diag_server.log; then
    echo -e "${GREEN}✓ Server attempted to send response${NC}"
    grep -E "writeStream|Sending control frames|encodeShortProtected" /tmp/simple_diag_server.log | head -5
else
    echo -e "${RED}✗ Server did NOT attempt to send response${NC}"
fi

# Check for decryption issues
echo ""
echo -e "${YELLOW}Packet Decryption:${NC}"
if grep -q "decodeShortProtected\|decoded 1-RTT" /tmp/simple_diag_server.log; then
    DECODE_COUNT=$(grep -c "decodeShortProtected\|decoded 1-RTT" /tmp/simple_diag_server.log || echo "0")
    echo "  Server 1-RTT decode attempts: $DECODE_COUNT"
fi

# Show critical errors
echo ""
if grep -qi "error\|failed\|invalid" /tmp/simple_diag_server.log; then
    echo -e "${RED}Errors found in server log:${NC}"
    grep -i "error\|failed\|invalid" /tmp/simple_diag_server.log | head -10
fi

echo ""
echo "Full logs:"
echo "  Server: /tmp/simple_diag_server.log"
echo "  Client: /tmp/simple_diag_client.log"
echo ""
echo -e "${RED}TEST FAILED${NC}"
exit 1
