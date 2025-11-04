#!/usr/bin/env bash
set -e

echo "========================================"
echo "QUIC 1-RTT Diagnostic Test"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    pkill -f diag_test_server || true
    pkill -f diag_test_client || true
}
trap cleanup EXIT

# Build server (use existing test_quic_server as template)
echo -e "${BLUE}[1/4] Building diagnostic server...${NC}"
# Copy the working imports from test_quic_server
zig build-exe diag_test_server.zig \
    -freference-trace \
    --mod quic \
    --mod root=src/quic.zig \
    -lc \
    -Iforks/boringssl/include \
    -Lforks/boringssl/build/crypto \
    -Lforks/boringssl/build/ssl \
    -lcrypto \
    -lssl 2>&1

# Try simpler approach if that fails
if [ $? -ne 0 ]; then
    echo "Trying simplified build..."
    cp test_quic_server.zig diag_server_backup.zig
    zig build 2>&1 | grep -q "error" && echo -e "${RED}✗ Build failed${NC}" && exit 1
    # Just use test_quic_server binary with modified behavior
    cp diag_test_server.zig test_quic_server.zig
    zig build
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ Server build failed${NC}"
        mv diag_server_backup.zig test_quic_server.zig
        exit 1
    fi
    mv diag_server_backup.zig test_quic_server.zig
fi
echo -e "${GREEN}✓ Server built${NC}"
echo ""

# Build client
echo -e "${BLUE}[2/4] Building diagnostic Go client...${NC}"
cd "$(dirname "$0")"
go build -o diag_test_client diag_test_client.go

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Client build failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Client built${NC}"
echo ""

# Start server
echo -e "${BLUE}[3/4] Starting server...${NC}"
./diag_test_server > /tmp/diag_server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"
sleep 2

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}✗ Server failed to start${NC}"
    cat /tmp/diag_server.log
    exit 1
fi
echo -e "${GREEN}✓ Server started${NC}"
echo ""

# Run client
echo -e "${BLUE}[4/4] Running diagnostic client...${NC}"
echo "----------------------------------------"
./diag_test_client 2>&1 | tee /tmp/diag_client.log
CLIENT_EXIT=$?
echo "----------------------------------------"
echo ""

# Stop server
kill $SERVER_PID 2>/dev/null || true
sleep 1

# Analysis
echo "========================================"
echo "Test Analysis"
echo "========================================"
echo ""

echo -e "${YELLOW}--- Client Summary ---${NC}"
if grep -q "SUCCESS! Received" /tmp/diag_client.log; then
    echo -e "${GREEN}✓ Client received response data${NC}"
    grep "Received" /tmp/diag_client.log | tail -3
else
    echo -e "${RED}✗ Client did NOT receive response${NC}"
    if grep -q "timeout" /tmp/diag_client.log; then
        echo -e "${RED}  Reason: Timeout${NC}"
    elif grep -q "EOF" /tmp/diag_client.log; then
        echo -e "${RED}  Reason: Stream closed by server${NC}"
    fi
fi
echo ""

echo -e "${YELLOW}--- Server Summary ---${NC}"
if grep -q "RECEIVED.*BYTES from stream 0" /tmp/diag_server.log; then
    echo -e "${GREEN}✓ Server received STREAM frame${NC}"
    grep "RECEIVED.*BYTES" /tmp/diag_server.log | head -3
else
    echo -e "${RED}✗ Server did NOT receive STREAM frame${NC}"
fi
echo ""

if grep -q "ECHOING.*bytes back" /tmp/diag_server.log; then
    echo -e "${GREEN}✓ Server attempted to echo${NC}"
    grep -A2 "ECHOING" /tmp/diag_server.log | head -5
else
    echo -e "${RED}✗ Server did NOT attempt echo${NC}"
fi
echo ""

if grep -q "writeStream SUCCESS" /tmp/diag_server.log; then
    echo -e "${GREEN}✓ Server writeStream succeeded${NC}"
    grep "writeStream SUCCESS" /tmp/diag_server.log | head -3
else
    echo -e "${RED}✗ Server writeStream did not succeed${NC}"
    if grep -q "writeStream FAILED" /tmp/diag_server.log; then
        echo -e "${RED}  Found writeStream failures:${NC}"
        grep "writeStream FAILED" /tmp/diag_server.log | head -3
    fi
    if grep -q "writeStream returned 0" /tmp/diag_server.log; then
        echo -e "${YELLOW}  writeStream returned 0 (keys not ready or flow control)${NC}"
    fi
fi
echo ""

echo -e "${YELLOW}--- Packet-Level Analysis ---${NC}"

# Check for 1-RTT packet decryption on server
if grep -q "decodeShortProtected" /tmp/diag_server.log; then
    echo -e "${GREEN}✓ Server attempted to decode 1-RTT packets${NC}"
    DECODE_COUNT=$(grep -c "decodeShortProtected" /tmp/diag_server.log || echo "0")
    echo "  Decode attempts: $DECODE_COUNT"
else
    echo -e "${RED}✗ Server did not attempt 1-RTT decode${NC}"
fi

# Check for STREAM frame parsing
if grep -q "Server received STREAM frame" /tmp/diag_server.log; then
    echo -e "${GREEN}✓ Server parsed STREAM frame${NC}"
    grep "Server received STREAM frame" /tmp/diag_server.log | head -3
else
    echo -e "${RED}✗ Server did not parse STREAM frame${NC}"
fi

# Check for 1-RTT packet encoding on server
if grep -q "Sending control frames" /tmp/diag_server.log; then
    echo -e "${GREEN}✓ Server attempted to send 1-RTT packets${NC}"
    SEND_COUNT=$(grep -c "Sending control frames" /tmp/diag_server.log || echo "0")
    echo "  Send attempts: $SEND_COUNT"
else
    echo -e "${RED}✗ Server did not attempt to send 1-RTT packets${NC}"
fi

# Check client 1-RTT reception
echo ""
echo -e "${YELLOW}--- Client Packet Reception ---${NC}"
if grep -q "Received 1-RTT packet" /tmp/diag_client.log; then
    echo -e "${GREEN}✓ Client received 1-RTT packets from server${NC}"
    RX_COUNT=$(grep -c "Received 1-RTT packet" /tmp/diag_client.log || echo "0")
    echo "  Count: $RX_COUNT"
    grep "Received 1-RTT packet" /tmp/diag_client.log | head -5
else
    echo -e "${YELLOW}⚠ Client logs don't show 1-RTT packet reception details${NC}"
fi

echo ""
echo "========================================"
echo "Log Files"
echo "========================================"
echo "Server log: /tmp/diag_server.log"
echo "Client log: /tmp/diag_client.log"
echo ""
echo "To examine full logs:"
echo "  cat /tmp/diag_server.log"
echo "  cat /tmp/diag_client.log"
echo ""

# Final verdict
echo "========================================"
echo "Final Verdict"
echo "========================================"
if grep -q "SUCCESS! Received" /tmp/diag_client.log && \
   grep -q "RECEIVED.*BYTES from stream 0" /tmp/diag_server.log; then
    echo -e "${GREEN}✓✓✓ TEST PASSED: Bi-directional communication works!${NC}"
    exit 0
else
    echo -e "${RED}✗✗✗ TEST FAILED: Bi-directional communication broken${NC}"
    echo ""
    echo "Likely causes:"
    if ! grep -q "RECEIVED.*BYTES from stream 0" /tmp/diag_server.log; then
        echo -e "${RED}1. Server not receiving/parsing client STREAM frames${NC}"
        echo "   -> Check 1-RTT packet decryption on server RX path"
    fi
    if grep -q "RECEIVED.*BYTES from stream 0" /tmp/diag_server.log && \
       ! grep -q "SUCCESS! Received" /tmp/diag_client.log; then
        echo -e "${RED}2. Server receiving but client not getting response${NC}"
        echo "   -> Check server 1-RTT packet TX and client RX decryption"
    fi
    exit 1
fi
