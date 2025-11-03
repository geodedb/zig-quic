#!/bin/bash
# Comprehensive QUIC/TLS debugging test
# Captures server and client outputs with full TLS debugging

set -e

SERVER_BIN="./zig-out/bin/quic-server"
CLIENT_BIN="./test-clients/quic-go-client/quic-go-test-client"
SERVER_LOG="/tmp/quic-server-debug.log"
CLIENT_LOG="/tmp/quic-client-debug.log"
PORT=4433

echo "=== QUIC/TLS 1.3 Handshake Debug Test ==="
echo ""

# Clean up old logs
rm -f "$SERVER_LOG" "$CLIENT_LOG" /tmp/sslkeylog.txt

# Kill any existing server
pkill -f quic-server || true
sleep 1

# Start server in background with debug output
echo "[1/4] Starting Zig QUIC server on port $PORT..."
"$SERVER_BIN" 2>&1 | tee "$SERVER_LOG" &
SERVER_PID=$!
echo "       Server PID: $SERVER_PID"
sleep 2

# Check if server started successfully
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    exit 1
fi

echo "[2/4] Server ready, starting instrumented quic-go client..."
echo ""

# Run client with full debugging
export QUIC_GO_LOG_LEVEL=debug
export SSLKEYLOGFILE=/tmp/sslkeylog.txt
"$CLIENT_BIN" -addr 127.0.0.1:$PORT -verbose 2>&1 | tee "$CLIENT_LOG" || true

echo ""
echo "[3/4] Test completed, stopping server..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo "[4/4] Analyzing results..."
echo ""
echo "================================================================"
echo "SERVER TRANSCRIPT HASH AND KEYS:"
echo "================================================================"
grep -A1 "\[TLS_KEY_SCHEDULE\]" "$SERVER_LOG" || echo "(No server key schedule output found)"

echo ""
echo "================================================================"
echo "CLIENT KEYS (from quic-go):"
echo "================================================================"
grep "\[TLS_DEBUG\]" "$CLIENT_LOG" || echo "(No client TLS debug output found)"

echo ""
echo "================================================================"
echo "CLIENT CRYPTO PROCESSING:"
echo "================================================================"
grep "\[CRYPTO_MGR\]\|\[UNPACKER\]" "$CLIENT_LOG" | head -20 || echo "(No crypto manager output found)"

echo ""
echo "================================================================"
echo "ANALYSIS:"
echo "================================================================"

# Extract transcript hashes
SERVER_HASH=$(grep "Transcript hash (CH+SH):" "$SERVER_LOG" | sed 's/.*: //' || echo "NOT_FOUND")
echo "Server transcript hash: $SERVER_HASH"

# Extract traffic secrets
SERVER_CLIENT_HS=$(grep "Client HS traffic secret:" "$SERVER_LOG" | sed 's/.*: //' || echo "NOT_FOUND")
SERVER_SERVER_HS=$(grep "Server HS traffic secret:" "$SERVER_LOG" | sed 's/.*: //' || echo "NOT_FOUND")

CLIENT_READ_HS=$(grep "setReadKey(Handshake):" "$CLIENT_LOG" | sed 's/.*trafficSecret=//' || echo "NOT_FOUND")
CLIENT_WRITE_HS=$(grep "setWriteKey(Handshake):" "$CLIENT_LOG" | sed 's/.*trafficSecret=//' || echo "NOT_FOUND")

echo ""
echo "Server-side Client HS secret: $SERVER_CLIENT_HS"
echo "Client-side Write HS secret:  $CLIENT_WRITE_HS"
echo ""
echo "Server-side Server HS secret: $SERVER_SERVER_HS"
echo "Client-side Read HS secret:   $CLIENT_READ_HS"
echo ""

# Compare secrets
if [ "$SERVER_CLIENT_HS" != "NOT_FOUND" ] && [ "$CLIENT_WRITE_HS" != "NOT_FOUND" ]; then
    if [ "$SERVER_CLIENT_HS" = "$CLIENT_WRITE_HS" ]; then
        echo "✓ Client handshake secrets MATCH"
    else
        echo "✗ Client handshake secrets MISMATCH"
    fi
fi

if [ "$SERVER_SERVER_HS" != "NOT_FOUND" ] && [ "$CLIENT_READ_HS" != "NOT_FOUND" ]; then
    if [ "$SERVER_SERVER_HS" = "$CLIENT_READ_HS" ]; then
        echo "✓ Server handshake secrets MATCH"
    else
        echo "✗ Server handshake secrets MISMATCH"
    fi
fi

echo ""
echo "Full logs saved to:"
echo "  Server: $SERVER_LOG"
echo "  Client: $CLIENT_LOG"
echo "  SSL keys: /tmp/sslkeylog.txt"
