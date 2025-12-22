#!/usr/bin/env bash
set -e

# Generate certs if not exist (P-256)
rm -f server.key server.crt
openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"

# Kill any existing server
killall quic-server 2>/dev/null || true

# Start server with certs
echo "Starting server with certs..."
LOG_LEVEL=debug ./zig-out/bin/quic-server --bind 127.0.0.1:4433 --cert server.crt --key server.key --insecure > server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

sleep 2

# Run Zig client
echo "Running Zig client..."
LOG_LEVEL=debug timeout 10 ./zig-out/bin/quic-client 127.0.0.1 4433 --alpn hq-interop --insecure --msg "PING" > client.log 2>&1 || true

# Check client log for success
if grep -q "echo: PING" client.log; then
    echo "SUCCESS: Zig client received echo response."
else
    echo "FAILURE: Zig client did not receive echo."
    echo "--- Client Log ---"
    cat client.log
    echo "--- Server Log ---"
    cat server.log
fi

# Run Go client (optional, to verify standard client interoperability)
echo "Running Go client..."
timeout 10 go run -mod=mod test-go-client.go > go-client.log 2>&1 || true

if grep -q "Received: hello from go client" go-client.log; then # Assuming go client sends something and expects something
    echo "SUCCESS: Go client worked."
else
    echo "FAILURE: Go client failed."
    echo "--- Go Client Log ---"
    cat go-client.log
fi

kill $SERVER_PID
