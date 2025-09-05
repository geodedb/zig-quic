#!/usr/bin/env bash
set -euo pipefail

# Pick a free high port to avoid AddressInUse when multiple runs happen quickly.
PORT=${PORT:-0}
if [ "$PORT" = "0" ]; then
	# Ask kernel for a free port using Python or fallback to lsof method.
	if command -v python3 >/dev/null 2>&1; then
		PORT=$(python3 - <<'PY'
import socket
s=socket.socket()
s.bind(('127.0.0.1',0))
print(s.getsockname()[1])
s.close()
PY
)
	else
		# Fallback: naive scan
		for p in $(seq 45000 46000); do
			(echo >/dev/tcp/127.0.0.1/$p) >/dev/null 2>&1 || { PORT=$p; break; }
		done
	fi
fi

LOG_DIR=logs
mkdir -p "$LOG_DIR"

echo "Building QUIC server..."
zig build cli

echo "Starting QUIC server on 127.0.0.1:$PORT ..."
./zig-out/bin/quic-server --bind 127.0.0.1:$PORT --insecure >"$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

echo "Running internal quic-client..."
CLIENT_LOG="$LOG_DIR/client.log"
./zig-out/bin/quic-client --connect 127.0.0.1:$PORT --insecure --msg hello >"$CLIENT_LOG" 2>&1 || CLIENT_RC=$? || true

# Give server a brief moment to flush logs
sleep 1
kill $SERVER_PID 2>/dev/null || true

CLIENT_RC=${CLIENT_RC:-0}

echo "Test complete (server PID $SERVER_PID, client rc $CLIENT_RC)"
echo "Server log: $LOG_DIR/server.log" 
echo "Client log: $CLIENT_LOG" 

if ! grep -q "echo:" "$CLIENT_LOG"; then
	echo "Interop test failed: echo not observed"
	echo "--- client log ---"; sed -n '1,200p' "$CLIENT_LOG"; echo "--- server log ---"; sed -n '1,200p' "$LOG_DIR/server.log"
	exit 1
fi

exit 0