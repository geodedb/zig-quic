#!/usr/bin/env bash

pkill "go-interop" || true

set -euo pipefail

PORT=${PORT:-0} # 0 means ephemeral port
HOST=${HOST:-127.0.0.1}

# Generate certs
bash ./examples/interop/certs/generate.sh

# Start server on ephemeral port and capture stderr
./zig-out/bin/go-interop-server \
  --addr "${HOST}:${PORT}" \
  --alpn h3 \
  --cert examples/interop/certs/cert.pem \
  --key  examples/interop/certs/key.pem \
  2> /tmp/srv.err &
echo $! > /tmp/srv.pid

# Wait up to ~2s for the "listening on" line
for i in {1..20}; do
  if grep -q "listening on " /tmp/srv.err; then
    break
  fi
  sleep 0.1
done

# Extract bound address (host:port) robustly and validate
addr="$(sed -n 's/.*listening on \([^ ]\+\).*/\1/p' /tmp/srv.err | head -n1 || true)"
if [[ -z "${addr}" || "${addr}" == *":0" || ! "${addr}" =~ ^[0-9.]+:[0-9]+$ ]]; then
  echo "ERROR: failed to parse valid server address"
  echo "--- server stderr:"
  sed -n '1,200p' /tmp/srv.err || true
  kill "$(cat /tmp/srv.pid)" 2>/dev/null || true
  exit 1
fi

echo "server_addr=${addr}"

# Run client (fail fast if unreachable)
./zig-out/bin/go-interop-client \
  --addr "${addr}" \
  --alpn h3 \
  --sni test.local \
  --insecure \
  --msg hello

# Cleanup
kill "$(cat /tmp/srv.pid)" 2>/dev/null || true
