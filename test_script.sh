#!/usr/bin/env bash

pkill "go-interop" || true

set -euo pipefail

PORT=${PORT:-0} # 0 means ephemeral port
HOST=${HOST:-127.0.0.1}

if [[ /tmp/srv.err ]]; then
  rm -f /tmp/srv.err
fi

# Generate certs
bash ./examples/interop/certs/generate.sh

# Build Go interop binaries if missing
if [[ ! -x ./zig-out/bin/go-interop-server || ! -x ./zig-out/bin/go-interop-client ]]; then
  echo "building go interop shims..." >&2
  mkdir -p ./zig-out/bin
  ( cd examples/interop/go-server && go build -o ../../../zig-out/bin/go-interop-server . )
  ( cd examples/interop/go-client && go build -o ../../../zig-out/bin/go-interop-client . )
fi

# Start server on ephemeral port and capture stderr
./zig-out/bin/go-interop-server \
  --addr "${HOST}:${PORT}" \
  --alpn h3 \
  --cert examples/interop/certs/cert.pem \
  --key  examples/interop/certs/key.pem \
  2> /tmp/srv.err &
echo $! > /tmp/srv.pid

# Wait up to ~2s for the "listening on" line
for _ in {1..20}; do
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
set +e
client_out=$(./zig-out/bin/go-interop-client \
  --addr "${addr}" \
  --alpn h3 \
  --sni test.local \
  --insecure \
  --msg hello 2>&1)
status=$?
set -e
echo "client_output=${client_out}" >&2
if echo "$client_out" | grep -q "Application error 0x0 (remote): bye"; then
  echo "interop: treating remote bye (0x0) as success" >&2
  status=0
fi
if [ $status -ne 0 ]; then
  echo "interop client failed" >&2
  kill "$(cat /tmp/srv.pid)" 2>/dev/null || true
  exit $status
fi

# Optional: run zig server+client echo sanity on fixed high port (avoid dynamic capture complexity)
ZIG_ECHO_PORT=${ZIG_ECHO_PORT:-44345}
./zig-out/bin/quic-server --bind "${HOST}:${ZIG_ECHO_PORT}" --alpn h3 --insecure --real-tls 2> /tmp/zsrv.err &
zpid=$!
sleep 0.4
./zig-out/bin/quic-client --connect "${HOST}:${ZIG_ECHO_PORT}" --sni test.local --alpn h3 --insecure --real-tls --msg ping || true
kill $zpid 2>/dev/null || true

# Cleanup
kill "$(cat /tmp/srv.pid)" 2>/dev/null || true