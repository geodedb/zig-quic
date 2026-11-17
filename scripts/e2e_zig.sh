#!/usr/bin/env bash
# e2e-test-zig (SONNY-6668): the Zig client against the Zig server over
# loopback, one request/response stream. Fails unless the client exits 0
# having received the server's echo of its request; a server that merely
# logged a connection is not enough.
#
# Environment (defaults match the CI job):
#   BIN=zig-out/bin  ADDR=127.0.0.1:4433  CERT=server-cert.pem
#   KEY=server-key.pem  ALPN=hq-interop  CLIENT_ALPN=$ALPN  LOG_DIR=/tmp
set -euo pipefail

BIN="${BIN:-zig-out/bin}"
ADDR="${ADDR:-127.0.0.1:4433}"
CERT="${CERT:-server-cert.pem}"
KEY="${KEY:-server-key.pem}"
ALPN="${ALPN:-hq-interop}"
CLIENT_ALPN="${CLIENT_ALPN:-$ALPN}"
LOG_DIR="${LOG_DIR:-/tmp}"
REQUEST="e2e-zig-request"

"$BIN/quic-server" --bind "$ADDR" --cert "$CERT" --key "$KEY" --insecure --alpn "$ALPN" >"$LOG_DIR/server.log" 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT
sleep 3

rc=0
timeout 30 "$BIN/quic-client" --connect "$ADDR" --insecure --alpn "$CLIENT_ALPN" --msg "$REQUEST" >"$LOG_DIR/client.log" 2>&1 || rc=$?
cat "$LOG_DIR/client.log"

if [ "$rc" -ne 0 ]; then
  echo "e2e-zig: FAIL: client exit $rc" >&2
  exit 1
fi
if ! grep -q "^echo: ${REQUEST}\$" "$LOG_DIR/client.log"; then
  echo "e2e-zig: FAIL: no echo of the request on the stream" >&2
  exit 1
fi
echo "e2e-zig: PASS: request/response stream completed"
