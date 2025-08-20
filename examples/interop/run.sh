#!/usr/bin/env bash
set -euo pipefail

# Manual interop runner: builds zig binaries and runs go harness.
# Prereqs: go toolchain, openssl for certs.

ROOT=$(cd "$(dirname "$0")"/../.. && pwd)
INTEROP_DIR="$ROOT/examples/interop"
CERT_DIR="$INTEROP_DIR/certs"

if [ ! -f "$CERT_DIR/cert.pem" ]; then
  echo "Generating self-signed certs..." >&2
  bash "$CERT_DIR/generate.sh"
fi

# Build zig tools and CLI
( cd "$ROOT" && zig build cli tools )

# Run Go server and client examples with module replace to local quic-go
( cd "$INTEROP_DIR" && go mod tidy )

echo "Starting quic-go server..." >&2
( cd "$INTEROP_DIR/go-server" && go run . --addr 127.0.0.1:4433 --alpn h3 --cert "$CERT_DIR/cert.pem" --key "$CERT_DIR/key.pem" ) &
GO_SERVER_PID=$!
sleep 1

echo "Running quic-go client..." >&2
( cd "$INTEROP_DIR/go-client" && go run . --addr 127.0.0.1:4433 --alpn h3 --sni test.local --insecure )

kill $GO_SERVER_PID || true
