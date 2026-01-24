#!/usr/bin/env bash
set -euo pipefail

# Debug script to test if the Zig server receives and responds to packets

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
pushd "$ROOT" >/dev/null

echo "Building Zig QUIC implementation..."
zig build -Drelease-safe=true install || exit 1

echo "Starting Zig server locally..."
./zig-out/bin/quic-server --bind 127.0.0.1:4433 --alpn h3 --insecure &
SERVER_PID=$!
sleep 2

echo "Testing with nc (netcat)..."
echo -n "test" | nc -u 127.0.0.1 4433

sleep 1

echo "Killing server..."
kill $SERVER_PID 2>/dev/null || true

echo "Done"
popd >/dev/null