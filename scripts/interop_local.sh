#!/usr/bin/env bash
set -euo pipefail

# Local helper to run a subset of interop cases using the python interop runner.
# Builds the zig-qns image and then invokes the runner pairing it with quic-go
# (or any other implementation specified via IMPL env var).
#
# Usage:
#   scripts/interop_local.sh            # build image + run handshake + transfer with quic-go
#   TESTS=handshake,transfer IMPL=quiche scripts/interop_local.sh

ROOT=$(dirname "$0")/..
pushd "$ROOT" >/dev/null

IMAGE_TAG=zig-qns:local
echo "[interop] Building local zig-qns image..."
docker build -t $IMAGE_TAG examples/interop/zig-qns

pushd examples/interop/quic-interop-runner >/dev/null
pip3 install -r requirements.txt >/dev/null

TESTS=${TESTS:-handshake,transfer}
IMPL=${IMPL:-quic-go}

echo "[interop] Running tests $TESTS against $IMPL"
# Forward retry token secret if provided so retry testcase can validate token MACs.
EXTRA_ENV=()
if [[ -n "${RETRY_TOKEN_SECRET:-}" ]]; then
	echo "[interop] Propagating RETRY_TOKEN_SECRET to container"
	EXTRA_ENV+=("-e" "RETRY_TOKEN_SECRET=$RETRY_TOKEN_SECRET")
fi

# Run interop tests; always continue to allow log summarization even on failure.
python3 run.py -t $TESTS -c zig -s $IMPL -r zig=$IMAGE_TAG "${EXTRA_ENV[@]}" || true

LOG_DIR="logs"
echo "[interop] Parsing path validation events in $LOG_DIR"
MATCHES=$(grep -h "path: \(change detected\|validated\)" "$LOG_DIR"/*.log 2>/dev/null || true)
if [[ -n "$MATCHES" ]]; then
	echo "[interop][path] Events detected:" >&2
	echo "$MATCHES" >&2
else
	echo "[interop][path] No path validation events found" >&2
fi

echo "Logs are under examples/interop/quic-interop-runner/$LOG_DIR"
popd >/dev/null
popd >/dev/null
