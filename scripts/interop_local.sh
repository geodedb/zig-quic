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
echo "[interop] Building local zig-qns image (root context)..."
docker build -t $IMAGE_TAG -f examples/interop/zig-qns/Dockerfile .

pushd examples/interop/quic-interop-runner >/dev/null
# Create isolated virtualenv for runner deps to avoid system / read-only store issues.
if [[ ! -d .venv ]]; then
	echo "[interop] Creating local Python virtualenv" >&2
	python3 -m venv .venv
fi
source .venv/bin/activate
pip install --upgrade pip >/dev/null 2>&1 || true
pip install -r requirements.txt >/dev/null 2>&1 || {
	echo "[interop] ERROR: failed to install Python requirements" >&2
	deactivate || true
	exit 1
}

# Inject a temporary 'zig' implementation entry if missing (avoid committing changes to submodule).
if ! grep -q '"zig"' implementations.json; then
	echo "[interop] Injecting temporary zig implementation entry" >&2
	cp implementations.json implementations.json.bak
	python - <<'EOF'
import json, pathlib
p=pathlib.Path('implementations.json')
data=json.loads(p.read_text())
if 'zig' not in data:
		data['zig']={"image":"zig-qns:local","url":"https://github.com/spyder/zig-quic","role":"both"}
		p.write_text(json.dumps(data, indent=2)+"\n")
EOF
fi

TESTS=${TESTS:-handshake,transfer}
IMPL=${IMPL:-quic-go}

echo "[interop] Running tests $TESTS against $IMPL"
# Forward retry token secret if provided so retry testcase can validate token MACs.
EXTRA_ENV=()
if [[ -n "${RETRY_TOKEN_SECRET:-}" ]]; then
	echo "[interop] Propagating RETRY_TOKEN_SECRET to container"
	EXTRA_ENV+=("-e" "RETRY_TOKEN_SECRET=$RETRY_TOKEN_SECRET")
fi

# Prepare a local logs directory for this invocation (mirrors runner output layout)
RUN_LOG_DIR="logs"
mkdir -p "$RUN_LOG_DIR"

# Run interop tests; always continue to allow log summarization even on failure.
python run.py -t $TESTS -c zig -s $IMPL -r zig=$IMAGE_TAG "${EXTRA_ENV[@]}" || true

# Restore original implementations.json if we modified it.
if [[ -f implementations.json.bak ]]; then
	mv implementations.json.bak implementations.json
fi

LOG_DIR="logs"
echo "[interop] Parsing path validation events in $LOG_DIR (server/client/endpoint logs if present)"
MATCHES=$(grep -R "path: \(change detected\|validated\)" "$LOG_DIR" 2>/dev/null || true)
if [[ -n "$MATCHES" ]]; then
	echo "[interop][path] Events detected:" >&2
	echo "$MATCHES" >&2
else
	echo "[interop][path] No path validation events found" >&2
fi

echo "Logs are under examples/interop/quic-interop-runner/$LOG_DIR"
deactivate || true
popd >/dev/null
popd >/dev/null
