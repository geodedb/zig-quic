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

RUNNER_DIR=examples/interop/quic-interop-runner
pushd "$RUNNER_DIR" >/dev/null
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
python - <<'EOF'
import json, pathlib, sys
p=pathlib.Path('implementations.json')
data=json.loads(p.read_text())
changed=False
if 'zig' not in data:
	data['zig']={"image":"zig-qns:local","url":"https://github.com/spyder/zig-quic","role":"both"}
	changed=True
else:
	# update image tag each run so latest local build used
	if data['zig'].get('image')!='zig-qns:local':
		data['zig']['image']='zig-qns:local'; changed=True
if changed:
	p.write_text(json.dumps(data, indent=2)+"\n")
EOF

TESTS=${TESTS:-handshake,transfer}
# If IMPL is 'all', exercise all other known implementations as server with zig client.
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

# Sanity cleanup and override setup
rm -f __pycache__/interop*.pyc 2>/dev/null || true
PYTHONPATH="$(pwd)/../zig-wrapper/interop_runner_patch:${PYTHONPATH:-}" export PYTHONPATH
export PYTHON_INTEROP_OVERRIDE=1
if ! grep -q 'class InteropRunner' interop.py; then
	echo "[interop] ERROR: InteropRunner class missing in upstream module" >&2
	exit 1
fi

# Run interop tests; always continue to allow log summarization even on failure.
if [[ "$IMPL" == "all" ]]; then
	# Build list of all implementations except zig (prefer jq, fallback to python)
	if command -v jq >/dev/null 2>&1; then
		ALL_SERVERS=$(jq -r 'keys | map(select(. != "zig")) | join(",")' implementations.json)
	else
		ALL_SERVERS=$(python - <<'EOF'
import json, sys
data=json.load(open('implementations.json'))
print(','.join([k for k in data.keys() if k!='zig']))
EOF
)
	fi
	ZIG_VERBOSE=1 python run.py -t $TESTS -c zig -s "$ALL_SERVERS" -r zig=$IMAGE_TAG --no-auto-unsupported zig "${EXTRA_ENV[@]}" || true
else
	ZIG_VERBOSE=1 python run.py -t $TESTS -c zig -s $IMPL -r zig=$IMAGE_TAG --no-auto-unsupported zig,$IMPL "${EXTRA_ENV[@]}" || true
fi

# No restore needed; modification is idempotent and minimal.

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
