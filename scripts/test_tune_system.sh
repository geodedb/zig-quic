#!/usr/bin/env bash
# Shell tests for tune-system.sh — dry-run only, no sudo required.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TUNE="$SCRIPT_DIR/tune-system.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

[ -x "$TUNE" ] || fail "tune-system.sh missing or not executable"

# 1. --help exits 0
"$TUNE" --help >/dev/null 2>&1 || fail "--help should exit 0"
pass "--help exits 0"

# 2. Unknown subcommand exits non-zero
if "$TUNE" bogus >/dev/null 2>&1; then fail "unknown subcommand should exit non-zero"; fi
pass "unknown subcommand rejected"

# 3. --dry-run apply covers all knob names from the drop-in
out=$("$TUNE" apply --dry-run 2>&1)
for key in rmem_max wmem_max rmem_default wmem_default netdev_max_backlog udp_mem udp_rmem_min udp_wmem_min ip_local_port_range default_qdisc file-max; do
    echo "$out" | grep -q "$key" || fail "dry-run missing knob: $key"
done
pass "dry-run covers all knobs"

# 4. check subcommand reads current values
"$TUNE" check >/dev/null 2>&1 || fail "check should exit 0"
pass "check exits 0"

echo "ALL PASS"
