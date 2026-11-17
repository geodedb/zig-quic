#!/usr/bin/env bash
set -euo pipefail

zig version
printf '%s\n' 'Checking portable clocks and entropy'
zig build test-portable-runtime -j2 --summary all
printf '%s\n' 'Checking nonblocking UDP batching'
zig build test -Dtest-filter=udp_batch_runtime_smoke -j2 --summary all
printf '%s\n' 'Checking real Geode transport compatibility'
zig build test -Dtest-filter=transport_geode_compat -j2 --summary all
# SONNY-6669: off Linux the loopback benchmarks cannot measure; they must
# say so (a not-measured row, which fails the perf gate), never report
# placeholder numbers.
printf '%s\n' 'Checking that Linux-only benchmarks are not measured here'
zig build bench -- --suite=poll_overhead --output=bench-nonlinux.json
python3 - bench-nonlinux.json <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))["rows"]
bad = [r for r in rows if r.get("not_measured") != "UnsupportedPlatform"]
print(f"{len(rows)} rows, {len(rows) - len(bad)} not measured (UnsupportedPlatform)")
if not rows or bad:
    sys.exit(f"expected every row not measured, got: {bad or 'no rows'}")
PY
