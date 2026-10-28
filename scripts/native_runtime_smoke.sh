#!/usr/bin/env bash
set -euo pipefail

zig version
printf '%s\n' 'Checking portable clocks and entropy'
zig build test-portable-runtime -j2 --summary all
printf '%s\n' 'Checking nonblocking UDP batching'
zig build test -Dtest-filter=udp_batch_runtime_smoke -j2 --summary all
printf '%s\n' 'Checking real Geode transport compatibility'
zig build test -Dtest-filter=transport_geode_compat -j2 --summary all
