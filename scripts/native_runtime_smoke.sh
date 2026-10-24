#!/usr/bin/env bash
set -euo pipefail

zig version
zig build test-portable-runtime
zig build test -- --test-filter udp_batch_runtime_smoke
zig build test -- --test-filter transport_geode_compat
