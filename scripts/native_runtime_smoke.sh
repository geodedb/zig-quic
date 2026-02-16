#!/usr/bin/env bash
set -euo pipefail

zig version
zig build test -- --test-filter udp_batch_runtime_smoke
