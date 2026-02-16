$ErrorActionPreference = "Stop"

zig version
zig build test -- --test-filter udp_batch_runtime_smoke
