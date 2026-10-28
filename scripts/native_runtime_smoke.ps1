$ErrorActionPreference = "Stop"

zig version
zig build test-portable-runtime
zig build test -- --test-filter udp_batch_runtime_smoke
