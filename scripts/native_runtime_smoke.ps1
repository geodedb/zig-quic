$ErrorActionPreference = "Stop"

zig version
zig build test-portable-runtime
zig build test -- --test-filter udp_batch_runtime_smoke
# SONNY-6669: off Linux the loopback benchmarks cannot measure; they must
# say so (a not-measured row), never report placeholder numbers.
zig build bench -- --suite=poll_overhead --output=bench-nonlinux.json
$rows = (Get-Content bench-nonlinux.json -Raw | ConvertFrom-Json).rows
$bad = @($rows | Where-Object { $_.not_measured -ne "UnsupportedPlatform" })
Write-Host "$($rows.Count) rows, $($rows.Count - $bad.Count) not measured (UnsupportedPlatform)"
if ($rows.Count -eq 0 -or $bad.Count -ne 0) { throw "expected every row not measured" }
