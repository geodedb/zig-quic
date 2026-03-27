# Benchmark Results

JSON benchmark result files. Format version 1.

## Files

- `baseline.json` — accepted performance standard (update with `make bench-baseline`)
- `<git-sha>.json` — per-commit snapshots (save with `make bench-save`)

## Workflow

1. `make bench-baseline` — set new acceptance criteria
2. `make bench-save` — capture current performance snapshot
3. `make bench-compare` — detect regressions against baseline (exit 1 on fail)
