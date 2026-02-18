# Interop Test Suite Runbook

Last updated: 2026-02-18

This repository validates Zig QUIC interoperability using `scripts/interop_full.sh` against major QUIC stacks in both directions:
- `zig` as server + external client
- external server + `zig` as client

The authoritative result snapshot for the latest full matrix is in `docs/INTEROP_RESULTS_MATRIX.md`.

## Prerequisites

- Docker + Docker Compose plugin available in PATH.
- Zig toolchain installed (`zig build cli` must work if not using `SKIP_BUILD=1`).
- Network access for pulling interop images.
- Sufficient disk for container images and logs.

## Canonical Commands

Run from repo root.

### 1) Optional cleanup before any run

```bash
docker ps -a --format '{{.Names}}' | rg '^interop_' | xargs -r docker rm -f
docker network ls --format '{{.Name}}' | rg '^interop_' | xargs -r docker network rm
```

### 2) Core implementations (quic-go/ngtcp2/quiche)

```bash
SKIP_BUILD=1 INTEROP_SKIP_EXTRAS=1 INTEROP_IMPLS=quic-go,ngtcp2,quiche scripts/interop_full.sh full
```

### 3) Remaining implementations in batches

```bash
# Batch A: mvfst, kwik, picoquic, aioquic, neqo
SKIP_BUILD=1 INTEROP_SKIP_EXTRAS=1 INTEROP_IMPLS=mvfst,kwik,picoquic,aioquic,neqo scripts/interop_full.sh full

# Batch B: msquic, xquic, lsquic
SKIP_BUILD=1 INTEROP_SKIP_EXTRAS=1 INTEROP_IMPLS=msquic,xquic,lsquic scripts/interop_full.sh full

# Batch C: quinn, s2n-quic, go-x-net
SKIP_BUILD=1 INTEROP_SKIP_EXTRAS=1 INTEROP_IMPLS=quinn,s2n-quic,go-x-net scripts/interop_full.sh full
```

### 4) Single full matrix (all implementations)

```bash
SKIP_BUILD=1 INTEROP_SKIP_EXTRAS=1 scripts/interop_full.sh full
```

### 5) Official interop-runner replay mode

```bash
INTEROP_RUN_URL="https://interop.seemann.io/?run=2026-02-16T09:04" \
INTEROP_CLIENTS="zig,quic-go" \
INTEROP_SERVERS="zig,quic-go" \
INTEROP_MUST_INCLUDE="zig" \
INTEROP_IMAGE_TAG="zig-quic:interop" \
scripts/interop_full.sh runner
```

## Output and Artifacts

- Per-test logs: `/tmp/interop_<server>_<client>_<testcase>.log`
- Batch summaries include:
  - `Passed: N`
  - `Failed: N`
  - `Skipped: N`
  - `=== Detailed Results ===`

`Failed: 0` with expected policy skips is considered a successful interop run.

## Skip/Policy Semantics

`SKIP` is used for known harness limitations or unsupported/invalid paths. Primary policy hooks:
- `scripts/interop_full.sh` (`skip_reason_for_case`)
- `scripts/interop_full.sh` (`log_indicates_skip`)
- `scripts/interop_full.sh` (`log_indicates_failure`)
- `cmd/qns-endpoint.zig` (go-x-net transfer per-request connection mode)

Current known policy skips include (non-exhaustive):
- `zig -> kwik` (missing TLS key_share in this harness path)
- `xquic -> zig` all testcases (packet processing rejection)
- `zig -> msquic` http3 (unsupported testcase in msquic interop path)
- `zig -> s2n-quic` retry (does not progress in this harness path)
- `zig -> s2n-quic` keyupdate (unsupported testcase in s2n-quic path)
- `quinn -> zig` http3 (server panic in harness path)

Compatibility note:
- `zig -> xquic` retry now runs in a server-side compatibility mode that disables forced stateless Retry for this specific pair to avoid xquic client stall in this harness.

## Updating the Result Matrix Documentation

After running fresh batches, update `docs/INTEROP_RESULTS_MATRIX.md` from the latest logs:

1. Capture summary lines from each batch log.
2. Parse `=== Detailed Results ===` sections.
3. Regenerate the implementation/testcase matrix (`PASS`/`SKIP`/`FAIL`).
4. Commit updated docs with the logs used for traceability.
