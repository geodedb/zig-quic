# Performance Targets

Last updated: 2026-02-16

## Purpose

This document defines the repository's minimum performance contract for QUIC hot paths and CI regression gating.

## Workload Profiles

The repository uses these bounded reference profiles for regression checks:

1. Microbench profile (CI-safe)

- Command: `zig build bench`
- Focus: packet encode/decode hot path, pacing arithmetic, header-protection decode path.
- Data sizes: short-header payloads and handshake payloads used by `bench/main.zig`.

1. Functional profile (correctness under performance changes)

- Command: `zig build test`
- Focus: protocol correctness and no-regression behavior with optimized code paths.

1. Full graph profile (periodic)

- Command: `zig build -Dfull-test-graph=true test`
- Focus: broad integration coverage for refactors touching core packet/recovery/transport code.

## CI Performance Budgets

`scripts/perf-gate.sh` is the unified tiered A/B regression gate (Phase 7
Task 7.1). It runs `zig build bench` to capture current-HEAD JSON and
invokes `zig build bench-compare` against
`benchmarks/results/baseline.json`. Absolute upper bounds are enforced by
`benchmarks/compare.zig`'s `absolute_gates` table:

- `micro/varint / encode` — `latency_p99_ns <= 250`
- `micro/pacing / delay_compute` — `latency_p99_ns <= 400`
- `micro/header_protection / decode` — `latency_p99_ns <= 400000`
- `micro/frame_serialization / short_header_encode` — `alloc_bytes == 0`
- `micro/frame_serialization / short_header_decode` — `alloc_bytes == 0`

Thresholds are intentionally conservative to avoid host-noise flakiness
while still catching material regressions.

`scripts/perf-gate.sh` also enforces the Linux UDP batching guardrail as
a post-compare ratio check (absorbed from the retired
`scripts/perf_udp_batch_gate.sh`):

- Reads `integration/udp_batch` rows for `single` + `batch` variants
- Computes `speedup = batch / single` (throughput_ops_per_sec)
- Requires `speedup >= 0.95x` (default; override via
  `UDP_BATCH_SPEEDUP_MIN=<float>`)
- Skipped on non-Linux hosts (bench emits placeholder rows there)

`scripts/cross_platform_udp_batch_smoke.sh` enforces compile-only
portability guardrails for the batched transport path by driving the
`zig build cross-smoke` step (see `build.zig:cross_smoke_step`):

- Compiles `src/quic/endpoint/transport.zig`,
  `src/quic/endpoint/udp_transport.zig`, and `src/quic/endpoint.zig` via
  `addObject` (no linking) for each target
- Targets matrix:
  - `x86_64-macos-none`
  - `aarch64-macos-none`
  - `x86_64-windows-gnu`
  - `aarch64-windows-gnu`
- Verifies that Linux batched syscalls remain behind fallback-safe
  abstractions and compile cleanly for non-Linux targets

Native runtime smoke coverage is also available on GitLab SaaS non-Linux runners:

- `runtime-smoke-macos-saas` (tag: `saas-macos-medium-m1`, image: `macos-15-xcode-16`)
- `runtime-smoke-windows-saas` (tag: `saas-windows-medium-amd64`)
- Both run `src/quic/endpoint/test_udp_batch_runtime_smoke.zig` via:
  - `scripts/native_runtime_smoke.sh` (macOS)
  - `scripts/native_runtime_smoke.ps1` (Windows)
- Enable by setting CI variable `ENABLE_NATIVE_RUNTIME_SMOKE=true`

## Validation Commands

- Unified perf gate (manual mode): `scripts/perf-gate.sh --baseline=benchmarks/results/baseline.json`
- Unified perf gate (paired-commit mode): `scripts/perf-gate.sh --baseline-commit=<sha>`
- Unified perf gate (phased mode): `scripts/perf-gate.sh <step-name> before` then `... after`
- Local cross-platform compile matrix gate: `scripts/cross_platform_udp_batch_smoke.sh`
- Native runtime smoke (portable): `zig build test -- --test-filter udp_batch_runtime_smoke`
- Baseline bench JSON capture: `zig build bench -- --suite=all --output=benchmarks/results/baseline.json`

## Change Management

Any PR that changes packet encoding/decoding, recovery ACK processing, event-loop polling, or CI benchmark logic must:

1. Run `scripts/perf-gate.sh --baseline=benchmarks/results/baseline.json`.
2. Include updated benchmark evidence in MR notes when thresholds are adjusted.
3. Update this document if workloads or budgets change.
