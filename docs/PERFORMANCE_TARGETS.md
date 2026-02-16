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

2. Functional profile (correctness under performance changes)
- Command: `zig build test`
- Focus: protocol correctness and no-regression behavior with optimized code paths.

3. Full graph profile (periodic)
- Command: `zig build -Dfull-test-graph=true test`
- Focus: broad integration coverage for refactors touching core packet/recovery/transport code.

## CI Performance Budgets

`scripts/perf_gate.sh` enforces deterministic upper bounds from benchmark output:

- `varint encode` <= `250 ns/op`
- `pacing delay compute` <= `400 ns/op`
- `hp decode timing` <= `800000000 ns total` (for the bench loop count)
- `short-header allocs/op` for `into encode` must equal `0`
- `short-header allocs/op` for `into decode` must equal `0`

Thresholds are intentionally conservative to avoid host-noise flakiness while still catching material regressions.

`scripts/perf_udp_batch_gate.sh` enforces Linux UDP batching guardrails:

- Runs `zig run bench/udp_batch_bench.zig -- --mode both`
- Parses `mode=single` and `mode=batch` syscall-per-packet and speedup outputs
- Requires syscall reduction factor >= `4.0x` (`single_spp / batch_spp`)
- Requires throughput speedup >= `0.95x` (noise-tolerant non-regression floor)

`scripts/cross_platform_udp_batch_smoke.sh` enforces compile-only portability guardrails for the batched transport path:

- Runs `zig test --test-no-exec` for `src/quic/endpoint/transport.zig`, `src/quic/endpoint/udp_transport.zig`, and `src/quic/endpoint.zig`
- Runs `zig build-exe -fno-emit-bin` for `bench/udp_batch_bench.zig` to guarantee benchmark portability (non-Linux builds skip runtime execution but must compile)
- Targets matrix:
  - `x86_64-macos-none`
  - `aarch64-macos-none`
  - `x86_64-windows-gnu`
  - `aarch64-windows-gnu`
- Verifies that Linux batched syscalls remain behind fallback-safe abstractions and compile cleanly for non-Linux targets

Native runtime smoke coverage is also available on GitLab SaaS non-Linux runners:

- `runtime-smoke-macos-saas` (tag: `saas-macos-medium-m1`, image: `macos-15-xcode-16`)
- `runtime-smoke-windows-saas` (tag: `saas-windows-medium-amd64`)
- Both run `src/quic/endpoint/test_udp_batch_runtime_smoke.zig` via:
  - `scripts/native_runtime_smoke.sh` (macOS)
  - `scripts/native_runtime_smoke.ps1` (Windows)
- Enable by setting CI variable `ENABLE_NATIVE_RUNTIME_SMOKE=true`

## Validation Commands

- Local perf gate: `scripts/perf_gate.sh`
- Local UDP batch gate: `scripts/perf_udp_batch_gate.sh`
- Local cross-platform compile matrix gate: `scripts/cross_platform_udp_batch_smoke.sh`
- Native runtime smoke (portable): `zig build test -- --test-filter udp_batch_runtime_smoke`
- Baseline bench output capture: `zig build bench | tee /tmp/bench.txt`
- Allocation regression verification: confirm bench line
  `short-header allocs/op: ... into encode=0.0000, into decode=0.0000`

## Change Management

Any PR that changes packet encoding/decoding, recovery ACK processing, event-loop polling, or CI benchmark logic must:

1. Run `scripts/perf_gate.sh`.
2. Include updated benchmark evidence in MR notes when thresholds are adjusted.
3. Update this document if workloads or budgets change.
