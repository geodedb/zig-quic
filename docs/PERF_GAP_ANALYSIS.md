# Performance Gap Analysis

Last updated: 2026-02-16

Repository: `gitlab.com/devnw/zig/quic`  
PerfScore formula: `Impact(1-5) * Likelihood(1-5) * 4`

## Performance Context Snapshot

- Primary hot path: QUIC endpoint packet RX/TX (`src/quic/endpoint/incoming/*.zig`, `src/quic/packet.zig`, `src/quic/recovery/recovery.zig`).
- Pipeline-critical paths: `.gitlab-ci.yml` e2e/interop/quality jobs.
- Performance contract source of truth: `docs/PERFORMANCE_TARGETS.md`.

## Baseline Measurements (Safe + Bounded)

- `zig build test`
  - stderr includes expected secure-client guard:
    - `ERROR: quic_client: connectEx requires a CA certificate (use connectInsecure for insecure testing)`
  - Result: pass.
- `zig build -Dfull-test-graph=true test`
  - same expected stderr guard.
  - Result: pass.
- `zig build bench`
  - `varint encode: 86.273 ns/op`
  - `pacing delay compute: 121.59294 ns/op`
  - `hp decode timing: 223846903 ns total for 2000 ops`
  - `short-header allocs/op: legacy encode=1.0000, legacy decode=2.0000, into encode=0.0000, into decode=0.0000`
  - Result: pass.
- `scripts/perf_gate.sh`
  - Parsed and enforced deterministic thresholds for varint/pacing/hp decode and zero-allocation hot path.
  - Result: `PASS`.

## Summary

- Total findings tracked: **10**
- Final status counts:
  - `Closed / Implemented`: **10**
  - `Blocked`: **0**
  - `Open`: **0**
- Confidence counts:
  - `confidence::confirmed`: 10
  - `confidence::suspected`: 0

### Top 5 Residual Risks

1. None.
2. None.
3. None.
4. None.
5. None.

## Stack-Ranked Findings

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | GitLab Issue | Fix Summary | Owner | SLA/Due | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | P0 | 80 | Hot-path short-header TX allocations in ACK/control paths (`confidence::confirmed`) | App/Transport | `src/quic/endpoint/incoming/module_b2.zig:445`, `src/quic/connection/methods_b.zig:398`, `src/quic/endpoint/frame_handler.zig:152`, `bench/main.zig:370` | `zig build bench` reports `into encode=0.0000`, `into decode=0.0000` | https://gitlab.com/devnw/zig/quic/-/issues/62 | Migrated hot-path callsites to `encodeShortProtectedInto` with pooled packet buffers and allocation guardrail bench check | Core QUIC | 2026-02-16 | Closed / Implemented |
| 2 | P1 | 64 | Recovery ACK handling O(acked×sent) (`confidence::confirmed`) | Recovery | `src/quic/recovery/recovery.zig:40`, `src/quic/recovery/recovery.zig:120`, `src/quic/recovery/recovery.zig:173` | `zig build test` pass after PN-index migration | https://gitlab.com/devnw/zig/quic/-/issues/78 | Added per-space `sent_index` map and switched ACK marking to direct PN lookups | Recovery maintainers | 2026-02-16 | Closed / Implemented |
| 3 | P1 | 64 | ACK assembly full stream-map scan for flow-control updates (`confidence::confirmed`) | Endpoint RX/Flow control | `src/quic/conn.zig:693`, `src/quic/conn.zig:929`, `src/quic/conn.zig:942`, `src/quic/endpoint/incoming/module_b2.zig:445` | `zig build test` pass with dirty-stream queue path enabled | https://gitlab.com/devnw/zig/quic/-/issues/79 | Added dirty-stream queue (`pending_fc_streams`) and bounded FC frame emission path | Endpoint maintainers | 2026-02-16 | Closed / Implemented |
| 4 | P1 | 64 | Sleep-based PollSync/accept coordination overhead (`confidence::confirmed`) | Transport API | `src/quic/transport.zig:45`, `src/quic/transport.zig:54`, `src/quic/transport.zig:71` | `zig build test` pass with mutex+condition synchronization | https://gitlab.com/devnw/zig/quic/-/issues/80 | Replaced sleep-spin sync with mutex/condition-variable coordination | Transport maintainers | 2026-02-16 | Closed / Implemented |
| 5 | P2 | 48 | Benchmarks not regression-gated in CI (`confidence::confirmed`) | CI/CD | `.gitlab-ci.yml:388`, `scripts/perf_gate.sh:5`, `scripts/perf_gate.sh:50` | `scripts/perf_gate.sh` PASS locally; parses and enforces thresholds | https://gitlab.com/devnw/zig/quic/-/issues/12 | Added deterministic perf gate script and wired it into `quality-zig-gates` | CI maintainers | 2026-02-16 | Closed / Implemented |
| 6 | P2 | 48 | Rust e2e lacked cache parity (`confidence::confirmed`) | CI/CD | `.gitlab-ci.yml:177`, `.gitlab-ci.yml:180`, `.gitlab-ci.yml:183` | CI config now includes cargo cache paths and lockfile-keyed cache | https://gitlab.com/devnw/zig/quic/-/issues/74 | Added cargo cache + target cache for Rust e2e job | CI maintainers | 2026-02-16 | Closed / Implemented |
| 7 | P2 | 48 | Interop CI recreated stack repeatedly with fixed sleeps (`confidence::confirmed`) | CI/CD Interop | `.gitlab-ci.yml:320`, `.gitlab-ci.yml:334`, `.gitlab-ci.yml:353` | CI script now keeps simulator up once, uses readiness loop, and runs grouped cases | https://gitlab.com/devnw/zig/quic/-/issues/81 | Reworked interop job to reuse simulator lifecycle and remove repeated full down/up cycles | CI + Interop maintainers | 2026-02-16 | Closed / Implemented |
| 8 | P2 | 40 | Non-Linux loop fallback readiness handling (`confidence::confirmed`) | Platform/Infra | `src/quic/endpoint/io.zig:360`, `src/quic/endpoint/io.zig:379`, `src/quic/io/loop_kqueue.zig:71`, `src/quic/io/loop_kqueue.zig:85` | `zig build test` pass after readiness-driven fallback implementation | https://gitlab.com/devnw/zig/quic/-/issues/26 | Replaced sleep fallback in kqueue/non-Windows paths with readiness-driven poll/kevent waits | Platform maintainers | 2026-02-16 | Closed / Implemented |
| 9 | P3 | 32 | Batched UDP recv/send path (`confidence::confirmed`) | App/Transport | `src/quic/endpoint/transport.zig:31`, `src/quic/endpoint/udp_transport.zig:31`, `src/quic/endpoint/udp_transport.zig:205`, `src/quic/endpoint.zig:585`, `bench/udp_batch_bench.zig:1`, `src/quic/endpoint/test_udp_batch_runtime_smoke.zig:1`, `build.zig:770`, `scripts/perf_udp_batch_gate.sh:1`, `scripts/cross_platform_udp_batch_smoke.sh:1`, `scripts/native_runtime_smoke.sh:1`, `scripts/native_runtime_smoke.ps1:1`, `.gitlab-ci.yml:389`, `.gitlab-ci.yml:390`, `.gitlab-ci.yml:392`, `.gitlab-ci.yml:410` | `sudo perf stat` (640000 packets): single mode `sendto=640000`, `recvfrom=640000`; batch mode `sendmmsg=40000`, `recvmmsg=40000`; benchmark syscall/packet `2.0000 -> 0.1250` (16x reduction), pps `215311.74 -> 228844.46`; cross-target compile matrix PASS: macOS/windows (`x86_64`,`aarch64`) for `transport.zig`, `udp_transport.zig`, `endpoint.zig`, and `bench/udp_batch_bench.zig`; runtime smoke test added for non-Linux fallback behavior and wired to SaaS macOS/Windows jobs (variable-gated) | https://gitlab.com/devnw/zig/quic/-/issues/82 | Added Linux `sendmmsg/recvmmsg` backend with transport-level batching API and per-packet fallback; wired endpoint poll to `recvBatch`; added deterministic UDP-batch validation gate, cross-platform compile matrix gate, native runtime smoke test, and SaaS macOS/Windows runtime smoke jobs | Endpoint maintainers | 2026-02-16 | Closed / Implemented |
| 10 | Info | 16 | Missing explicit SLO/workload performance contract (`confidence::confirmed`) | Platform/Infra | `docs/PERFORMANCE_TARGETS.md:1`, `.gitlab-ci.yml:388`, `README.md:92` | Contract doc added and wired to CI perf gate | https://gitlab.com/devnw/zig/quic/-/issues/83 | Added versioned performance target/workload contract and linked it from README | Core + CI maintainers | 2026-02-16 | Closed / Implemented |

## Findings By Area

### area::app

- `#62` Closed / Implemented.
- `#78` Closed / Implemented.
- `#79` Closed / Implemented.
- `#80` Closed / Implemented.
- `#82` Closed / Implemented.

### area::ci

- `#12` Closed / Implemented.
- `#74` Closed / Implemented.
- `#81` Closed / Implemented.

### area::infra

- `#26` Closed / Implemented.
- `#83` Closed / Implemented.

## Delivery Plan Status

### Quick Wins (<= 30 days)

- Completed: `#62`, `#78`, `#79`, `#80`.

### Medium (<= 90 days)

- Completed: `#12`, `#74`, `#81`, `#26`.

### Strategic (> 90 days)

- Completed: `#83`.
- Completed: `#82`.

## Blocked Items

- None.
