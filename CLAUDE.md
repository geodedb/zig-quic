# CLAUDE.md

This repository is **zig-quic**, a QUIC (RFC 9000) + HTTP/3 implementation in Zig.

Zig version: **0.16.0** (pinned in `build.zig.zon`).

## Quick Commands

```bash
zig build                       # build libraries + binaries
zig build test                  # run test suite
zig build bench                 # run benchmark suite (primary)
zig build bench -- --list       # list all scenarios
zig build bench-micro           # micro tier only (<30s)
zig build bench-integration     # integration tier only (<5min)
zig build bench-external        # external tier (needs go/cargo/python3+aioquic)
scripts/perf-gate.sh --help     # regression gate (3 modes: paired-commit / manual / phased)
```

## Performance Work Protocol

**This repo gates performance claims behind a paired A/B run.**

If you change code in `src/quic/`, `src/h3/`, or `benchmarks/`, or if your MR claims any performance benefit, you MUST follow `.claude/skills/quic-performance-gating/SKILL.md` and run `scripts/perf-gate.sh` before requesting review.

Authoritative references:

- **Skill (enforcement)** — `.claude/skills/quic-performance-gating/SKILL.md`
- **Targets** — `docs/PERFORMANCE_TARGETS.md` (tier thresholds + absolute gates + integration/external tables)
- **Protocol + log** — `docs/PERFORMANCE_TRACKING.md` (A/B protocol + MR checklist + dated decision log)
- **Operator manual** — `docs/BENCHMARKS.md` (quick start, per-suite detail, troubleshooting, adding-a-bench recipe)
- **Gate script** — `scripts/perf-gate.sh`

**Pick the right suite.** `--suite=micro` for pure-function changes (<30s). `--suite=integration` for endpoint/connection/stream/handshake paths (<5min). `--suite=all` only for baseline refresh or release candidates.

## Repository Layout

- `src/quic/` — QUIC protocol implementation (connection, packet, frame, crypto, recovery, endpoint)
- `src/h3/` — HTTP/3 on top of QUIC
- `lib.zig`, `quic.zig` — public API roots
- `benchmarks/` — v2 performance benchmark suite
  - `common.zig` — shared harness (ScenarioSpec, ResultRow, runRepeated)
  - `compare.zig` — tier-aware regression comparator
  - `bench_runner.zig` — suite dispatcher
  - `micro/` — 8 micro-benchmarks (varint, pacing, hp, aead, tls_keygen, frame_serialization, connection_lookup, loss_detection_scan)
  - `integration/` — 7 integration benchmarks (poll_overhead, conn_scale, udp_batch, handshake_e2e, stream_throughput, datagram_batch, flush_cadence)
  - `external/` — cross-impl compare wrapping test-clients/ (quic-go, quinn, aioquic)
  - `results/baseline.json` — v2 schema baseline (captured fresh per Phase 10)
- `scripts/perf-gate.sh` — unified tiered A/B gate
- `test-clients/` — external QUIC implementations for interop + external compare
- `interop/` — Dockerized interop test harness
- `tests/` — test suite (unit + integration)
- `cmd/` — executable binaries (quic-server, quic-client, quic-client-comprehensive)
- `docs/` — architecture, design, targets, tracking, benchmarks, gap analyses
- `specs/` — RFC references (aead, tls, x509, quic)

## Known Pre-existing Issues

See `docs/superpowers/plans/2026-04-20-perf-bench-suite-and-gating.md` → "Known Pre-existing Issues" for tracked items that pre-date the v2 benchmark work:

1. `tests/test_transport_geode_compat.zig:246` — CA cert runtime assertion (pre-existing functional bug; blocks pre-push test hook — use `--no-verify` with explicit authorization when needed)
2. `api.getPort(ep)` uses `posix.getsockname` removed in Zig 0.16 — bench sidesteps via atomic port counter; production callers need the fix
3. No lightweight `make interop_local` target (existing targets chain through docker)

## Further Reading

- `README.md` — user-facing project overview
- `CONTRIBUTING.md` — contribution guidelines
- `docs/ARCHITECTURE.md` — design overview
- `docs/PERF_GAP_ANALYSIS.md` — open P0/P1 perf findings (14 items)
- `docs/superpowers/plans/2026-04-20-perf-bench-suite-and-gating.md` — v2 benchmark suite + gating plan
- `docs/superpowers/specs/2026-04-20-perf-bench-suite-and-gating-design.md` — corresponding design spec
