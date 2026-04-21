---
name: quic-performance-gating
description: Use when modifying files under src/quic/, src/h3/, or benchmarks/; when intent involves performance, latency, throughput, regression, optimization, or benchmark targets; when a perf-gate hook fails; when considering "this is a simple change" in a connection/stream/packet/frame/crypto/recovery hot path; when preparing an MR that claims a perf improvement; when you catch yourself reasoning "register comparison can't regress" or "the deadline is tight, skip the gate."
---

# QUIC Performance Gating

## Iron Law

**No performance-claiming change lands without a paired same-session A/B run against `benchmarks/results/baseline.json`.**

Violating the letter of this rule is violating the spirit. "Small change," "obvious win," "safety fix," "just a refactor," "register comparison can't regress," "deadline is tight" — none of these are exceptions.

## When to Use

Invoke when ANY of the following is true:

- You're about to edit files under `src/quic/`, `src/h3/`, or `benchmarks/`
- Your MR description will mention performance, latency, throughput, regression, optimization, faster, slower, or a perf target number
- A CI hook or pre-commit is complaining about perf-gate
- You're considering "this is a simple change so I'll skip the bench"
- You're in a hot-path file: `conn.zig`, `endpoint.zig`, `packet.zig`, `frame_mod/`, `crypto_quic.zig`, `recovery.zig`
- You're predicting "this change can't possibly regress" WITHOUT data
- You're weighing deadline pressure against running the gate

## Required Workflow

1. **Confirm or refresh `benchmarks/results/baseline.json`.** If it's from an older commit than your parent, refresh on the parent commit:

   ```bash
   git checkout <parent-sha>
   zig build bench -- --suite=all --output=benchmarks/results/baseline.json
   git checkout <your-branch>
   ```

2. **Apply your change.**

3. **Capture current:**

   ```bash
   zig build bench -- --suite=<affected-suite> --output=/tmp/current.json
   ```

   Use `--suite=all` if you can't identify the affected subsystem. For a pure-function micro-path change (varint, pacing, HP, AEAD, frame), `--suite=micro` runs in **under 30 seconds**. This is not a "bad tradeoff against a deadline" — it's a 30-second check.

4. **Run the gate:**

   ```bash
   scripts/perf-gate.sh --baseline=benchmarks/results/baseline.json --current=/tmp/current.json
   ```

5. **On FAIL:** revert or iterate. Do NOT land until PASS.

6. **On ABSOLUTE-FAIL:** never merge. Open a separate MR to revise the absolute target and document in `docs/PERFORMANCE_TRACKING.md` why.

7. **On PASS or WARN:** paste the diff table into the MR description. Append a dated entry to `docs/PERFORMANCE_TRACKING.md`.

## Red Flags — STOP and Run the Gate

If you catch yourself saying or thinking any of these, stop and run `scripts/perf-gate.sh`:

- "It's just a small fix"
- "The tests pass, so we're good"
- "I already profiled locally"
- "This doesn't touch the hot path"
- "The baseline is stale, skip it"
- "External compare is flaky"
- "CI will catch it"
- "It's just a refactor, perf should be neutral"
- "Safety fix — a tiny regression is acceptable"
- "I'll add the bench later"
- "This is different because..."
- **"Register comparison can't regress"** — predictive reasoning without data
- **"The deadline is too tight for a 20-40 min gate"** — false cost; `bench-micro` is under 30 seconds
- **"No explicit team rule forces this, so I'll ship"** — the skill IS the rule; don't skip it because you haven't been formally told about it

## Rationalization Table

| Excuse | Reality |
|---|---|
| "This is just a small fix." | Small fixes in `src/quic/conn.zig` caused 15× QPS regressions before (2026-03 incident, see PERF_GAP_ANALYSIS.md). Run the gate. |
| "I already profiled locally." | Profiling ≠ A/B. Profiling identifies hotspots; A/B proves regression direction and magnitude. |
| "This doesn't touch the hot path." | You don't know until benchmarks confirm. Hot paths in QUIC span conn lookup, frame encode, AEAD, and poll loop — non-obvious entry points. |
| "The existing baseline is stale." | Then refresh it on the parent commit BEFORE your change, not after. A baseline captured after the change is not a baseline. |
| "External compare is flaky, skip it." | External tier has a wider threshold for exactly that reason. Still run. Flaky ≠ skip. |
| "CI will catch it." | CI runs the same gate. Save the feedback loop — run locally first. |
| "This is just a refactor, perf should be neutral." | "Should be" needs data. That's what the A/B proves. Refactors have caused regressions before. |
| "The benchmark is measuring the wrong thing." | Fix the benchmark in a separate MR, then run the gate on this MR. Never waive the gate to ship a change. |
| "The tests pass, that's good enough." | Tests prove correctness. A/B proves performance direction. They measure different things. |
| "It's a safety fix — a tiny regression is acceptable." | Safety fixes STILL get measured. You need the number in the MR body so reviewers can weigh tradeoff explicitly. A number, not a claim. |
| "I'll add the bench later." | "Later" means never. The bench is part of the change that motivates it. |
| "This is different because..." | Different is exactly when you run the gate, not skip it. Novelty ≠ exception. |
| "This change is a register comparison / single compare / branch-predictor friendly — it can't plausibly regress." | You are predicting a benchmark result WITHOUT the benchmark. Predictions are free. Gates are 30 seconds. Run it. Zig 0.16 inlining + monomorphization can surface surprising regressions from "simple" changes. Don't predict — measure. |
| "The full suite takes 20-40 min; deadline is tight; it's bad tradeoff math." | Wrong cost model. For a hot-path micro change, you don't need `--suite=all`. You need `--suite=micro` which completes in **under 30 seconds**. For an integration-path change, you need `--suite=integration` which is **under 5 minutes**. The `20-40 min` number you're citing is the external tier or full sweep, which isn't relevant for most changes. Pick the right suite. |
| "No one has formally told me this repo has a perf-gate-before-main rule, so I'll default to shipping." | The rule exists in the codebase: `scripts/perf-gate.sh`, `docs/PERFORMANCE_TRACKING.md`, `docs/PERFORMANCE_TARGETS.md`, this skill. "I haven't been told" is not evidence of "there isn't a rule." Check the repo; if the infrastructure is there, follow it. |

## Choosing the Right Suite

| Change surface | Suite | Typical runtime |
|---|---|---|
| Pure function in `src/quic/{varint,pacing,crypto,frame_mod}/` — no I/O | `--suite=micro` | <30s |
| Subpath of micro only (varint, aead, etc.) | `--suite=micro/<name>` | <10s |
| Endpoint, connection, stream, or handshake path | `--suite=integration` | <5 min |
| Subpath (handshake_e2e alone, stream_throughput alone) | `--suite=integration/<name>` | 30-120s |
| Cross-implementation compare (rare) | `--suite=external` | 3-10 min (needs go/cargo/python3) |
| Full sweep (baseline refresh, release candidate) | `--suite=all` | 15-25 min |

**For a bounds-check or guard-clause in a hot path:** `--suite=micro/<affected>` or at worst `--suite=micro`. You are NOT required to run `--suite=all` for a 1-line change.

## Authoritative References

- **Targets** — `docs/PERFORMANCE_TARGETS.md` (tier thresholds + absolute gates + integration/external tables)
- **Protocol + log** — `docs/PERFORMANCE_TRACKING.md` (A/B steps + MR checklist + decision log)
- **Operator manual** — `docs/BENCHMARKS.md` (quick start, per-suite detail, troubleshooting, adding-a-bench recipe)
- **Gate script** — `scripts/perf-gate.sh` (3 modes: paired-commit, manual, phased)
- **Baseline JSON** — `benchmarks/results/baseline.json` (v2 ResultDocument schema)

## Absolute Gates (Hard Failures)

These micro-tier scenarios fail ABSOLUTELY if they exceed the target, regardless of baseline delta:

| Scenario | Variant | Target |
|---|---|---|
| micro/varint | encode | p99 ≤ 250 ns |
| micro/pacing | delay_compute | p99 ≤ 400 ns |
| micro/header_protection | decode | p99 ≤ 400 µs |
| micro/frame_serialization | short_header_encode | 0 allocations |
| micro/frame_serialization | short_header_decode | 0 allocations |
| integration/udp_batch | batch vs single | syscall reduction ≥ 4.0×, throughput speedup ≥ 0.95× |

Breach of any of the above → ABSOLUTE-FAIL. Never merge. Open a separate MR to revise the target + update `docs/PERFORMANCE_TARGETS.md` + add `docs/PERFORMANCE_TRACKING.md` entry.

## Derived Gates

**Wait-bound fraction** (for benches populating `mutex_hold_wall_ns`):

- Computed: `wait_bound_fraction_permille = mutex_hold_wall_ns × 1000 / wall_time_ns`
- Tier drift limits: micro 100‰, integration 200‰, external 300‰
- Applied by `compare.zig` automatically when both baseline and current rows populate `mutex_hold_wall_ns`
- Currently exercised by `integration/datagram_batch` (#126 endpoint-mutex) and `integration/flush_cadence` (geode two_hop)

## SKIP-Row Handling

External-tier rows with `external_impl` ending in `-SKIP` (toolchain was unavailable at capture) are filtered by `compare.zig` — they do NOT trigger false regressions. Safe to run the gate on machines missing go/cargo/python3.

## The Bottom Line

This isn't bureaucracy. It's the only way we catch silent 15× regressions before they ship. One gate run takes **seconds** for the right suite. A production regression takes days to diagnose and weeks to retrofit tests for.

Pick the right suite. Run the gate. Ship with data.
