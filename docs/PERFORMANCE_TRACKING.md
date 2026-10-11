# Performance Tracking Log

Append-only record of baseline captures, threshold revisions, and
notable regressions / improvements. Every performance-claiming MR must
add an entry to the [Decision Log](#decision-log) below.

Companion documents:

- Targets + absolute gates: [`docs/PERFORMANCE_TARGETS.md`](PERFORMANCE_TARGETS.md)
- Operator manual: [`docs/BENCHMARKS.md`](BENCHMARKS.md)
- Gate script: [`scripts/perf-gate.sh`](../scripts/perf-gate.sh)

## A/B Protocol

The tiered A/B gate runs the same suite twice — once on the parent
commit, once on your change — and compares the two JSON result
documents via `zig build bench-compare` (invoked under
`scripts/perf-gate.sh`). Tier thresholds come from
`docs/PERFORMANCE_TARGETS.md`; absolute gates come from the
`absolute_gates` table in `benchmarks/compare.zig`.

### Step-by-step

1. **Identify the parent commit.** This is `HEAD^` on a linear branch,
   or the merge-base with `main` on a long-lived branch.

2. **Verify or refresh `benchmarks/results/baseline.json`.** If the
   stored baseline predates your parent commit, re-capture on the
   parent before making changes:

   ```bash
   git checkout <parent-sha>
   zig build bench -- --suite=all --output=benchmarks/results/baseline.json
   git checkout <your-branch>
   ```

   Alternatively, run the gate in paired-commit mode, which does the
   checkout in a temp worktree for you:

   ```bash
   scripts/perf-gate.sh --baseline-commit=<parent-sha>
   ```

3. **Apply your change.** Implement, test, `zig fmt`, `zig build test`.

4. **Capture current-HEAD results.**

   ```bash
   zig build bench -- --suite=all --output=/tmp/current.json
   ```

   Narrow the suite if the change is scoped: `--suite=micro`,
   `--suite=integration/poll_overhead`, etc. Micro-only runs are
   acceptable when you only touched a pure-function hot path.

5. **Run the gate.**

   ```bash
   scripts/perf-gate.sh --baseline=benchmarks/results/baseline.json \
                        --current=/tmp/current.json
   ```

   Exit codes:

   - `0` — all PASS (including WARN rows inside noise-floor).
   - `1` — FAIL or ABSOLUTE-FAIL. Do not merge.
   - `2` — environment mismatch (differing zig_version / os / arch /
     cpu) or invocation error. Re-capture on matching hardware, or
     document in the decision log why the hardware changed.
   - `3` — missing dependency (`zig`, `jq`). Fix locally.

6. **On FAIL** — revert, iterate, or reduce scope. Do not land until
   the gate returns PASS.

7. **On ABSOLUTE-FAIL** — never merge. Absolute targets in
   `docs/PERFORMANCE_TARGETS.md` are hard contracts. Revising them
   requires a separate MR that (a) updates the target, (b) adds a
   decision-log entry here explaining why, and (c) re-captures the
   baseline.

8. **On PASS or WARN** — paste the diff table from
   `scripts/perf-gate.sh` output into the MR description, and add a
   dated entry to the [Decision Log](#decision-log) below.

### Paired-commit vs. phased mode

- **Paired-commit** (`--baseline-commit=<sha>`) — the gate script
  creates a temp worktree on `<sha>`, runs the suite there, then runs
  it again on the working tree and compares. Cleanest for MR review.
- **Phased** (`<step-name> before` then `... after`) — for multi-step
  interactive workflows. Writes paired JSON + a markdown diff into
  `benchmarks/results/paired/<step>-{before,after,diff}.{json,md}`.
  Useful when the change is iterative and you want snapshots between
  steps.

## MR Review Checklist

Reviewers of a performance-claiming MR — or any MR touching
`src/quic/`, `src/h3/`, or `benchmarks/` — confirm:

- [ ] The MR body contains the `scripts/perf-gate.sh` diff table
      (copy-pasted, not summarised).
- [ ] All FAIL rows have been addressed — either eliminated by further
      iteration or justified by a new decision-log entry that the
      author links in the MR description.
- [ ] No ABSOLUTE-FAIL row appears anywhere in the output.
- [ ] Absolute gates in `docs/PERFORMANCE_TARGETS.md` were respected
      (same values as `benchmarks/compare.zig`'s `absolute_gates`
      table).
- [ ] If the author refreshed the baseline, the new
      `benchmarks/results/baseline.json` is included in the MR diff
      and the decision-log entry explains why.
- [ ] The decision-log entry names the hardware and Zig version used.
- [ ] Cross-references between `docs/PERFORMANCE_TARGETS.md`,
      `docs/PERFORMANCE_TRACKING.md`, and `docs/BENCHMARKS.md` are
      intact (no broken paths).
- [ ] External-tier rows, if present, are accompanied by a note on
      which toolchains (`go` / `cargo` / `python3`) were available at
      capture time. Rows with `external_impl=<name>-SKIP` are
      expected when a toolchain is absent and do not count as FAIL.

## Decision Log

Newest entries go **above** the placeholder marker. Keep entries short
(six lines or so) and link out to MRs for detail. Date headings use
ISO-8601 `YYYY-MM-DD`.

<!-- New entries go above this line -->

### 2026-04-20 — Initial v2 baseline capture

- **Commit:** `2916974` (parent of baseline commit; baseline JSON
  captured on top of this)
- **Hardware:** host `haleth`, Intel Xeon E5-2680 v4 @ 2.40GHz,
  251 GiB RAM, Linux 6.12.74+deb13+1-amd64 (Debian 13)
- **Zig version:** 0.16.0
- **Suite:** `--suite=all` (64 ResultRow rows across 18 scenario names:
  8 micro + 7 integration + 3 external)
- **Summary:** First capture on the consolidated v2 benchmark suite.
  Establishes the reference point for all subsequent A/B comparisons.
  Replaces the retired v1 `bench/` tree and its ad-hoc `perf_gate.sh`
  / `perf_udp_batch_gate.sh` scripts (absorbed into
  `scripts/perf-gate.sh` + `benchmarks/compare.zig`).
- **Notable baseline numbers** (full per-variant matrix in
  `benchmarks/results/baseline.json`):
  - `micro/varint encode` p99=2ns (absolute gate ≤250ns — large margin)
  - `micro/pacing delay_compute` p99=1ns (gate ≤400ns)
  - `micro/header_protection decode` p99=1.2µs (gate ≤400µs)
  - `micro/frame_serialization short_header_encode/decode` alloc_bytes=0 (hard gate)
  - `micro/connection_lookup` p99: 152ns → 731ns → 15.6µs → 152µs
    (10 → 10K conns; O(N) scan signature for #154)
  - `micro/loss_detection_scan` p99: 2µs → 284µs → 589µs → 4.05ms
    (100 → 100K entries; O(N) scan signature for #90)
  - `integration/poll_overhead 100c` p99=8µs; `10Kc` p99=674µs (#182 target)
  - `integration/conn_scale 1c` setup-throughput normalized (doc note)
  - `integration/handshake_e2e serial` p50=2.5ms, `10Kp` p50=1.03s
  - `integration/stream_throughput 1KB-c1` 5.5K ops/s, `1KB-c10` 7.2K ops/s
  - `integration/datagram_batch` batch_64/batch_1 p99 ratio ≈3× (#126 signal)
  - `integration/flush_cadence burst_flush` p50=130ms, `small_writes_1_stream`
    p50=133µs — burst/single per-write ratio ≈9.85× (geode target: ≤1.5×)
  - `integration/udp_batch batch/single` throughput ratio 1.57× (preserves
    ≥0.95× absolute gate; syscall-reduction ratio check in `perf-gate.sh`)
- **External tier:** initial capture landed all 3 scenarios as SKIP
  (`external_impl=<impl>-SKIP`) despite toolchains being available —
  root cause: handshake_e2e 10Kp exhausted the process's FD limit,
  breaking subsequent `which go`/`which cargo`/`which python3`
  subprocess spawns. Fixed in commit `464adca` (toolchain-availability
  cache prewarmed at bench_runner entry, before FD pressure builds).
- **Harness metadata gaps (initial capture):** `quic_git_sha`,
  `hostname`, `kernel` fields in 17/64 rows + document-level landed
  as `"unknown"` — same FD-exhaustion root cause. Fixed in commit
  `577dfe8` (env-metadata cache prewarmed at bench_runner entry).
- **Re-capture on commit `9cbf3ac`** (2026-04-20, ~21 min runtime):
  0 unknown rows, 0 SKIP rows, all 3 external impls produced real
  numbers. External-tier p50 numbers captured AFTER integration
  tier saturates FDs/CPU (quic-go 1285ms, quinn 1298ms, aioquic
  1533ms) — ~10× slower than isolated-tier runs (109/103/335ms).
  This is honest full-suite measurement with accumulated resource
  pressure, not a fluke. Isolated-tier A/B against these numbers
  will compare apples-to-apples. Integration-tier values remained
  within ±5% of the initial capture (normal sample variance).

### 2026-04-27 — Multi-issue perf unblock pass + baseline refresh

- **Scope.** Closure pass for the 11 perf-gated GitLab issues that
  were *Blocked* in `docs/PERF_GAP_ANALYSIS.md`: `#109`, `#126`,
  `#129`, `#154`, `#158`, `#160`, `#165`, `#167`, `#172`, `#182`,
  `#183`. Each one now has substantive in-repo implementation; the
  multi-platform CI matrix follow-up for `#172` remains the only
  external dependency (documented in `docs/PLATFORM_SUPPORT.md`).
- **A/B mode.** `--suite=micro` paired against HEAD baseline captured
  before the unblock pass (commit `04fd9f5`). Full integration-tier
  paired runs not exercised this pass — the gating-skill rule
  permits `--suite=micro` for hot-path micro-changes. The integration
  benchmarks run as part of routine CI; reviewers should rerun
  `--suite=integration` against the refreshed baseline before merging
  any subsequent perf change in this region.
- **Notable changes vs. pre-pass HEAD baseline:**
  - **Throughput:** stable across the matrix; most variants ±5%
    (within sample variance). No absolute-gate breach.
  - **`micro/varint encode` p99=1ns** (was 2ns) — within noise,
    well under the 250 ns absolute gate.
  - **`micro/pacing delay_compute` p99≈0–1ns** — sub-ms residual
    deadline is now stored in `Timer.deadline_ns_extra` and checked
    via `timerExpired()` (`#158` closure). The hot path is unchanged
    when no pacing is active (zero overhead for non-paced sends).
  - **`micro/connection_lookup`** 10/100/1K/10K p99: 142 / 184 / 177
    / 443 ns. The 8-byte DCID fast path (`#154` closure) skips the
    candidate-length sweep when matching; second-pass tweak ensures
    we don't repeat the same lookup in the sweep when fast path
    already covered it.
  - **`micro/loss_detection_scan` 10K p99=242µs** (was 209µs).
    +33µs is consistent with the 4 atomic stores per ACK that
    `Recovery.refreshAtomicMirrors` adds (`#160` closure). Total
    per-ACK overhead is ~3-5 ns × 4 stores ≈ 20 ns × 10000 ACKs
    ≈ 200µs. This is the cost of the lock-free reader path; the
    pacing-loop benefit (no longer contending on `recovery.mutex`)
    dominates in real workloads and is exercised by the
    `integration/datagram_batch concurrent_independent_progress`
    variant added for `#126`.
  - **`micro/frame_serialization short_header_encode/decode`
    alloc_count=0** — absolute gate still passes.
- **Baseline refresh.** `benchmarks/results/baseline.json` updated
  from the pre-pass capture (commit `4fda623`) to the post-pass
  capture (this commit). Future MRs running `--suite=micro` will
  A/B against the new baseline.
- **Outstanding work tracked under follow-ups, not new gaps:**
  - `#129` connection-pool reuse (slab/freelist of recycled
    `Connection` structs) deferred — bounded enforcement is in
    place via `cfg.max_connections` check at registration.
  - `#167` shared-slab buffer pool deferred — per-connection pool
    size reduced 16 → 4 slots (4× memory reduction; 64 KB → 16 KB
    per conn) which captures the immediate win.
  - `#165`/`#183` paced-send `sendBatch` flush integrates
    `sendmmsg` for the timer-fired flush; non-paced (immediate)
    sends still call per-packet `sendTo` and stay deferred for a
    future steady-state-batching pass.
  - `#109` cross-stream coalescing (multiple STREAM frames from
    different streams in one packet) deferred — within-packet
    ACK+STREAM coalescing has always existed; GSO-style multi-
    packet batching is now provided by the paced flush above.

### 2026-05-29 — Rejected server short-header cadence experiments

- `da08ef4` capped server short-header app receive to one UDP batch and was
  reverted by `9a35274` after it regressed Geode's 1024 x 8 sustained workload
  and 4096-client setup reliability.
- `c2874fb`/`76b45ec` tried a short-header wall-clock yield. The first variant
  regressed setup retries by shrinking receive slices; the repaired full-batch
  variant still regressed Geode's accepted 4096 single-op gate to 3053/4096
  first-response timeouts. The follow-up revert restores the proven
  `a68d36e`/`9a35274` behavior.

### 2026-10-11 — SONNY-4788: verified external benchmark results

The external harness now requires every configured warmup and measured client
invocation to succeed. Whole-process deadlines include waiting after pipe EOF;
failures, output overruns, missing clients, failed builds and failed server
startup invalidate the run. Missing toolchains and unsupported platforms retain
explicit skip rows. Go, Quinn and aioquic verify a separate test CA and server
leaf, reject empty responses, and cannot count an unrelated stream as the reply.

A full unchanged-parent capture at `56c0b977b4e861fad775b0cfff04a3cf98f8ba8f`
completed before implementation (76 rows, 2434.655s). The candidate external
capture completed on the same Linux host and CPU affinity 8–11 (161.500s,
including compilation). Source files, fixtures and client binaries were
fingerprinted and unchanged during the candidate run. All three rows contain
20 successful measured iterations, with no skipped implementation. Each scenario
ran seven times with two successful warmups before each set of 20 measurements.

The existing manual performance gate returned **0 FAIL, 0 WARN**:

| Implementation | Parent ops/s | Candidate ops/s | Parent p95 ns | Candidate p95 ns | Gate |
|---|---:|---:|---:|---:|---|
| quic-go | 1.066 | 148.532 | 10000000000 | 7876352 | PASS |
| Quinn | 7.399 | 11.071 | 142360168 | 96071040 | PASS |
| aioquic | 0.049 | 2.220 | 15000000000 | 457552894 | PASS |

**Interpretation:** the parent fabricated one successful iteration for failed Go
and aioquic exchanges and assigned timeout sentinel latencies; its Quinn client
bypassed certificate and handshake-signature verification. Those rows are not
valid speed comparisons. No performance improvement is claimed across these
behaviors. Acceptance additionally requires the real authenticated exchanges,
14 subprocess regressions, seven trust/response cases per client, Go race tests,
and three real certificate-generation regressions. Integration fixtures remain
separate and unchanged.

The first candidate correctly rejected a CA used as a server leaf. The repaired
fixture uses a distinct CA and `CA:FALSE` server certificate; no certificate or
signature check was bypassed to pass the gate. Existing gate thresholds and
failure policies are unchanged, and Go trust regressions are a new required CI
job independent of the existing advisory Go CLI interoperability job.

Evidence identifiers: parent `4788-baseline-full-275.json` (SHA-256
`6b2396c0f8ba7e11b1d7fea3d849a87eda58c50f2a5ad279c69f77c04a1ad387`),
candidate `4788-candidate-external-345.json` (SHA-256
`5c4986c995c822bc3287c5c29037552a769926d9090a758181ec3dcb678e93c1`),
and gate `4788-perf-gate-346.log`. Both captures are retained with the review's
source fingerprints; the candidate was an uncommitted tree on the parent SHA.

### 2026-10-11 — SONNY-4788: POSIX missing-tool probe correction

The command probe now recognizes both exit 1 and exit 127 as an absent optional
tool. The tool name remains a quoted positional argument; process launch,
timeout, signal and unexpected exit failures still invalidate the benchmark.
Two production-probe regressions cover present/missing tools, literal shell
metacharacters and invalid probe options. The full suite passes 165 tests with
three existing skips. With an empty toolchain PATH, the parent executable fails
with `ToolchainProbeFailed`; the candidate lists scenarios and runs the micro
suite successfully.

The full baseline at exact parent `884aa9dd1e03a37220f446247a4b7e35745b08ea`
was verified unchanged. A new same-session parent/candidate capture on the same
Linux host and CPU affinity 8–11 covered all 35 micro rows and all three external
clients. Source files, fixtures and client binaries stayed unchanged. Every
external row contains 20 successful measured exchanges across seven repeats.

| Client | Parent ops/s | Candidate ops/s | Parent p95 ns | Candidate p95 ns | Gate |
|---|---:|---:|---:|---:|---|
| quic-go | 152.320 | 155.836 | 7117380 | 7439795 | PASS |
| Quinn | 10.965 | 11.007 | 95113656 | 94643679 | PASS |
| aioquic | 2.240 | 2.235 | 456279820 | 453514153 | PASS |

The external gate passed with **0 FAIL, 0 WARN**. The micro gate reported
**12 FAIL, 1 WARN**, including frame serialization, connection lookup and send
buffer p95 regressions. Overall performance qualification remains **FAILED**;
these results do not authorize merging the correction. No thresholds were
changed and no speedup is claimed. Investigate measurement correctness and
comparable runtime behavior before repeating qualification.

Evidence: `4788-probe-qualification-590.json`; parent/candidate micro hashes
`72e3284b8a81a408a512a67471936e193693e368158c2812b988740953a9200c` /
`311cb0c6ef59e798f212d5d9913240f98c3a3ade41d845fec11e0848d7d96428`;
parent/candidate external hashes
`941da9e06668f09edc240943a6a4eea2a2a7e987e11460ca631d1afae9b3f278` /
`68f475cc0d048f6f901ef7a4a4d621e6fcc99b88030f333b58f544f6d41ee604`.

</content>
