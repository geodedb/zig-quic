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

### 2026-04-20 — Initial v2 baseline capture (placeholder — populated in Phase 10)

- **Commit:** *filled in at Task 10.2*
- **Hardware:** *filled in at Task 10.2 (host, CPU model, RAM, kernel
  version)*
- **Zig version:** 0.16.0
- **Summary:** First capture on the consolidated v2 benchmark suite
  (8 micro + 7 integration + 3 external scenarios). Establishes the
  reference point for all subsequent A/B comparisons. Replaces the
  retired v1 `bench/` tree and its ad-hoc `perf_gate.sh` /
  `perf_udp_batch_gate.sh` scripts (absorbed into
  `scripts/perf-gate.sh` + `benchmarks/compare.zig`).
- **Notes:** Integration-tier targets in
  `docs/PERFORMANCE_TARGETS.md` are populated from this capture when
  Task 10.2 runs. External-tier capture is deferred if the required
  toolchains (`go` / `cargo` / `python3` + `aioquic`) are not
  available at capture time — skipped rows land with
  `external_impl=<name>-SKIP` and are listed here. Phase 10 Task 10.2
  fills in the commit SHA, hardware inventory, and the final
  per-variant numbers for the Integration Tier Targets table.
</content>
