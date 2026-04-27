# Gap Analysis

Last updated: 2026-04-27

Status note (2026-04-27): this file intentionally contains open repository-level gaps only. Closed items are moved to `docs/GAP_ANALYSIS_RESOLVED.md`; *Partial* and *Planning* items remain here with the new status. GitLab issues are the authoritative status records; this file is the flatfile mirror for humans and agents. The 2026-04-26 status changes were written back to GitLab on 2026-04-27 (status comments posted to #88, #115, #142, #177; #170 closed with closure note).

## Summary

- Remaining open repository gaps: 5. Three moved from Blocked to Partial / Planning in the 2026-04-26 closure pass (GAP-0013, GAP-0004, GAP-0060); the two endpoint performance items (GAP-0053, GAP-0054) remain Blocked on benchmark-backed design.
- Status changes during this pass:
  - GAP-0013 / #142: Blocked -> **Partial**. New `tests/test_key_update_lifecycle.zig` (5 RFC 9001 §5.4 / §6 / §6.6 tests) wired in `build.zig:1832-1838` and cross-referenced from `tests/integration/key_update.zig:110, 116, 301`. Remaining 49 advanced-crypto integration skips tracked in `docs/SKIPPED_TEST_INVENTORY.md`.
  - GAP-0004 / #88: Blocked -> **Partial**. Per-scenario triage complete in `docs/SKIPPED_TEST_INVENTORY.md` (30 files, 5 categories, linked GAPs/issues, top-5 follow-up actions). Remaining work is per-category remediation MRs.
  - GAP-0060 / #177: Blocked / Deferred -> **Planning**. Staged refactor plan landed at `docs/superpowers/plans/2026-04-26-method-module-refactor.md` (5 stages, real `wc -l` inventory, perf-gate skill referenced). Execution gated by per-stage perf-gate runs.
- Previous closures retained: GAP-0007 (crypto audit evidence completed), GAP-0055 (Retry-before-allocation implemented and tested).
- Supporting docs: `docs/CRYPTO_AUDIT.md`, `docs/SKIPPED_TEST_INVENTORY.md`, `docs/superpowers/plans/2026-04-26-method-module-refactor.md`.
- Scanner/report notes remain in `docs/SECURITY_REVIEW_NOTES.md`; raw scan reports are in `/tmp` and intentionally not committed.

Top risks:
- Crypto lifecycle in-repo executable coverage now lands via `tests/test_key_update_lifecycle.zig`, but full advanced-crypto integration coverage (49 skips across `key_update.zig` and `rfc9001_advanced.zig`) remains open under GAP-0013 / #142. Full interop itself is clean: `make interop-full` passed `105`, failed `0`, skipped `50` implementation/harness-unsupported cases.
- Broad skipped integration-test coverage is now per-scenario triaged but still requires per-category remediation MRs: GAP-0004 / #88.
- Endpoint-level receive contention proof and connection allocation pooling remain blocked on benchmark-backed design: GAP-0053 / #126 and GAP-0054 / #129.
- Method-module architecture is now in *Planning*; execution gated by per-stage perf-gate runs: GAP-0060 / #177.

## Stack-Ranked Findings

| Rank | Sev | Risk | Finding | Component | CWE/OWASP | Evidence(file:line) | Issue URL | Fix | Owner | Due | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | High | 64 | Full crypto hardening pass needed | crypto / TLS | CWE-327 / OWASP A02 | `tests/test_key_update_lifecycle.zig` (5 RFC 9001 vectors); `build.zig:1832-1838`; `tests/integration/key_update.zig:110, 116, 301`; remaining: `tests/integration/key_update.zig` (52 skips) and `tests/integration/rfc9001_advanced.zig` (27 skips) | https://gitlab.com/devnw/zig/quic/-/issues/142 | Finish remaining advanced-crypto integration skips and AEAD vectors | Unassigned | 2026-05-26 | Partial: in-repo executable coverage added in `tests/test_key_update_lifecycle.zig`; remaining 49 advanced-crypto integration skips tracked in `docs/SKIPPED_TEST_INVENTORY.md` (rows for `key_update.zig`, `rfc9001_advanced.zig`) |
| 2 | Medium | 48 | 529 test stubs return SkipZigTest | tests | Requirement coverage | `docs/SKIPPED_TEST_INVENTORY.md` per-file triage table (30 files, 5 categories, top-5 follow-ups); skip inventory command returned `529` | https://gitlab.com/devnw/zig/quic/-/issues/88 | Land per-category remediation MRs (stale-rationale unskips first, then impl-required) | Unassigned | Needs per-category remediation | Partial: per-scenario triage complete in `docs/SKIPPED_TEST_INVENTORY.md` (30 files, 5 categories, linked to GAPs); remaining work is per-category remediation MRs (top 5 follow-ups documented) |
| 3 | Medium | 40 | Endpoint receive lock proof incomplete | endpoint | Performance / contention | `src/quic/endpoint.zig:848-856` releases endpoint mutex between datagrams; no concurrency benchmark committed | https://gitlab.com/devnw/zig/quic/-/issues/126 | Add concurrent receive benchmark and prove no cross-connection regression | Endpoint | Medium | Blocked: implementation is partial; validation is missing |
| 4 | Medium | 40 | Connection allocations are not pooled | endpoint / server | Performance / allocation | `src/quic/endpoint/server.zig:326-328`; `src/quic/endpoint/server.zig:397-414`; `src/quic/config.zig:58-60` | https://gitlab.com/devnw/zig/quic/-/issues/129 | Add bounded connection/TLS-context pool | Endpoint | Medium | Blocked: requires allocator profile and pool design |
| 5 | Medium | 36 | Non-domain method module naming obscures ownership | transport architecture | Maintainability | `docs/superpowers/plans/2026-04-26-method-module-refactor.md` (5-stage plan, real `wc -l` inventory, perf-gate skill referenced 5x); `src/quic/conn.zig` still forwards broad `methods_a/b/c` API; `src/quic/connection/key_update.zig:1-14` is the sole domain extraction so far | https://gitlab.com/devnw/zig/quic/-/issues/177 | Execute the staged plan with per-stage perf-gate runs | Core QUIC | Strategic | Planning: staged refactor plan landed at `docs/superpowers/plans/2026-04-26-method-module-refactor.md`; execution gated by per-stage perf-gate runs |

## Findings By Area

- **Core QUIC security:** GAP-0013 moves to *Partial*. The 2026-04-26 pass added in-repo executable coverage at `tests/test_key_update_lifecycle.zig` (5 RFC 9001 §5.4 / §6 / §6.6 tests, wired in `build.zig:1832-1838` and cross-referenced from `tests/integration/key_update.zig:110, 116, 301`). Full closure requires the remaining 49 advanced-crypto integration skips in `key_update.zig` and `rfc9001_advanced.zig` to be unskipped against existing production primitives. GAP-0007 was closed in a prior pass with `docs/CRYPTO_AUDIT.md`, fallible Retry/key-update derivation, and `rg` evidence showing no crypto `catch unreachable` sites in active QUIC crypto paths.
- **Test coverage:** GAP-0004 moves to *Partial*. The original "requires per-scenario triage" blocker is resolved -- `docs/SKIPPED_TEST_INVENTORY.md` now contains a 30-file triage table with 5 categories (stale-rationale, impl-required, harness-unsupported, cipher-availability, out-of-scope), linked GAPs/issues, and a top-5 follow-up action list. Remaining work is per-category remediation MRs; the skip count itself is still 529.
- **Performance:** GAP-0053 is *Closed* (2026-04-27) — concurrent-receive bench variant added. GAP-0054 is *Partial* — bounded enforcement landed; pool reuse design deferred. Eight perf-gated GitLab issues moved from Blocked to Closed/Partial in the 2026-04-27 unblock pass; see `docs/PERF_GAP_ANALYSIS.md` for the full table.
- **Architecture:** GAP-0060 moves to *Planning*. The 5-stage refactor plan at `docs/superpowers/plans/2026-04-26-method-module-refactor.md` is the closure work for the prior "needs a staged refactor plan" blocker; execution remains gated by per-stage perf-gate runs.
- **Supply-chain/tooling review:** 2026-04-26 security/delivery findings were closed in prior passes and moved to `docs/GAP_ANALYSIS_RESOLVED.md`.

## Remediation Horizon

- **Quick wins:** the per-category remediation MRs identified in `docs/SKIPPED_TEST_INVENTORY.md` -> *Top 5 Highest-Value Follow-Up Actions* (e.g. the `flow_control.zig` 58-skip unskip MR and the `rfc9000_advanced.zig` 16-skip unskip MR) touch zero production code and immediately convert ~150 stale-rationale skips into real assertions.
- **Medium:** complete the GAP-0013 advanced-crypto integration unskips against `tests/test_key_update_lifecycle.zig` evidence; benchmark endpoint receive/allocation fixes (GAP-0053/GAP-0054).
- **Strategic:** execute the staged method-module refactor under `docs/superpowers/plans/2026-04-26-method-module-refactor.md` (#177/#115) with per-stage perf-gate runs.

## Gaps

### GAP-0004: 529 test stubs return SkipZigTest
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/88
- **Category:** Test
- **Severity:** Medium
- **Requirement source:** GitLab issues #5, #7, #24, #27, #30, #31; prior `docs/requirements.md` test coverage claims.
- **Current state (evidence):**
  - `docs/SKIPPED_TEST_INVENTORY.md` now contains a 30-file per-file triage table with 5 categories (stale-rationale, impl-required, harness-unsupported, cipher-availability, out-of-scope), an Owner column, linked GAPs/issues, and a recommendation column.
  - `## Triage Summary` and `### Top 5 Highest-Value Follow-Up Actions` document per-category remediation order: ~150 stale-rationale skips first (largest blocks: `flow_control.zig` 58, `key_update.zig` 52, `rfc9000_advanced.zig` 16); ~290 impl-required skips kept with linked GAPs; 40-skip `interop/interop.zig` reclassified as harness-unsupported.
  - `rg --hidden --glob '!.git/**' --glob '!.claude/worktrees/**' --glob '*.zig' -n 'return error\.SkipZigTest' tests src | wc -l` - `529` (unchanged in this pass; 2026-04-26 was a documentation-only triage pass).
  - Highest-count files: `tests/integration/zero_rtt.zig` - 62 skips; `tests/integration/flow_control.zig` - 58 skips; `tests/integration/fault/fault.zig` - 56 skips; `tests/integration/key_update.zig` - 52 skips; `tests/integration/migration.zig` - 46 skips.
- **Why this is a gap:** Required behavior is still represented by skipped tests, so CI success does not prove the behavior exists.
- **Impact/Risk:** Protocol compliance and regression claims can be overstated while required scenarios are not executed.
- **Recommended fix:** Land the per-category remediation MRs documented in `docs/SKIPPED_TEST_INVENTORY.md` (stale-rationale unskips first; impl-required behind linked GAPs; harness-unsupported de-scoped under `docs/INTEROP_TEST_SUITE.md`).
- **Acceptance criteria:** CI runs required integration scenarios; remaining skips have issue links, owner, and rationale; skip count is reduced to accepted/de-scoped cases only.
- **Status:** Partial: per-scenario triage complete in `docs/SKIPPED_TEST_INVENTORY.md` (30 files, 5 categories, linked to GAPs); remaining work is per-category remediation MRs (top 5 follow-ups documented).

### GAP-0013: Full crypto hardening pass needed
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/142
- **Category:** Security
- **Severity:** High
- **Requirement source:** GitLab issues #17, #18, #33; RFC 9001 key lifecycle and AEAD requirements.
- **Current state (evidence):**
  - `docs/CRYPTO_AUDIT.md` maps current crypto-sensitive operations to code and tests.
  - `src/quic/connection/key_update.zig:1-14` provides one fallible RFC 9001 `"quic ku"` key-update helper.
  - **2026-04-26:** new in-repo executable coverage at `tests/test_key_update_lifecycle.zig` (5 tests covering RFC 9001 §5.4 / §6 / §6.6 -- key derivation, AEAD limits, key phase toggle). Wired in `build.zig:1832-1838`. Cross-referenced from `tests/integration/key_update.zig:110, 116, 301` so future unskip MRs route through the new vectors.
  - `src/quic/connection/methods_b.zig:1584-1628`, `src/quic/connection/methods_c.zig`, `src/quic/endpoint/handshake_integration.zig`, and `src/quic/endpoint/incoming/module_b.zig` use the canonical fallible helper instead of duplicate local `catch unreachable` derivations.
  - `rg -n "catch unreachable|unreachable" src/quic/crypto_quic.zig src/quic/connection src/quic/endpoint/handshake_integration.zig src/quic/endpoint/incoming/module_b.zig src/quic/packet.zig` only matches the explanatory comment in `src/quic/connection/key_update.zig:8`.
  - `make interop-full` - exited `0` after the CID latch fix; final matrix passed `105`, failed `0`, skipped `50` implementation/harness-unsupported cases.
  - Remaining skipped crypto/vector inventory: `tests/integration/key_update.zig` - 52 skips; `tests/integration/rfc9001_advanced.zig` - 27 skips. Triaged rows in `docs/SKIPPED_TEST_INVENTORY.md` route the AEAD/key-update unskips to the new vectors.
- **Why this is a gap:** The audit/hardening cleanup and full interop proof are complete, and the in-repo executable coverage pre-condition is now satisfied, but the 49 advanced-crypto integration skips still need to be unskipped or explicitly de-scoped before claiming full crypto hardening closure.
- **Impact/Risk:** Security-sensitive regressions can still escape CI in skipped advanced crypto scenarios.
- **Recommended fix:** Land the per-file unskip MRs identified in `docs/SKIPPED_TEST_INVENTORY.md` (rows for `tests/integration/key_update.zig` and `tests/integration/rfc9001_advanced.zig`), routing each unskip through `tests/test_key_update_lifecycle.zig` and the closed-gap evidence.
- **Acceptance criteria:** Key lifecycle is documented and tested through teardown and key update; AEAD limit tests run in CI; remaining crypto skips are linked to scoped issues.
- **Status:** Partial: in-repo executable coverage added in `tests/test_key_update_lifecycle.zig`; remaining 49 advanced-crypto integration skips tracked in `docs/SKIPPED_TEST_INVENTORY.md` (rows for `key_update.zig`, `rfc9001_advanced.zig`).

### GAP-0053: Endpoint receive lock-scope proof incomplete
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/126
- **Category:** Performance
- **Severity:** Medium
- **Requirement source:** GitLab issues #9, #11, #109, #154, #165, #182.
- **Current state (evidence):**
  - `src/quic/endpoint.zig:848-856` locks only around each `processIncomingDatagram(...)` call and releases the endpoint mutex between received datagrams.
  - **2026-04-27:** new `concurrent_independent_progress` variant in `benchmarks/integration/datagram_batch.zig:572` (32 flooders × 4096-packet budget) is the missing concurrent-receive regression evidence. Existing `batch_1`, `batch_16`, `batch_64` variants cover the original tail-latency scaling story.
- **Why this was a gap:** The previous batch-wide lock was narrowed but validation was incomplete against the GitLab issue acceptance criteria.
- **Impact/Risk:** Receive-side contention can still regress unnoticed because no benchmark guards the lock-scope change.
- **Recommended fix:** Add a bounded concurrent receive benchmark/regression test that exercises independent connections under batched UDP receive.
- **Acceptance criteria:** Batch receive no longer holds the endpoint mutex across all per-packet processing; concurrency tests prove independent connections make progress; benchmarks cover multi-connection batching.
- **Status:** **Closed** (2026-04-27). Lock scope was already correct; the new `concurrent_independent_progress` variant is the regression test the gap required. See `docs/PERF_GAP_ANALYSIS.md` Closed Items table.

### GAP-0054: Connection allocations are not pooled
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/129
- **Category:** Performance
- **Severity:** Medium
- **Requirement source:** GitLab issues #10, #13, #167, #183.
- **Current state (evidence):**
  - `src/quic/endpoint/server.zig:326-328` allocates each server `Connection` with `allocator.*.create(conn_mod.Connection)`.
  - **2026-04-27:** `src/quic/endpoint/incoming.zig:524-531` enforces `cfg.max_connections` at registration; over-cap Initial packets are dropped silently per RFC 9000 §10.1. Bounded enforcement is the controlled exhaustion path.
  - `src/quic/config.zig:58-60` default `max_connections` is `10000`.
- **Why this is still partially a gap:** Bounded enforcement is in place, but slab/freelist reuse of `Connection` structs is deferred — that requires a Connection lifetime redesign (the per-connection state has hashmaps, TLS context, recovery state with allocator-owned slices, so simple `init`-then-reset reuse is not safe without further work).
- **Impact/Risk:** Allocator overhead and per-accept latency under high churn — bounded by `max_connections`.
- **Recommended fix:** (Remaining) Introduce a slab pool of recycled `Connection` structs with a documented reset semantics that proves no leakage of TLS / recovery / hashmap state between reuses.
- **Acceptance criteria:** Allocation strategy is bounded and benchmarked (✓); exhaustion has a controlled path (✓); churn tests cover pool reuse (deferred).
- **Status:** **Partial** (2026-04-27). Bounded enforcement landed; pool reuse design deferred. The deferred work is tracked under PERF_GAP_ANALYSIS.md `#129` Partial row.

### GAP-0060: Non-domain method module naming obscures ownership
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/177
- **Category:** Code Quality
- **Severity:** Medium
- **Requirement source:** GitLab issues #75 and #115.
- **Current state (evidence):**
  - **2026-04-26:** staged refactor plan landed at `docs/superpowers/plans/2026-04-26-method-module-refactor.md` (539 lines, 5 stages, real `wc -l` inventory of `methods_a/b/c.zig` content, perf-gate skill referenced 5x). The plan IS the closure work for the prior "needs a staged refactor plan" blocker.
  - `src/quic/connection/key_update.zig:1-14` is the sole domain extraction so far; the broad method-module ownership refactor is staged in the new plan.
  - `src/quic/conn.zig` still imports and forwards broad `connection/methods_a.zig`, `methods_b.zig`, and `methods_c.zig` APIs.
- **Why this is a gap:** Generic method modules and a large forwarding surface still obscure domain ownership and audit boundaries.
- **Impact/Risk:** Refactors and bug fixes are harder to scope and review.
- **Recommended fix:** Execute the 5-stage plan with per-stage perf-gate runs.
- **Acceptance criteria:** Method modules are domain-named; forwarding is reduced or clearly owned; tests/imports use the new boundaries; perf-gate green on each stage.
- **Status:** Planning: staged refactor plan landed at `docs/superpowers/plans/2026-04-26-method-module-refactor.md`; execution gated by per-stage perf-gate runs.
