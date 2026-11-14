# Gap Analysis

Last updated: 2026-06-11

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
| 1 | High | 64 | Full crypto hardening pass needed | crypto / TLS | CWE-327 / OWASP A02 | `tests/test_key_update_lifecycle.zig` (5 RFC 9001 vectors); `build.zig:1832-1838`; `tests/integration/key_update.zig:110, 116, 301`; remaining: `tests/integration/key_update.zig` (52 skips) and `tests/integration/rfc9001_advanced.zig` (27 skips) | <https://gitlab.com/devnw/zig/quic/-/issues/142> | Finish remaining advanced-crypto integration skips and AEAD vectors | Unassigned | 2026-05-26 | Partial: in-repo executable coverage added in `tests/test_key_update_lifecycle.zig`; remaining 49 advanced-crypto integration skips tracked in `docs/SKIPPED_TEST_INVENTORY.md` (rows for `key_update.zig`, `rfc9001_advanced.zig`) |
| 2 | Medium | 48 | 529 test stubs return SkipZigTest | tests | Requirement coverage | `docs/SKIPPED_TEST_INVENTORY.md` per-file triage table (30 files, 5 categories, top-5 follow-ups); skip inventory command returned `529` | <https://gitlab.com/devnw/zig/quic/-/issues/88> | Land per-category remediation MRs (stale-rationale unskips first, then impl-required) | Unassigned | Needs per-category remediation | Partial: per-scenario triage complete in `docs/SKIPPED_TEST_INVENTORY.md` (30 files, 5 categories, linked to GAPs); remaining work is per-category remediation MRs (top 5 follow-ups documented) |
| 3 | Medium | 40 | Endpoint receive lock proof incomplete | endpoint | Performance / contention | `src/quic/endpoint.zig:848-856` releases endpoint mutex between datagrams; no concurrency benchmark committed | <https://gitlab.com/devnw/zig/quic/-/issues/126> | Add concurrent receive benchmark and prove no cross-connection regression | Endpoint | Medium | Blocked: implementation is partial; validation is missing |
| 4 | Medium | 40 | Connection allocations are not pooled | endpoint / server | Performance / allocation | `src/quic/endpoint/server.zig:326-328`; `src/quic/endpoint/server.zig:397-414`; `src/quic/config.zig:58-60` | <https://gitlab.com/devnw/zig/quic/-/issues/129> | Add bounded connection/TLS-context pool | Endpoint | Medium | Blocked: requires allocator profile and pool design |
| 5 | Medium | 36 | Non-domain method module naming obscures ownership | transport architecture | Maintainability | `docs/superpowers/plans/2026-04-26-method-module-refactor.md` (5-stage plan, real `wc -l` inventory, perf-gate skill referenced 5x); `src/quic/conn.zig` still forwards broad `methods_a/b/c` API; `src/quic/connection/key_update.zig:1-14` is the sole domain extraction so far | <https://gitlab.com/devnw/zig/quic/-/issues/177> | Execute the staged plan with per-stage perf-gate runs | Core QUIC | Strategic | Planning: staged refactor plan landed at `docs/superpowers/plans/2026-04-26-method-module-refactor.md`; execution gated by per-stage perf-gate runs |

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

- **GitLab issue:** <https://gitlab.com/devnw/zig/quic/-/issues/88>
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

- **GitLab issue:** <https://gitlab.com/devnw/zig/quic/-/issues/142>
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

- **GitLab issue:** <https://gitlab.com/devnw/zig/quic/-/issues/126>
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

- **GitLab issue:** <https://gitlab.com/devnw/zig/quic/-/issues/129>
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

- **GitLab issue:** <https://gitlab.com/devnw/zig/quic/-/issues/177>
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

## 2026-06-11 Conformance Gap Round (NEWGAP-series)

This section records the 2026-06-11 requirements-to-code gap analysis focused on RFC 9000 / RFC 9001 / RFC 9002 conformance. Existing findings above are unchanged. Status legend: **Fixed** = closed in code with tests; **Open** = tracked, not yet implemented.

### Stack-Ranked Findings (NEWGAP-series)

| ID | Sev | Category | Title | Location | RFC | Status |
|---|---|---|---|---|---|---|
| NEWGAP-01 | High | conformance | Received CID transport parameters not authenticated against on-wire CIDs | `src/quic/connection/methods_c.zig` `applyPeerTransportParameters` | RFC 9000 §7.3 | **Fixed** (commit `0e7ede3`) |
| NEWGAP-02 | High | conformance | RETIRE_CONNECTION_ID never sent outbound; `retire_prior_to` retires locally but peer never notified | `src/quic/conn.zig` `onNewConnectionId` | RFC 9000 §5.1.2 | **Open** |
| NEWGAP-03 | High | conformance | No CONNECTION_ID_LIMIT_ERROR enforcement when peer exceeds `active_connection_id_limit` | `src/quic/conn.zig` `onNewConnectionId` | RFC 9000 §5.1.1 | **Fixed** (commit `0e7ede3`) |
| NEWGAP-04 | Medium | conformance | Unknown/malformed frames in Initial space silently dropped instead of FRAME_ENCODING_ERROR | `src/quic/endpoint/incoming.zig` | RFC 9000 §12.4 | **Fixed** (commit `2047925`) |
| NEWGAP-05 | Medium | missing-feature | Server `preferred_address` parsed to raw bytes only; never structurally parsed or migrated to | `src/quic/transport_params.zig` | RFC 9000 §9.6 | **Open** |
| NEWGAP-06 | Medium | conformance | ECN validation failure does not disable ECN for the path; no ECT-acked vs counter cross-check | `src/quic/recovery/recovery.zig` | RFC 9000 §13.4.2.1 | **Open** |
| NEWGAP-07 | Low | missing-feature | Reactive MAX_STREAMS on STREAMS_BLOCKED is log-only despite GAP-0003/#86 marked resolved | `src/quic/endpoint/frame_handler.zig` | RFC 9000 §4.6, §19.14 | **Fixed** (SONNY-6478) |
| NEWGAP-08 | Low | missing-feature | Server never issues NEW_TOKEN for future address validation | (absent) | RFC 9000 §8.1.3 | **Open** |
| NEWGAP-09 | Low | conformance/code-quality | `pto.zig` `.PtoApp` branch returns "not implemented"; dead module diverges from the live app-PTO path | `src/quic/endpoint/pto.zig` | RFC 9002 §6.2.4 | **Open** |
| NEWGAP-10 | Medium | conformance | Initial/Handshake PTO fires on every 100 ms timer wake-up regardless of its deadline, and each firing raises the backoff shared with application data | `src/quic/connection/methods_b.zig`, `src/quic/endpoint.zig` | RFC 9002 §6.2.1 | **Fixed** (v0.1.51) |
| NEWGAP-11 | Medium | conformance | The client takes no RTT sample during the handshake: the server acknowledges its Initial and Handshake packets in separate ACK-only packets that the client never processes | `src/quic/endpoint/incoming.zig`, `src/quic/endpoint/incoming/module_b.zig` | RFC 9002 §5.1 | **Open** |
| NEWGAP-12 | High | liveness | Under heavy loss a long transfer can stall for good: key-phase desync, PTO probes never received by the connection, accepted connection never reaching `tryAccept` | `src/quic/endpoint/incoming/module_b.zig`, `src/quic/connection/methods_b.zig`, `src/quic/endpoint.zig` | RFC 9001 §6, RFC 9002 §6.2 | **Open** |

### NEWGAP-01: Received CID transport parameters not authenticated against on-wire CIDs

- **Severity:** High
- **Category:** conformance
- **RFC:** RFC 9000 §7.3
- **Location:** `src/quic/connection/methods_c.zig` `applyPeerTransportParameters`
- **Status:** **Fixed** (commit `0e7ede3`). Both roles verify `initial_source_connection_id == peer Initial SCID`; the client verifies `original_destination_connection_id == its first DCID`; a mismatch aborts the handshake with TRANSPORT_PARAMETER_ERROR.
- **Residual:** The Retry-path `retry_source_connection_id` check is not implemented (no stored Retry SCID) — minor residual.

### NEWGAP-02: RETIRE_CONNECTION_ID never sent outbound

- **Severity:** High
- **Category:** conformance
- **RFC:** RFC 9000 §5.1.2
- **Location:** `src/quic/conn.zig` `onNewConnectionId`
- **Status:** **Open**. `retire_prior_to` retires connection IDs locally but the peer is never notified. Needs a pending-retire queue plus send-path integration (the encoder `writeRetireConnectionId` exists; there is no outbound caller).

### NEWGAP-03: No CONNECTION_ID_LIMIT_ERROR enforcement when peer exceeds active_connection_id_limit

- **Severity:** High
- **Category:** conformance
- **RFC:** RFC 9000 §5.1.1
- **Location:** `src/quic/conn.zig` `onNewConnectionId`
- **Status:** **Fixed** (commit `0e7ede3`). `onNewConnectionId` returns `error.ConnectionIdLimitError` instead of evicting; `handleNewConnectionId` closes with CONNECTION_ID_LIMIT_ERROR (0x09); a regression test was added.

### NEWGAP-04: Unknown/malformed frames in Initial space silently dropped instead of FRAME_ENCODING_ERROR

- **Severity:** Medium
- **Category:** conformance
- **RFC:** RFC 9000 §12.4
- **Location:** `src/quic/endpoint/incoming.zig`
- **Status:** **Fixed** (commit `2047925`). Initial frame-decode errors now close with FRAME_ENCODING_ERROR, matching the 1-RTT path.

### NEWGAP-05: Server preferred_address parsed to raw bytes only

- **Severity:** Medium
- **Category:** missing-feature
- **RFC:** RFC 9000 §9.6
- **Location:** `src/quic/transport_params.zig`
- **Status:** **Open**. The server `preferred_address` transport parameter is parsed to raw bytes only; it is never structurally parsed or migrated to. This is also a `docs/IMPLEMENTATION_STATUS.md` overstatement ("Complete"); either implement structured parse + client migration or downgrade the status doc.

### NEWGAP-06: ECN validation failure does not disable ECN for the path

- **Severity:** Medium
- **Category:** conformance
- **RFC:** RFC 9000 §13.4.2.1
- **Location:** `src/quic/recovery/recovery.zig`
- **Status:** **Open**. ECN validation failure does not disable ECN for the path, and there is no ECT-acked vs counter cross-check. Add per-space ECN validation state and disable ECN on failure.

### NEWGAP-07: Reactive MAX_STREAMS on STREAMS_BLOCKED is log-only

- **Severity:** Low
- **Category:** missing-feature
- **RFC:** RFC 9000 §4.6, §19.14
- **Location:** `src/quic/endpoint/frame_handler.zig`
- **Status:** **Fixed** (SONNY-6478). Completed streams are retired (`src/quic/connection/stream_retire.zig`) and each retired peer-initiated stream returns one unit of stream-count credit. MAX_STREAMS goes out once half the initial limit has been returned, with other flow-control frames, and immediately on STREAMS_BLOCKED. Covered by `zig build test-stream-retirement`.

### NEWGAP-08: Server never issues NEW_TOKEN for future address validation

- **Severity:** Low
- **Category:** missing-feature
- **RFC:** RFC 9000 §8.1.3
- **Location:** (absent)
- **Status:** **Open**. SHOULD-level; optional post-handshake NEW_TOKEN issuance is not implemented.

### NEWGAP-09: pto.zig .PtoApp branch returns "not implemented" (dead module)

- **Severity:** Low
- **Category:** conformance/code-quality
- **RFC:** RFC 9002 §6.2.4
- **Location:** `src/quic/endpoint/pto.zig`
- **Status:** **Open**. The `.PtoApp` branch returns "not implemented" and the dead module diverges from the live app-PTO path. App PTO IS sent via `connection/methods_b.sendPtoProbeApp`; either implement or delete the dead `pto.zig` branch to avoid a maintainer trap.

### NEWGAP-10: handshake-space PTO ignores its deadline

- **Severity:** Medium
- **Category:** conformance
- **RFC:** RFC 9002 §6.2.1
- **Location:** `src/quic/connection/methods_b.zig` (`computeAndMaybeArmPtoInitial`, `computeAndMaybeArmPtoHandshake`), `src/quic/endpoint.zig` (`processExpiredTimers`)
- **Status:** **Fixed** (v0.1.51, found with SONNY-6478). The Initial and Handshake PTO timers wake at least every 100 ms and sent a probe on every wake-up without checking the backed-off deadline. A slow handshake on a starved machine therefore probed about ten times a second, and each probe raised `rec.pto_count`, which the application space shares: the high-parallel clients reached 240 and their application PTO deadline saturated. An expiry now probes only once `Connection.handshakePtoDue` reports the deadline has passed; an early wake-up re-arms the timer, as `appPtoDue` does for the application space. Covered by `zig build test-tail-loss-pto` ("Initial PTO probes follow the backed-off RFC 9002 deadline": 3 Initial packets in 1.5 s, previously 29).

### NEWGAP-11: no RTT sample from the handshake on the client

- **Severity:** Medium
- **Category:** conformance
- **RFC:** RFC 9002 §5.1, §6.2.2
- **Location:** `src/quic/endpoint/incoming.zig` (`processInitial` ACK reply), `src/quic/endpoint/incoming/module_b.zig` (Handshake ACK reply)
- **Status:** **Open** (found with SONNY-6478, v0.1.51). The server acknowledges the client's Initial and Handshake packets in separate ACK-only packets sent after its own flight. A trace showed the client never processes an Initial or Handshake ACK (probably because they arrive after it has dropped those keys), so it confirms the handshake without an RTT sample. Its first application PTO then uses the 333 ms initial RTT, which is about 1 s (RFC 9002 §6.2.2), not a few milliseconds: on loopback, a lost first request is resent after about 1 s (`zig build test-tail-loss-pto`, "a lost request"). Fix: bundle the ACK in the server's first Initial and Handshake packets, as RFC 9000 §13.2.1 encourages.

### NEWGAP-12: long transfers can stall under heavy loss

- **Severity:** High
- **Category:** liveness
- **RFC:** RFC 9001 §6 (key update), RFC 9002 §6.2 (PTO)
- **Location:** `src/quic/endpoint/incoming/module_b.zig` (key promotion, 16-packet old-key window), `src/quic/connection/methods_b.zig` (`maybeTriggerKeyUpdateOnSend`, every 512 packets or 1 MiB), `src/quic/endpoint.zig` (accept queue)
- **Status:** **Open** (found with SONNY-6478, v0.1.51). On 2 CPUs shared with 16 busy loops, `zig build test-large-stream-flow-control` stalls in 1/20 (ReleaseSafe) to 10/20 (Debug) runs, and the lossy-loopback MAX_STREAM_DATA test in 1–2/20, with tens of thousands of receive-buffer drops. The failure report (`reportStall`) showed three distinct mechanisms, none in code this release changed:
  1. **Key-phase desync.** The client sends with key phase 1 while the server is at receive phase 0. The server decrypts none of the client's last ~5,500 packets, so nothing is acknowledged again.
  2. **Probes never reach the connection,** with no key update involved. After a 391-packet burst was lost, six consecutive client PTO probes produced no ACK, and the server's largest received packet number did not move, although the server was idle and polling every millisecond.
  3. **Accepted connection never handed to the application.** The server acknowledged every client packet, but `tryAccept` never returned the connection, so no data was read (16 MiB test, 0 bytes delivered).

  These tests could not reach this regime before v0.1.51 (a stream beyond its receive window crawled, SONNY-6475), and the application PTO used to fire every 100 ms, which masked slow recovery. Disabling automatic key updates did not remove the stalls (1 in 9 runs still stalled), so mechanism 1 is not the only cause. Each needs its own investigation; the failure report in the test prints the state needed to tell them apart.

### Second-pass additions

The 2026-06-11 SECOND-PASS review surfaced one further conformance/security finding, now Fixed.

| ID | Sev | Category | Title | Location | RFC | Status |
|---|---|---|---|---|---|---|
| NEW-GAP-10 | High | conformance/security | Server did not discard a client Initial packet carried in a UDP datagram smaller than 1200 bytes | `src/quic/endpoint.zig` `processIncomingDatagram` + concurrent poll dispatch | RFC 9000 §14.1 | **Fixed** (commit `ad34e76`) |

### NEW-GAP-10: Server did not discard a client Initial in a UDP datagram <1200 bytes

- **Severity:** High
- **Category:** conformance/security
- **RFC:** RFC 9000 §14.1
- **Location:** `src/quic/endpoint.zig` `processIncomingDatagram` + concurrent poll dispatch
- **Status:** **Fixed** (commit `ad34e76`). The server discards supported-version Initials carried in datagrams smaller than 1200 bytes (anti-amplification); loopback is exempt when `cfg.exempt_localhost` is set (mirrors the amplification localhost exemption); the unknown-version Version-Negotiation probe path is unaffected.

### Third-pass additions

The 2026-06-11 THIRD-PASS review surfaced one further conformance finding, now Fixed.

| ID | Sev | Category | Title | Location | RFC | Status |
|---|---|---|---|---|---|---|
| NEWGAP-11 | Medium | conformance/missing-feature | DATAGRAM frame only handled type 0x30 (with an incorrect length field) and rejected 0x31 as FRAME_ENCODING_ERROR | `src/quic/frame/datagram.zig`, `frame.zig`, `types.zig` | RFC 9221 §4 | **Fixed** (commit `ddb3e1a`) |

### NEWGAP-11: DATAGRAM frame only handled type 0x30 and rejected 0x31

- **Severity:** Medium
- **Category:** conformance/missing-feature
- **RFC:** RFC 9221 §4
- **Location:** `src/quic/frame/datagram.zig`, `frame.zig`, `types.zig`
- **Status:** **Fixed** (commit `ddb3e1a`). Decode now handles 0x30 (data-to-end) and 0x31 (length-prefixed); the encoder emits the self-delimiting 0x31 form; `FrameType.DATAGRAM_LEN` (0x31) was added; both type codes are routed in `frame.decodeOne`. Follow-up (still open): advertise the `max_datagram_frame_size` transport parameter when `enable_datagram` is set (datagrams default off, so not yet negotiated).
