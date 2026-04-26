# Gap Analysis

Last updated: 2026-04-26

Status note (2026-04-26): this file intentionally contains open repository-level gaps only. Closed items are moved to `docs/GAP_ANALYSIS_RESOLVED.md`. GitLab issues are the authoritative status records; this file is the flatfile mirror for humans and agents. GitLab write-back is currently blocked because `glab auth status` reports no API token and write attempts returned `401 Unauthorized`.

## Summary

- Remaining open repository gaps: 5, all marked Blocked or Blocked / Deferred with explicit unblock steps.
- Closed during this pass: GAP-0007 (crypto audit evidence completed) and GAP-0055 (Retry-before-allocation implemented and tested).
- New supporting docs: `docs/CRYPTO_AUDIT.md` and `docs/SKIPPED_TEST_INVENTORY.md`.
- Scanner/report notes remain in `docs/SECURITY_REVIEW_NOTES.md`; raw scan reports are in `/tmp` and intentionally not committed.

Top risks:
- Full crypto lifecycle/key-update/AEAD unit and integration coverage remains incomplete and blocked on remaining skipped test-vector work: GAP-0013 / #142. Full interop itself is clean: `make interop-full` passed `105`, failed `0`, skipped `50` implementation/harness-unsupported cases.
- Broad skipped integration-test coverage remains blocked pending per-scenario requirement triage: GAP-0004 / #88.
- Endpoint-level receive contention proof and connection allocation pooling remain blocked on benchmark-backed design: GAP-0053 / #126 and GAP-0054 / #129.
- Method-module architecture remains blocked/deferred because it requires a broad staged refactor: GAP-0060 / #177.

## Stack-Ranked Findings

| Rank | Sev | Risk | Finding | Component | CWE/OWASP | Evidence(file:line) | Issue URL | Fix | Owner | Due | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | High | 64 | Full crypto hardening pass needed | crypto / TLS | CWE-327 / OWASP A02 | `src/quic/connection/methods_b.zig:1584-1628`; `tests/integration/key_update.zig`; `tests/integration/rfc9001_advanced.zig` | https://gitlab.com/devnw/zig/quic/-/issues/142 | Finish lifecycle/key-update/AEAD tests and docs | Unassigned | 2026-05-26 | Blocked: requires remaining key lifecycle/AEAD test-vector implementation |
| 2 | Medium | 48 | 529 test stubs return SkipZigTest | tests | Requirement coverage | `docs/SKIPPED_TEST_INVENTORY.md`; skip inventory command returned `529` | https://gitlab.com/devnw/zig/quic/-/issues/88 | Replace/de-scope skipped scenarios with linked requirements | Unassigned | Needs triage | Blocked: requires per-scenario requirements triage |
| 3 | Medium | 40 | Endpoint receive lock proof incomplete | endpoint | Performance / contention | `src/quic/endpoint.zig:848-856` releases endpoint mutex between datagrams; no concurrency benchmark committed | https://gitlab.com/devnw/zig/quic/-/issues/126 | Add concurrent receive benchmark and prove no cross-connection regression | Endpoint | Medium | Blocked: implementation is partial; validation is missing |
| 4 | Medium | 40 | Connection allocations are not pooled | endpoint / server | Performance / allocation | `src/quic/endpoint/server.zig:326-328`; `src/quic/endpoint/server.zig:397-414`; `src/quic/config.zig:58-60` | https://gitlab.com/devnw/zig/quic/-/issues/129 | Add bounded connection/TLS-context pool | Endpoint | Medium | Blocked: requires allocator profile and pool design |
| 5 | Medium | 36 | Non-domain method module naming obscures ownership | transport architecture | Maintainability | `src/quic/conn.zig` still forwards broad `methods_a/b/c` API; `src/quic/connection/key_update.zig:1-14` is only a narrow extraction | https://gitlab.com/devnw/zig/quic/-/issues/177 | Rename/split method modules by domain | Core QUIC | Strategic | Blocked / Deferred |

## Findings By Area

- **Core QUIC security:** GAP-0013 remains open. GAP-0007 was closed with `docs/CRYPTO_AUDIT.md`, fallible Retry/key-update derivation, and `rg` evidence showing no crypto `catch unreachable` sites in active QUIC crypto paths.
- **Test coverage:** GAP-0004 remains blocked because the broad skipped-test inventory now exists, but each skipped scenario still needs implement/de-scope triage.
- **Performance:** GAP-0053 and GAP-0054 remain blocked on concurrency/allocation design and benchmark evidence.
- **Architecture:** GAP-0060 remains blocked/deferred because this pass only extracted the key-update helper, not the broad method-module ownership split.
- **Supply-chain/tooling review:** 2026-04-26 security/delivery findings were closed in prior passes and moved to `docs/GAP_ANALYSIS_RESOLVED.md`.

## Remediation Horizon

- **Quick wins:** no verified quick wins remain in this file after the 2026-04-26 closure pass.
- **Medium:** unblock skipped integration tests (GAP-0004) with requirements triage and benchmark endpoint receive/allocation fixes (GAP-0053/GAP-0054).
- **Strategic:** complete remaining crypto lifecycle vectors (#142) and complete the method-module ownership refactor (#177/#115).

## Gaps

### GAP-0004: 529 test stubs return SkipZigTest
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/88
- **Category:** Test
- **Severity:** Medium
- **Requirement source:** GitLab issues #5, #7, #24, #27, #30, #31; prior `docs/requirements.md` test coverage claims.
- **Current state (evidence):**
  - `docs/SKIPPED_TEST_INVENTORY.md` records the 2026-04-26 skip inventory and top affected files.
  - `rg --hidden --glob '!.git/**' --glob '!.claude/worktrees/**' --glob '*.zig' -n 'return error\.SkipZigTest' tests src | wc -l` - `529`
  - Highest-count files: `tests/integration/zero_rtt.zig` - 62 skips; `tests/integration/flow_control.zig` - 58 skips; `tests/integration/fault/fault.zig` - 56 skips; `tests/integration/key_update.zig` - 52 skips; `tests/integration/migration.zig` - 46 skips.
- **Why this is a gap:** Required behavior is still represented by skipped tests, so CI success does not prove the behavior exists.
- **Impact/Risk:** Protocol compliance and regression claims can be overstated while required scenarios are not executed.
- **Recommended fix:** Replace skips with executable tests or explicitly de-scope each skipped scenario with linked GitLab requirements.
- **Acceptance criteria:** CI runs required integration scenarios; remaining skips have issue links, owner, and rationale; skip count is reduced to accepted/de-scoped cases only.
- **Status:** Blocked. Inventory is complete; unblock by triaging each skipped scenario against a GitLab requirement and deciding implement vs explicitly de-scope before coding.

### GAP-0013: Full crypto hardening pass needed
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/142
- **Category:** Security
- **Severity:** High
- **Requirement source:** GitLab issues #17, #18, #33; RFC 9001 key lifecycle and AEAD requirements.
- **Current state (evidence):**
  - `docs/CRYPTO_AUDIT.md` maps current crypto-sensitive operations to code and tests.
  - `src/quic/connection/key_update.zig:1-14` provides one fallible RFC 9001 `"quic ku"` key-update helper.
  - `src/quic/connection/methods_b.zig:1584-1628`, `src/quic/connection/methods_c.zig`, `src/quic/endpoint/handshake_integration.zig`, and `src/quic/endpoint/incoming/module_b.zig` now use the canonical fallible helper instead of duplicate local `catch unreachable` derivations.
  - `rg -n "catch unreachable|unreachable" src/quic/crypto_quic.zig src/quic/connection src/quic/endpoint/handshake_integration.zig src/quic/endpoint/incoming/module_b.zig src/quic/packet.zig` only matches the explanatory comment in `src/quic/connection/key_update.zig:8`.
  - `make interop-full` - exited `0` after the CID latch fix; final matrix passed `105`, failed `0`, skipped `50` implementation/harness-unsupported cases.
  - Remaining skipped crypto/vector inventory: `tests/integration/key_update.zig` - 52 skips; `tests/integration/rfc9001_advanced.zig` - 27 skips.
- **Why this is a gap:** The audit/hardening cleanup and full interop proof are complete, but key lifecycle, key update, and AEAD limit claims are not completely exercised by executable in-repo vectors.
- **Impact/Risk:** Security-sensitive regressions can still escape CI in skipped advanced crypto scenarios.
- **Recommended fix:** Enable the remaining key update, key lifecycle, and AEAD limit integration tests, or explicitly de-scope each skipped scenario to a linked GitLab requirement.
- **Acceptance criteria:** Key lifecycle is documented and tested through teardown and key update; AEAD limit tests run in CI; remaining crypto skips are linked to scoped issues.
- **Status:** Blocked. Unblock by implementing the missing key lifecycle, key-update, and AEAD-limit test vectors before claiming full crypto hardening closure.

### GAP-0053: Endpoint receive lock-scope proof incomplete
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/126
- **Category:** Performance
- **Severity:** Medium
- **Requirement source:** GitLab issues #9, #11, #109, #154, #165, #182.
- **Current state (evidence):**
  - `src/quic/endpoint.zig:848-856` now locks only around each `processIncomingDatagram(...)` call and releases the endpoint mutex between received datagrams.
  - No committed concurrent receive benchmark or regression harness proves independent connections make progress under multi-connection batching.
- **Why this is a gap:** The previous batch-wide lock was narrowed, but validation is incomplete against the GitLab issue acceptance criteria.
- **Impact/Risk:** Receive-side contention can still regress unnoticed because no benchmark guards the lock-scope change.
- **Recommended fix:** Add a bounded concurrent receive benchmark/regression test that exercises independent connections under batched UDP receive.
- **Acceptance criteria:** Batch receive no longer holds the endpoint mutex across all per-packet processing; concurrency tests prove independent connections make progress; benchmarks cover multi-connection batching.
- **Status:** Blocked. Unblock with a concurrent receive benchmark that proves no cross-connection regression.

### GAP-0054: Connection allocations are not pooled
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/129
- **Category:** Performance
- **Severity:** Medium
- **Requirement source:** GitLab issues #10, #13, #167, #183.
- **Current state (evidence):**
  - `src/quic/endpoint/server.zig:326-328` allocates each server `Connection` with `allocator.*.create(conn_mod.Connection)`.
  - `src/quic/endpoint/server.zig:397-414` encodes per-connection transport/TLS setup and applies AEAD configuration per connection.
  - `src/quic/config.zig:58-60` default `max_connections` is `10000`.
- **Why this is a gap:** High-churn server workloads use general allocation for large connection objects instead of a bounded pool/slab.
- **Impact/Risk:** Allocator overhead, memory fragmentation, and large memory spikes under load.
- **Recommended fix:** Introduce a bounded connection/TLS-context pool sized by `max_connections` and add exhaustion metrics.
- **Acceptance criteria:** Allocation strategy is bounded and benchmarked; exhaustion has a controlled path; churn tests cover pool reuse.
- **Status:** Blocked. Unblock with an allocator profile and a bounded connection/TLS-context pool ownership design.

### GAP-0060: Non-domain method module naming obscures ownership
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/177
- **Category:** Code Quality
- **Severity:** Medium
- **Requirement source:** GitLab issues #75 and #115.
- **Current state (evidence):**
  - `src/quic/connection/key_update.zig:1-14` extracts RFC 9001 key-update derivation into a domain-named module.
  - `src/quic/conn.zig` still imports and forwards broad `connection/methods_a.zig`, `methods_b.zig`, and `methods_c.zig` APIs.
- **Why this is a gap:** Generic method modules and a large forwarding surface still obscure domain ownership and audit boundaries.
- **Impact/Risk:** Refactors and bug fixes are harder to scope and review.
- **Recommended fix:** Rename/split method modules by domain and reduce or remove the forwarding table.
- **Acceptance criteria:** Method modules are domain-named; forwarding is reduced or clearly owned; tests/imports use the new boundaries.
- **Status:** Blocked / Deferred. Unblock with a staged method-module refactor plan and full regression suite, because this touches broad public forwarding and connection ownership boundaries.
