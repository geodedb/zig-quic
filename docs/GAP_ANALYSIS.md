# Gap Analysis

Last updated: 2026-04-26

Status note (2026-04-26): this file intentionally contains open repository-level gaps and the latest security/delivery-pipeline review findings. Closed items are moved to `docs/GAP_ANALYSIS_RESOLVED.md`. GitLab issues are the authoritative status records; this file is the flatfile mirror for humans and agents.

## Summary

- Remaining repository gaps preserved below: 7, all marked Blocked or Blocked / Deferred with explicit unblock steps.
- Closed during 2026-04-26 implementation pass: GAP-0056, GAP-0058, GAP-0061, and security/delivery issues #43, #57, #59, #157, #191, #195, #196, #197, #198.
- Scanner/report notes: `docs/SECURITY_REVIEW_NOTES.md`; raw scan reports are in `/tmp` and intentionally not committed.

Top risks:
- Crypto hardening audit remains incomplete and blocked on a dedicated audit/vector pass: GAP-0007 / #136.
- Full crypto lifecycle/key-update/AEAD coverage remains incomplete and blocked on test-vector work: GAP-0013 / #142.
- Retry-required Initials can allocate full connection state pre-validation and need a Retry-first design: GAP-0055 / #188.
- Endpoint-level receive contention and connection allocation pooling remain blocked on benchmark-backed design: GAP-0053 / #126 and GAP-0054 / #129.
- Method-module architecture remains blocked/deferred because it requires a broad staged refactor: GAP-0060 / #177.

## Stack-Ranked Findings

| Rank | Sev | Risk | Finding | Component | CWE/OWASP | Evidence(file:line) | Issue URL | Fix | Owner | Due | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | Critical | 80 | Crypto hardening audit incomplete | crypto | CWE-327 / OWASP A02 | `src/quic/crypto_quic.zig:161-165`; `src/quic/connection/methods_b.zig:18`; `src/quic/endpoint/handshake_integration.zig:42` | https://gitlab.com/devnw/zig/quic/-/issues/136 | Complete crypto audit, remove/justify `catch unreachable`, add RFC vectors | Unassigned | 2026-05-03 | Blocked: requires dedicated crypto audit and RFC vector suite |
| 2 | High | 64 | Full crypto hardening pass needed | crypto / TLS | CWE-327 / OWASP A02 | `src/quic/connection/methods_b.zig:1553-1558`; `tests/integration/key_update.zig`; `tests/integration/rfc9001_advanced.zig` | https://gitlab.com/devnw/zig/quic/-/issues/142 | Finish lifecycle/key-update/AEAD tests and docs | Unassigned | 2026-05-26 | Blocked: requires key lifecycle/AEAD test-vector implementation |
| 3 | High | 64 | Pre-Retry connection allocation exhaustion | endpoint / server | CWE-770 / OWASP A05 | `src/quic/endpoint/incoming.zig:429-470`; `src/quic/endpoint/incoming.zig:594-645`; `src/quic/endpoint/server.zig:313-320` | https://gitlab.com/devnw/zig/quic/-/issues/188 | Generate Retry before full connection/TLS allocation | Unassigned | 2026-05-26 | Blocked: requires Retry-first allocation design and spoofed Initial tests |
| 4 | Medium | 48 | 528 test stubs return SkipZigTest | tests | Requirement coverage | `rg --hidden --glob '!.git/**' --glob '!.claude/worktrees/**' --glob '*.zig' -n 'return error\\.SkipZigTest' tests src | wc -l` | https://gitlab.com/devnw/zig/quic/-/issues/88 | Replace/de-scope skipped scenarios with linked requirements | Unassigned | Needs triage | Blocked: requires per-scenario requirements triage |
| 5 | Medium | 40 | Endpoint mutex held during receive batch | endpoint | Performance / contention | `src/quic/endpoint.zig:845-853` | https://gitlab.com/devnw/zig/quic/-/issues/126 | Narrow endpoint mutex critical section and add concurrency benchmark | Endpoint | Medium | Blocked |
| 6 | Medium | 40 | Connection allocations are not pooled | endpoint / server | Performance / allocation | `src/quic/endpoint/server.zig:313-320`; `src/quic/endpoint/server.zig:410-414` | https://gitlab.com/devnw/zig/quic/-/issues/129 | Add bounded connection/TLS-context pool | Endpoint | Medium | Blocked |
| 7 | Medium | 36 | Non-domain method module naming obscures ownership | transport architecture | Maintainability | `src/quic/conn.zig:1599-1714` | https://gitlab.com/devnw/zig/quic/-/issues/177 | Rename/split method modules by domain | Core QUIC | Strategic | Blocked / Deferred |

## Findings By Area

- **Core QUIC security:** GAP-0007, GAP-0013, and GAP-0055 remain the highest-impact protocol/security gaps and are blocked on dedicated design/audit work.
- **Test coverage:** GAP-0004 remains blocked because broad skipped-test requirements still need per-scenario execution or de-scoping.
- **Performance:** GAP-0053 and GAP-0054 remain blocked on concurrency/allocation design and benchmark evidence.
- **Architecture:** GAP-0060 remains blocked/deferred because it is a broad connection-method ownership refactor.
- **Supply-chain/tooling review:** 2026-04-26 security/delivery findings were closed in this pass and moved to `docs/GAP_ANALYSIS_RESOLVED.md`.

## Remediation Horizon

- **Quick wins:** no verified quick wins remain in this file after the 2026-04-26 closure pass.
- **Medium:** unblock skipped integration tests (GAP-0004) with requirements triage and design measured endpoint receive/allocation fixes (GAP-0053/GAP-0054).
- **Strategic:** complete crypto audit/hardening (#136/#142), move Retry generation ahead of full connection/TLS allocation (#188), and complete the method-module ownership refactor (#177).

## Gaps

### GAP-0004: 528 test stubs return SkipZigTest
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/88
- **Category:** Test
- **Severity:** Medium
- **Requirement source:** GitLab issues #5, #7, #24, #27, #30, #31; prior `docs/requirements.md` test coverage claims.
- **Current state (evidence):**
  - `rg --hidden --glob '!.git/**' --glob '!.claude/worktrees/**' --glob '*.zig' -n 'return error\.SkipZigTest' tests src | wc -l` - `528`
  - `tests/integration/zero_rtt.zig` - 62 skips; `tests/integration/flow_control.zig` - 58 skips; `tests/integration/fault/fault.zig` - 56 skips; `tests/integration/key_update.zig` - 52 skips; `tests/integration/migration.zig` - 46 skips.
- **Why this is a gap:** Required behavior is represented by skipped tests, so CI success does not prove the behavior exists.
- **Impact/Risk:** Protocol compliance and regression claims can be overstated while required scenarios are not executed.
- **Recommended fix:** Replace skips with executable tests or explicitly de-scope each skipped scenario with linked GitLab requirements.
- **Acceptance criteria:** CI runs required integration scenarios; remaining skips have issue links, owner, and rationale; skip count is reduced to accepted/de-scoped cases only.
- **Status:** Blocked. Unblock by triaging each skipped scenario against a GitLab requirement and deciding implement vs explicitly de-scope before coding.

### GAP-0007: Crypto hardening audit incomplete
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/136
- **Category:** Security
- **Severity:** Critical
- **Requirement source:** GitLab issues #17 and #33; RFC 9001 crypto and side-channel requirements.
- **Current state (evidence):**
  - `src/quic/packet.zig:1267` - Retry integrity tag comparison now uses `std.crypto.timing_safe.eql`; the older specific Retry comparison finding is resolved.
  - `src/quic/conn.zig:1428` - stateless reset token comparison uses `std.crypto.timing_safe.eql`.
  - `src/quic/crypto_quic.zig:161-165`, `src/quic/connection/methods_b.zig:18`, `src/quic/connection/methods_c.zig:19`, `src/quic/endpoint/handshake_integration.zig:42` - crypto/key derivation paths still use `catch unreachable`.
  - `src/quic/crypto_quic.zig:65-77`, `src/quic/crypto_quic.zig:121-130` - AEAD nonce construction exists, but audit evidence tying all paths to RFC 9001 vectors is incomplete.
- **Why this is a gap:** Some crypto findings are fixed, but the repository lacks complete proof that all crypto-sensitive operations are audited and tested.
- **Impact/Risk:** Reviewers cannot prove side-channel resistance, key lifecycle behavior, or QUIC-TLS vector compliance end to end.
- **Recommended fix:** Complete the crypto audit, remove or justify `catch unreachable` in crypto paths, and add RFC vector coverage for nonce, Retry, reset token, and key update behavior.
- **Acceptance criteria:** Audit doc maps every crypto-sensitive operation to code and tests; crypto `catch unreachable` sites are eliminated or justified; CI runs the relevant KAT/vector tests.
- **Status:** Blocked. Unblock with a dedicated crypto audit pass covering RFC 9001 vectors, key derivation fallibility, and side-channel-sensitive comparisons.

### GAP-0013: Full crypto hardening pass needed
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/142
- **Category:** Security
- **Severity:** High
- **Requirement source:** GitLab issues #17, #18, #33; RFC 9001 key lifecycle and AEAD requirements.
- **Current state (evidence):**
  - `src/quic/connection/methods_b.zig:1553-1558` - `zeroKeys` uses `std.crypto.secureZero`.
  - `src/quic/crypto_quic.zig:161-165` and key-update helper sites - crypto derivation still uses `catch unreachable`.
  - `tests/integration/key_update.zig` - 52 skipped tests; `tests/integration/rfc9001_advanced.zig` - 27 skipped tests.
- **Why this is a gap:** Some hardening exists, but key lifecycle, key update, and AEAD limit claims are not completely exercised.
- **Impact/Risk:** Security-sensitive regressions may escape CI.
- **Recommended fix:** Complete the crypto review and enable key update/AEAD limit integration tests.
- **Acceptance criteria:** Key lifecycle is documented and tested through teardown and key update; AEAD limit tests run in CI; remaining crypto skips are linked to scoped issues.
- **Status:** Blocked. Unblock by implementing the missing key lifecycle, key-update, and AEAD-limit test vectors before claiming closure.

### GAP-0053: Endpoint mutex held during receive batch
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/126
- **Category:** Performance
- **Severity:** Medium
- **Requirement source:** GitLab issues #9, #11, #109, #154, #165, #182.
- **Current state (evidence):**
  - `src/quic/endpoint.zig:845-853` - locks `self.mu`, iterates `batch_n`, and calls `self.processIncomingDatagram(...)` for each packet before unlock.
- **Why this is a gap:** The endpoint-global lock covers the whole batch processing path.
- **Impact/Risk:** Slow packet processing serializes unrelated connections and limits receive-side parallelism.
- **Recommended fix:** Narrow the mutex critical section to map/state operations and move safe per-packet work outside the lock.
- **Acceptance criteria:** Batch receive no longer holds the endpoint mutex across all per-packet processing; concurrency tests prove independent connections make progress; benchmarks cover multi-connection batching.
- **Status:** Blocked. Unblock with a lock-scope design and a concurrent receive benchmark that proves no cross-connection regression.

### GAP-0054: Connection allocations are not pooled
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/129
- **Category:** Performance
- **Severity:** Medium
- **Requirement source:** GitLab issues #10, #13, #167, #183.
- **Current state (evidence):**
  - `src/quic/endpoint/server.zig:313-320` - allocates each server `Connection` with `allocator.*.create(conn_mod.Connection)`.
  - `src/quic/endpoint/server.zig:410-414` - allocates a TLS context per connection.
  - `src/quic/config.zig:58-60` - default `max_connections` is `10000`.
- **Why this is a gap:** High-churn server workloads use general allocation for large connection objects instead of a bounded pool/slab.
- **Impact/Risk:** Allocator overhead, memory fragmentation, and large memory spikes under load.
- **Recommended fix:** Introduce a bounded connection/TLS-context pool sized by `max_connections` and add exhaustion metrics.
- **Acceptance criteria:** Allocation strategy is bounded and benchmarked; exhaustion has a controlled path; churn tests cover pool reuse.
- **Status:** Blocked. Unblock with an allocator profile and a bounded connection/TLS-context pool ownership design.

### GAP-0055: Pre-Retry connection allocation exhaustion
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/188
- **Category:** Security
- **Severity:** High
- **Requirement source:** GitLab issues #44 and #125; RFC 9000 address validation guidance.
- **Current state (evidence):**
  - `src/quic/endpoint/incoming.zig:429-470` - checks `max_connections`, then creates a server connection for a new Initial.
  - `src/quic/endpoint/incoming.zig:594-645` - generates and sends Retry later if the address is still unvalidated.
  - `src/quic/endpoint/server.zig:313-320` - allocates a full `Connection`; `src/quic/endpoint/server.zig:410-414` allocates TLS context.
- **Why this is a gap:** Retry-required Initials can allocate full connection state before address validation.
- **Impact/Risk:** Spoofed Initial packets can consume memory and TLS setup work pre-authentication.
- **Recommended fix:** Generate Retry before full connection allocation, using temporary state until token validation succeeds.
- **Acceptance criteria:** Retry-required Initials do not allocate full connection/TLS state; tests prove bounded allocation under spoofed Initial flood; valid Retry tokens proceed normally.
- **Status:** Blocked. Unblock with a Retry-first state-machine design that sends Retry before full `Connection` and TLS context allocation.

### GAP-0060: Non-domain method module naming obscures ownership
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/177
- **Category:** Code Quality
- **Severity:** Medium
- **Requirement source:** GitLab issues #75 and #115.
- **Current state (evidence):**
  - `src/quic/conn.zig:1599-1714` - imports `connection/methods_a.zig`, `methods_b.zig`, `methods_c.zig` and forwards more than 100 symbols.
  - `src/quic/conn.zig:416-420` and `src/quic/connection/methods_b.zig:25` - separate trace toggles.
- **Why this is a gap:** Generic module names and forwarding obscure domain ownership and audit boundaries.
- **Impact/Risk:** Refactors and bug fixes are harder to scope and review.
- **Recommended fix:** Rename/split method modules by domain and reduce or remove the forwarding table.
- **Acceptance criteria:** Method modules are domain-named; forwarding is reduced or clearly owned; tests/imports use the new boundaries.
- **Status:** Blocked / Deferred. Unblock with a staged method-module refactor plan and full regression suite, because this touches broad public forwarding and connection ownership boundaries.
