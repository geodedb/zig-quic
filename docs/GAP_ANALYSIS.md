# Gap Analysis

Status note (2026-04-25): this file intentionally contains only open repository-level gaps. Closed items are moved to `docs/GAP_ANALYSIS_RESOLVED.md`. The 10 remaining entries below are unresolved and continue to be tracked by their linked open GitLab issues.

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

### GAP-0056: QNS container runtime user hardening needs verification
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/191
- **Category:** Security
- **Severity:** Low
- **Requirement source:** GitLab issue #60.
- **Current state (evidence):**
  - `interop/Dockerfile:36-40` - sets `USER quic` before entrypoint.
  - `examples/interop/zig-qns/Dockerfile:28-37` - intentionally does not set `USER quic` because setup needs root.
  - `examples/interop/zig-qns/run_endpoint.sh:37-44` - uses `setpriv` when present, but falls back to current user if missing.
- **Why this is a gap:** Effective runtime user is not proven by CI for both images and setup paths.
- **Impact/Risk:** A base-image or script change can silently run the endpoint as root.
- **Recommended fix:** Add container build/runtime checks asserting endpoint user and required capabilities.
- **Acceptance criteria:** CI builds both interop images and asserts endpoint process runs as `quic`; fallback behavior is tested or fails closed; docs identify hardening status by image.

### GAP-0058: Deprecated/dead transport code remains in production tree
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/175
- **Category:** Code Quality
- **Severity:** Medium
- **Requirement source:** GitLab issues #75, #103, #115.
- **Current state (evidence):**
  - `src/quic/connection/methods_a.zig:1162-1169` - keeps a legacy stream-0 flow-control compatibility block alongside map-backed stream state.
  - `src/quic/connection/methods_c.zig:578-580` - still carries a stale placeholder comment on the active CID issuance path even though frame scheduling now exists.
  - Previous CUBIC and PMTUD duplicate evidence was resolved by GAP-0017, GAP-0044, and GAP-0062 and is no longer part of this open item.
- **Why this is a gap:** Dead or deprecated production-visible surfaces remain available.
- **Impact/Risk:** Future fixes can target stale code and leave active paths unchanged.
- **Recommended fix:** Remove, rename, or quarantine legacy modules behind test-only imports and document the authoritative module map.
- **Acceptance criteria:** Deprecated transport modules are removed or test-only; public imports expose authoritative implementations; production references to deprecated types are gone.

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

### GAP-0061: QUIC minimum datagram size literal is duplicated
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/178
- **Category:** Code Quality
- **Severity:** Medium
- **Requirement source:** GitLab issues #75 and #115; RFC 9000 minimum initial datagram size.
- **Current state (evidence):**
  - `rg -n '\b1200\b' src/quic | wc -l` - `127`
  - `src/quic/frame/misc.zig:17` - defines `MIN_INITIAL_PACKET_SIZE`.
  - `src/quic/config.zig:40-41` - still contains a direct `1200` default.
- **Why this is a gap:** A canonical constant exists, but semantically related production literals remain duplicated.
- **Impact/Risk:** Packet sizing, PMTUD behavior, and test expectations can drift.
- **Recommended fix:** Use a canonical constant for RFC 9000 minimum datagram size and document remaining unrelated literals.
- **Acceptance criteria:** Production code uses a named constant; remaining `1200` literals are documented tests or unrelated values; packet sizing tests reference the constant.
