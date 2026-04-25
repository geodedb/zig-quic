# Gap Analysis

Status note (2026-04-25): this file intentionally contains only open repository-level gaps. Closed items are moved to `docs/GAP_ANALYSIS_RESOLVED.md`. The remaining entries below are unresolved and continue to be tracked by their linked open GitLab issues; large protocol/architecture items are effectively blocked on staged implementation plans and focused verification evidence.

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

### GAP-0008: Connection migration incomplete - disable_active_migration unenforced
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/137
- **Category:** Feature
- **Severity:** High
- **Requirement source:** GitLab issues #20 and #7; RFC 9000 migration and transport parameter requirements.
- **Current state (evidence):**
  - `src/quic/transport_params.zig:129`, `src/quic/transport_params.zig:212-218`, `src/quic/transport_params.zig:270-272` - `disable_active_migration` is parsed and encoded.
  - `src/quic/config.zig:15-78` - no runtime config field controls `disable_active_migration`.
  - `rg -n 'disable_active_migration|disabled_active_migration' src tests` - shows transport parameter handling and tests, but no enforcement path.
  - `tests/integration/migration.zig:146-186` - migration scenarios remain skipped/TODO.
- **Why this is a gap:** The transport parameter exists on the wire but is not enforced by endpoint migration behavior.
- **Impact/Risk:** Peers can receive policy signals that the implementation does not honor.
- **Recommended fix:** Add configuration and endpoint enforcement for active migration policy, implement migration state transitions, and enable migration tests.
- **Acceptance criteria:** `disable_active_migration` is configurable and enforced; NAT rebinding and active migration are distinguished; integration tests cover allowed and forbidden migration.

### GAP-0009: Version negotiation lacks RFC 9368 end-to-end verification
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/138
- **Category:** Feature
- **Severity:** High
- **Requirement source:** GitLab issues #7 and #32; RFC 9000 version negotiation and RFC 9368 compatible VN.
- **Current state (evidence):**
  - `src/quic/config.zig:31-32` - exposes `compatible_vn`.
  - `src/quic/endpoint/incoming.zig:311-348` - processes Version Negotiation only when `ctx.cfg.compatible_vn` is enabled and can switch between v1/v2.
  - `tests/unit/version/test_version.zig` - covers version constants and helper behavior.
  - `tests/integration/rfc9000_section7.zig:554` - marks version negotiation as partial.
- **Why this is a gap:** Unit helper coverage exists, but full endpoint compatible-VN and downgrade handling are not proven end to end.
- **Impact/Risk:** Real client/server version negotiation may fail despite helper tests passing.
- **Recommended fix:** Add endpoint and interop tests for compatible VN, original-version rejection, and downgrade detection.
- **Acceptance criteria:** Compatible VN succeeds in a real handshake; downgrade/original-version rejection cases are tested; docs describe exact VN support.

### GAP-0010: QUIC v2 packet type remapping unverified
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/139
- **Category:** Feature
- **Severity:** High
- **Requirement source:** GitLab issues #6, #7, #32; RFC 9369.
- **Current state (evidence):**
  - `src/quic/packet.zig:1013-1016` - defines `QUIC_V2` as `0x709a50c4`.
  - `src/quic/crypto_quic.zig:150-165` - defines v2 Retry secrets and labels.
  - `rg -n 'remap|packet type|QUIC_V2|quicv2|compatible_vn|Version Negotiation|shouldAcceptVersionNegotiation' src tests` - finds constants and VN tests, but no clear packet-type remapping implementation.
- **Why this is a gap:** v2 constants are present, but v2 packet type mapping and interop behavior are not evidenced.
- **Impact/Risk:** Advertising v2 support can break interop or overstate protocol support.
- **Recommended fix:** Implement or identify packet type remapping per RFC 9369 and add v2 encode/decode and handshake tests.
- **Acceptance criteria:** v2 long-header packet type mapping is unit tested; v2 handshake support is tested or explicitly unsupported; interop docs reflect actual status.

### GAP-0011: Stream state machine uses boolean flags not explicit enum
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/140
- **Category:** Feature
- **Severity:** High
- **Requirement source:** GitLab issues #23, #24, #30, #31; RFC 9000 stream state requirements.
- **Current state (evidence):**
  - `src/quic/connection/stream.zig:108-116` - `StreamTx` is `off`, `fin_sent`, `aborted`, and `peer_max_stream_data`, with no explicit state enum.
  - `src/quic/connection/methods_b.zig:620-724` - reset/stop paths mutate boolean-style state.
- **Why this is a gap:** Boolean combinations can encode invalid or ambiguous RFC stream states.
- **Impact/Risk:** FIN, RESET_STREAM, STOP_SENDING, and flow-control transitions can diverge under edge cases.
- **Recommended fix:** Introduce explicit send/receive stream state enums and transition helpers.
- **Acceptance criteria:** RFC stream states are represented by types; invalid transitions return defined errors; tests cover legal and illegal transitions.

### GAP-0012: CID lifecycle management lacks proactive issuance and rotation integration
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/141
- **Category:** Feature
- **Severity:** High
- **Requirement source:** GitLab issues #7, #20, #22; RFC 9000 connection ID lifecycle requirements.
- **Current state (evidence):**
  - `src/quic/connection/methods_c.zig:540-612` - implements CID issue/flush helpers.
  - `src/quic/connection/methods_c.zig:688-713` - implements rotating issuance when at active CID limit.
  - `rg -n 'flushPendingNewConnectionIds|issueNewConnectionIdRotating|issueNewConnectionId\(' src tests` - shows production exposure and tests, but no proactive endpoint/handshake integration call beyond manual helper usage.
- **Why this is a gap:** CID helpers exist but are not wired into normal lifecycle events.
- **Impact/Risk:** Migration and CID retirement can stall because peers may not receive replacement CIDs.
- **Recommended fix:** Wire CID issuance into handshake completion, migration preparation, and retire handling.
- **Acceptance criteria:** Endpoints proactively advertise CIDs according to limits; retirement triggers replacements when allowed; integration tests prove migration has usable CIDs.

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

### GAP-0014: Stream state machine per RFC 9000 needs explicit modeling
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/143
- **Category:** Feature
- **Severity:** High
- **Requirement source:** GitLab issues #23, #24, #30, #31; RFC 9000 stream state requirements.
- **Current state (evidence):**
  - `src/quic/connection/stream.zig:21-106` - models receive reassembly and FIN offset.
  - `src/quic/connection/stream.zig:108-116` - models transmit state with booleans.
  - `src/quic/connection/methods_b.zig:620-724` - implements reset/stop behavior outside a central state model.
- **Why this is a gap:** Stream behavior is distributed rather than governed by one explicit RFC state model.
- **Impact/Risk:** Graceful close, reset, stop-sending, read/write, and flow-control paths can disagree.
- **Recommended fix:** Create a stream state module with transition tables and route stream operations through it.
- **Acceptance criteria:** Send and receive states are explicit; RESET/STOP/FIN/read/write paths share transition helpers; tests cover transition tables.

### GAP-0015: RESET_STREAM/STOP_SENDING needs integration tests
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/144
- **Category:** Test
- **Severity:** High
- **Requirement source:** GitLab issues #24 and #31; RFC 9000 RESET_STREAM and STOP_SENDING requirements.
- **Current state (evidence):**
  - `src/quic/endpoint/frame_handler.zig:448-500` - dispatches STOP_SENDING and RESET_STREAM frames.
  - `src/quic/connection/methods_b.zig:620-724` - implements reset and stop handling.
  - `tests/integration/flow_control.zig` - 58 skipped tests remain in a stream-adjacent integration suite.
- **Why this is a gap:** Handler code exists, but real endpoint packet flow is not proven for reset/stop behavior.
- **Impact/Risk:** API, packet protection, retransmission, or flow-control sequencing bugs may remain hidden.
- **Recommended fix:** Add endpoint-level tests for peer RESET_STREAM and STOP_SENDING in both directions.
- **Acceptance criteria:** CI verifies packet emission, stream state, and application-visible behavior for RESET_STREAM and STOP_SENDING.

### GAP-0016: Loss detection edge cases untested
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/146
- **Category:** Test
- **Severity:** High
- **Requirement source:** GitLab issues #5, #7, #21, #32; RFC 9002.
- **Current state (evidence):**
  - `tests/integration/rfc9002_recovery.zig` - 5 `return error.SkipZigTest` occurrences.
  - `rg --hidden --glob '!.git/**' --glob '!.claude/worktrees/**' --glob '*.zig' -n 'return error\.SkipZigTest' tests src | wc -l` - `528` total skips.
- **Why this is a gap:** Recovery implementation cannot be considered fully verified while edge-case recovery tests are skipped.
- **Impact/Risk:** Persistent congestion, reordering, multi-space PTO, or fault-injection regressions may pass CI.
- **Recommended fix:** Enable skipped RFC 9002 tests and add targeted loss/PTO assertions.
- **Acceptance criteria:** CI covers packet-threshold loss, time-threshold loss, PTO backoff, persistent congestion, and multi-space interactions.

### GAP-0017: Two conflicting CUBIC implementations remain in tree
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/148
- **Category:** Bug
- **Severity:** High
- **Requirement source:** GitLab issues #21 and #108; congestion control implementation expectations.
- **Current state (evidence):**
  - `src/quic/recovery.zig:127-140` - legacy `Cubic` placeholder delegates to `NewReno`.
  - `src/quic/recovery/recovery.zig:446-558` - active recovery implementation includes a real CUBIC branch.
  - `src/quic/conn.zig:701-704` - keeps legacy `cc_nr` and `cc_cubic` fields marked as non-authoritative.
- **Why this is a gap:** The tree exposes both placeholder and real CUBIC surfaces.
- **Impact/Risk:** Maintainers can fix or test the wrong congestion controller.
- **Recommended fix:** Remove or quarantine the legacy placeholder and ensure imports/tests reference the authoritative recovery module.
- **Acceptance criteria:** Only one production CUBIC implementation remains reachable; legacy fields are removed or test-only; CUBIC tests assert the active path.

### GAP-0044: DPLPMTUD state is split and lacks end-to-end verification
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/151
- **Category:** Feature
- **Severity:** Medium
- **Requirement source:** GitLab issues #7, #20, #32; RFC 9000 path MTU requirements.
- **Current state (evidence):**
  - `src/quic/connection/methods_b.zig:939-995` - implements PMTUD timer/probe state handling.
  - `src/quic/connection/pmtud.zig:22-31` - defines a separate `PmtudState` struct.
  - `src/quic/conn.zig:468` - defines active connection `PmtudState` as an enum.
  - `src/quic/connection/connection.zig:53` - re-exports the struct state.
- **Why this is a gap:** Tests or callers can target a PMTUD type that production logic does not use.
- **Impact/Risk:** DPLPMTUD support status is ambiguous and can regress between modules.
- **Recommended fix:** Consolidate PMTUD state and add endpoint-level probe, ACK, and ICMP validation tests.
- **Acceptance criteria:** One PMTUD state model is used by production code and exports; tests cover probe start/search, ACK validation, ICMP handling, and the 1200-byte floor.

### GAP-0045: Path validation minimal - no timeout, retry, or multi-path probing
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/152
- **Category:** Feature
- **Severity:** Medium
- **Requirement source:** GitLab issues #7 and #20; RFC 9000 path validation and migration requirements.
- **Current state (evidence):**
  - `src/quic/connection/methods_a.zig:908-927` - seeds challenge data and marks `path_validation_pending`.
  - `src/quic/endpoint/frame_handler.zig:408-425` - clears pending state on matching PATH_RESPONSE.
  - `rg -n 'path_validation|path_challenge|PATH_RESPONSE|PATH_CHALLENGE|onPathValidated|disable_active_migration|migration' src/quic tests/integration` - shows skipped/TODO migration paths and no clear timeout/retry/failure callback implementation.
- **Why this is a gap:** Basic challenge/response exists, but validation lifecycle behavior is not complete.
- **Impact/Risk:** New paths can remain pending indefinitely or fail without visible policy handling.
- **Recommended fix:** Add path validation timers, retry limits, failure callbacks, and multi-path tracking.
- **Acceptance criteria:** PATH_CHALLENGE retry/timeout behavior is tested; failed validation prevents migration; NAT rebinding and migration scenarios have explicit tests.

### GAP-0050: H3 layer silently discards poll errors
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/159
- **Category:** Bug
- **Severity:** High
- **Requirement source:** GitLab issue #28 and closed H3 plumbing issues #132-#135.
- **Current state (evidence):**
  - `src/h3/server.zig:69` - calls `api.poll(ep, 2) catch {}`.
  - `src/h3/server.zig:219-221` - converts `api.writeStream(...)` failure to `0` and discards poll errors.
  - `src/h3/client.zig:78-80`, `src/h3/client.zig:90-93`, `src/h3/client.zig:130-132`, `src/h3/client.zig:154-158` - catch poll/write/read errors and continue or return without surfacing root cause.
- **Why this is a gap:** Transport errors are hidden from the HTTP/3 caller.
- **Impact/Risk:** Applications see timeouts or empty responses instead of actionable transport failures.
- **Recommended fix:** Propagate unexpected H3 polling/write/read errors and handle expected transient errors explicitly.
- **Acceptance criteria:** H3 tests inject a transport error and assert caller-visible failure; expected transient errors are separately handled.

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

### GAP-0057: Silent transport error paths drop critical handshake data
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/174
- **Category:** Bug
- **Severity:** High
- **Requirement source:** GitLab issues #14, #15, #32; QUIC handshake and transport parameter requirements.
- **Current state (evidence):**
  - `src/quic/connection/methods_a.zig:471-487` - converts HANDSHAKE_DONE packet encoding failure to `0`, then sets `handshake_done_sent = true`.
  - `src/quic/connection/methods_a.zig:490-495` - ignores `applyPeerTransportParameters(...)` errors and retains defaults.
  - `src/quic/endpoint/incoming.zig:821-829` - ignores `sendServerHello` and `sendHandshakePackets` failures.
- **Why this is a gap:** Critical handshake failures can be treated as success or non-fatal defaulting.
- **Impact/Risk:** Peers can stall or continue with incorrect transport parameters without observable errors.
- **Recommended fix:** Return or record transport errors for critical handshake send/apply failures; ignore only explicitly recoverable errors.
- **Acceptance criteria:** Malformed peer transport parameters fail/close correctly; HANDSHAKE_DONE is not marked sent after encode/send failure; injected failure tests assert observable errors.

### GAP-0058: Deprecated/dead transport code remains in production tree
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/175
- **Category:** Code Quality
- **Severity:** Medium
- **Requirement source:** GitLab issues #75, #103, #115.
- **Current state (evidence):**
  - `src/quic/recovery.zig:127-140` - exposes placeholder CUBIC wrapper.
  - `src/quic/connection/connection.zig:48-56` - re-exports modular types, including a PMTUD state that differs from the active enum.
  - `src/quic/conn.zig:701-704` - keeps legacy recovery fields marked non-authoritative.
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

### GAP-0062: PMTUD state is defined in incompatible forms
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/180
- **Category:** Bug
- **Severity:** Medium
- **Requirement source:** GitLab issues #32, #75, #115; RFC 9000 path MTU requirements.
- **Current state (evidence):**
  - `src/quic/connection/pmtud.zig:22-31` - defines `PmtudState` as a struct.
  - `src/quic/connection/connection.zig:53` - re-exports that struct.
  - `src/quic/conn.zig:468` - defines active connection `PmtudState` as an enum.
- **Why this is a gap:** Public/modular PMTUD type and active production PMTUD type are not the same model.
- **Impact/Risk:** API users or tests can exercise a type that production logic does not use.
- **Recommended fix:** Consolidate PMTUD state definitions and route production code through the canonical module.
- **Acceptance criteria:** One PMTUD state type is exported for production use; tests exercise the active type; dead/incompatible exports are removed or marked internal.

### GAP-0064: Core API and connection modules lack colocated tests
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/181
- **Category:** Test
- **Severity:** Low
- **Requirement source:** GitLab issues #30, #31, #32.
- **Current state (evidence):**
- **Current state (evidence):**
  - `src/quic/conn.zig` now includes focused colocated tests for `PacketBufferPool.release` and stateless reset token retirement.
  - `rg -n '^test ' src/quic/api.zig` still returns no colocated API tests.
- **Why this is a gap:** `conn.zig` now has local invariant checks, but the public API module still relies on external tests only.
- **Impact/Risk:** Helper and API invariants can regress without narrow, local diagnostics.
- **Recommended fix:** Add focused colocated tests for pure/helper behavior in `api.zig` and `conn.zig`.
- **Acceptance criteria:** `api.zig` and `conn.zig` include targeted colocated tests; external endpoint tests remain; CI runs both.
