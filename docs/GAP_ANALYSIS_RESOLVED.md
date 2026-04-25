# Resolved Gap Analysis Items

Generated: 2026-04-25

GitLab is authoritative for issue status. This file mirrors resolved or invalidated items that were removed from `docs/GAP_ANALYSIS.md`.

## Re-audited and Closed During 2026-04-25 Analysis

### GAP-0051: requirements.md contained factual inaccuracies
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/173
- **Resolution status:** Closed after this documentation update.
- **Resolution evidence:**
  - `docs/requirements.md:1-8` now states GitLab is authoritative and points to the generated mirror instead of duplicating stale implementation claims.
  - `docs/REQUIREMENTS.md:1-12` now identifies the mirror as non-authoritative and links GitLab issues.
  - `docs/REQUIREMENTS.md:14-20` records current verification caveats, including Zig 0.16.0 and 528 skipped tests.
- **Notes:** The previous all-implemented claims were removed rather than repeated.

### GitLab #189: SSLKEYLOGFILE writes TLS session keys in production builds
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/189
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/connection/methods_a.zig:36-40` gates key logging behind Debug/test builds with `builtin.mode` and `builtin.is_test`.
- **Notes:** No open gap remains for this item.

### GitLab #190: Congestion window check was log-only
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/190
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/connection/methods_b.zig:431-438` returns `0` when `bytes_in_flight >= cwnd`.
  - `rg -n 'CC-OVERRIDE' src tests` produced no current production hit during the audit.
- **Notes:** Congestion-window enforcement is no longer tracked as an open gap.

### GitLab #127: Duplicate StreamRx in conn.zig and connection/stream.zig
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/127
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/conn.zig:425-426` aliases `StreamTx` from the canonical stream module.
  - `src/quic/connection/stream.zig:21-106` contains the canonical `StreamRx` implementation.
- **Notes:** Remaining stream-state modeling issues are tracked separately as GAP-0011 and GAP-0014.

### GitLab #128: No QUIC-layer performance benchmarks in CI
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/128
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `.gitlab-ci.yml:528-538` runs `scripts/perf-gate.sh` and UDP batch smoke checks.
  - `.gitlab-ci.yml:540-590` defines a 20x stress integration benchmark job.
  - `build.zig:1868-2027` wires the benchmark suite.
- **Notes:** Performance requirements with remaining implementation gaps are tracked by open GitLab issues and relevant gaps.

### GitLab #130: ArrayList frame buffer allocation per sendDatagram
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/130
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/connection/methods_b.zig:160-168` uses a fixed stack buffer and fixed buffer writer for DATAGRAM send frame construction.
- **Notes:** No open gap remains for this allocation site.

### GitLab #131: Recovery mutex serialized congestion reads
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/131
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/recovery/recovery.zig:741-745` provides `getCongestionState()`.
  - `src/quic/connection/methods_b.zig:431-435` uses the congestion state snapshot for send-window checks.
- **Notes:** Broader recovery critical-section performance remains tracked by non-gap performance issues.

### GAP-0059: API stream-finished contract was ambiguous
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/176
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `src/quic/api.zig:328-330` documents `isStreamFinished` as RX-side completion.
  - `src/quic/api.zig:146-150` marks `closeConnection` as deprecated in favor of `Connection.close()`.
- **Notes:** No open gap remains for this API wording.

### GAP-0063: H3 varint codec was duplicated
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/179
- **Resolution status:** Closed.
- **Resolution evidence:**
  - `rg -n 'pub fn encodeVarint|pub fn decodeVarint|fn encodeVarint|fn decodeVarint' src/h3 src/quic` returns H3 varint definitions in `src/h3/varint.zig` only for the H3 layer.
- **Notes:** H3 error propagation remains open as GAP-0050.

### GitLab #184: readStreamUnlocked shifted inbox on every read
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/184
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `src/quic/connection/stream.zig` now tracks `StreamRx.inbox_read_off` and exposes `readInto()`; `src/quic/connection/methods_b.zig` and `src/quic/connection/methods_c.zig` use cursor reads instead of per-read `copyForwards` shifts.
- **Verification:** `zig build -Dtest-filter=stream_edges test` exited `0`.

### GitLab #185: remaining orderedRemove call sites in src/quic
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/185
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `rg -n "orderedRemove" src/quic` returns no matches. Timer, retired-list, and stream-buffer removals use `swapRemove`; `src/quic/conn.zig` now stores stateless reset tokens as `ResetTokenEntry{ sequence, token }` so retire-prior-to semantics survive unordered removal.
- **Verification:** `zig build -Dtest-filter=packet_pool test` exited `0`.

### GitLab #186: StreamRx tryDrain O(N^2) worst case
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/186
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `src/quic/connection/stream.zig` sorts buffered segments by offset and drains them in one compaction pass.
- **Verification:** `zig build -Dtest-filter=stream_edges test` exited `0`.

### GitLab #187: PacketBufferPool.release linear scan
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/187
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `src/quic/conn.zig` computes the packet-pool slot index from pointer offset with bounds and alignment checks instead of scanning 16 slots.
- **Verification:** `zig build -Dtest-filter=packet_pool test` exited `0`.

### GAP-0065: Interop Docker image baked static test certificates
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/193
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `interop/Dockerfile` no longer copies `tests/certs/cert.pem` or `tests/certs/key.pem`; `interop/run_endpoint.sh` generates ephemeral fallback TLS material at startup; `interop/README.md` documents the runtime-generated fallback.
- **Verification:** `bash -n interop/run_endpoint.sh` exited `0`.

### GAP-0066: Crypto debug global mutable state needed thread-local/local storage
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/194
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `src/quic/packet.zig` uses `threadlocal` test-only debug state and `src/quic/crypto_quic.zig` uses function-local Retry tag temporary ciphertext storage.

### GAP-0050: H3 layer silently discarded poll/read/write errors
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/159
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/h3/server.zig:36-52` returns `!void` from `serveConnection` and propagates control/QPACK stream open/write failures.
  - `src/h3/server.zig:65-84` propagates `api.poll` failures and non-`WouldBlock` read failures instead of swallowing them.
  - `src/h3/server.zig:207-218` and `src/h3/client.zig:84-95` retry only bounded transient transport write errors and return unexpected failures.
  - `src/h3/client.zig:123-148` propagates H3 control/QPACK open/write/poll failures to the caller.
  - `cmd/qns-endpoint.zig:768-772` logs H3 serve failures from the QNS endpoint instead of ignoring them.
- **Verification:**
  - `zig build -Dtest-filter=h3_error test` exited `0`.
  - `zig build -Dtest-filter=h3_loopback test` exited `0`; output included `[h3] request stream=0 path=/index.html` and `[h3] response stream=0 sent`.
- **Notes:** The loopback test fixture now supplies embedded test server certificate material and polls until accept so it exercises the real server endpoint path.

### GAP-0064: Core API and connection modules lacked colocated tests
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/181
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/api.zig:428-450` adds a colocated test for handshake completion versus confirmation state.
  - `src/quic/api.zig:452-475` adds a colocated test proving `pollReady` reports cached readiness without mutating queues.
  - `src/quic/conn.zig` already contains focused colocated coverage for packet-pool release and stateless reset token retirement from the previous closure pass.
  - `build.zig:877-906` wires a focused `-Dtest-filter=api_colocated` target for `src/quic/api.zig`.
- **Verification:** `zig build -Dtest-filter=api_colocated test` exited `0`.

### GAP-0008: Connection migration incomplete - disable_active_migration unenforced
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/137
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/config.zig:31-35` exposes `QuicConfig.disable_active_migration`.
  - `src/quic/endpoint/handshake_integration.zig` writes the configured value into client/server transport parameters and records `disable_active_migration_advertised`.
  - `src/quic/connection/methods_c.zig:528` records peer `disable_active_migration`.
  - `src/quic/endpoint.zig:1417-1421` rejects peer address changes after advertising `disable_active_migration`.
  - `tests/test_disable_active_migration.zig:12-83` covers transport-parameter encoding, endpoint address-change rejection, and peer parameter recording.
- **Verification:** `zig build -Dtest-filter=disable_active_migration test` exited `0`.
- **Notes:** Broader multipath/CID lifecycle work remains tracked separately by GAP-0012 and GAP-0045.

### GAP-0010: QUIC v2 packet type remapping unverified
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/139
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/packet.zig:59-96` defines version-aware long-header packet type mapping for QUIC v1 and v2.
  - `src/quic/packet.zig:553-580`, `src/quic/packet.zig:1165-1178`, and `src/quic/packet.zig:1252-1289` use the mapping in Initial, 0-RTT, and Retry paths.
  - `src/quic/endpoint.zig:1400-1407` dispatches long-header packets through the version-aware packet kind.
  - `tests/test_quic_v2_packet_types.zig:10-58` covers v1/v2 type decoding plus v2 Initial, Handshake, 0-RTT, and Retry encoding/verification.
- **Verification:** `zig build -Dtest-filter=v2_packet_types test` exited `0`.

### GAP-0044: DPLPMTUD state is split and lacks end-to-end verification
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/151
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/connection/pmtud.zig:10-28` now owns the canonical DPLPMTUD phase enum.
  - `src/quic/conn.zig:29-32` exports the connection PMTUD state from the canonical module instead of a local duplicate.
  - `tests/unit/connection/test_pmtud.zig:16-46` verifies the canonical state model.
  - `tests/test_pmtud.zig:32-40` verifies the active connection implementation exports and uses the same PMTUD state model.
- **Verification:** `zig build -Dtest-filter=pmtud test` exited `0`.

### GAP-0057: Silent transport error paths drop critical handshake data
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/174
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/connection/methods_a.zig:177-218` sends HANDSHAKE_DONE through `sendHandshakeDoneControl()` and only marks it sent after encode and send succeed.
  - `src/quic/connection/methods_a.zig:488-498` now propagates peer transport-parameter apply/cache errors instead of swallowing them.
  - `src/quic/connection/methods_c.zig:462-470` returns malformed transport parameter errors without setting `transport_params_applied`.
  - `src/quic/endpoint/incoming.zig:765-768` records non-duplicate Initial CRYPTO failures; `src/quic/endpoint/incoming.zig:824-833` records ServerHello/Handshake packet send failures.
  - `tests/test_handshake_error_propagation.zig:12-39` injects HANDSHAKE_DONE send failure and malformed transport parameters.
- **Verification:** `zig build -Dtest-filter=handshake_error test` exited `0`.

### GAP-0062: PMTUD state is defined in incompatible forms
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/180
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/connection/pmtud.zig:10-28` provides a single canonical `PmtudState` enum.
  - `src/quic/conn.zig:29-32` aliases `PmtudState` from the canonical module.
  - `tests/unit/connection/test_pmtud.zig:16-46` and `tests/test_pmtud.zig:32-40` prove tests and active connection code use the same state model.
- **Verification:** `zig build -Dtest-filter=pmtud test` exited `0`.

## Previously Closed Gap Issues

The following issues are closed in GitLab and were not reopened during the 2026-04-25 audit. Where implementation evidence was not re-collected in this pass, the resolution evidence is the GitLab closed state.

- **Governance boundary:** CI/CD external-tool hash/toolchain pinning (#54), Docker tag/digest pinning (#55), and pre-commit hook pinning/enforcement are intentionally not repo-local implementation gaps. #54 and #55 are closed as won't-do under external controls; pre-commit enforcement is also externalized unless governance ownership changes.
- **GAP-0001:** https://gitlab.com/devnw/zig/quic/-/issues/84 - build break. Current command evidence: `zig build test` exited `0` on 2026-04-25, with the CA-certificate diagnostic recorded in `docs/REQUIREMENTS.md`.
- **GAP-0002:** https://gitlab.com/devnw/zig/quic/-/issues/85 - stale RESET_STREAM/STOP_SENDING docs. Current related implementation evidence: `src/quic/endpoint/frame_handler.zig:448-500` and `src/quic/connection/methods_b.zig:620-724`.
- **GAP-0003:** https://gitlab.com/devnw/zig/quic/-/issues/86 - STREAMS_BLOCKED response handling. Status evidence: GitLab issue is closed.
- **GAP-0005:** https://gitlab.com/devnw/zig/quic/-/issues/91 - old `module_c.zig` NotImplemented path. Status evidence: GitLab issue is closed.
- **GAP-0006:** https://gitlab.com/devnw/zig/quic/-/issues/92 - stale triage labels. Status evidence: GitLab issue is closed.
- **GAP-0018:** https://gitlab.com/devnw/zig/quic/-/issues/149 - Retry integrity tag timing-safe comparison. Current evidence: `src/quic/packet.zig:1267` uses `std.crypto.timing_safe.eql`.
- **GAP-0047:** https://gitlab.com/devnw/zig/quic/-/issues/155 - misleading frame handler comment. Status evidence: GitLab issue is closed.
- **H3 plumbing issues:** https://gitlab.com/devnw/zig/quic/-/issues/132, https://gitlab.com/devnw/zig/quic/-/issues/133, https://gitlab.com/devnw/zig/quic/-/issues/134, https://gitlab.com/devnw/zig/quic/-/issues/135 - closed in GitLab. Remaining H3 adapter gap is GAP-0050.
