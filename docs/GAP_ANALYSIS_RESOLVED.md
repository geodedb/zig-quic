# Resolved Gap Analysis Items

Generated: 2026-04-26 (GitLab closures landed 2026-04-27)

GitLab is authoritative for issue status. This file mirrors resolved or invalidated items that were removed from `docs/GAP_ANALYSIS.md`.

## Closed During 2026-04-26 Implementation Pass

### GAP-0007: Crypto hardening audit incomplete
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/136 (closed 2026-04-27, closure note `note_3289087096`)
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `docs/CRYPTO_AUDIT.md` maps current QUIC crypto-sensitive operations to code and tests.
  - `src/quic/crypto_quic.zig:158-196` now derives Retry key/IV with fallible `try` calls, validates ODCID length, bounds the Retry pseudo-packet AAD, and returns explicit errors instead of using `catch unreachable`.
  - `src/quic/connection/key_update.zig:1-14` centralizes RFC 9001 Section 6 `"quic ku"` derivation as a fallible helper.
  - `src/quic/connection/methods_b.zig:1584-1628`, `src/quic/connection/methods_c.zig`, `src/quic/endpoint/handshake_integration.zig`, and `src/quic/endpoint/incoming/module_b.zig` now use the canonical key-update helper instead of duplicate local derivation helpers.
  - `rg -n "catch unreachable|unreachable" src/quic/crypto_quic.zig src/quic/connection src/quic/endpoint/handshake_integration.zig src/quic/endpoint/incoming/module_b.zig src/quic/packet.zig` only matched the explanatory comment in `src/quic/connection/key_update.zig:8`.
- **Verification:** `zig build test --summary failures` exited `0`; `zig build -Dfull-test-graph=true test --summary failures` exited `0` during the implementation pass; `make interop-full` exited `0` with `105` passed, `0` failed, `50` implementation/harness skips. Full advanced crypto lifecycle coverage remains open in GAP-0013 / #142.

### GAP-0055: Pre-Retry connection allocation exhaustion
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/188 (closed 2026-04-27, closure note `note_3289087653`)
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/endpoint/incoming.zig:379-386` parses Initial token bytes before any new server connection allocation.
  - `src/quic/endpoint/incoming.zig:438-483` validates Retry tokens and sends stateless Retry before `max_connections` checks and before `createServerConnection(...)`.
  - `src/quic/endpoint/incoming.zig:502-508` passes verified Retry state into server creation only after token validation.
  - `src/quic/endpoint/server.zig:338-340` restores the Retry SCID as the accepted server connection's local CID after a validated Retry.
  - `tests/test_retry.zig:62-70` proves first Retry does not create an accepted/server connection; `tests/test_retry.zig:211-218` proves a validated Retry proceeds with restored SCID and ODCID.
- **Verification:** `zig build test --summary failures` exited `0`; `zig build -Dfull-test-graph=true test --summary failures` exited `0` during the implementation pass; `make interop-full` exited `0` with `105` passed, `0` failed, `50` implementation/harness skips.

### GitLab #157: Compiled Go binaries with Critical CVEs committed to repository
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/157
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - Removed tracked native test-client binaries: `test-clients/legacy-clients/go/test-client`, `test-clients/quic-test-legacy/test-client`, `test-clients/quic-test-legacy/test-client-comprehensive`, `test-clients/quic-test-legacy/test-client-xnet`, `test-clients/quic-test-legacy/test_client`, and `test-clients/quic-test-legacy/test_comprehensive`.
  - `.gitignore:81-89` now ignores rebuilt local Go test-client binaries.
  - `scripts/check-no-committed-binaries.sh:18-37` rejects tracked ELF/Mach-O/PE native binaries.
  - `.gitlab-ci.yml:714-726` runs the committed-binary gate in CI.
- **Verification:** `scripts/check-no-committed-binaries.sh` exited `0`; standalone Go client builds succeeded to `/tmp`.

### GitLab #59: Go toolchain/module vulnerability scan drift
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/59
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - Go modules now declare `go 1.25.0` and `toolchain go1.26.2`: `examples/interop/go.mod:3-5`, `test-clients/legacy-clients/go/go.mod:3-5`, `test-clients/quic-test-legacy/go.mod:3-5`, `test-clients/quic-test-legacy/xnet-quic/go.mod:3-5`, `test-clients/quic-go-client/go.mod:3-5`.
  - `.gitlab-ci.yml:745-766` runs govulncheck through the configured Go toolchain and keeps binary-mode coverage for standalone files in `test-clients/quic-test-legacy`.
- **Verification:** `GOTOOLCHAIN=go1.26.2 go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...` exited `0` for `examples/interop`, `test-clients/quic-test-legacy/xnet-quic`, `test-clients/quic-go-client`, and `test-clients/legacy-clients/go`; binary-mode govulncheck exited `0` for `client.go`, `server.go`, `test_client.go`, and `test_client_comprehensive.go`.

### GitLab #57: Python dependency specs remained unpinned
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/57
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `clients/python/requirements.txt:2-6` pins `aioquic==1.3.0`, `pytest==9.0.3`, and `pytest-asyncio==1.3.0`.
  - `test-clients/aioquic-client/requirements.txt:1` and `test-clients/legacy-clients/python/requirements.txt:1` pin `aioquic==1.3.0`.
  - `.gitlab-ci.yml:728-743` adds a Safety job over all tracked Python requirement files.
- **Verification:** Safety `check --full-report` exited `0` for all three requirement files; Python clients compiled under a clean `/tmp/quic-aioquic-venv`.

### GitLab #196: Interop clients disabled TLS verification and wrote TLS key logs by default
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/196
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `test-clients/quic-go-client/main.go:19-39` makes `-insecure` and `-keylog` explicit opt-ins.
  - `test-clients/quic-test-legacy/test_client.go:17-32`, `test_client_comprehensive.go`, and `xnet-quic/client.go` use the explicit `-insecure` flag and only write key logs when `-keylog` or `SSLKEYLOGFILE` is set.
  - `clients/python/test_client.py:61-66` and `test-clients/aioquic-client/test_client.py:61-66` default to certificate verification and only set `ssl.CERT_NONE` for `--insecure`.
  - `.gitlab-ci.yml:248` and `.gitlab-ci.yml:294`, `Makefile`, and `test-clients/run-tests.sh` now pass `--insecure` only in local/self-signed test paths.
- **Verification:** Go standalone builds succeeded; Python clients compiled under `/tmp/quic-aioquic-venv`; `rg -n 'InsecureSkipVerify:\s*true|verify_mode\s*=\s*0|os\.Create\("/tmp/tls_keys|insecure\s*=.*true' test-clients clients` has no active insecure-default/keylog-default hits.

### GitLab #195: Rust test clients carried rustls-webpki advisories and CI missed quinn-client audit
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/195
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `clients/rust/Cargo.lock:535-538`, `test-clients/legacy-clients/rust/Cargo.lock`, and `test-clients/quinn-client/Cargo.lock:672-675` now use `rustls-webpki 0.103.13`.
  - `.gitlab-ci.yml:710-712` audits `clients/rust`, `test-clients/legacy-clients/rust`, and `test-clients/quinn-client`.
- **Verification:** `cargo audit` exited `0` in all three Rust client directories. `test-clients/quinn-client` still prints two allowed informational `rand` warnings, but no failing vulnerability remains.

### GitLab #197: Secret scanners flagged public RFC private-key examples
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/197
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `.semgrepignore:1-4` excludes only the two public RFC text files with published PEM examples.
  - `trivy-secret.yaml:1-8` adds a narrow Trivy secret allow rule for `rfc7468.txt` and `rfc8410.txt`.
- **Verification:** `trivy fs --scanners secret --secret-config trivy-secret.yaml --skip-db-update --format json specs/x509` reported `0` secrets; `semgrep scan --config p/secrets --metrics=off --include 'specs/x509/*.txt' .` reported `0` findings and explicitly skipped the two `.semgrepignore` paths.

### GAP-0056 / GitLab #191: QNS container runtime user hardening needed verification
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/191
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `examples/interop/zig-qns/run_endpoint.sh:37-58` and `interop/run_endpoint.sh` now fail closed if root cannot drop privileges with `setpriv`, unless `INTEROP_ALLOW_ROOT_ENDPOINT=1` is explicitly set for local debugging.
  - `examples/interop/zig-qns/run_endpoint.sh:111-114` adds `INTEROP_PRIVILEGE_CHECK=1` to prove the drop target without running simulator setup.
  - `.gitlab-ci.yml:448-449` builds `zig-qns:local` and asserts the privilege check returns `quic`.
- **Verification:** `docker build -f examples/interop/zig-qns/Dockerfile -t zig-qns:local .` and `docker run --rm -e INTEROP_PRIVILEGE_CHECK=1 zig-qns:local` exited `0` with output `quic`; ShellCheck passed for both endpoint scripts.

### GitLab #198: Interop shell command variables relied on word splitting
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/198
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `scripts/interop_control_test.sh:59-119` now stores the Docker Compose invocation in a Bash array and invokes it as `"${COMPOSE[@]}"`.
- **Verification:** `shellcheck -x scripts/interop_control_test.sh scripts/check-no-committed-binaries.sh` exited `0`.

### GitLab #43: Developer shell helper exported tokens into child-process environment
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/43
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:** `scripts/devshell_auth.sh:12-14`, `scripts/devshell_auth.sh:26-29`, `scripts/devshell_auth.sh:40-51` now emit an explicit warning whenever credentials are exported into the current shell.
- **Verification:** `bash -n scripts/devshell_auth.sh` and `shellcheck -x scripts/devshell_auth.sh` exited `0`.

### GAP-0058: Deprecated/dead transport code remained in production tree
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/175
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/connection/methods_a.zig:1162-1172` no longer contains the legacy stream-0 compatibility block that updated flow-control state without emitting a frame.
  - `src/quic/connection/methods_c.zig:578-585` replaces the stale placeholder CID issuance comment with the active pending-advertisement behavior.
- **Verification:** `zig build test --summary failures` exited `0`.

### GAP-0061: QUIC minimum datagram size literal was duplicated in config default
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/178
- **Resolution status:** Closed / Implemented for the tracked production default.
- **Resolution evidence:** `src/quic/config.zig:11-14` names the RFC 9000 §14.1 floor as `MIN_INITIAL_DATAGRAM_SIZE`; `src/quic/config.zig:48-49` uses that named constant for the `max_datagram_size` default.
- **Verification:** `zig build test --summary failures` exited `0`. Remaining `1200` literals in `src/quic` are protocol comments, test data, recovery defaults, or path/packet-size handling sites outside the tracked `config.zig` default.

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
- **Notes:** Explicit stream-state modeling is now closed as GAP-0011 and GAP-0014.

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
- **Notes:** CID lifecycle and path-validation timeout/retry work are now closed as GAP-0012 and GAP-0045.

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

### GAP-0009: Version negotiation lacks RFC 9368 end-to-end verification
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/138
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `tests/test_version_negotiation.zig:181-268` drives a compatible-VN selection from a grease initial version to QUIC v1, retransmits a real Initial through UDP endpoints, accepts the server connection, and asserts both endpoints completed the TLS handshake and negotiated ALPN.
  - `tests/test_version_negotiation.zig:186-198` configures compatible VN on both endpoints and uses embedded test certificate material so the server endpoint is a real server role.
  - `src/quic/endpoint/incoming.zig:284-348` validates VN acceptance, selects v1/v2, updates the connection version, and calls the Initial probe callback.
- **Verification:** `zig build -Dtest-filter=version_negotiation test` exited `0`.

### GAP-0011: Stream state machine uses boolean flags not explicit enum
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/140
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/connection/stream.zig:13-41` defines explicit RFC 9000 send and receive state enums.
  - `src/quic/connection/stream.zig:125-149` transitions receive state through FIN/final-size handling and reset handling.
  - `src/quic/connection/stream.zig:199-235` routes transmit writes, FIN, and reset through explicit state helpers.
- **Verification:** `zig build -Dtest-filter=streams test` exited `0`.

### GAP-0012: CID lifecycle management lacks proactive issuance and rotation integration
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/141
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/connection/methods_c.zig:548-576` adds proactive local CID supply filling up to the peer active connection ID limit.
  - `src/quic/connection/methods_c.zig:640-675` triggers replacement CID issuance after `RETIRE_CONNECTION_ID` frees capacity.
  - `src/quic/connection/methods_a.zig:177-195` piggybacks pending `NEW_CONNECTION_ID` frames in server handshake-completion control packets.
  - `tests/test_connection_id_retire_and_reissue.zig:40-63` proves proactive filling and replacement after retirement.
- **Verification:** `zig build -Dtest-filter=connection_id test` exited `0`.

### GAP-0014: Stream state machine per RFC 9000 needs explicit modeling
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/143
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/connection/stream.zig:13-41` models RFC 9000 send/receive stream states explicitly.
  - `src/quic/connection/methods_b.zig:619-624` records graceful FIN as `DataSent`.
  - `src/quic/connection/methods_b.zig:635-680` records local reset as `ResetSent`.
  - `src/quic/connection/methods_b.zig:732-740` records received reset as `ResetRead`.
- **Verification:** `zig build -Dtest-filter=streams test` exited `0`.

### GAP-0015: RESET_STREAM/STOP_SENDING needs integration tests
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/144
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/connection/methods_b.zig:635-680` sends `RESET_STREAM` and updates stream TX state.
  - `src/quic/connection/methods_b.zig:682-727` handles `STOP_SENDING` by emitting `RESET_STREAM` with the correct final size.
  - `tests/test_stream_flow_control.zig:232-268` proves `RESET_STREAM` trims buffered data beyond final size and blocks future reads.
  - Focused stream/reset API tests cover packet emission and state transitions for reset/stop paths.
- **Verification:** `zig build -Dtest-filter=streams test` exited `0`.

### GAP-0016: Loss detection edge cases untested
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/146
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `tests/test_recovery_protocol_gaps.zig:5-27` verifies application PTO expiry sends a probe and accounts bytes in flight.
  - `tests/test_recovery_protocol_gaps.zig:29-41` verifies ACK-only packets do not reset PTO backoff.
  - `tests/test_recovery_protocol_gaps.zig:43-63` verifies packet-number gaps trigger threshold loss.
  - `tests/test_recovery_protocol_gaps.zig:65-88` verifies ACK delay affects RTT samples and underutilized congestion window suppresses pacing delay.
- **Verification:** `zig build -Dtest-filter=loss_edge test` exited `0`.

### GAP-0017: Two conflicting CUBIC implementations remain in tree
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/148
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/recovery.zig:127-128` now re-exports the authoritative `recovery/congestion.zig` CUBIC implementation instead of a NewReno placeholder wrapper.
  - `src/quic/conn.zig:680-710` no longer carries the legacy `cc_nr` and `cc_cubic` fields.
  - `src/quic/connection/methods_c.zig` no longer double-counts sent packets through the legacy congestion path.
- **Verification:** `zig build -Dtest-filter=loss_edge test` exited `0`.

### GAP-0045: Path validation minimal - no timeout, retry, or multi-path probing
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/152
- **Resolution status:** Closed / Implemented.
- **Resolution evidence:**
  - `src/quic/conn.zig:755-772` tracks path-validation attempts, maximum attempts, deadline, and failed state.
  - `src/quic/connection/methods_a.zig:939-999` starts PATH_CHALLENGE probes with retry deadlines and emits probes immediately on the new path.
  - `src/quic/connection/methods_a.zig:1005-1034` clears validation only for matching PATH_RESPONSE and advances timeout retry/failure progression.
  - `src/quic/endpoint/frame_handler.zig:415-420` delegates PATH_RESPONSE handling to connection validation state.
  - `tests/test_path_validation.zig:336-395` covers timeout retry/failure and matching response cleanup.
- **Verification:** `zig build -Dtest-filter=path_validation test` exited `0`.

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

## Closed During 2026-04-27 Performance Unblock Pass

### GAP-0053: Endpoint receive lock-scope proof incomplete
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/126
- **Resolution status:** Closed / Implemented (2026-04-27).
- **Resolution evidence:**
  - Per-datagram lock release in `src/quic/endpoint.zig:848-856` was already in place.
  - New `concurrent_independent_progress` variant in `benchmarks/integration/datagram_batch.zig:572` (32 flooders × 4096-packet budget) is the missing concurrent-receive regression evidence.
  - Existing `batch_1`, `batch_16`, `batch_64` variants cover the original tail-latency scaling story and remain green.

### GitLab #154: O(N) connection lookup per packet
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/154
- **Resolution status:** Closed / Implemented (2026-04-27).
- **Resolution evidence:**
  - 8-byte DCID fast path lands at `src/quic/endpoint/lookup.zig:139` ahead of the candidate-length sweep.
  - The candidate-length sweep skips `DEFAULT_DCID_LEN` when `tried_default` is set, avoiding the redundant lookup.
  - `connection_lookup` micro-bench covers 10/100/1K/10K variants; perf-gate run on 2026-04-27 shows 10K p99 = 443 ns within sample variance of pre-pass HEAD baseline.

### GitLab #158: Pacing timer truncated to 1ms granularity
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/158
- **Resolution status:** Closed / Implemented (2026-04-27).
- **Resolution evidence:**
  - `src/quic/endpoint/types.zig:21` adds `Timer.deadline_ns_extra: u32` for sub-millisecond residual.
  - `src/quic/endpoint.zig:103-115` adds `nowNsMonotonic` and `timerExpired(deadline_ms, deadline_ns_extra, now_ms, now_ns)` helpers.
  - `schedulePaced` (`endpoint.zig:741-769`) stores ns precision; `processExpiredTimers` checks ns when `deadline_ns_extra > 0`.
  - `senderPaced` inline-send threshold tightened from 1 ms to 10 µs since timer scheduling now has true ns precision.
  - `tests/test_pmtud.test.pmtud pacing: paced send occurs under NewReno and CUBIC when cwnd is partially full` passes with the updated atomic-mirror refresh.

### GitLab #160: Recovery mutex critical section blocks congestion reads
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/160
- **Resolution status:** Closed / Implemented (2026-04-27).
- **Resolution evidence:**
  - `src/quic/recovery/recovery.zig:157-211` adds `cwnd_atomic`, `bytes_in_flight_atomic`, `smoothed_rtt_atomic`, `mds_atomic` lock-free reader mirrors with `.acquire`/`.release` ordering.
  - Public `cwndSnapshot()`, `bytesInFlightSnapshot()`, `smoothedRttSnapshot()`, `mdsSnapshot()` getters never block on `mutex`.
  - Mutating methods (`onPacketSent`, `onAckReceivedWithEcn`, `onLossTimeExpired`, `setMds`, `setCcMode`) call `refreshAtomicMirrors()` via LIFO defer so updates land before mutex release.
  - `senderPaced` (`src/quic/endpoint.zig:1717`) reads pacing inputs via the snapshot getters — pacing path no longer contends on `recovery.mutex` with ACK processing.
  - 4 atomic-mirror unit tests pass (`recovery: atomic mirrors track cc.cwnd and bytes_in_flight after onPacketSent` etc.).

### GitLab #172: ECN platform validation incomplete (in-repo)
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/172
- **Resolution status:** Closed / Implemented in-repo (2026-04-27); multi-platform CI runner provisioning remains *BLOCKED-EXTERNAL*.
- **Resolution evidence:**
  - `src/quic/endpoint/udp_transport.zig` now has explicit `builtin.target.os.tag` branches in `recvFn`, `sendFn`, `pollFn`, `closeFn`, `init`/`initPosix`, `deinit`.
  - New `posixSendTo` and `posixRecvFrom` helpers use `std.posix` for cross-platform fallback; `recvBatchFallback` and `sendBatchFallback` updated to use these helpers.
  - `docs/PLATFORM_SUPPORT.md` documents the support matrix (Linux full ECN; macOS/BSD posix fallback returning null ECN; Windows not supported by this transport).
  - Inline tests verify Linux runtime path and force compile-time symbol resolution of the posix fallback (`udp_transport: posix fallback symbols compile under non-linux branch`).

### GitLab #182: Timer O(N) + PTO polling per poll cycle
- **GitLab issue:** https://gitlab.com/devnw/zig/quic/-/issues/182
- **Resolution status:** Closed / Implemented (2026-04-27).
- **Resolution evidence:**
  - `Endpoint.pto_dirty_set` (hashset of *Connection) tracks the dirty subset.
  - `Endpoint.pto_dirty_count` (atomic u32) short-circuits the drain when no connection is dirty — poll-loop overhead is zero in the steady-state idle path.
  - `Endpoint.pto_dirty_mu` is a dedicated leaf mutex separate from `mu` so `Connection.markPtoDirty()` callers don't need to acquire `mu` (avoiding the existing `endpoint.mu -> conn.mu` lock-order rule).
  - `Connection.markPtoDirty()` (in `src/quic/conn.zig`) is the canonical setter — sets `pto_dirty = true` and notifies the endpoint via `pto_dirty_notify_fn` only on the false→true transition (idempotent, no double-add).
  - All 6 prior `self.pto_dirty = true` sites in `methods_b.zig` and `methods_c.zig` now call `self.markPtoDirty()`; the `init` site (line 1078) keeps direct assignment because the connection isn't endpoint-registered yet.
  - Poll-loop drain at `src/quic/endpoint.zig:891-921` uses `pto_dirty_set` instead of iterating `conns`.
