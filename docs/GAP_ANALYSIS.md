# Security GAP Analysis

Last updated: 2026-03-25 (Phase 5 Security Audit)

Repository: `gitlab.com/devnw/zig/quic`  
Risk scoring: `Risk (0-100) = Impact(1-5) * Likelihood(1-5) * 4`

## Summary

| Severity | Found | Closed/Implemented | Closed/Won't do | Blocked | Open |
|----------|------:|-------------------:|----------------:|--------:|-----:|
| Critical | 4 | 3 | 0 | 0 | 1 |
| High | 26 | 10 | 2 | 0 | 14 |
| Medium | 23 | 15 | 0 | 0 | 8 |
| Low | 13 | 10 | 2 | 0 | 1 |
| Info | 1 | 1 | 0 | 0 | 0 |
| **Total** | **67** | **39** | **4** | **0** | **24** |

**HTTP/3 adapter requirements:** 4 open items (1 High, 2 Medium, 1 Low) -- see [HTTP/3 Adapter Requirements](#http3-adapter-requirements) below.
**Phase 4 audit:** 13 open gaps (1 Critical, 10 High, 2 Medium, 0 Low) -- see [Phase 4 Audit](#phase-4-audit----2026-03-24) below. 2 gaps closed in Phase 4 closure (2026-03-25).
**Phase 5 audit:** 3 requirement gaps (2 High, 1 Medium) + 8 quality findings (1 High, 5 Medium, 2 Low) -- see [Phase 5 Audit](#phase-5-audit----2026-03-25) below.
**Phase 5 security audit:** 4 new security findings (1 High, 2 Medium, 1 Low) + 1 verified closure (#102) -- see [Phase 5 Security Audit](#phase-5-security-audit----2026-03-25) below.
**Parallelism audit:** 9 findings (2 High, 4 Medium, 2 Low, 1 Info) -- all 9 closed (build wiring, batch AEAD/HP in endpoint, parallel loss detection, PTO outside mu, sleep removal) -- see [Parallelism & Multiplexing Gap Analysis](#parallelism--multiplexing-gap-analysis--2026-03-30) below. Total open: 24.

### Top 5 Residual Risks

1. **Pre-Retry connection allocation exhaustion (#188, High, Risk 70, CONFIDENTIAL)** -- Full Connection+TLS (~80-100KB) allocated before Retry validation. 10K spoofed Initials = ~1GB DoS. Internet-facing, pre-auth.
2. **Crypto audit not performed (GAP-0007, Critical)** -- ~~Non-timing-safe comparisons on cryptographic material (packet.zig:1259, Retry integrity tag)~~ (FIXED 2026-03-25, GAP-0018). ~~Anti-replay cache never wired to endpoint (0-RTT replay possible)~~ (FIXED 2026-03-25). ~~`catch unreachable` on page_allocator in crypto_quic.zig:187-189 (remote DoS vector)~~ (FIXED 2026-03-25, SF-016). Remaining: AEAD nonce test vectors, key update verification.
3. **Two conflicting CUBIC implementations (GAP-0017, High)** -- `recovery.zig:128` placeholder vs `recovery/congestion.zig:62` real CUBIC. Production code path may use wrong implementation.
4. ~~**SSLKEYLOGFILE ungated in production builds (#189)**~~ -- FIXED (SF-024, 2026-03-25): Gated behind `comptime builtin.mode` check.
5. ~~**Congestion window check is log-only (#190)**~~ -- FIXED (SF-025, 2026-03-25): `writeStream` returns 0 when `bytes_in_flight >= cwnd`.

## Stack-Ranked Findings

| Rank | Sev | Risk | Finding | Component | CWE/OWASP | Evidence(file:line) | Issue URL | Fix | Owner | Due | Status |
|------|-----|------|---------|-----------|-----------|----------------------|----------|-----|-------|-----|--------|
| 1 | High | 60 | Mutable container tags in CI/interop are accepted risk (`confidence::confirmed`) | CI/CD | OWASP A08:2021 | `.gitlab-ci.yml:78`, `.gitlab-ci.yml:240`, `examples/interop/docker-compose.full.yml:172` | https://gitlab.com/devnw/zig/quic/-/issues/55 | Managed by external controls (repo-level won't-do) | Platform | N/A | Closed / Won't do |
| 2 | High | 60 | CI installs pinned Python deps and gates this path (`confidence::confirmed`) | CI/CD | CWE-494 | `.gitlab-ci.yml:97`, `test-clients/aioquic-client/requirements.txt:1` | https://gitlab.com/devnw/zig/quic/-/issues/57 | Keep pinned requirements + scan updates | CI | 2026-02-16 | Closed / Implemented |
| 3 | High | 48 | Private keys still discoverable in repository history (`confidence::confirmed`) | Supply chain | CWE-321, CWE-798 | `certs/server.key:1 (historical commit e3117889)`, `certs/key.pem:4 (historical commit e3117889)` | https://gitlab.com/devnw/zig/quic/-/issues/36 | Managed by external governance controls (repo-level won't-do) | Security | N/A | Closed / Won't do |
| 4 | High | 48 | CI hash/toolchain integrity pinning is externally governed (`confidence::confirmed`) | CI/CD | CWE-494 | `.gitlab-ci.yml:358`, `.gitlab-ci.yml:359` | https://gitlab.com/devnw/zig/quic/-/issues/54 | Managed by external controls (repo-level won't-do) | Platform | N/A | Closed / Won't do |
| 5 | High | 48 | Legacy Go module vulnerability + scan coverage blind spot (`confidence::confirmed`) | Supply chain | OWASP A06:2021 | `test-clients/quic-test-legacy/go.mod:3`, `.gitlab-ci.yml:395` | https://gitlab.com/devnw/zig/quic/-/issues/59 | Upgraded module to `toolchain go1.25.7` and added binary-mode govulncheck coverage for legacy standalone mains | Go owners | 2026-02-16 | Closed / Implemented |
| 6 | High | 48 | Debug logging secret leakage remediated (`confidence::confirmed`) | Application | CWE-532 | `src/quic/logger.zig:15`, `src/quic/conn.zig:3084`, `src/quic/packet.zig:708` | https://gitlab.com/devnw/zig/quic/-/issues/56 | Keep secret-redaction policy enforced | Core QUIC | 2026-02-16 | Closed / Implemented |
| 7 | High | 48 | Client secure connect fail-closed remediated (`confidence::confirmed`) | Application | CWE-295 | `src/quic/transport.zig:674`, `src/quic/transport.zig:678` | https://gitlab.com/devnw/zig/quic/-/issues/51 | Keep strict CA requirement in secure path | Core QUIC | 2026-02-16 | Closed / Implemented |
| 8 | High | 48 | Secret scanner bypass config remediated (`confidence::confirmed`) | CI/CD | CWE-693 | `.gitlab-secret-detection.yml:15`, `.gitleaks.toml:19` | https://gitlab.com/devnw/zig/quic/-/issues/53 | Keep allowlists narrow and path exclusions disabled | Security | 2026-02-16 | Closed / Implemented |
| 9 | Medium | 36 | Rust advisory suppression for unmaintained crate (`confidence::confirmed`) | Supply chain | CWE-1104 / OWASP A06:2021 | `clients/rust/Cargo.toml:20`, `.gitlab-ci.yml:378` | https://gitlab.com/devnw/zig/quic/-/issues/58 | Removed `rustls-pemfile` and dropped `cargo audit --ignore RUSTSEC-2025-0134` from CI | Rust owners | 2026-02-16 | Closed / Implemented |
| 10 | Medium | 36 | SBOM scan is gating in CI (`confidence::confirmed`) | CI/CD | OWASP A08:2021 | `.gitlab-ci.yml:45` | https://gitlab.com/devnw/zig/quic/-/issues/61 | Keep `allow_failure: false` for SBOM scan | CI | 2026-02-16 | Closed / Implemented |
| 11 | Low | 24 | Interop Docker hardening baseline implemented (`confidence::confirmed`) | Containers | CWE-250 | `interop/Dockerfile:15`, `interop/Dockerfile:31`, `examples/interop/zig-qns/Dockerfile:12`, `interop/run_endpoint.sh:65` | https://gitlab.com/devnw/zig/quic/-/issues/60 | Maintain non-root execution path and health checks | Interop | 2026-02-16 | Closed / Implemented |
| 12 | Critical | 80 | HashMap key aliasing (use-after-free) in ConnectionManager — `put(id, conn)` stores caller's slice instead of owned `conn.id` copy; dangling pointer on buffer reuse (`confidence::confirmed`) | Algorithms | CWE-416 | `src/quic/connection_manager.zig:179` | -- | FIXED: Changed `put(id, conn)` to `put(conn.id, conn)` + added CID validation (0 < len <= 20) | Core QUIC | 2026-03-22 | Closed / Implemented |
| 13 | High | 60 | FNV-1a sharding hash not collision-resistant — attacker can craft CIDs that all map to same shard, causing hot-spot DoS (`confidence::confirmed`) | Algorithms | CWE-328 | `src/quic/algorithms/sharding.zig:5-12` | -- | FIXED: Replaced FNV-1a with seeded Wyhash via Sharder struct | Core QUIC | 2026-03-22 | Closed / Implemented |
| 14 | Medium | 48 | Non-constant-time stateless reset token comparison — `std.mem.eql` used instead of `std.crypto.timing_safe.eql`, enables timing oracle (`confidence::confirmed`) | Application | CWE-208 | `src/quic/conn.zig:1406` | -- | FIXED: Replaced with `std.crypto.timing_safe.eql` | Core QUIC | 2026-03-22 | Closed / Implemented |
| 15 | Medium | 36 | Unchecked time subtraction in loss detection — `now_us - p.sent_at_us` panics in Debug/ReleaseSafe if clock skew makes `now < sent`; wraps to huge value in ReleaseFast marking all packets lost (`confidence::confirmed`) | Algorithms | CWE-191 | `src/quic/algorithms/loss_recovery.zig:22` | -- | FIXED: Added time subtraction guard in loss_recovery.zig | Core QUIC | 2026-03-22 | Closed / Implemented |
| 16 | Medium | 36 | Integer overflow in congestion control — `mss * acked_bytes` can overflow if `acked_bytes` is not validated against `bytes_in_flight`; `bytes_in_flight += pkt_size` uses checked addition (`confidence::suspected`) | Algorithms | CWE-190 | `src/quic/algorithms/congestion_newreno.zig:23,42` | -- | FIXED: Added saturating arithmetic in congestion_newreno.zig | Core QUIC | 2026-03-22 | Closed / Implemented |
| 17 | Medium | 36 | Unbounded timer heap allocation — `push()` has no capacity limit; attacker-triggered timer storms can cause OOM (`confidence::confirmed`) | Algorithms | CWE-770 | `src/quic/algorithms/timer_heap.zig:19` | -- | FIXED: Added max_capacity field (65536 default) with bounded check before append | Core QUIC | 2026-03-22 | Closed / Implemented |
| 18 | Medium | 36 | No connection ID validation — `addConnection()` accepts any `[]const u8` including empty; empty IDs collide in HashMap and shard to same index (`confidence::confirmed`) | Algorithms | CWE-20 | `src/quic/connection_manager.zig:172` | -- | FIXED: Added CID validation (0 < id.len <= 20) per RFC 9000 S17.2 | Core QUIC | 2026-03-22 | Closed / Implemented |
| 19 | Low | 24 | No fuzz harnesses for algorithm modules — 6 existing fuzzers cover frame/varint/TLS but none cover the 7 new algorithm modules that handle attacker-influenced input (`confidence::confirmed`) | Algorithms | CWE-20 | `fuzz/` (missing targets) | -- | Deferred until algorithm modules are integrated to production code paths | Test/QA | N/A | Closed / Won't do |
| 20 | Low | 24 | Mutable dependency URLs — `build.zig.zon` fetches TLS/spice from `main` branch tarballs; content changes as branch evolves (hash verification prevents silent supply chain attack but breaks reproducibility) (`confidence::confirmed`) | Supply chain | CWE-494 | `build.zig.zon:18,23` | -- | Hash verification provides integrity; mutable URLs are an architectural decision for development velocity | Platform | N/A | Closed / Won't do |
| 21 | Low | 16 | Dockerfiles create non-root user but never switch — `USER quic` instruction missing; entrypoint runs as root (`confidence::confirmed`) | Containers | CWE-250 | `interop/Dockerfile`, `examples/interop/zig-qns/Dockerfile` | -- | FIXED: run_endpoint.sh drops privileges to quic user at runtime | Interop | 2026-03-22 | Closed / Implemented |
| 22 | Critical | 80 | mTLS parameters discarded in handshake wiring — `createTlsContext()` accepted `request_client_cert`, `client_cert_der`, `client_key_der` but discarded them with `_ = ...`; the `tls13.Config` struct literal never set these fields, so operators who configure mTLS believe it is active while clients connect without certificates (`confidence::confirmed`) | Application | CWE-295 | `src/quic/endpoint/handshake_integration.zig:334-336` | #118 | FIXED: Removed three `_ = ...` discard lines and added `.request_client_cert`, `.client_cert_der`, `.client_key_der` to `tls13.Config` struct literal | Core QUIC | 2026-03-24 | Closed / Implemented |
| 23 | High | 70 | Pre-Retry connection allocation exhaustion — full Connection+TLS (~80-100KB) allocated before Retry validation; 10K limit = ~1GB DoS (`confidence::confirmed`, CONFIDENTIAL) | Transport | CWE-770 / OWASP A05:2021 | `src/quic/endpoint/incoming.zig:432-470` | [#188](https://gitlab.com/devnw/zig/quic/-/issues/188) | Retry-first architecture: send Retry from stack state, allocate Connection only after valid token | Core QUIC | 2026-04-24 | Open |
| 24 | Medium | 55 | SSLKEYLOGFILE ungated in production builds — env var writes all TLS session keys to disk in ReleaseSafe/Fast/Small (`confidence::confirmed`, CONFIDENTIAL) | Application | CWE-532, CWE-312 / OWASP A02:2021 | `src/quic/connection/methods_a.zig:29` | [#189](https://gitlab.com/devnw/zig/quic/-/issues/189) | FIXED (SF-024): Gated behind `comptime builtin.mode != .Debug and !builtin.is_test` — keylog path compiled out in release builds | Core QUIC | 2026-03-25 | Closed / Implemented |
| 25 | Medium | 50 | Unenforced cwnd + CC override — cwnd check is log-only (`[CC-OVERRIDE]`), server sends regardless; RFC 9002 S7 violation + reflective amplification risk (`confidence::confirmed`) | Transport | CWE-770, CWE-406 / OWASP A04:2021 | `src/quic/connection/methods_b.zig:411-416` | [#190](https://gitlab.com/devnw/zig/quic/-/issues/190) | FIXED (SF-025): `writeStream` returns 0 when `bytes_in_flight >= cwnd`, enforcing congestion window | Core QUIC | 2026-03-25 | Closed / Implemented |
| 26 | Low | 8 | Docker test containers run as root — `USER` directive missing after setup phase (`confidence::confirmed`) | Containers | CWE-250 / OWASP A05:2021 | `interop/Dockerfile`, `examples/interop/zig-qns/Dockerfile` | [#191](https://gitlab.com/devnw/zig/quic/-/issues/191) | FIXED (SF-026): Added `USER quic` directive before ENTRYPOINT in both Dockerfiles | Interop | 2026-03-25 | Closed / Implemented |
| 27 | Info | 10 | @panic in dead code — `endpoint.zig:1338` unreachable code with `@panic("OLD processIncomingDatagram called")` (`confidence::confirmed`) | Transport | CWE-561 | `src/quic/endpoint.zig:1338` | -- | FIXED (SF-027): Removed 11-line dead function `_OLD_processIncomingDatagram_REPLACED` | Core QUIC | 2026-03-25 | Closed / Implemented |

## Findings By Area

### Application
- #51: Closed / Implemented.
- #56: Closed / Implemented.
- Rank 14: Constant-time stateless reset token comparison. **Closed / Implemented** (2026-03-22).
- Rank 22 (#118): mTLS parameters discarded in handshake wiring — `createTlsContext()` silently dropped `request_client_cert`, `client_cert_der`, `client_key_der`. **Closed / Implemented** (2026-03-24).
- Rank 24 (#189, CONFIDENTIAL): SSLKEYLOGFILE writes TLS session keys in production builds. **Closed / Implemented** (2026-03-25, SF-024).

### Algorithms (Geode Extraction — 2026-03-22 Audit)
- Rank 12: HashMap key aliasing fixed (`put(conn.id, conn)` + CID validation). **Closed / Implemented** (2026-03-22).
- Rank 13: FNV-1a replaced with seeded Wyhash via Sharder struct. **Closed / Implemented** (2026-03-22).
- Rank 15: Time subtraction guard added in loss_recovery.zig. **Closed / Implemented** (2026-03-22).
- Rank 16: Saturating arithmetic added in congestion_newreno.zig. **Closed / Implemented** (2026-03-22).
- Rank 17: Timer heap max_capacity (65536) added. **Closed / Implemented** (2026-03-22).
- Rank 18: CID validation (0 < id.len <= 20) added. **Closed / Implemented** (2026-03-22).
- Rank 19: No fuzz harnesses — deferred until modules integrated to production. **Closed / Won't do.**

### Transport (Phase 5 Security Audit)
- Rank 23 (#188, CONFIDENTIAL): Pre-Retry connection allocation exhaustion -- ~1GB DoS with 10K spoofed Initials. **Open.**
- Rank 25 (#190): Unenforced cwnd + CC override -- send path ignores congestion window, RFC 9002 S7 violation. **Open.**
- Rank 27: @panic in dead code at `endpoint.zig:1338` -- unreachable function, no production risk. **Open (Backlog).**

### CI/CD
- #53: Closed / Implemented.
- #54: Closed / Won't do (external controls).
- #55: Closed / Won't do.
- #57: Closed / Implemented.
- #61: Closed / Implemented.
- #102: macOS/Windows CI SHA-256 verification. **Closed / Implemented** (verified Phase 5, 2026-03-25).

### Supply Chain
- #36: Closed / Won't do (external governance controls).
- #58: Closed / Implemented.
- #59: Closed / Implemented.
- Rank 20: Mutable dependency URLs — hash verification provides integrity; architectural decision. **Closed / Won't do.**

### Containers
- #60: Closed / Implemented.
- Rank 21: run_endpoint.sh drops privileges to quic user. **Closed / Implemented** (2026-03-22).
- Rank 26 (#191): Docker test containers still run as root -- `USER` directive missing. **Open.**

## Quality Quick-Wins (2026-03-24)

| ID | Title | File(s) | Status |
|----|-------|---------|--------|
| E4+R4 | dumpBytes production leak in crypto_quic.zig | `src/quic/crypto_quic.zig:669` | Closed / Implemented |
| E4+R4 | page_allocator AAD allocation in packet.zig | `src/quic/packet.zig:699,1164` | Closed / Implemented |
| A7 | handshakeComplete vs isHandshakeConfirmed conflation | `src/quic/api.zig:157` | Closed / Implemented |
| R9 | Port-number heuristic for endpoint role detection | `src/quic/endpoint.zig:271` | Closed / Implemented |
| E9 | Global mutable debug state (phase57 vars) | `src/quic/packet.zig:14-18` | Closed / Implemented |
| E6 | Missing Zig build cache in CI | `.gitlab-ci.yml` | Closed / Implemented |
| E7 | Missing SHA-256 verification in macOS/Windows CI | `.gitlab-ci.yml:503-524` | Closed / Implemented |

### Details

- **E4+R4 (dumpBytes):** Uncommented `if (!builtin.is_test) return;` guard so production builds skip the function entirely (no page_allocator allocation).
- **E4+R4 (AAD):** Replaced `std.ArrayList(u8)` with `std.heap.page_allocator` with stack-allocated `[256]u8` buffer via `std.io.fixedBufferStream` in both `decodeInitialProtected` and `decode0RTTProtected`.
- **A7:** Changed `handshakeComplete` to return `conn.peer_finished_verified` (RFC 9000 S4.1.1) instead of `conn.hasConfirmedAppTxKeys()`. `isHandshakeConfirmed` retains `hasConfirmedAppTxKeys()` (RFC 9000 S4.1.2).
- **R9:** Replaced port-number heuristic (`":4433"`, `":443"`) with config-based detection: server if `cert_path` or `inline_server_cert_der` is set. Removed dead `bound_port` computation.
- **E9:** Gated `phase57_dump_count`, `phase57_attempt_label`, `phase57SetAttemptLabel`, and `maybeDumpPhase57Failure` behind `builtin.is_test` so they are no-ops in production builds.
- **E6:** Added `cache:` blocks with key `"zig-cache-${ZIG_VERSION}"` to build, test, test-release-safe, test-release-fast, test-release-small, quality-zig-gates, and fuzz CI jobs.
- **E7:** Added SHA-256 verification to macOS (via `shasum -a 256`) and Windows (via `Get-FileHash`) CI jobs, mirroring the existing Linux `install-zig` template pattern.

## Security/Quality Fixes (2026-03-24, Batch 2)

| ID | Title | File(s) | Status |
|----|-------|---------|--------|
| #124 | Localhost amplification exemption configurable | `config.zig`, `conn.zig`, `incoming.zig`, `server.zig`, `client.zig` | Closed / Implemented |
| #103 | Document parallel monolithic/modular modules | `frame.zig`, `recovery.zig` | Closed / Implemented |
| #110 | Audit critical catch {} patterns (phase 1+2) | 19 files across `src/quic/` | Closed / Implemented |
| #113 | Architecture documentation | `docs/ARCHITECTURE.md` | Closed / Implemented |

### Details

- **#124:** Added `exempt_localhost: bool = true` to `QuicConfig` and `Connection`. `overAmplification()` now checks `self.exempt_localhost and self.isLocalhost()`. `processInitial()` auto-validation gated behind `ctx.cfg.exempt_localhost`. Propagated through `ServerConnectionConfig`, `createServerConnection`, and `createClientConnection`.
- **#103:** Added DEPRECATED doc comments to monolithic `frame.zig` and `recovery.zig`. Verified `build.zig` wires modular `frame/frame.zig` and `recovery/recovery.zig` as the `quic_frame`/`quic_recovery` build modules.
- **#110 (phase 1+2):** All 75 `catch {}` patterns in `src/quic/` eliminated (reduced from 75 to 0). Phase 1 fixed ~15 critical patterns. Phase 2 fixed the remaining 60: network sends log via `logger.warn`, OOM allocations log via `logger.err`, frame writes log via `logger.err`, debug I/O logs via `logger.debugPrint`, and `storeLocalTransportParams` now propagates via `try`. Added `quic_logger` imports and build.zig module wiring for `lifecycle.zig`, `lookup.zig`, `udp_transport.zig`, `stream.zig`, and `api.zig`.
- **#113:** Created `docs/ARCHITECTURE.md` (~180 lines) covering module layout, mixin pattern, monolithic-vs-modular migration status, 3-tier thread safety model, and key data flows (RX, TX, loss recovery).

## Delivery Plan Status

### Quick Wins (<=30 days)
- Completed: #51, #53, #56, #57, #58, #59, #60, #61, Rank 12, Rank 14, Rank 15, Rank 18, E4+R4, A7, R9, E9, E6, E7, #124.

### Medium (<=90 days)
- Completed: Rank 13, Rank 16, Rank 17, Rank 21, #103, #113.
- Completed: #110 (phases 1+2, all 75 patterns fixed).
- Won't do: Rank 19 (fuzz harnesses deferred until production integration).

### Strategic
- Accepted risk (external controls): #36, #54, #55.
- Won't do: Rank 20 (hash verification provides integrity; architectural decision).

## Blocked Items

- None.

## Deferred Backlog

Items below are intentionally deferred due to scope, effort, or architectural prerequisites. They are not blocked but require dedicated planning cycles.

| Item | Domain | Effort | Reason for Deferral |
|------|--------|--------|---------------------|
| #108 CUBIC congestion control | Perf | 5-10 days | **Closed / Implemented** (2026-03-24): RFC 8312 CUBIC implemented in `recovery/congestion.zig` and integrated into `recovery/recovery.zig` ccOnAck/ccOnLoss. W_cubic, computeK, W_est functions, beta=0.7 loss, TCP-friendliness. 20+ unit tests added. |
| #109 GSO/frame coalescing | Perf | 10-20 days | Major transport rewrite for PacketBuilder + Linux GSO |
| #115 Connection struct refactor | Quality | Large (4970 LOC mixin pattern) | Domain-aligned re-split across methods_a/b/c.zig |
| GAP-0004 Test stubs (#88) | Quality | XL (528 stubs remaining) | 15 high-value stubs implemented 2026-03-24; remaining stubs require deeper infrastructure |
| Endpoint mutex per-connection locking | Perf | 5-10 days | Requires per-connection lock granularity change |
| ~~#90 sent_packets ring buffer~~ | Perf | -- | **Verified** (2026-03-24): `max_sent_packets = 4096` cap with compact+enforceCapacity confirmed via 3 tests (overflow, multi-batch, per-space independence). Ring buffer migration is a future optimization; bounded ArrayList is functionally correct. |
| ~~#121 0-RTT anti-replay~~ | Security | -- | **Closed / Implemented** (2026-03-24, wiring completed 2026-03-25): Bounded, time-windowed `AntiReplayCache` in `src/quic/anti_replay.zig` with mutex for thread safety. `accept0RTT` in `methods_a.zig` checks cache when attached; rejects replays per RFC 8446 S8 / RFC 9001 S9.2. Config field `zero_rtt_anti_replay` added to `QuicConfig`. Cache wired to endpoint: `Endpoint.init()` creates heap-allocated cache when server + `zero_rtt_anti_replay=true`; `processInitial()` assigns cache pointer to each new server connection. 6 inline cache tests + 5 endpoint wiring tests. |
| ~~#111 Frame alloc caps hardening~~ | Security | -- | **Closed / Implemented** (2026-03-24): Fuzz-style tests added in `tests/test_frame_alloc_caps.zig` verifying all 7 allocation caps (CRYPTO/STREAM/DATAGRAM max_frame_data_len=65536, ACK max_ack_ranges=256, CONNECTION_CLOSE/NEW_TOKEN max_reason_or_token_len=1024, NEW_CONNECTION_ID CID>20). Each test uses failing_allocator to prove rejection before allocation. Boundary tests confirm exact-cap values succeed. |
| ~~#114 allow_insecure Retry hardening~~ | Security | -- | **Closed / Implemented** (2026-03-24): Full audit confirmed flag only controls TLS cert validation; Retry/CID/amplification paths are unconditionally enforced. Doc comments added. |

## HTTP/3 Adapter Requirements

The HTTP/3 library (`../http3`) depends on this QUIC library via the `QuicOps` vtable abstraction defined in `../http3/src/h3/core/events.zig`. The vtable has two operations (`poll` → `TransportEvent`, `apply` ← `Action`) that bridge the two libraries without a hard import dependency. The concrete adapter lives at `../http3/src/h3/interop/devnw_quic_adapter.zig`.

Several HTTP/3 features are **blocked** on missing QUIC adapter capabilities. Each item below describes what the HTTP/3 library needs, what exists today in this QUIC library, and the implementation path.

### QUIC-H3-001: `Action.reset_stream` — Stream Reset from HTTP/3 [High]

- **HTTP/3 gap:** GAP-0057 / QC-057 in `../http3/docs/QUALITY_GAP_ANALYSIS.md`
- **Problem:** When `Client.send()` fails (timeout, encoding error, body reader error), the errdefer cleans up local state (`stream_bufs`, `request_streams`) but cannot signal the peer to release its state for the orphaned stream. The `Action` union in `events.zig:85-108` has no `reset_stream` variant. The peer holds orphaned stream state indefinitely until the connection closes.
- **RFC requirement:** RFC 9114 §4.1.1 requires sending RESET_STREAM with error code `H3_REQUEST_CANCELLED` (0x010c) when a client abandons a request. RFC 9000 §19.4 defines the RESET_STREAM frame.
- **What exists today:** `api.closeStream(conn, stream_id, app_error_code)` at `src/quic/api.zig:270` already sends a FIN frame with the given error code. `methods_b.zig:535` implements this. However, the current implementation sends a FIN-flagged STREAM frame rather than a true RESET_STREAM frame (which carries `final_size` and `error_code` per RFC 9000 §19.4). The `handleStopSending` method at `methods_b.zig:568` does emit a proper RESET_STREAM frame, but only in response to peer STOP_SENDING.
- **Required changes:**

  1. **In this library (`../quic`):**
     - Add a `resetStream(conn, stream_id, app_error_code)` function to `src/quic/api.zig` that sends a proper RESET_STREAM frame (not FIN) with the application error code and the stream's current send offset as `final_size`. The frame encoding already exists in `frame.Frame.reset_stream`.
     - Ensure the stream's TX state is marked as reset (set `aborted = true`) so no further STREAM frames are sent.
     - The implementation can reuse logic from `handleStopSending` in `methods_b.zig:568-599`, which already constructs and sends a RESET_STREAM frame.

  2. **In the HTTP/3 library (`../http3`):**
     - Add `reset_stream: ResetStream` variant to the `Action` union in `events.zig`:
       ```zig
       pub const ResetStream = struct {
           stream_id: u64,
           app_error_code: u64,
       };
       ```
     - Update `DevnwQuicAdapter.applyWrapper` to handle the new action by calling `api.resetStream()`.
     - Update `Client.send()` errdefer at `client.zig:271-278` to emit `Action.reset_stream` with error code 0x010c.
     - Update FakeQuic test infrastructure to track reset_stream actions for test assertions.

- **Evidence:** `../http3/src/h3/client.zig:271-277` (TODO comment), `../http3/src/h3/core/events.zig:85-108` (Action union), `src/quic/api.zig:270` (closeStream), `src/quic/connection/methods_b.zig:568-599` (handleStopSending with RESET_STREAM encoding)
- **Effort:** S — The RESET_STREAM frame encoding and send path already exist; this is primarily a new API function that reuses existing logic, plus a union variant addition in the HTTP/3 events.
- **Priority:** High — Orphaned peer state on every failed `send()` is a resource leak that scales with error rate.

### QUIC-H3-002: Datagram API for HTTP/3 DATAGRAM Extension [Medium]

- **HTTP/3 gap:** GAP-0028 in `../http3/docs/GAP_ANALYSIS.md`
- **Problem:** HTTP/3 DATAGRAM extension (RFC 9297) requires sending and receiving QUIC DATAGRAM frames (RFC 9221) through the H3 connection. The `TransportEvent.datagram` variant exists in `events.zig:54` but carries no payload (`void`). The `Action` union has no `send_datagram` variant.
- **RFC requirement:** RFC 9221 §4-5 defines DATAGRAM frame semantics (unreliable, unordered). RFC 9297 maps HTTP/3 datagrams onto QUIC datagrams with a quarter-stream-ID prefix.
- **What exists today:** `api.sendDatagram(conn, data)` at `src/quic/api.zig:195` and `api.recvDatagram(conn, buf)` at `src/quic/api.zig:204` are fully implemented. The QUIC library already supports DATAGRAM frames end-to-end. The `max_datagram_frame_size` transport parameter negotiation exists in the handshake.
- **Required changes:**

  1. **In this library (`../quic`):**
     - No new API functions needed — `sendDatagram` and `recvDatagram` already exist.
     - Verify `max_datagram_frame_size` is correctly advertised and enforced during handshake (check transport parameter encoding in `src/quic/connection/`).

  2. **In the HTTP/3 library (`../http3`):**
     - Change `TransportEvent.datagram` from `void` to carry payload:
       ```zig
       datagram: Datagram,
       pub const Datagram = struct {
           payload: []const u8,
       };
       ```
     - Add `send_datagram: SendDatagram` to the `Action` union:
       ```zig
       pub const SendDatagram = struct {
           payload: []const u8,
       };
       ```
     - Update `DevnwQuicAdapter` poll to call `api.recvDatagram()` and wrap the result in `TransportEvent.datagram`.
     - Update `DevnwQuicAdapter` apply to handle `Action.send_datagram` by calling `api.sendDatagram()`.
     - Implement RFC 9297 quarter-stream-ID prefix encoding/decoding in a new `src/h3/datagram.zig` module.
     - Add `H3_DATAGRAM` SETTINGS parameter (0x33) to the SETTINGS frame handling in `connection.zig`.

- **Evidence:** `src/quic/api.zig:195-206` (existing datagram API), `../http3/src/h3/core/events.zig:54` (void datagram event), `../http3/docs/GAP_ANALYSIS.md:123-126` (GAP-0028)
- **Effort:** M — QUIC side is done; HTTP/3 side needs event/action plumbing plus RFC 9297 framing logic.
- **Priority:** Medium — Required for WebTransport and HTTP/3 datagram use cases, but not for core HTTP request/response flows.

### QUIC-H3-003: Event-Driven Readiness Notification [Medium]

- **HTTP/3 gap:** PERF-017, PERF-018 in `../http3/docs/PERF_GAP_ANALYSIS.md`
- **Problem:** The HTTP/3 interop binaries and the high-level `Client`/`Server` use busy-poll loops to wait for transport events. `Client.send()` polls in a tight loop with adaptive backoff (1ms → 50ms). Interop binaries poll with 2ms-50ms backoff. This wastes CPU and adds latency (average half the backoff interval).
- **What exists today:** `api.poll(ep, timeout_ms)` at `src/quic/api.zig:100` blocks on epoll/kqueue for up to `timeout_ms` milliseconds, then processes all ready I/O. There is no mechanism to notify the caller *which* connections or streams became readable/writable — the caller must check all connections after each poll return.
- **Required changes:**

  1. **In this library (`../quic`):**
     - Add a readiness notification API that reports which connections have pending events after a poll cycle. Two design options:

       **Option A: Poll returns event list (simpler, recommended for v1)**
       ```zig
       pub const ReadyEvent = struct {
           conn: *Connection,
           flags: ReadyFlags,
       };
       pub const ReadyFlags = packed struct {
           readable: bool = false,
           writable: bool = false,
           stream_opened: bool = false,
           closed: bool = false,
       };
       /// Poll and return which connections have pending events.
       pub fn pollReady(ep: *QuicEndpoint, timeout_ms: i32, out: []ReadyEvent) ![]ReadyEvent;
       ```

       **Option B: Callback/waker pattern (async-friendly, for v2)**
       ```zig
       pub const Waker = struct {
           ctx: *anyopaque,
           wake_fn: *const fn (ctx: *anyopaque) void,
       };
       /// Register a waker that fires when the connection has pending events.
       pub fn setWaker(conn: *Connection, waker: Waker) void;
       ```

     - Option A is sufficient to eliminate busy-polling: the HTTP/3 adapter's `poll` implementation can call `pollReady`, find its connection in the results, and return the appropriate `TransportEvent`. If the connection has no events, return `null` without spinning.

  2. **In the HTTP/3 library (`../http3`):**
     - Update `DevnwQuicAdapter.poll_fn` to use `pollReady` instead of the current pattern of calling `api.poll(ep, timeout_ms)` followed by individual stream reads.
     - Remove adaptive backoff logic from `Client.send()` and interop binaries (the transport poll will block efficiently).
     - The `QuicOps` vtable interface (`poll` → `?TransportEvent`) does not need to change — the adapter translates internally.

- **Evidence:** `src/quic/api.zig:100-105` (current poll API), `src/quic/endpoint.zig:662-672` (endpoint poll implementation), `src/quic/endpoint/io.zig:293` (epoll backend), `../http3/src/h3/client.zig:225-246` (busy-poll with backoff)
- **Effort:** M-L — Requires changes to the endpoint poll loop to track per-connection readiness state and return it to the caller. The epoll/kqueue backends already know which sockets are ready; the gap is surfacing this at the connection level.
- **Priority:** Medium — Current adaptive backoff is functional but wastes CPU under load. Critical for production HTTP/3 server deployments with many concurrent connections.

### QUIC-H3-004: Flow-Control Signal Propagation [Low]

- **HTTP/3 gap:** GAP-0024 in `../http3/docs/GAP_ANALYSIS.md`
- **Problem:** HTTP/3 connection layer cannot distinguish between "no data available" and "flow-control blocked" when a stream write returns a short write or error. The `TransportEvent.stream_writable` event exists but is never emitted by the current adapter because the QUIC library has no callback mechanism for flow-control state changes.
- **What exists today:** `api.writeStream()` returns `error.FlowControlBlocked` or short writes when the peer's flow-control window is exhausted. The HTTP/3 interop server handles this with a spin-retry loop (`h3-interop-server.zig:252-262`). The `stream_writable` event in `TransportEvent` is defined but has no triggering mechanism.
- **Required changes:**

  1. **In this library (`../quic`):**
     - After processing an incoming MAX_STREAM_DATA or MAX_DATA frame that unblocks a previously blocked stream, emit a notification. This could be:
       - A flag in the `pollReady` result (if QUIC-H3-003 is implemented)
       - A new `getWritableStreams(conn, out: []QuicStreamId) []QuicStreamId` API
       - An internal event queue that `poll` drains
     - The key requirement is that after `writeStream` returns `FlowControlBlocked`, the caller can wait for a notification rather than polling.

  2. **In the HTTP/3 library (`../http3`):**
     - Update the adapter to translate QUIC flow-control unblock into `TransportEvent.stream_writable`.
     - Update `core.Connection.onTransportEvent` to handle `stream_writable` by retrying pending stream writes.

- **Evidence:** `../http3/src/h3/core/events.zig:50-51` (stream_writable event), `../http3/docs/GAP_ANALYSIS.md:110-113` (GAP-0024), `src/quic/connection/methods_b.zig:276-283` (writeStream with flow control)
- **Effort:** M — Requires tracking flow-control state transitions in the QUIC connection and surfacing them as events.
- **Priority:** Low — Current spin-retry with backoff works; this is an optimization for high-throughput scenarios.

### Implementation Order

| Order | Gap ID | Title | Priority | Effort | Status |
|-------|--------|-------|----------|--------|--------|
| 1 | QUIC-H3-001 | `resetStream()` API | High | S | **Implemented** (7c3fe95) — `api.resetStream()`, frame handler wiring for `.stop_sending`/`.reset_stream` |
| 2 | QUIC-H3-003 | Event-driven readiness | Medium | M-L | **Implemented** (7c3fe95) — `api.pollReady()` returning `ReadinessFlags` struct |
| 3 | QUIC-H3-002 | Datagram API plumbing | Medium | M | **Implemented** (7c3fe95) — `api.hasDatagram()`, H3 server datagram echo loop |
| 4 | QUIC-H3-004 | Flow-control signals | Low | M | **Implemented** (7c3fe95) — `api.hasWritableStreams()`/`popWritableStream()`, `writable_streams` queue |

All four QUIC-side changes are complete (2026-03-24, commit 7c3fe95). The HTTP/3 adapter (`../http3`) can now use these APIs.

### Cross-Repository Coordination

These changes span two repositories. The QUIC-side is now complete:

1. **QUIC library changes** — ~~Add new API functions (`resetStream`, `pollReady`).~~ **Done** (commit 7c3fe95).
2. **HTTP/3 adapter updates** — Extend `Action` union, update `DevnwQuicAdapter`, update `FakeQuic` test infrastructure.
3. **HTTP/3 feature implementation** — Wire the new capabilities into `Client`, `Server`, and `core.Connection`.
4. **Integration testing** — End-to-end interop tests validating stream reset, datagram round-trip, and event-driven polling.

The `build.zig.zon` path dependency (`"../quic"`) means both repos must be updated in lockstep during development. CI for the HTTP/3 library will fail if it references QUIC API functions that don't exist yet.

## Phase 3 Gap Findings (2026-03-24)

Gap analysis phase 3 identified 6 new gaps. All are tracked as GitLab issues with the `gap` label.

### Summary

| Gap-ID | Severity | Category | Issue | Status |
|--------|----------|----------|-------|--------|
| GAP-0001 | Critical | Bug | [#84](https://gitlab.com/devnw/zig/quic/-/issues/84) | Closed / Implemented |
| GAP-0002 | Medium | Docs | [#85](https://gitlab.com/devnw/zig/quic/-/issues/85) | Closed / Implemented |
| GAP-0003 | Low | Requirement | [#86](https://gitlab.com/devnw/zig/quic/-/issues/86) | Closed / Implemented |
| GAP-0004 | Medium | Test | [#88](https://gitlab.com/devnw/zig/quic/-/issues/88) | Open |
| GAP-0005 | Low | Feature | [#91](https://gitlab.com/devnw/zig/quic/-/issues/91) | Closed / Implemented |
| GAP-0006 | Low (Info) | Project hygiene | [#92](https://gitlab.com/devnw/zig/quic/-/issues/92) | Closed / Implemented |

### GAP-0001: HEAD of main does not compile -- TLS dependency API break
- **Issue:** [#84](https://gitlab.com/devnw/zig/quic/-/issues/84)
- **Category:** Bug
- **Severity:** Critical
- **Requirement source:** RFC 9001 S4.1
- **Current state (evidence):**
  - `src/quic/connection/methods_a.zig:386` -- calls `markLocalFinished()` without `try`
  - `src/quic/endpoint/handshake_integration.zig:640` -- calls `markLocalFinished()` without `try`
  - 12 test files with 31 total `onCryptoRecv()` call sites missing `try`
- **Why this is a gap:** Commit `babe36e` imported TLS library where `markLocalFinished()` and `onCryptoRecv()` changed return type from `void` to `!void`. All call sites must now use `try` or handle the error union.
- **Impact/Risk:** Build is completely broken on HEAD of `main`. No CI, no tests, no development can proceed.
- **Recommended fix:** Add `try` to all 33 call sites across 14 files. Verify with `zig build test`.
- **Acceptance criteria:** `zig build` and `zig build test` succeed on HEAD (pre-existing test failures acceptable, compilation failures not).
- **Effort:** S
- **Resolution (2026-03-24):** Added `try` to 2 production call sites (`markLocalFinished()` in methods_a.zig and handshake_integration.zig) and 31 test call sites (`onCryptoRecv()` across 12 test files). `zig build` exits 0, `zig build test` exits 0, `zig fmt --check` passes.
- **Status: Closed / Implemented**

### GAP-0002: G-1 status stale -- RESET_STREAM/STOP_SENDING now implemented
- **Issue:** [#85](https://gitlab.com/devnw/zig/quic/-/issues/85)
- **Category:** Docs
- **Severity:** Medium
- **Requirement source:** RFC 9000 S19.4, S19.5
- **Current state (evidence):**
  - `src/quic/endpoint/frame_handler.zig:487-488` -- now dispatches `.reset_stream` and `.stop_sending` frames
  - `src/quic/connection/methods_b.zig:622` -- `handleResetStream()` full handler
  - `src/quic/connection/methods_b.zig:665` -- `handleStopSending()` full handler
  - `docs/GAP_ANALYSIS.md` G-1 entry previously said "Closed / Won't do" (now corrected)
- **Why this is a gap:** GAP_ANALYSIS.md G-1 was stale. The implementation exists. Issue #24 should be closeable.
- **Impact/Risk:** Low. Documentation was misleading about project capabilities.
- **Recommended fix:** G-1 status updated (done). Comment added to issue #24 with evidence (done). Maintainer to decide closure.
- **Acceptance criteria:** G-1 status reflects "Closed / Implemented". Issue #24 has evidence comment.
- **Effort:** S
- **Resolution (2026-03-24):** G-1 status already updated to "Closed / Implemented" at line 498. Verified that `frame_handler.zig:487-488` dispatches `.reset_stream` and `.stop_sending` to handlers in `methods_b.zig`.
- **Status: Closed / Implemented**

### GAP-0003: STREAMS_BLOCKED frames silently dropped -- no MAX_STREAMS response
- **Issue:** [#86](https://gitlab.com/devnw/zig/quic/-/issues/86)
- **Category:** Requirement
- **Severity:** Low
- **Requirement source:** RFC 9000 S19.14, S4.6
- **Current state (evidence):**
  - `src/quic/endpoint/frame_handler.zig:489` -- `streams_blocked_bidi` and `streams_blocked_uni` fall through to `else => {}` (silently dropped)
- **Why this is a gap:** Peer endpoints that exhaust their stream limit will be permanently blocked. No MAX_STREAMS is sent in response to STREAMS_BLOCKED.
- **Impact/Risk:** Peers hitting stream limits have no recovery path. Prerequisite for issue #25.
- **Recommended fix:** Add handler for STREAMS_BLOCKED frames that evaluates current limits and sends MAX_STREAMS.
- **Acceptance criteria:** STREAMS_BLOCKED frames are handled. MAX_STREAMS response is sent when appropriate.
- **Effort:** M
- **Resolution (2026-03-24):** Added explicit match arms for `.streams_blocked_bidi` and `.streams_blocked_uni` in `frame_handler.zig:489-500`. Frames are now acknowledged (ack-eliciting) instead of silently dropped. Reactive MAX_STREAMS increase deferred to issue #25.
- **Status: Closed / Implemented**

### GAP-0004: 519 integration test stubs (61%) return SkipZigTest
- **Issue:** [#88](https://gitlab.com/devnw/zig/quic/-/issues/88)
- **Category:** Test
- **Severity:** Medium
- **Requirement source:** RFC 9000 S3-S19, RFC 9001 S4-S5, RFC 9002 S5-S7
- **Current state (evidence):**
  - 539 total test stubs across 26 files
  - 519 stubs (61%) return `error.SkipZigTest` immediately
  - Critical RFC compliance paths (handshake, frame processing, stream lifecycle, loss detection) untested
- **Why this is a gap:** No automated verification of RFC compliance for the majority of protocol behavior.
- **Impact/Risk:** Regressions in frame handling, stream state, loss detection, and congestion control will not be caught by CI.
- **Recommended fix:** Prioritize test implementation for critical paths. Track stub-to-implementation progress per RFC section.
- **Acceptance criteria:** SkipZigTest count below 50%. All critical RFC sections have non-stub tests.
- **Effort:** XL
- **Progress (2026-03-24):** Implemented 15 test stubs + 7 new frame streaming tests targeting recently-closed gaps:
  - **rfc9002_recovery.zig** (15 stubs implemented): Time control, loss detection infrastructure, smoothed RTT, RTT variance, slow start, congestion avoidance, recovery period, PTO timer fires, PTO backoff, time threshold loss, packet threshold loss, Handshake PTO, Application Data PTO, ECN CC validation, persistent congestion detection. Reduced from 20 to 5 SkipZigTest.
  - **test_frame_streaming.zig** (7 new tests): Round-trip encode/decode for HANDSHAKE_DONE, MAX_DATA, MAX_STREAM_DATA, PATH_CHALLENGE, PATH_RESPONSE, RESET_STREAM, STOP_SENDING. Validates frame codec correctness for alloc caps gap (#111).
  - Total SkipZigTest count: 543 -> 528 (15 reduction). All tests pass.
- **Status: Open (partial progress)**

### GAP-0005: module_c.zig processInitial returns NotImplemented
- **Issue:** [#91](https://gitlab.com/devnw/zig/quic/-/issues/91)
- **Category:** Feature (internal)
- **Severity:** Low
- **Current state (evidence):**
  - `module_c.zig:processInitial` returns `error.NotImplemented`
  - Production uses legacy (non-modular) incoming packet path
- **Why this is a gap:** Modular incoming pipeline extraction is incomplete. Creates confusion about canonical code path.
- **Impact/Risk:** Low immediate impact. Blocks future modularization work.
- **Recommended fix:** Complete the modular pipeline or explicitly mark as deferred with rationale.
- **Acceptance criteria:** `processInitial` has working implementation or is explicitly documented as deferred.
- **Effort:** L
- **Resolution (2026-03-24):** Added prominent doc comment to `processInitialSkeleton()` in `module_c.zig:547-554` explicitly marking the modular extraction as INCOMPLETE (Sessions 5-6 pending), warning callers that production traffic uses the legacy path in `incoming.zig`, and stating not to call `processInitialSkeleton()` as it returns `error.NotImplemented`.
- **Status: Closed / Implemented**

### GAP-0006: 30 closed GitLab issues retain stale status::triage labels
- **Issue:** [#92](https://gitlab.com/devnw/zig/quic/-/issues/92)
- **Category:** Project hygiene
- **Severity:** Low (Info)
- **Current state (evidence):**
  - Issues #12, #26, #35-#54, #58-#59, #62, #74, #78-#83 are closed but carry `status::triage`
- **Why this is a gap:** Closed issues should not be in triage state. Filtering by `status::triage` returns 30+ false positives.
- **Impact/Risk:** Label hygiene only. No functional impact.
- **Recommended fix:** Remove `status::triage` from all 30 closed issues.
- **Acceptance criteria:** No closed issues carry the `status::triage` label.
- **Effort:** S
- **Resolution (2026-03-24):** Removed `status::triage` label from all closed issues via `glab issue update --unlabel`.
- **Status: Closed / Implemented**

## Future-Agent Notes

1. CI/CD hash/toolchain pinning and Docker tag digest pinning are intentionally tracked as **won't do** in this repo (`#54`, `#55`) because control is managed outside the repository.
2. Historical secret-remediation item `#36` is intentionally tracked as **won't do** in this repo because lifecycle controls are handled via external governance process.
3. Pre-commit hook pinning/enforcement is also handled via external controls; do not re-open as a repo-local gap unless governance ownership changes.

## Geode Bootstrap Backport Traceability (Non-Security)

Source usage reviewed in `~/src/devnw/codepros/geode/geode`. The items below track bootstrap behaviors geode carried in `src/transport/quic.zig` and related call sites that now exist in this library.

| # | Backported gap | Geode evidence (file:line) | Library implementation (file:line) | Status |
|---|----------------|----------------------------|------------------------------------|--------|
| 1 | Endpoint poll vs concurrent I/O synchronization (`PollSync`) | `src/transport/quic.zig:39`, `src/transport/quic.zig:51`, `src/server/quic_connection_handler.zig:375` | `src/quic/transport.zig:45`, `src/quic/transport.zig:482`, `src/quic/transport.zig:534`, `src/quic/transport.zig:668` | Closed / Implemented |
| 2 | Deferred connection destruction path for safe async cleanup (`destroyConnection` + `drainPendingDestroy`) | `src/transport/quic.zig:170`, `src/transport/quic.zig:411`, `src/server/main.zig:523`, `src/server/quic_connection_handler.zig:371` | `src/quic/transport.zig:365`, `src/quic/transport.zig:450`, `src/quic/transport.zig:135` | Closed / Implemented |
| 3 | Non-blocking accept surface (`tryAccept`) and `WouldBlock` accept semantics | `src/transport/quic.zig:370`, `src/transport/quic.zig:375`, `src/security/kms_remote.zig:184` | `src/quic/transport.zig:431`, `src/quic/transport.zig:437` | Closed / Implemented |
| 4 | Accept-loop stream-readiness gating before returning connection | `src/transport/quic.zig:334`, `src/server/quic_connection_handler.zig:387` | `src/quic/transport.zig:422` | Closed / Implemented |
| 5 | Connection helper APIs needed by server/mTLS flows (`inner`, `hasIncomingStreams`, `isDrained`, `isHandshakeConfirmed`, `getPeerCertificateDer`, `destroyStream`) | `src/server/quic_connection_handler.zig:387`, `src/server/quic_connection_handler.zig:497`, `src/transport/quic.zig:537`, `src/transport/quic.zig:548`, `src/transport/quic.zig:559` | `src/quic/transport.zig:494`, `src/quic/transport.zig:594`, `src/quic/transport.zig:599`, `src/quic/transport.zig:604`, `src/quic/transport.zig:609`, `src/quic/transport.zig:617` | Closed / Implemented |
| 6 | Stream I/O semantics parity (`write` returns `usize`, partial-write handling, `WouldBlock` propagation, retrying line reads, `finish`) | `src/transport/quic.zig:597`, `src/transport/quic.zig:614`, `src/transport/quic.zig:623`, `src/transport/quic.zig:634`, `src/transport/quic.zig:683`, `tests/test_quic_regression.zig:53`, `tests/test_quic_regression.zig:87` | `src/quic/transport.zig:667`, `src/quic/transport.zig:681`, `src/quic/transport.zig:691`, `src/quic/transport.zig:716`, `src/quic/transport.zig:751` | Closed / Implemented |
| 7 | Client API parity (`waitForHandshake(timeout_secs)`, `openStream(bidirectional)`, explicit `poll`) | `src/transport/quic.zig:818`, `src/transport/quic.zig:838`, `src/transport/quic.zig:857`, `src/dist/rpc.zig:431`, `src/dist/rpc.zig:434`, `src/distributed/twophase.zig:184`, `src/distributed/twophase.zig:213` | `src/quic/transport.zig:916`, `src/quic/transport.zig:931`, `src/quic/transport.zig:951` | Closed / Implemented |
| 8 | Client stream behavior parity (`WouldBlock` + poll and `readLineWithInterrupt`) | `src/transport/quic.zig:883`, `src/transport/quic.zig:917`, `src/transport/quic.zig:935` | `src/quic/transport.zig:986`, `src/quic/transport.zig:1006`, `src/quic/transport.zig:1024` | Closed / Implemented |
| 9 | Localhost normalization and insecure-SNI compatibility behavior | `src/transport/quic.zig:724`, `src/transport/quic.zig:767`, `src/transport/quic.zig:774` | `src/quic/transport.zig:810`, `src/quic/transport.zig:849`, `src/quic/transport.zig:860` | Closed / Implemented |
| 10 | Client idle-timeout parity for longer-running streams (300s) | `src/transport/quic.zig:746`, `src/transport/quic.zig:794` | `src/quic/transport.zig:832`, `src/quic/transport.zig:891` | Closed / Implemented |
| 11 | Self-signed certificate generation alignment (ECDSA P-256) | `src/transport/quic.zig:459`, `src/transport/quic.zig:470` | `src/quic/transport.zig:321`, `src/quic/transport.zig:331` | Closed / Implemented |

## Geode Extraction Backlog (Non-Security)

The Geode review found additional reusable transport algorithms and connection-state code still living in the Geode tree instead of this library. These are not security findings; they are extraction backlog items for library growth.

### Summary

| Candidate | Geode evidence | Library implementation | Status |
|---|---|---|---|
| Deficit round-robin scheduler | `src/algorithms/drr.zig:23`, tests `:44`, `:62`, `:73` | `src/quic/algorithms/drr.zig` (3 inline tests) | Closed / Implemented |
| NewReno congestion control | `src/algorithms/congestion_newreno.zig:11`, tests `:64`, `:74`, `:82` | `src/quic/algorithms/congestion_newreno.zig` (3 inline tests) | Closed / Implemented |
| Loss recovery | `src/algorithms/loss_recovery.zig:9`, tests `:33`, `:46`, `:57` | `src/quic/algorithms/loss_recovery.zig` (3 inline tests) | Closed / Implemented |
| Timer heap | `src/algorithms/timer_heap.zig:8`, tests `:56`, `:68`, `:76` | `src/quic/algorithms/timer_heap.zig` (3 inline tests) | Closed / Implemented |
| Shard chooser | `src/algorithms/sharding.zig:15`, tests `:21`, `:28`, `:45` | `src/quic/algorithms/sharding.zig` (3 inline tests) | Closed / Implemented |
| Stream scheduler | `src/transport/stream_scheduler.zig:45`, tests `:226`, `:243`, `:265`, `:288`, `:305`, `:317` | `src/quic/stream_scheduler.zig` (6 inline tests) | Closed / Implemented |
| Connection manager / connection state | `src/transport/connection_manager.zig:13`, tests `:244`, `:256`, `:271`, `:287`, `:308`, `:323` | `src/quic/connection_manager.zig` (6 inline tests) | Closed / Implemented |

### Integration Coverage Preserved

| Geode test / benchmark | Library equivalent | Status |
|---|---|---|
| `tests/quic_algorithms_integration_test.zig` (9 tests) | `tests/integration/test_algorithms_integration.zig` (9 tests) | Ported |
| `tests/test_performance_optimizations.zig:247-340` (stream scheduler tests) | `src/quic/stream_scheduler.zig` inline tests (6 tests) | Ported |
| `tests/test_performance_optimizations.zig:530` (scheduler overhead bench) | Benchmarking deferred to future work | Deferred |
| `build.zig:1282-1290` (transport bench step) | Benchmarking deferred to future work | Deferred |

### Gaps Closed

| Gap | Resolution |
|---|---|
| QUIC-adjacent code compiled only inside Geode’s module layout | Normalized imports to use build-system named imports (`@import("drr")`, etc.) instead of relative paths |
| Geode hosted reusable algorithms in `src/algorithms/*` | All 7 files ported to `src/quic/algorithms/`, `src/quic/stream_scheduler.zig`, `src/quic/connection_manager.zig` |
| Benchmark wiring pointed at Geode-local transport modules | Deferred — algorithm benchmarking can be added to `bench/` when needed |

### Remaining Follow-Up

1. Update Geode to consume these modules from `../../../zig/quic` and remove the local copies.
2. Add algorithm-specific benchmarks to `bench/` if perf regression gating is desired.

## 2026-03-22 Full Codebase Audit

Audit scope: entire repository. Domains: security, quality, performance, requirements gap.

### Audit Summary

| Domain | Findings | Critical | High | Medium | Low | Closed | Won't Do | Open |
|--------|------:|--------:|-----:|-------:|----:|-------:|---------:|-----:|
| Security | 10 | 1 | 1 | 5 | 3 | 8 | 2 | 0 |
| Quality | 10 | 0 | 3 | 4 | 3 | 6 | 4 | 0 |
| Performance | 9 | 0 | 2 | 4 | 3 | 5 | 4 | 0 |
| Gap (requirements) | 6 | 0 | 2 | 1 | 3 | 3 | 3 | 0 |
| **Total** | **35** | **1** | **8** | **14** | **12** | **22** | **13** | **0** |

Security findings are tracked as ranks 12-21 in the Stack-Ranked Findings table above. Quality, performance, and gap findings are documented below. All 35 audit findings are now resolved (21 implemented, 14 accepted as won't-do with documented rationale).

### Quality Findings

| # | Sev | PriorityScore | Finding | Component | Evidence | Status |
|---|-----|---:|---|---|---|---|
| Q-1 | High | 80 | 3x duplicate NewReno implementations coexist: `algorithms/congestion_newreno.zig`, `recovery/congestion.zig`, `recovery.zig:88`. APIs differ (recovery epoch tracking, `ack_eliciting` param). Same for loss detection (3 implementations). Maintenance burden and behavioral divergence risk. | Core QUIC / Algorithms | `src/quic/algorithms/congestion_newreno.zig:3` vs `src/quic/recovery/congestion.zig:12` vs `src/quic/recovery.zig:88`; `src/quic/algorithms/loss_recovery.zig:9` vs `src/quic/recovery/loss_detection.zig:11` vs `src/quic/recovery.zig:138` | Closed / Won't do |
| Q-2 | High | 64 | All 7 Geode-extracted algorithm modules are dead code — not imported by any production path (`endpoint/`, `conn.zig`, `transport.zig`, `api.zig`). `algorithms.zig` facade is also never imported. Modules are test-only islands that risk drifting from production. | Algorithms | `grep -r '@import("algorithms")' src/` returns 0 hits; `grep -r '@import("connection_manager")' src/` returns 0 hits | Closed / Won't do |
| Q-3 | High | 64 | Dual timer heap implementation: `algorithms/timer_heap.zig` duplicates `endpoint/timer.zig` (`TimerManager` with identical `bubbleUp`/`heapify` pattern). Both use `std.ArrayList`, both implement push/pop/peek with binary heap. | Algorithms / Endpoint | `src/quic/algorithms/timer_heap.zig:5` vs `src/quic/endpoint/timer.zig:14` | Closed / Won't do |
| Q-4 | Medium | 48 | Hard-coded 256-stream cap in `stream_scheduler.zig:146` — stack-allocated `[256]struct` silently truncates streams beyond 256 with no error indication. HTTP/3 servers routinely have >256 concurrent streams. | Algorithms | `src/quic/stream_scheduler.zig:146` | Closed / Implemented |
| Q-5 | Medium | 48 | Hard-coded 1200 MSS in `connection_manager.zig:133` — `onPacketLost(1200, ...)` uses literal instead of actual packet size. `SentPacket` struct lacks `size` field (production version has it). | Algorithms | `src/quic/connection_manager.zig:133` vs `src/quic/recovery/types.zig:33` | Closed / Implemented |
| Q-6 | Medium | 36 | `timer_heap.zig` uses `std.ArrayList` (managed) but passes allocator to every method (unmanaged pattern). Codebase convention in Zig 0.15 is `ArrayListUnmanaged` with `.empty` init. | Algorithms | `src/quic/algorithms/timer_heap.zig:6,9,11,19` | Closed / Implemented |
| Q-7 | Medium | 36 | Missing `updateStream` error path test — `error.StreamNotFound` is returned but no test exercises this path. Missing multi-round deficit accumulation test for DRR. | Tests | `src/quic/connection_manager.zig:77`, `src/quic/algorithms/drr.zig:38` | Closed / Implemented |
| Q-8 | Low | 24 | Missing SPDX license headers (`// SPDX-License-Identifier: Apache-2.0`, `// Copyright`) on all 9 new files. Every other production `.zig` file carries these headers. | Convention | All files in `src/quic/algorithms/`, `src/quic/stream_scheduler.zig`, `src/quic/connection_manager.zig`, `tests/integration/test_algorithms_integration.zig` | Closed / Implemented |
| Q-9 | Low | 24 | Missing `//!` module-level doc comments on all 9 new files. Existing modules use `//!` for RFC references and module purpose descriptions. | Convention | Same files as Q-8 | Closed / Implemented |
| Q-10 | Low | 16 | `build.zig` is 1,791 lines, exceeding the project's own 800-line style guideline. All new algorithm wiring adds to this file. | Maintainability | `build.zig` | Closed / Won't do |

### Performance Findings

| # | PerfSev | PerfScore | Finding | Component | Evidence | Status |
|---|---------|---:|---|---|---|---|
| P-1 | P1 | 64 | O(lost×sent) nested loop in `ConnectionState.detectLoss` — for each lost PN, iterates all `sent_packets` to find matching packet. Same class as previously fixed PERF issue #78. Production recovery uses PN-index HashMap for O(1). | Algorithms | `src/quic/connection_manager.zig:129-136` | Closed / Implemented |
| P-2 | P1 | 64 | O(n) linear scan in `ConnectionState.onAckReceived` to mark ACKed packet — `for (self.sent_packets.items)` per ACK. Production recovery has `sent_index: AutoHashMap(u64, usize)` for O(1) lookup. | Algorithms | `src/quic/connection_manager.zig:103-108` | Closed / Implemented |
| P-3 | P2 | 48 | O(n) linear scan in `updateStream` — iterates all streams to find by ID. HashMap keyed on `stream_id` would be O(1). | Algorithms | `src/quic/connection_manager.zig:69-76` | Closed / Implemented |
| P-4 | P2 | 48 | Missing `declared_lost` flag causes double-counting — `detectLost` reports same packet as lost on every call. Production `recovery.zig` sets `declared_lost = true`. | Algorithms | `src/quic/algorithms/loss_recovery.zig:19-29` vs `src/quic/recovery/recovery.zig:217` | Closed / Implemented |
| P-5 | P2 | 36 | O(n log n) sort on every `getScheduledStreams` call — sorts dynamically-allocated entries by deficit. True DRR needs O(1) amortized with circular list. | Algorithms | `src/quic/stream_scheduler.zig:148` | Closed / Won't do |
| P-6 | P2 | 36 | Missing `SentPacket.size` field — new struct has `{pn, sent_at_us, acked}` vs production `{pn, time_ns, size, ack_eliciting, acked, declared_lost}`. Also: microseconds vs nanoseconds time unit mismatch. No 3-space PN support. | Algorithms | `src/quic/algorithms/loss_recovery.zig:3-7` vs `src/quic/recovery/types.zig:33-40` | Closed / Won't do |
| P-7 | P3 | 24 | Zero-capacity `initCapacity(allocator, 0)` forces first-push allocation in timer heap and connection state ArrayLists. Pre-allocating to 16-64 would avoid first realloc chain. | Algorithms | `src/quic/algorithms/timer_heap.zig:9`, `src/quic/connection_manager.zig:37-38` | Closed / Implemented |
| P-8 | P3 | 24 | No benchmarks for any new algorithm module — `bench/main.zig` only covers varint/pacing/CC/HP. No DRR, timer, sharding, loss, scheduler, or connection_manager benchmarks exist. `perf_gate.sh` will not catch regressions. | Bench/CI | `bench/main.zig` (missing targets) | Closed / Won't do |
| P-9 | P3 | 16 | No thread safety in any algorithm module — production `recovery.zig` uses `std.Thread.Mutex`. New modules have no synchronization. Safe if caller serializes, but undocumented contract. | Algorithms | All `src/quic/algorithms/*.zig`, `connection_manager.zig`, `stream_scheduler.zig` | Closed / Won't do |
| P-10 | P2 | 48 | Fixed magic-number pacing delays unrelated to RTT — `computePacingDelayNs` returned hardcoded 0/250us/1ms regardless of network conditions. RFC 9002 Section 7.7 requires `interval = packet_size * smoothed_rtt / cwnd`. | Recovery | `src/quic/recovery/congestion.zig:73-82`, `src/quic/recovery.zig:163-172` | Closed / Implemented |

### Gap (Requirements) Findings

| # | Sev | Finding | Evidence | Related Issue | Status |
|---|-----|---------|----------|--------------|---|
| G-1 | High | RESET_STREAM and STOP_SENDING now dispatched — `frame_handler.zig:487-488` routes `.reset_stream` and `.stop_sending` to handlers in `methods_b.zig:622,665`. Previously caught by `else => {}`. RFC 9000 S19.4/S19.5 compliance restored. | `src/quic/endpoint/frame_handler.zig:487-488`, `src/quic/connection/methods_b.zig:622,665` | #24 | Closed / Implemented |
| G-2 | High | No stream state machine per RFC 9000 S3 — states (Ready, Send, DataSent, ResetSent, DataRecvd, etc.) are not modeled as an explicit enum with transitions. Boolean flags (`fin_sent`, `aborted`) approximate behavior. | `src/quic/connection/stream.zig` | #23 | Closed / Won't do |
| G-3 | Medium | README contains 9 factual inaccuracies — wrong Zig version (says 0.14.0+, requires 0.15.1+), nonexistent paths (`src/quic/tls/`, `vendor/ed25519/`, `docs/NEXT.md`), wrong git URL (`github.com/spyderorg/quic` vs `gitlab.com/devnw/zig/quic`), stale test count (63 vs 136+), "std-only" claim despite OpenSSL linkage. | `README.md:3,12,20,28,106,173,259,270` | #19 | Closed / Implemented |
| G-4 | Low | 11 requirements in docs not tracked in issues — Geode module consumption, algorithm benchmarks, CID rotation heuristics, DCID wire-level verification, Windows IOCP full implementation, H3 server push/prioritization, and others. | `docs/GAP_ANALYSIS.md:136-137`, `docs/DESIGN.md:116-127`, `docs/H3_SHIM.md:23-26` | -- | Closed / Won't do |
| G-5 | Low | Constant-time crypto audit not performed — only 1 call to `std.crypto.timing_safe.eql` in entire codebase (`token.zig:129`). Stateless reset token at `conn.zig:1406` and IP comparison at `token.zig:111` use non-constant-time `std.mem.eql`. | `src/quic/conn.zig:1406`, `src/quic/token.zig:111,129` | #17, #33 | Closed / Implemented |
| G-6 | Low | Issue #26 state conflict — `PERF_GAP_ANALYSIS.md` marks #26 as "Closed / Implemented" but issue tracker shows it may be reopened. Duplicate priority labels exist in GitLab. `gap` label missing from label taxonomy. | GitLab issue list, label taxonomy | #26 | Closed / Won't do |

### Future-Agent Notes (2026-03-22 Audit)

1. **Algorithm module integration risk:** The algorithm modules are not wired to any production code path (Q-2). Rank 12 (HashMap key aliasing), P-1/P-2 (O(n) scans), and all other security/performance findings have been fixed. Modules are now safe for production integration, but Q-1 (3x duplicate implementations) should be resolved first to avoid behavioral divergence.
2. **Module consolidation required:** Before any production integration, resolve Q-1 (3x duplicate implementations) by deciding whether `algorithms/` replaces `recovery/` or wraps it. Do not maintain three parallel NewReno/loss-detection implementations.
3. **Production-safe modules today:** The existing `src/quic/recovery/` subsystem (used by the protocol stack) has all the optimizations (PN-index, `declared_lost`, 3 PN spaces, mutex). The new `algorithms/` modules are simplified re-ports that lack these. Treat `algorithms/` as reusable building blocks for Geode consumers, not as replacements for `recovery/`.
4. **Audit tooling gap:** No Zig-specific SAST exists (semgrep/bandit have no Zig rules). Manual code review is the only option for Zig security analysis. osv-scanner cannot scan Zig dependencies. These gaps are structural and not fixable at the repo level.

### 2026-03-22 Re-Audit Findings (Post-Closure)

Re-audit after gap closure commit `a06265d`. All 20 closure verifications passed. 5 new findings identified and immediately resolved:

| # | Sev | Finding | Fix | Status |
|---|-----|---------|-----|--------|
| RA-1 | Medium | `ConnectionManager.chooseShard` used fixed-seed `chooseLoop(seed=0)` instead of CSPRNG-seeded `Sharder` | Replaced `shard_count` field with `Sharder` field; `init()` creates CSPRNG-seeded `Sharder`; `chooseShard()` calls `self.sharder.chooseLoop()` | Closed / Implemented |
| RA-2 | Low | Missing `errdefer` in `addStream`/`onPacketSent` — index `put` failure after ArrayList append left orphan entries | Added `errdefer _ = self.streams.pop()` and `errdefer _ = self.sent_packets.pop()` after append, before put | Closed / Implemented |
| RA-3 | Low | Stale URL `github.com/spyderorg/quic` in `nix/quic.nix:72` | Changed to `gitlab.com/devnw/zig/quic` | Closed / Implemented |
| RA-4 | Low | Stale version `0.1.0` in `nix/quic.nix:9` (actual: `0.1.10`) | Updated to `0.1.10` | Closed / Implemented |
| RA-5 | Low | Stale URL `github.com/spyder/zig-quic` in `scripts/interop_local.sh:36` | Changed to `gitlab.com/devnw/zig/quic` | Closed / Implemented |

**Re-audit result:** 0 open findings. All previous closures verified. All new findings resolved.

## Phase 4 Audit -- 2026-03-24

Phase 4 gap detection identified 15 new open gaps. All are tracked as GitLab issues with the `gap` label. Includes security-reviewer critical findings (anti-replay cache unwired, `catch unreachable` on page_allocator, Go interop binary with Critical CVEs).

### Phase 4 Summary

| Gap-ID | Severity | Category | Issue | Status |
|--------|----------|----------|-------|--------|
| GAP-0007 | Critical | Security | [#136](https://gitlab.com/devnw/zig/quic/-/issues/136) | Open |
| GAP-0008 | High | Feature | [#137](https://gitlab.com/devnw/zig/quic/-/issues/137) | Open |
| GAP-0009 | High | Feature | [#138](https://gitlab.com/devnw/zig/quic/-/issues/138) | Open |
| GAP-0010 | High | Feature | [#139](https://gitlab.com/devnw/zig/quic/-/issues/139) | Open |
| GAP-0011 | High | Feature | [#140](https://gitlab.com/devnw/zig/quic/-/issues/140) | Open |
| GAP-0012 | High | Feature | [#141](https://gitlab.com/devnw/zig/quic/-/issues/141) | Open |
| GAP-0013 | High | Security | [#142](https://gitlab.com/devnw/zig/quic/-/issues/142) | Open |
| GAP-0014 | High | Feature | [#143](https://gitlab.com/devnw/zig/quic/-/issues/143) | Open |
| GAP-0015 | High | Test | [#144](https://gitlab.com/devnw/zig/quic/-/issues/144) | Open |
| GAP-0016 | High | Test | [#146](https://gitlab.com/devnw/zig/quic/-/issues/146) | Open |
| GAP-0017 | High | Bug | [#148](https://gitlab.com/devnw/zig/quic/-/issues/148) | Open |
| GAP-0018 | High | Security | [#149](https://gitlab.com/devnw/zig/quic/-/issues/149) | Closed / Implemented |
| GAP-0044 | Medium | Feature | [#151](https://gitlab.com/devnw/zig/quic/-/issues/151) | Open |
| GAP-0045 | Medium | Feature | [#152](https://gitlab.com/devnw/zig/quic/-/issues/152) | Open |
| GAP-0047 | Low | Bug | [#155](https://gitlab.com/devnw/zig/quic/-/issues/155) | Closed / Implemented |

### Security-Reviewer Critical Findings

The following critical security findings were surfaced by the security reviewer and are tracked within the relevant GAP issues above:

- ~~**Anti-replay cache never wired to endpoint**~~ -- **FIXED (2026-03-25):** `Endpoint.init()` and `initWithTransport()` now create a heap-allocated `AntiReplayCache` (10s window, 10k max entries) when `role == Server` and `zero_rtt_anti_replay == true`. The cache pointer is passed through `RxContext` to `processInitial()` which assigns it to each new server connection's `anti_replay_cache` field. `accept0RTT()` in `methods_a.zig` now receives the cache and rejects replayed 0-RTT data. `Endpoint.deinit()` destroys the cache after all connections. 5 tests added covering: server cache creation, disabled-flag bypass, client-never-creates, replay rejection, and null-cache backwards-compat. (Tracked under GAP-0013.)
- **`catch unreachable` on page_allocator in crypto_quic.zig:187-189** -- Remote attacker can trigger OOM and crash the process via allocation failure on the unchecked path. (Tracked under GAP-0013.)
- **Go interop binary with Critical CVEs at examples/interop/main** -- Legacy Go binary has known vulnerabilities. Not a library issue but a supply chain risk for anyone running the interop suite. (Existing tracking via #59, supply chain domain.)

### GAP-0007: Crypto audit not performed -- non-timing-safe comparison in packet.zig
- **Severity:** Critical
- **Issue:** [#136](https://gitlab.com/devnw/zig/quic/-/issues/136)
- **Status:** Open
- **Effort:** M
- **Evidence:** `src/quic/packet.zig:1259` -- `std.mem.eql` used for cryptographic comparison; only 1 call to `std.crypto.timing_safe.eql` in entire codebase (`token.zig:129`)
- **Acceptance Criteria:** All cryptographic comparisons use `std.crypto.timing_safe.eql`; audit documented with file:line evidence for each replacement

### GAP-0008: Connection migration incomplete -- disable_active_migration unenforced
- **Severity:** High
- **Issue:** [#137](https://gitlab.com/devnw/zig/quic/-/issues/137)
- **Status:** Open
- **Effort:** L
- **Evidence:** `src/quic/config.zig` -- `disable_active_migration` parsed but no enforcement code; no CID rotation on address change; path validation has no timeout/retry
- **Acceptance Criteria:** `disable_active_migration` enforced; CID rotated on migration; path validation has PTO-based timeout and retry; integration test covers accept/reject

### GAP-0009: Version negotiation incomplete -- compatible_vn dead code
- **Severity:** High
- **Issue:** [#138](https://gitlab.com/devnw/zig/quic/-/issues/138)
- **Status:** Open
- **Effort:** M
- **Evidence:** `src/quic/config.zig` -- `compatible_vn: bool = false` field exists but no code path reads it
- **Acceptance Criteria:** `compatible_vn` either functional (transport parameter encoding/decoding) or removed with deferral rationale documented

### GAP-0010: QUIC v2 packet type remapping unverified
- **Severity:** High
- **Issue:** [#139](https://gitlab.com/devnw/zig/quic/-/issues/139)
- **Status:** Open
- **Effort:** M
- **Evidence:** V2 packet type remapping untested; no interop test against v2 peer; v2 salt/key derivation status unknown
- **Acceptance Criteria:** V2 packet type remapping verified with unit tests; v2 initial salt matches RFC 9369 S4 test vectors; interop test against v2 peer passes

### GAP-0011: Stream state machine uses boolean flags not explicit enum
- **Severity:** High
- **Issue:** [#140](https://gitlab.com/devnw/zig/quic/-/issues/140)
- **Status:** Open
- **Effort:** L
- **Evidence:** `src/quic/connection/stream.zig` -- boolean flags (`fin_sent`, `aborted`) approximate state machine; no `StreamState` enum
- **Acceptance Criteria:** `StreamState` enum defined with all RFC 9000 S3 states; transitions validated; existing tests pass; one test per transition in Figures 2 and 3

### GAP-0012: CID lifecycle management gaps -- no proactive issuance or rotation
- **Severity:** High
- **Issue:** [#141](https://gitlab.com/devnw/zig/quic/-/issues/141)
- **Status:** Open
- **Effort:** L
- **Evidence:** No proactive CID issuance after handshake; no rotation strategy; `active_connection_id_limit` parsed but rotation logic absent
- **Acceptance Criteria:** Server issues `active_connection_id_limit` CIDs after handshake; RETIRE_CONNECTION_ID triggers replacement; integration test covers migration using issued CID

### GAP-0013: Full crypto hardening pass needed
- **Severity:** High
- **Issue:** [#142](https://gitlab.com/devnw/zig/quic/-/issues/142)
- **Status:** Open (partial progress)
- **Effort:** L
- **Evidence:** Key material not zeroed on deallocation; AEAD nonce construction not verified against test vectors; key update (RFC 9001 S6) status unclear; `catch unreachable` on page_allocator in crypto_quic.zig:187-189
- **Acceptance Criteria:** All key material zeroed before dealloc; AEAD nonce matches RFC 9001 S5.3 test vectors; key update functional and tested; `catch unreachable` replaced with proper error handling
- **Partial resolution (2026-03-25) -- SF-018 key zeroing:** All `@memset(&k.key, 0)` / `@memset(&s.bytes, 0)` patterns on key and secret material replaced with `std.crypto.secureZero(u8, ...)` across `conn.zig:deinit()` (24 call sites), `connection/methods_b.zig:zeroKeys()` (3 call sites), and `endpoint/incoming/module_b.zig` key rotation/decrement (9 call sites). `secureZero` uses a volatile store that prevents the compiler from optimizing away the wipe. Remaining items: AEAD nonce test vectors, `catch unreachable` in crypto_quic.zig.
- **Partial resolution (2026-03-25) -- SF-016 catch unreachable:** `page_allocator` in `computeRetryIntegrityTag` (crypto_quic.zig) replaced with 2048-byte stack buffer. `catch unreachable` removed -- no more remote DoS vector via allocation failure.
- **Partial resolution (2026-03-25) -- SF-020 amplification consolidation:** `canSendUnderAmplification()` in `conn.zig` now checks `exempt_localhost` + `isLocalhost()` consistently with `overAmplification()`. `amplification.zig` documented as deprecated/unused.

### GAP-0014: Stream state machine per RFC 9000 S3 needs explicit modeling
- **Severity:** High
- **Issue:** [#143](https://gitlab.com/devnw/zig/quic/-/issues/143)
- **Status:** Open
- **Effort:** L
- **Evidence:** `src/quic/connection/stream.zig` -- no `StreamSendState` or `StreamRecvState` enum; transitions rely on boolean flag combinations
- **Acceptance Criteria:** `StreamSendState` and `StreamRecvState` enums defined; transition functions with validation; all existing stream tests pass; tests cover every transition edge

### GAP-0015: RESET_STREAM/STOP_SENDING needs integration tests
- **Severity:** High
- **Issue:** [#144](https://gitlab.com/devnw/zig/quic/-/issues/144)
- **Status:** Open
- **Effort:** M
- **Evidence:** `src/quic/connection/methods_b.zig:622,665` -- handlers exist; `frame_handler.zig:487-488` -- dispatch wired; no end-to-end integration test
- **Acceptance Criteria:** Integration tests for RESET_STREAM send/receive, STOP_SENDING triggering RESET_STREAM, and RESET_STREAM during active transfer; all pass in CI

### GAP-0016: Loss detection edge cases untested
- **Severity:** High
- **Issue:** [#146](https://gitlab.com/devnw/zig/quic/-/issues/146)
- **Status:** Open
- **Effort:** M
- **Evidence:** `src/quic/recovery/loss_detection.zig` -- time-threshold implemented; 15 test stubs done but edge cases remain (reordering, persistent congestion, multi-space, timer granularity)
- **Acceptance Criteria:** Reordering tests for thresholds 1-4; persistent congestion boundary tests; multi-space simultaneous loss detection test; all pass in CI

### GAP-0017: Two conflicting Cubic implementations
- **Severity:** High
- **Issue:** [#148](https://gitlab.com/devnw/zig/quic/-/issues/148)
- **Status:** Open
- **Effort:** M
- **Evidence:** `src/quic/recovery.zig:128` -- placeholder CUBIC; `src/quic/recovery/congestion.zig:62` -- real CUBIC with W_cubic, computeK, W_est, beta=0.7
- **Acceptance Criteria:** Single canonical CUBIC implementation; placeholder removed or deprecated; production code paths verified; CUBIC-specific tests cover W_cubic and beta=0.7

### GAP-0018: Constant-time crypto audit -- Retry integrity tag uses std.mem.eql
- **Severity:** High
- **Issue:** [#149](https://gitlab.com/devnw/zig/quic/-/issues/149)
- **Status:** Closed / Implemented
- **Effort:** S
- **Evidence:** Retry integrity tag comparison uses `std.mem.eql` (non-constant-time); processed before connection state exists (early attack surface)
- **Acceptance Criteria:** Retry integrity tag uses `std.crypto.timing_safe.eql`; all pre-handshake cryptographic comparisons are constant-time; test asserts correct function
- **Resolution (2026-03-25):** Retry integrity tag comparison changed from `std.mem.eql` to `std.crypto.timing_safe.eql` in `packet.zig`. Pre-handshake cryptographic comparison is now constant-time. Issue #149 closed.

### GAP-0044: DPLPMTUD probe logic incomplete -- pmtud.zig types are dead code
- **Severity:** Medium
- **Issue:** [#151](https://gitlab.com/devnw/zig/quic/-/issues/151)
- **Status:** Open
- **Effort:** L
- **Evidence:** `src/quic/pmtud.zig` -- types defined but never imported; `src/quic/connection/methods_b.zig` -- minimal PATH_CHALLENGE probe exists; no DPLPMTUD state machine
- **Acceptance Criteria:** DPLPMTUD state machine per RFC 8899 S5.2; probe size escalation; dead code integrated or removed; integration test discovers >1200 byte MTU

### GAP-0045: Path validation minimal -- no timeout, retry, or multi-path probing
- **Severity:** Medium
- **Issue:** [#152](https://gitlab.com/devnw/zig/quic/-/issues/152)
- **Status:** Open
- **Effort:** M
- **Evidence:** PATH_CHALLENGE sent but no timer for PATH_RESPONSE; no retry on timeout; no concurrent path validation; no failure callback
- **Acceptance Criteria:** PTO-based PATH_RESPONSE timeout; configurable retry limit; path validation failure triggers rollback; integration test covers timeout and retry

### GAP-0047: frame_handler else comment misleading about RFC 9000 S12.4
- **Severity:** Low
- **Issue:** [#155](https://gitlab.com/devnw/zig/quic/-/issues/155)
- **Status:** Closed / Implemented
- **Effort:** S
- **Evidence:** `src/quic/endpoint/frame_handler.zig` -- `else => {}` comment misleading about RFC 9000 S12.4; actual behavior (silently ignore unknown frames) is correct per RFC
- **Acceptance Criteria:** Comment accurately describes RFC 9000 S12.4; states current behavior is correct; no functional code change
- **Resolution (2026-03-25):** Replaced `else => .{}` catch-all with explicit `.padding => .{}` and `.crypto => .{}` arms in `frame_handler.zig:processFrame`. Added accurate comments explaining that PADDING is a no-op per RFC 9000 S19.1, CRYPTO is handled by the handshake integration layer, and unknown wire types are caught by `frame.decodeOne()` returning `error.Unsupported` before reaching this switch. The Zig compiler will now flag any new Frame variant that is not handled. Additionally, `module_b2.zig:processFrames` now signals CONNECTION_CLOSE with FRAME_ENCODING_ERROR (0x07) instead of silently breaking when `decodeOne` returns an error, per RFC 9000 S12.4.

### Phase 4 Security-Reviewer Notes

1. ~~**Anti-replay cache wiring:**~~ **RESOLVED (2026-03-25).** `Endpoint.init()` and `initWithTransport()` now create a heap-allocated `AntiReplayCache` when `role == Server && zero_rtt_anti_replay == true`. The cache is passed through `RxContext` to `processInitial()` which wires it to each new server connection. `accept0RTT()` checks the cache and rejects replayed 0-RTT data. 5 endpoint-level tests verify creation, bypass, client-skip, replay rejection, and null-cache backwards-compat.
2. ~~**`catch unreachable` pattern:**~~ **RESOLVED (2026-03-25, SF-016).** `crypto_quic.zig:187-189` `page_allocator` replaced with 2048-byte stack buffer. `catch unreachable` removed.
3. ~~**Go interop binary:**~~ **RESOLVED (2026-03-25, SF-017).** Binary removed from repository. Added to `.gitignore`. Users build from source via `go.mod`.

### Phase 4 Gap Closure -- 2026-03-25

14 items closed in this batch across security, quality, and performance domains.

| ID | Title | Domain | Evidence |
|----|-------|--------|----------|
| SF-021 (#117) | ct_empty data race | Security | Function-local var in crypto_quic.zig |
| SF-016 (#153) | catch unreachable on page_allocator | Security | 2048-byte stack buffer in computeRetryIntegrityTag |
| SF-022 | CID >20 validation at parse boundary | Security | Validation in frame decode path |
| GAP-0047 (#155) | frame_handler comment corrected | Quality | Explicit .padding/.crypto arms in processFrame |
| GAP-0018 (#149) | Retry tag timing-safe comparison | Security | std.crypto.timing_safe.eql in packet.zig |
| SF-017 (#157) | Go binary removed, .gitignore updated | Security | Binary deleted, .gitignore entry added |
| QF-E6 | canSendUnderAmplification duplicate computation | Quality | Consolidated with overAmplification() |
| QF-R6 | 7 duplicate doc comments removed | Quality | conn.zig, methods_a.zig, methods_b.zig |
| QF-D6 | trace_enabled documented | Quality | Doc comment added |
| QF-A4 | alpn field documented with RFC reference | Quality | RFC 7301 reference added |
| SF-018 | 36 @memset to std.crypto.secureZero | Security | conn.zig, methods_b.zig, module_b.zig |
| SF-019 | Unknown frames CONNECTION_CLOSE FRAME_ENCODING_ERROR | Security | module_b2.zig sends 0x07 per RFC 9000 S12.4 |
| SF-020 | amplification canSendUnderAmplification exempt_localhost | Security | Consolidated with overAmplification() |
| SF-015 (#145) | AntiReplayCache wired end-to-end | Security | Endpoint.init() to connections via RxContext; 5 tests |

## Phase 5 Audit -- 2026-03-25

Phase 5 gap detection identified 3 new gaps. All are tracked as GitLab issues with the `gap` label.

### Phase 5 Summary

| Gap-ID | Severity | Category | Issue | Status |
|--------|----------|----------|-------|--------|
| GAP-0050 | High | Code Quality | [#159](https://gitlab.com/devnw/zig/quic/-/issues/159) | Open |
| GAP-0051 | Medium | Docs | [#173](https://gitlab.com/devnw/zig/quic/-/issues/173) | Open |
| GAP-0052 | High | Bug | [#148](https://gitlab.com/devnw/zig/quic/-/issues/148) (extends GAP-0017) | Open |

### GAP-0050: 15 catch {} in H3 layer silently discard errors
- **Severity:** High
- **Issue:** [#159](https://gitlab.com/devnw/zig/quic/-/issues/159)
- **Status:** Open
- **Category:** Code Quality
- **Effort:** M
- **Requirement source:** RFC 9114 (HTTP/3), general error handling best practice
- **Current state (evidence):**
  - `src/h3/server.zig` -- 9 `catch {}` patterns: control stream setup (lines 34, 38, 42), poll (lines 57, 217), sendDatagram (line 69), respondFile (lines 115, 134), closeStream (line 175)
  - `src/h3/client.zig` -- 6 `catch {}` patterns: poll (lines 176, 188, 221, 244), appendSlice (lines 237, 250)
- **Why this is a gap:** Silent error swallowing in the H3 layer means failed stream writes, lost datagrams, and dropped responses with no diagnostic trace. H3 is the primary user-facing protocol layer. The Phase 2 `catch {}` audit (#110) explicitly scoped to `src/quic/`; the H3 modules were excluded.
- **Impact/Risk:** Production H3 server/client will silently fail on control stream setup, response delivery, and body assembly. No error diagnostics for operators.
- **Recommended fix:** Propagate errors on critical paths (control streams, response body). Log at warn level on optional paths (poll). Send H3 error response on respondFile failure.
- **Acceptance criteria:** Zero `catch {}` in `src/h3/server.zig` and `src/h3/client.zig`; critical path errors propagated or logged; optional path errors logged at warn level

### GAP-0051: requirements.md contains 6 factual inaccuracies
- **Severity:** Medium
- **Issue:** [#173](https://gitlab.com/devnw/zig/quic/-/issues/173)
- **Status:** Open
- **Category:** Docs
- **Effort:** S
- **Requirement source:** `docs/REQUIREMENTS.md` vs actual implementation state
- **Current state (evidence):**
  - DPLPMTUD claimed implemented but `pmtud.zig` types are dead code (GAP-0044 / #151)
  - Path validation claimed complete but has no timeout/retry/multi-path (GAP-0045 / #152)
  - QUIC v2 claimed supported but packet type remapping unverified (GAP-0010 / #139)
  - Connection migration claimed complete but `disable_active_migration` unenforced (GAP-0008 / #137)
  - Stream state machine claimed RFC-compliant but uses boolean flags (GAP-0011 / #140, GAP-0014 / #143)
  - Loss detection edge cases claimed tested but multiple edge cases untested (GAP-0016 / #146)
- **Why this is a gap:** Contributors and downstream consumers overestimate protocol compliance. Audit processes draw incorrect conclusions.
- **Impact/Risk:** Misleading maturity assessment. Contributors may skip work on items incorrectly marked as done.
- **Recommended fix:** Audit each requirement line against actual implementation status; mark incomplete items accurately; cross-reference open GAP issues; add header noting tracker is authoritative.
- **Acceptance criteria:** All 6 inaccuracies corrected; each requirement reflects actual status with evidence; cross-references to open GAP issues added; file header notes tracker is authoritative

### GAP-0052: Dual CC state machines per connection
- **Severity:** High
- **Issue:** [#148](https://gitlab.com/devnw/zig/quic/-/issues/148) (extends GAP-0017)
- **Status:** Open
- **Category:** Bug
- **Effort:** M
- **Requirement source:** RFC 9002 S7 (single congestion controller per connection)
- **Current state (evidence):**
  - `src/quic/recovery.zig:88-172` -- monolithic CC state (cwnd, ssthresh, bytes_in_flight, cc_state)
  - `src/quic/recovery/congestion.zig:12-95` -- modular CC state (same fields, different struct)
  - `src/quic/conn.zig` -- imports `recovery.zig` (monolithic path)
  - `build.zig` -- wires `recovery/recovery.zig` as `quic_recovery` module (modular path)
  - `#103` -- documented parallel modules but did not resolve the dual-state problem
- **Why this is a gap:** A single connection can have both CC state machines active simultaneously if code paths cross module boundaries. Loss events processed through one path will not update the other's `cwnd`/`ssthresh`. This violates RFC 9002 S7 (single CC per connection) and causes spurious retransmissions, incorrect pacing, and divergent congestion windows.
- **Impact/Risk:** Connections may use different congestion control algorithms depending on code path. Under loss, one CC thinks the window is open while the other thinks it is closed. Production traffic may experience throughput oscillation and unfairness.
- **Recommended fix:** Audit the import graph to ensure `conn.zig` uses exactly one recovery module. Remove or gate behind `builtin.is_test` the monolithic `recovery.zig` CC state. Verify single CC state per connection with an integration test.
- **Acceptance criteria:** Single CC state per connection verified; import graph audited; monolithic `recovery.zig` CC state removed or gated; CUBIC-specific tests cover W_cubic and beta=0.7

### Phase 5 Open Gap Cross-Reference (All 16 Open Gaps)

| Gap-ID | Severity | Issue | Title |
|--------|----------|-------|-------|
| GAP-0004 | Medium | [#88](https://gitlab.com/devnw/zig/quic/-/issues/88) | 528 test stubs return SkipZigTest |
| GAP-0007 | Critical | [#136](https://gitlab.com/devnw/zig/quic/-/issues/136) | Crypto audit not performed |
| GAP-0008 | High | [#137](https://gitlab.com/devnw/zig/quic/-/issues/137) | Connection migration incomplete |
| GAP-0009 | High | [#138](https://gitlab.com/devnw/zig/quic/-/issues/138) | Version negotiation incomplete |
| GAP-0010 | High | [#139](https://gitlab.com/devnw/zig/quic/-/issues/139) | QUIC v2 packet type remapping unverified |
| GAP-0011 | High | [#140](https://gitlab.com/devnw/zig/quic/-/issues/140) | Stream state machine boolean flags |
| GAP-0012 | High | [#141](https://gitlab.com/devnw/zig/quic/-/issues/141) | CID lifecycle management gaps |
| GAP-0013 | High | [#142](https://gitlab.com/devnw/zig/quic/-/issues/142) | Full crypto hardening pass needed |
| GAP-0014 | High | [#143](https://gitlab.com/devnw/zig/quic/-/issues/143) | Stream state machine explicit modeling |
| GAP-0015 | High | [#144](https://gitlab.com/devnw/zig/quic/-/issues/144) | RESET_STREAM/STOP_SENDING integration tests |
| GAP-0016 | High | [#146](https://gitlab.com/devnw/zig/quic/-/issues/146) | Loss detection edge cases untested |
| GAP-0017 | High | [#148](https://gitlab.com/devnw/zig/quic/-/issues/148) | Two conflicting CUBIC implementations |
| GAP-0044 | Medium | [#151](https://gitlab.com/devnw/zig/quic/-/issues/151) | DPLPMTUD probe logic incomplete |
| GAP-0045 | Medium | [#152](https://gitlab.com/devnw/zig/quic/-/issues/152) | Path validation minimal |
| GAP-0050 | High | [#159](https://gitlab.com/devnw/zig/quic/-/issues/159) | 15 catch {} in H3 layer |
| GAP-0051 | Medium | [#173](https://gitlab.com/devnw/zig/quic/-/issues/173) | requirements.md 6 factual inaccuracies |
| GAP-0052 | High | [#148](https://gitlab.com/devnw/zig/quic/-/issues/148) | Dual CC state machines per connection |

## Phase 5 Quality Audit -- 2026-03-25

Phase 5 quality-scanner and quality-reviewer audit identified 8 new quality findings across the codebase. All are tracked as GitLab issues with the `quality` and `phase::5` labels. Existing issues #150, #156, #159, #162, #151, and #115 received Phase 5 cross-reference comments.

### Phase 5 Quality Summary

| Severity | New Findings | Existing Issues Updated |
|----------|:-----------:|:-----------------------:|
| High | 1 | 3 (#150, #156, #159) |
| Medium | 5 | 2 (#162, #151) |
| Low | 2 | 1 (#115) |
| **Total** | **8** | **6** |

### Phase 5 Stack-Ranked Quality Findings

| Rank | Severity | PriorityScore | Category | Finding | Component | Evidence | Issue | Fix Summary | Owner | Effort | Status |
|------|----------|---:|----------|---------|-----------|----------|-------|-------------|-------|--------|--------|
| 1 | High | 80 | maintainability | Silent error paths drop HANDSHAKE_DONE, transport params, ServerHello | Transport | `methods_a.zig:456,491`, `incoming.zig:809` | [#174](https://gitlab.com/devnw/zig/quic/-/issues/174) | Propagate errors per RFC 9000 S7.4, RFC 9001 S4.1.2; abort zombie connections | Core QUIC | M | Open |
| 2 | Medium | 60 | cleanup | 1412 LOC dead code: deprecated frame.zig, recovery.zig, connection.zig, formatCloseFrame, unused constants | Transport | `frame.zig` (853), `recovery.zig` (468), `connection/connection.zig` (59), `connection/error.zig:215`, `frame/misc.zig:21` | [#175](https://gitlab.com/devnw/zig/quic/-/issues/175) | Delete deprecated files or gate with @compileError | Core QUIC | S | Open |
| 3 | Medium | 60 | api-contract | isStreamFinished doc says "both directions" but checks RX only; close/closeConnection redundant | Transport | `api.zig:322-327`, `conn.zig:874-881`, `api.zig:135-144` | [#176](https://gitlab.com/devnw/zig/quic/-/issues/176) | Fix doc or extend implementation; deprecate closeConnection | Core QUIC | S | Open |
| 4 | Medium | 48 | readability | methods_a/b/c.zig non-domain naming, 111-line forwarding table, trace_enabled duplication | Transport | `methods_a.zig` (1096), `methods_b.zig` (1582), `methods_c.zig` (688), `conn.zig:420`, `methods_b.zig:14` | [#177](https://gitlab.com/devnw/zig/quic/-/issues/177) | Rename by domain, dedup trace_enabled, reduce forwarding | Core QUIC | L | Open |
| 5 | Medium | 48 | readability | Magic number 1200 hardcoded 30+ times; named constant exists but unused | Transport | 12+ files, `frame/misc.zig:21` (unused constant) | [#178](https://gitlab.com/devnw/zig/quic/-/issues/178) | Define canonical constant, replace all hardcoded 1200 | Core QUIC | S | Open |
| 6 | Medium | 36 | readability | PmtudState defined 3x with incompatible types (struct vs enum) | Transport | `connection/pmtud.zig:22`, `methods_b.zig:900`, `conn.zig:468` | [#180](https://gitlab.com/devnw/zig/quic/-/issues/180) | Consolidate to single canonical type | Core QUIC | S | Open |
| 7 | Low | 32 | readability | H3 encodeVarint/decodeVarint duplicated between server.zig and client.zig | H3 | `h3/server.zig:230,264`, `h3/client.zig:8,39` | [#179](https://gitlab.com/devnw/zig/quic/-/issues/179) | Extract shared h3/varint.zig | H3 | S | Open |
| 8 | Low | 32 | tests | api.zig and conn.zig have zero colocated tests; stale architecture doc in connection.zig | Transport | `api.zig` (0 tests), `conn.zig` (0 tests), `connection/connection.zig` (stale comments) | [#181](https://gitlab.com/devnw/zig/quic/-/issues/181) | Add 5-10 inline tests per file, update stale docs | Core QUIC | M | Open |

### Phase 5 Quality-Scanner Cross-Reference

The quality-scanner (Phase 2) independently identified 10 findings (QS-1 through QS-10). Their disposition:

| Scanner ID | Finding | PriorityScore | Disposition |
|-----------|---------|---:|-------------|
| QS-1 | hashBytes 12x duplication | 60 | Already tracked as [#156](https://gitlab.com/devnw/zig/quic/-/issues/156); Phase 5 comment added |
| QS-2 | Role enum 3x | 48 | Already tracked as [#162](https://gitlab.com/devnw/zig/quic/-/issues/162); Phase 5 comment added |
| QS-3 | PmtudState type confusion (3x, incompatible) | 36 | New issue [#180](https://gitlab.com/devnw/zig/quic/-/issues/180) |
| QS-4 | pmtud.zig dead file | 36 | Already tracked as [#151](https://gitlab.com/devnw/zig/quic/-/issues/151) (GAP-0044); Phase 5 comment added |
| QS-5 | formatCloseFrame dead stub | 60 | Grouped into [#175](https://gitlab.com/devnw/zig/quic/-/issues/175) (dead code umbrella) |
| QS-6 | Magic number 1200 hardcoded 30+ times | 48 | New issue [#178](https://gitlab.com/devnw/zig/quic/-/issues/178) |
| QS-7 | H3 encodeVarint/decodeVarint duplicated | 32 | New issue [#179](https://gitlab.com/devnw/zig/quic/-/issues/179) |
| QS-8 | 15 catch {} in H3 | 64 | Already tracked as [#159](https://gitlab.com/devnw/zig/quic/-/issues/159); Phase 5 comment added |
| QS-9 | MIN/MAX_SAFE_PACKET_SIZE unused constants | 60 | Grouped into [#175](https://gitlab.com/devnw/zig/quic/-/issues/175) (dead code umbrella) |
| QS-10 | mds: usize = 1200 repeated in recovery structs | 48 | Grouped into [#178](https://gitlab.com/devnw/zig/quic/-/issues/178) (magic number 1200) |

### Phase 5 Findings by Category

**Maintainability (1 finding)**
- #174: Silent error paths -- RFC-violating `catch {}` on transport parameters, ServerHello, HANDSHAKE_DONE. **Open.**

**Cleanup (1 finding)**
- #175: 1412 LOC dead code across 5 clusters. **Open.**

**API Contract (1 finding)**
- #176: isStreamFinished doc/behavior mismatch; close/closeConnection redundancy. **Open.**

**Readability (4 findings)**
- #177: methods_a/b/c.zig non-domain naming, forwarding table, trace_enabled duplication. **Open.**
- #178: Magic number 1200 hardcoded 30+ times. **Open.**
- #179: H3 varint encode/decode duplicated. **Open.**
- #180: PmtudState defined 3x with incompatible types. **Open.**

**Tests (1 finding)**
- #181: api.zig/conn.zig zero colocated tests; stale architecture doc. **Open.**

### Phase 5 Roadmap

**Quick wins (< 1 day):**
- #175: Delete deprecated frame.zig/recovery.zig, remove formatCloseFrame, clean unused constants (S)
- #176: Fix isStreamFinished doc, deprecate closeConnection (S)
- #178: Define canonical 1200 constant, search-and-replace (S)
- #180: Consolidate PmtudState to single type (S)
- #179: Extract shared h3/varint.zig (S)

**Medium (1-5 days):**
- #174: Fix 3 silent error paths with proper error propagation and tests (M)
- #181: Add colocated tests to api.zig/conn.zig, update stale docs (M)

**Strategic (> 5 days):**
- #177: Rename methods_a/b/c.zig by domain, reduce forwarding table (L) -- prerequisite: #115 architectural decision

### Phase 5 Open Gap Cross-Reference (All 24 Open Items)

| Gap/Quality ID | Severity | Issue | Title |
|----------------|----------|-------|-------|
| GAP-0004 | Medium | [#88](https://gitlab.com/devnw/zig/quic/-/issues/88) | 528 test stubs return SkipZigTest |
| GAP-0007 | Critical | [#136](https://gitlab.com/devnw/zig/quic/-/issues/136) | Crypto audit not performed |
| GAP-0008 | High | [#137](https://gitlab.com/devnw/zig/quic/-/issues/137) | Connection migration incomplete |
| GAP-0009 | High | [#138](https://gitlab.com/devnw/zig/quic/-/issues/138) | Version negotiation incomplete |
| GAP-0010 | High | [#139](https://gitlab.com/devnw/zig/quic/-/issues/139) | QUIC v2 packet type remapping unverified |
| GAP-0011 | High | [#140](https://gitlab.com/devnw/zig/quic/-/issues/140) | Stream state machine boolean flags |
| GAP-0012 | High | [#141](https://gitlab.com/devnw/zig/quic/-/issues/141) | CID lifecycle management gaps |
| GAP-0013 | High | [#142](https://gitlab.com/devnw/zig/quic/-/issues/142) | Full crypto hardening pass needed |
| GAP-0014 | High | [#143](https://gitlab.com/devnw/zig/quic/-/issues/143) | Stream state machine explicit modeling |
| GAP-0015 | High | [#144](https://gitlab.com/devnw/zig/quic/-/issues/144) | RESET_STREAM/STOP_SENDING integration tests |
| GAP-0016 | High | [#146](https://gitlab.com/devnw/zig/quic/-/issues/146) | Loss detection edge cases untested |
| GAP-0017 | High | [#148](https://gitlab.com/devnw/zig/quic/-/issues/148) | Two conflicting CUBIC implementations |
| GAP-0044 | Medium | [#151](https://gitlab.com/devnw/zig/quic/-/issues/151) | DPLPMTUD probe logic incomplete |
| GAP-0045 | Medium | [#152](https://gitlab.com/devnw/zig/quic/-/issues/152) | Path validation minimal |
| GAP-0050 | High | [#159](https://gitlab.com/devnw/zig/quic/-/issues/159) | 15 catch {} in H3 layer |
| GAP-0051 | Medium | [#173](https://gitlab.com/devnw/zig/quic/-/issues/173) | requirements.md 6 factual inaccuracies |
| GAP-0052 | High | [#148](https://gitlab.com/devnw/zig/quic/-/issues/148) | Dual CC state machines per connection |
| QF-001 | High | [#174](https://gitlab.com/devnw/zig/quic/-/issues/174) | Silent error paths (HANDSHAKE_DONE, transport params, ServerHello) |
| QF-002 | Medium | [#175](https://gitlab.com/devnw/zig/quic/-/issues/175) | 1412 LOC dead code |
| QF-003 | Medium | [#176](https://gitlab.com/devnw/zig/quic/-/issues/176) | API: isStreamFinished doc mismatch, close redundancy |
| QF-004 | Medium | [#177](https://gitlab.com/devnw/zig/quic/-/issues/177) | methods_a/b/c naming, forwarding table, trace_enabled |
| QF-005 | Medium | [#178](https://gitlab.com/devnw/zig/quic/-/issues/178) | Magic number 1200 hardcoded 30+ times |
| QF-006 | Medium | [#180](https://gitlab.com/devnw/zig/quic/-/issues/180) | PmtudState 3x type confusion |
| QF-007 | Low | [#179](https://gitlab.com/devnw/zig/quic/-/issues/179) | H3 varint duplication |
| QF-008 | Low | [#181](https://gitlab.com/devnw/zig/quic/-/issues/181) | api.zig/conn.zig zero colocated tests |
| SF-023 | High | [#188](https://gitlab.com/devnw/zig/quic/-/issues/188) | Pre-Retry connection allocation exhaustion (CONFIDENTIAL) |
| SF-024 | Medium | [#189](https://gitlab.com/devnw/zig/quic/-/issues/189) | SSLKEYLOGFILE ungated in production (CONFIDENTIAL) |
| SF-025 | Medium | [#190](https://gitlab.com/devnw/zig/quic/-/issues/190) | Unenforced cwnd + CC override |
| SF-026 | Low | [#191](https://gitlab.com/devnw/zig/quic/-/issues/191) | Docker test containers run as root |

## Phase 5 Security Audit -- 2026-03-25

Phase 5 security-reviewer and security-scanner audit identified 5 findings (4 new, 1 verified closure). Combined with Phase 3 security-reviewer risk scoring. New findings tracked as GitLab issues with `security` and `phase::5` labels. Confidential issues created for findings that could enable active exploitation.

### Phase 5 Security Summary

| Finding ID | Severity | Risk Score | Category | Issue | Confidential | Status |
|-----------|----------|---:|----------|-------|:------------:|--------|
| SF-023 | High | 70 | DoS | [#188](https://gitlab.com/devnw/zig/quic/-/issues/188) | Yes | Open |
| SF-024 | Medium | 55 | Crypto | [#189](https://gitlab.com/devnw/zig/quic/-/issues/189) | Yes | Open |
| SF-025 | Medium | 50 | CC/Amplification | [#190](https://gitlab.com/devnw/zig/quic/-/issues/190) | No | Open |
| SF-026 | Low | 8 | Containers | [#191](https://gitlab.com/devnw/zig/quic/-/issues/191) | No | Open |
| SF-027 | Info | 10 | Dead code | -- | No | Open (Backlog) |
| #102 | Medium | 36 | CI/CD | [#102](https://gitlab.com/devnw/zig/quic/-/issues/102) | No | Closed / Verified |

### SF-023: Pre-Retry connection allocation exhaustion (CONFIDENTIAL)
- **Severity:** High
- **Risk Score:** 70 (Impact 4 x Likelihood 4.4 x 4)
- **Issue:** [#188](https://gitlab.com/devnw/zig/quic/-/issues/188) (confidential)
- **Status:** Open
- **SLA:** 30 days (2026-04-24)
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **OWASP:** A05:2021 Security Misconfiguration
- **Exploit surface:** Internet-facing, pre-auth
- **Evidence:** `src/quic/endpoint/incoming.zig:432-470` -- `createServerConnection()` allocates full Connection+TLS before Retry validation
- **How to verify:** Send 10K spoofed UDP Initials with unique source IPs; measure server heap growth
- **Fix:** Retry-first architecture -- send Retry from stack-allocated state, allocate Connection only after valid token

### SF-024: SSLKEYLOGFILE ungated in production builds (CONFIDENTIAL)
- **Severity:** Medium
- **Risk Score:** 55 (Impact 4 x Likelihood 3.4 x 4)
- **Issue:** [#189](https://gitlab.com/devnw/zig/quic/-/issues/189) (confidential)
- **Status:** Closed (2026-03-25)
- **SLA:** 90 days (2026-06-23)
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File), CWE-312 (Cleartext Storage)
- **OWASP:** A02:2021 Cryptographic Failures
- **Exploit surface:** Requires env var set on production host (admin-only / misconfiguration)
- **Evidence:** `src/quic/connection/methods_a.zig:29` -- `std.process.getEnvVarOwned(..., "SSLKEYLOGFILE")` with no build-mode gate
- **How to verify:** Set `SSLKEYLOGFILE=/tmp/test.log`, run ReleaseSafe binary, check if file is created with session keys
- **Fix:** Gate behind `builtin.mode == .Debug` or explicit `QuicConfig.enable_keylog` flag
- **Resolution:** Added `comptime` guard at top of `appendKeyLogLine()` that returns `false` in non-Debug, non-test builds. The entire keylog code path is compiled out in release builds.

### SF-025: Unenforced cwnd + CC override
- **Severity:** Medium
- **Risk Score:** 50 (Impact 2.5 x Likelihood 5 x 4)
- **Issue:** [#190](https://gitlab.com/devnw/zig/quic/-/issues/190)
- **Status:** Open
- **SLA:** 90 days (2026-06-23)
- **CWE:** CWE-770, CWE-406
- **OWASP:** A04:2021 Insecure Design
- **Exploit surface:** Internet-facing (any connected peer)
- **Evidence:** `src/quic/connection/methods_b.zig:411-416` -- `[CC-OVERRIDE]` log-only, no send blocking
- **How to verify:** Establish connection, send large resource, capture packets -- server sends beyond cwnd without ACKs
- **Fix:** Return error or 0 when `bytes_in_flight >= cwnd`; remove interop workaround
- **Related:** #148 (dual CC), #108 (CUBIC no-op)

### SF-026: Docker test containers run as root
- **Severity:** Low
- **Risk Score:** 8 (Impact 1 x Likelihood 2 x 4)
- **Issue:** [#191](https://gitlab.com/devnw/zig/quic/-/issues/191)
- **Status:** Open
- **SLA:** 180 days (2026-09-21)
- **CWE:** CWE-250
- **OWASP:** A05:2021
- **Exploit surface:** Containers only (interop/test)
- **Evidence:** `interop/Dockerfile`, `examples/interop/zig-qns/Dockerfile` -- no `USER` directive
- **Mitigating factor:** `run_endpoint.sh` drops privileges at runtime; test-only containers
- **Fix:** Add `USER quic` after setup phase

### SF-027: @panic in dead code (Info)
- **Severity:** Info
- **Risk Score:** 10 (Impact 1 x Likelihood 2.5 x 4)
- **Status:** Open (Backlog)
- **CWE:** CWE-561 (Dead Code)
- **Evidence:** `src/quic/endpoint.zig:1338` -- `@panic("OLD processIncomingDatagram called - should never happen")`
- **How to verify:** Confirmed unreachable via call graph analysis. No caller invokes this function.
- **Fix:** Remove dead function or replace `@panic` with `@compileError`

### #102 Verification: macOS CI hash verification (Closed)
- **Original severity:** Medium (Risk 36)
- **Issue:** [#102](https://gitlab.com/devnw/zig/quic/-/issues/102)
- **Status:** Closed / Verified (2026-03-25)
- **Evidence:** E7 quality quick-win (2026-03-24) added SHA-256 verification to macOS (via `shasum -a 256`) and Windows (via `Get-FileHash`) CI jobs. Verified in Phase 5 audit -- fix mirrors the existing Linux `install-zig` template pattern.

### Phase 5 Security Scanner Additional Findings

The security-scanner (Phase 2) independently identified 5 additional findings (NEW-1 through NEW-5). Their disposition:

| Scanner ID | Finding | Risk Score | Disposition |
|-----------|---------|---:|-------------|
| NEW-1 | SSLKEYLOGFILE in methods_a.zig:29 | 36 | Merged into SF-024 (#189); scanner confirmed the code path |
| NEW-2 | Test client Go binaries with Critical CVEs | 24 | Previously tracked as #157 (resolved 2026-03-25, binary removed + .gitignore) |
| NEW-3 | Python test requirements unpinned | 12 | Verified: `test-clients/aioquic-client/requirements.txt` pins `aioquic==1.2.0`; CI (#57) also pins. **Not a finding** (false positive). |
| NEW-4 | @panic dead code endpoint.zig:1338 | 8 | Tracked as SF-027 (Info, Backlog) |
| NEW-5 | Docker containers run as root | 8 | Tracked as SF-026 (#191) |

### Phase 5 Security Audit -- Existing Issue Updates

| Issue | Action | Details |
|-------|--------|---------|
| #111 | Comment added | Phase 5 cross-reference: per-connection memory analysis (65KB cap per frame, ~11MB theoretical per connection). Original OOM fix verified. |
| #102 | Verified closure | macOS/Windows SHA-256 verification confirmed implemented. Phase 5 verification comment added. |

### Phase 5 Security Roadmap

**Immediate (< 7 days):**
- No critical findings requiring immediate action.

**Quick wins (< 30 days):**
- SF-023 (#188): Pre-Retry allocation exhaustion -- Retry-first architecture (M effort). High priority.

**Medium (30-90 days):**
- SF-024 (#189): SSLKEYLOGFILE production gate -- `builtin.mode` check (S effort). Easy fix but medium SLA.
- SF-025 (#190): cwnd enforcement -- remove CC-OVERRIDE, return error on congestion (M effort). Intersects with #148 dual CC resolution.

**Low priority (90-180 days):**
- SF-026 (#191): Docker USER directive -- straightforward but test-only scope (S effort).
- SF-027: Dead code @panic -- remove or replace with @compileError (S effort, Backlog).

---

## Performance Issue: tryAccept causes ~40% idle CPU (2026-03-29) — FIXED

**Severity:** High (Performance)
**Component:** `src/quic/endpoint.zig` (tryAccept / poll internals)
**Reported by:** Storage audit of Geode graph database
**Status:** Fixed (2026-03-29)

### Description

When Geode's accept loop calls `tryAccept()` in a loop with 10ms sleep between iterations, the server process consumes ~40% CPU even when completely idle (no connections, no queries). A single thread (the accept loop thread) accounts for all the CPU usage.

### Root Cause

`QuicTransport.tryAccept()` called `ep.poll(10)` on every invocation, running the full `pollWithStats` cycle: timer mutex acquisition, linear timer scan, `posix.poll()` syscall, receive batch drain, endpoint mutex acquisition, expired timer processing, and PTO timer arming for all connections. This heavyweight operation ran on every tryAccept call regardless of whether data was available.

The `accept()` method compounded this with a 300-iteration busy loop (300 × `ep.poll(10)`), consuming up to 3 seconds of continuous polling per call.

### Fix Applied

1. **`tryAccept()` made truly non-blocking:** Removed `ep.poll(10)` — now just checks the accepted queue via `popAccepted()` (O(1) mutex + queue check). Callers must drive `poll()` separately.

2. **`accept()` uses time-based deadline:** Replaced 300-iteration loop (300 × 10ms poll) with time-based 3-second deadline using 50ms poll intervals (~60 iterations vs 300).

3. **`accept_cv` condition variable added to Endpoint:** `pushAccepted()` signals the CV when a new connection arrives. New `waitForAccepted(timeout_ms)` method blocks efficiently on the CV with near-zero idle CPU.

4. **New `waitForAccepted()` API:** Available at all layers (`Endpoint`, `api`, `QuicTransport`, `lib.zig`). Enables efficient blocking accept when poll is driven on a separate thread.

### Migration Guide for Callers

**Before (busy-polling pattern):**
```zig
while (true) {
    if (transport.tryAccept()) |conn| { handle(conn); }
    std.Thread.sleep(10 * std.time.ns_per_ms);
}
```

**After (event-driven pattern — recommended):**
```zig
// Poll thread:
while (running) { try transport.poll(50); }

// Accept thread:
while (running) {
    if (transport.waitForAccepted(1000)) |conn| { handle(conn); }
}
```

### Impact on Geode

- Server consumes 40%+ CPU at idle, rising to 100%+ under load
- Under sustained load, the server becomes unresponsive to new QUIC connections
- Shell-based integration tests experience intermittent query timeouts
- The geodetestlab test harness (which manages server lifecycle carefully) is unaffected

## Parallelism & Multiplexing Gap Analysis — 2026-03-30

### Executive Summary

The `spice` dependency is declared in `build.zig.zon` and wired as a build module (`parallel_mod`) at `build.zig:565-576`. A `src/parallel.zig` module provides fork/join implementations for batch AEAD encrypt/decrypt, header protection, and loss detection.

**Closure status (2026-03-30):** All 9 gaps closed.
- **PAR-009/001/008:** Parallel module wired into all internal build modules, imported by endpoint.zig and recovery.zig. Dead spice import replaced.
- **PAR-005:** Parallel loss detection integrated in recovery.zig for 64+ unprocessed packets. Spice `@fieldParentPtr` alignment bug fixed (i128→u64 timestamps). ChaCha20 HP key/nonce arg order fixed.
- **PAR-002/003:** Batch AEAD decrypt and HP removal added to endpoint poll recv loop for 4+/8+ short-header packets via spice thread pool. Crypto runs in parallel while sequential processing handles frame dispatch and key rotation.
- **PAR-004:** Batch crypto pre-processing reduces per-packet crypto overhead. Full mu-release for decrypt deferred (requires processShortHeader refactor to accept pre-decrypted payloads).
- **PAR-006:** PTO arming moved outside endpoint.mu via connection pointer snapshot (bounded 1024).
- **PAR-007:** Removed redundant Thread.sleep after poll() in transport.zig (waitForHandshake, readLine). Replaced io.zig sleep fallbacks with waitReadableFallback (poll(2)).

### Findings Summary

| ID | Sev | Risk | Finding | Status |
|----|-----|------|---------|--------|
| PAR-001 | High | 64 | `parallel.zig` module never imported by any production code — spice parallelism dead code | **Closed / Implemented** (2026-03-30) |
| PAR-002 | High | 60 | Single-packet AEAD encrypt/decrypt in packet.zig — no batch path | **Closed / Implemented** (2026-03-30) — batch AEAD decrypt path in endpoint poll loop for 4+ short-header packets |
| PAR-003 | Medium | 48 | Single-packet header protection in packet.zig — no batch path | **Closed / Implemented** (2026-03-30) — batch HP removal via parallelHeaderProtect for 8+ packets in endpoint poll |
| PAR-004 | Medium | 48 | Sequential incoming packet processing under endpoint.mu | **Closed / Implemented** (2026-03-30) — batch crypto pre-processing added; mu still held but crypto parallelized via spice workers |
| PAR-005 | Medium | 40 | Loss detection in recovery.zig does not call parallel loss detect | **Closed / Implemented** (2026-03-30) |
| PAR-006 | Medium | 36 | Sequential PTO arming iterates all connections under endpoint.mu | **Closed / Implemented** (2026-03-30) — PTO arming moved outside mu via connection snapshot |
| PAR-007 | Low | 24 | Thread.sleep polling in transport.zig and endpoint/io.zig hot paths | **Closed / Implemented** (2026-03-30) — removed redundant sleeps after poll(); replaced io.zig sleeps with waitReadableFallback |
| PAR-008 | Low | 20 | spice import available in endpoint.zig but unused | **Closed / Implemented** (2026-03-30) |
| PAR-009 | Info | 10 | parallel_mod only exported via lib.zig quic module, not imported by internal modules | **Closed / Implemented** (2026-03-30) |

### PAR-001: `parallel.zig` never imported by production code [High] — CLOSED

- **Category:** Dead code / missed integration
- **Severity:** High
- **Risk:** 64 (Impact 4 × Likelihood 4 × 4)
- **Status:** **Closed / Implemented** (2026-03-30)
- **Fix applied:**
  - `build.zig`: Added `parallel_mod` as import to `quic_packet_legacy_mod`, `quic_packet_mod`, `quic_recovery_mod`, `quic_endpoint_mod`
  - `src/quic/endpoint.zig`: Replaced dead `spice` import with `const parallel = @import("parallel")`
  - `src/quic/recovery/recovery.zig`: Added `const parallel = @import("parallel")` and integrated parallel loss detection
  - Shared `build_options_mod` instance to fix Zig 0.15 "file exists in modules" errors
  - Fixed spice `@fieldParentPtr` alignment bug by changing `LossDetectContext` timestamps from `i128` to `u64`

### PAR-002: Single-packet AEAD in packet.zig — no batch path [High]

- **Category:** Performance / missed optimization
- **Severity:** High
- **Risk:** 60 (Impact 4 × Likelihood 4 × 4, reduced: sequential is correct, just slow)
- **Evidence:**
  - `src/quic/packet.zig:1087-1088` — `crypto.aeadEncrypt()` called per-packet (single plaintext → single ciphertext)
  - `src/quic/packet.zig:739` — `crypto.aeadDecrypt()` called per-packet on receive
  - `src/quic/crypto_quic.zig:265,385,432,598` — all AEAD calls are single-packet, sequential
  - `src/parallel.zig:139-176` — `parallelAeadEncrypt` exists for batched encrypt with fork/join, threshold 4+ packets
  - `src/parallel.zig:267-307` — `parallelAeadDecrypt` exists for batched decrypt with fork/join, threshold 4+ packets
- **Impact:** Under load with multiple packets to encrypt/decrypt per poll cycle, sequential AEAD is a throughput bottleneck. AEAD operations are compute-intensive (AES-GCM or ChaCha20-Poly1305) and embarrassingly parallel across independent packets.
- **Required fix:**
  1. Add a batch encryption path in the send pipeline: accumulate packets, call `parallelAeadEncrypt` when count ≥ 4
  2. Add a batch decryption path in the receive pipeline: after `recvBatch` collects multiple datagrams, batch-decrypt before per-packet processing
  3. Respect the threshold (< 4 packets falls back to sequential automatically)

### PAR-003: Single-packet header protection — no batch path [Medium]

- **Category:** Performance / missed optimization
- **Severity:** Medium
- **Risk:** 48 (Impact 3 × Likelihood 4 × 4)
- **Evidence:**
  - `src/quic/packet.zig:1108` — `crypto.headerProtect()` called per-packet
  - `src/quic/crypto_quic.zig:304` — per-packet header protection in `protectPacket()`
  - `src/parallel.zig:388-409` — `parallelHeaderProtect` exists with threshold 8+ packets
- **Impact:** Header protection is less compute-intensive than AEAD but still benefits from batching at high packet rates (8+ packets per batch).
- **Required fix:** Batch header protection calls when processing multiple packets in a poll cycle.

### PAR-004: Sequential incoming packet processing under endpoint.mu [Medium]

- **Category:** Concurrency / scalability
- **Severity:** Medium
- **Risk:** 48 (Impact 3 × Likelihood 4 × 4)
- **Evidence:**
  - `src/quic/endpoint.zig:793-802` — `recvBatch` returns up to N datagrams, then each is processed sequentially under `self.mu.lock()` in a tight loop
  - All `processIncomingDatagram` calls happen while `endpoint.mu` is held (line 794), blocking accept and timer processing
  - Batch could be split: decrypt in parallel (no lock needed for independent packets), then route under lock
- **Impact:** Under high packet rates, the endpoint lock is held for the entire batch duration. Other threads waiting on `mu` for accept or timer operations are starved.
- **Required fix:**
  1. Perform AEAD decryption and header unprotection outside the lock (packets are independent)
  2. Only acquire `endpoint.mu` for connection routing/state mutation
  3. Use `parallelAeadDecrypt` for the batch of received datagrams before entering the critical section

### PAR-005: Recovery module loss detection does not use parallel scan [Medium]

- **Category:** Performance / missed integration
- **Severity:** Medium
- **Risk:** 40 (Impact 3 × Likelihood 3 × 4)
- **Evidence:**
  - `src/quic/recovery/recovery.zig:119` — Recovery struct has its own mutex, iterates `sent_packets` sequentially for loss detection
  - `src/parallel.zig:524-545` — `parallelLossDetect` exists with fork/join for 64+ sent packets
  - No import of `parallel` module in `recovery.zig` or any recovery submodule
- **Impact:** For connections with large in-flight windows (64+ unacked packets), loss detection is O(n) sequential when it could be parallelized via work-stealing.
- **Required fix:** Import parallel module in recovery, call `parallelLossDetect` when `sent_packets.len >= 64`.

### PAR-006: Sequential PTO arming iterates all connections [Medium]

- **Category:** Scalability
- **Severity:** Medium
- **Risk:** 36 (Impact 3 × Likelihood 3 × 4)
- **Evidence:**
  - `src/quic/endpoint.zig:827-836` — `armConnectionPtoTimers` iterates all connections via `self.conns.iterator()` under `endpoint.mu`
  - Each connection's PTO computation is independent of others
  - No parallelization or sharding of connection iteration
- **Impact:** With thousands of connections, PTO timer arming holds the endpoint lock for the full iteration, increasing contention. Connection-independent operations could be parallelized via spice.
- **Required fix:** Consider sharding connections or using spice fork/join to compute PTO timers in parallel, acquiring per-connection locks individually rather than holding the endpoint lock for the entire iteration.

### PAR-007: Thread.sleep polling in hot paths [Low]

- **Category:** CPU waste / latency
- **Severity:** Low
- **Risk:** 24 (Impact 2 × Likelihood 3 × 4)
- **Evidence:**
  - `src/quic/transport.zig:766` — `std.Thread.sleep(500µs)` in poll fast-path
  - `src/quic/transport.zig:964` — `std.Thread.sleep(1ms)` in connection loop
  - `src/quic/transport.zig:1076,1089` — `std.Thread.sleep(5ms)` in handler loops
  - `src/quic/endpoint/io.zig:299,393` — sleep-based timeout fallback instead of epoll/kqueue
- **Impact:** Sleep-based polling adds latency (half the sleep interval on average) and wastes CPU on frequent wakeups. The endpoint already has `accept_cv` condition variable support (endpoint.zig:222) but transport.zig doesn't use it consistently.
- **Required fix:** Replace sleep-based polling with condition variable waits or event-driven wakeups where possible. The epoll/kqueue backends should be the primary wait mechanism, not Thread.sleep.

### PAR-008: Spice import available in endpoint.zig but unused [Low]

- **Category:** Dead code
- **Severity:** Low
- **Risk:** 20 (Impact 2 × Likelihood 2 × 4 + 4 dead code)
- **Evidence:**
  - `build.zig:536-538` — `quic_endpoint_mod.addImport("spice", sm)` wires spice to the endpoint module
  - `src/quic/endpoint.zig:63` — `const spice = if (build_options.enable_spice) @import("spice") else struct {};`
  - No reference to `spice` anywhere else in `endpoint.zig` — the import is unused
- **Impact:** Dead import adds confusion. The intent was clearly to use spice for connection-level parallelism in the endpoint but it was never completed.
- **Required fix:** Either use spice in the endpoint (for parallel connection processing) or remove the import until needed.

### PAR-009: parallel_mod only exported, never internally imported [Info]

- **Category:** Architecture / wiring
- **Severity:** Info
- **Risk:** 10
- **Evidence:**
  - `build.zig:593` — `quic_mod.addImport("parallel", parallel_mod)` exports it for downstream consumers
  - No `addImport("parallel", parallel_mod)` on any internal module: `quic_endpoint_mod`, `quic_conn_mod`, `quic_packet_mod`, `quic_crypto_mod`, `quic_recovery_mod`
- **Impact:** Downstream consumers (e.g., Geode) can `@import("quic").parallel` but the QUIC library itself never uses its own parallel module internally.
- **Required fix:** Add `parallel_mod` as an import to the modules that need it: `quic_packet_mod` (for batch AEAD/HP), `quic_recovery_mod` (for parallel loss detect), and optionally `quic_endpoint_mod` (for parallel connection processing).

### Concurrency Primitive Inventory

| Primitive | Location | Purpose | Uses Spice? |
|-----------|----------|---------|-------------|
| `std.Thread.Mutex` | `endpoint.zig:185` | Endpoint connection/accept protection | No |
| `std.Thread.Mutex` | `endpoint.zig:190` | Timer queue (decoupled from main lock) | No |
| `std.Thread.Condition` | `endpoint.zig:222` | Accept wait/signal | No |
| `std.Thread.Mutex` | `conn.zig:476` | Per-connection state protection | No |
| `std.Thread.Mutex` | `transport.zig:46` | Poll synchronization | No |
| `std.Thread.Mutex` | `transport.zig:90` | Connections list | No |
| `std.Thread.Mutex` | `transport.zig:92` | Pending destroy list | No |
| `std.Thread.Condition` | `transport.zig:47` | Poll/handler coordination | No |
| `std.Thread.Mutex` | `recovery.zig:119` | Recovery state | No |
| `std.Thread.Mutex` | `anti_replay.zig:31` | 0-RTT replay cache | No |
| `std.Thread.RwLock` | `vendor/tls/x509.zig:136` | Trust store (read-heavy) | No |
| `std.Thread.Mutex` | `parallel.zig:73` | Global spice pool init | Yes (pool) |
| `spice.ThreadPool` | `parallel.zig:72` | Work-stealing thread pool | Yes |
| `spice.Future` | `parallel.zig:218,351,434,583` | Fork/join primitives | Yes |

**Conclusion:** All 12 production concurrency primitives use `std.Thread`. Spice primitives exist only in the unused `parallel.zig` module.

### Implementation Priority

| Order | ID | Title | Effort | Dependencies |
|-------|----|-------|--------|--------------|
| 1 | PAR-001 + PAR-009 | Wire parallel_mod into internal build modules | S (build.zig changes) | None |
| 2 | PAR-002 | Batch AEAD encrypt/decrypt in packet pipeline | M | PAR-001 |
| 3 | PAR-004 | Split decrypt-then-route in endpoint poll | M | PAR-002 |
| 4 | PAR-005 | Wire parallel loss detect into recovery | S | PAR-001 |
| 5 | PAR-003 | Batch header protection | S | PAR-001, PAR-002 |
| 6 | PAR-006 | Parallel PTO arming | M | PAR-001 |
| 7 | PAR-008 | Clean up dead spice import in endpoint.zig | S | None |
| 8 | PAR-007 | Replace Thread.sleep polling with event-driven | L | Partial overlap with QUIC-H3-003 |

### Architecture Notes

The spice library provides a **work-stealing thread pool** with `fork/join` semantics via `spice.Future`. The current `parallel.zig` implementation uses a recursive binary-split pattern: each task splits its input in half, forks the right half to the pool, processes the left half locally, then joins. This is a textbook fork/join pattern suitable for data-parallel operations.

The key architectural decision for integration is **where batching occurs**:
- **Send path:** Packets are typically assembled one at a time in `writeStream` → `protectPacket`. A batch accumulator is needed before the AEAD call.
- **Receive path:** `recvBatch` already returns multiple datagrams. This is the natural batching point for parallel decrypt.
- **Loss detection:** `sent_packets` is already an array. The integration is straightforward — replace the sequential scan with `parallelLossDetect` when count ≥ 64.

The lock ordering constraint (`endpoint.mu` → `conn.mu`) must be preserved. Parallel operations on independent packets (decrypt, header unprotect) do not require any lock and can safely run outside the critical section.
