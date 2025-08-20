# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-08-20

## Quick Status

- Completed (summary):

  - QUIC packet paths: Initial, Handshake, Short (1-RTT) encode/decode; AES-128-GCM AEAD and AES HP; PN unmask; PN expansion wired per space; per-space ACK builders.
  - TLS helpers: transcript hashing, HKDF label, Initial/Handshake/App secret derivation (v1/v2), Finished compute/verify; minimal TLS engine for tests.
  - X.509 (minimal): DER parsing for validity, SAN/CN match; insecure-gated verification.
  - Frames: PADDING, PING, CRYPTO, STREAM (LEN, OFF?, FIN), ACK with ranges (encode/decode).
  - Endpoint: UDP socket, epoll/kqueue/IOCP stubs, readable draining; timers with per-space PTO kinds; deterministic helpers flushTimers()/forceExpireAllTimers().
  - Recovery (RFC 9002 scaffolding): RTT estimator; PTO compute with exponential backoff helper; packet-threshold + time-threshold loss marking; NewReno cwnd/bytes_in_flight; ack-eliciting classification; PTO probe generation in Initial/Handshake; per-space PTO counters and cancel-on-ACK wiring.
  - Tooling: varint CLI; fuzzers/bench build.

- Open Gaps (undone items only):
  - Version Negotiation handling (decode/process) and downgrade protection; RFC 9368 optional mode.
  - Retry + anti-amplification; stateless token encode/verify; Stateless Reset.
  - Connection lifecycle: accept/connect API, connection manager, packet coalescing; closing/draining; CONNECTION_CLOSE/HANDSHAKE_DONE.
  - Flow control: connection/stream windows, MAX_DATA/MAX_STREAM_DATA/BLOCKED enforcement.
  - Stream subsystem: IDs, bidi/uni, state machine, reassembly/FIN handling beyond codec.
  - Path validation/migration/PMTUD; ECN + Spin Bit (optional); GREASE (optional); DATAGRAM API (RFC 9221 optional).
  - TLS 1.3 interop handshake (CH/SH encode/parse, extensions: ALPN, SNI, SIG_ALGs, key_share, groups); ECDSA P-256/384 verify; certificate chain/path building and validation (basic constraints, key usage, SAN wildcards, name constraints, trust store integration).
  - CHACHA20-POLY1305 integration (AEAD + HP); key update; 0-RTT.
  - Recovery: full retransmission queue/scheduler; per-space separation in CC; pacing token-bucket; ECN reactions.
  - API: streams/datagrams read/write; endpoint/connection public API completion.
  - CLI: quic-client/quic-server with echo/throughput; insecure toggle for testing.
  - CI: matrix build/test, doc gate (doccheck + GAP timestamp), egress controls and caches; cross-compile artifacts.
  - Security: zeroization of secrets, strict parsing audit; anti-amplification & rate limits for tokens/resets pending.
  - Performance: zero-alloc hot paths post-warmup; benches validating loopback P50 <= 50µs.

---

## RFC 9000 — QUIC: A Transport Protocol for UDP (Baseline)

Implemented (partial):

- §16 Varint encoding/decoding.
- §17 Frames: PADDING, PING, CRYPTO, STREAM (subset), ACK with ranges (write/decode). Types enumerated for some control frames.
- §17 ACK ranges and largest acknowledged: aggregated from a recent PN bitset window.
- §12/§19 Packet formats: Initial, Handshake, Short header paths; DCID/SCID handling for server; PN length determination; header protection application.
- §14.2 Packet number encoding/decoding: PN length recovery on decode; PN expansion wired for Initial/Handshake/1-RTT using per-space expected next (RFC 9000 §12.3).
- §10/§11 Socket and datagram processing: single-socket endpoint; demux by DCID for Short; basic intake loop.
- §13 ACK generation per PN space: Initial/Handshake/App have separate trackers and ACK builders.
- §7.4 Transport Parameters: minimal encode/decode; plumbed as opaque blob through TLS engine for exchange.

Not yet implemented / incomplete (priority gaps):

- Version Negotiation packet (VN) and downgrade protection (RFC 9368 compatibility optional): encode exists; decode/handling not implemented.
- Retry packet and stateless token validation (anti-amplification): token encoding/verification is a stub; no Retry flow.
- Stateless Reset: not implemented.
- Connection establishment plumbing: no connection manager, accept/connect API plumbing, no coalescing.
- Flow Control: connection and stream flow control, MAX_DATA/MAX_STREAM_DATA, BLOCKED frames, accounting and enforcement: not implemented.
- Stream subsystem: stream state machine, ID allocation, ordering, reassembly, FIN handling beyond frame codec: not implemented.
- Path validation (PATH_CHALLENGE/PATH_RESPONSE), migration (NAT rebinding), and PMTUD: not implemented.
- Error handling: CONNECTION_CLOSE (transport/application), error codes, lifecycle; HANDSHAKE_DONE; closing/draining: not implemented.
- ECN, Spin Bit (RFC 9312 optional), Grease (RFC 9287 optional): not implemented.
- Datagram extension (RFC 9221 optional): frame type declared; no API, no send/recv path.
- Key update (post-handshake), 1-RTT secrets rotation: not implemented.
- Anti-amplification limit enforcement pre-address validation: not implemented.

---

## RFC 9001 — Using TLS to Secure QUIC (QUIC-TLS Binding)

Implemented (partial):

- Initial secret derivation for QUIC v1/v2, traffic secret export, header protection and AEAD using std.crypto primitives.
- TLS transcript hashing and HKDF-Expand-Label helpers.
- Finished verification and generation.
- RSA-PSS-SHA256 CertificateVerify verification (in-repo), gated by `allow_insecure`.
- Minimal X.509 parsing (DER): validity, SAN dNSName, CN fallback; DNS match helper.
- Transport Parameters exchange: opaque TP blob carried in CH/SH via TLS engine hooks (minimal placeholder format).

Not yet implemented / incomplete:

- Interoperable TLS 1.3 handshake message parsing/encoding and extension negotiation (ALPN, SNI, SIG_ALGs, key_share, supported_groups, etc.). Current envelopes are non-wire-compatible.
- ECDSA (P-256/P-384) CertificateVerify verification (SEC1 parsing, curve math) and signature algorithm selection: unsupported.
- Certificate chain validation and path building, signature verification of TBSCertificate, basic constraints, key usage, SAN wildcards, name constraints, and trust store integration: minimal to none (only leaf validity/name check).
- Cipher suites: CHACHA20-POLY1305 integration (AEAD + HP) not plumbed; only AES-128-GCM used in code paths.
- 0-RTT/early data and early secret derivation: not implemented.
- Key update and exporter interfaces: not implemented.
- Alert mapping and error surfaces to transport close codes: not implemented.

---

## RFC 9002 — QUIC Loss Detection and Congestion Control

Implemented (initial scaffolding):

- Packet sent-time tracking map; largest_acked tracking; simple onAckReceived/onPacketSent hooks.
- Endpoint timers and wake-up integration.
- RTT estimator with min_rtt/smoothed/rttvar and PTO computation helper; ack delay handling placeholder.
- Per-space PTO timer kinds (Initial/Handshake/App) and endpoint integration that toggles connection PTO flags.
- Basic packet-threshold loss detection (threshold=3) and cwnd/ssthresh/bytes-in-flight updates for NewReno on ACK/loss.
- Ack-eliciting classification helper; send path marks ack-eliciting and accounts bytes_in_flight; unit tests for RTT/PTO and classification.

Not yet implemented / incomplete:

- Handshake and Initial distinct RTT/PTO paths; time-threshold loss and probe packets generation.
- Full loss recovery loop (marking, retransmission scheduling), ECN, and pacing.
- Proper bytes_acked accounting using actual sent sizes per packet; per-space separation for cc.

---

## Optional RFCs (compile-time toggles)

- RFC 9221 Datagram: NOT IMPLEMENTED (frame enum present only).
- RFC 9368 Compatible Version Negotiation: NOT IMPLEMENTED.
- RFC 9369 QUIC v2: Key schedule available; VN/Version handling and invariants NOT IMPLEMENTED.
- RFC 9287 Grease for QUIC: NOT IMPLEMENTED.
- RFC 9312 Spin Bit: NOT IMPLEMENTED.

---

## Library/API/Tooling Gaps

- Public API (`src/quic/api.zig`): endpoint/connection/stream APIs mostly `error.NotImplemented`; no real accept/connect lifecycle, no stream open/read/write, no datagrams.
- CLI tools: `quic-client`/`quic-server` absent; only varint tool exists.
- CI: matrix build/test and doc gate not configured under `.github/workflows/`.
- Docs process: `doccheck`/`update-gap` exist; enforcement via CI missing.
- Security hygiene: zeroization of secrets, strict parsing audit, anti-amplification & rate limits for tokens/resets pending.
- Performance: zero-alloc hot paths and pacing not enforced; no benches validating 50µs target.

---

## Actionable Next Slices

### Next Steps (plan)

1. Loss Recovery Phase 2 completion

   - Ensure per-space PTO arming/cancel is exercised on all ack-eliciting sends and any ACK in that space; finalize probe generation and backoff reset semantics; add KATs for PTO backoff/probes; stabilize timer tests.
   - Introduce retransmission queue and accurate bytes_acked/lost accounting using tracked sent sizes; mark and schedule retransmits on time/packet-threshold loss.
   - Add pacing scaffold (token-bucket) hooks; stub ECN accounting.

2. Transport features

   - Version Negotiation decode/handling + downgrade protection (optionally RFC 9368); Retry + token encode/verify + anti-amplification limits; Stateless Reset; CONNECTION_CLOSE/HANDSHAKE_DONE.
   - Stream manager + flow control (MAX_DATA/MAX_STREAM_DATA/BLOCKED) with unit tests.

3. TLS/X.509 hardening and interop

   - Implement ECDSA P-256 verify and KATs; begin interoperable TLS 1.3 handshake encode/parse sufficient for CH/SH with TP extension and CRYPTO streams.
   - Expand X.509: basic constraints, key usage checks, simple path building; plumb allow_insecure for tests.
   - Add CHACHA20-POLY1305 option and key schedule plumbing.

4. API and CLI

   - Flesh out public API for endpoint/connection/streams/datagrams; implement cmd/quic-client and cmd/quic-server minimal echo/throughput (insecure mode allowed for tests).

5. CI and tooling

   - Add GitHub Actions matrix (ubuntu-latest, windows-latest, macos-14); run zig build/test, fuzz/bench build; enforce doccheck and GAP timestamp bump; no Internet egress for unit tests; cache Zig; cross-compile artifacts for x86_64/aarch64/riscv64.

6. Interop (manual/optional initially)

   - Status: Scaffolded (manual harness under examples/interop with Go client/server, Zig CLI wrappers, cert generator, run script). Not wired to CI and handshake likely not yet interoperable.
   - How to run (developer-only):
     - Generate certs: `bash ./examples/interop/certs/generate.sh`
     - Build CLIs/tools: `zig build cli tools`
     - Prime Go deps (first time): `cd examples/interop && go mod tidy`
     - Run helper: `bash ./examples/interop/run.sh`
   - Goal: validate both directions once TLS/streams are wired:
     - Start this Zig QUIC server (insecure, fixed cert/key) listening on 127.0.0.1:4433 with ALPN=h3.
     - Use quic-go (Go) as client to connect, perform handshake, send a STREAM payload, expect echo.
     - Reverse: start quic-go server, connect with this Zig client and validate handshake + data.

7. Performance/security polish
   - Zeroize secret material; audit constant-time code paths; reduce heap allocs on hot paths; add microbenchmarks validating latency targets.

---

## Recent Slice (2025-08-19)

- Wired ACK generation per PN space and PN expansion for Initial/Handshake.
- Added RFC 9002 recovery scaffolding: RTT estimator, PTO calculation helper; NewReno cwnd/bytes-in-flight; basic packet-threshold loss.
- Integrated PTO timers into endpoint; added test-only `Endpoint.forceExpireAllTimers()` for deterministic expiry; stabilized timers tests.
- Fixed PTO delay conversions and clamped extremes to avoid casts; adjusted endpoint poll to pre/post process timers and provide deterministic sleep fallback for tests.

---

## Risks

- TLS/X.509 correctness (ECDSA, chain verify) and interop.
- Loss recovery correctness (timers, PTO) leading to flakiness. Deterministic timer helper mitigates test flake; runtime behavior still needs robust backoff/probe logic.
- Packet number expansion and header protection corner cases.
