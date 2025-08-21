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
  - Tooling/interop: varint CLI; fuzzers/bench build; interop-runner tool (scenario list/run); Go harness (server/client with datagram/retry/version flags); minimal Zig CLI stubs (quic-client/quic-server) wired in build.

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
  - CLI: server/client are stubs; echo/throughput modes and proper lifecycle not implemented.
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
- CLI tools: server/client exist as stubs; echo/throughput modes and I/O paths pending.
- CI: matrix build/test and doc gate not configured under `.github/workflows/`.
- Docs process: `doccheck`/`update-gap` exist; enforcement via CI missing.
- Security hygiene: zeroization of secrets, strict parsing audit, anti-amplification & rate limits for tokens/resets pending.
- Performance: zero-alloc hot paths and pacing not enforced; no benches validating 50µs target.

---

## Actionable Next Slices

### Immediate (next PR)

1. Interop scenarios (no wire changes)

- Add ALPN-mismatch scenario to interop-runner (expect TLS/handshake failure with clear error).
- Add version-negotiation scenarios using Go harness flags:
  - Overlap (client v2,v1; server v1) → expect v1 negotiated.
  - Mismatch (client v2 only; server v1 only) → expect VN handling or clear failure.
- Extend output assertions (use go-client --print-version) and list/run-all.

1. Version Negotiation handling (transport)

- Implement VN packet decode/processing and basic downgrade protection per RFC 9000 §6 + RFC 9368 optional mode (toggle).
- Unit tests for VN packet parsing and negotiation outcome; fuzz VN parser.

### Near-term

1. TLS interop subset

- Implement wire-compatible TLS 1.3 ClientHello/ServerHello (X25519 key_share, SNI, ALPN, supported_groups, sig_algs); map into QUIC-TLS (no record layer); keep AES-128-GCM initially.
- Minimal certificate verify path in allow_insecure mode to unblock interop; follow with ECDSA P-256 verification KATs.

1. API/CLI wiring

- Fill minimal stream open/write/read and datagram send/recv to back CLI echo modes; basic flow control stubs.
- Harden endpoint accept/connect lifecycle; add CONNECTION_CLOSE/HANDSHAKE_DONE basics.

1. Recovery/pacing

- Introduce retransmission queue and bytes_acked accounting; add time-threshold loss tests; token-bucket pacing stub.

1. CI/doc gates

- Add GitHub Actions matrix (ubuntu-latest, windows-latest, macos-14); run build, test, fuzz/bench build.
- Enforce `doccheck` and GAP timestamp bump when code changes.

---

## Recent Slice (2025-08-20)

- Added interop-runner tool with scenarios: go_echo_smoke, go_echo_datagram, go_retry_smoke (MUST PASS) and Zig↔Go XFAIL placeholders.
- Added Go harness (examples/interop/go-server, go-client) with flags: --datagram, --retry, --versions, and cert generator; local replace of quic-go for offline.
- Wired build aliases: `interop-list` and `interop-run -Dscenario=...`; stabilized runner allocator (page allocator) for child processes.
- Introduced minimal `cmd/quic-client` and `cmd/quic-server` stubs; integrated in build.
- Updated this GAP with status and next steps.

---

## Risks

- TLS/X.509 correctness (ECDSA, chain verify) and interop.
- Loss recovery correctness (timers, PTO) leading to flakiness; mitigated by deterministic timer helpers, needs probe/backoff KATs.
- Version Negotiation and Retry corner cases; downgrade protection.
- Performance targets unmet until pacing/alloc reductions are implemented.
