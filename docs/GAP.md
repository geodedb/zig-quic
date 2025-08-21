# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-08-21

## Quick Status

- Completed (summary):

  - QUIC packet paths: Initial, Handshake, Short (1-RTT) encode/decode; AES-128-GCM AEAD and AES HP; PN unmask; PN expansion wired per space; per-space ACK builders.
  - Version Negotiation: encoder existed; now added decode + downgrade-protection helper; unit tests cover parsing and malformed versions list.
  - TLS helpers: transcript hashing, HKDF label, Initial/Handshake/App secret derivation (v1/v2), Finished compute/verify; minimal TLS engine for tests.
  - X.509 (minimal): DER parsing for validity, SAN/CN match; insecure-gated verification.
  - Frames: PADDING, PING, CRYPTO, STREAM (LEN, OFF?, FIN), ACK with ranges (encode/decode).
  - Endpoint: UDP socket, epoll/kqueue/IOCP stubs, readable draining; timers with per-space PTO kinds; deterministic helpers flushTimers()/forceExpireAllTimers().
  - Recovery (RFC 9002 scaffolding): RTT estimator; PTO compute with exponential backoff helper; packet-threshold + time-threshold loss marking; NewReno cwnd/bytes_in_flight; ack-eliciting classification; PTO probe generation in Initial/Handshake; per-space PTO counters and cancel-on-ACK wiring.
  - Tooling/interop: varint CLI; fuzzers/bench build; interop-runner tool (scenario list/run); Go harness (server/client with datagram/retry/version flags); minimal Zig CLI stubs (quic-client/quic-server) wired in build.
  - Interop scenarios added: ALPN mismatch (expect fail), Version Negotiation overlap (expect v1), VN mismatch (expect VN/fail); runner asserts via go-client --print-version.

- Open Gaps (undone items only):
  - VN processing integration: transport path wiring to react to VN (restart with offered version) and optional RFC 9368 Compatible VN toggle.
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
- §6 Version Negotiation: VN encode, decode, and downgrade-protection helper implemented; unit tests added.

Not yet implemented / incomplete (priority gaps):

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
- RFC 9368 Compatible Version Negotiation: NOT IMPLEMENTED (VN decode helper exists; toggle and processing path pending).
- RFC 9369 QUIC v2: Key schedule available; VN/version handling and invariants NOT COMPLETE.
- RFC 9287 Grease for QUIC: NOT IMPLEMENTED.
- RFC 9312 Spin Bit: NOT IMPLEMENTED.

---

## Standards & Constraints Compliance Check

- Zig version: Requirement pins 0.13.0; current dev/builds use 0.14.x. Gap: adjust CI/tooling to install 0.13.0 and ensure compatibility, or formally update the pin with justification.
- Dependencies: std-only honored; no external C libraries used. OK.
- Security: constant-time crypto via std.crypto; zeroization and strict parsing audit pending; anti-amplification and rate-limits pending. Gap.
- Logging: JSON Lines at INFO/ERROR required; logging format not enforced yet. Gap.
- Performance: target P50 <= 50µs; benches exist but not validating target; zero-alloc hot path not enforced. Gap.
- Limits: RSS <= 512 MiB in tests not explicitly enforced. Gap.
- Reproducibility: fuzzers/tests have fixed seeds in examples; CI gating absent. Gap.

---

## Library/API/Tooling Gaps

- Public API (`src/quic/api.zig`): endpoint/connection/stream APIs mostly `error.NotImplemented`; no real accept/connect lifecycle, no stream open/read/write, no datagrams.
- CLI tools: server/client exist as stubs; echo/throughput modes and I/O paths pending.
- CI: matrix build/test and doc gate not configured under `.github/workflows/`.
- Docs process: `doccheck`/`update-gap` exist; enforcement via CI missing.
- Security hygiene: zeroization of secrets, strict parsing audit, anti-amplification & rate limits for tokens/resets pending.
- Performance: zero-alloc hot paths and pacing not enforced; no benches validating 50µs target.

---

## Acceptance Tests Status

- Varint tool:
  - encode 64 → "40 40" (OK)
  - decode 7f ff → "16383" (OK)
  - decode 40 → stderr contains "VARINT_UNDERFLOW", exit 2 (OK)
- TLS KAT: test name contains "tls_key_schedule_kat" passes. Build runner uses `-Dtest-filter=tls_key_schedule_kat` due to Zig 0.14 CLI; add convenience step or CI wrapper to meet exact invocation if pinning 0.13.0.

---

## Actionable Next Slices

### Immediate (next PR)

1. Wire Version Negotiation into connection/endpoint handshake

- On receiving VN: validate downgrade; if acceptable, restart with a mutually supported version; guard with optional RFC 9368 toggle.
- Add VN parser fuzz target; corpus with malformed version lists and edge DCID/SCID lengths.

1. TLS 1.3 interop subset

- Implement wire-compatible CH/SH (X25519 key_share, SNI, ALPN, supported_groups, sig_algs) within QUIC-TLS binding (no record layer), AES-128-GCM only.
- Start with `allow_insecure` verification to unblock interop; add ECDSA P-256 verification KATs subsequently.

1. Minimal streams/datagrams and CLI echo

- Implement openStream/writeStream/readStream and DATAGRAM send/recv; basic flow-control stubs.
- Update CLI server/client to echo over a bidi stream and optional datagram echo.

1. CI/doc gates and version pin

- Add GitHub Actions matrix (ubuntu-latest, windows-latest, macos-14); run build, test, fuzz/bench build; enforce `doccheck` and GAP timestamp bump on code changes.
- Ensure Zig 0.13.0 toolchain install and build pass; or update the documented pin and adjust acceptance instructions accordingly.

### Near-term (subsequent PRs)

1. Retry and anti-amplification

- Implement Retry packet flow and stateless token encode/verify; enforce anti-amplification prior to address validation; add tests.

1. Recovery/pacing

- Retransmission queue and scheduler; accurate bytes_acked; time-threshold loss KATs; token-bucket pacing stub.

1. Optional features toggles

- Wire build flags for: RFC 9221 DATAGRAM, RFC 9368 Compatible VN, RFC 9369 QUIC v2, RFC 9287 Grease, RFC 9312 Spin Bit; defaults per spec.

1. Security & X.509

- ECDSA P-256 verification; expand X.509 validation (basic constraints, KU/EKU, SAN wildcards) and trust store stub; zeroize keying material.

---

## Recent Slice (2025-08-21)

- Added ALPN-mismatch and Version Negotiation interop scenarios; runner assertions for negotiated version via go-client.
- Implemented VN decode and downgrade-protection helper; created unit tests, including malformed versions length.
- Kept interop-list/run steps; CLI stubs unchanged pending streams/datagrams integration.
- Fixed GAP date and expanded compliance section vs requirements (Zig pin, CI, logging, performance).

---

## Risks

- TLS/X.509 correctness (ECDSA, chain verify) and interop.
- Loss recovery correctness (timers, PTO) leading to flakiness; mitigated by deterministic timer helpers, needs probe/backoff KATs.
- Version Negotiation and Retry corner cases; downgrade protection; migration/NAT rebinding.
- Performance targets unmet until pacing/alloc reductions are implemented; logging format compliance pending.
