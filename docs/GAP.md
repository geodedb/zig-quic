# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-08-19

This document compares the current codebase against the relevant QUIC RFCs in `specs/` and summarizes what is implemented vs. still required for a production baseline.

## Snapshot: What Works Today (high level)

- QUIC packets: Initial, Handshake, and Short (1-RTT) encode/decode with AES-128-GCM and AES-based header protection (server and client directions), including HP sample, PN mask/unmask (RFC 9001 §5.4).
- TLS 1.3 helpers: transcript hash, HKDF label functions, Initial/Handshake/App secret derivation (v1/v2 key schedule), Finished compute/verify.
- X25519 ephemeral and deterministic test paths; minimal TLS engine that tracks CH/SH, transcript, and Finished; non-interoperable placeholder CH/SH envelopes for tests.
- X.509 (minimal): DER parsing of validity, subject CN, SAN dNSName; name match helper; validity window checks; insecure mode gating.
- CertificateVerify: RSA-PSS-SHA256 verification implemented in-repo (MGF1-SHA256, saltLen=32). ECDSA currently unsupported.
- Frames: PADDING, PING, CRYPTO, STREAM (LEN, optional OFF, FIN), ACK with ranges (encode/decode).
- Endpoint: single UDP socket, basic event loop backends (epoll/kqueue/IOCP stubs), draining readable, simple timer wheel with tests.
- Initial → Handshake key transition for server; reply Handshake packet construction.
- Tools/fuzz/bench: varint CLI passes acceptance; fuzzers and bench build.

---

## RFC 9000 — QUIC: A Transport Protocol for UDP (Baseline)

Implemented (partial):

- §16 Varint encoding/decoding.
- §17 Frames: PADDING, PING, CRYPTO, STREAM (subset), ACK with ranges (write/decode). Types enumerated for some control frames.
- §17 ACK ranges and largest acknowledged: aggregated from a recent PN bitset window.
- §12/§19 Packet formats: Initial, Handshake, Short header paths; DCID/SCID handling for server; PN length determination; header protection application.
- §14.2 Packet number encoding/decoding: PN length recovery on decode for protected packets (no full PN expansion across epochs).
- §10/§11 Socket and datagram processing: single-socket endpoint; demux by DCID for Short; basic intake loop.

Not yet implemented / incomplete (priority gaps):

- Version Negotiation packet (VN) and downgrade protection (RFC 9368 compatibility optional): not implemented.
- Retry packet and stateless token validation (anti-amplification): token encoding/verification is a stub; no Retry flow.
- Stateless Reset: not implemented.
- Packet Number Spaces separation (Initial/Handshake/1-RTT) and PN expansion relative to expected: simplified; decode uses truncated PN only; no full expansion logic.
- Transport Parameters: encode/decode/validation not present.
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

Not yet implemented / incomplete:

- Interoperable TLS 1.3 handshake message parsing/encoding (ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished) and extension negotiation (ALPN, SNI, SIG_ALGs, key_share, supported_groups, etc.). Current envelopes are non-wire-compatible.
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

Not yet implemented / incomplete:

- RTT estimation (smoothed_rtt, rttvar), ack delay incorporation, min_rtt tracking.
- Loss detection across PN spaces, time-threshold and packet-threshold loss.
- Probe Timeout (PTO) calculation and management per epoch; handshake/app distinct timers.
- Congestion control (NewReno default, CUBIC optional) and pacing; bytes-in-flight accounting, cwnd/ssthresh updates.
- Ack-eliciting detection; ECN accounting.

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

1. PN expansion + ACK/rx polish (RFC 9000)

   - Implement PN expansion (short + long) using largest received and expected next per space.
   - Separate PN spaces and state (Initial/Handshake/1-RTT) in connection.
   - Encode/decode Transport Parameters scaffolding.

1. Loss recovery skeleton (RFC 9002)

   - Add RTT estimator and PTO per space; basic loss detection; wire into endpoint timers.
   - Add NewReno cwnd/bif accounting; ack-eliciting detection.

1. TLS/X.509 hardening (RFC 9001)

   - Implement ECDSA P-256 verify; add positive/negative KATs.
   - Begin real TLS handshake message encode/parse (ClientHello key_share/sig_algs, ServerHello) sufficient to carry real SPKI/signatures over CRYPTO.
   - Expand X.509: basic constraints and SPKI signature verify of leaf -> self/issuer.

1. Transport features

   - Retry/token and anti-amplification; stateless reset; CONNECTION_CLOSE/HANDSHAKE_DONE.
   - Stream manager + flow control (MAX_DATA/MAX_STREAM_DATA/BLOCKED) with unit tests.

1. Tooling/CI

   - Add `cmd/quic-client.zig`/`cmd/quic-server.zig` minimal echo interop (insecure mode).
   - Set up `.github/workflows/ci.yml` (linux/windows/macos), run `doccheck`, enforce GAP timestamp.

---

## Risks

- TLS/X.509 correctness (ECDSA, chain verify) and interop.
- Loss recovery correctness (timers, PTO) leading to flakiness.
- Packet number expansion and header protection corner cases.
