# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-08-21

## Quick Status

- Completed (summary):

  - QUIC packet paths: Initial, Handshake, Short (1-RTT) encode/decode; AES-128-GCM AEAD, AES header protection; PN unmask + expansion per space; per-space ACK builders.
  - Version Negotiation: VN encoder/decoder with downgrade protection; Compatible VN toggle honored.
  - Retry: Integrity generation/verification wired (v1/v2), stateless HMAC tokens (bound to client IP + ODCID + expiry); server issues Retry as needed; client validates and retries with token.
  - Address validation and amplification defense: 3x anti-amplification before validation; PATH_CHALLENGE echo and PATH_RESPONSE validation; NAT rebinding path validation.
  - Streams + flow control (baseline):
    - Robust RX reassembly across gaps and multiple streams with per-stream inbox.
    - Enforce TX limits for MAX\*DATA and MAX_STREAMS; signal DATA_BLOCKED, STREAM_DATA_BLOCKED, and STREAMS_BLOCKED\*\* accordingly.
    - Update peer maxima from MAX\*DATA/MAX_STREAM[_DATA]; advertise local MAX\*\* periodically with ACKs.
  - DATAGRAM (RFC 9221) baseline: frame codec; optional echo path when enabled.
  - TLS 1.3 (QUIC binding subset): X25519, HKDF/SHA-256, Finished; handshake secrets exported to derive QUIC keys; EncryptedExtensions with ALPN; allow_insecure honored for tests; minimal X.509 parsing present.
  - TLS certs/validation (new): client path now validates the presented chain: SAN-to-SNI match, validity window, BasicConstraints and EKU serverAuth, signature verification for leaf/intermediates using ECDSA P-256/P-384 and RSA-PSS-SHA256 (std.crypto). SNI plumbed from API to TLS; ALPN enforced and exposed via getter.
  - Recovery scaffolding: RTT/PTO with backoff; packet- and time-threshold loss; NewReno controller; PTO arming per space; sent-bytes accounting.
  - Endpoint/platform: epoll/kqueue/IOCP backends with deterministic test fallback; outbound capture ring for tests.
  - CI/docs: matrices for Zig 0.14.1; doccheck + GAP gates; dev release tarball job; acceptance tools and tests.

- Open Gaps vs requirements:

  - TLS 1.3 handshake completeness:
    - Pending: ChaCha20-Poly1305 cipher and HP variant; optional 0-RTT keys; richer signature algorithm matrix; platform trust store integration.
  - Congestion control + pacing:
    - CUBIC exists as a toggle but logic is a stub; pacing not implemented; no ECN.
  - Flow control polish:
    - FIN handling in reassembly; proactive MAX\_\* growth thresholds; stream- and connection-level autotuning; broader tests.
  - Connection lifecycle:
    - HANDSHAKE_DONE emission/handling; CONNECTION_CLOSE mapping to app errors; Key Update; application close semantics.
  - Tokens:
    - Client-side NEW_TOKEN caching/persistence and pre-CH usage; rotation/expiry policy tests.
  - Options/telemetry:
    - Spin Bit, GREASE behaviors and toggles; QUIC v2 compile-time path and KATs; DATAGRAM robustness tests.
  - Security/process:
    - Zeroize secrets; constant-time audit of critical paths; JSON Lines logging consistently applied; expand fuzz corpora beyond varint/frames/packets (e.g., Retry, VN, TLS CRYPTO sequences).
  - Performance:
    - P50 ≤ 50µs loopback target not yet measured; hot paths still allocate in places; benches need realistic scenarios; PMTUD not implemented.

## Next Slices (actionable, in order)

1. TLS validation and ALPN hardening

   - Add ChaCha20-Poly1305 cipher and HP; optional early-data keys.
   - Integrate minimal trust store hook and negative tests for name mismatch/expired cert; extend KATs.

2. CUBIC + pacing

   - Implement a production CUBIC controller (RFC 9438 lineage) with bytes_in_flight integration; maintain NewReno default.
   - Add basic packet pacing using cwnd/rtt and timers; benches to compare NR vs CUBIC on loopback.

3. Flow control completeness

   - Handle FIN in reassembly; emit MAX\_\* on threshold crossings; tests for DATA_BLOCKED/STREAM_DATA_BLOCKED/STREAMS_BLOCKED triggering and recovery.
   - Tighten connection-level accounting and window growth.

4. Tokens lifecycle

   - Persist NEW_TOKEN on client and use on subsequent connections; add expiry/rotation tests and replay protection checks.

5. Lifecycle frames and key management

   - Emit/handle HANDSHAKE_DONE; implement CONNECTION_CLOSE mapping; add Key Update.

6. Options and versioning

   - Finalize Spin Bit and GREASE behaviors; validate QUIC v2 path under -Dversion=v2; add KATs.

7. Fuzzing, logging, and performance

   - Extend fuzzers for Retry/VN/TLS CRYPTO sequences; adopt fixed seeds in CI.
   - Implement JSON Lines logging at INFO/ERROR; redact secrets.
   - Optimize hot path allocations and measure P50 with benches; add PMTUD planning.

## Risks

- TLS/X.509 correctness and interop remain complex; mitigate with KATs, golden traces, and fuzzing.
- Pacing and CUBIC cross-platform timer precision may vary; isolate with deterministic tests.
- Token misuse or weak binding risks; ensure MAC binding and expiry enforcement, especially across NATs.

## Done Criteria for the next iteration

- TLS: EE + Certificate + CertificateVerify verified against local CA or with --insecure; ALPN enforced and surfaced to app; ChaCha20-Poly1305 available.
- CC: CUBIC functional with pacing; benches run and compare cwnd evolution; default remains NewReno.
- Flow control: FIN handling + threshold-based MAX\_\*; comprehensive blocked signaling tests pass.
- Tokens: client caches NEW_TOKEN and uses it on subsequent handshakes; tests cover expiry and invalid token rejection.
- Lifecycle: HANDSHAKE_DONE and graceful CONNECTION_CLOSE wired; basic Key Update.
- All unit tests pass in debug and -Drelease-safe; fuzzers/benches build; GAP updated and doccheck passes.
