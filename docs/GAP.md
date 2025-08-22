# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-08-21

## Latest slice (status bump)

- Added TLS/X.509 SNI negative tests and allow_insecure bypass tests; wired into build.zig and CI gates.
- Fixed build wiring for tests using proper module imports; all tests pass in Debug and -Drelease-safe.
- GAP.md updated; doccheck and GAP gating continue to enforce docs discipline.

## Quick Status

- Completed (summary):

  - QUIC packet paths: Initial, Handshake, Short (1-RTT) encode/decode; AES-128-GCM AEAD, AES header protection; PN unmask + expansion per space; per-space ACK builders.
  - Version Negotiation: VN encoder/decoder with downgrade protection; Compatible VN toggle honored (RFC 9368).
  - Retry: Integrity generation/verification wired (v1/v2), stateless HMAC tokens (bound to client IP + ODCID + expiry); server issues Retry as needed; client validates and retries with token.
  - Address validation and amplification defense: 3x anti-amplification before validation; PATH_CHALLENGE echo and PATH_RESPONSE validation; NAT rebinding path validation.
  - Streams + flow control (baseline):
    - RX reassembly across gaps; per-stream inbox.
    - Enforce TX limits for MAX\*DATA and MAX_STREAMS; send DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED.
    - Update peer maxima; advertise local MAX\*\* periodically with ACKs.
  - DATAGRAM (RFC 9221) baseline: frame codec; optional echo path when enabled.
  - TLS 1.3 (QUIC binding subset): X25519, HKDF/SHA-256, Finished; handshake secrets exported to derive QUIC keys; EncryptedExtensions with ALPN; allow_insecure for tests; minimal X.509 parsing.
  - TLS certs/validation (client): SAN-to-SNI match, validity window, BasicConstraints and EKU serverAuth, signature verification for leaf/intermediates using ECDSA P-256/P-384 and RSA-PSS-SHA256 (std.crypto). SNI plumbed from API; ALPN enforced and exposed via getter; negative SNI tests added.
  - Recovery: RTT/PTO with backoff; packet- and time-threshold loss; NewReno controller; per-space PTO; sent-bytes accounting.
  - Endpoint/platform: epoll/kqueue/IOCP backends abstraction; deterministic test backend; outbound capture ring for tests.
  - Tooling/CI/docs: varint CLI and acceptance tests; fuzz/bench targets build; doccheck enforces pub docs; GAP gating requires timestamp bump on code changes.

- Open Gaps vs requirements:

  - TLS 1.3 and QUIC-TLS (RFC 9001):
    - Pending cipher: ChaCha20-Poly1305 AEAD + header protection variant.
    - Optional 0-RTT (early data) key schedule and acceptance tests.
    - Key Update.
    - Platform trust store integration hook; more KATs (expired, not-yet-valid, EKU/KU mismatches).
  - Transport (RFC 9000):
    - HANDSHAKE_DONE frame emit/handle.
    - CONNECTION_CLOSE mapping to app error space + graceful close semantics.
    - Stateless reset (encode/decode and validation).
    - Spin Bit (RFC 9312) and GREASE (RFC 9287) toggles and behavior.
    - QUIC v2 (RFC 9369) compile-time path and KATs.
    - PMTUD / probing and safe max_udp_payload tuning.
  - Loss recovery (RFC 9002):
    - ECN integration (optional); ack frequency tuning tests.
    - Pacing (timer-based) tied to cwnd/rtt.
  - Congestion control:
    - CUBIC implementation behind -Dcc=cubic; maintain NewReno default. Benchmarks to compare cwnd evolution.
  - Flow control and stream lifecycle:
    - FIN handling in reassembly; proactive MAX\_\* growth thresholds/autotuning.
    - STOP_SENDING and RESET_STREAM semantics and tests.
  - Tokens lifecycle:
    - Client-side NEW_TOKEN persistence and reuse on subsequent connections; rotation/expiry policy; replay checks.
  - Security/process:
    - Zeroize secrets; constant-time review of critical paths.
    - JSON Lines logging at INFO/ERROR across codebase; never log secrets (tests may print for KATs only).
  - Performance/reproducibility:
    - P50 ≤ 50µs loopback not measured; reduce hot-path allocations; benches need realistic flows.
    - Extend fuzz corpora beyond varint/frame/VN (e.g., Retry, TLS CRYPTO sequences, malformed certs).

## Next Slices (actionable, in order)

1. TLS crypto parity and validation hardening

- Implement ChaCha20-Poly1305 AEAD + HP and cipher negotiation; add KATs.
- Add certificate expiry/not-yet-valid KATs; expand name matching cases (wildcards, IDNA punycode minimal handling if needed for tests).
- Expose trust store hook with stub default; add allow_insecure test toggles already present.

2. Lifecycle frames and key management

- Emit/handle HANDSHAKE_DONE; wire CONNECTION_CLOSE mapping; implement Key Update.
- Unit tests for each; integrate into initial handshake loop tests.

3. CUBIC + pacing

- Implement CUBIC controller (bytes-based) and pacing using timers; ensure -Dcc=cubic switches logic.
- Benchmarks: NR vs CUBIC on loopback; capture P50 and allocation counts.

4. Flow control completeness

- FIN-aware reassembly; threshold-based MAX\_\* emission; tests for BLOCKED signaling.
- Implement STOP_SENDING/RESET_STREAM with state machine coverage.

5. Tokens lifecycle

- Persist NEW_TOKEN on client; use pre-CH when available; add rotation/expiry tests and replay defenses.

6. Options and versions

- Implement Spin Bit and GREASE toggles; add QUIC v2 path and KATs under -Dversion=v2.

7. Fuzzing, logging, and performance

- Extend fuzzers (Retry, TLS CRYPTO ordering, malformed DER); fix seeds in CI.
- Implement JSON Lines logging consistently (INFO/ERROR); ensure no secrets in release logs.
- Optimize hot paths and measure P50; plan PMTUD.

## Risks

- TLS/X.509 correctness and interop remain complex; mitigate with KATs, golden traces, and fuzzing.
- Pacing and CUBIC need precise timers; cross-platform drift differences.
- Token binding/expiry correctness across NAT and migrations.

## Done Criteria for the next iteration

- ChaCha20-Poly1305 supported and selected when negotiated; KATs pass.
- HANDSHAKE_DONE + CONNECTION_CLOSE + Key Update wired with tests.
- CUBIC functional with pacing; benches compare NR vs CUBIC; default remains NewReno.
- FIN handling + threshold-based MAX\_\* + STOP_SENDING/RESET_STREAM tests pass.
- NEW_TOKEN persisted and used on subsequent connections; expiry/replay tests in place.
- All unit tests pass (debug and -Drelease-safe); fuzzers/benches build; GAP updated; doccheck passes.
