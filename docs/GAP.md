# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-08-21

## Quick Status

- Completed (summary):

  - Added minimal Streams: single bidi stream (id 0) with LEN+OFF STREAM frames TX/RX, basic recv buffer, naive peer/local windows; API wired (open/write/read/close).
  - QUIC packet paths: Initial, Handshake, Short (1-RTT) encode/decode; AES-128-GCM AEAD and AES HP; PN unmask; PN expansion per space; per-space ACK builders.
  - VN: encoder/decoder + downgrade-protection; integrated with optional Compatible VN toggle.
  - Recovery scaffolding: RTT/PTO with backoff; packet-threshold/time-threshold loss; NewReno; accurate bytes_acked/lost accounting via sent_sizes map; PTO init fix.
  - DATAGRAM API and server echo path.
  - Stateless tokens + anti-amplification: HMAC-based stateless token format (IP + ODCID hash + expiry), server verifies token to lift 3x limit; server can issue Retry packets with tokens; client handles Retry and re-sends Initial with token.
  - TLS 1.3 wiring: transcript helper, X25519 minimal CH/SH helpers, and Finished helpers; Engine gains queueFinished with verify_data; Handshake secrets drive QUIC Handshake key derivation; minimal Certificate/Verify stubs with allow_insecure toggle.
  - Flow control: enforce local MAX_STREAM_DATA on incoming stream 0; update peer_max_stream_data from MAX_STREAM_DATA; opportunistic MAX_STREAM_DATA emission; blocked frame placeholders.
  - Path: add PATH_CHALLENGE/PATH_RESPONSE frame codecs and RX hooks (echo TODO); groundwork for validation.
  - Tests tightened: outbound capture hook added to Endpoint; Retry test asserts Retry format; amplification test enforces 3x gating.
  - CI/docs: matrices for Zig 0.14.1; doccheck + GAP gates; README acceptance tests; dev-release job fixed to update/create tag 'dev' and attach tarball.

- Open Gaps vs requirements:

  - TLS 1.3 handshake: CH/SH/Finished plumbing exists, but full TLS message formats, cert chain validation, and CertificateVerify are minimal; no EncryptedExtensions; no ALPN; no record layer (by design); ChaCha20-Poly1305 not wired yet.
  - Retry integrity: Retry Pseudo-Packet AEAD verify/sign still pending (client verify stubbed in endpoint; compute in packet.encodeRetry pending).
  - Flow control: still missing MAX_DATA/MAX_STREAMS and proper blocked signaling; stream reassembly and gap handling naive; no per-connection flow control yet.
  - Recovery details: pacing hooks not implemented; ECN not implemented; CUBIC optional cc not added; more tests needed.
  - Lifecycle: HANDSHAKE_DONE, CONNECTION_CLOSE mapping and app error propagation incomplete; key update missing; 0-RTT optional not implemented.
  - Path: validation echo wiring pending; migration + NAT rebinding handling minimal; NEW_TOKEN persistence not implemented; PMTUD not implemented.
  - Options toggles: Spin Bit, GREASE, QUIC v2 compile-time toggles partially wired but not fully exercised; DATAGRAM lacks FC interaction tests.
  - Security/process: JSON-lines logging not consistently applied; zeroization audit pending; fuzz corpora to be extended.

## Next Slice (actionable)

1. Retry integrity + client validation

- Implement RFC 9001 Retry integrity: compute tag using Initial secrets and pseudo-packet (per spec); update packet.encodeRetry to produce real tag.
- Client: verify tag; drop invalid Retry; add unit tests (tamper tag → drop; valid → accept and resend Initial with token).

1. TLS 1.3 CH/SH handshake subset

- Implement ClientHello/ServerHello, transcript, ECDHE X25519, HKDF traffic secrets, Finished verify; export handshake secrets per RFC 9001.
- Minimal X.509: load cert/key for server from paths; verify chain (basic constraints, KU/EKU, SAN, validity) with allow_insecure flag.

1. Flow control and streams polish

- Implement MAX_DATA/MAX_STREAMS and blocked signaling; proper recv reassembly; tests for backpressure.

1. Recovery + pacing

- Add simple packet pacing; add CUBIC via -Dcc=cubic; benches.

1. Path validation + migration

- Implement PATH_CHALLENGE echo and PATH_RESPONSE generation; add NEW_TOKEN issuance and tests.

1. Logging/bench/fuzz

- JSON-lines structured logs; zeroize secrets; extend fuzzers with Retry/Handshake corpora.

## Risks

- TLS/X.509 correctness and interop complexity; mitigated by KATs, fuzzing, and incremental wiring.
- Retry integrity errors can cause handshake failure; ensure extensive tests.
- Timing/pacing cross-platform differences across epoll/kqueue/IOCP.

## Done Criteria for this iteration

- Retry packets carry valid integrity tag; client verifies and resends Initial with token; tests cover accept/reject paths.
- TLS handshake subset completes CH/SH/Finished; keys exported and used for Handshake/1-RTT; server cert served and verified (with --insecure bypass for tests).
- Flow-control enforced with MAX_STREAM_DATA growth signaling; basic PATH validation echo works.
- All unit tests pass with `zig build test` and in release-safe; fuzz/bench build.
