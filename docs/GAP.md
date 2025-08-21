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
  - Tests tightened: outbound capture hook added to Endpoint; Retry test now asserts long header type=Retry, DCID==client SCID, token present; amplification test enforces 3x gating.
  - CI/docs: matrices for Zig 0.14.1/0.14.1; doccheck + GAP gates; README updated with acceptance tests and process helpers; module export documented.

- Open Gaps vs requirements:

  - TLS 1.3 handshake: only key schedule KATs; no full CH/SH, no cert verification, no Finished/traffic secrets progression; X.509 minimal parser present but not wired; support AES-128-GCM only (no ChaCha20-Poly1305 binding yet).
  - Retry integrity: Retry Pseudo-Packet AEAD not implemented; tag currently zeroed; client does not verify integrity (RFC 9001 requirement).
  - Flow control: no MAX_DATA/MAX_STREAMS/MAX_STREAM_DATA frames; no STREAM_BLOCKED/DATA_BLOCKED signaling; stream reassembly gaps handling naive.
  - Recovery details: PTO probes limited; no pacing; ECN not implemented; loss detection needs more coverage; CUBIC optional cc stub not present.
  - Lifecycle: HANDSHAKE_DONE, CONNECTION_CLOSE mapping and app error propagation incomplete; key update missing; 0-RTT optional not implemented.
  - Path: validation frames (PATH_CHALLENGE/RESPONSE), migration + NAT rebinding handling minimal; anti-amplification implemented but no persistent NEW_TOKEN path; PMTUD not implemented.
  - Options toggles: Spin Bit, GREASE, QUIC v2 both compile-time toggles partially wired but not fully exercised; DATAGRAM RFC 9221 negotiated but lacks flow control interaction tests.
  - Security/process: JSON-lines logging not consistently applied; secrets zeroization audit pending; deterministic seeds fixed for fuzzers but coverage targets TBD; doccheck may miss some public APIs.

## Next Slice (actionable)

1. Retry integrity + client validation

- Implement RFC 9001 Retry integrity: compute tag using Initial secrets and pseudo-packet (per spec); update packet.encodeRetry to produce real tag.
- Client: verify tag; drop invalid Retry; add unit tests (tamper tag → drop; valid → accept and resend Initial with token).
- Update docs/README and acceptance notes.

1. TLS 1.3 CH/SH handshake subset

- Implement ClientHello/ServerHello, transcript, ECDHE X25519, HKDF traffic secrets, Finished verify; export handshake secrets per RFC 9001.
- Minimal X.509: load cert/key for server from paths; verify chain (basic constraints, KU/EKU, SAN, validity) with allow_insecure flag.
- Unit tests with deterministic vectors; wire to connection state machine; add CLI flags for cert/key/ca.

1. Flow control and streams polish

- Implement MAX\_\* frames, BLOCKED signaling; proper recv reassembly; update stream API behavior; tests for backpressure.

1. Recovery + pacing

- Add simple packet pacing; refine loss detection; add CUBIC as optional via -Dcc=cubic; tests and benches.

1. Path validation + migration

- Implement PATH_CHALLENGE/RESPONSE; NEW_TOKEN issuance; NAT rebinding handling; tests for anti-amplification lift and path switch.

1. Logging/bench/fuzz

- JSON-lines structured logs; zeroize secrets; extend fuzzers (packet/frame parsers) with fixed seeds; add perf bench and targets.

## Risks

- TLS/X.509 correctness and interop complexity; mitigated by KATs, fuzzing, and incremental wiring.
- Retry integrity errors can cause handshake failure; ensure extensive tests.
- Timing/pacing cross-platform differences across epoll/kqueue/IOCP.

## Done Criteria for this iteration

- Retry packets carry valid integrity tag; client verifies and resends Initial with token; tests cover accept/reject paths.
- TLS handshake subset completes CH/SH/Finished; keys exported and used for Handshake/1-RTT; server cert served and verified (with --insecure bypass for tests).
- All unit tests pass with `zig build test` and in release-safe; README acceptance tests pass; fuzz/bench build.
