# GAP Analysis — Initial Slice (VarInt + Frames + Build/Tooling)

Date: 2025-08-19

## Current State

- Language/runtime: Zig 0.14.x on CI; runs locally on Linux.
- Implemented QUIC Initial/Handshake protection with AES-128-GCM and AES/ChaCha header protection.
- Minimal TLS 1.3 engine (transcript, key schedule) in `src/quic/tls/`; CH/SH minimal envelopes.
- Event loop/timers scaffold with passing timer tests on Linux.
- Tools: `quic-varint`, `doccheck`, `update-gap` build and run.

## Gaps vs Objectives

- TLS 1.3 handshake is minimal; no cert/X.509 validation yet.
- Endpoint/UDP IO stubs still limited; no real network roundtrip yet.
- Streams, flow control, recovery/CC remain to be implemented.

## Risks

- TLS/X.509 correctness and interop; mitigated via KATs and fuzzing.
- Header protection and PN truncation edge-cases; addressed by targeted tests.

## This Slice (2025-08-19T00:00Z)

- Wired X25519 ECDHE into TLS engine using `std.crypto.dh.X25519` (Zig 0.14 API):
  - Deterministic ephemeral generation in tests, pub/share via `scalarmult`.
  - Transcript updates on sending CH/SH; automatic shared secret computation per role.
- 1-RTT bootstrap and short-header path:
  - Added `tests/test_shortrtt_roundtrip.zig` exercising encode/decode of short-header with 1-RTT keys.
  - Fixed short-header decode double-unmasking; now unmask once to infer PN length, decrypt with masked bytes.
  - Fixed AEAD nonce to use truncated PN value on short-header encode to match decoder (no PN reconstruction context in test).
  - Added debug dumps under tests to aid AAD/nonce validation.
- Cleanups:
  - Eliminated heap allocs in minimal CH/SH encoders (stack buffers).
  - Marked handshake state flags on send (ServerHello `sh_seen`).

## Next Slice

- Harden long-header parsing (varint bounds, PN length validation) across Initial/Handshake.
- Derive/validate handshake Finished; begin minimal X.509 DER parsing and signature verification stubs.
- Implement basic STREAM/ACK frame encode/decode for 1-RTT; ACK PNs and simple retransmit tests.
- Extend event loop to real epoll wait and UDP send/recv; start in-process UDP loopback tests.
