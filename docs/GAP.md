# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-08-22 03:15 UTC

## Latest slice (status bump)

- Integrated Recovery into Connection:
  - Replaced naive send/ack/loss/PTO tracking with recovery.Recovery for Application space.
  - Endpoint and Connection now pass PacketNumberSpace when recording sends.
  - ACK handling builds PN lists from ACK ranges and feeds Recovery.onAckReceived.
  - PTO for App uses Recovery.computeNextPtoTimeNs; backoff tied to rec.pto_count.
  - Time-threshold loss promotion runs on timer via Recovery.onLossTimeExpired.
- Kept Initial/Handshake PTO on legacy estimators temporarily; App space authoritative via Recovery.
- All unit tests continue to pass locally; timers tests updated to remain deterministic.

## Coverage vs Requirements (snapshot)

- Library (src/):
  - Implemented: varint; frames (PING/ACK/CRYPTO/STREAM/MAX**/BLOCKED/PATH**/NEW_TOKEN/DATAGRAM/HANDSHAKE_DONE/CONNECTION_CLOSE); packet encode/decode (Initial/Handshake/Short), PN mask/unmask + expansion; AEAD (AES-128-GCM, ChaCha20-Poly1305), HP (AES/ChaCha); recovery with RTT/PTO, packet- and time-threshold loss, NewReno; QUIC-TLS key schedule (HKDF-SHA256; v1/v2 salts; Retry tag); TLS 1.3 engine subset; X.509 minimal parser/validation; endpoint skeleton with timers and test inject; basic path validation; amplification guard; version negotiation and retry helpers.
  - Partial: persistent congestion and pacing; stream reassembly/FIN; flow control auto-tuning; DATAGRAM end-to-end surface; migration/NAT rebinding; stateless reset; QUIC v2 full flow; Compatible VN (RFC 9368), GREASE (RFC 9287), Spin Bit (RFC 9312); 0-RTT.
- CLI/tools:
  - Implemented: varint tool; client/server scaffolds build.
  - Partial: CLI flags for DATAGRAM/spin-bit/grease/cc; X.509 wiring; logging.
- Tests/fuzz/bench:
  - Implemented: KATs (key schedule, AEAD/HP), retry integrity, cipher negotiation, PN expansion, initial/handshake loops, timers, VN, amplification, TLS cert KATs, key update (TX/RX), recovery unit tests.
  - Gaps: persistent congestion tests; pacing benches; v2 vectors; DATAGRAM e2e; migration/stateless-reset; 0-RTT.
- Docs/CI/process:
  - Implemented: DESIGN.md, GAP.md; doccheck/update-gap tools; CI workflow scaffold; build.zig options for test filtering.
  - Gaps: JSON Lines logging enforcement; CI gates for GAP bump/doccheck across OS matrix; reproducible seeds pinned in CI; cross-compile matrix and egress denial.

## Open Gaps (detail)

- RFC 9002 loss recovery: persistent congestion marking; unify Initial/Handshake wiring into Recovery; pacing hook usage.
- Congestion control: CUBIC option and pacing; benchmarks.
- Flow control/streams: FIN-aware reassembly; STOP_SENDING/RESET_STREAM; MAX\* emission; per-stream windows.
- Extensions/toggles: RFC 9221 DATAGRAM API to CLI; RFC 9368 Compatible VN; RFC 9369 v2; RFC 9287 GREASE; RFC 9312 Spin Bit.
- Migration/security: NEW_TOKEN persistence/use; path migration/NAT rebinding; stateless reset; anti-amplification limits/backoff.
- TLS 1.3: optional 0-RTT; trust store provider; more X.509 cases.
- Event loop/UDP: epoll/kqueue/IOCP parity; pacing timers; non-blocking I/O.
- Logging/observability: JSON Lines logs at INFO/ERROR; counters and tracing.

## Next Slices (actionable, in order)

1. Finish Recovery integration
   - Wire Initial/Handshake spaces to Recovery; drive a single PTO scheduler; add persistent congestion + tests.
2. Pacing + CUBIC
   - Add pacing scheduler and unify with event loop timers; enable -Dcc=cubic option; bench NR vs CUBIC.
3. Flow control and streams
   - FIN-aware reassembly; STOP_SENDING/RESET_STREAM; threshold-based MAX\*; expand tests.
4. Extensions toggles
   - DATAGRAM to CLI; Spin Bit and GREASE toggles; Compatible VN; v2 tests.
5. Migration/tokens
   - Token persistence and path migration/NAT rebinding; stateless reset detection.
6. TLS/Trust/0-RTT
   - 0-RTT keys/tests; trust store; X.509 KATs.
7. Event loop and CI hardening
   - Backends; CI gates; cross-compiles; egress denial; pinned seeds.

## Risks

- TLS/X.509 correctness and interop.
- Cross-platform loop and timer behavior.
- Recovery edge cases: persistent congestion and probe racing.

## Done Criteria for the next iteration

- Recovery covers all spaces with persistent congestion; single PTO scheduler; tests/benches added; docs updated.


### 1755903354 — Wired Recovery-driven PTO for Initial/Handshake/Application; updated timers tests; added Application PTO probe; validated in debug and -Drelease-safe; fuzz/bench build OK
