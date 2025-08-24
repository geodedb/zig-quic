# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-08-23 12:00 UTC

## Latest slice (status bump)

- Timer-driven pacing integration
  - Connection now delegates send via a pluggable sender callback; Endpoint installs a paced-sender that schedules transmit via timers.
  - Removed sleep-based pacing from hot path; pacing delay computed by Recovery.computePacingDelayNs and scheduled by the event loop.
  - Fixed build graph to share a single recovery module (quic_recovery) across conn/endpoint/api to avoid duplicate-module errors.
  - Added build filter flag support usage: run “zig build -Dtest-filter=tls_key_schedule_kat test”.
- Build/Test
  - zig build, zig build test pass locally after pacing refactor; acceptance varint tests (encode/decode/underflow) pass.
  - TLS key schedule KAT shows “PASSED tls_key_schedule_kat”.

## Coverage vs Requirements (snapshot)

- Library (src/):
  - Implemented: varint; frames (PING/ACK/CRYPTO/STREAM/MAX**/BLOCKED/PATH**/NEW_TOKEN/DATAGRAM/HANDSHAKE_DONE/CONNECTION_CLOSE); packet encode/decode (Initial/Handshake/Short), PN mask/unmask + expansion; AEAD (AES-128-GCM, ChaCha20-Poly1305), HP (AES/ChaCha); recovery with RTT/PTO, packet- and time-threshold loss, persistent congestion; NewReno; QUIC-TLS key schedule (HKDF-SHA256; v1/v2 salts; Retry tag); TLS 1.3 subset; X.509 minimal parser/validation; endpoint with timers and test injection; anti-amplification; version negotiation and retry helpers; timer-driven pacing hook in endpoint.
  - Partial: stream reassembly/FIN; flow control auto-tuning; DATAGRAM end-to-end surfacing; migration/NAT rebinding; stateless reset; QUIC v2 flow; Compatible VN (RFC 9368), GREASE (RFC 9287), Spin Bit (RFC 9312); 0-RTT; pacing policy tuning across OS backends.
- CLI/tools:
  - Implemented: varint tool; client/server scaffolds build.
  - Partial: CLI flags for DATAGRAM/spin-bit/grease/cc; certificate/CA wiring; JSON Lines logging.
- Tests/fuzz/bench:
  - Implemented: KATs (key schedule, AEAD/HP), retry integrity, cipher negotiation, PN expansion, initial/handshake loops, timers, VN, amplification, TLS cert KATs, Key Update (TX/RX), recovery unit tests incl. persistent congestion; pacing micro-benches.
  - Gaps: QUIC v2 vectors; DATAGRAM e2e; migration/stateless-reset; 0-RTT; broader perf benches and observability.
- Docs/CI/process:
  - Implemented: DESIGN.md, GAP.md; doccheck/update-gap tools; CI workflow with multi-OS build+test, fuzz/bench builds, doccheck, GAP bump checks on PRs.
  - Gaps: strict JSON Lines logging enforcement; deterministic seeds checked in CI across fuzz/bench; cross-compile build-only matrix; explicit internet egress denial in tests.

## Open Gaps (detail)

- Congestion control: add CUBIC implementation and selection via -Dcc=cubic; validate with benches.
- Streams/flow control: FIN-aware reassembly, STOP_SENDING/RESET_STREAM, dynamic MAX\* emission, per-stream/connection windows.
- Extensions/toggles: RFC 9221 DATAGRAM API to CLI; RFC 9368 Compatible VN; RFC 9369 v2; RFC 9287 GREASE; RFC 9312 Spin Bit.
- Migration/security: NEW_TOKEN persistence/use; path migration and NAT rebinding; stateless reset detection; amplification limits/backoff coverage.
- TLS 1.3: optional 0-RTT; trust store provider; additional X.509 validation variants.
- Event loop/UDP: finalize epoll/kqueue/IOCP parity; pacing timers on Windows/macOS; non-blocking UDP path perf; pacing policy tuning.
- Logging/observability: JSON Lines logs (INFO/ERROR), counters, structured trace points.

## Next Slices (actionable, in order)

1. CUBIC + benches
   - Implement CUBIC; expose -Dcc=cubic; add comparative NR vs CUBIC throughput/latency benches over fixed BDP/RTT/loss profiles.
2. Stream and flow control basics
   - Implement FIN-aware reassembly; STOP_SENDING/RESET_STREAM; emit MAX_DATA/MAX_STREAM_DATA thresholds; unit tests.
3. Extensions to CLI and wire toggles
   - Wire DATAGRAM to CLI; add spin-bit and grease toggles; groundwork for Compatible VN and v2 vectors.
4. Migration/token handling
   - Persist NEW_TOKEN; path validation/migration; stateless reset detector; tests for amplification backoff.
5. Event loop parity + logging
   - Validate pacing across epoll/kqueue/IOCP; add JSON Lines logs; pin deterministic seeds in CI.

## Risks

- TLS/X.509 interop edge cases.
- Cross-platform loop and timer behavior.
- Pacing policy and recovery interactions.

## Done Criteria for the next iteration

- CUBIC implemented and selectable; initial benches in bench/ comparing NR vs CUBIC; stream FIN and RESET implemented with tests; CLI exposes DATAGRAM/spin-bit/grease; docs updated; CI green on all OS.

### 1755993600 — Wired pacing option, configurable MDS; added pacing bench and ACK-driven PC test; all tests green

## Status update — 2025-08-23

- Streams: Implemented RX-side RESET_STREAM handling and stream teardown API. Emits RESET_STREAM on STOP_SENDING with final_size of bytes sent. RX path caps final_size, trims buffered data, marks finished.
- Flow control: Threshold bumps for MAX_DATA and MAX_STREAM_DATA when consumption crosses 50% of current window; blocked signaling for STREAM_DATA_BLOCKED/DATA_BLOCKED.
- Recovery/CC: Parameterized CUBIC vs NewReno benchmark over RTT/BDP/loss; simple pacing heuristic benchmarked.
- CI/build: Tooling and benches compile on Zig 0.14.1; acceptance tests pass.

### Next slice (preview)

- Add tests for RESET_STREAM receive semantics and lifecycle teardown; integrate with connection close paths.
- Expand CC benches: different loss patterns and RTT variance; report throughput vs. time.
- Document transport error mapping for stream errors.

### 1755994716 — all
