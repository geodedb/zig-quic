# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-08-23 12:00 UTC

## Latest slice (status bump)

- AEAD usage limits (RFC 9001 §6.6)
  - Added connection-level counters for TX-encrypted packets (confidentiality) and RX auth failures (integrity) with configurable limits; default thresholds follow RFC guidance.
  - Endpoint calls into the connection on decryption/authentication failures across all spaces; when integrity limit is exceeded, we send CONNECTION_CLOSE with AEAD_LIMIT_REACHED (0x0f).
  - Tests: new unit test asserts integrity-limit close behavior; full suite remains green. TLS key schedule KAT still prints "PASSED tls_key_schedule_kat".
  - Follow-up: audit HP timing behavior (§9.5) and refine proactive key update near confidentiality limits.

## Coverage vs Requirements (snapshot)

- Library (src/):
  - Implemented: varint; frames (PING/ACK/ACK_ECN/CRYPTO/STREAM/MAX**/BLOCKED/PATH**/NEW_TOKEN/DATAGRAM/HANDSHAKE_DONE/CONNECTION_CLOSE); packet encode/decode (Initial/Handshake/Short), PN mask/unmask + expansion; AEAD (AES-128-GCM, ChaCha20-Poly1305), HP (AES/ChaCha); recovery with RTT/PTO, packet- and time-threshold loss, persistent congestion; NewReno + CUBIC option; QUIC-TLS key schedule (HKDF-SHA256; v1/v2 salts; Retry tag); TLS 1.3 subset; X.509 minimal parser/validation; endpoint with timers, ECN ancillary (IPv4/IPv6), ICMP error-queue parsing (PTB) with spoof-checks; anti-amplification; version negotiation and retry helpers; timer-driven pacing hook; basic DPLPMTUD state machine (ProbeStart/ProbeSearch); AEAD usage-limit enforcement (integrity close, confidentiality counter).
  - Partial: stream reassembly/FIN; flow control auto-tuning; DATAGRAM end-to-end surfacing; migration/NAT rebinding; QUIC v2 flow; Compatible VN (RFC 9368), GREASE (RFC 9287), Spin Bit (RFC 9312); 0-RTT; pacing policy tuning across OS backends.
- CLI/tools:
  - Implemented: varint tool; client/server scaffolds build.
  - Partial: CLI flags for DATAGRAM/spin-bit/grease/cc; certificate/CA wiring; JSON Lines logging.
- Tests/fuzz/bench:
  - Implemented: KATs (key schedule, AEAD/HP), retry integrity, cipher negotiation, PN expansion, initial/handshake loops, timers, VN, amplification, TLS cert KATs, Key Update (TX/RX), recovery unit tests incl. persistent congestion; PMTUD tests (probe sizing, ACK raise, ICMP clamp + spoof-check, DPLPMTUD progression); pacing micro-benches.
  - Gaps: QUIC v2 vectors; DATAGRAM e2e; migration/stateless-reset; 0-RTT; broader perf benches and observability.
- Docs/CI/process:
  - Implemented: DESIGN.md, GAP.md; doccheck/update-gap tools; CI workflow with multi-OS build+test, fuzz/bench builds, doccheck, GAP bump checks on PRs.
  - Gaps: strict JSON Lines logging enforcement; deterministic seeds checked in CI across fuzz/bench; cross-compile build-only matrix; explicit internet egress denial in tests.

## Open Gaps (detail)

- Congestion control: add CUBIC implementation and selection via -Dcc=cubic; validate with benches.
- Streams/flow control: FIN-aware reassembly, STOP_SENDING/RESET_STREAM, dynamic MAX\* emission, per-stream/connection windows.
- Extensions/toggles: RFC 9221 DATAGRAM API to CLI; RFC 9368 Compatible VN; RFC 9369 v2; RFC 9287 GREASE; RFC 9312 Spin Bit.
- Migration/security: NEW_TOKEN persistence/use; path migration and NAT rebinding; amplification limits/backoff coverage.
- TLS 1.3: optional 0-RTT; trust store provider; additional X.509 validation variants; HP timing audit (§9.5).
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

- Persist NEW_TOKEN; path validation/migration; tests for amplification backoff.

1. Event loop parity + logging
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
- Recovery/CC: Parameterized CUBIC vs NewReno benchmark over RTT/BDP/loss; simple pacing heuristic benchmarked. Added PMTUD tests that validate cwnd-aware gating and pacing behavior under both NewReno and CUBIC modes, including blackhole backoff single‑outstanding invariant.
- CI/build: Tooling and benches compile on Zig 0.14.1; acceptance tests pass.

### Next slice (preview)

- Add tests for RESET_STREAM receive semantics and lifecycle teardown; integrate with connection close paths.
- Expand CC benches: different loss patterns and RTT variance; report throughput vs. time.
- Document transport error mapping for stream errors.

### 1755994716 — all

### 1756684800 — Build/Test verification bump (2025‑08‑31)

- Build: zig build PASS (Linux).
- Tests: zig build test PASS; TLS key schedule KAT prints "PASSED tls_key_schedule_kat"; AEAD/HP KATs and handshake traces observed.
- No change to open gaps below; NEXT.md updated for date sync.

### 1756688400 — ACK ranges + ECN codec landed

- Transport frames: Added ACK_ECN (0x03) support with ECN counters; ACK multi‑range encode/decode implemented per RFC 9000 §19.3.2; new unit test `tests/test_ack_ranges_ecn.zig` added.
- Fixes: Avoided stack‑slice lifetime bug by embedding a ranges buffer in `Frame.ack`; introduced `EcnCounts` type.
- Build/Test: zig build/test green; TLS KAT still prints "PASSED tls_key_schedule_kat".

### 1756692000 — ECN → recovery wired; tests green

- Recovery/CC: Endpoint → Connection → Recovery now plumb ECN counts from ACK_ECN; Recovery halves cwnd on CE increases per RFC 9002 guidance; per‑space last‑seen ECN counters tracked to ensure monotonicity.
- API: Introduced `Recovery.onAckReceivedWithEcn(...)` and kept `onAckReceived(...)` as a wrapper for compatibility; `Connection.onAckReceivedSpace(...)` now accepts optional ECN.
- Build/Test: `zig build test` PASS on Linux; TLS KAT prints "PASSED tls_key_schedule_kat"; no regressions observed.
- Follow‑up: Outgoing ACKs currently omit ECN counts; needs per‑path ECN counter plumbing from socket to ACK builder.

### 1756695600 — Outgoing ACK_ECN emission wired

- Transport frames: Endpoint now emits ACK_ECN when ECN counters are present from the connection for each PN space (Initial/Handshake/App).
- Connection: Added per‑space ECN counters and helpers (`onEcnMark`, `getAckEcn`).
- Socket ECN (Linux): Implemented ancillary ECN reception via IP_RECVTOS using recvmsg with cmsg parsing; guarded with a recvfrom fallback for portability.
- Tests: Added `tests/test_ack_ecn_emit.zig` to assert ACK_ECN emission when ECN is observed (CE) on incoming packets.
- Follow‑ups: IPv6 ECN ancillary (IPV6_RECVTCLASS/IPV6_TCLASS) pending. (See next entry.)

### 1756699200 — IPv6 ECN ancillary landed

- Socket ECN (Linux/IPv6): Enabled ancillary reception for IPv6 traffic class. We set IPV6_RECVTCLASS on the socket and parse cmsgs with level IPPROTO_IPV6 and type IPV6_TCLASS to extract ECN bits from the low two bits of the traffic class. Guarded by target/availability with a recvfrom fallback.
- Tests: Existing ECN injection path exercises ACK_ECN emission; full test suite remains green.
- Docs: This GAP, GAP_ANALYSIS, and NEXT updated to mark IPv6 ECN ancillary as implemented.
