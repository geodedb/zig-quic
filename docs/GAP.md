# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-09-03

## Latest slice (status bump)

- ECN ACK_ECN emission (RFC 9000 §19.3.2):
  - Implemented per-space ECN counters and ACK_ECN emission for Initial, Handshake, and Application.
  - Endpoint Application ACK path now unifies ACK_ECN selection across allow/ack-only branches and falls back to current datagram ECN bits when counters are zero.
  - Remaining: longitudinal ECN test reveals Application-space ACK_ECN may be missed under reordering/loss; tracked below.

## Coverage vs Requirements (snapshot)

- Library (src/):
  - Implemented: varint; frames (PING/ACK/ACK_ECN/CRYPTO/STREAM/MAX**/BLOCKED/PATH**/NEW_TOKEN/DATAGRAM/HANDSHAKE_DONE/CONNECTION_CLOSE); packet encode/decode (Initial/Handshake/Short), PN encode/mask/unmask + expansion; AEAD (AES-128-GCM, ChaCha20-Poly1305), HP (AES/ChaCha); recovery (RTT/PTO/loss/PC); NewReno + CUBIC; QUIC‑TLS key schedule; TLS 1.3 subset; X.509 minimal; endpoint with timers, ECN ancillary (IPv4/IPv6), ICMP PTB handling w/ spoof‑checks; anti‑amplification; VN/Retry; pacing hook; DPLPMTUD basic; AEAD usage‑limit enforcement.
  - Partial: stream reassembly/FIN; flow‑control auto‑tuning; DATAGRAM end‑to‑end surfacing; migration/NAT rebinding; QUIC v2; Compatible VN (RFC 9368); GREASE (RFC 9287); Spin Bit (RFC 9312); 0‑RTT; pacing policy tuning across OS backends; HP timing audit.
- CLI/tools:
  - Implemented: varint tool; client/server scaffolds build.
  - Partial: CLI flags for DATAGRAM/spin‑bit/grease/cc; certificate/CA wiring; JSON Lines logging.
- Tests/fuzz/bench:
  - Implemented: KATs (key schedule, AEAD/HP), retry integrity, cipher negotiation, PN expansion, initial/handshake loops, timers, VN, amplification, TLS cert KATs, Key Update (TX/RX), recovery tests incl. PC; PMTUD tests; pacing micro‑benches; ACK ranges + ECN tests.
  - Gaps: ECN longitudinal Application ACK_ECN (one failing scenario); QUIC v2 vectors; DATAGRAM e2e; migration/stateless‑reset; 0‑RTT; broader perf benches and observability.
- Docs/CI/process:
  - Implemented: DESIGN.md, GAP.md; doccheck/update-gap tools; CI workflow with multi‑OS build+test, fuzz/bench builds, doccheck, GAP bump checks.
  - Gaps: strict JSON Lines logging enforcement; deterministic seeds for fuzz/bench in CI; build‑only cross‑compile matrix.

## Open Gaps (detail)

- ECN longitudinal (Application): ensure ACK_ECN emission under reordering/loss; audit anti‑amplification interaction and connection demux tie‑break.
- Migration/security: NEW_TOKEN persistence/use; path migration and NAT rebinding; amplification backoff coverage.
- TLS 1.3: optional 0‑RTT; trust store provider; HP timing audit (§9.5).
- Event loop/UDP: epoll/kqueue/IOCP parity; pacing timers on Windows/macOS; non‑blocking UDP path perf; pacing policy tuning.
- Logging/observability: JSON Lines logs (INFO/ERROR), counters, structured trace points.

## Next Slices (actionable, in order)

1. ECN longitudinal fix — Application ACK_ECN
   - Ensure ACK_ECN when ECN marked datagram observed; unify demux selection by preferring connection with app_rx/tx keys for DCID; consider emitting ACK_ECN even without new ack‑eliciting frames if counters advanced (within RFC guidance).
2. Streams & flow control basics
   - FIN‑aware reassembly; STOP_SENDING/RESET_STREAM; dynamic MAX thresholds; tests.
3. Migration/token handling
   - Persist NEW_TOKEN; path validation/migration; tests for amplification backoff.
4. Event loop parity + logging
   - Validate pacing across epoll/kqueue/IOCP; add JSON Lines logs; pin deterministic seeds in CI.

## Risks

- TLS/X.509 interop edge cases; cross‑platform loop behavior; pacing and recovery interactions.

## Done Criteria for the next iteration

- ECN longitudinal fixed; all tests green; docs updated; CI green.
