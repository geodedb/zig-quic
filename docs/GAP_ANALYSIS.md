# GAP Analysis — QUIC v1

Date: 2025-09-01T00:00:00Z

## Summary delta since prior analysis

- ECN longitudinal test added across Initial/Handshake/Application under reordering and one loss. Short‑header demux refined to prefer connections with 1‑RTT RX keys and avoid zero‑length DCID. Deterministic PN length (4) enforced for HP sampling stability. Handshake made deterministic in tests.

### Verification (this run)

- zig build: PASS (Linux)
- zig build test: 59/60 PASS. One failing test: tests/test_ecn_longitudinal.zig — Application‑space ACK_ECN not observed (ACK encoded without ECN counts). TLS KAT still prints “PASSED tls_key_schedule_kat”.
- CI rehearsal: not executed in this run; keep `act -W .github/workflows/ci.yml` as a required pre‑push rehearsal.

## Requirements checklist (from requirements.md)

- Transport (RFC 9000 §2–§4, §12–§20):

  - ACK ranges + ECN (§19.3.2): Codec and recovery integration implemented; per‑space ECN counters and outgoing ACK_ECN emission present. Gap: longitudinal E2E Application‑space case fails under reordering/loss; likely interaction with anti‑amplification gating (§8.1) or demux selection; classify as Partial pending fix.
  - Version Negotiation, Retry, CONNECTION_CLOSE (§6, §10–§11, §19.19): Implemented (tests present).
  - Path validation/migration (§9; §19.17–§19.18): Partial — NAT rebinding/validation and preferred‑address basics exist; more race/validation coverage pending.
  - PMTUD/DPLPMTUD (§14.2–§14.4): Implemented — probe sizing (PING+PADDING), ACK‑driven raise, ICMP PTB clamp with spoof‑checks; DPLPMTUD timers.

- TLS 1.3 + QUIC‑TLS (RFC 9001):

  - HP/AEAD/PN masking (§5.4–§5.5; A.1–A.5): Implemented (KATs).
  - Key Update sequencing (§6.1–§6.5): Implemented; RX promotion/prev‑window and TX finalize‑on‑ACK.
  - AEAD usage limits (§6.6): Implemented (counters; integrity close path; config overrides).
  - HP timing side‑channels (§9.5): Gap — audit ongoing; micro‑bench present.

- Recovery & CC (RFC 9002): PTO/loss/PC implemented; NewReno default; CUBIC optional.

- Non‑Functional: Zig 0.14.1; std‑only; zeroization; deterministic tests.

## Implemented (evidence)

- Wire/crypto: Initial/Handshake/Short encode/decode; PN expand/mask; KATs.
- Transport: VN/Retry; anti‑amplification (3×) (§8.1); timers; pacing hook; ACK_ECN encode/decode.
- PMTUD/DPLPMTUD: ACK‑raise; ICMP error‑queue parsing; spoof‑checks; timers.
- Key Update: RX/TX paths with bounded prev‑window; finalize/zeroize on ACK.
- Recovery/CC: RTT/PTO; threshold loss; persistent congestion; CUBIC selectable.

## Partial

- ECN longitudinal (Application): ACK_ECN missing in one E2E scenario (under reordering/loss). Suspects: ACK‑only suppressed by 3× amplification gate (§8.1) or demux picks a conn without app_tx_keys; fix tracked in NEXT.
- Migration/stateless reset: expand tests for concurrent path candidates and preferred‑address handshake.
- Streams/flow control: more lifecycle/edge cases.
- Safety: HP timing audit (§9.5).

## Gaps (blocking)

1. Longitudinal ECN Application ACK_ECN conformance (§19.3.2) — failing test to fix.
2. Migration/path validation scenarios (§9; §19.17–§19.19) — broaden coverage and implementation.
3. HP constant‑time audit (§9.5).

## Notes

- Keep CI rehearsal with `act` in the process gates. Document anti‑amplification nuances (division‑based compare) and ACK‑only behavior when address isn’t validated (§8.1).
