# NEXT — Near‑term Plan (rolling)

- Add client consumption of NewSessionTicket and derive resumption secret (RFC 8446 §4.6.1) for future 0-RTT.

Date: 2025‑09‑04

## 1) ECN longitudinal — FIX Application ACK_ECN (RFC 9000 §19.3.2)

- Scope: Make `tests/test_ecn_longitudinal.zig` pass by ensuring Application‑space ACK_ECN is emitted under reordering and one loss.
- Current: Endpoint unifies ACK_ECN selection (counters or fallback to current datagram). Test still fails in one scenario.
- Hypotheses: (a) anti‑amplification gating timing; (b) demux selects a conn instance lacking app_tx_keys; (c) ACK path races with counters update.
- Tasks:
  - Precompute ACK_ECN before allow/ack‑only split (DONE); if ecn_bits!=0, force ACK_ECN for that ACK.
  - Add deterministic ACK scheduling when ECN counters advance, even if no new ack‑eliciting frames (bounded frequency to remain RFC‑compliant).
  - Strengthen demux preference: prefer entry with app_rx_keys/app_tx_keys for matching DCID, longest DCID wins; fallback only if none.
  - Add targeted unit to assert at least one ACK_ECN with ect1>=1 after receiving ECT(1) under reordering with one loss.
- Acceptance: Longitudinal test passes; `zig build test` green.

## 2) Streams & flow control (MVP)

- FIN‑aware reassembly; STOP_SENDING/RESET_STREAM end‑to‑end; dynamic MAX_DATA/MAX_STREAM_DATA thresholds.
- Acceptance: lifecycle tests and transport error mapping per §11.1–§11.2; flow‑control threshold bump tests.

## 3) Migration / stateless reset

- PATH_CHALLENGE/RESPONSE integration; NAT rebinding handling; preferred‑address probe; stateless reset detector.
- Acceptance: migration tests per §9; frame semantics §19.17–§19.19 validated.

## 4) Safety hardening

- AEAD usage‑limit counters and enforcement — DONE; integrity limit close with AEAD_LIMIT_REACHED, confidentiality counters + config overrides.
- HP/PN timing (RFC 9001 §9.5): constant‑time audit — IN PROGRESS.
  - Audit notes: fixed‑length HP sample (16); PN mask application bounded ≤4 bytes; avoid data‑dependent early exits.

## 5) Tooling/CI

- Keep `zig build tools && ./zig-out/bin/doccheck` green; ensure GAP.md/GAP_ANALYSIS.md updated in PRs with code changes.
- Run `act -W .github/workflows/ci.yml` before push to keep main green.

## 6) Connection ID hardening & rotation policy

- HKDF stateless reset token derivation COMPLETE (vector test added).
- Add base secret rotation: trigger on key update, periodic timer (e.g. 10 min), packet count threshold, path validation success.
- Ensure NEW_CONNECTION_ID batching respects MTU (cap frames per packet, spill to follow-on packet if needed) and add test capturing multiple NEW_CONNECTION_ID frames piggybacked with ACK ensuring no overflow and correct `retired_prior_to` propagation.

Acceptance: rotation policy unit tests; all existing CID lifecycle + token vector tests remain green.
