# NEXT — Near‑term Plan (rolling)

Date: 2025‑09‑01

## 1) ECN longitudinal — FIX Application ACK_ECN (RFC 9000 §19.3.2)

- Scope: Make `tests/test_ecn_longitudinal.zig` pass by ensuring Application‑space ACK_ECN is emitted under reordering and one loss.
- Hypotheses: ACK‑only blocked by anti‑amplification (§8.1) when address not validated; or demux selects a connection lacking app_tx_keys causing ACK encode without ECN.
- Tasks:
  - Ensure short‑header RX path calls `getAckEcn(.Application)` and that `canSendUnderAmplification()` allows an ACK‑only send after receiving >= 1x bytes; otherwise, perform minimal validation (PATH_CHALLENGE/RESPONSE) in test or relax gating for ACK‑only per §8.1 exception if applicable.
  - Verify demux prefers the connection with app_rx_keys and app_tx_keys for this DCID; add a tie‑break by longer DCID if multiple match.
  - Add a unit assertion that after receiving ECT(1) the next ACK carries `ect1 >= 1`.
- Acceptance: Longitudinal test passes; `zig build test` green.

## 2) Streams & flow control (MVP)

- FIN‑aware reassembly; STOP_SENDING/RESET_STREAM end‑to‑end; dynamic MAX_DATA/MAX_STREAM_DATA thresholds.
- Acceptance: lifecycle tests and transport error mapping per §11.1–§11.2; flow‑control threshold bump tests.

## 3) PMTUD/DPLPMTUD — DONE (ICMP PTB + DPLPMTUD basic state machine)

- Implemented: Minimal probe sizing (PING+PADDING to exact UDP payload), per‑path MTU state, ACK‑based validation and path_mtu raise; ICMP PTB clamp helper wired via endpoint Linux error queue (IPv4/IPv6) with spoof‑checks; basic DPLPMTUD state machine (ProbeStart/ProbeSearch) with timer integration and ACK‑progression hooks.
- Tests: `tests/test_pmtud.zig` covers probe sizing, ACK validation, ICMP PTB clamp, spoof‑check rejection, and state‑machine progression.
- Acceptance: unit tests pass; endpoint timer dispatch includes `.Pmtud` kind; overall test suite green (Debug).

### Operational guidance (PMTUD/ICMP)

- Prefer ACK-confirmed probing to raise MTU; accept ICMP PTB only with strict spoof checks (quoted short-header must include our DCID at expected offset; ignore undersized quotes).
- Start from a conservative floor (e.g., 1280) and probe upward in small steps; do not exceed link-local constraints without validation. Back off to the last known-good on PTB.
- Keep one outstanding probe at a time; overwrite older pending when sending a new probe; raise MTU only on ACK of the latest pending PN.

### New coverage added in this slice

- Probe variants and ICMP spoof corner (undersized quote ignored).
- Migration scenarios: back-to-back rebinds, validation timeout keeps 3x gating.
- Streams: overlapping segments and FIN-before-gap behavior; recovery ack idempotence on stream offsets.
- Key Update: RX promotes on next-phase, retains a short previous-key window; TX toggles to new keys.

### Control-plane noise suppression (new)

- Coalesce \*\_BLOCKED (STREAM_DATA_BLOCKED/DATA_BLOCKED): emit once per peer limit value; suppress repeats until the limit changes.
- Pace MAX\_\* (MAX_STREAM_DATA/MAX_DATA) in ACK path: include only when local maxima increase since last emission.

## 4) Migration / stateless reset

- PATH_CHALLENGE/RESPONSE integration; NAT rebinding handling; preferred‑address probe; stateless reset detector.
- Acceptance: migration tests per §9; frame semantics §19.17–§19.19 validated. :contentReference[oaicite:134]{index=134} :contentReference[oaicite:136]{index=136} :contentReference[oaicite:137]{index=137}

## 5) Safety hardening

- AEAD usage‑limit counters and enforcement — DONE; integrity limit close with AEAD_LIMIT_REACHED, confidentiality counters + config overrides, unit test added.
- HP/PN timing (RFC 9001 §9.5): constant‑time audit — IN PROGRESS.
  - Audit note: header protection unmasking uses fixed‑length operations (sample size 16, PN copy <= 4) and avoids early‑exit timing on mask application. PN length determination calls `unmaskLongHeaderAndPn` once per packet on a fixed 4‑byte buffer; no data‑dependent loops beyond bounded 4 bytes.
  - Micro‑bench pointer: add a tiny bench in `bench/` to time `decodeShortProtected` and `decodeInitialProtected` across random inputs and key phases to detect gross timing variance. Not a side‑channel proof, but a guardrail.
- Acceptance: unit tests assert counter thresholds per RFC 9001 §6.6; review checklist tracks constant‑time adherence for HP timing (§9.5). :contentReference[oaicite:130]{index=130} :contentReference[oaicite:131]{index=131}

### New tests added recently

- ECN E2E: ACK_ECN emission validated for Short, Initial, and Handshake spaces (`tests/test_ack_ecn_emit.zig`, `tests/test_ack_ecn_initial.zig`, `tests/test_ack_ecn_handshake.zig`); longitudinal Application case currently failing — tracked by item 1.
- Stateless reset: retire_prior_to actively tears down tokens during traffic (`tests/test_stateless_reset_retire_prior_to_active.zig`).

## Process gates (each slice)

- Update `docs/GAP.md` + `docs/GAP_ANALYSIS.md`; update `docs/DESIGN.md` if APIs change.
- `zig build`, `zig build test` green; fuzz/bench build.
- Rehearse CI locally with `act -W .github/workflows/ci.yml` before pushing; ensure all jobs pass.
- Doccheck passes; no Internet egress in tests. (Carry‑over from copilot instructions.) :contentReference[oaicite:141]{index=141}

### Recent changes

- Migration/path: preferred‑address and rebinding race validations; PTO‑gated retries keep ≤3× amplification until PATH_RESPONSE.
- ECN: longitudinal multi‑ACK validation across Initial/Handshake/App under reordering and one loss (`tests/test_ecn_longitudinal.zig`).
- HP timing: micro‑benchmark timing `decodeShortProtected` and `decodeInitialProtected` across key phases (`bench/main.zig`).
- Fuzz: short‑decode harness and seed corpora for key‑phase flips, PN length edges, PING/PADDING shapes, and VN minimal cases.

### Next steps

- Migration: concurrent validation for multiple candidate paths, drop stale challenges, and preferred‑address active migration handshake.
- ECN: add CE reaction checks in recovery (cwnd reduction) under CE bursts; add more reorder/loss mixes.
- HP timing: extend micro‑bench to randomized PN lengths and larger payloads; consider hardware counters.
- Fuzz: add seeds for PMTUD probe shapes and ICMP quote offsets in error‑queue parsing.
