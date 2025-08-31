# NEXT — Near‑term Plan (rolling)

Date: 2025‑08‑31

## 1) ACK multi‑range + ECN — DONE (codec + recovery + ACK_ECN emission + Linux+IPv6 ancillary)

- Implemented: ACK ranges vector + ECN counters; encode/decode; unit test `tests/test_ack_ranges_ecn.zig`; ECN counts plumbed to recovery/CC with CE response; endpoint emits ACK_ECN when ECN counters observed per space; Linux ancillary ECN reception (IPv4 IP_RECVTOS + recvmsg, IPv6 IPV6_RECVTCLASS/IPV6_TCLASS) and `tests/test_ack_ecn_emit.zig`.
- Acceptance: unit tests pass; overall test suite green (Debug). :contentReference[oaicite:125]{index=125}

## 2) Streams & flow control (MVP)

- FIN‑aware reassembly; STOP_SENDING/RESET_STREAM end‑to‑end; dynamic MAX_DATA/MAX_STREAM_DATA thresholds.
- Acceptance: lifecycle tests and transport error mapping per §11.1–§11.2; flow‑control threshold bump tests. :contentReference[oaicite:127]{index=127}

## 3) PMTUD/DPLPMTUD — DONE (ICMP PTB + DPLPMTUD basic state machine)

- Implemented: Minimal probe sizing (PING+PADDING to exact UDP payload), per‑path MTU state, ACK‑based validation and path_mtu raise; ICMP PTB clamp helper wired via endpoint Linux error queue (IPv4/IPv6) with spoof‑checks; basic DPLPMTUD state machine (ProbeStart/ProbeSearch) with timer integration and ACK‑progression hooks.
- Tests: `tests/test_pmtud.zig` covers probe sizing, ACK validation, ICMP PTB clamp, spoof‑check rejection, and state‑machine progression.
- Acceptance: unit tests pass; endpoint timer dispatch includes `.Pmtud` kind; overall test suite green (Debug). :contentReference[oaicite:133]{index=133}

## 4) Migration / stateless reset

- PATH_CHALLENGE/RESPONSE integration; NAT rebinding handling; preferred‑address probe; stateless reset detector.
- Acceptance: migration tests per §9; frame semantics §19.17–§19.19 validated. :contentReference[oaicite:134]{index=134} :contentReference[oaicite:136]{index=136} :contentReference[oaicite:137]{index=137}

## 5) Safety hardening

- AEAD usage‑limit counters and enforcement; audit HP/PN recovery paths for constant‑time where applicable.
- Acceptance: unit tests assert counter thresholds per RFC 9001 §6.6; review checklist notes constant‑time adherence for HP timing (§9.5). :contentReference[oaicite:130]{index=130} :contentReference[oaicite:131]{index=131}

## Process gates (each slice)

- Update `docs/GAP.md` + `docs/GAP_ANALYSIS.md`; update `docs/DESIGN.md` if APIs change.
- `zig build`, `zig build test` green; fuzz/bench build.
- Doccheck passes; no Internet egress in tests. (Carry‑over from copilot instructions.) :contentReference[oaicite:141]{index=141}
