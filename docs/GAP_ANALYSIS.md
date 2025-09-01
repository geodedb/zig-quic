# GAP Analysis — QUIC v1

Date: 2025-09-01T00:00:00Z

## Summary delta since prior analysis

Latest slice landed: control-frame coalescing/pacing (suppressed _*BLOCKED spam; paced MAX*_ emission), key update stress + OOO PN-gap acceptance window tests, PMTUD IPv6 EH offset acceptance, and PMTUD cwnd-aware probe gating with PTO backoff assertions. Added PMTUD pacing tests parameterized over NewReno and CUBIC, asserting single-outstanding behavior and PTO backoff under blackhole conditions. Anti-amplification hardening retained. All tests green. :contentReference[oaicite:85]{index=85}

### Verification (this run)

- zig build: PASS (Linux)
- zig build test: PASS; TLS KAT prints "PASSED tls_key_schedule_kat"; AEAD/HP KATs and handshake/initial loops emit expected traces; new PMTUD pacing/CC tests pass. :contentReference[oaicite:93]{index=93}
- CI rehearsal: `act -W .github/workflows/ci.yml` PASS (all jobs) — required before push.

## Requirements checklist (parsed from requirements.md)

- Transport (RFC 9000 §2–§4, §12–§20):

  - Frames incl. ACK ranges + ECN (§19.3): Implemented — ACK ranges vector + ECN encode/decode with unit tests; ECN counts consumed by recovery/CC; outgoing ACKs emit ECN counts when observed. Socket ECN reception via ancillary implemented on Linux for IPv4 (IP_RECVTOS) and IPv6 (IPV6_RECVTCLASS/TCLASS) using recvmsg with cmsg parsing. Longitudinal E2E test across spaces under reordering/loss added (`tests/test_ecn_longitudinal.zig`). :contentReference[oaicite:49]{index=49} :contentReference[oaicite:50]{index=50}
  - Version Negotiation, Retry, CONNECTION_CLOSE (§6, §10–§11, §19.19): Implemented (tests present). :contentReference[oaicite:53]{index=53} :contentReference[oaicite:54]{index=54}
  - Path validation/migration (§9; §19.17–§19.18): Partial → Expanded — tests cover back‑to‑back rebinds, preferred‑address validation, PTO‑gated retries, and reordering races (see `tests/test_migration_scenarios.zig`). Further integration for concurrent path candidates remains. :contentReference[oaicite:55]{index=55} :contentReference[oaicite:57]{index=57} :contentReference[oaicite:58]{index=58}
  - PMTUD/DPLPMTUD (§14.2–§14.4): Implemented — probe sizing (PING+PADDING) with ACK-based validation; ICMP PTB parsing via Linux error queue (IPv4/IPv6) with spoof-checks; basic DPLPMTUD state machine (ProbeStart/ProbeSearch) and timers. Unit tests cover probe sizing, ACK raise, ICMP clamp + spoof-check, and state progression. :contentReference[oaicite:61]{index=61} :contentReference[oaicite:62]{index=62}
    - Spoof-check corner handling: undersized ICMP quotes are ignored; DCID mismatch quotes are rejected (tests in `tests/test_pmtud.zig`).
    - Probe overwrite policy: only one outstanding probe is tracked; sending a new probe overwrites prior pending PN/size; path_mtu is raised only on ACK of the latest pending.
    - Pacing/cwnd interaction: probes are gated by cwnd (no send when cwnd < bytes_in_flight + probe_size), and PTO backoff is reflected in recovery timers (tests in `tests/test_pmtud.zig`).

- TLS 1.3 + QUIC‑TLS (RFC 9001):

  - HKDF labels; Initial/Handshake/1‑RTT keys; HP sample/PN mask (§5.4–§5.5; A.1–A.5): Implemented (KATs). :contentReference[oaicite:65]{index=65} :contentReference[oaicite:66]{index=66}
  - Key Update sequencing, retention windows (§6.1–§6.5): Implemented. Tests include RX promotion, bounded previous-key acceptance, OOO across PN gaps within a limited window, and TX finalize/zeroize on ACK. Fuzz corpus includes key‑phase toggle seeds.
  - AEAD usage limits (§6.6): Implemented — counters and enforcement (integrity close; confidentiality counter) with config overrides and a unit test. :contentReference[oaicite:70]{index=70}
  - HP timing side‑channel constraints (§9.5): Gap — audit in progress; micro‑benchmark added in `bench/main.zig` to monitor decode timing variance across key phases; docs carry audit notes. :contentReference[oaicite:72]{index=72}

- Recovery & CC (RFC 9002):

  - PTO, loss detection, persistent congestion (§6–§7): Implemented. :contentReference[oaicite:75]{index=75} :contentReference[oaicite:76]{index=76}
  - NewReno default; CUBIC optional (-Dcc=cubic): Implemented; benches added.

- Non‑Functional:

  - Zig 0.14.1, std‑only; zeroization of retired keys; deterministic tests: Implemented (policy/docs/tests).

- CLI/Tools/CI:
  - Varint tool acceptance; TLS key schedule KAT; CI doc gates: Implemented.

## Implemented (evidence‑based)

- Wire & crypto: Initial/Handshake/Short encode/decode; PN expand/mask; AEAD + header protection per RFC 9001; TLS key schedule KATs passing. :contentReference[oaicite:87]{index=87}
- Transport: VN/Retry; anti‑amplification; timers; endpoint pacing hook; STOP_SENDING/RESET_STREAM handling present; flow-control threshold bumps. :contentReference[oaicite:89]{index=89}
- Key Update: TX/RX sequencing with previous key phase retention and finalize‑on‑ACK; tests in `tests/test_key_update.zig` and `tests/test_rx_key_update_accept.zig` pass (RFC 9001 §6.2–§6.5). :contentReference[oaicite:108]{index=108}
- Recovery: RTT/PTO, packet/time‑threshold loss, persistent congestion per RFC 9002 §7.6; NewReno default; CUBIC implemented and selectable (`-Dcc=cubic`), with comparative benches. :contentReference[oaicite:91]{index=91}
- Tooling/CI/docs: varint tool acceptance; CI/doc gates; TLS KAT shows “PASSED tls_key_schedule_kat”. :contentReference[oaicite:93]{index=93}

## Partially implemented

- Streams/flow control: FIN reassembly and dynamic MAX\* emission implemented with coalescing/pacing; more lifecycle matrix coverage desirable (§2–§4; §11.2). :contentReference[oaicite:97]{index=97}
- Migration/stateless reset: PATH_CHALLENGE/RESPONSE + preferred‑address rules need integration & tests (§19.17–§19.19; §9.6). :contentReference[oaicite:102]{index=102} :contentReference[oaicite:104]{index=104}
- Safety: HP timing side‑channel hardening requires audit (RFC 9001 §9.5). :contentReference[oaicite:113]{index=113}

## Gaps (blocking conformance)

1. Migration/path validation & stateless reset (§9; §19.17–§19.19): concurrent path candidate handling and preferred‑address active migration handshake tests. :contentReference[oaicite:118]{index=118}
2. Safety: HP constant‑time audit (§9.5): extend analysis beyond guardrail bench; side‑channel review checklist. :contentReference[oaicite:122]{index=122}

## Next (pointer)

See `NEXT.md` for the ordered slices and acceptance tests aligned to the above gaps.
