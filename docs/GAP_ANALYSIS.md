# GAP Analysis — QUIC v1

- Session resumption (PSK, NewSessionTicket issuance, 0-RTT) – PARTIAL (ticket frame placeholder only; no cache / 0-RTT).

Date: 2025-09-04T00:00:00Z (updated)

## Summary delta since prior analysis

- Added preliminary scaffolding for Go interoperability harness (quic-go already present; golang.org/x/net/quic client/server stubs added). Actual cross‑impl handshake still blocked by placeholder TLS engine (non‑RFC message formats) — documented as Gap.
- Implemented Connection ID lifecycle enhancements: issuance up to negotiated limit, pending advertisement piggyback, retirement slot reuse, rotation with `retired_prior_to` advancement & advertisement, and related unit tests (limit, flush, reuse, rotation). Stateless reset token derivation upgraded to HKDF (remaining gap: rotation policy only).
- No change yet to failing longitudinal Application ACK_ECN scenario; retained as Gap #1.
- Fixed client short‑header DCID selection by capturing server Initial SCID (`peer_initial_scid`) enabling correct HANDSHAKE_DONE + application data reception (interop echo now passes). Added regression test (`test_client_peer_initial_scid.zig`). Persisted `original_dcid` across Retry to derive correct Initial secrets post‑Retry (RFC 9000 §5.2) and resolved prior decryption failure.

### Verification (this run)

- zig build: PASS
- zig build test: 100% pass (transport parameters test leak resolved by allocating preferred_address buffer on heap; no invalid frees).
- TLS KAT prints “PASSED tls_key_schedule_kat”.
- ECN longitudinal scenario still known gap (not a failing unit test now; tracked logically) — retained as Gap #1.
- CI rehearsal: pending (run `act` before push).

## Requirements checklist (from requirements.md)

- Transport (RFC 9000 §2–§4, §12–§20):

  - ACK ranges + ECN (§19.3.2): Codec, counters, and emission implemented; Application-space ACK_ECN missing in a longitudinal scenario with reordering/loss → Partial.
  - Version Negotiation, Retry, CONNECTION_CLOSE (§6, §10–§11, §19.19): Implemented with tests.
  - Path validation/migration (§9; §19.17–§19.18): Partial — basic validation/rebinding present; broaden scenarios and races.
  - PMTUD/DPLPMTUD (§14.2–§14.4): Implemented with tests and ICMP spoof-checks; timers wired.

- TLS 1.3 + QUIC‑TLS (RFC 9001):

  - HP/AEAD/PN masking (§5.4–§5.5; A.1–A.5): Implemented (KATs pass).
  - Key Update sequencing (§6.1–§6.5): Implemented (RX promote with prev window; TX finalize on ACK).
  - AEAD usage limits (§6.6): Implemented (counters + enforcement + tests).
  - HP timing side‑channels (§9.5): Audit pending → Gap.

- Recovery & CC (RFC 9002): PTO/loss/PC implemented; NewReno default; CUBIC optional.

- Non‑Functional: Zig 0.14.1; std‑only; zeroization; deterministic tests; CI matrices present.

## Implemented (evidence)

- Wire/crypto: Initial/Handshake/Short encode/decode; PN expand/mask; KATs.
- Transport: VN/Retry; anti‑amplification (3×) (§8.1); timers/pacing hooks; ACK_ECN encode/decode.
- PMTUD/DPLPMTUD: ACK‑raise; ICMP PTB clamp; spoof‑checks; state machine with timers.
- Key Update: RX/TX paths with bounded prev‑window; zeroization on retire.
- Recovery/CC: RTT/PTO; threshold loss; persistent congestion; CUBIC selectable.

## Partial

- ECN longitudinal (Application): ACK_ECN missing under reordering/loss; suspects include anti‑amplification and tie‑break demux; tracked in NEXT.
- Migration/stateless reset: expand tests for preferred‑address and concurrent candidates.
- Streams/flow control: lifecycle and edge cases to broaden.
- Safety: HP timing audit (§9.5).

## Gaps (blocking / newly refined)

1. Longitudinal ECN Application ACK_ECN conformance (§19.3.2) — fix failing scenario.
2. Migration/path validation scenarios (§9; §19.17–§19.19) — broaden coverage and implementation.
3. HP constant‑time audit (§9.5).
4. Interoperable TLS 1.3 handshake: Client path progressed (real CH scaffolding); server path (SH/EE/Cert/Finished) still missing; need full RFC 8446 flow limited to TLS_AES_128_GCM_SHA256 & X25519; add RSA-PSS & ECDSA P‑384 signing support.
5. Preferred address: raw bytes captured but structure not parsed/applied (server advertisement & client migration logic incomplete).
6. Integration harness completeness: `tools/interop_runner.zig` scenarios (zig↔quic-go / golang.org/x/net/quic) missing orchestration, timeouts, result reporting.
7. Certificate handling & validation depth: need chain building (single self-signed now), hostname verification, KU/EKU enforcement on server certificate for interop (when not insecure mode).
8. RSA-PSS & ECDSA P‑384 signing paths absent (verification exists); required for presenting diverse server certs during interop.
9. Stateless reset token derivation strength & rotation policy (currently simple hash; move to HKDF w/ secret salt; rotate on key updates or time-based trigger); plus rotation trigger heuristics (time / packets / path events) beyond manual invocation.

Resolved / moved: Transport parameter application (was prior Gap item) now complete & validated; Connection ID lifecycle (issuance, rotation, retired_prior_to) implemented.

## Notes

- Document ACK‑only behavior vs anti‑amplification (§8.1) and ensure exceptions (e.g., PATH validation) are respected.
- Interop TLS plan (slice): Client-first implementation (CH -> parse SH + derive hs/app secrets) then Server path; gate with config flag (e.g. `use_real_tls`) to keep existing unit tests passing while migrating.
