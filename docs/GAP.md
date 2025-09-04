# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-09-04 (updated)

## Latest slice (status bump)

### Transport Parameters Fidelity Expansion

Added encode/decode coverage for additional RFC 9000 transport parameters: `stateless_reset_token`, `max_udp_payload_size`, `ack_delay_exponent`, `max_ack_delay`, `initial_source_connection_id`, `retry_source_connection_id`, and raw `preferred_address` capture (structure parse deferred). Round‑trip test now allocates and frees owned slices (fixing prior leak); all tests green.

Outstanding in this area:

- Parse and validate `preferred_address` structure (IPv4/IPv6, CID, SR token) and apply on server advertisement / client migration path.
- Apply negotiated values into connection runtime (ACK delay exponent usage in ACK encode path; max_ack_delay timer; enforce max_udp_payload_size; initial flow control windows derivation).
- Integrate active_connection_id_limit handling for CID retirement issuance cadence.

### Partial Real TLS Bootstrapping (experimental flag `real_tls`)

Remaining from prior ECN slice: Application-space ACK_ECN under reordering/loss (unchanged).

Added:

- Added config flag `real_tls` (client/server CLI `--real-tls`).
- TLS Engine gained `real_mode` + spec-oriented ClientHello builder (cipher list, supported_versions, groups, key_share (x25519), sig_algs, ALPN, QUIC TP ext 0x0039).
- Endpoint now gates initial ClientHello generation: if `real_tls` true, attempt real CH else fallback to legacy minimal placeholder.
- Server path & parsing of real ServerHello / EncryptedExtensions / Certificate / Finished still pending (currently placeholder auto SH emission remains).
- Crash observed when running standalone client with `--real-tls` against no server (null-pointer free suspicion in retransmit buffer path) — to be triaged next slice.
- Hypothesis: fallback path interaction with uninitialized retransmit buffer; will add defensive nulling and a targeted unit test.

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
- TLS 1.3 (interop specific): real ServerHello parse; EE (ALPN+TP) emit/parse; Certificate & CV & Finished; key schedule integration replacing placeholder; error mapping & alerts -> QUIC CONNECTION_CLOSE; crash fix on empty network; X25519 retry edge cases.
- Event loop/UDP: epoll/kqueue/IOCP parity; pacing timers on Windows/macOS; non‑blocking UDP path perf; pacing policy tuning.
- Logging/observability: JSON Lines logs (INFO/ERROR), counters, structured trace points.

## Next Slices (actionable, in order)

- Real TLS server path (ServerHello + EncryptedExtensions + Certificate(+Verify) + Finished) + handshake secret install: parse SH (cipher suite, key share) → derive handshake secrets; emit EE (ALPN + full TP set); emit Certificate/CertificateVerify (add RSA-PSS & ECDSA P‑384 signing) + Finished; client verifies chain & Finished → install 1-RTT keys.
- Apply negotiated transport parameters: wire ack_delay_exponent into ACK encode; store/enforce max_ack_delay; enforce max_udp_payload_size; initialize flow control windows from peer limits; enforce active_connection_id_limit.
- Preferred address parsing & utilization: parse blob, validate, server advertise path, client migration trigger logic.
- Interop runner enhancements: add zig↔quic-go handshake scenarios, capture CH/SH/EE hex dumps.
- Crash triage: retransmit buffer free path under `real_tls` fallback (add OOM injection test).
- ECN longitudinal fix — Application ACK_ECN under reordering/loss.
- HP timing side-channel audit scaffolding (measurement harness) (may defer behind above).
- Streams & flow control refinements (FIN/RESET/STOP_SENDING) (deferred until after interop handshake success).

Deferred (tracked): migration/token handling, extended logging/JSON lines, 0‑RTT enablement.

## Risks

- TLS/X.509 interop edge cases; cross‑platform loop behavior; pacing and recovery interactions.

## Done Criteria for the next iteration

- ECN longitudinal fixed; all tests green; docs updated; CI green.
