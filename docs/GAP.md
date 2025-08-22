# GAP Analysis — RFCs 9000/9001/9002 (+ options)

Date: 2025-08-22 00:05 UTC

## Latest slice (status bump)

- Completed runtime Key Update integration:
  - TX: threshold-based trigger, ACK-gated finalization, zeroization of previous TX keys.
  - RX: accept NEXT on decrypt success, promote and toggle phase, bounded previous-keys window with zeroization on expiry.
- Added targeted RX Key Update acceptance tests covering promotion and prev-window behavior.
- Fixed endpoint short-header RX compile-time type mismatch (v1 vs v2 key material struct) by explicit branching to construct packet.AeadKeys.
- Full build passes in debug and -Drelease-safe; tools/fuzzers/benches build.

## Quick Status

- Completed (summary):

  - QUIC packet paths: Initial, Handshake, Short (1-RTT) encode/decode; AES-128-GCM and ChaCha20-Poly1305 AEAD; AES and ChaCha header protection; PN unmask + expansion per space; per-space ACK builders.
  - TLS 1.3 (QUIC binding subset): X25519, HKDF/SHA-256, Finished; handshake secrets exported to derive QUIC keys; EncryptedExtensions with ALPN; allow_insecure for tests; minimal X.509 parsing.
  - TLS certs/validation (client): SAN-to-SNI match, validity window (+ KATs), wildcard DNS matching, BasicConstraints and EKU serverAuth, signature verification via std.crypto; KU enforcement.
  - Crypto tests: AEAD/HP round-trips; cipher negotiation round-trips (AES vs ChaCha); supplemental KATs; Retry integrity; key schedule KATs; RX Key Update acceptance.
  - Recovery/Endpoint/Tooling: as previously listed.

- Open Gaps vs requirements (delta):

  - TLS 1.3 and QUIC-TLS (RFC 9001):
    - 0-RTT (early data) key schedule and acceptance tests (optional).
    - Platform trust store integration (hook exists; currently stubbed).
  - Transport, Loss Recovery, CC, Flow control, Tokens, Security/Process, Performance: unchanged from prior section.

## Next Slices (actionable, in order)

1. Document runtime Key Update strategy in DESIGN.md; add diagrams. Ensure doccheck passes for new public APIs/comments.
2. CUBIC + pacing prototype behind -Dcc=cubic and measure benches; preserve NewReno default.
3. Flow control completeness: FIN-aware reassembly; threshold-based MAX\_\*; STOP_SENDING/RESET_STREAM state machines.
4. Tokens lifecycle: persist/use NEW_TOKEN; expiry/replay defenses; NAT/migration path validation refinements.
5. Fuzz/logging/perf: extend fuzzers (VN/Retry/TLS ordering); adopt JSON Lines logs; measure P50; plan PMTUD.

## Risks

- TLS/X.509 correctness and interop remain complex; mitigated by KATs, golden traces, and fuzzing.
- Pacing and CUBIC need precise timers; cross-platform drift differences.
- Token binding/expiry correctness across NAT and migrations.

## Done Criteria for the next iteration

- DESIGN.md updated with Key Update details; doccheck passes.
- CUBIC functional with pacing; benches compare NR vs CUBIC; default remains NewReno.
- FIN handling + threshold-based MAX\_\* + STOP_SENDING/RESET_STREAM tests pass.
- NEW_TOKEN persisted and used on subsequent connections; expiry/replay tests in place.
- All unit tests pass (debug and -Drelease-safe); fuzzers/benches build; GAP updated.
