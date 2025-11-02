# TLS 1.3 Implementation Plan (RFC 8446)

## Goals

- Deliver a complete TLS 1.3 stack strictly conforming to RFC 8446 using Zig 0.15.1 standard library primitives (no external deps).
- Provide QUIC-ready handshake, traffic protection, session resumption, and 0-RTT flows with clear API boundaries.
- Supply exhaustive tests (positive, negative, fuzz) per RFC section, plus integration with QUIC transport components.
- Maintain reference-quality documentation in `docs/` and in-source comments that cite RFC 8446 sections.

## High-Level Architecture

1. **Record Layer (RFC 8446 §5):** framing, AEAD payload protection, nonce derivation, padding.
2. **Handshake State Machine (RFC 8446 §4):** client/server message sequences, transcript hash, key schedule hooks, extensions.
3. **Key Schedule & Secrets (RFC 8446 §7):** HKDF expand/extract, handshake/application traffic keys, key updates.
4. **Signature & Certificate Handling (RFC 8446 §4.4, §4.2.3, §4.2.4):** X.509 parsing, signature validation, OCSP/SCT placeholders.
5. **Session Resumption & 0-RTT (RFC 8446 §2.2, §2.3, §4.6.1, §8):** ticket issuance, anti-replay policy, PSK binders.
6. **Alerts & Error Handling (RFC 8446 §6):** alert taxonomy, connection failover paths, QUIC mapping.
7. **State Synchronization with QUIC:** handshake integration, cipher suite negotiation, key update triggers, exporter API.

## Work Breakdown

### Phase 1 – Foundations & Scaffolding

- [x] Audit current `tls13.zig`, `tls13_full.zig`, `asn1.zig`, `sig.zig`, `x509.zig` to map desired reuse vs. std replacements.
  - Findings recorded 2025-11-02: `tls13.zig` provides a QUIC-focused minimal handshake engine with custom transcript helpers; `tls13_full.zig` re-implements full ClientHello parsing, extensions, and certificate handling without leveraging `std.crypto.tls`; `asn1.zig` and `x509.zig` duplicate DER/X.509 parsing now available in `std.crypto.asn1`/`std.crypto.x509`; `sig.zig` wraps signature schemes rather than reusing `std.crypto.sign`; key schedule already delegates to `std.crypto.kdf.hkdf`.
- [x] Define module boundaries & public APIs (`tls13.zig` as facade, `tls13_full.zig` for reference impl).
  - Added `Config`, `Callbacks`, and `Context` scaffolding with RFC 8446 section references to formalize the upcoming public surface, while leaving behavior gated behind `error.Unimplemented` until individual phases land.
- [x] Establish shared data structures (transcript, secrets, context structs) with RFC citations.
  - Introduced `SecretSchedule`, `TranscriptSet`, `HandshakePhase`, and `CryptoStreams` in `tls13.zig` to centralize traffic secrets, transcript hashes, and CRYPTO buffers with inline references to RFC 8446 §4.4.1/§7.1 and RFC 9001 §4.1.4, readying the context for upcoming handshake logic.
- [x] Replace home-grown HKDF helpers with `std.crypto.kdf.hkdf`, documenting remaining ASN.1/X.509 migration.
  - Confirmed `key_schedule.zig` already uses `std.crypto.kdf.hkdf.Hkdf`; logged outstanding work to migrate ASN.1/X.509 to the stdlib in `docs/GAP.md` for visibility.
- [x] Draft test harness layout in `tests/` (unit, integration, fuzz skeletons per section).
  - Added `tests/test_tls_harness_layout.zig` with skip-marked placeholders covering unit, integration, and fuzz targets mapped to RFC 8446/9001 clauses so future slices can enable suites incrementally without breaking CI.

### Phase 2 – Record Layer (RFC 8446 §5)

- [x] Implement record framing, content types, padding per §5.1–§5.4.
  - Added `src/quic/tls/record.zig` with TLSPlaintext view helpers, legacy version validation, and TLSInnerPlaintext pack/unpack routines that enforce RFC 8446 §5.1/§5.4 limits. New unit coverage in `tests/test_tls_record_layer.zig` exercises happy paths plus malformed record handling.
- [x] Integrate AEAD suites (`TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_256_GCM_SHA384`) with std crypto.
  - Implemented `AeadCipher` in `record.zig`, wiring std.crypto AES-GCM and ChaCha20-Poly1305 with zeroization and suite metadata per RFC 8446 §5.2.
- [x] Provide nonce derivation per §5.3, usage limits per §5.5.
  - Added `xorNonce` helper and `AeadUsageLimits` counters with confidentiality/integrity enforcement and error surfacing when limits are exceeded.
- [x] Tests: encode/decode positive paths, tampering negative cases, fuzz on record payloads.
  - Extended `tests/test_tls_record_layer.zig` with AEAD round-trip, usage-limit, and nonce validation coverage; fuzz harness remains planned once broader handshake wiring lands.

### Phase 3 – Handshake Core (RFC 8446 §4)

- [x] Wire `Context.processCrypto` to buffer Initial CRYPTO data, parse a spec-compliant ClientHello (supported_versions + x25519 key_share), persist transcript updates, and expose normalized handshake metadata for the QUIC server role.
  - Added `HandshakeState` with owned ClientHello storage, view accessors, and `tests/test_tls_handshake_context.zig` covering parsing, transcript hashing, and duplicate-message rejection.
- [x] Implement server-side ServerHello → EncryptedExtensions → Finished flight production with transcript checkpoints and handshake secret installation.
  - `Context.processCrypto` now records the ClientHello transcript hash checkpoint and invokes `driveServerHandshakeFlight()` once, producing a ServerHello (TLS_AES_128_GCM_SHA256, x25519) on Initial CRYPTO, installing Handshake traffic secrets via `installTrafficSecret`, emitting EncryptedExtensions + Finished on Handshake CRYPTO, and caching the Finished pre-hash for later verification.
- [x] Emit QUIC transport parameters (extension 0x0039) in EncryptedExtensions using configurable payload; regression covered in `tests/test_tls_handshake_context.zig`.
- [x] Capture ClientHello ALPN offers, negotiate the server-preferred protocol, expose it via `Context.negotiatedAlpn()`, and fail the handshake with `HandshakeError.AlpnNegotiationFailed` when no overlap exists.
- [x] Surface negotiated handshake metadata and Finished verification state to the QUIC layer.
  - `Context.notifyMetadata()` fires a single `on_handshake_metadata` callback carrying the negotiated ALPN and encoded local QUIC transport parameters, while `metadataView()` and `localTransportParameters()` expose the cached slices for later inspection.
  - `confirmPeerFinished()` now triggers the optional `on_peer_finished` callback before promoting to `application_ready`, and `bumpPhaseAfterFinished()` retains the existing `on_handshake_complete` notification once both Finished messages are confirmed.
- [x] Parse and cache `pre_shared_key` identities and binders so PSK-capable clients can be negotiated once resumption support lands while continuing the full handshake flow by default.
- [x] Surface negotiated transport parameters/ALPN into the outer QUIC connection wiring.
  - `conn.zig` now duplicates negotiated ALPN and both local/peer QUIC transport parameter payloads, exposing them through getters so endpoint/api layers no longer reach into the TLS engine directly. New `tests/test_conn_metadata.zig` asserts the cached slices outlive the original buffers.
- [x] Manage transcript hash checkpoints (§4.4.1) and drive key schedule transitions (§7.1) across handshake flights, including Finished verification helpers.
  - Stored the handshake secret returned by `deriveHandshakeTraffic`, validated peer Finished messages against a transcript snapshot before mutating the running hash, and derived application send/receive secrets exactly once per endpoint role.
  - Added `tests/test_tls_handshake_context.zig` coverage that synthesizes a peer Finished and asserts the context promotes to `application_ready` with both application slots populated.
- [x] Plumb verified Finished state into QUIC outer components (e.g., enabling short-header transmission gates).
  - Registered a peer Finished callback in the TLS engine and wired `Connection.updatePeerFinishedStatus` so QUIC now reacts immediately to verification changes without polling.
- [x] Extend Finished handlers to cover client role, including transcript management when acting as initiator.
  - Verified the TLS peer-finished callback wiring drives both client and server connections by adding `tests/test_conn_peer_finished.zig`, ensuring short-header gating reacts immediately for initiators too.
- [x] Added regression ensuring tampered peer Finished triggers `HandshakeError.FinishedVerifyFailed`, keeping application secrets unset until verification succeeds.
- [ ] Tests: end-to-end handshake happy path, downgrade attempt detection, malformed message rejection, and fuzz on ClientHello parsers/extension decoding.

### Phase 4 – Authentication & Certificates (RFC 8446 §4.4)

- ASN.1/X.509 parsing via `std.crypto.x509` or scoped reuse of existing modules with RFC-cited comments.
- Implement certificate verification, server name indication checks, signature verification per §4.4.2–§4.4.3.
- Support OCSP/SCT placeholders for future expansion (§4.4.2.1) with TODO tags and GAP doc updates.
- Tests: self-signed cert rejection, signature mismatch, fuzz on certificate parsing.

### Phase 5 – Session Resumption & 0-RTT (RFC 8446 §2.2, §4.6.1, §8)

- Implement ticket issuance, PSK binder computation, ticket age handling (§4.2.11.1–§4.2.11.3, §4.6.1).
- Add 0-RTT flow control, anti-replay window, single-use tickets (§8.1–§8.3).
- Tests: PSK resumption success, replay attempt rejection, fuzz PSK binder inputs.

### Phase 6 – Alerts, Key Updates, Exporters (RFC 8446 §6, §7.2, §7.5)

- Map alert codes and connection close behavior, ensuring QUIC’s mapping is respected.
- Implement key update process (§7.2) and exporter interface (§7.5).
- Tests: key update handshake, exporter derivations, alert escalation scenarios.

### Phase 7 – Integration & Tooling

- Connect TLS implementation to QUIC handshake flow, ensuring secrets propagate to packet protection.
- Provide bench/fuzz targets in `bench/` and `fuzz/` for handshake and record parsing.
- Update documentation (`docs/README.md`, `docs/GAP.md`, `docs/DESIGN.md`, `docs/NEXT.md`) per Process Gates.
- Run CI (unit, fuzz smoke, benches) and capture coverage delta.

## Testing Strategy

- **Unit Tests:** Each module gets targeted positive/negative tests referencing RFC subsections.
- **Integration Tests:** Client/server handshake scripts (loopback) covering full flows, resumption, key updates.
- **Fuzzing:** Harnesses for record decoding, handshake message parsing, certificate parsing; integrate with `zig build fuzz` targets.
- **Property Tests:** HKDF output verification against RFC vectors, transcript hash invariants.
- **Interop Hooks:** Prepare for future interop tests (e.g., OpenSSL/BoringSSL) though out-of-scope for initial slices.

## Tooling & Documentation

- Use `zig std` doc server for stdlib APIs referencing.
- Keep RFC citations in comments for each implementation block (e.g., `// RFC 8446 §7.1`).
- Document any intentionally unimplemented optional features in `docs/GAP.md` and propose follow-ups in `docs/NEXT.md`.

## Risks & Mitigations

- **Complexity:** Mitigate via phased delivery, pervasive tests, and incremental integration with QUIC.
- **Interop:** Plan early integration tests against known-good TLS libs.
- **Performance:** Benchmark record layer and key schedule to ensure no regressions against QUIC requirements.

## Deliverables Checklist per Phase

- Source updates with RFC-referenced comments.
- Tests (positive/negative/fuzz) passing locally and in CI.
- Documentation updates (GAP, DESIGN, NEXT).
- Bench/fuzz targets (where applicable).
- QA notes summarizing verification per Process Gates.
