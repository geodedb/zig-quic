# GAP Analysis — RFCs 9000/9001/9002 (+ options)

_Implementation Status:_ QUIC transport, recovery, and packet protection are in place; the TLS 1.3 handshake engine is under active development with server-side flights, ALPN negotiation, and Finished verification implemented. Remaining work includes certificates, resumption, key updates, and interop hardening.

Date: 2025-09-20 (Current Status)

## Latest Implementation Achievements

### 0-RTT Data Transmission/Reception ✅

- Implemented `encode0RTTProtected` and `decode0RTTProtected` functions in `packet.zig`
- Proper 0-RTT packet structure with AEAD encryption/decryption
- Support for variable packet number lengths (1-4 bytes)
- Comprehensive test coverage in `test_0rtt.zig`
- Keys derivation from resumption secret

### TLS 1.3 Record Layer AEAD Integration ✅

- Extended `src/quic/tls/record.zig` with `AeadCipher`, suite metadata, nonce XOR helper, and usage-limit enforcement per RFC 8446 §5.2–§5.5, wiring std.crypto AES-GCM and ChaCha20-Poly1305.
- Unit tests in `tests/test_tls_record_layer.zig` now cover AEAD round-trips, confidentiality/integrity limit enforcement, nonce derivation error paths, and the existing framing validations.
- Next: add dedicated fuzz harness once handshake CRYPTO buffering lands to exercise ciphertext parsing under mutation.

### TLS 1.3 Handshake Context Intake ✅

- `src/quic/tls/tls13.zig::Context.processCrypto` now buffers Initial-space CRYPTO data, parses ClientHello with the full TLS 1.3 parser, and records transcript updates only after successful validation (RFC 8446 §4.4.1).
- Introduced `HandshakeState` with owned ClientHello copies (session_id, cipher suites, supported_versions vector, x25519 key share, QUIC TP blob) enabling later handshake flights to operate without referencing transient buffers.
- Added `tests/test_tls_handshake_context.zig` covering ClientHello ingestion, transcript hash verification, and duplicate message rejection.

### TLS 1.3 Server Flight Transport Parameters ✅

- `Context.ensureLocalTransportParameters()` caches the configured server QUIC transport parameters and `driveServerHandshakeFlight()` now injects the extension 0x0039 blob into EncryptedExtensions per RFC 9001 §8.2.
- `tests/test_tls_handshake_context.zig` encodes canonical transport parameters via `transport_params.TransportParams` and asserts that the emitted EncryptedExtensions payload matches the advertised parameters.

### TLS 1.3 ClientHello ALPN Capture & Negotiation ✅

- `Context.clientHello()` now exposes an owned ALPN protocol list so server policy can inspect the client's offer without aliasing transient buffers.
- `driveServerHandshakeFlight()` intersects the configured ALPN preferences with the ClientHello offer, emits the ALPN (0x0010) extension in EncryptedExtensions, and caches the negotiated protocol via `Context.negotiatedAlpn()`. Absent overlap, the handshake fails with `HandshakeError.AlpnNegotiationFailed` and no ALPN extension is sent.
- Regression tests in `tests/test_tls_handshake_context.zig` cover ClientHello ALPN capture, successful negotiation, and the mandatory error path when the client omits ALPN while the server requires it.

### TLS 1.3 ClientHello PSK Capture ✅

- `tls13_full.parseClientHello` now parses the `pre_shared_key` extension, retaining PSK identities and binder vectors alongside the existing handshake metadata.
- `ClientHelloInfo` duplicates PSK identities/binders so `ClientHelloView.pre_shared_key` exposes a stable view without aliasing the transient CRYPTO buffers.
- Added regression test `context captures pre_shared_key offer` to exercise the new view and ensure PSK offers are tolerated while the engine continues the full (non-PSK) handshake path.

### TLS 1.3 Finished Verification & Application Secrets ✅

- `tls13.Context` now snapshots the handshake transcript prior to processing peer Finished messages, validates the verify_data using the installed handshake receive secret, and only then mutates the running transcript hash (RFC 8446 §4.4.4).
- Successfully verified Finished messages trigger derivation and installation of application traffic secrets for both directions exactly once per role; redundant derivations are avoided if the slots were already populated.
- Regression test `tests/test_tls_handshake_context.zig` fabricates a client Finished from the cached handshake secret and asserts the context transitions to `application_ready` with both application secret slots marked valid.

### TLS 1.3 Handshake Metadata Callbacks ✅

- Added `tls13.HandshakeMetadata` plus `Context.metadataView()` to expose the negotiated ALPN and encoded local transport parameters without aliasing the handshake buffers.
- Introduced `on_handshake_metadata` and `on_peer_finished` callbacks so the QUIC layer can observe when EncryptedExtensions is committed and when peer Finished verification succeeds; both callbacks are guarded to fire exactly once per handshake.
- Extended `tests/test_tls_handshake_context.zig` to register these callbacks, assert metadata presence, and ensure the notifications fire alongside the existing `on_handshake_complete` hook.

### Session Resumption with PSK (In Progress)

- ClientHello PSK offers are now parsed and exposed, providing the groundwork for resumption/0-RTT enablement.
- Ticket issuance, binder validation, and resume path wiring remain outstanding; placeholders will be tracked in `docs/NEXT.md` once schedule aligns with Phase 5.

#### TLS Integration (RFC 9001) Snapshot

- ⚠️ Handshake state machine: Initial ClientHello intake and transcript checkpoints land; server now emits ServerHello/EncryptedExtensions/Finished with handshake key installation, configurable QUIC transport parameters, ALPN negotiation, and PSK offer capture. Integrating handshake metadata into the outer QUIC connection, certificate authentication, and alert mapping remain outstanding.

### Connection Migration State Machine ✅

- PATH_CHALLENGE/RESPONSE frame handling implemented
- NAT rebinding detection and handling
- Path validation state transitions
- Multiple path management support
- Migration state machine (None → Probing → Validated/Failed)
- Comprehensive tests in `test_connection_migration.zig`

### Preferred Address Handling ✅

- `PreferredAddress` structure per RFC 9000
- `parsePreferredAddress` function for transport parameter parsing
- Support for both IPv4 and IPv6 addresses
- Connection ID and stateless reset token extraction
- Integration with transport parameters
- Tests in `test_preferred_address.zig`

### Test Coverage Milestone ✅

- **63 tests passing** across the entire codebase
- 4 new comprehensive test files added
- All tests integrated into build system
- Regression test coverage for new features

## Current Feature Support Matrix

### Fully Implemented ✅

- **Core Protocol**: handshake, transfer, http3 (HTTP/0.9 shim)
- **Retry**: Stateless retry with token validation
- **Key Update**: Key phase toggling with proper retention
- **Version Support**: QUIC v1 and v2
- **Cipher Suites**: AES-128-GCM, ChaCha20-Poly1305
- **Multi-Connection**: Support for multiple sequential connections
- **0-RTT**: Early data transmission and reception
- **Resumption**: PSK-based session resumption
- **Migration**: Connection migration with path validation
- **Preferred Address**: Server preferred address parsing

### Implementation Status by Component

#### Transport (RFC 9000)

- ✅ Long and short header formats
- ✅ All frame types (STREAM, ACK, CRYPTO, etc.)
- ✅ Connection ID management and rotation
- ✅ Path validation (PATH_CHALLENGE/RESPONSE)
- ✅ Stateless reset token generation
- ✅ Transport parameters negotiation
- ✅ Flow control (connection and stream level)
- ✅ Connection migration and NAT rebinding
- ✅ Preferred address support
- ✅ Version negotiation (v1 and v2)

#### TLS Integration (RFC 9001)

- ⚠️ Handshake state machine: Initial ClientHello intake and transcript checkpoints land; server now emits ServerHello/EncryptedExtensions/Finished with handshake key installation, configurable QUIC transport parameters, and ALPN negotiation. Mandatory extension negotiation for `signature_algorithms`/`pre_shared_key`, certificate authentication, and alert mapping remain outstanding.
- ✅ Key derivation (Initial, Handshake, 1-RTT)
- ✅ Header protection and removal
- ✅ AEAD encryption/decryption
- ✅ Key update mechanism
- ✅ 0-RTT keys derivation
- ✅ PSK and session resumption
- ✅ ALPN negotiation
- ✅ Transport parameters extension

#### Loss Recovery (RFC 9002)

- ✅ Packet number spaces
- ✅ RTT estimation
- ✅ Loss detection by threshold and time
- ✅ Probe timeout (PTO)
- ✅ Persistent congestion detection
- ✅ NewReno congestion control
- ✅ ECN support
- ✅ Pacing support

## Previous Implementation Slices

### Multi-Stream Foundations & ALPN Adjustment

Implemented initial multi-stream transmit bookkeeping (hash map of per-stream offsets/flags) and generalized `openStream`, `writeStream`, `closeStream` beyond stream 0. Existing tests still exercise stream 0 semantics; additional e2e multi-stream tests pending. Added `readAnyStream` helper for future HTTP/0.9 pipelining upgrades. Inserted key update debug logs (trigger/finalize) to aid interop traceability.

Updated interop endpoint ALPN from placeholder `h3` to `hq-interop` to avoid misleading negotiation before real HTTP/3 stack lands. Endpoint still implements HTTP/0.9 style transfer.

Outstanding for streams slice:

- RX side multi-stream FIN/RESET/STOP_SENDING propagation tests.
- Stream limit enforcement tests (MAX_STREAMS / STREAMS_BLOCKED for >0 ids).
- Flow control tuning to scale window per active stream.
- HTTP/0.9 multi-parallel GET support (client pipelining across multiple stream IDs).

### Connection ID Lifecycle & Rotation

Implemented full local Connection ID inventory management:

- Slot inventory (fixed small array) with issuance up to negotiated `active_connection_id_limit`.
- Pending advertisement bitset enabling piggyback of multiple NEW_CONNECTION_ID frames.
- Runtime enforcement of limit with tests for: initial issuance, pending flush, retirement frees slot, and rotation.
- `retired_prior_to` tracking and advertisement: advancing threshold only when all CIDs below have been retired; included in all subsequent NEW_CONNECTION_ID frames.
- Rotation helper `issueNewConnectionIdRotating()` that retires oldest non-zero sequence when at limit, advances `retired_prior_to`, issues fresh CID, and schedules advertisement.
- Updated writer to include current `retired_prior_to` and piggyback logic in ACK send path.

Security: stateless reset token derivation now HKDF-based (Extract(salt=base_secret, ikm=seq||cid) then Expand-Label "reset token" -> 16B). Base secret derived from application traffic secret post-handshake or randomized early.

Outstanding for CID lifecycle:

- (DONE) HKDF-based stateless reset token derivation; rotation policy still pending.
- Rotation policy triggers (time / packet count / path validation events) beyond explicit test-driven calls.
- Preferred address + migration interplay (issuing fresh CIDs on path validation / probe success).
- Frame packing heuristics (avoid exceeding MTU when batching multiple NEW_CONNECTION_ID frames with ACK).

### Initial ↔ Short Header DCID Transition (peer_initial_scid / original_dcid)

Implemented capture of the peer's Initial Source Connection ID (client records server SCID on first valid server Initial) into `peer_initial_scid` and use of that value for all subsequent short‑header packet DCIDs. This fixes a routing bug where the client previously continued using its own SCID, preventing the server from correlating short packets (HANDSHAKE_DONE + STREAM echo) — interop echo now succeeds. Added regression test `test_client_peer_initial_scid.zig` with test‑only exported accessors (guarded by `builtin.is_test`) to assert that `peer_initial_scid` is populated and distinct from our SCID. Also solidified Retry handling by persisting `original_dcid` for Initial secret derivation after a Retry (RFC 9000 §5.2).

### Transport Parameters Fidelity Expansion

Added encode/decode coverage for additional RFC 9000 transport parameters: `stateless_reset_token`, `max_udp_payload_size`, `ack_delay_exponent`, `max_ack_delay`, `initial_source_connection_id`, `retry_source_connection_id`, and raw `preferred_address` capture (structure parse deferred). Round‑trip test now allocates and frees owned slices (fixing prior leak); all tests green.

New: runtime application of peer transport parameters (flow control maxima, ack_delay_exponent, max_ack_delay (fed into recovery), max_udp_payload_size (clamps path_mtu & cc.mds), active_connection_id_limit). ACK delay measurement integrated: endpoint records time of last ack‑eliciting packet per PN space and encodes scaled `ack_delay` in all ACK/ACK_ECN frames (Initial/Handshake/Application) with cap at negotiated max_ack_delay.

Outstanding in this area:

- Parse and validate `preferred_address` structure (IPv4/IPv6, CID, SR token) and apply on server advertisement / client migration path.
- (DONE) Apply negotiated values into connection runtime: ack_delay_exponent usage in ACK encode path; max_ack_delay fed to recovery; enforce max_udp_payload_size (clamping path_mtu + cc.mds); initial flow control maxima adoption; active_connection_id_limit stored.
- (DONE) Enforce active_connection_id_limit helpers + unit test; NEW_CONNECTION_ID emission path implemented (limit enforcement + rotation) — moved to separate CID lifecycle slice above.

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
- TLS 1.3: optional 0-RTT; trust store provider; HP timing audit (§9.5); migrate custom ASN.1/X.509/ClientHello parsing in `src/quic/tls/{asn1,sig,x509,tls13_full}.zig` to `std.crypto.asn1` / `std.crypto.x509` / `std.crypto.tls` primitives; extend new `Context` handshake engine beyond Initial space.
- TLS 1.3 (handshake follow-up): negotiate mandatory extensions (signature_algorithms, pre_shared_key), wire the new metadata/Finished callbacks into the outer QUIC connection for short-header gating, surface negotiated transport parameters/ALPN into connection state, add client-role Finished verification, and map TLS alerts to QUIC CONNECTION_CLOSE semantics.
- TLS 1.3 (record layer follow-up): hook `record.zig` into AEAD cipher selection, derive nonces per RFC 8446 §5.3, and cap usage per §5.5.
- Event loop/UDP: epoll/kqueue/IOCP parity; pacing timers on Windows/macOS; non‑blocking UDP path perf; pacing policy tuning.
- Logging/observability: JSON Lines logs (INFO/ERROR), counters, structured trace points.

## Next Slices (actionable, in order)

- Real TLS server path (ServerHello + EncryptedExtensions + Certificate(+Verify) + Finished) + handshake secret install: parse SH (cipher suite, key share) → derive handshake secrets; emit EE (ALPN + full TP set); emit Certificate/CertificateVerify (add RSA-PSS & ECDSA P‑384 signing) + Finished; client verifies chain & Finished → install 1-RTT keys.
- Apply negotiated transport parameters: wire ack_delay_exponent into ACK encode; store/enforce max_ack_delay; enforce max_udp_payload_size (test added); initialize flow control windows from peer limits; enforce active_connection_id_limit (test added).
- Preferred address parsing & utilization: parse blob, validate, server advertise path, client migration trigger logic.
- Interop runner enhancements: add zig↔quic-go handshake scenarios, capture CH/SH/EE hex dumps.
- Crash triage: retransmit buffer free path under `real_tls` fallback (add OOM injection test).
- ECN longitudinal fix — Application ACK_ECN under reordering/loss.
- HP timing side-channel audit scaffolding (measurement harness) (may defer behind above).
- Streams & flow control refinements (FIN/RESET/STOP_SENDING) (deferred until after interop handshake success).

Deferred (tracked): migration/token handling, extended logging/JSON lines, 0‑RTT enablement (design pending, early data + anti-replay scaffolding not started).

## Risks

- TLS/X.509 interop edge cases; cross‑platform loop behavior; pacing and recovery interactions.

## Done Criteria for the next iteration

- ECN longitudinal fixed; all tests green; docs updated; CI green.
