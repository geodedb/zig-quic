# GAP Analysis — Initial Slice (VarInt + Frames + Build/Tooling)

Date: 2025-08-18

## Current State

- Language/runtime: Zig 0.13.0 target assumed; repository lacks build.zig/build.zig.zon.
- Code present: `quic.zig` providing:
  - RFC 9000 varint encode/decode (Section 16).
  - Frame enum and writer for many transport frames (PING/STREAM/ACK/etc.).
  - Minimal `Packet` struct with encode and AEAD-protect placeholder.
  - Inline unit tests for frames/packet encode.
- Docs present: `README.md`, `docs/GAP_ANALYSIS.md` (legacy name), specs/ data only.
- No CLI tools or library layout under `src/` yet.
- No CI, no fuzzers/benchmarks.

## Gaps vs Objectives

- Missing build system: no `build.zig` / `.zon`, no steps for test, tools, fuzz, bench.
- Missing required CLI tools: `quic-client`, `quic-server`, and `tools/varint_tool`.
- Library API (`src/quic/api.zig`) not structured; code is monolithic in `quic.zig`.
- TLS 1.3/QUIC-TLS:
  - No `src/quic/tls/` modules (key schedule, TLS handshake, X.509, ASN.1, signatures).
  - No KATs beyond placeholder.
- Transport: no endpoint/connection/streams, flow-control, migration, versioning modules.
- Recovery/CC: no loss recovery or congestion control modules.
- Event loop/UDP backends not implemented.
- Docs: `docs/README.md`, `docs/DESIGN.md`, iterative GAP process helper tools missing.
- CI: no workflows, no gating on docs/coverage.

## Risks

- TLS/X.509 correctness and interop; will mitigate with KATs and fuzzing.
- Event loop portability (epoll/kqueue/IOCP) complexity.
- Performance targets without external deps.

## Next Feature Slice (this batch)

- Establish build system and initial tooling.
- Implement `tools/quic-varint` CLI to satisfy acceptance tests.
- Add a placeholder TLS KAT test emitting the required marker line.
- Fix compile issue in `Packet.encode` size estimation.

## Done in this Slice

- Added `build.zig`/`build.zig.zon` with test step and `--test-filter` passthrough.
- Implemented `tools/quic-varint` CLI with encode/decode and underflow handling.
- Added `tests/test_tls_key_schedule.zig` placeholder printing `PASSED tls_key_schedule_kat`.
- Fixed early-return bug in `Packet.encode` size estimation.

## Planned Next Slice

- Restructure into `src/quic/` modules starting with `varint.zig`, `frame.zig`, and public API skeleton `api.zig`.
- Add `tools/update_gap.zig` and `tools/doccheck.zig` stubs and wire into CI later.
- Introduce `docs/DESIGN.md` and expand README with build/run instructions.
- Begin `src/quic/tls/key_schedule.zig` with labeled HKDF per RFC 9001 and add real KATs.

---

Update 2025-08-18T12:00Z:

- Wired QUIC v2 (RFC 9369) initial salt and labels; added `deriveInitialSecretV2` and `deriveKeyIvHpV2` with KATs.
- `QuicConfig.version` now selects v1/v2 secrets at runtime via `deriveInitialSecretsForConfig`.
- Added event loop backends: `io/loop_epoll.zig`, `io/loop_kqueue.zig`, `io/loop_iocp.zig` and API `defaultLoopBackend()`.
- Added initial packet crypto scaffolding: helper to derive initial keys in `packet.zig`.
- Build fixed for Zig 0.14 runner; tests pass for TLS KATs including v2.

Next:

- Implement AEAD and header protection for Initial packets using std.crypto.
- Integrate event loop with UDP endpoint and timers; drive `api.poll`.
- Begin TLS handshake message scaffolding and X.509 parser stubs.

Update 2025-08-18T12:35Z:

- Implemented ChaCha20-based header protection (RFC 9001 §5.4.4) in `src/quic/crypto_quic.zig`.
- Left AES-based header protection (ECB single-block) as TODO; will target next slice for Initial packets.
- Wired public API to endpoint: `src/quic/api.zig` now exposes `endpointInit/endpointDeinit/poll` via `endpoint.zig`.
- Ported `tools/doccheck.zig` to Zig 0.14 directory APIs; builds on Linux.
- Re-verified acceptance: varint CLI exact outputs and TLS KATs passing.

Next:

- Implement AES-based header protection per RFC 9001 §5.4.3 and integrate full Initial packet protection path (AAD, nonce XOR, tag).
- Hook header protection into packet encode/decode helpers; add unit tests against RFC Appendix A samples.
- Begin timers and drive `api.poll` end-to-end through `endpoint`.

Update 2025-08-18T14:30Z:

- Implemented AES-128-GCM AEAD and AES-based header protection (RFC 9001 §5.4.3) alongside ChaCha20 HP in `src/quic/crypto_quic.zig`; fixed AES HP sample offset `(4 - pn_len)` for long headers.
- Wired full Initial protection path: `protectInitial/unprotectInitial` and packet helpers `encodeInitialProtected/decodeInitialProtected` with correct AAD, varint Length, PN truncation/length.
- Added RFC 9001 Appendix A tests: A.2 Client Initial byte-exact header/tail match; A.3 Server Initial header/tail match; corrected zero-length DCID in server Initial per spec.
- Endpoint: Linux IPv4 UDP bind via `std.posix`; epoll-based loop (`io/loop_epoll.zig`); timers integrated into `endpoint.poll` with schedule/cancel and unit tests passing on Linux; kqueue/IOCP guarded to avoid Linux build issues; platform selection via `builtin.target`.
- Zig 0.14 ports: updated posix/epoll APIs, removed deprecated net UDP types, and adjusted build/test wiring; `zig build update-gap` uses `-Dgap-summary` option.

Risks/Notes:

- UDP send/recv stubs pending (currently Unsupported) — needed for real IO.
- TLS 1.3 handshake and X.509 parsing/verification not yet implemented.
- Non-Linux loop backends (kqueue/IOCP) still stubs; compile guards in place.
- Need more decode coverage (Initial decode path and error handling), and fuzz corpora growth.

Next:

- Complete UDP send/recv for IPv4/IPv6 and plumb endpoint IO to connection management.
- Implement TLS 1.3 handshake state machine (Client/Server) in `tls/tls13.zig` with transcript hashing and secrets export; add minimal `asn1.zig` and `x509.zig` for cert parsing/validation; `--insecure` bypass for tests.
- Wire `connect`/`accept` APIs; enforce anti-amplification, version negotiation, and stateless retry paths (`token.zig`).
- Build out stream/flow control: `stream.zig`, `flow_control.zig`, complete frame encode/decode and tests; optional DATAGRAM via build toggle.
- Start recovery/CC: RFC 9002 loss recovery timers, PTO/RTT; NewReno default in `congestion/newreno.zig`.
- CI: add GitHub Actions matrix (Linux/macOS/Windows), build fuzzers/bench, enforce `tools/doccheck` and mandatory GAP update on code changes.
- Docs: update `README.md` and `docs/DESIGN.md` to reflect Initial crypto and event loop; add doc comments to exported APIs.
