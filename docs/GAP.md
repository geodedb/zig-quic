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
