# QUIC

Zig 0.13.0 workspace for a std-only QUIC implementation. This repo currently includes:

- Varint/frames utilities and tests (in `quic.zig`).
- CLI tool `quic-varint` for encoding/decoding QUIC varints.
- Placeholder TLS key schedule KAT test.

## Build

- Debug: `zig build`
- Release-safe: `zig build -Drelease-safe=true`

## Tools

- Build tools: `zig build tools`
- Varint encode: `./zig-out/bin/quic-varint encode 64` → prints `40 40`
- Varint decode: `./zig-out/bin/quic-varint decode 7f ff` → prints `16383`

## Tests

- Run all tests: `zig build test`
- Filter TLS KAT: `zig build test --test-filter tls_key_schedule_kat`

## Docs

- Gap analysis: `docs/GAP.md`
- Design: `docs/DESIGN.md`

## Next

- Move into `src/quic/*` modules, implement QUIC-TLS key schedule with real KATs, add fuzzers/benches, and expand transport + TLS.
