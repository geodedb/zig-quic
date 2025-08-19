# QUIC

Zig std-only QUIC workspace (target Zig 0.13.0/0.14.x). Includes:

- Varint/frames utilities and tests.
- AES-128-GCM AEAD, AES/ChaCha header protection for QUIC Initial/Handshake/Short helpers.
- Minimal TLS 1.3 key schedule + X25519 ECDHE hooks and tests.
- CLI tool `quic-varint`.

## Build

- Debug: `zig build`
- Release-safe: `zig build -Drelease-safe=true`

## Tools

- Build tools: `zig build tools`
- Varint encode: `./zig-out/bin/quic-varint encode 64` → `40 40`
- Varint decode: `./zig-out/bin/quic-varint decode 7f ff` → `16383`
- Varint underflow: `./zig-out/bin/quic-varint decode 40` prints `VARINT_UNDERFLOW` to stderr, exit 2

## Tests

- All tests: `zig build test`
- Filtered TLS KAT only: `zig build -Dtest-filter=tls_key_schedule_kat test`
- Short-header 1-RTT roundtrip is included in default test run.

## Docs

- Gap analysis: `docs/GAP.md`
- Design: `docs/DESIGN.md`

## Next

- Expand TLS 1.3 handshake (Finished, certs), enable 1-RTT streams/ACKs, wire UDP IO and event loop.
