# QUIC

Zig std-only QUIC workspace (target Zig 0.14.1/0.14.x). Includes:

- Varint/frames utilities and tests.
- AES-128-GCM AEAD, AES/ChaCha header protection for QUIC Initial/Handshake/Short helpers.
- Minimal TLS 1.3 key schedule + X25519 ECDHE hooks and tests.
- CLI tool `quic-varint`.
- Optional RFC 9368 Compatible Version Negotiation toggle and minimal DATAGRAM echo path.

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

### Acceptance tests (exact outputs)

- Cmd 1:
  - Run: `zig build tools && ./zig-out/bin/quic-varint encode 64`
  - Expect stdout: `40 40`
  - Exit: `0`
- Cmd 2:
  - Run: `./zig-out/bin/quic-varint decode 7f ff`
  - Expect stdout: `16383`
  - Exit: `0`
- Cmd 3:
  - Run: `./zig-out/bin/quic-varint decode 40`
  - Expect stderr contains: `VARINT_UNDERFLOW`
  - Exit: `2`
- Cmd 4:
  - Run: `zig build test --test-filter "tls_key_schedule_kat"`
  - Expect stdout contains: `PASSED tls_key_schedule_kat`
  - Exit: `0`

## CLI

- Server: `./zig-out/bin/quic-server --bind 0.0.0.0:4433 --alpn h3 --datagram=true --compatible-vn --retry true --token-expiry-ms 60000`
- Client: `./zig-out/bin/quic-client --connect 127.0.0.1:4433 --sni test.local --alpn h3 --datagram=true --compatible-vn`

With datagram enabled, the server will echo any DATAGRAM payloads. When `--retry true` is set, the server will issue a QUIC Retry with a stateless token bound to the client address; the client will re-send Initial with the token.

## Docs

- Gap analysis: `docs/GAP.md`
- Design: `docs/DESIGN.md`

## Using from another Zig project

This repo exports a module named `quic`. Consumers can import it via `@import("quic")`.

1. Add dependency (build.zig.zon)

```zig
.dependencies = .{
    // Use a pinned commit tarball
    .quic = .{
        .url = "https://github.com/spyderorg/quic/archive/<commit>.tar.gz",
        .hash = "<sha256>",
    },
    // Or for local development
    // .quic = .{ .path = "../quic" },
};
```

1. Wire the module (build.zig)

```zig
const quic_dep = b.dependency("quic", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("quic", quic_dep.module("quic"));
```

1. Use in code (src/main.zig)

```zig
const std = @import("std");
const quic = @import("quic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var cfg = quic.QuicConfig{
        .alpn = &[_][]const u8{ "h3" },
        .enable_datagram = true,
        // Optional pacing and max datagram size
        .enable_pacing = false,
        .max_datagram_size = 1200,
    };
    const ep = try quic.endpointInit(&alloc, "0.0.0.0:0", &cfg);
    defer quic.endpointDeinit(ep);

    const conn = try quic.connect(ep, "127.0.0.1:4433", "test.local");
    defer _ = quic.closeConnection(conn, 0);

    // Drive IO & timers
    try quic.poll(ep, 10);
}
```

Notes:

- Target Zig 0.14.1 for compatibility (ReleaseSafe recommended for production).
- The module name is `quic`; no additional deps are required.

## Process helpers

- Update GAP after a slice: `zig build update-gap --summary "Finished <slice>"`
- Doc completeness check (CI gate): `zig build doccheck`
- Fuzzers build: `zig build fuzz`
- Benches build: `zig build bench && ./zig-out/bin/quic-bench`

## CI

GitHub Actions matrix builds on ubuntu, windows, macOS. One job pins Zig 0.14.1 for compatibility; another runs on 0.14.1. Doccheck enforces public symbol docs and GAP.md must be bumped when code changes.

## Next

- TLS 1.3 CH/SH/Finished wiring into QUIC handshake (X.25519 + Finished verify; X.509 minimal; allow_insecure).
- Flow control frames: MAX*DATA, MAX_STREAM_DATA, MAX_STREAMS*{BIDI,UNI}, DATA*BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED*{BIDI,UNI}.
- CUBIC toggle and pacing hooks; path validation; spin bit and GREASE.
- More KATs and fuzz corpora (Retry tamper covered by new test).
