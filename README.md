# QUIC

Zig std-only QUIC v1/v2 implementation (Zig 0.15.1/0.14.x). **Production-grade** transport with comprehensive feature support and 63 tests passing.

## 🎆 Implementation Highlights

- **Full QUIC v1 & v2 support** with RFC 9000/9001/9002 compliance
- **0-RTT early data** transmission and reception
- **Session resumption** with PSK (Pre-Shared Keys)
- **Connection migration** with PATH_CHALLENGE/RESPONSE
- **Preferred address** handling for server migration
- **63 comprehensive tests** passing
- **Interoperability tested** against 18 QUIC implementations

## Core Features

- ✅ **Transport**: All frame types, connection ID management, path validation
- ✅ **Crypto**: AES-128-GCM, ChaCha20-Poly1305, header protection
- ✅ **TLS 1.3**: Full integration with key derivation, PSK, 0-RTT
- ✅ **Signatures**: ECDSA (P-256/P-384), RSA-PSS, Ed25519 (vendored from vendor/ed25519/)
- ✅ **Recovery**: Loss detection, PTO, congestion control (NewReno/CUBIC)
- ✅ **Flow Control**: Connection and stream-level with dynamic limits
- ✅ **Migration**: NAT rebinding, path validation, preferred address
- ✅ **Version Negotiation**: QUIC v1 and v2, compatible VN
- ✅ **Streams**: Multi-stream support with proper lifecycle management

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

## Interoperability Testing

Test against other QUIC implementations:

- Quick verification: `./scripts/interop_test.sh`
- Core tests: `./scripts/interop_verify.sh`
- Full matrix: `./scripts/interop_full.sh quick`

See [examples/interop/README.md](examples/interop/README.md) for detailed interop testing documentation.

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

- Target Zig 0.15.1 for compatibility (ReleaseSafe recommended for production).
- The module name is `quic`; no additional deps are required.

## Process helpers

- Update GAP after a slice: `zig build tools && ./zig-out/bin/update-gap --summary "Finished <slice>"`
- Doc completeness check (CI gate): `zig build tools && ./zig-out/bin/doccheck`
- Fuzzers build: `zig build fuzz`
- Benches build: `zig build bench && ./zig-out/bin/quic-bench [rtt_ns] [bdp_packets] [loss_every]`

### CC bench examples

- Default: `./zig-out/bin/quic-bench`
- Single scenario: RTT=200us, BDP=100 packets, no loss: `./zig-out/bin/quic-bench 200000 100 0`
- Grid of scenarios: `./zig-out/bin/quic-bench --grid`
- CSV output (single): `./zig-out/bin/quic-bench 200000 100 0 --csv`
- CSV + grid: `./zig-out/bin/quic-bench --grid --csv` (prints header and rows)
- RTT=1ms, BDP=200 packets, drop every 50th pkt: `./zig-out/bin/quic-bench 1000000 200 50`

## CI

GitHub Actions matrix builds on ubuntu, windows, macOS. One job pins Zig 0.15.1 for compatibility; another runs on 0.15.1. Doccheck enforces public symbol docs and GAP.md must be bumped when code changes.

## Implementation Details

### Code Architecture
- [`src/quic/conn.zig`](src/quic/conn.zig): Connection state machine with full packet processing
- [`src/quic/endpoint.zig`](src/quic/endpoint.zig): UDP socket management and event loop
- [`src/quic/frame.zig`](src/quic/frame.zig): All 20+ frame types encode/decode
- [`src/quic/tls/tls13.zig`](src/quic/tls/tls13.zig): Complete TLS 1.3 handshake
- [`src/quic/recovery.zig`](src/quic/recovery.zig): Loss detection and congestion control
- [`src/h3/`](src/h3/): Basic HTTP/3 with static QPACK

### Platform Support
- **Linux**: Full implementation with epoll, ECN, PMTUD
- **macOS**: Full implementation with kqueue  
- **Windows**: Basic support (IOCP stub)

## Next Steps

See [docs/NEXT.md](docs/NEXT.md) for the development roadmap including:
- Interoperability validation with all implementations
- Performance optimizations and benchmarking
- Production readiness enhancements
- Advanced features (multipath, QUIC-LB)
