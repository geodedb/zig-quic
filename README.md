# QUIC

Zig QUIC v1/v2 implementation (Zig 0.15.1+). **Beta** transport with comprehensive feature support. Requires OpenSSL for TLS 1.3 cryptographic operations at link time.

## 🎆 Implementation Highlights

- **Full QUIC v1 & v2 support** with RFC 9000/9001/9002 compliance
- **0-RTT early data** transmission and reception
- **Session resumption** with PSK (Pre-Shared Keys)
- **Connection migration** with PATH_CHALLENGE/RESPONSE
- **Preferred address** handling for server migration
- **Comprehensive test suite** passing
- **Interoperability tested** against 18 QUIC implementations

## Status

| Aspect | Info |
|--------|------|
| API Stability | Beta |
| Zig Version | 0.15.1+ |
| Platforms | Linux, macOS, Windows |

## Core Features

- ✅ **Transport**: All frame types, connection ID management, path validation
- ✅ **Crypto**: AES-128-GCM, ChaCha20-Poly1305, header protection
- ✅ **TLS 1.3**: Full integration with key derivation, PSK, 0-RTT
- ✅ **Signatures**: ECDSA (P-256/P-384), RSA-PSS, Ed25519 (via external TLS dependency)
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
- Official run-profile replay: `./scripts/interop_runner_replay.sh --run-url "https://interop.seemann.io/?run=2026-02-16T09:04" --client zig,quic-go --server zig,quic-go`

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

- Gap analysis: `docs/GAP_ANALYSIS.md`
- Performance targets and benchmark gates: `docs/PERFORMANCE_TARGETS.md`
- Design: `docs/DESIGN.md`

## Using from another Zig project

This repo exports a module named `quic`. Consumers can import it via `@import("quic")`.

1. Add dependency (build.zig.zon)

```zig
.dependencies = .{
    // Use a pinned commit tarball
    .quic = .{
        .url = "https://gitlab.com/devnw/zig/quic/-/archive/<commit>/quic-<commit>.tar.gz",
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

## High-Level Transport API

For ease of use, this library includes a high-level transport layer that provides a simple, ergonomic API for building QUIC applications without dealing with low-level packet handling.

### Features

- **Secure TLS Defaults**: Explicit certificates required; optional self-signed generation for local testing
- **Connection Pooling**: Manages multiple connections efficiently
- **Stream Management**: Easy-to-use stream API with read/write helpers
- **Client & Server**: Full support for both client and server sides

### Quick Example

Using the transport module from a Zig project:

```zig
// Add to build.zig.zon dependencies
.quic = .{
    .url = "https://gitlab.com/devnw/zig/quic/-/archive/<commit>/quic-<commit>.tar.gz",
    .hash = "<sha256>",
},

// Wire the transport module in build.zig
const quic_dep = b.dependency("quic", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("quic", quic_dep.module("transport"));

// Use in code
const transport = @import("quic");

// Server example
var quic_transport = try transport.QuicTransport.init(allocator, .{
    .port = 4433,
    .cert_path = "certs/server.crt",
    .key_path = "certs/server.key",
});
defer quic_transport.deinit();

try quic_transport.listen();
while (true) {
    try quic_transport.poll(10);
    const conn = quic_transport.accept() catch continue;
    // Handle connection...
}

// Client example
var client = transport.QuicClient.init(allocator);
defer client.deinit();

try client.connectEx("127.0.0.1", 4433, "certs/ca.crt", null, null);
const stream = try client.openStream(true);
defer stream.close();

try stream.writeAll("Hello, QUIC!");
```

Generate certificates with OpenSSL (or run `./create_test_certs.sh` for local testing) and
ensure `cert_path`, `key_path`, and `ca` point to the correct files.

### Building Examples

Build and run the transport layer examples:

```bash
# Build examples
zig build examples

# Run server
# (Generate `certs/server.crt` and `certs/server.key` beforehand.)
./zig-out/bin/server-transport

# Run client (in another terminal)
./zig-out/bin/client-transport 127.0.0.1 4433 certs/ca.crt
# Or, for local testing only:
# ./zig-out/bin/client-transport 127.0.0.1 4433 --insecure
```

See [docs/TRANSPORT_LAYER.md](docs/TRANSPORT_LAYER.md) for complete API documentation and [docs/GEODE_TRANSPORT_MIGRATION.md](docs/GEODE_TRANSPORT_MIGRATION.md) for migration from geode/bootstrap transport shims.

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

GitLab CI runs Zig build/test components, cross-language e2e interop smoke tests, security scans, SBOM generation/scanning, and semantic release automation. Quality and security tracking live in `docs/GAP_ANALYSIS.md` and `docs/QUALITY_GAP_ANALYSIS.md`.

## Implementation Details

### Code Architecture
- [`src/quic/conn.zig`](src/quic/conn.zig): Connection state machine with full packet processing
- [`src/quic/endpoint.zig`](src/quic/endpoint.zig): UDP socket management and event loop
- [`src/quic/frame.zig`](src/quic/frame.zig): All 20+ frame types encode/decode
- TLS 1.3: Provided by external [`tls`](https://gitlab.com/devnw/zig/tls) dependency (see `build.zig.zon`)
- [`src/quic/recovery.zig`](src/quic/recovery.zig): Loss detection and congestion control
- [`src/h3/`](src/h3/): Basic HTTP/3 with static QPACK

### Platform Support
- **Linux**: Full implementation with epoll, ECN, PMTUD
- **macOS**: Full implementation with kqueue  
- **Windows**: Basic support (IOCP stub)

## Next Steps

See the [docs/](docs/) directory for the development roadmap including:
- Interoperability validation with all implementations
- Performance optimizations and benchmarking
- Production readiness enhancements
- Advanced features (multipath, QUIC-LB)

## License

Apache-2.0 License - see [LICENSE](LICENSE) for details.
