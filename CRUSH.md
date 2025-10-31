# CRUSH Guide for QUIC Implementation

This guide helps AI agents effectively work in this Zig QUIC implementation codebase.

## Project Overview

Production-grade QUIC v1/v2 implementation in **Zig 0.15.1** (std-only, with vendored Ed25519).

- **Language:** Zig 0.15.1
- **RFC Compliance:** RFC 9000 (QUIC v1), RFC 9001 (TLS), RFC 9002 (Recovery)
- **Features:** 0-RTT, session resumption, connection migration, 63+ passing tests
- **Platforms:** Linux (epoll), macOS (kqueue), Windows (IOCP stub)
- **Testing:** 76 test files, interop testing with 18 QUIC implementations

## Essential Commands

### Build Commands

```bash
# Debug build (default)
zig build

# Release build (recommended for production)
zig build -Drelease-safe=true

# Build CLI tools (client, server, varint encoder/decoder)
zig build cli

# Build development tools (update-gap, doccheck, interop-runner)
zig build tools

# Build fuzzers
zig build fuzz

# Build benchmarks
zig build bench

# Build transport layer examples
zig build examples
```

### Test Commands

```bash
# Run all tests
zig build test

# Run specific test by filter (substring match)
zig build -Dtest-filter="tls_key_schedule_kat" test

# Run legacy tests (in quic.zig)
zig build -Dlegacy-tests=true test

# Common test filters:
# - "tls_key_schedule_kat" - TLS key derivation tests
# - "timers" - Timer functionality tests
# - "stream_fc" or "streams" - Stream flow control tests
# - "migration_path" or "path_reset" - Connection migration tests
# - "h3_loopback" - HTTP/3 loopback tests
```

### Lint and Documentation Gates

```bash
# Build doccheck tool
zig build tools

# Run documentation completeness check (CI gate)
./zig-out/bin/doccheck

# Update GAP.md after implementing a feature slice
./zig-out/bin/update-gap --summary "Implemented XYZ feature"

# Format all Zig code
zig fmt .
```

### CLI Tools Usage

```bash
# Varint encoder/decoder
./zig-out/bin/quic-varint encode 64        # Output: 40 40
./zig-out/bin/quic-varint decode 7f ff     # Output: 16383
./zig-out/bin/quic-varint decode 80        # Exit 2, stderr: VARINT_UNDERFLOW

# QUIC server (with datagram support, retry, compatible version negotiation)
./zig-out/bin/quic-server --bind 0.0.0.0:4433 \
  --alpn h3 \
  --datagram=true \
  --compatible-vn \
  --retry true \
  --token-expiry-ms 60000

# QUIC client
./zig-out/bin/quic-client --connect 127.0.0.1:4433 \
  --sni test.local \
  --alpn h3 \
  --datagram=true \
  --compatible-vn

# Debug clients (for testing streams and datagrams)
./zig-out/bin/quic-debug-client
./zig-out/bin/quic-debug-dgram-client
```

### Interoperability Testing

```bash
# Quick interop verification
./scripts/interop_test.sh

# Core interop tests
./scripts/interop_verify.sh

# Full interop matrix (tests against 18 implementations)
./scripts/interop_full.sh quick

# Test with specific implementations
make interop-quic-go    # Test with quic-go
make interop-zig        # Test Zig-to-Zig interop

# Docker-based interop testing
make interop-build      # Build Docker image
make interop-basic      # Test against quic-go (~5 min)
make interop-quick      # Test against 3 implementations (~15 min)
make interop-full       # Test against all 17 implementations (~60 min)
```

### Cross-Compilation

```bash
# Quick cross-compile (primary targets)
make cross-compile-quick

# Full cross-compilation (all 11 targets)
make cross-compile

# Release builds for all targets
make cross-compile-release

# Individual target examples
make x86_64-linux-gnu
make aarch64-linux-musl
make x86_64-macos
make aarch64-macos
make x86_64-windows-gnu
make wasm32-wasi
```

### Makefile Targets

```bash
# Full CI pipeline (build, test, fuzz, bench, doccheck)
make ci

# GitHub Actions CI target (includes cross-compilation)
make ci-github

# Clean build artifacts
make clean

# Help (shows all available targets)
make help
```

## Code Organization

### Directory Structure

```
.
├── src/
│   ├── quic/           # Core QUIC implementation
│   │   ├── api.zig     # Public API
│   │   ├── conn.zig    # Connection state machine
│   │   ├── endpoint.zig # UDP socket management and event loop
│   │   ├── packet.zig   # Packet encoding/decoding
│   │   ├── frame.zig    # All 20+ frame types
│   │   ├── recovery.zig # Loss detection and congestion control
│   │   ├── varint.zig   # Variable-length integer encoding
│   │   ├── crypto_quic.zig # AEAD operations
│   │   ├── transport_params.zig # Transport parameters
│   │   ├── transport.zig # High-level transport API
│   │   ├── tls/         # TLS 1.3 implementation
│   │   │   ├── tls13.zig      # TLS handshake
│   │   │   ├── key_schedule.zig # Key derivation
│   │   │   ├── x509.zig       # Certificate parsing
│   │   │   ├── sig.zig        # Signatures (ECDSA, RSA-PSS, Ed25519)
│   │   │   └── asn1.zig       # ASN.1 parsing
│   │   └── io/          # Platform-specific event loops
│   │       ├── loop_epoll.zig  # Linux (epoll)
│   │       ├── loop_kqueue.zig # macOS (kqueue)
│   │       └── loop_iocp.zig   # Windows (IOCP stub)
│   └── h3/             # HTTP/3 minimal shim
│       ├── server.zig  # H3 server
│       └── client.zig  # H3 client
├── cmd/                # CLI binaries
│   ├── quic-client.zig
│   ├── quic-server.zig
│   ├── quic-debug-client.zig
│   ├── quic-debug-dgram-client.zig
│   └── qns-endpoint.zig # QNS interop endpoint
├── tests/              # 76 test files
├── tools/              # Development tools
│   ├── varint_tool.zig
│   ├── update_gap.zig
│   ├── doccheck.zig
│   └── interop_runner.zig
├── examples/           # Example implementations
│   ├── client_transport.zig
│   └── server_transport.zig
├── fuzz/               # Fuzzers
├── bench/              # Benchmarks
├── interop/            # Interoperability testing
├── docs/               # Documentation
│   ├── DESIGN.md
│   ├── GAP.md
│   ├── GAP_ANALYSIS.md
│   ├── TRANSPORT_LAYER.md
│   └── NEXT.md
├── build.zig           # Build configuration
├── Makefile            # Make targets
└── CRUSH.md            # This file
```

### Module System

The project uses Zig's module system with explicit imports configured in `build.zig`:

- `quic_api` - Public API module
- `quic_conn` - Connection module
- `quic_endpoint` - Endpoint module
- `quic_packet` - Packet module
- `quic_frame` - Frame module
- `quic_crypto` - Crypto module
- `quic_tls` - TLS key schedule
- `quic_tls13` - TLS 1.3 handshake
- `quic_varint` - Varint encoding
- `quic_recovery` - Loss recovery
- `quic_transport_params` - Transport parameters
- `quic_logger` - Logging utilities
- `transport` - High-level transport API module
- `h3_server` / `h3_client` - HTTP/3 modules

## Naming Conventions and Style

### File Names
- `snake_case` for all filenames: `key_schedule.zig`, `transport_params.zig`

### Code Style
- **Imports:** `const std = @import("std");` at the top
- **Types:** UpperCamelCase - `Connection`, `Endpoint`, `QuicConfig`
- **Functions:** lowerCamelCase - `processIncomingDatagram`, `deriveKeys`
- **Variables:** lowerCamelCase - `srcCid`, `dstCid`, `allocator`
- **Constants:** lower_snake - `max_udp_payload`, `initial_max_data`
- **Public API types:** Prefix with `Quic*` - `QuicTransport`, `QuicClient`

### Formatting
- Run `zig fmt .` before committing
- One declaration per line
- Align field initializers as seen in existing code
- Use explicit integer widths: `u8`, `u16`, `u32`, `u64`, `i64`
- Use `usize` for indexing and length
- Prefer error unions over optionals where failures are expected

### Error Handling
- Define error sets: `const CryptoError = error{...};`
- Propagate with `try` where possible
- Never print secrets (keys, nonces, tokens)
- Map transport/TLS failures to QUIC error codes (RFC 9000/9001)
- Zeroize retired keys with `std.mem.set`

### Memory Management
- Pass `allocator: *std.mem.Allocator` explicitly
- Use `defer` for cleanup and zeroization
- Avoid hidden allocations in hot paths
- Use saturating counters for packet numbers and byte counts

### Concurrency
- Event loop abstractions in `src/quic/io/*`
- Avoid blocking operations
- Use timers via endpoint/connection helpers
- Single-threaded event loop model

## Testing Approach

### Test Organization
- Unit tests in `tests/` directory (76 files)
- Integration tests use in-memory loopback
- Known Answer Tests (KATs) for crypto operations
- Property-based fuzzing in `fuzz/`

### Test Patterns
```zig
// Unit test example
test "varint encoding" {
    const encoded = try varint.encode(64);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x40, 0x40}, encoded);
}

// Integration test pattern
test "connection handshake" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Setup client and server endpoints
    // ... perform handshake
    // ... assert connection established
}
```

### Test Coverage Areas
- TLS 1.3 key schedule (RFC 8446 test vectors)
- Packet protection (RFC 9001 Appendix A)
- Frame encoding/decoding
- Loss detection and congestion control
- Flow control (connection and stream level)
- Connection migration and path validation
- 0-RTT and session resumption
- PMTUD and DPLPMTUD
- ECN marking and validation
- Key updates
- Version negotiation

## Important Gotchas and Patterns

### 1. Vendored Ed25519
The project uses a vendored Ed25519 implementation from `vendor/ed25519/` instead of the standard library. This provides constant-time, production-grade Ed25519 signatures.

### 2. Platform-Specific Event Loops
The event loop backend is selected at compile time based on the target platform:
- Linux: epoll (`src/quic/io/loop_epoll.zig`)
- macOS: kqueue (`src/quic/io/loop_kqueue.zig`)
- Windows: IOCP stub (`src/quic/io/loop_iocp.zig`)

### 3. Packet Number Encoding
QUIC uses truncated packet numbers on the wire. The receiver must expand them based on the expected range. See `src/quic/packet.zig` for expansion logic.

### 4. Header Protection Side Channels
Header protection mask generation must use constant-time operations to avoid timing side channels. See RFC 9001 §5.4 for security considerations.

### 5. Key Zeroization
Retired cryptographic keys must be explicitly zeroized after use:
```zig
defer std.mem.set(u8, key_buffer[0..], 0);
```

### 6. Connection ID Management
- Each connection has multiple CIDs for migration support
- Endpoint maintains CID → Connection mapping
- Hash-based lookup: `Key{ peer_hash, dcid_hash }`

### 7. Timer Management
Three timer kinds per connection:
- PTO (Probe Timeout) per packet number space (Initial, Handshake, Application)
- PMTUD probe timer for path MTU discovery
- Generic application timers

### 8. Congestion Control Selection
Runtime selection between NewReno and CUBIC:
```zig
cfg.congestion_control = .NewReno; // or .CUBIC
```

### 9. Test Filtering in build.zig
The build system supports substring-based test filtering with special handling for common filters. See `build.zig` lines 301-358 for filter logic.

### 10. Acceptance Testing
The project includes strict acceptance tests that verify:
- Exact CLI output formats
- Exit codes
- Documentation completeness
- Test selection (fails on empty selection)

## Security Considerations

### Cryptographic Operations
- **Constant-time crypto:** All AEAD and signature operations must be constant-time
- **Header protection:** Mask generation uses constant-time sample extraction
- **Key derivation:** HKDF-Extract and HKDF-Expand from RFC 5869
- **Key updates:** Forward secrecy via TLS 1.3 key update mechanism

### Logging and Debugging
- **Never log:** Keys, nonces, token contents, decrypted payloads
- **Safe to log:** Packet types, frame types, connection states, public CIDs
- **Debug mode:** Use `quic_logger` module for conditional logging

### Amplification Attack Prevention
- Address validation before sending >3x bytes received
- Retry packets with stateless reset tokens
- Path validation with PATH_CHALLENGE/RESPONSE

### Stateless Reset
- 128-bit unpredictable stateless reset token
- Last 16 bytes of datagram interpreted as potential reset
- Server generates tokens bound to connection IDs

## Process and Development Workflow

### Slice-Based Development
After implementing each feature slice:
1. Update `docs/GAP.md` with the new implementation status
2. Update `docs/GAP_ANALYSIS.md` if needed
3. Adjust `docs/DESIGN.md` if APIs changed
4. Rebuild: `zig build`
5. Run tests: `zig build test`
6. Run fuzz and bench: `zig build fuzz bench`
7. Fix all failures
8. Update GAP: `./zig-out/bin/update-gap --summary "Implemented feature X"`

### CI/CD Pipeline
GitHub Actions runs on `ubuntu-24.04`, `macos-14`, `windows-2022`:
1. Zig version check (must be 0.15.1)
2. Build (debug and release)
3. Test suite
4. Cross-compilation verification
5. Doccheck gate
6. GAP.md update verification (on PRs)

### Pull Request Requirements
- All tests passing
- `doccheck` passing (all public symbols documented)
- `docs/GAP.md` updated if code changed
- `zig fmt` applied
- No secrets in commit history

## Troubleshooting

### Zig Version Mismatch
**Problem:** Build fails with "Zig version mismatch"
**Solution:** Ensure Zig 0.15.1 is installed: `zig version` should output `0.15.1`

### Empty Test Selection
**Problem:** `zig build -Dtest-filter="xyz" test` exits with no tests run
**Solution:** Check that the filter substring matches actual test names in `tests/` directory

### Varint Underflow
**Expected behavior:** `./zig-out/bin/quic-varint decode 80` exits with code 2 and prints `VARINT_UNDERFLOW` to stderr

### Doccheck Failures
**Problem:** `./zig-out/bin/doccheck` fails with "Missing documentation"
**Solution:** Add doc comments (`///`) to all public functions and types

### Cross-Compilation Errors
**Problem:** Cross-compilation fails for a specific target
**Solution:** Check that the target triple is supported by Zig 0.15.1. Some targets may require additional system libraries.

### Interop Test Failures
**Problem:** Interop tests fail with quic-go or other implementations
**Note:** Some interop failures are expected due to TLS 1.3 handshake incompatibilities with certain implementations. See `Makefile` lines 185-211 for known issues.

### Windows Build Issues
**Problem:** Build fails on Windows
**Solution:**
- Ensure `ws2_32.lib` is available (should be automatic with linkLibC)
- IOCP backend is a stub; full Windows support is partial
- Use PowerShell for acceptance tests: `powershell -File tools/acceptance.ps1`

## Using the Library

### As a Zig Dependency

Add to `build.zig.zon`:
```zig
.dependencies = .{
    .quic = .{
        .url = "https://github.com/spyderorg/quic/archive/<commit>.tar.gz",
        .hash = "<sha256>",
    },
};
```

Wire in `build.zig`:
```zig
const quic_dep = b.dependency("quic", .{
    .target = target,
    .optimize = optimize
});
exe.root_module.addImport("quic", quic_dep.module("quic"));
```

### Low-Level API Example

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

### High-Level Transport API Example

```zig
const transport = @import("quic"); // Using "transport" module

// Server
var quic_transport = try transport.QuicTransport.init(allocator, .{
    .port = 4433,
});
defer quic_transport.deinit();

try quic_transport.listen();
while (true) {
    try quic_transport.poll(10);
    const conn = quic_transport.accept() catch continue;
    // Handle connection...
}

// Client
var client = transport.QuicClient.init(allocator);
defer client.deinit();

try client.connect("127.0.0.1", 4433);
const stream = try client.openStream(true);
defer stream.close();

try stream.writeAll("Hello, QUIC!");
```

See `docs/TRANSPORT_LAYER.md` for complete transport API documentation.

## Canonical Test Filters

These filters can be used with `zig build -Dtest-filter="<value>" test`:

| Name | Filter Substring | Description |
|------|------------------|-------------|
| TLS KAT | `tls_key_schedule_kat` | TLS 1.3 key derivation test vectors |
| Timers | `timers` | Connection and endpoint timer tests |
| Streams | `streams` or `stream_fc` | Stream flow control tests |
| Migration | `migration_path` or `path_reset` | Connection migration scenarios |
| H3 Loopback | `h3_loopback` | HTTP/3 client-server loopback |
| Header Protection | `bench_hp` | Header protection benchmarks |

## Acceptance Tests

The project includes strict acceptance tests in `tools/acceptance.sh` (POSIX) and `tools/acceptance.ps1` (PowerShell) that verify:

1. **Zig version:** Must be 0.15.1
2. **Tool presence:** `quic-varint`, `update-gap`, `doccheck`, `interop-runner`
3. **Varint outputs:** Exact stdout/stderr matching and exit codes
4. **KAT pass:** TLS key schedule test must pass
5. **Doccheck:** Documentation completeness gate
6. **GAP helper:** update-gap tool functionality
7. **CRUSH.md sections:** Required documentation sections present
8. **Canonical filters:** All filters execute and match tests

Run acceptance tests:
```bash
# POSIX (Linux, macOS)
bash tools/acceptance.sh

# Windows
powershell -File tools/acceptance.ps1
```

## Additional Resources

- **RFC 9000:** QUIC Transport Protocol
- **RFC 9001:** Using TLS to Secure QUIC
- **RFC 9002:** QUIC Loss Detection and Congestion Control
- **RFC 8446:** TLS 1.3
- **RFC 5869:** HKDF Key Derivation
- **docs/DESIGN.md:** Architecture and design decisions
- **docs/GAP.md:** Implementation progress tracking
- **docs/NEXT.md:** Development roadmap
- **README.md:** Project overview and quick start

## Nix Flake Support

The project includes Nix flake configuration for reproducible builds:

```bash
# Build package
nix build .#quic

# Debug build
nix build .#quic-debug

# Enter dev shell
nix develop
```

See `docs/FLAKE_USAGE.md` for detailed Nix integration examples.
