# QUIC Endpoint Integration Guide

## Overview

This guide explains how to integrate the QUIC integration test framework with the actual endpoint implementation. It addresses the architectural considerations, integration strategies, and provides practical examples.

## Architecture

### Test Framework Design

The integration test framework (Phases 1-5) is designed around **loopback transport** for deterministic, in-memory testing:

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Client    │────────▶│   Loopback   │────────▶│   Server    │
│  Endpoint   │         │  Transport   │         │  Endpoint   │
│   (Test)    │◀────────│  (In-Memory) │◀────────│   (Test)    │
└─────────────┘         └──────────────┘         └─────────────┘
```

**Benefits**:
- Deterministic timing (mock time control)
- Packet loss/corruption/reordering injection
- No OS-level dependencies (no UDP sockets)
- Fast execution (<5ms per test)
- Reproducible failures (seeded RNG)

### Current Endpoint Implementation

The production QUIC endpoint (`src/quic/endpoint.zig`) uses **real UDP sockets**:

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Client    │────────▶│   UDP Socket │────────▶│   Server    │
│  Endpoint   │         │  (Real OS)   │         │  Endpoint   │
│ (Production)│◀────────│              │◀────────│(Production) │
└─────────────┘         └──────────────┘         └─────────────┘
```

**Key APIs**:
- `Endpoint.init(allocator, bind_addr, config)` - Bind UDP socket
- `Endpoint.connectClient(hostport)` - Create client connection
- `Endpoint.poll(timeout_ms)` - Process events (recv/send/timers)
- `Endpoint.sendTo(peer, data)` - Send UDP packet
- `Endpoint.recvFrom(buf)` - Receive UDP packet

## Integration Approaches

### Approach 1: Real UDP Testing (Current - Phase 6)

**Use real UDP sockets on localhost for integration testing.**

```zig
test "Real endpoint: Basic handshake" {
    const allocator = std.testing.allocator;

    // Create server endpoint on localhost
    var server_ep = try Endpoint.init(allocator, "127.0.0.1:0", &server_config);
    defer server_ep.deinit();

    // Create client endpoint
    var client_ep = try Endpoint.init(allocator, "127.0.0.1:0", &client_config);
    defer client_ep.deinit();

    // Connect client to server
    const conn = try client_ep.connectClient("127.0.0.1:server_port");

    // Poll both endpoints until handshake completes
    while (!conn.isHandshakeComplete()) {
        try server_ep.poll(10);
        try client_ep.poll(10);
    }

    try std.testing.expect(conn.isHandshakeComplete());
}
```

**Pros**:
- Works with current endpoint implementation (no modifications)
- Tests real packet processing, OS interactions
- Can use real network conditions (via `tc` on Linux)

**Cons**:
- Slower than loopback (OS overhead)
- Non-deterministic timing (OS scheduler)
- Requires free ports (potential test flakiness)
- Harder to inject specific faults

**Status**: ✅ Implemented in Phase 6 (see `real_endpoint.zig`)

### Approach 2: Transport Abstraction (Future - Phase 7+)

**Refactor endpoint to support pluggable transports.**

```zig
// Abstract transport interface
pub const Transport = struct {
    sendFn: *const fn (ctx: *anyopaque, peer: SockAddr, data: []const u8) anyerror!usize,
    recvFn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!RecvResult,
    context: *anyopaque,
};

// Endpoint supports both real UDP and loopback
pub const Endpoint = struct {
    transport: Transport,  // Pluggable transport
    // ... rest of endpoint fields ...

    pub fn initWithTransport(allocator, transport: Transport, config) !Endpoint {
        // Use provided transport instead of creating UDP socket
    }
};

// Test with loopback transport
test "Loopback endpoint: Packet loss recovery" {
    var loopback_transport = try LoopbackTransport.init(allocator, .{
        .loss_rate = 0.1,  // 10% packet loss
    });
    defer loopback_transport.deinit();

    var server_ep = try Endpoint.initWithTransport(
        allocator,
        loopback_transport.asTransport(),
        &server_config
    );
    // ... test with deterministic packet loss ...
}
```

**Pros**:
- Best of both worlds: deterministic loopback + real UDP
- All 458 skip tests can be enabled
- Fault injection works with real endpoint
- Mock time control works

**Cons**:
- Requires endpoint refactoring (significant work)
- Changes production code structure
- Need to ensure transport abstraction doesn't add overhead

**Status**: 📝 Planned for future phases (requires RFC)

### Approach 3: Hybrid Strategy (Recommended)

**Use both approaches for comprehensive testing:**

1. **Phase 6 (Current)**: Real UDP tests for basic functionality
   - Connection establishment
   - Basic data transfer
   - TLS handshake
   - Error handling

2. **Phase 7+**: Loopback integration after refactoring
   - All 458 skip tests
   - RFC compliance verification
   - Fault injection scenarios
   - Performance testing

## Phase 6 Implementation

Phase 6 demonstrates real endpoint integration with UDP-based tests.

### Test File Structure

```
tests/integration/
├── real_endpoint.zig         # Real UDP-based integration tests (Phase 6)
├── harness.zig               # Test infrastructure (loopback-based)
├── loopback.zig              # In-memory transport
├── connection_pair.zig       # Loopback fixture
└── rfc9000_section7.zig      # Skip tests (awaiting loopback integration)
```

### Real Endpoint Tests (Phase 6)

See `real_endpoint.zig` for examples:
- Basic connection establishment
- Handshake completion
- Simple data transfer
- Connection closure
- Error scenarios

### Running Real Endpoint Tests

```bash
# Run real endpoint integration tests
zig test tests/integration/real_endpoint.zig --test-filter "real-endpoint"

# Run with verbose output
zig test tests/integration/real_endpoint.zig -- --summary all

# Run specific test
zig test tests/integration/real_endpoint.zig --test-filter "handshake"
```

## API Reference

### Production Endpoint API

Key types and functions from `src/quic/endpoint.zig`:

```zig
// Endpoint initialization
pub fn init(
    allocator: *std.mem.Allocator,
    bind_addr: []const u8,  // e.g., "127.0.0.1:0"
    config: *const QuicConfig
) !Endpoint

// Client connection
pub fn connectClient(
    self: *Endpoint,
    hostport: []const u8  // e.g., "127.0.0.1:4433"
) !*Connection

// Event processing
pub fn poll(
    self: *Endpoint,
    timeout_ms: i32  // -1 for blocking, 0 for non-blocking
) !void

// Packet send/recv (low-level)
pub fn sendTo(
    self: *Endpoint,
    peer: SockAddr,
    data: []const u8
) !usize

pub fn recvFrom(
    self: *Endpoint,
    buf: []u8
) !struct { n: usize, peer: SockAddr }

// Connection management
pub fn deinit(self: *Endpoint) void
```

### Connection API

Key types from `src/quic/conn.zig`:

```zig
pub const Connection = struct {
    // State queries
    pub fn isHandshakeComplete(self: *const Connection) bool
    pub fn isClosed(self: *const Connection) bool

    // Stream operations
    pub fn streamSend(
        self: *Connection,
        stream_id: u64,
        data: []const u8,
        fin: bool
    ) !void

    pub fn streamRecv(
        self: *Connection,
        stream_id: u64,
        buf: []u8
    ) !usize
};
```

### Config Structure

From `src/quic/config.zig`:

```zig
pub const QuicConfig = struct {
    // TLS credentials
    cert_path: []const u8 = "",
    key_path: []const u8 = "",
    ca_path: []const u8 = "",

    // Protocol parameters
    max_idle_timeout_ms: u64 = 30000,
    initial_max_data: u64 = 1048576,  // 1MB
    initial_max_stream_data_bidi_local: u64 = 262144,  // 256KB
    initial_max_stream_data_bidi_remote: u64 = 262144,
    initial_max_stream_data_uni: u64 = 262144,
    max_concurrent_bidi_streams: u64 = 100,
    max_concurrent_uni_streams: u64 = 100,

    // Connection ID
    connection_id_length: u8 = 8,

    // Loss recovery
    max_ack_delay_ms: u64 = 25,
    ack_delay_exponent: u8 = 3,

    // Flow control
    disable_active_migration: bool = false,

    // Testing
    allow_insecure_tls: bool = false,
};
```

## Integration Checklist

### Phase 6 (Real UDP Integration) - Current

- [x] Document endpoint API
- [x] Create real endpoint test file
- [x] Implement basic connection tests
- [x] Document integration approach
- [x] Update IMPLEMENTATION_SUMMARY.md

### Phase 7+ (Transport Abstraction) - Future

- [ ] Design transport interface
- [ ] Refactor endpoint for pluggable transport
- [ ] Implement loopback transport adapter
- [ ] Enable skip tests with loopback
- [ ] Verify all 458 tests pass
- [ ] Benchmark transport abstraction overhead

## Test Coverage Status

### Real Endpoint Tests (Phase 6) - Enabled

✅ Basic connection establishment (3 tests)
✅ Handshake completion verification (2 tests)
✅ Simple data transfer (2 tests)
✅ Connection lifecycle (2 tests)
✅ Error scenarios (1 test)

**Total: 10 real endpoint integration tests**

### Loopback Tests (Phase 7+) - Awaiting Transport Refactoring

📝 RFC 9000 §7: Connection establishment (26 tests)
📝 RFC 9002: Loss recovery (26 tests)
📝 RFC 9000 Packets: Packet processing (32 tests)
📝 RFC 9000 §8: Address validation (30 tests)
📝 Connection migration (46 tests)
📝 Flow control (51 tests)
📝 Key updates (52 tests)
📝 0-RTT and resumption (62 tests)
📝 Interoperability (40 tests)
📝 Stress testing (37 tests)
📝 Fault injection (56 tests)

**Total: 458 tests awaiting loopback integration**

## Troubleshooting

### Port Already in Use

**Problem**: `AddressAlreadyInUse` error when running tests

**Solution**: Tests use port 0 to let OS assign free ports. If you specify ports manually, ensure they're free:

```bash
# Check if port is in use
lsof -i :4433

# Use port 0 for automatic assignment
var ep = try Endpoint.init(allocator, "127.0.0.1:0", &config);
```

### Handshake Timeout

**Problem**: Handshake doesn't complete within timeout

**Solution**: Ensure both endpoints are polling:

```zig
// Bad: Only polling one endpoint
while (!conn.isHandshakeComplete()) {
    try client_ep.poll(10);  // Server not polling!
}

// Good: Poll both endpoints
const max_iterations = 1000;
var i: usize = 0;
while (i < max_iterations and !conn.isHandshakeComplete()) : (i += 1) {
    try server_ep.poll(1);
    try client_ep.poll(1);
}
```

### TLS Certificate Errors

**Problem**: TLS handshake fails with certificate validation errors

**Solution**: Use test certificates or disable validation for testing:

```zig
var config = QuicConfig{
    .allow_insecure_tls = true,  // For testing only!
    // ... other config ...
};
```

For production-like testing, generate test certificates:

```bash
# Generate self-signed certificate (see tls_helpers.zig)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Future Roadmap

### Phase 7: Transport Abstraction Design ✅ COMPLETED
- ✅ RFC for transport interface design (TRANSPORT_ABSTRACTION_RFC.md)
- ✅ Performance impact analysis
- ✅ Transport interface implementation (transport.zig)
- ✅ Loopback transport adapter

### Phase 8: Endpoint Integration Planning ✅ COMPLETED
- ✅ Comprehensive integration plan (ENDPOINT_TRANSPORT_INTEGRATION_PLAN.md)
- ✅ Three-phase migration strategy (8a: additive, 8b: parallel, 8c: clean)
- ✅ Risk analysis with mitigation strategies
- ✅ Timeline estimation (43 hours, ~1-2 weeks)
- ✅ Complete implementation roadmap with code examples

**Next Step**: Execute the integration plan from ENDPOINT_TRANSPORT_INTEGRATION_PLAN.md when resources are available for the 1-2 week dedicated sprint.

### Phase 9+: Endpoint Integration Execution (PLANNED)
- 📝 Execute Phase 8a: Add transport field to Endpoint (non-breaking)
- 📝 Execute Phase 8b: Implement UdpTransport adapter
- 📝 Execute Phase 8c: Remove sock_fd field (clean migration)
- 📝 Enable all 474 skip tests with loopback transport
- 📝 RFC compliance verification
- 📝 Performance benchmarking

**Reference**: See `ENDPOINT_TRANSPORT_INTEGRATION_PLAN.md` for the complete 800+ line implementation roadmap covering all integration steps, testing strategies, and rollback procedures.

### Phase 10: CI/CD Integration
- 📝 Automated test execution
- 📝 Coverage reporting
- 📝 Performance regression detection

## Contributing

When adding new integration tests:

1. **Real endpoint tests** (UDP-based):
   - Add to `real_endpoint.zig`
   - Use real sockets on localhost
   - Keep tests simple and focused
   - Handle port allocation gracefully

2. **Loopback tests** (future):
   - Add to RFC-specific test files
   - Use skip tests with detailed comments
   - Document RFC section references
   - Will be enabled after transport refactoring

## References

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html): QUIC Transport Protocol
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html): QUIC TLS
- [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html): QUIC Loss Detection
- `src/quic/endpoint.zig`: Production endpoint implementation
- `tests/integration/harness.zig`: Test infrastructure
- `tests/integration/loopback.zig`: Loopback transport implementation
- `IMPLEMENTATION_SUMMARY.md`: Test framework implementation status
