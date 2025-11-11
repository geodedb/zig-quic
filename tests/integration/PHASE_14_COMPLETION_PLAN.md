# Phase 14 Completion Plan - Real Endpoint Integration

**Date**: November 10, 2025
**Status**: IN PROGRESS
**Estimated Time**: 5.5-7.5 hours

## Overview

Phase 14 was completed as "architectural validation" but deferred the actual implementation (line 1062 of IMPLEMENTATION_SUMMARY.md: "Replace EndpointWrapper with real Endpoint in helpers"). Now that Phases 15-20 have implemented all the required TLS infrastructure, we can complete Phase 14 as originally intended.

## What Exists and Works

### Production Endpoint (src/quic/endpoint.zig)
- **Line 207**: `initWithTransport()` - Creates endpoint with custom transport
  ```zig
  pub fn initWithTransport(
      alloc: *std.mem.Allocator,
      transport: transport_mod.Transport,
      cfgp: *const cfg.QuicConfig,
  ) !Endpoint
  ```
- **Line 416**: `connectClient()` - Establishes client connection to server
- **Fields**: `.conns`, `.accepted`, `.role`, `.transport`, `.cfg`

### Production Connection (src/quic/conn.zig)
- **Line 461**: `Connection` struct with TLS state
- **Line 516-517**: Handshake status fields:
  - `handshake_done_sent: bool` (server completion)
  - `handshake_done_seen: bool` (client completion)
- **Line 470**: `tls_context: ?*tls13.Context` - TLS state machine
- **Line 486-497**: Keys (hs_client/server, app_rx/tx_keys)

### Production Config (src/quic/config.zig)
- **Line 12**: `QuicConfig` struct
- **Required field**: `alpn: []const []const u8` (line 16)
- **Optional fields**: allow_insecure, cert_path, key_path, etc.

### TLS Integration (Phases 16-20)
- ✅ **Certificate helpers**: `tests/integration/certificate_helpers.zig` (7/7 tests)
- ✅ **Key derivation**: Phase 19a validated (7/7 tests)
- ✅ **CRYPTO frames**: Phase 19b validated (9/9 tests)
- ✅ **Packet protection**: Phase 19c validated (8/8 tests)
- ✅ **Handshake integration**: Phase 20 validated (20/20 tests)

## Implementation Tasks

### Task 1: Replace EndpointWrapper with Real Endpoint (2-3 hours)

**File**: `tests/integration/endpoint_loopback_helpers.zig`

**Current State** (lines 295-323):
```zig
pub const EndpointWrapper = struct {
    adapter: *adapter_mod.LoopbackTransportAdapter,
    transport: adapter_mod.Transport,
    role: EndpointRole,
    allocator: std.mem.Allocator,
    // ...stub implementation...
};
```

**Target State**:
```zig
// Import real types (uncomment lines 280-282)
const endpoint_mod = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const config_mod = @import("quic_config");

pub const EndpointWrapper = struct {
    // Real endpoint instance
    endpoint: *endpoint_mod.Endpoint,
    // Adapter for cleanup
    adapter: *adapter_mod.LoopbackTransportAdapter,
    role: EndpointRole,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        adapter: *adapter_mod.LoopbackTransportAdapter,
        role: EndpointRole,
    ) !EndpointWrapper {
        // Create minimal QuicConfig
        const quic_config = config_mod.QuicConfig{
            .alpn = &[_][]const u8{"test"},
            .allow_insecure = true,  // For testing only
        };

        // Create real endpoint with loopback transport
        const ep = try allocator.create(endpoint_mod.Endpoint);
        ep.* = try endpoint_mod.Endpoint.initWithTransport(
            &allocator,
            adapter.asTransport(),
            &quic_config,
        );

        return EndpointWrapper{
            .endpoint = ep,
            .adapter = adapter,
            .role = role,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *EndpointWrapper) void {
        self.endpoint.deinit();
        self.allocator.destroy(self.endpoint);
    }
};
```

**Changes Required**:
1. Uncomment production imports (lines 280-282)
2. Add `endpoint: *endpoint_mod.Endpoint` field
3. Update `init()` to create real endpoint with `initWithTransport()`
4. Update `deinit()` to clean up endpoint
5. Update `getTransport()` to return `&self.endpoint.transport`

### Task 2: Implement ConnectionPair.connect() (2-3 hours)

**File**: `tests/integration/connection_pair.zig`

**Current State** (line 132):
```zig
pub fn connect(self: *ConnectionPair) !void {
    return error.NotImplementedYet;  // ← BLOCKING 84 TESTS!
}
```

**Target Implementation**:
```zig
pub fn connect(self: *ConnectionPair) !void {
    // 1. Get server endpoint's bound address
    const server_addr = try self.server.endpoint.getBoundAddress();

    // 2. Client initiates connection
    const client_conn = try self.client.endpoint.connectClient(server_addr);

    // 3. Exchange Initial packets (triggers handshake)
    try self.exchangePackets();

    // 4. Wait for server to accept connection
    const max_wait_ms = 1000;
    var waited_ms: u64 = 0;
    while (self.server_conn == null and waited_ms < max_wait_ms) : (waited_ms += 10) {
        try self.exchangePackets();

        // Check if server has accepted
        if (self.server.endpoint.accepted.items.len > 0) {
            self.server_conn = self.server.endpoint.accepted.items[0];
            break;
        }

        std.time.sleep(10 * std.time.ns_per_ms);
    }

    if (self.server_conn == null) {
        return error.ServerConnectionTimeout;
    }

    self.client_conn = client_conn;
}
```

**Changes Required**:
1. Replace `error.NotImplementedYet` with real implementation
2. Call `endpoint.connectClient()` on client
3. Pump packets through loopback via `exchangePackets()`
4. Wait for server to create connection (check `.accepted` list)
5. Store both connections

### Task 3: Implement ConnectionPair.exchangePackets() (1 hour)

**Current State** (lines 136-151): Stub with placeholders

**Target Implementation**:
```zig
pub fn exchangePackets(self: *ConnectionPair) !void {
    var buf: [4096]u8 = undefined;

    // Client → Server
    while (try self.transport.recvAtA(&buf)) |len| {
        // Deliver to server endpoint
        try self.server.endpoint.processIncomingDatagram(buf[0..len]);
    }

    // Server → Client
    while (try self.transport.recvAtB(&buf)) |len| {
        // Deliver to client endpoint
        try self.client.endpoint.processIncomingDatagram(buf[0..len]);
    }
}
```

**Changes Required**:
1. Replace placeholder with real packet delivery
2. Use loopback's `recvAtA()` and `recvAtB()`
3. Call endpoint's incoming packet handler

### Task 4: Implement ConnectionPair.waitForHandshake() (1 hour)

**New Method** (add to ConnectionPair):
```zig
pub fn waitForHandshake(self: *ConnectionPair, timeout_ms: u64) !void {
    const start_time = std.time.milliTimestamp();

    while (true) {
        // Check if handshake complete on both sides
        if (self.client_conn) |client_conn| {
            if (self.server_conn) |server_conn| {
                // Client checks handshake_done_seen
                // Server checks handshake_done_sent
                const client_done = client_conn.handshake_done_seen;
                const server_done = server_conn.handshake_done_sent;

                if (client_done and server_done) {
                    return; // Handshake complete!
                }
            }
        }

        // Exchange packets
        try self.exchangePackets();

        // Check timeout
        const elapsed = std.time.milliTimestamp() - start_time;
        if (elapsed > timeout_ms) {
            return error.HandshakeTimeout;
        }

        // Small delay
        std.time.sleep(10 * std.time.ns_per_ms);
    }
}
```

**Changes Required**:
1. Add new `waitForHandshake()` method
2. Poll both connections for handshake completion
3. Continue exchanging packets until done
4. Add timeout handling

### Task 5: Configure build.zig (30 minutes)

Add integration test modules similar to existing patterns:

```zig
// Integration test modules
const integration_harness = mkModule(b, "tests/integration/harness.zig");
integration_harness.addImport("quic_endpoint", quic_endpoint_mod);
integration_harness.addImport("quic_conn", quic_conn_mod);
integration_harness.addImport("quic_config", quic_config_mod);

const integration_helpers = mkModule(b, "tests/integration/endpoint_loopback_helpers.zig");
integration_helpers.addImport("quic_endpoint", quic_endpoint_mod);
integration_helpers.addImport("quic_conn", quic_conn_mod);
integration_helpers.addImport("quic_config", quic_config_mod);
integration_helpers.addImport("loopback", loopback_mod);
integration_helpers.addImport("loopback_transport_adapter", adapter_mod);

const integration_connection_pair = mkModule(b, "tests/integration/connection_pair.zig");
integration_connection_pair.addImport("harness", integration_harness);
integration_connection_pair.addImport("loopback", loopback_mod);

// Test executable for rfc9000_section7.zig
const test_rfc9000_section7 = addTst(b, "tests/integration/rfc9000_section7.zig", target, optimize);
test_rfc9000_section7.root_module.addImport("scenarios", scenarios_mod);
test_rfc9000_section7.root_module.addImport("connection_pair", integration_connection_pair);
test_rfc9000_section7.root_module.addImport("harness", integration_harness);
const run_test_rfc9000_section7 = b.addRunArtifact(test_rfc9000_section7);
test_step.dependOn(&run_test_rfc9000_section7.step);
```

### Task 6: Enable First Integration Test (1 hour)

**File**: `tests/integration/rfc9000_section7.zig`

**Current** (line 38-43):
```zig
test "RFC 9000 §7.1 - Client sends Initial packet" {
    // SKIP: Requires actual packet encoding and endpoint integration
    return error.SkipZigTest;
}
```

**Target**:
```zig
test "RFC 9000 §7.1 - Client sends Initial packet" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Client Initial packet")
        .withCapture()
        .withAlpn(&[_][]const u8{"test"});

    var pair = try scenario.createPair();
    try pair.connect();

    // Verify client sent Initial packet
    const capture = pair.client.capture orelse return error.NoCaptureEnabled;
    try std.testing.expect(capture.packets_sent > 0);
}
```

## Success Criteria

Phase 14 complete when:
1. ✅ EndpointWrapper uses real Endpoint via `initWithTransport()`
2. ✅ ConnectionPair.connect() establishes real connection
3. ✅ ConnectionPair.exchangePackets() delivers packets via loopback
4. ✅ ConnectionPair.waitForHandshake() polls until complete
5. ✅ First integration test passes (no skip)
6. ✅ Build system configured with module imports
7. ✅ Test pass rate maintained (99.7%)
8. ✅ Documentation updated

## Risks and Mitigation

**Risk 1**: TLS handshake may not complete over loopback
- **Mitigation**: Phases 19-20 validated all components work
- **Fallback**: Debug with packet capture

**Risk 2**: Build configuration may need adjustments
- **Mitigation**: Follow existing test patterns (line 779 of build.zig)
- **Reference**: `test_endpoint_handshake_integration` configuration

**Risk 3**: Timing issues with handshake polling
- **Mitigation**: Add generous timeout (5 seconds)
- **Debug**: Print handshake state at each poll

## Timeline

**Hour 0-2**: Replace EndpointWrapper (Task 1)
**Hour 2-4**: Implement ConnectionPair methods (Tasks 2-4)
**Hour 4-5**: Configure build system (Task 5)
**Hour 5-6**: Enable first test and debug (Task 6)
**Hour 6-7**: Update documentation, validate all works

**Total**: 6-7 hours estimated

## Next Steps After Completion

Once Phase 14 is truly complete:
- **Phase 14a**: Enable batch 1 of Tier 1 tests (10-15 tests, 1-2 hours)
- **Phase 14b**: Enable batch 2 of Tier 1 tests (15-20 tests, 2-3 hours)
- **Phase 14c**: Enable remaining Tier 1 tests (30-40 tests, 3-4 hours)

**Total to enable all 84 Tier 1 tests**: 6-9 hours additional after Phase 14 completion

## References

- **Endpoint API**: src/quic/endpoint.zig (line 207: initWithTransport)
- **Connection API**: src/quic/conn.zig (line 516-517: handshake status)
- **Phase 14 Deferred Work**: IMPLEMENTATION_SUMMARY.md (line 1062)
- **TLS Infrastructure**: Phases 16-20 (136 tests passing, ~1,200 lines)
- **Build Pattern**: build.zig (line 779: test_endpoint_handshake_integration)
