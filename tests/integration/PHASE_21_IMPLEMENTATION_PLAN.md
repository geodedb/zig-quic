# Phase 21: Enable Tier 1 Tests - Implementation Plan

**Date**: November 10, 2025
**Status**: IN PROGRESS
**Revised Estimate**: 4-6 hours (down from 11-16 hours original estimate)

## Executive Summary

Phase 21 aims to enable 84 Tier 1 skip tests by replacing stub types in the integration test framework with real Endpoint/Connection implementations. Initial strategic analysis (see IMPLEMENTATION_SUMMARY.md lines 2826-2990) estimated 11-16 hours assuming end-to-end implementation from scratch.

**CRITICAL DISCOVERY**: Comprehensive codebase survey revealed that **all handshake infrastructure already exists** (1,117+ lines in `src/quic/endpoint/handshake_integration.zig`, 136 handshake tests passing). The actual gap is much smaller - we just need to wire the test framework to use production types.

## What Already Exists

### 1. Complete Handshake Implementation (1,117 lines)
- `src/quic/endpoint/handshake_integration.zig` - Full TLS handshake integration
- TLS callbacks (`onSecretAvailable`, `onHandshakeComplete`, `onHandshakeMetadata`)
- Key installation (Handshake and Application encryption levels)
- Transport parameters extraction and validation
- CRYPTO frame reassembly via CryptoBuffer
- Packet protection integration

### 2. Integration Test Framework Infrastructure
- `tests/integration/connection_pair.zig` (ConnectionPair fixture)
- `tests/integration/scenarios.zig` (Scenario builder with fluent API)
- `tests/integration/loopback.zig` (LoopbackTransport for in-memory packet exchange)
- `tests/integration/harness.zig` (TestEndpoint wrapper with packet capture, time control)

### 3. Handshake Test Coverage (136 tests across 10 files)
- `tests/test_real_tls_full_handshake.zig` (1 test)
- `tests/test_tls_handshake_context.zig` (10 tests)
- `tests/test_tls_server_handshake_flight.zig` (2 tests)
- `tests/test_initial_handshake_loop.zig` (1 test)
- `tests/test_ack_ecn_handshake.zig` (1 test)
- `tests/unit/endpoint/test_handshake_integration.zig` (67 tests)
- `tests/test_tls_handshake_secrets.zig` (1 test)
- `tests/unit/endpoint/test_process_handshake.zig` (28 tests)
- `tests/unit/connection/test_handshake.zig` (24 tests)

## The Actual Gap

### Problem: Stub Types in Test Framework

**File**: `tests/integration/harness.zig` (lines 17-47)

```zig
// Stub types for test harness (until full endpoint integration)
// These will be replaced with real types when connecting to actual QUIC implementation
const Endpoint = struct {
    allocator: std.mem.Allocator,
    config: Config,
    // ... stub implementation ...
};

const Connection = opaque {};

const Config = struct {
    // Placeholder config fields
    allocator: std.mem.Allocator = undefined,
    role: enum { client, server } = .client,
    // ... placeholder fields ...
};
```

**File**: `tests/integration/connection_pair.zig` (lines 121-133)

```zig
pub fn connect(self: *ConnectionPair) !void {
    // This is a placeholder for the actual connection establishment
    // In real implementation, would:
    // 1. Client calls endpoint.connect()
    // 2. Wire transport callbacks to use loopback
    // 3. Pump packets through loopback
    // 4. Wait for handshake completion

    // For now, just create placeholder connections
    // Real implementation requires integration with actual Endpoint/Connection API
    _ = self;
    return error.NotImplementedYet;  // ← BLOCKING THE 84 TESTS!
}
```

### Why Phase 14 Didn't Complete This

From IMPLEMENTATION_SUMMARY.md (lines 1010-1128), Phase 14 was completed as "architectural validation":

> "Phase 14 takes an incremental approach, focusing on architectural validation rather than full feature completeness. The goal is to prove that the adapter → Transport → Endpoint integration chain works correctly, while acknowledging that TLS certificate management and handshake testing are complex enough to warrant dedicated phases."

> "Phase 14's focused approach allows us to validate the foundation (8 hours) before committing to the full implementation."

**Decision**: Phase 14 validated that `Endpoint.initWithTransport()` API worked, then explicitly deferred stub replacement to future phases. Phases 15-20 focused on validating TLS components, but never circled back to replace the stubs.

## Revised Phase 21 Scope

### NOT NEEDED (Original Analysis Was Wrong)
- ❌ 11-16 hours of end-to-end handshake implementation
- ❌ Implementing TLS from scratch
- ❌ Building packet encoding/decoding
- ❌ Creating handshake state machine
- ❌ Implementing key derivation

### ACTUALLY NEEDED (The Real Work)

**1. Replace Stub Types with Real Imports (30 minutes)**
- Update `tests/integration/harness.zig`:
  - Import `quic_endpoint`, `quic_conn`, `quic_config` modules
  - Replace `Endpoint` stub with real `endpoint_mod.Endpoint`
  - Replace `Connection` opaque with real `conn_mod.Connection`
  - Replace `Config` stub with `config_mod.QuicConfig`

**2. Implement ConnectionPair.connect() (1-2 hours)**
- Wire client/server endpoints with loopback transport
- Create client connection via `endpoint.connectClient()`
- Accept server connection via endpoint incoming packet handler
- Link transport callbacks to loopback queues

**3. Implement ConnectionPair.exchangePackets() (1-2 hours)**
- Poll endpoint for outgoing packets
- Deliver packets through loopback transport
- Pump packets in both directions (client → server, server → client)
- Handle UDP datagram delivery and reception

**4. Add Handshake Completion Polling (1 hour)**
- Implement `ConnectionPair.waitForHandshake()` method
- Poll both endpoints until `conn.isHandshakeConfirmed()` returns true
- Add timeout handling (e.g., 5 second max wait)
- Report handshake status for debugging

**5. Enable First Batch of Tier 1 Tests (1 hour)**
- Remove `return error.SkipZigTest` from 5-10 tests in `rfc9000_section7.zig`
- Start with simplest tests:
  - "Client sends Initial packet"
  - "Server responds with Initial packet"
  - "Handshake completes successfully"
- Verify tests pass with real endpoints
- Fix any integration issues discovered

**Total Estimated Effort**: 4.5-6.5 hours (much less than 11-16 hours!)

## Implementation Steps

### Step 1: Update harness.zig (30 min) ✅ IN PROGRESS

Replace stub types with real imports:

```zig
// Phase 21: Real endpoint integration
const endpoint_mod = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const config_mod = @import("quic_config");

// Use real types
const Endpoint = endpoint_mod.Endpoint;
const Connection = conn_mod.Connection;
const Config = config_mod.QuicConfig;
```

**Status**: ✅ PARTIALLY COMPLETE - Added documentation and transition path, stub types converted to wrappers with TODO markers.

### Step 2: Configure build.zig (30 min)

Add integration test configuration similar to existing tests:

```zig
// Integration tests configuration
const integration_harness = mkModule(b, "tests/integration/harness.zig");
integration_harness.addImport("quic_endpoint", quic_endpoint_mod);
integration_harness.addImport("quic_conn", quic_conn_mod);
integration_harness.addImport("quic_config", quic_config_mod);

const integration_connection_pair = mkModule(b, "tests/integration/connection_pair.zig");
integration_connection_pair.addImport("harness", integration_harness);
integration_connection_pair.addImport("loopback", loopback_mod);
// ... add other imports ...

// Create test executable for rfc9000_section7.zig
const test_rfc9000_section7 = addTst(b, "tests/integration/rfc9000_section7.zig", target, optimize);
test_rfc9000_section7.root_module.addImport("scenarios", scenarios_mod);
test_rfc9000_section7.root_module.addImport("connection_pair", connection_pair_mod);
test_rfc9000_section7.root_module.addImport("harness", integration_harness);
```

### Step 3: Implement ConnectionPair.connect() (1-2 hours)

```zig
pub fn connect(self: *ConnectionPair) !void {
    // Phase 21: Real implementation using production Endpoint

    // 1. Create client connection
    const server_addr = try self.server.getBoundAddress();
    self.client_conn = try self.client.endpoint.connectClient(server_addr);

    // 2. Exchange Initial packets to establish connection
    try self.exchangePackets();

    // 3. Server accepts connection (happens automatically via incoming packet handler)
    // Wait for server to create connection object
    const max_wait_ms = 1000;
    var waited_ms: u64 = 0;
    while (self.server_conn == null and waited_ms < max_wait_ms) : (waited_ms += 10) {
        try self.exchangePackets();
        std.time.sleep(10 * std.time.ns_per_ms);
    }

    if (self.server_conn == null) {
        return error.ServerConnectionTimeout;
    }
}
```

### Step 4: Implement ConnectionPair.exchangePackets() (1 hour)

```zig
pub fn exchangePackets(self: *ConnectionPair) !void {
    // Phase 21: Real packet exchange implementation
    var buf: [4096]u8 = undefined;

    // Client → Server
    while (try self.transport.recvAtA(&buf)) |len| {
        // Deliver to server endpoint
        try self.server.endpoint.processIncomingDatagram(buf[0..len], self.client.addr);
    }

    // Server → Client
    while (try self.transport.recvAtB(&buf)) |len| {
        // Deliver to client endpoint
        try self.client.endpoint.processIncomingDatagram(buf[0..len], self.server.addr);
    }
}
```

### Step 5: Implement Handshake Completion (1 hour)

```zig
pub fn waitForHandshake(self: *ConnectionPair, timeout_ms: u64) !void {
    const start_time = std.time.milliTimestamp();

    while (true) {
        // Check if handshake complete
        if (self.client_conn) |client_conn| {
            if (client_conn.isHandshakeConfirmed()) {
                if (self.server_conn) |server_conn| {
                    if (server_conn.isHandshakeConfirmed()) {
                        return; // Both sides complete!
                    }
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

### Step 6: Enable First Tests (1 hour)

Update `tests/integration/rfc9000_section7.zig`:

```zig
test "RFC 9000 §7.1 - Client sends Initial packet" {
    // Phase 21: ENABLED - using real endpoints
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

    // Verify packet was Initial type
    const first_packet = capture.getPacket(0);
    try std.testing.expect(first_packet.packet_type == .Initial);
}
```

## Benefits of Revised Scope

1. **Massive Effort Reduction**: 4-6 hours vs 11-16 hours (62% reduction)
2. **Reuses Existing Infrastructure**: 1,117 lines of handshake code + 136 passing tests
3. **Clear Integration Path**: Well-defined steps with existing examples
4. **Incremental Progress**: Can enable tests gradually (5-10 at a time)
5. **Low Risk**: All components already validated in Phases 19-20

## Risk Mitigation

### Potential Issues

1. **Build System Configuration**: May need to adjust module imports
   - Mitigation: Follow existing test patterns in build.zig
   - Reference: `test_endpoint_handshake_integration` configuration (line 779)

2. **Endpoint API Mismatches**: Test framework may not match production API
   - Mitigation: Start with simplest tests, fix API issues incrementally
   - Reference: Phase 14 documented `Endpoint.initWithTransport()` usage

3. **Loopback Transport Integration**: Packet delivery may have edge cases
   - Mitigation: Phases 11-13 validated loopback adapter (20/20 tests passing)
   - Reference: `endpoint_loopback_helpers.zig` (463 lines, 9/9 tests)

## Success Criteria

**Phase 21 Complete When**:
1. ✅ Stub types replaced with real imports in `harness.zig`
2. ✅ Build configuration added for integration tests
3. ✅ `ConnectionPair.connect()` implemented and working
4. ✅ `ConnectionPair.exchangePackets()` implemented
5. ✅ `ConnectionPair.waitForHandshake()` implemented
6. ✅ First 5-10 Tier 1 tests enabled and passing
7. ✅ Documentation updated (IMPLEMENTATION_SUMMARY.md, ENDPOINT_INTEGRATION_GUIDE.md)

**Measurable Progress**:
- Skip tests enabled: 0/84 → 5-10/84 (initial batch)
- Test pass rate: Maintain 99.7% (1668/1673)
- Integration tests: 0 → 5-10 passing
- Code added: ~200-300 lines (connection_pair.zig implementation)

## Next Steps After Phase 21

Once first batch enabled, continue incrementally:

**Phase 21a**: Enable remaining connection establishment tests (20 tests, 2-3 hours)
**Phase 21b**: Enable loss recovery tests (26 tests, 3-4 hours)
**Phase 21c**: Enable packet processing tests (32 tests, 3-4 hours)

Total to enable all 84 Tier 1 tests: 8-11 hours (including Phase 21 initial 4-6 hours)

## References

- **Original Analysis**: IMPLEMENTATION_SUMMARY.md lines 2826-2990
- **Phase 14 Architectural Validation**: IMPLEMENTATION_SUMMARY.md lines 1010-1128
- **Handshake Integration Code**: `src/quic/endpoint/handshake_integration.zig` (1,117 lines)
- **Loopback Adapter**: `tests/integration/loopback_transport_adapter.zig` (Phase 11-13)
- **Build Configuration Example**: build.zig line 779 (`test_endpoint_handshake_integration`)
- **Skip Test Documentation**: `tests/integration/rfc9000_section7.zig` (26 skip tests)

## Conclusion

Phase 21's original 11-16 hour estimate was based on the assumption that end-to-end handshake implementation was needed from scratch. Comprehensive codebase survey revealed this assumption was incorrect - all infrastructure exists and is validated. The actual work is connecting existing components (4-6 hours), not building them.

This is excellent news: Phase 21 can be completed much faster than originally estimated, and the 84 Tier 1 tests can be enabled incrementally with high confidence in success.
