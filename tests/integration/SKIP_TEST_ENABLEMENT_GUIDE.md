# Skip Test Enablement Guide

## Overview

This guide explains how to enable the 474 skip tests now that the transport abstraction is fully integrated (Phases 8-9 complete). The `endpoint_loopback_helpers.zig` module provides utilities to make this process straightforward.

## Prerequisites

Before enabling skip tests, ensure:

1. ✅ **Phase 8c Complete**: Endpoint uses Transport abstraction (sock_fd removed)
2. ✅ **Phase 9 Complete**: Endpoint-loopback integration validated
3. ✅ **Transport Available**: Both UdpTransport and LoopbackTransport implemented
4. ✅ **Test Helpers Ready**: `endpoint_loopback_helpers.zig` provides helper utilities

**Status**: All prerequisites met as of Phase 9 completion.

## Test Categories

The 474 skip tests are organized by RFC section:

| Category | File | Tests | Priority |
|----------|------|-------|----------|
| Connection Establishment | `rfc9000_section7.zig` | 26 | HIGH |
| Loss Recovery | `rfc9002_recovery.zig` | 26 | HIGH |
| Packet Processing | `rfc9000_packets.zig` | 32 | HIGH |
| Address Validation | `rfc9000_section8.zig` | 30 | MEDIUM |
| Connection Migration | `migration.zig` | 46 | MEDIUM |
| Flow Control | `flow_control.zig` | 51 | MEDIUM |
| Key Updates | `key_update.zig` | 52 | LOW |
| 0-RTT & Resumption | `zero_rtt.zig` | 62 | LOW |
| Interoperability | `interop/` | 40 | LOW |
| Stress Testing | `stress/` | 37 | LOW |
| Fault Injection | Various | 56 | LOW |
| **TOTAL** | | **474** | |

## Enablement Process

### Step 1: Choose a Test to Enable

Start with high-priority, simple tests. Example from `rfc9000_section7.zig`:

```zig
test "RFC 9000 §7.1 - Client sends Initial packet" {
    // SKIP: Requires actual packet encoding and endpoint integration
    // This test would verify that a client generates a valid Initial packet
    // with proper packet number, connection ID, and CRYPTO frame.
    return error.SkipZigTest;
}
```

### Step 2: Import Helper Module

Add the helper import at the top of the test file:

```zig
const helpers = @import("endpoint_loopback_helpers.zig");
```

### Step 3: Replace Skip with Implementation

Replace the `return error.SkipZigTest` with actual test logic:

```zig
test "RFC 9000 §7.1 - Client sends Initial packet" {
    // Create helper with default configuration
    var helper = try helpers.createBasicScenario(testing.allocator);
    defer helper.deinit();

    // Create client endpoint with loopback transport
    var client = try helper.createClientEndpoint();
    defer client.deinit();

    // TODO: Trigger Initial packet generation
    // TODO: Capture packet via loopback transport
    // TODO: Verify packet structure

    try testing.expect(true);  // Placeholder until implemented
}
```

### Step 4: Implement Test Logic

Add the specific test logic based on RFC requirements:

```zig
test "RFC 9000 §7.1 - Client sends Initial packet" {
    var helper = try helpers.createBasicScenario(testing.allocator);
    defer helper.deinit();

    // Enable packet capture
    helper.loopback_config.enable_capture = true;

    var client = try helper.createClientEndpoint();
    defer client.deinit();

    // Initiate connection (triggers Initial packet)
    const conn = try client.connectTo("server:4433");

    // Wait for packet to be sent
    try helper.advanceTime(10); // Allow processing

    // Retrieve captured packet from loopback
    const packets = try helper.getCapturedPackets();
    try testing.expect(packets.len > 0);

    // Verify packet is Initial type (RFC 9000 §17.2.2)
    const initial_pkt = packets[0];
    try testing.expect(initial_pkt.header.packet_type == .Initial);
    try testing.expect(initial_pkt.header.version == 0x00000001);

    // Verify packet contains CRYPTO frame with ClientHello
    const has_crypto_frame = for (initial_pkt.frames) |frame| {
        if (frame == .CRYPTO) break true;
    } else false;
    try testing.expect(has_crypto_frame);
}
```

### Step 5: Run and Debug

```bash
# Run the specific test
zig test tests/integration/rfc9000_section7.zig --test-filter "Client sends Initial"

# Run all tests in the file
zig test tests/integration/rfc9000_section7.zig

# Run with verbose output
zig test tests/integration/rfc9000_section7.zig --summary all
```

### Step 6: Document Implementation

Update the test comment to indicate it's enabled:

```zig
test "RFC 9000 §7.1 - Client sends Initial packet" {
    // ENABLED: Verifies client generates valid Initial packet
    // RFC 9000 §17.2.2: Initial packet format
    // RFC 9000 §7.1: Client connection establishment
    ...
}
```

## Helper API Reference

### EndpointLoopbackHelper

Main helper class for endpoint-loopback integration:

```zig
pub const EndpointLoopbackHelper = struct {
    // Initialize helper
    pub fn init(allocator: std.mem.Allocator) !EndpointLoopbackHelper

    // Clean up resources
    pub fn deinit(self: *EndpointLoopbackHelper) void

    // Create client endpoint with loopback
    pub fn createClientEndpoint(self: *EndpointLoopbackHelper) !*Endpoint

    // Create server endpoint with loopback
    pub fn createServerEndpoint(self: *EndpointLoopbackHelper) !*Endpoint

    // Connect client to server
    pub fn connectClientToServer(
        self: *EndpointLoopbackHelper,
        client: *Endpoint,
        server: *Endpoint
    ) !*Connection

    // Wait for handshake with timeout
    pub fn waitForHandshake(
        self: *EndpointLoopbackHelper,
        conn: *Connection,
        timeout_ms: u64
    ) !void

    // Advance mock time
    pub fn advanceTime(self: *EndpointLoopbackHelper, ms: u64) !void
};
```

### Scenario Helpers

Pre-configured helpers for common test scenarios:

```zig
// Clean loopback (no packet loss/delay)
var helper = try helpers.createBasicScenario(allocator);

// 10% packet loss with delay
var helper = try helpers.createLossyScenario(allocator, 0.1);

// 50ms delay with 10ms jitter
var helper = try helpers.createDelayedScenario(allocator, 50, 10);
```

### LoopbackConfig

Fine-grained loopback configuration:

```zig
helper.loopback_config = .{
    .loss_rate = 0.05,          // 5% packet loss
    .corruption_rate = 0.01,    // 1% corruption
    .delay_ms = 20,             // 20ms base delay
    .jitter_ms = 5,             // 5ms jitter
    .max_packet_size = 1280,    // QUIC minimum MTU
};
```

## Common Patterns

### Pattern 1: Basic Handshake Test

```zig
test "Basic handshake completes" {
    var helper = try helpers.createBasicScenario(testing.allocator);
    defer helper.deinit();

    var client = try helper.createClientEndpoint();
    defer client.deinit();

    var server = try helper.createServerEndpoint();
    defer server.deinit();

    const conn = try helper.connectClientToServer(client, server);
    try helper.waitForHandshake(conn, 5000);

    try testing.expect(conn.isHandshakeComplete());
}
```

### Pattern 2: Packet Loss Recovery

```zig
test "Recovers from 20% packet loss" {
    var helper = try helpers.createLossyScenario(testing.allocator, 0.2);
    defer helper.deinit();

    // Setup client/server
    var client = try helper.createClientEndpoint();
    defer client.deinit();

    var server = try helper.createServerEndpoint();
    defer server.deinit();

    // Connect despite packet loss
    const conn = try helper.connectClientToServer(client, server);
    try helper.waitForHandshake(conn, 10000); // Longer timeout

    try testing.expect(conn.isHandshakeComplete());
}
```

### Pattern 3: PTO Testing

```zig
test "PTO timer fires after packet loss" {
    var helper = try helpers.createBasicScenario(testing.allocator);
    defer helper.deinit();

    // Configure 100% loss for first packet
    helper.loopback_config.loss_rate = 1.0;

    var client = try helper.createClientEndpoint();
    defer client.deinit();

    // Send packet (will be lost)
    const conn = try client.connectTo("server:4433");

    // Advance time to PTO timeout
    try helper.advanceTime(conn.pto_timeout_ms);

    // Verify retransmission occurred
    const stats = try helper.getLoopbackStats();
    try testing.expect(stats.retransmissions > 0);
}
```

### Pattern 4: Flow Control Testing

```zig
test "Flow control limits data transfer" {
    var helper = try helpers.createBasicScenario(testing.allocator);
    defer helper.deinit();

    // Set small flow control window
    helper.endpoint_config.initial_max_data = 1024;  // 1KB

    var client = try helper.createClientEndpoint();
    defer client.deinit();

    var server = try helper.createServerEndpoint();
    defer server.deinit();

    const conn = try helper.connectClientToServer(client, server);
    try helper.waitForHandshake(conn, 5000);

    // Try to send more than flow control allows
    const large_data = try allocator.alloc(u8, 2048);  // 2KB
    defer allocator.free(large_data);

    // Should block after 1KB
    const sent = try conn.streamSend(0, large_data, false);
    try testing.expectEqual(@as(usize, 1024), sent);
}
```

## Implementation Status Tracking

Update this section as tests are enabled:

### RFC 9000 §7 - Connection Establishment (0/26 enabled)

- [ ] Client sends Initial packet
- [ ] Initial contains CRYPTO frame with ClientHello
- [ ] Initial uses long header format
- [ ] Initial includes token if available
- [ ] Server responds with Initial
- [ ] Server Initial contains ServerHello
- [ ] Server sends ACK for client Initial
- [ ] Transport parameters exchanged
- [ ] Invalid transport parameters rejected
- [ ] initial_source_connection_id validated
- [ ] Handshake completes successfully
- [ ] Connection IDs established
- [ ] ... (16 more tests)

### RFC 9002 - Loss Recovery (0/26 enabled)

- [ ] Loss detection after timeout
- [ ] Fast retransmit on triple duplicate ACK
- [ ] PTO timer fires correctly
- [ ] RTT estimation works
- [ ] ... (22 more tests)

### RFC 9000 Packets (0/32 enabled)

- [ ] Long header packet encoding
- [ ] Short header packet encoding
- [ ] Packet number encoding
- [ ] Packet protection/unprotection
- [ ] ... (28 more tests)

*Continue for all 474 tests...*

## Troubleshooting

### Issue: Test times out

**Cause**: Handshake not completing, endpoints not polling

**Solution**: Ensure both endpoints are polled regularly:

```zig
// Poll both endpoints until condition
while (!conn.isHandshakeComplete()) {
    try client.poll(1);
    try server.poll(1);
    try helper.advanceTime(1);
}
```

### Issue: Packet not captured

**Cause**: Capture not enabled or packets lost

**Solution**: Enable capture before sending:

```zig
helper.loopback_config.enable_capture = true;
helper.loopback_config.loss_rate = 0.0;  // Disable loss for capture
```

### Issue: TLS handshake fails

**Cause**: Missing certificates or TLS configuration

**Solution**: Use test certificates or disable validation:

```zig
helper.endpoint_config.allow_insecure_tls = true;  // Testing only!
```

## Best Practices

1. **Start Simple**: Enable basic tests first (handshake, data transfer)
2. **One at a Time**: Enable and verify one test before moving to next
3. **Document Progress**: Update the status tracking section
4. **Add Comments**: Explain RFC requirements in test comments
5. **Use Helpers**: Leverage scenario helpers for common patterns
6. **Test Isolation**: Each test should be independent (no shared state)
7. **Cleanup Resources**: Always use defer for cleanup
8. **Verify RFC Compliance**: Include RFC section references in assertions

## Contributing

When enabling skip tests:

1. Follow the enablement process above
2. Add detailed RFC citations in test comments
3. Use helper utilities from `endpoint_loopback_helpers.zig`
4. Update the implementation status tracking section
5. Submit PR with enabled tests and passing results

## References

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html): QUIC Transport Protocol
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html): QUIC TLS
- [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html): QUIC Loss Detection
- `endpoint_loopback_helpers.zig`: Helper utilities
- `loopback.zig`: Loopback transport implementation
- `IMPLEMENTATION_SUMMARY.md`: Phase completion status
- `ENDPOINT_INTEGRATION_GUIDE.md`: Integration architecture
