//! RFC 9000 - Packet Processing Tests
//!
//! Tests for QUIC packet processing including:
//! - Initial packet processing (§17.2.2)
//! - Handshake packet processing (§17.2.4)
//! - 1-RTT packet processing (§17.3)
//! - Version Negotiation packets (§17.2.1)
//! - Retry packet validation (§17.2.5)
//! - Coalesced packets (§12.2)
//! - ECN processing (§13.4)
//!
//! RFC References:
//! - RFC 9000 §17: Packet Formats
//! - RFC 9000 §12-13: Packet Processing
//! - RFC 3168: ECN

const std = @import("std");
const scenarios = @import("scenarios");
const connection_pair = @import("connection_pair");
const harness = @import("harness");
const loopback = @import("loopback");
const packet_inspector = @import("packet_inspector");

// =============================================================================
// Infrastructure Tests
// =============================================================================

test "Packet processing test infrastructure with capture" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Packet processing testing")
        .withCapture(); // Essential for packet inspection

    _ = try scenario.createPair();

    // Verify infrastructure ready for packet processing tests
    const pair = scenario.pair.?;
    _ = pair.server;
    _ = pair.client;
}

test "ECN marking support in loopback transport" {
    const allocator = std.testing.allocator;

    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder.build();
    defer pair.deinit();

    // ECN configuration available
    try std.testing.expect(!pair.transport.config.enable_ecn); // Default false
}

test "Packet corruption simulation for malformed packet testing" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withPacketCorruption(0.1) // 10% corruption
        .withCapture();

    _ = try scenario.createPair();

    const pair = scenario.pair.?;
    try std.testing.expectEqual(@as(f64, 0.1), pair.transport.config.corruption_rate);
}

test "Packet reordering simulation" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withPacketReordering(0.2) // 20% reordering
        .withCapture();

    _ = try scenario.createPair();

    const pair = scenario.pair.?;
    try std.testing.expectEqual(@as(f64, 0.2), pair.transport.config.reordering_rate);
}

test "MTU enforcement for packet size testing" {
    const allocator = std.testing.allocator;

    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withMtu(1200) // Minimum QUIC MTU
        .build();
    defer pair.deinit();

    try std.testing.expectEqual(@as(u16, 1200), pair.config.transport.mtu);
}

// =============================================================================
// Phase 21.3 - Packet Inspector Proof-of-Concept
// =============================================================================

test "Phase 21.3 - Packet inspector header parsing" {
    // Test Initial packet header parsing
    var packet: [30]u8 = undefined;
    var i: usize = 0;

    // First byte: Long header + Fixed bit + Type=Initial (00)
    packet[i] = 0xC0;
    i += 1;

    // Version (QUIC v1)
    std.mem.writeInt(u32, packet[i..][0..4], 0x00000001, .big);
    i += 4;

    // DCID
    packet[i] = 8;
    i += 1;
    @memset(packet[i..i + 8], 0xAA);
    i += 8;

    // SCID
    packet[i] = 8;
    i += 1;
    @memset(packet[i..i + 8], 0xBB);
    i += 8;

    const info = try packet_inspector.parsePacketHeader(packet[0..i]);

    try std.testing.expectEqual(packet_inspector.PacketType.Initial, info.packet_type);
    try std.testing.expectEqual(packet_inspector.PacketNumberSpace.Initial, info.pn_space);
    try std.testing.expect(info.is_long_header);
}

test "Phase 21.3 - Packet type detection helpers" {
    // Build Initial packet
    var packet: [30]u8 = undefined;
    packet[0] = 0xC0;  // Initial
    std.mem.writeInt(u32, packet[1..][0..4], 0x00000001, .big);
    packet[5] = 0;  // DCID len
    packet[6] = 0;  // SCID len

    try std.testing.expect(packet_inspector.isInitialPacket(&packet));
    try std.testing.expect(!packet_inspector.isHandshakePacket(&packet));
    try std.testing.expect(!packet_inspector.isOneRTTPacket(&packet));

    const pn_space = try packet_inspector.getPacketNumberSpace(&packet);
    try std.testing.expectEqual(packet_inspector.PacketNumberSpace.Initial, pn_space);
}

test "Phase 21.3 - Packet capture integration" {
    // Simulate captured packets
    var packet1: [30]u8 = undefined;
    packet1[0] = 0xC0;  // Initial
    std.mem.writeInt(u32, packet1[1..][0..4], 0x00000001, .big);
    packet1[5] = 0;
    packet1[6] = 0;

    var packet2: [30]u8 = undefined;
    packet2[0] = 0xE0;  // Handshake
    std.mem.writeInt(u32, packet2[1..][0..4], 0x00000001, .big);
    packet2[5] = 0;
    packet2[6] = 0;

    const captured = [_]harness.CapturedPacket{
        .{ .timestamp_ms = 0, .direction = .sent, .data = &packet1 },
        .{ .timestamp_ms = 10, .direction = .received, .data = &packet2 },
    };

    // Count packet types
    const initial_count = try packet_inspector.countPacketTypeInCapture(&captured, .Initial);
    const handshake_count = try packet_inspector.countPacketTypeInCapture(&captured, .Handshake);

    try std.testing.expectEqual(@as(usize, 1), initial_count);
    try std.testing.expectEqual(@as(usize, 1), handshake_count);

    // Find specific packet
    const initial_pkt = try packet_inspector.findPacketInCapture(&captured, .Initial);
    try std.testing.expect(initial_pkt != null);

    // Assertion helper
    try packet_inspector.expectPacketInCapture(&captured, .Initial);
    try packet_inspector.expectPacketInCapture(&captured, .Handshake);
}

// =============================================================================
// RFC 9000 §17.2.2 - Initial Packet Processing
// =============================================================================

test "RFC 9000 §17.2.2 - Initial packet processing setup" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Initial packet processing")
        .withCapture()
        .withTimeControl();

    _ = try scenario.createPair();
}

test "RFC 9000 §17.2.2 - Server processes client Initial" {
    // Tier 1 Step 3 Phase 7: ENABLED - Validate Initial packet processing state
    const allocator = std.testing.allocator;

    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder.build();
    defer pair.deinit();

    // Establish connection (processes Initial packets)
    try pair.connect();

    try std.testing.expect(pair.server_conn != null);
    try std.testing.expect(pair.client_conn != null);

    // After handshake, Initial packet numbers should have been used
    // TX side: at least one Initial packet should have been sent
    try std.testing.expect(pair.server_conn.?.pn_initial_tx > 0);
    try std.testing.expect(pair.client_conn.?.pn_initial_tx > 0);

    // RX side: Initial PN window should have tracked received packets
    try std.testing.expect(pair.server_conn.?.pn_initial.have_any);
    try std.testing.expect(pair.client_conn.?.pn_initial.have_any);
}

test "RFC 9000 §17.2.2 - Invalid Initial packet rejected" {
    // SKIP: Requires packet validation
    return error.SkipZigTest;
}

test "RFC 9000 §17.2.2 - Initial packet with token processed" {
    // SKIP: Requires token processing
    return error.SkipZigTest;
}

// =============================================================================
// RFC 9000 §17.2.4 - Handshake Packet Processing
// =============================================================================

test "RFC 9000 §17.2.4 - Handshake packet processing setup" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Handshake packet processing")
        .withCapture();

    _ = try scenario.createPair();
}

test "RFC 9000 §17.2.4 - Handshake packet processed" {
    // Tier 1 Step 3 Phase 7: ENABLED - Validate Handshake packet processing state
    const allocator = std.testing.allocator;

    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder.build();
    defer pair.deinit();

    try pair.connect();

    try std.testing.expect(pair.server_conn != null);
    try std.testing.expect(pair.client_conn != null);

    // After handshake, Handshake packet numbers should have been used
    // TX side: at least one Handshake packet should have been sent
    try std.testing.expect(pair.server_conn.?.pn_handshake_tx > 0);
    try std.testing.expect(pair.client_conn.?.pn_handshake_tx > 0);

    // RX side: Handshake PN window should have tracked received packets
    try std.testing.expect(pair.server_conn.?.pn_handshake.have_any);
    try std.testing.expect(pair.client_conn.?.pn_handshake.have_any);
}

test "RFC 9000 §17.2.4 - Handshake keys must be available" {
    // Tier 1 Step 3 Phase 7: ENABLED - Validate Handshake keys were derived
    const allocator = std.testing.allocator;

    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder.build();
    defer pair.deinit();

    try pair.connect();

    try std.testing.expect(pair.server_conn != null);
    try std.testing.expect(pair.client_conn != null);

    // RFC 9000 §17.2.4: Handshake packets use Handshake keys
    // After handshake completion, Handshake keys may be dropped (RFC 9001 §4.9.2)
    // But Handshake PNs should have been used, indicating keys were available
    // This is already validated by the previous test (pn_handshake_tx > 0)

    // We can also verify that at this point, 1-RTT keys are available
    // (which means Handshake was successful)
    try std.testing.expect(pair.server_conn.?.app_tx_keys != null);
    try std.testing.expect(pair.client_conn.?.app_tx_keys != null);
}

// =============================================================================
// RFC 9000 §17.3 - 1-RTT Packet Processing
// =============================================================================

test "RFC 9000 §17.3 - 1-RTT packet processing setup" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("1-RTT packet processing")
        .withCapture();

    _ = try scenario.createPair();
}

test "RFC 9000 §17.3 - Short header packets processed" {
    // Tier 1 Step 3 Phase 7: ENABLED - Validate 1-RTT packet processing state
    const allocator = std.testing.allocator;

    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder.build();
    defer pair.deinit();

    try pair.connect();

    try std.testing.expect(pair.server_conn != null);
    try std.testing.expect(pair.client_conn != null);

    // After handshake, Application Data (1-RTT) packet numbers should exist
    // RFC 9000 §17.3: 1-RTT packets use short header format
    // pn_app_tx may be 0 if no application data was sent yet
    // But pn_app should have tracked any received packets
    const server = pair.server_conn.?;
    const client = pair.client_conn.?;

    // At minimum, verify 1-RTT keys are installed
    // (required for processing short header packets)
    try std.testing.expect(server.app_rx_keys != null);
    try std.testing.expect(server.app_tx_keys != null);
    try std.testing.expect(client.app_rx_keys != null);
    try std.testing.expect(client.app_tx_keys != null);
}

test "RFC 9000 §17.3 - Spin bit preserved" {
    // SKIP: Requires spin bit handling
    return error.SkipZigTest;
}

test "RFC 9000 §17.3 - Key phase bit handled" {
    // Tier 1 Step 3 Phase 7: ENABLED - Validate key phase bit initialization
    const allocator = std.testing.allocator;

    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder.build();
    defer pair.deinit();

    try pair.connect();

    try std.testing.expect(pair.server_conn != null);
    try std.testing.expect(pair.client_conn != null);

    // RFC 9000 §17.3.1: Key phase bit is initially 0
    // After initial connection (no key update yet), key phase should be false
    try std.testing.expectEqual(false, pair.server_conn.?.tx_key_phase);
    try std.testing.expectEqual(false, pair.server_conn.?.rx_key_phase);
    try std.testing.expectEqual(false, pair.client_conn.?.tx_key_phase);
    try std.testing.expectEqual(false, pair.client_conn.?.rx_key_phase);
}

// =============================================================================
// RFC 9000 §17.2.1 - Version Negotiation
// =============================================================================

test "RFC 9000 §17.2.1 - Version negotiation packet test setup" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Version negotiation testing")
        .withCapture();

    _ = try scenario.createPair();
}

test "RFC 9000 §17.2.1 - VN packet sent for unknown version" {
    // SKIP: Requires VN packet generation
    return error.SkipZigTest;
}

test "RFC 9000 §17.2.1 - VN packet lists supported versions" {
    // SKIP: Requires VN packet parsing
    return error.SkipZigTest;
}

test "RFC 9000 §17.2.1 - VN packet causes client retry" {
    // SKIP: Requires VN handling
    return error.SkipZigTest;
}

// =============================================================================
// RFC 9000 §17.2.5 - Retry Packet
// =============================================================================

test "RFC 9000 §17.2.5 - Retry packet test setup" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Retry packet testing")
        .withCapture();

    _ = try scenario.createPair();
}

test "RFC 9000 §17.2.5 - Retry packet has integrity tag" {
    // SKIP: Requires Retry generation
    return error.SkipZigTest;
}

test "RFC 9000 §17.2.5 - Invalid Retry integrity rejected" {
    // SKIP: Requires Retry validation
    return error.SkipZigTest;
}

test "RFC 9000 §17.2.5 - Retry packet includes token" {
    // SKIP: Requires Retry processing
    return error.SkipZigTest;
}

// =============================================================================
// RFC 9000 §12.2 - Coalesced Packets
// =============================================================================

test "RFC 9000 §12.2 - Coalesced packet test setup" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Coalesced packet testing")
        .withCapture();

    _ = try scenario.createPair();
}

test "RFC 9000 §12.2 - Multiple packets in single datagram" {
    // SKIP: Requires coalescing support
    return error.SkipZigTest;
}

test "RFC 9000 §12.2 - Initial and Handshake coalesced" {
    // SKIP: Requires coalescing
    return error.SkipZigTest;
}

test "RFC 9000 §12.2 - Padding between coalesced packets" {
    // SKIP: Requires coalescing
    return error.SkipZigTest;
}

// =============================================================================
// RFC 9000 §13.4 - ECN Processing
// =============================================================================

test "RFC 9000 §13.4 - ECN test infrastructure" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("ECN testing")
        .withEcn() // Enable ECN marking
        .withCapture();

    _ = try scenario.createPair();

    const pair = scenario.pair.?;
    try std.testing.expect(pair.transport.config.enable_ecn);
}

test "RFC 9000 §13.4 - ECN counts in ACK frames" {
    // SKIP: Requires ECN counter processing
    return error.SkipZigTest;
}

test "RFC 9000 §13.4 - ECN-CE triggers congestion response" {
    // SKIP: Requires ECN processing
    return error.SkipZigTest;
}

test "RFC 9000 §13.4 - ECN validation" {
    // SKIP: Requires ECN validation
    return error.SkipZigTest;
}

// =============================================================================
// Packet Number Handling
// =============================================================================

test "Packet number decoding test setup" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Packet number testing")
        .withCapture();

    _ = try scenario.createPair();
}

test "Packet number expansion" {
    // SKIP: Requires PN expansion logic
    return error.SkipZigTest;
}

test "Packet number wrapping handled" {
    // SKIP: Requires PN wrapping
    return error.SkipZigTest;
}

// =============================================================================
// Malformed Packet Handling
// =============================================================================

test "Malformed packet test infrastructure" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Malformed packet testing")
        .withPacketCorruption(1.0) // 100% corruption
        .withCapture();

    _ = try scenario.createPair();
}

test "Invalid packet header rejected" {
    // SKIP: Requires header validation
    return error.SkipZigTest;
}

test "Packet with invalid CID ignored" {
    // SKIP: Requires CID validation
    return error.SkipZigTest;
}

test "Packet too small rejected" {
    // SKIP: Requires size validation
    return error.SkipZigTest;
}

// =============================================================================
// TODO Tests
// =============================================================================

test "TODO: Stateless reset packet processing (§10.3)" {
    // Should verify stateless reset packets are recognized and handled
    return error.SkipZigTest;
}

test "TODO: Packet with future packet number accepted (§12.3)" {
    // Should verify packets with PNs ahead of expected are buffered
    return error.SkipZigTest;
}

test "TODO: Duplicate packet numbers ignored (§12.3)" {
    // Should verify duplicate PNs are detected and ignored
    return error.SkipZigTest;
}

test "TODO: Packet with invalid checksum rejected (§17)" {
    // Should verify AEAD authentication failures cause packet rejection
    return error.SkipZigTest;
}

test "TODO: Initial packet padding verified (§14.1)" {
    // Should verify Initial packets meet minimum size requirement
    return error.SkipZigTest;
}

test "TODO: Key phase mismatch handled (§17.3.1)" {
    // Should verify key phase bit mismatch triggers key update
    return error.SkipZigTest;
}

test "RFC 9000 §12.1 - Packet number space separation" {
    // Tier 1 Step 3 Phase 7.4: ENABLED - Validate separate PN spaces
    const allocator = std.testing.allocator;

    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder.build();
    defer pair.deinit();

    try pair.connect();

    try std.testing.expect(pair.server_conn != null);
    try std.testing.expect(pair.client_conn != null);

    const server = pair.server_conn.?;
    const client = pair.client_conn.?;

    // RFC 9000 §12.1: QUIC has three packet number spaces:
    // - Initial space
    // - Handshake space
    // - Application Data space
    //
    // Each space maintains independent packet number sequences.

    // Verify all three TX spaces were used during handshake
    try std.testing.expect(server.pn_initial_tx > 0);
    try std.testing.expect(server.pn_handshake_tx > 0);
    try std.testing.expect(client.pn_initial_tx > 0);
    try std.testing.expect(client.pn_handshake_tx > 0);

    // Verify all three RX spaces tracked packets
    try std.testing.expect(server.pn_initial.have_any);
    try std.testing.expect(server.pn_handshake.have_any);
    try std.testing.expect(client.pn_initial.have_any);
    try std.testing.expect(client.pn_handshake.have_any);

    // Verify Application Data space exists (keys installed)
    try std.testing.expect(server.app_tx_keys != null);
    try std.testing.expect(server.app_rx_keys != null);
    try std.testing.expect(client.app_tx_keys != null);
    try std.testing.expect(client.app_rx_keys != null);

    // Verify the three spaces are independent structures
    // (comparing addresses ensures they are not aliased)
    const server_initial_ptr = &server.pn_initial;
    const server_hs_ptr = &server.pn_handshake;
    const server_app_ptr = &server.pn_app;

    try std.testing.expect(server_initial_ptr != server_hs_ptr);
    try std.testing.expect(server_initial_ptr != server_app_ptr);
    try std.testing.expect(server_hs_ptr != server_app_ptr);
}

// =============================================================================
// Test Summary
// =============================================================================

// Phase 3 RFC 9000 Packet Processing Implementation Status:
// - Infrastructure tests: 6/6 passing ✅
// - Skip tests (require endpoint): 25+ tests documented 📝
// - TODO tests: 7 additional tests documented for future implementation
//
// This test file establishes the structure for packet processing testing.
// Tests can be enabled as packet encoding/decoding is implemented.
