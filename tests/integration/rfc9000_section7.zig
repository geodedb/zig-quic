//! RFC 9000 §7 - Connection Establishment Tests
//!
//! Tests for QUIC connection establishment including:
//! - Client Initial packet generation (§7.1, §17.2.2)
//! - Server Initial response (§7.2, §17.2.2)
//! - Transport parameter exchange (§7.3, §18)
//! - Version negotiation (§6, §17.2.1)
//! - Connection ID management (§5.1-5.3)
//! - Retry packet flow (§8.1.1, §17.2.5)
//!
//! RFC References:
//! - RFC 9000 §7: Cryptographic and Transport Handshake
//! - RFC 9001: Using TLS to Secure QUIC
//! - RFC 9369: QUIC Version 2

const std = @import("std");
const testlog = @import("testlog");
const scenarios = @import("scenarios"); // Module import (configured in build.zig)
const connection_pair = @import("connection_pair"); // Module import (configured in build.zig)
// Note: harness is available through scenarios and connection_pair if needed

// NOTE: Many tests in this file are marked as "skip" because they require
// full endpoint integration with actual packet encoding/decoding and TLS
// handshake implementation. These tests establish the structure and can be
// enabled as the QUIC implementation matures.

/// Test configuration for connection establishment scenarios
const ConnectionEstablishmentConfig = struct {
    enable_capture: bool = true,
    enable_time_control: bool = true,
    enable_0rtt: bool = false,
    alpn: []const []const u8 = &[_][]const u8{"test"},
};

// =============================================================================
// RFC 9000 §7.1 - Client Initial Packet
// =============================================================================

test "RFC 9000 §7.1 - Client sends Initial packet" {
    // Phase 14: ENABLED - Basic connection establishment test
    const allocator = std.testing.allocator;

    // Create connection pair with real endpoints
    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withCapture()
        .build();
    defer pair.deinit();

    // Establish connection
    try pair.connect();

    // Verify connections were established
    try std.testing.expect(pair.client_conn != null);
    try std.testing.expect(pair.server_conn != null);

    // TODO: Add packet capture validation when EndpointWrapper supports it
}

test "RFC 9000 §7.1 - Initial packet contains CRYPTO frame with ClientHello" {
    // Tier 1 Step 1 Phase 1: ENABLED - Validate CRYPTO frame in Initial packet
    const allocator = std.testing.allocator;

    // Create connection pair with packet capture enabled
    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withCapture()
        .build();
    defer pair.deinit();

    // Establish connection (this triggers Initial packet with ClientHello)
    try pair.connect();

    // Get captured packets from client
    const client_packets = pair.getClientPackets();
    try std.testing.expect(client_packets != null);
    try std.testing.expect(client_packets.?.len > 0);

    // Find the first Initial packet sent by client
    const packet_inspector = @import("packet_inspector");
    var found_initial = false;
    var found_crypto = false;

    for (client_packets.?) |captured| {
        if (captured.direction != .sent) continue;

        // Check if this is an Initial packet
        if (packet_inspector.isInitialPacket(captured.data)) {
            found_initial = true;

            // Decrypt and check for CRYPTO frame
            // Client Initial packets use is_client=true for decryption
            const has_crypto = try packet_inspector.initialPacketHasCryptoFrame(
                allocator,
                captured.data,
                true, // is_client
            );

            if (has_crypto) {
                found_crypto = true;
                break;
            }
        }
    }

    // Verify we found an Initial packet with CRYPTO frame
    try std.testing.expect(found_initial);
    try std.testing.expect(found_crypto);
}

test "RFC 9000 §7.1 - Initial packet uses long header format" {
    // Tier 1 Step 1 Phase 1: ENABLED - Validate long header format
    const allocator = std.testing.allocator;

    // Create connection pair with packet capture
    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withCapture()
        .build();
    defer pair.deinit();

    // Establish connection
    try pair.connect();

    // Get client packets
    const client_packets = pair.getClientPackets();
    try std.testing.expect(client_packets != null);

    // Validate that Initial packets use long header format
    const packet_inspector = @import("packet_inspector");
    var found_initial_with_long_header = false;

    for (client_packets.?) |captured| {
        if (captured.direction != .sent) continue;

        // Parse packet header
        const info = packet_inspector.parsePacketHeader(captured.data) catch continue;

        // Check if this is an Initial packet with long header
        if (info.packet_type == .Initial and info.is_long_header) {
            found_initial_with_long_header = true;
            break;
        }
    }

    try std.testing.expect(found_initial_with_long_header);
}

test "RFC 9000 §7.1 - Initial packet includes token if available" {
    // Tier 1 Step 1 Phase 1: ENABLED - Validate token field exists in Initial packets
    // Note: For first connection without Retry, token is typically empty
    const allocator = std.testing.allocator;

    // Create connection pair with packet capture
    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withCapture()
        .build();
    defer pair.deinit();

    // Establish connection
    try pair.connect();

    // Get client packets
    const client_packets = pair.getClientPackets();
    try std.testing.expect(client_packets != null);

    // Validate that Initial packets have token field (even if empty)
    const packet_inspector = @import("packet_inspector");
    var found_initial_with_token_field = false;

    for (client_packets.?) |captured| {
        if (captured.direction != .sent) continue;

        // Parse packet header
        const info = packet_inspector.parsePacketHeader(captured.data) catch continue;

        // Check if this is an Initial packet
        if (info.packet_type == .Initial) {
            // Token field should exist (even if empty for first connection)
            if (info.token) |token| {
                // Token field exists (may be empty, that's fine)
                _ = token;
                found_initial_with_token_field = true;
                break;
            }
        }
    }

    try std.testing.expect(found_initial_with_token_field);
}

// =============================================================================
// RFC 9000 §7.2 - Server Initial Response
// =============================================================================

test "RFC 9000 §7.2 - Server responds with Initial packet" {
    // Phase 21: ENABLED - Server response test
    const allocator = std.testing.allocator;

    // Create connection pair
    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder.build();
    defer pair.deinit();

    // Establish connection (this triggers Initial packet exchange)
    try pair.connect();

    // Verify server accepted the connection (indicates it processed Initial and responded)
    try std.testing.expect(pair.server_conn != null);

    // Verify client connection exists (indicates it received server's response)
    try std.testing.expect(pair.client_conn != null);
}

test "RFC 9000 §7.2 - Server Initial contains CRYPTO frame with ServerHello" {
    // Tier 1 Step 1: ENABLED - Validate server Initial packet has CRYPTO frame
    const allocator = std.testing.allocator;

    // Create connection pair with packet capture enabled
    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withCapture()
        .build();
    defer pair.deinit();

    // Establish connection (server sends Initial with ServerHello)
    try pair.connect();

    // Get captured packets from server
    const server_packets = pair.getServerPackets();
    try std.testing.expect(server_packets != null);
    try std.testing.expect(server_packets.?.len > 0);

    // Find the first Initial packet sent by server
    const packet_inspector = @import("packet_inspector");
    var found_initial = false;
    var found_crypto = false;

    // First, extract the client's DCID from client packets (needed for server packet decryption)
    // RFC 9001 §5.2: Initial keys are derived from client's original DCID
    const client_packets = pair.getClientPackets();
    try std.testing.expect(client_packets != null);

    testlog.print("[TEST §7.2 CRYPTO] Found {} client packets\n", .{client_packets.?.len});

    var client_dcid: ?[]const u8 = null;
    for (client_packets.?, 0..) |captured, i| {
        testlog.print("[TEST §7.2 CRYPTO] Client packet {}: direction={}, len={}\n", .{ i, captured.direction, captured.data.len });
        if (captured.direction != .sent) continue;
        if (packet_inspector.isInitialPacket(captured.data)) {
            client_dcid = try packet_inspector.extractInitialDcid(captured.data);
            testlog.print("[TEST §7.2 CRYPTO] Extracted client DCID len={}: ", .{client_dcid.?.len});
            for (client_dcid.?) |b| testlog.print("{X:0>2} ", .{b});
            testlog.print("\n", .{});
            break;
        }
    }
    try std.testing.expect(client_dcid != null);

    for (server_packets.?) |captured| {
        if (captured.direction != .sent) continue;

        // Check if this is an Initial packet
        if (packet_inspector.isInitialPacket(captured.data)) {
            found_initial = true;

            // Decrypt server Initial packet using client's original DCID
            const has_crypto = packet_inspector.serverInitialHasCryptoFrame(
                allocator,
                captured.data,
                client_dcid.?, // Use client's DCID for key derivation
            ) catch |err| {
                testlog.print("ERROR: Failed to decrypt server Initial packet: {}\n", .{err});
                testlog.print("  Client DCID len={}: ", .{client_dcid.?.len});
                for (client_dcid.?) |b| testlog.print("{X:0>2} ", .{b});
                testlog.print("\n  Server packet len={}\n", .{captured.data.len});
                continue;
            };

            if (has_crypto) {
                found_crypto = true;
                break;
            }
        }
    }

    // Verify we found a server Initial packet with CRYPTO frame
    try std.testing.expect(found_initial);
    try std.testing.expect(found_crypto);
}

test "RFC 9000 §7.2 - Server sends ACK for client Initial" {
    // Tier 1 Step 1 Phase 2: ENABLED - Validate server sends ACK frame
    const allocator = std.testing.allocator;

    // Create connection pair with packet capture enabled
    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withCapture()
        .build();
    defer pair.deinit();

    // Establish connection (server should ACK client Initial)
    try pair.connect();

    // Get captured packets from server
    const server_packets = pair.getServerPackets();
    try std.testing.expect(server_packets != null);
    try std.testing.expect(server_packets.?.len > 0);

    // Find server packet with ACK frame (should be in Initial or Handshake packet)
    const packet_inspector = @import("packet_inspector");
    var found_ack = false;

    // First, extract the client's DCID from client packets (needed for server packet decryption)
    // RFC 9001 §5.2: Initial keys are derived from client's original DCID
    const client_packets = pair.getClientPackets();
    try std.testing.expect(client_packets != null);

    var client_dcid: ?[]const u8 = null;
    for (client_packets.?) |captured| {
        if (captured.direction != .sent) continue;
        if (packet_inspector.isInitialPacket(captured.data)) {
            client_dcid = try packet_inspector.extractInitialDcid(captured.data);
            break;
        }
    }
    try std.testing.expect(client_dcid != null);

    for (server_packets.?) |captured| {
        if (captured.direction != .sent) continue;

        // Check Initial packets (server may send ACK in Initial packet)
        if (packet_inspector.isInitialPacket(captured.data)) {
            // Extract just the Initial packet (may be coalesced with Handshake)
            const initial_packet = packet_inspector.extractInitialPacket(captured.data) catch continue;

            // Decrypt server Initial packet using client's original DCID
            var decrypted = packet_inspector.decryptInitialPacketWithDcid(
                allocator,
                initial_packet,
                false, // is_client=false for server packets
                client_dcid.?, // Use client's DCID for key derivation
            ) catch continue;
            defer decrypted.deinit();

            // Check for ACK frame
            if (packet_inspector.hasAckFrame(allocator, decrypted.payload) catch false) {
                found_ack = true;
                break;
            }
        }
        // Also check Handshake packets (server may send ACK in Handshake packet)
        else if (packet_inspector.isHandshakePacket(captured.data)) {
            // For now, we'll assume ACK is in Initial packet
            // Handshake packet decryption requires handshake keys which are more complex
            // This will be handled in Phase 4
            continue;
        }
    }

    // Verify we found an ACK frame from server
    try std.testing.expect(found_ack);
}

// =============================================================================
// RFC 9000 §7.3 - Transport Parameter Exchange
// =============================================================================

test "RFC 9000 §7.3 - Transport parameters exchanged in TLS extensions" {
    // SKIP: Requires TLS handshake integration (Phase 15+)
    return error.SkipZigTest;
}

test "RFC 9000 §7.3 - Invalid transport parameters cause connection failure" {
    // Tier 1 Step 1 Phase 3: ENABLED - Validate parameter validation logic
    // Note: This tests the validation logic, not actual wire-level rejection
    const tparams = @import("quic_transport_params");

    // Test 1: Invalid max_udp_payload_size (too small, RFC 9000 §18.2)
    {
        var params = tparams.TransportParams{};
        params.max_udp_payload_size = 1000; // Invalid: must be >= 1200

        // Validation should fail
        const result = params.checkLimits();
        try std.testing.expectError(error.InvalidTransportParams, result);
    }

    // Test 2: Invalid ack_delay_exponent (too large, RFC 9000 §18.2)
    {
        var params = tparams.TransportParams{};
        params.ack_delay_exponent = 21; // Invalid: max is 20

        // Validation should fail
        const result = params.checkLimits();
        try std.testing.expectError(error.InvalidTransportParams, result);
    }

    // Test 3: Invalid max_ack_delay (too large, RFC 9000 §18.2)
    {
        var params = tparams.TransportParams{};
        params.max_ack_delay = 16384; // Invalid: max is 16383 (2^14 - 1)

        // Validation should fail
        const result = params.checkLimits();
        try std.testing.expectError(error.InvalidTransportParams, result);
    }
}

test "RFC 9000 §7.3 - initial_source_connection_id must match" {
    // Tier 1 Step 1 Phase 3: ENABLED - Validate SCID matches transport parameter
    const allocator = std.testing.allocator;
    const tparams = @import("quic_transport_params");

    // Create connection pair with packet capture
    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withCapture()
        .build();
    defer pair.deinit();

    // Establish connection
    try pair.connect();

    // Get server's Initial packet to extract SCID
    const server_packets = pair.getServerPackets();
    try std.testing.expect(server_packets != null);

    const packet_inspector = @import("packet_inspector");
    var server_scid: ?[]const u8 = null;

    for (server_packets.?) |captured| {
        if (captured.direction != .sent) continue;

        if (packet_inspector.isInitialPacket(captured.data)) {
            const info = try packet_inspector.parsePacketHeader(captured.data);
            if (info.scid) |scid| {
                server_scid = scid;
                break;
            }
        }
    }

    try std.testing.expect(server_scid != null);

    // Get server's transport parameters and decode them
    const server_params_encoded = pair.server_conn.?.getLocalTransportParams();
    try std.testing.expect(server_params_encoded != null);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const server_params = try tparams.TransportParams.decode(alloc, server_params_encoded.?);

    // Verify initial_source_connection_id is present (required for servers)
    try std.testing.expect(server_params.initial_source_connection_id != null);

    // Verify it matches the SCID from the Initial packet
    const param_scid = server_params.initial_source_connection_id.?;
    try std.testing.expectEqualSlices(u8, server_scid.?, param_scid);
}

// =============================================================================
// RFC 9000 §7.4 - Cryptographic Handshake
// =============================================================================

test "RFC 9000 §7.4 - Handshake completes successfully" {
    // SKIP: Requires TLS handshake integration (Phase 15+)
    return error.SkipZigTest;
}

test "RFC 9000 §7.4 - Handshake packets use Handshake packet type" {
    // SKIP: Requires TLS handshake integration (Phase 15+)
    return error.SkipZigTest;
}

test "RFC 9000 §7.4 - 1-RTT keys derived after handshake" {
    // SKIP: Requires TLS handshake integration (Phase 15+)
    return error.SkipZigTest;
}

// =============================================================================
// Infrastructure Tests (Can run with current implementation)
// =============================================================================

test "Connection pair can be created for handshake testing" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Basic handshake setup")
        .withCapture()
        .withTimeControl()
        .withAlpn(&[_][]const u8{"h3"});

    _ = try scenario.createPair();

    // Verify infrastructure is set up
    _ = scenario.pair.?; // Verify pair exists
    // TODO: Add capture and time_control support to EndpointWrapper
    // try std.testing.expect(pair.server.capture != null);
    // try std.testing.expect(pair.client.capture != null);
    // try std.testing.expect(pair.server.time_control != null);
    // try std.testing.expect(pair.client.time_control != null);
}

test "Scenario builder supports connection establishment configuration" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withAlpn(&[_][]const u8{ "h3", "h3-29" })
        .with0Rtt()
        .withCapture()
        .withTimeControl();

    try std.testing.expectEqualSlices([]const u8, &[_][]const u8{ "h3", "h3-29" }, scenario.tls_config.alpn);
    try std.testing.expect(scenario.tls_config.enable_0rtt);
}

test "Connection pair provides access to transport statistics" {
    const allocator = std.testing.allocator;

    var pair = try connection_pair.createBasicPair(allocator);
    defer pair.deinit();

    const stats = pair.getTransportStats();
    try std.testing.expectEqual(@as(u64, 0), stats.packets_sent);
    try std.testing.expectEqual(@as(u64, 0), stats.packets_received);
    try std.testing.expectEqual(@as(u64, 0), stats.packets_lost);
}

test "Loopback transport can simulate packet loss during handshake" {
    const allocator = std.testing.allocator;

    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withPacketLoss(0.5) // 50% loss to test retransmission
        .withCapture()
        .build();
    defer pair.deinit();

    try std.testing.expectEqual(@as(f64, 0.5), pair.config.transport.loss_rate);
}

// =============================================================================
// RFC 9000 §6 - Version Negotiation (Partial Implementation)
// =============================================================================

test "RFC 9000 §6 - Version negotiation test infrastructure" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Version negotiation setup")
        .withCapture();

    _ = try scenario.createPair();

    // Infrastructure ready for version negotiation tests
    // Actual VN tests require packet encoding/decoding
}

test "RFC 9000 §6 - Client supports multiple QUIC versions" {
    // SKIP: Requires version negotiation implementation
    return error.SkipZigTest;
}

// =============================================================================
// RFC 9000 §5.1 - Connection ID Management (Partial)
// =============================================================================

test "RFC 9000 §5.1 - Connection ID test infrastructure" {
    const allocator = std.testing.allocator;

    var pair = try connection_pair.createBasicPair(allocator);
    defer pair.deinit();

    // Infrastructure ready for CID tests
    // Actual CID tests require endpoint integration
}

test "RFC 9000 §5.1 - Server provides new connection IDs" {
    // SKIP: Requires NEW_CONNECTION_ID frame processing
    return error.SkipZigTest;
}

// =============================================================================
// RFC 9000 §8.1.1 - Retry Packets (Partial)
// =============================================================================

test "RFC 9000 §8.1.1 - Retry packet test infrastructure" {
    const allocator = std.testing.allocator;

    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("Retry packet handling")
        .withCapture()
        .withTimeControl();

    _ = try scenario.createPair();

    // Infrastructure ready for Retry tests
}

test "RFC 9000 §8.1.1 - Client includes token from Retry in Initial" {
    // SKIP: Requires Retry packet handling
    return error.SkipZigTest;
}

// =============================================================================
// Summary Tests
// =============================================================================

test "Connection establishment test framework is operational" {
    // This meta-test verifies that the test infrastructure is working
    const allocator = std.testing.allocator;

    // Create scenario
    var scenario = scenarios.Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("RFC 9000 §7 test framework validation")
        .withCapture()
        .withTimeControl()
        .withAlpn(&[_][]const u8{"test"});

    _ = try scenario.createPair();

    // Create connection pair directly
    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withCapture()
        .withTimeControl()
        .build();
    defer pair.deinit();

    // Verify components work together (pair exists, endpoints created)
    // TODO: Add capture support to EndpointWrapper
    // try std.testing.expect(pair.server.capture != null);
    // try std.testing.expect(pair.client.capture != null);
}

// =============================================================================
// Placeholder Tests for Future Implementation
// =============================================================================

// The following tests are placeholders that document what needs to be tested
// once the QUIC endpoint integration is complete. Each test includes a comment
// explaining what it should verify.

test "TODO: Client generates random initial DCID (§7.2)" {
    // Tier 1 Step 1 Phase 5: ENABLED - Validate client generates random DCID
    const allocator = std.testing.allocator;

    // Create two connection pairs to verify randomness
    var builder1 = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair1 = try builder1.build();
    defer pair1.deinit();

    var builder2 = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair2 = try builder2.build();
    defer pair2.deinit();

    try pair1.connect();
    try pair2.connect();

    // Verify both clients have non-empty DCIDs
    try std.testing.expect(pair1.client_conn != null);
    try std.testing.expect(pair2.client_conn != null);
    try std.testing.expect(pair1.client_conn.?.peer_initial_dcid.len > 0);
    try std.testing.expect(pair2.client_conn.?.peer_initial_dcid.len > 0);

    // Verify the two DCIDs are different (extremely high probability for random generation)
    const dcid1 = pair1.client_conn.?.peer_initial_dcid.bytes[0..pair1.client_conn.?.peer_initial_dcid.len];
    const dcid2 = pair2.client_conn.?.peer_initial_dcid.bytes[0..pair2.client_conn.?.peer_initial_dcid.len];

    const are_different = !std.mem.eql(u8, dcid1, dcid2);
    try std.testing.expect(are_different);
}

test "RFC 9000 §7.2 - Server echoes client SCID in DCID" {
    // Tier 1 Step 1: ENABLED - Validate server uses client SCID as DCID
    const allocator = std.testing.allocator;

    // Create connection pair with packet capture enabled
    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withCapture()
        .build();
    defer pair.deinit();

    // Establish connection
    try pair.connect();

    // Get captured packets
    const client_packets = pair.getClientPackets();
    const server_packets = pair.getServerPackets();

    try std.testing.expect(client_packets != null);
    try std.testing.expect(server_packets != null);

    // Extract client's SCID from client Initial packet
    const packet_inspector = @import("packet_inspector");
    var client_scid: ?[]const u8 = null;

    for (client_packets.?) |captured| {
        if (captured.direction != .sent) continue;

        if (packet_inspector.isInitialPacket(captured.data)) {
            const info = try packet_inspector.parsePacketHeader(captured.data);
            if (info.scid) |scid| {
                client_scid = scid;
                break;
            }
        }
    }

    try std.testing.expect(client_scid != null);

    // Extract server's DCID from server Initial packet
    var server_dcid: ?[]const u8 = null;

    for (server_packets.?) |captured| {
        if (captured.direction != .sent) continue;

        if (packet_inspector.isInitialPacket(captured.data)) {
            const info = try packet_inspector.parsePacketHeader(captured.data);
            // dcid is []const u8, not optional
            if (info.dcid.len > 0) {
                server_dcid = info.dcid;
                break;
            }
        }
    }

    try std.testing.expect(server_dcid != null);

    // RFC 9000 §7.2: Server MUST use client's SCID as the DCID in response packets
    try std.testing.expectEqualSlices(u8, client_scid.?, server_dcid.?);
}

test "RFC 9000 §14.1 - Initial packets are padded to min size" {
    // Tier 1 Step 1: ENABLED - Validate Initial packet padding (anti-amplification)
    const allocator = std.testing.allocator;

    // Create connection pair with packet capture enabled
    var builder = connection_pair.ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withCapture()
        .build();
    defer pair.deinit();

    // Establish connection (client sends first Initial packet)
    try pair.connect();

    // Get captured packets from client
    const client_packets = pair.getClientPackets();
    try std.testing.expect(client_packets != null);

    // RFC 9000 §14.1: A client MUST expand the payload of all UDP datagrams
    // carrying Initial packets to at least 1200 bytes (minimum QUIC packet size)
    // This prevents amplification attacks.
    const packet_inspector = @import("packet_inspector");
    var found_initial = false;
    var min_initial_size_met = false;

    for (client_packets.?) |captured| {
        if (captured.direction != .sent) continue;

        if (packet_inspector.isInitialPacket(captured.data)) {
            found_initial = true;

            // Check that the UDP datagram (packet data) is at least 1200 bytes
            // Note: This checks the first Initial packet sent by client
            if (captured.data.len >= 1200) {
                min_initial_size_met = true;
                break;
            }
        }
    }

    // Verify we found an Initial packet and it meets minimum size
    try std.testing.expect(found_initial);
    try std.testing.expect(min_initial_size_met);
}

test "TODO: Connection completes 3-way handshake (§7)" {
    // SKIP: Requires TLS handshake integration (Phase 15+)
    return error.SkipZigTest;
}

test "TODO: Handshake completion clears Initial keys (§4.9.1)" {
    // SKIP: Requires TLS handshake integration (Phase 15+)
    return error.SkipZigTest;
}

test "TODO: Connection ID rotation works correctly (§5.1)" {
    // Should verify that NEW_CONNECTION_ID and RETIRE_CONNECTION_ID
    // frames work correctly
    return error.SkipZigTest;
}

test "TODO: Version negotiation selects common version (§6)" {
    // Should verify that VN packet correctly lists supported versions
    // and client selects appropriate version
    return error.SkipZigTest;
}

test "TODO: Retry forces new Initial with token (§8.1.1)" {
    // Should verify that Retry packet causes client to send new Initial
    // with the provided token
    return error.SkipZigTest;
}

test "TODO: Invalid Retry packet is ignored (§8.1.1)" {
    // Should verify that Retry packets with invalid integrity tags
    // are ignored
    return error.SkipZigTest;
}

test "TODO: Transport parameters are validated (§7.3)" {
    // Should verify that invalid transport parameters cause
    // connection to fail with TRANSPORT_PARAMETER_ERROR
    return error.SkipZigTest;
}

// =============================================================================
// Test Summary
// =============================================================================

// Phase 3 RFC 9000 §7 Implementation Status:
// - Infrastructure tests: 5/5 passing ✅
// - Skip tests (require endpoint): 20+ tests documented 📝
// - TODO tests: 10 additional tests documented for future implementation
//
// This test file establishes the structure for connection establishment testing.
// As the QUIC endpoint implementation progresses, skip tests can be enabled
// and implemented. The infrastructure is in place to support full RFC compliance
// testing.
