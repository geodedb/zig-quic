//! Endpoint-Loopback Integration Helpers
//!
//! This module provides helper utilities for testing the production QUIC endpoint
//! with loopback transport. These helpers make it easy to enable the 474 skip tests
//! by abstracting common patterns for endpoint creation, connection establishment,
//! and test scenarios.
//!
//! ## Purpose
//!
//! With Phase 8 (a/b/c) complete, the production endpoint now uses the Transport
//! abstraction. This enables deterministic testing using LoopbackTransport instead
//! of real UDP sockets. These helpers bridge the gap between the test framework
//! (Phases 1-7) and the production endpoint.
//!
//! ## Usage Pattern
//!
//! ```zig
//! test "RFC 9000 §7 - Basic handshake" {
//!     var helper = try EndpointLoopbackHelper.init(testing.allocator);
//!     defer helper.deinit();
//!
//!     // Configure loopback with fault injection
//!     helper.loopback_config.loss_rate = 0.05;  // 5% packet loss
//!
//!     // Create client and server endpoints
//!     var client = try helper.createClientEndpoint();
//!     var server = try helper.createServerEndpoint();
//!
//!     // Establish connection
//!     var conn = try helper.connectClientToServer(client, server);
//!
//!     // Wait for handshake
//!     try helper.waitForHandshake(conn, 5000); // 5 second timeout
//!
//!     // Test assertions
//!     try testing.expect(conn.isHandshakeComplete());
//! }
//! ```

const std = @import("std");
const testing = std.testing;
const loopback = @import("loopback.zig");
const harness = @import("harness.zig");

// Import production endpoint (once integrated with transport abstraction)
// const Endpoint = @import("../../src/quic/endpoint.zig").Endpoint;
// const Connection = @import("../../src/quic/conn.zig").Connection;
// const QuicConfig = @import("../../src/quic/config.zig").QuicConfig;

/// Configuration for loopback transport
pub const LoopbackConfig = struct {
    loss_rate: f32 = 0.0,          // 0-1 packet loss probability
    corruption_rate: f32 = 0.0,    // 0-1 corruption probability
    delay_ms: u32 = 0,             // Base delay in milliseconds
    jitter_ms: u32 = 0,            // Delay jitter in milliseconds
    max_packet_size: usize = 1472, // MTU (Ethernet - headers)
};

/// Configuration for endpoint creation
pub const EndpointConfig = struct {
    role: enum { Client, Server },
    max_idle_timeout_ms: u64 = 30000,
    initial_max_data: u64 = 1048576,  // 1MB
    max_concurrent_bidi_streams: u64 = 100,
    enable_0rtt: bool = false,
    alpn: []const []const u8 = &[_][]const u8{"test"},
};

/// Helper for endpoint-loopback integration testing
pub const EndpointLoopbackHelper = struct {
    allocator: std.mem.Allocator,
    loopback_transport: ?*loopback.LoopbackTransport,
    loopback_config: LoopbackConfig,

    /// Initialize helper
    pub fn init(allocator: std.mem.Allocator) !EndpointLoopbackHelper {
        return EndpointLoopbackHelper{
            .allocator = allocator,
            .loopback_transport = null,
            .loopback_config = .{},
        };
    }

    /// Deinitialize helper and clean up resources
    pub fn deinit(self: *EndpointLoopbackHelper) void {
        if (self.loopback_transport) |transport| {
            transport.deinit();
            self.allocator.destroy(transport);
        }
    }

    /// Create and initialize loopback transport
    pub fn createLoopbackTransport(self: *EndpointLoopbackHelper) !*loopback.LoopbackTransport {
        if (self.loopback_transport == null) {
            const transport = try self.allocator.create(loopback.LoopbackTransport);
            errdefer self.allocator.destroy(transport);

            transport.* = try loopback.LoopbackTransport.init(self.allocator, self.loopback_config);
            self.loopback_transport = transport;
        }
        return self.loopback_transport.?;
    }

    /// Create client endpoint with loopback transport
    ///
    /// NOTE: This is a stub showing the intended API. Implementation requires
    /// production endpoint integration (Phase 8c complete, now available).
    pub fn createClientEndpoint(self: *EndpointLoopbackHelper) !void {
        _ = self;
        // TODO: Implement once endpoint integration is validated
        // const transport = try self.createLoopbackTransport();
        // const config = self.buildQuicConfig(.Client);
        // return try Endpoint.initWithTransport(self.allocator, transport.asTransport(), &config);
        return error.NotImplementedYet;
    }

    /// Create server endpoint with loopback transport
    ///
    /// NOTE: This is a stub showing the intended API. Implementation requires
    /// production endpoint integration (Phase 8c complete, now available).
    pub fn createServerEndpoint(self: *EndpointLoopbackHelper) !void {
        _ = self;
        // TODO: Implement once endpoint integration is validated
        // const transport = try self.createLoopbackTransport();
        // const config = self.buildQuicConfig(.Server);
        // return try Endpoint.initWithTransport(self.allocator, transport.asTransport(), &config);
        return error.NotImplementedYet;
    }

    /// Build QuicConfig from EndpointConfig
    ///
    /// NOTE: This is a stub. Actual implementation would convert EndpointConfig
    /// to the production QuicConfig format.
    fn buildQuicConfig(self: *EndpointLoopbackHelper, role: enum { Client, Server }) void {
        _ = self;
        _ = role;
        // TODO: Convert EndpointConfig to QuicConfig
    }

    /// Connect client to server endpoint
    ///
    /// NOTE: This is a stub showing the intended API.
    pub fn connectClientToServer(self: *EndpointLoopbackHelper, client: anytype, server: anytype) !void {
        _ = self;
        _ = client;
        _ = server;
        // TODO: Implement connection establishment
        // return try client.connectTo("server:4433");
        return error.NotImplementedYet;
    }

    /// Wait for handshake completion with timeout
    ///
    /// NOTE: This is a stub showing the intended API.
    pub fn waitForHandshake(self: *EndpointLoopbackHelper, conn: anytype, timeout_ms: u64) !void {
        _ = self;
        _ = conn;
        _ = timeout_ms;
        // TODO: Poll both endpoints until handshake completes or timeout
        return error.NotImplementedYet;
    }

    /// Advance mock time for testing timeouts
    ///
    /// This is useful for testing PTO, idle timeout, and other time-based logic
    /// without waiting for real time to pass.
    pub fn advanceTime(self: *EndpointLoopbackHelper, ms: u64) !void {
        const transport = self.loopback_transport orelse return error.TransportNotInitialized;
        // TODO: Implement time advancement in loopback transport
        _ = transport;
        _ = ms;
    }
};

/// Helper function to create a basic client-server test scenario
///
/// This provides a simple way to set up a client-server pair for testing.
/// The returned helper manages cleanup automatically.
pub fn createBasicScenario(allocator: std.mem.Allocator) !EndpointLoopbackHelper {
    var helper = try EndpointLoopbackHelper.init(allocator);
    errdefer helper.deinit();

    // Default configuration suitable for most tests
    helper.loopback_config = .{
        .loss_rate = 0.0,
        .delay_ms = 0,
    };

    return helper;
}

/// Helper function to create a scenario with packet loss
///
/// Useful for testing loss recovery and retransmission logic.
pub fn createLossyScenario(allocator: std.mem.Allocator, loss_rate: f32) !EndpointLoopbackHelper {
    var helper = try EndpointLoopbackHelper.init(allocator);
    errdefer helper.deinit();

    helper.loopback_config = .{
        .loss_rate = loss_rate,
        .delay_ms = 10,
        .jitter_ms = 5,
    };

    return helper;
}

/// Helper function to create a scenario with network delay
///
/// Useful for testing RTT estimation and PTO calculations.
pub fn createDelayedScenario(allocator: std.mem.Allocator, delay_ms: u32, jitter_ms: u32) !EndpointLoopbackHelper {
    var helper = try EndpointLoopbackHelper.init(allocator);
    errdefer helper.deinit();

    helper.loopback_config = .{
        .delay_ms = delay_ms,
        .jitter_ms = jitter_ms,
    };

    return helper;
}

// =============================================================================
// Infrastructure Tests
// =============================================================================

test "EndpointLoopbackHelper initialization" {
    var helper = try EndpointLoopbackHelper.init(testing.allocator);
    defer helper.deinit();

    try testing.expect(helper.loopback_transport == null);
    try testing.expectEqual(@as(f32, 0.0), helper.loopback_config.loss_rate);
}

test "createBasicScenario provides clean defaults" {
    var helper = try createBasicScenario(testing.allocator);
    defer helper.deinit();

    try testing.expectEqual(@as(f32, 0.0), helper.loopback_config.loss_rate);
    try testing.expectEqual(@as(u32, 0), helper.loopback_config.delay_ms);
}

test "createLossyScenario configures packet loss" {
    var helper = try createLossyScenario(testing.allocator, 0.1);
    defer helper.deinit();

    try testing.expectEqual(@as(f32, 0.1), helper.loopback_config.loss_rate);
}

test "createDelayedScenario configures delay" {
    var helper = try createDelayedScenario(testing.allocator, 50, 10);
    defer helper.deinit();

    try testing.expectEqual(@as(u32, 50), helper.loopback_config.delay_ms);
    try testing.expectEqual(@as(u32, 10), helper.loopback_config.jitter_ms);
}
