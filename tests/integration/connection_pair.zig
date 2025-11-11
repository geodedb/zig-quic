//! Connection Pair Fixture for Integration Testing
//!
//! Provides a convenient fixture for creating linked client-server connections
//! with automatic loopback transport wiring and synchronized packet delivery.
//!
//! RFC References:
//! - RFC 9000 §7: Connection Establishment
//! - RFC 9001: Using TLS to Secure QUIC

const std = @import("std");
const harness = @import("harness");  // Module import (configured in build.zig)
const loopback = @import("loopback");  // Module import (configured in build.zig)
const tls_helpers = @import("tls_helpers");  // Module import (configured in build.zig)
const endpoint_loopback_helpers = @import("endpoint_loopback_helpers");  // Module import (configured in build.zig)

/// Configuration for connection pair
pub const ConnectionPairConfig = struct {
    /// Transport configuration
    transport: loopback.LoopbackTransport.Config = .{},

    /// Server TLS configuration
    server_tls: tls_helpers.TlsTestConfig = .{},

    /// Client TLS configuration
    client_tls: tls_helpers.TlsTestConfig = .{},

    /// Enable packet capture on both endpoints
    enable_capture: bool = false,

    /// Enable time control on both endpoints
    enable_time_control: bool = false,

    /// Automatic handshake completion timeout (0 = no auto handshake)
    auto_handshake_timeout_ms: u64 = 0,
};

/// Linked client-server connection pair
pub const ConnectionPair = struct {
    /// Allocator
    allocator: std.mem.Allocator,

    /// Loopback transport for packet exchange
    transport: *loopback.LoopbackTransport,

    /// Server endpoint wrapper (Phase 14: Uses real Endpoint!)
    server: endpoint_loopback_helpers.EndpointWrapper,

    /// Client endpoint wrapper (Phase 14: Uses real Endpoint!)
    client: endpoint_loopback_helpers.EndpointWrapper,

    /// Loopback transport adapter for client (SideA)
    client_adapter: endpoint_loopback_helpers.LoopbackTransportAdapter,

    /// Loopback transport adapter for server (SideB)
    server_adapter: endpoint_loopback_helpers.LoopbackTransportAdapter,

    /// Server connection (once established)
    server_conn: ?*endpoint_loopback_helpers.Connection,

    /// Client connection (once established)
    client_conn: ?*endpoint_loopback_helpers.Connection,

    /// Configuration
    config: ConnectionPairConfig,

    /// Initialize a connection pair (Phase 14: Real endpoints!)
    pub fn init(allocator: std.mem.Allocator, config: ConnectionPairConfig) !*ConnectionPair {
        const self = try allocator.create(ConnectionPair);
        errdefer allocator.destroy(self);

        // Create loopback transport
        const transport = try loopback.LoopbackTransport.init(allocator, config.transport);
        errdefer transport.deinit();

        // Create loopback transport adapters
        // Client = SideA, Server = SideB
        var client_adapter = endpoint_loopback_helpers.LoopbackTransportAdapter.init(
            transport,
            .SideA,
        );
        var server_adapter = endpoint_loopback_helpers.LoopbackTransportAdapter.init(
            transport,
            .SideB,
        );

        // Create client endpoint wrapper (Phase 14: Real Endpoint!)
        var client_wrapper = try endpoint_loopback_helpers.EndpointWrapper.init(
            allocator,
            &client_adapter,
            .Client,
        );
        errdefer client_wrapper.deinit();

        // Create server endpoint wrapper (Phase 14: Real Endpoint!)
        var server_wrapper = try endpoint_loopback_helpers.EndpointWrapper.init(
            allocator,
            &server_adapter,
            .Server,
        );
        errdefer server_wrapper.deinit();

        self.* = .{
            .allocator = allocator,
            .transport = transport,
            .client = client_wrapper,
            .server = server_wrapper,
            .client_adapter = client_adapter,
            .server_adapter = server_adapter,
            .server_conn = null,
            .client_conn = null,
            .config = config,
        };

        return self;
    }

    /// Clean up connection pair (Phase 14: Cleans up real endpoints)
    pub fn deinit(self: *ConnectionPair) void {
        if (self.server_conn) |_| {
            // Connection cleanup handled by endpoint
        }
        if (self.client_conn) |_| {
            // Connection cleanup handled by endpoint
        }

        // Clean up endpoint wrappers (Phase 14: Real endpoints!)
        self.client.deinit();
        self.server.deinit();

        // Clean up loopback transport
        self.transport.deinit();

        self.allocator.destroy(self);
    }

    /// Establish connection between client and server (Phase 14: Real implementation!)
    pub fn connect(self: *ConnectionPair) !void {
        // Phase 14: Real connection establishment using production Endpoint!

        // 1. Create client connection (doesn't send Initial packet yet)
        const client_conn = try self.client.endpoint.connectClient("127.0.0.1:443");

        // 2. Send Initial packet with ClientHello to start handshake
        try self.client.endpoint.clientSendInitialProbe(client_conn);

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

            std.Thread.sleep(10 * std.time.ns_per_ms);
        }

        if (self.server_conn == null) {
            return error.ServerConnectionTimeout;
        }

        self.client_conn = client_conn;
    }

    /// Exchange packets between client and server (Phase 14: Real implementation!)
    pub fn exchangePackets(self: *ConnectionPair) !void {
        // Phase 14: Use endpoint poll() to drive packet delivery!
        // The endpoints will call transport.recv() internally, which pulls from loopback

        // Poll both endpoints to send/receive packets
        // Use timeout_ms=0 for non-blocking poll
        try self.client.endpoint.poll(0);
        try self.server.endpoint.poll(0);
    }

    /// Wait for TLS handshake to complete on both sides (Phase 14: Real implementation!)
    pub fn waitForHandshake(self: *ConnectionPair, timeout_ms: u64) !void {
        // Phase 14: Poll real connections for handshake completion!
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
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    /// Run until both endpoints are idle (no packets in flight)
    pub fn runUntilIdle(self: *ConnectionPair) !void {
        const max_iterations = 1000;
        var iterations: usize = 0;

        while (iterations < max_iterations) : (iterations += 1) {
            try self.exchangePackets();

            // Check if idle
            if (self.transport.getAtoBQueueLen() == 0 and
                self.transport.getBtoAQueueLen() == 0)
            {
                break;
            }

            // Small delay to allow packet delivery
            std.time.sleep(1 * std.time.ns_per_ms);
        }

        if (iterations >= max_iterations) {
            return error.TimeoutWaitingForIdle;
        }
    }

    /// Advance time on both endpoints
    pub fn advanceTime(self: *ConnectionPair, ms: u64) void {
        self.server.advanceTime(ms);
        self.client.advanceTime(ms);
    }

    /// Get client-side captured packets
    pub fn getClientPackets(self: *ConnectionPair) ?[]const harness.CapturedPacket {
        return self.client.getCapturedPackets();
    }

    /// Get server-side captured packets
    pub fn getServerPackets(self: *ConnectionPair) ?[]const harness.CapturedPacket {
        return self.server.getCapturedPackets();
    }

    /// Get transport statistics
    pub fn getTransportStats(self: *ConnectionPair) loopback.LoopbackTransport.Stats {
        return self.transport.stats;
    }
};

/// Builder pattern for connection pair creation
pub const ConnectionPairBuilder = struct {
    config: ConnectionPairConfig,
    allocator: std.mem.Allocator,

    /// Initialize builder
    pub fn init(allocator: std.mem.Allocator) ConnectionPairBuilder {
        return .{
            .config = .{},
            .allocator = allocator,
        };
    }

    /// Set packet loss rate
    pub fn withPacketLoss(self: *ConnectionPairBuilder, rate: f64) *ConnectionPairBuilder {
        self.config.transport.loss_rate = rate;
        return self;
    }

    /// Set packet delay
    pub fn withDelay(self: *ConnectionPairBuilder, delay_ms: u32, jitter_ms: u32) *ConnectionPairBuilder {
        self.config.transport.delay_ms = delay_ms;
        self.config.transport.jitter_ms = jitter_ms;
        return self;
    }

    /// Set MTU
    pub fn withMtu(self: *ConnectionPairBuilder, mtu: u16) *ConnectionPairBuilder {
        self.config.transport.mtu = mtu;
        return self;
    }

    /// Enable packet capture
    pub fn withCapture(self: *ConnectionPairBuilder) *ConnectionPairBuilder {
        self.config.enable_capture = true;
        return self;
    }

    /// Enable time control
    pub fn withTimeControl(self: *ConnectionPairBuilder) *ConnectionPairBuilder {
        self.config.enable_time_control = true;
        return self;
    }

    /// Set ALPN protocol
    pub fn withAlpn(self: *ConnectionPairBuilder, alpn: []const []const u8) *ConnectionPairBuilder {
        self.config.server_tls.alpn = alpn;
        self.config.client_tls.alpn = alpn;
        return self;
    }

    /// Enable 0-RTT
    pub fn with0Rtt(self: *ConnectionPairBuilder) *ConnectionPairBuilder {
        self.config.server_tls.enable_0rtt = true;
        self.config.client_tls.enable_0rtt = true;
        return self;
    }

    /// Enable automatic handshake
    pub fn withAutoHandshake(self: *ConnectionPairBuilder, timeout_ms: u64) *ConnectionPairBuilder {
        self.config.auto_handshake_timeout_ms = timeout_ms;
        return self;
    }

    /// Build the connection pair
    pub fn build(self: *ConnectionPairBuilder) !*ConnectionPair {
        return try ConnectionPair.init(self.allocator, self.config);
    }
};

/// Quick helper to create a basic connection pair
pub fn createBasicPair(allocator: std.mem.Allocator) !*ConnectionPair {
    return try ConnectionPair.init(allocator, .{});
}

/// Quick helper to create a connection pair with packet capture
pub fn createPairWithCapture(allocator: std.mem.Allocator) !*ConnectionPair {
    return try ConnectionPair.init(allocator, .{
        .enable_capture = true,
    });
}

/// Quick helper to create a connection pair with packet loss
pub fn createPairWithLoss(allocator: std.mem.Allocator, loss_rate: f64) !*ConnectionPair {
    return try ConnectionPair.init(allocator, .{
        .transport = .{ .loss_rate = loss_rate },
    });
}

// Tests

test "ConnectionPair - basic initialization" {
    const allocator = std.testing.allocator;

    var pair = try ConnectionPair.init(allocator, .{});
    defer pair.deinit();

    // Transport, server, and client created successfully (verified by init not erroring)
    try std.testing.expect(pair.server_conn == null);
    try std.testing.expect(pair.client_conn == null);
}

test "ConnectionPair - with packet capture" {
    const allocator = std.testing.allocator;

    var pair = try ConnectionPair.init(allocator, .{
        .enable_capture = true,
    });
    defer pair.deinit();

    try std.testing.expect(pair.server.capture != null);
    try std.testing.expect(pair.client.capture != null);
}

test "ConnectionPair - with time control" {
    const allocator = std.testing.allocator;

    var pair = try ConnectionPair.init(allocator, .{
        .enable_time_control = true,
    });
    defer pair.deinit();

    try std.testing.expect(pair.server.time_control != null);
    try std.testing.expect(pair.client.time_control != null);

    // Test time advancement
    pair.advanceTime(1000);
    try std.testing.expectEqual(pair.server.time_control.?.now_ms, pair.client.time_control.?.now_ms);
}

test "ConnectionPairBuilder - fluent API" {
    const allocator = std.testing.allocator;

    var builder = ConnectionPairBuilder.init(allocator);
    var pair = try builder
        .withPacketLoss(0.1)
        .withDelay(10, 5)
        .withMtu(1400)
        .withCapture()
        .withTimeControl()
        .build();
    defer pair.deinit();

    try std.testing.expectEqual(@as(f64, 0.1), pair.config.transport.loss_rate);
    try std.testing.expectEqual(@as(u32, 10), pair.config.transport.delay_ms);
    try std.testing.expectEqual(@as(u32, 5), pair.config.transport.jitter_ms);
    try std.testing.expectEqual(@as(u16, 1400), pair.config.transport.mtu);
    try std.testing.expect(pair.config.enable_capture);
    try std.testing.expect(pair.config.enable_time_control);
}

test "ConnectionPair - quick helper functions" {
    const allocator = std.testing.allocator;

    // Basic pair
    var pair1 = try createBasicPair(allocator);
    defer pair1.deinit();
    // Server created successfully (verified by init not erroring)

    // Pair with capture
    var pair2 = try createPairWithCapture(allocator);
    defer pair2.deinit();
    try std.testing.expect(pair2.server.capture != null);

    // Pair with loss
    var pair3 = try createPairWithLoss(allocator, 0.05);
    defer pair3.deinit();
    try std.testing.expectEqual(@as(f64, 0.05), pair3.config.transport.loss_rate);
}

test "ConnectionPair - transport statistics access" {
    const allocator = std.testing.allocator;

    var pair = try ConnectionPair.init(allocator, .{});
    defer pair.deinit();

    const stats = pair.getTransportStats();
    try std.testing.expectEqual(@as(u64, 0), stats.packets_sent);
    try std.testing.expectEqual(@as(u64, 0), stats.packets_received);
}

test "ConnectionPairBuilder - with ALPN" {
    const allocator = std.testing.allocator;

    const alpn = [_][]const u8{"h3"};
    var builder = ConnectionPairBuilder.init(allocator);
    var pair = try builder.withAlpn(&alpn).build();
    defer pair.deinit();

    try std.testing.expectEqualSlices([]const u8, &alpn, pair.config.server_tls.alpn);
    try std.testing.expectEqualSlices([]const u8, &alpn, pair.config.client_tls.alpn);
}

test "ConnectionPairBuilder - with 0-RTT" {
    const allocator = std.testing.allocator;

    var builder = ConnectionPairBuilder.init(allocator);
    var pair = try builder.with0Rtt().build();
    defer pair.deinit();

    try std.testing.expect(pair.config.server_tls.enable_0rtt);
    try std.testing.expect(pair.config.client_tls.enable_0rtt);
}
