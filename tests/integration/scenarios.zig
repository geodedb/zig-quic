//! Test Scenario Builder for Integration Testing
//!
//! Provides fluent API for building QUIC test scenarios:
//! - Connection establishment patterns
//! - Data transfer sequences
//! - Error condition simulation
//! - Complex multi-step test flows
//!
//! RFC References:
//! - RFC 9000: QUIC Transport Protocol
//! - RFC 9001: Using TLS to Secure QUIC
//! - RFC 9002: QUIC Loss Detection and Congestion Control

const std = @import("std");
const harness = @import("harness");  // Module import (configured in build.zig)
const endpoint_loopback_helpers = @import("endpoint_loopback_helpers");  // Module import
const connection_pair = @import("connection_pair");  // Module import (configured in build.zig)
const loopback = @import("loopback");  // Module import (configured in build.zig)
const tls_helpers = @import("tls_helpers");  // Module import (configured in build.zig)

/// Test scenario builder
pub const Scenario = struct {
    /// Allocator
    allocator: std.mem.Allocator,

    /// Connection pair (once created)
    pair: ?*connection_pair.ConnectionPair,

    /// Transport configuration
    transport_config: loopback.LoopbackTransport.Config,

    /// TLS configuration
    tls_config: tls_helpers.TlsTestConfig,

    /// Enable packet capture
    capture_enabled: bool,

    /// Enable time control
    time_control_enabled: bool,

    /// Scenario metadata
    name: ?[]const u8,

    /// Initialize scenario builder
    pub fn init(allocator: std.mem.Allocator) Scenario {
        return .{
            .allocator = allocator,
            .pair = null,
            .transport_config = .{},
            .tls_config = .{},
            .capture_enabled = false,
            .time_control_enabled = false,
            .name = null,
        };
    }

    /// Clean up scenario
    pub fn deinit(self: *Scenario) void {
        if (self.pair) |pair| {
            pair.deinit();
        }
    }

    /// Set scenario name for debugging
    pub fn withName(self: *Scenario, name: []const u8) *Scenario {
        self.name = name;
        return self;
    }

    /// Configure packet loss rate
    pub fn withPacketLoss(self: *Scenario, rate: f64) *Scenario {
        self.transport_config.loss_rate = rate;
        return self;
    }

    /// Configure packet corruption rate
    pub fn withPacketCorruption(self: *Scenario, rate: f64) *Scenario {
        self.transport_config.corruption_rate = rate;
        return self;
    }

    /// Configure packet reordering rate
    pub fn withPacketReordering(self: *Scenario, rate: f64) *Scenario {
        self.transport_config.reordering_rate = rate;
        return self;
    }

    /// Configure network delay
    pub fn withDelay(self: *Scenario, delay_ms: u32, jitter_ms: u32) *Scenario {
        self.transport_config.delay_ms = delay_ms;
        self.transport_config.jitter_ms = jitter_ms;
        return self;
    }

    /// Configure MTU
    pub fn withMtu(self: *Scenario, mtu: u16) *Scenario {
        self.transport_config.mtu = mtu;
        return self;
    }

    /// Enable ECN marking
    pub fn withEcn(self: *Scenario) *Scenario {
        self.transport_config.enable_ecn = true;
        return self;
    }

    /// Enable packet capture
    pub fn withCapture(self: *Scenario) *Scenario {
        self.capture_enabled = true;
        return self;
    }

    /// Enable time control
    pub fn withTimeControl(self: *Scenario) *Scenario {
        self.time_control_enabled = true;
        return self;
    }

    /// Configure ALPN protocol
    pub fn withAlpn(self: *Scenario, alpn: []const []const u8) *Scenario {
        self.tls_config.alpn = alpn;
        return self;
    }

    /// Enable 0-RTT
    pub fn with0Rtt(self: *Scenario) *Scenario {
        self.tls_config.enable_0rtt = true;
        return self;
    }

    /// Create connection pair with current configuration
    pub fn createPair(self: *Scenario) !*Scenario {
        const config = connection_pair.ConnectionPairConfig{
            .transport = self.transport_config,
            .server_tls = self.tls_config,
            .client_tls = self.tls_config,
            .enable_capture = self.capture_enabled,
            .enable_time_control = self.time_control_enabled,
        };

        self.pair = try connection_pair.ConnectionPair.init(self.allocator, config);
        return self;
    }

    /// Establish connection (placeholder - requires endpoint integration)
    pub fn connect(self: *Scenario) !*Scenario {
        const pair = self.pair orelse return error.NoPairCreated;
        try pair.connect();
        return self;
    }

    /// Exchange packets between endpoints
    pub fn exchangePackets(self: *Scenario) !*Scenario {
        const pair = self.pair orelse return error.NoPairCreated;
        try pair.exchangePackets();
        return self;
    }

    /// Run until both endpoints are idle
    pub fn runUntilIdle(self: *Scenario) !*Scenario {
        const pair = self.pair orelse return error.NoPairCreated;
        try pair.runUntilIdle();
        return self;
    }

    /// Advance time on both endpoints
    pub fn advanceTime(self: *Scenario, ms: u64) *Scenario {
        if (self.pair) |pair| {
            pair.advanceTime(ms);
        }
        return self;
    }

    /// Get client captured packets
    pub fn getClientPackets(self: *Scenario) ?[]const harness.CapturedPacket {
        const pair = self.pair orelse return null;
        return pair.getClientPackets();
    }

    /// Get server captured packets
    pub fn getServerPackets(self: *Scenario) ?[]const harness.CapturedPacket {
        const pair = self.pair orelse return null;
        return pair.getServerPackets();
    }

    /// Get transport statistics
    pub fn getTransportStats(self: *Scenario) ?loopback.LoopbackTransport.Stats {
        const pair = self.pair orelse return null;
        return pair.getTransportStats();
    }

    /// Verify handshake completed (placeholder)
    pub fn expectHandshakeComplete(self: *Scenario) !*Scenario {
        const pair = self.pair orelse return error.NoPairCreated;
        _ = pair;
        // In real implementation, would check connection handshake state
        // For now, this is a placeholder
        return self;
    }

    /// Expect specific number of packets captured
    pub fn expectPacketCount(self: *Scenario, expected: usize) !*Scenario {
        const pair = self.pair orelse return error.NoPairCreated;
        const client_packets = pair.getClientPackets() orelse return error.CaptureNotEnabled;
        const server_packets = pair.getServerPackets() orelse return error.CaptureNotEnabled;

        const total = client_packets.len + server_packets.len;
        if (total != expected) {
            return error.PacketCountMismatch;
        }
        return self;
    }

    /// Expect packet loss occurred
    pub fn expectPacketLoss(self: *Scenario) !*Scenario {
        const pair = self.pair orelse return error.NoPairCreated;
        const stats = pair.getTransportStats();
        if (stats.packets_lost == 0) {
            return error.NoPacketLoss;
        }
        return self;
    }

    /// Expect no packet loss
    pub fn expectNoPacketLoss(self: *Scenario) !*Scenario {
        const pair = self.pair orelse return error.NoPairCreated;
        const stats = pair.getTransportStats();
        if (stats.packets_lost > 0) {
            return error.UnexpectedPacketLoss;
        }
        return self;
    }
};

/// Pre-configured scenario templates
pub const Templates = struct {
    /// Basic client-server connection scenario
    pub fn basicConnection(allocator: std.mem.Allocator) !*Scenario {
        var scenario = try allocator.create(Scenario);
        scenario.* = Scenario.init(allocator);
        _ = try scenario.createPair();
        return scenario;
    }

    /// Connection with packet capture enabled
    pub fn connectionWithCapture(allocator: std.mem.Allocator) !*Scenario {
        var scenario = try allocator.create(Scenario);
        scenario.* = Scenario.init(allocator);
        _ = scenario.withCapture();
        _ = try scenario.createPair();
        return scenario;
    }

    /// Connection with time control
    pub fn connectionWithTimeControl(allocator: std.mem.Allocator) !*Scenario {
        var scenario = try allocator.create(Scenario);
        scenario.* = Scenario.init(allocator);
        _ = scenario.withTimeControl();
        _ = try scenario.createPair();
        return scenario;
    }

    /// Connection with packet loss
    pub fn lossyConnection(allocator: std.mem.Allocator, loss_rate: f64) !*Scenario {
        var scenario = try allocator.create(Scenario);
        scenario.* = Scenario.init(allocator);
        _ = scenario.withPacketLoss(loss_rate);
        _ = try scenario.createPair();
        return scenario;
    }

    /// Connection with network latency
    pub fn delayedConnection(allocator: std.mem.Allocator, delay_ms: u32, jitter_ms: u32) !*Scenario {
        var scenario = try allocator.create(Scenario);
        scenario.* = Scenario.init(allocator);
        _ = scenario.withDelay(delay_ms, jitter_ms);
        _ = try scenario.createPair();
        return scenario;
    }

    /// Connection with comprehensive monitoring
    pub fn debugConnection(allocator: std.mem.Allocator) !*Scenario {
        var scenario = try allocator.create(Scenario);
        scenario.* = Scenario.init(allocator);
        _ = scenario.withCapture().withTimeControl();
        _ = try scenario.createPair();
        return scenario;
    }
};

// Tests

test "Scenario - basic initialization" {
    const allocator = std.testing.allocator;

    var scenario = Scenario.init(allocator);
    defer scenario.deinit();

    try std.testing.expect(scenario.pair == null);
    try std.testing.expect(!scenario.capture_enabled);
    try std.testing.expect(!scenario.time_control_enabled);
}

test "Scenario - fluent API configuration" {
    const allocator = std.testing.allocator;

    var scenario = Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario
        .withName("test scenario")
        .withPacketLoss(0.1)
        .withDelay(10, 5)
        .withMtu(1400)
        .withCapture()
        .withTimeControl();

    try std.testing.expectEqual(@as(f64, 0.1), scenario.transport_config.loss_rate);
    try std.testing.expectEqual(@as(u32, 10), scenario.transport_config.delay_ms);
    try std.testing.expectEqual(@as(u32, 5), scenario.transport_config.jitter_ms);
    try std.testing.expectEqual(@as(u16, 1400), scenario.transport_config.mtu);
    try std.testing.expect(scenario.capture_enabled);
    try std.testing.expect(scenario.time_control_enabled);
}

test "Scenario - create pair" {
    const allocator = std.testing.allocator;

    var scenario = Scenario.init(allocator);
    defer scenario.deinit();

    _ = try scenario.createPair();

    try std.testing.expect(scenario.pair != null);
}

test "Scenario - with ALPN" {
    const allocator = std.testing.allocator;

    const alpn = [_][]const u8{"h3"};
    var scenario = Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario.withAlpn(&alpn);

    try std.testing.expectEqualSlices([]const u8, &alpn, scenario.tls_config.alpn);
}

test "Scenario - advance time" {
    const allocator = std.testing.allocator;

    var scenario = Scenario.init(allocator);
    defer scenario.deinit();

    _ = scenario.withTimeControl();
    _ = try scenario.createPair();
    _ = scenario.advanceTime(1000);

    // Verify time was advanced
    const pair = scenario.pair.?;
    try std.testing.expectEqual(@as(i64, 1000), pair.server.time_control.?.now_ms);
    try std.testing.expectEqual(@as(i64, 1000), pair.client.time_control.?.now_ms);
}

test "Scenario - get transport stats" {
    const allocator = std.testing.allocator;

    var scenario = Scenario.init(allocator);
    defer scenario.deinit();

    _ = try scenario.createPair();

    const stats = scenario.getTransportStats();
    try std.testing.expect(stats != null);
    try std.testing.expectEqual(@as(u64, 0), stats.?.packets_sent);
}

test "Templates - basic connection" {
    const allocator = std.testing.allocator;

    var scenario = try Templates.basicConnection(allocator);
    defer {
        scenario.deinit();
        allocator.destroy(scenario);
    }

    try std.testing.expect(scenario.pair != null);
    try std.testing.expect(!scenario.capture_enabled);
}

test "Templates - connection with capture" {
    const allocator = std.testing.allocator;

    var scenario = try Templates.connectionWithCapture(allocator);
    defer {
        scenario.deinit();
        allocator.destroy(scenario);
    }

    try std.testing.expect(scenario.pair != null);
    try std.testing.expect(scenario.capture_enabled);
}

test "Templates - lossy connection" {
    const allocator = std.testing.allocator;

    var scenario = try Templates.lossyConnection(allocator, 0.15);
    defer {
        scenario.deinit();
        allocator.destroy(scenario);
    }

    try std.testing.expect(scenario.pair != null);
    try std.testing.expectEqual(@as(f64, 0.15), scenario.transport_config.loss_rate);
}

test "Templates - delayed connection" {
    const allocator = std.testing.allocator;

    var scenario = try Templates.delayedConnection(allocator, 20, 10);
    defer {
        scenario.deinit();
        allocator.destroy(scenario);
    }

    try std.testing.expect(scenario.pair != null);
    try std.testing.expectEqual(@as(u32, 20), scenario.transport_config.delay_ms);
    try std.testing.expectEqual(@as(u32, 10), scenario.transport_config.jitter_ms);
}

test "Templates - debug connection" {
    const allocator = std.testing.allocator;

    var scenario = try Templates.debugConnection(allocator);
    defer {
        scenario.deinit();
        allocator.destroy(scenario);
    }

    try std.testing.expect(scenario.pair != null);
    try std.testing.expect(scenario.capture_enabled);
    try std.testing.expect(scenario.time_control_enabled);
}
