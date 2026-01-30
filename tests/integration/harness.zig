//! Integration Test Harness - Core Infrastructure
//!
//! This module provides the foundation for integration testing the QUIC implementation.
//! It includes:
//! - TestEndpoint: Wrapper around Endpoint with test-specific features
//! - TestConnection: Helper to create and manage test connections
//! - PacketCapture: Record and replay QUIC packets for verification
//! - TimeControl: Mock time for deterministic testing
//!
//! RFC References:
//! - RFC 9000: QUIC Transport Protocol
//! - RFC 9001: QUIC TLS
//! - RFC 9002: QUIC Loss Detection and Congestion Control

const std = @import("std");
const tls_helpers = @import("tls_helpers");

// Phase 14: Stub types for harness (real endpoints via endpoint_loopback_helpers)
// Note: ConnectionPair uses endpoint_loopback_helpers.EndpointWrapper for real endpoints
// Harness provides test-specific features that wrap around endpoints

/// Stub endpoint for harness (Phase 14: Real endpoints via EndpointWrapper)
const Endpoint = struct {
    allocator: std.mem.Allocator,
    config: Config,

    pub fn init(allocator: std.mem.Allocator, config: Config) !*Endpoint {
        const self = try allocator.create(Endpoint);
        self.* = .{
            .allocator = allocator,
            .config = config,
        };
        return self;
    }

    pub fn deinit(self: *Endpoint) void {
        self.allocator.destroy(self);
    }
};

/// Stub connection for harness
const Connection = struct {
    id: u64,
};

/// Stub config for harness
const Config = struct {
    allocator: std.mem.Allocator = undefined,
    role: enum { client, server } = .client,
    cert_path: []const u8 = "",
    key_path: []const u8 = "",
    alpn: []const []const u8 = &[_][]const u8{},
    allow_insecure: bool = false,
};

/// Test-specific endpoint wrapper with enhanced capabilities for testing
pub const TestEndpoint = struct {
    /// Underlying QUIC endpoint
    endpoint: *Endpoint,

    /// Allocator for test resources
    allocator: std.mem.Allocator,

    /// Packet capture for verification
    capture: ?*PacketCapture,

    /// Mock time control
    time_control: ?*TimeControl,

    /// Error injection configuration
    error_injection: ErrorInjection,

    /// Test-specific metadata
    metadata: TestMetadata,

    /// Initialize a test endpoint
    pub fn init(allocator: std.mem.Allocator, config: Config) !*TestEndpoint {
        var self = try allocator.create(TestEndpoint);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.endpoint = try Endpoint.init(allocator, config);
        self.capture = null;
        self.time_control = null;
        self.error_injection = .{};
        self.metadata = .{};

        return self;
    }

    /// Clean up test endpoint resources
    pub fn deinit(self: *TestEndpoint) void {
        if (self.capture) |cap| {
            cap.deinit();
            self.allocator.destroy(cap);
        }
        if (self.time_control) |tc| {
            tc.deinit();
            self.allocator.destroy(tc);
        }
        self.endpoint.deinit();
        self.allocator.destroy(self);
    }

    /// Enable packet capture for this endpoint
    pub fn enableCapture(self: *TestEndpoint) !void {
        if (self.capture == null) {
            self.capture = try self.allocator.create(PacketCapture);
            self.capture.?.* = try PacketCapture.init(self.allocator);
        }
    }

    /// Get captured packets for verification
    pub fn getCapturedPackets(self: *TestEndpoint) ?[]const CapturedPacket {
        return if (self.capture) |cap| cap.packets.items else null;
    }

    /// Enable mock time control
    pub fn enableTimeControl(self: *TestEndpoint) !void {
        if (self.time_control == null) {
            self.time_control = try self.allocator.create(TimeControl);
            self.time_control.?.* = TimeControl.init();
        }
    }

    /// Advance mock time by specified duration
    pub fn advanceTime(self: *TestEndpoint, ms: u64) void {
        if (self.time_control) |tc| {
            tc.advance(ms);
        }
    }
};

/// Test-specific connection wrapper
pub const TestConnection = struct {
    /// Underlying QUIC connection
    conn: *Connection,

    /// Parent test endpoint
    endpoint: *TestEndpoint,

    /// Test-specific metadata
    metadata: TestMetadata,

    /// Initialize from existing connection
    pub fn init(endpoint: *TestEndpoint, conn: *Connection) TestConnection {
        return .{
            .conn = conn,
            .endpoint = endpoint,
            .metadata = .{},
        };
    }

    /// Send data on stream 0 (helper for tests)
    pub fn sendData(self: *TestConnection, data: []const u8) !void {
        try self.conn.streamSend(0, data, false);
    }

    /// Receive data from stream 0 (helper for tests)
    pub fn recvData(self: *TestConnection, buf: []u8) !usize {
        return self.conn.streamRecv(0, buf);
    }

    /// Wait for connection to complete handshake
    pub fn waitForHandshake(self: *TestConnection, timeout_ms: u64) !void {
        const start = if (self.endpoint.time_control) |tc| tc.now_ms else std.time.milliTimestamp();

        while (!self.conn.isHandshakeComplete()) {
            const now = if (self.endpoint.time_control) |tc| tc.now_ms else std.time.milliTimestamp();
            if (now - start > timeout_ms) {
                return error.HandshakeTimeout;
            }

            // Process endpoint events
            try self.endpoint.endpoint.poll(10);
        }
    }

    /// Get connection statistics (for verification)
    pub fn getStats(self: *TestConnection) ConnectionStats {
        return .{
            .bytes_sent = self.conn.stats.bytes_sent,
            .bytes_received = self.conn.stats.bytes_received,
            .packets_sent = self.conn.stats.packets_sent,
            .packets_received = self.conn.stats.packets_received,
            .packets_lost = self.conn.stats.packets_lost,
            .rtt_ms = self.conn.rec.rtt_state.smoothed_rtt,
        };
    }
};

/// Packet capture for verification
pub const PacketCapture = struct {
    /// Captured packets
    packets: std.ArrayList(CapturedPacket),

    /// Allocator
    allocator: std.mem.Allocator,

    /// Initialize packet capture
    pub fn init(allocator: std.mem.Allocator) !PacketCapture {
        return .{
            .packets = std.ArrayList(CapturedPacket){},
            .allocator = allocator,
        };
    }

    /// Clean up packet capture
    pub fn deinit(self: *PacketCapture) void {
        for (self.packets.items) |*pkt| {
            self.allocator.free(pkt.data);
        }
        self.packets.deinit(self.allocator);
    }

    /// Record a packet
    pub fn capture(self: *PacketCapture, direction: PacketDirection, data: []const u8) !void {
        const pkt_data = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(pkt_data);

        try self.packets.append(self.allocator, .{
            .timestamp_ms = std.time.milliTimestamp(),
            .direction = direction,
            .data = pkt_data,
        });
    }

    /// Clear captured packets
    pub fn clear(self: *PacketCapture) void {
        for (self.packets.items) |*pkt| {
            self.allocator.free(pkt.data);
        }
        self.packets.clearRetainingCapacity();
    }
};

/// Captured packet information
pub const CapturedPacket = struct {
    /// Timestamp when packet was captured
    timestamp_ms: i64,

    /// Direction (sent or received)
    direction: PacketDirection,

    /// Packet data
    data: []const u8,
};

/// Packet direction
pub const PacketDirection = enum {
    sent,
    received,
};

/// Mock time control for deterministic testing
pub const TimeControl = struct {
    /// Current mock time in milliseconds
    now_ms: i64,

    /// Initialize with time 0 (for deterministic testing)
    pub fn init() TimeControl {
        return .{
            .now_ms = 0,
        };
    }

    /// Clean up time control
    pub fn deinit(_: *TimeControl) void {
        // No resources to free
    }

    /// Advance time by specified milliseconds
    pub fn advance(self: *TimeControl, ms: u64) void {
        self.now_ms += @intCast(ms);
    }

    /// Set absolute time
    pub fn setTime(self: *TimeControl, ms: i64) void {
        self.now_ms = ms;
    }

    /// Get current mock time
    pub fn now(self: *TimeControl) i64 {
        return self.now_ms;
    }
};

/// Error injection configuration
pub const ErrorInjection = struct {
    /// Packet loss rate (0.0 to 1.0)
    packet_loss_rate: f64 = 0.0,

    /// Packet corruption rate (0.0 to 1.0)
    packet_corruption_rate: f64 = 0.0,

    /// Packet delay in milliseconds
    packet_delay_ms: u32 = 0,

    /// Certificate validation failures
    fail_cert_validation: bool = false,

    /// Allocation failures
    fail_allocations: bool = false,
};

/// Test metadata for tracking test state
pub const TestMetadata = struct {
    /// Test name
    name: ?[]const u8 = null,

    /// Test description
    description: ?[]const u8 = null,

    /// Custom tags
    tags: std.StringHashMap([]const u8) = undefined,

    /// Initialize metadata
    pub fn init(allocator: std.mem.Allocator) TestMetadata {
        return .{
            .tags = std.StringHashMap([]const u8).init(allocator),
        };
    }

    /// Clean up metadata
    pub fn deinit(self: *TestMetadata) void {
        if (@TypeOf(self.tags) != @TypeOf(undefined)) {
            self.tags.deinit();
        }
    }
};

/// Connection statistics for verification
pub const ConnectionStats = struct {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    packets_lost: u64,
    rtt_ms: u64,
};

/// Helper to create a test server configuration
pub fn createServerConfig(allocator: std.mem.Allocator) !Config {
    tls_helpers.ensureTestCertFiles(allocator) catch |err| {
        if (err == error.SkipZigTest) return error.SkipZigTest;
        return err;
    };
    var config = Config{};
    config.role = .server;
    config.cert_path = "tests/certs/cert.pem";
    config.key_path = "tests/certs/key.pem";
    config.alpn = &[_][]const u8{"test"};
    return config;
}

/// Helper to create a test client configuration
pub fn createClientConfig(allocator: std.mem.Allocator) !Config {
    var config = Config{};
    config.role = .client;
    config.alpn = &[_][]const u8{"test"};
    config.allow_insecure = true; // For testing with self-signed certs
    _ = allocator;
    return config;
}

// Test helper functions

/// Wait for condition with timeout
pub fn waitFor(
    condition_fn: *const fn () bool,
    timeout_ms: u64,
    check_interval_ms: u64,
) !void {
    const start = std.time.milliTimestamp();

    while (!condition_fn()) {
        const now = std.time.milliTimestamp();
        if (now - start > timeout_ms) {
            return error.Timeout;
        }
        std.time.sleep(check_interval_ms * std.time.ns_per_ms);
    }
}

/// Generate random test data
pub fn generateTestData(allocator: std.mem.Allocator, size: usize) ![]u8 {
    const data = try allocator.alloc(u8, size);
    std.crypto.random.bytes(data);
    return data;
}

test "TestEndpoint - basic initialization" {
    const allocator = std.testing.allocator;

    const config = try createServerConfig(allocator);
    var test_ep = try TestEndpoint.init(allocator, config);
    defer test_ep.deinit();

    // Endpoint created successfully (verified by init not erroring)
    try std.testing.expect(test_ep.capture == null);
    try std.testing.expect(test_ep.time_control == null);
}

test "TestEndpoint - packet capture enable" {
    const allocator = std.testing.allocator;

    const config = try createServerConfig(allocator);
    var test_ep = try TestEndpoint.init(allocator, config);
    defer test_ep.deinit();

    try test_ep.enableCapture();
    try std.testing.expect(test_ep.capture != null);
}

test "TimeControl - time advancement" {
    var tc = TimeControl.init();
    const initial = tc.now();

    tc.advance(1000);
    try std.testing.expectEqual(initial + 1000, tc.now());

    tc.advance(500);
    try std.testing.expectEqual(initial + 1500, tc.now());
}

test "generateTestData - random data generation" {
    const allocator = std.testing.allocator;

    const data = try generateTestData(allocator, 1024);
    defer allocator.free(data);

    try std.testing.expectEqual(@as(usize, 1024), data.len);

    // Verify data is not all zeros
    var has_nonzero = false;
    for (data) |byte| {
        if (byte != 0) {
            has_nonzero = true;
            break;
        }
    }
    try std.testing.expect(has_nonzero);
}
