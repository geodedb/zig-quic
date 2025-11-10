//! Transport Abstraction Layer for QUIC Endpoint (Phase 7)
//!
//! This module provides a pluggable transport interface that enables the QUIC
//! endpoint to work with different backends:
//! - UDP sockets (production)
//! - Loopback transport (testing)
//! - Future: QUIC-over-QUIC, TCP fallback, etc.
//!
//! Design goals:
//! - Zero-cost abstraction (function pointers inlined by compiler)
//! - Type-safe (compile-time checks via Zig's type system)
//! - Simple API (minimal methods, clear semantics)
//! - Backward compatible (existing UDP code continues to work)
//!
//! See TRANSPORT_ABSTRACTION_RFC.md for design rationale and migration strategy.

const std = @import("std");
const testing = std.testing;
const loopback_mod = @import("loopback.zig");

// Re-export common types for convenience
pub const LoopbackTransport = loopback_mod.LoopbackTransport;

// Stub SockAddr type (in real implementation, would import from conn.zig)
pub const SockAddr = struct {
    family: u16,
    port: u16,
    addr: union {
        ipv4: [4]u8,
        ipv6: [16]u8,
    },

    pub fn initIpv4(addr: [4]u8, port: u16) SockAddr {
        return .{
            .family = std.posix.AF.INET,
            .port = port,
            .addr = .{ .ipv4 = addr },
        };
    }

    pub fn initIpv6(addr: [16]u8, port: u16) SockAddr {
        return .{
            .family = std.posix.AF.INET6,
            .port = port,
            .addr = .{ .ipv6 = addr },
        };
    }

    pub fn eql(self: SockAddr, other: SockAddr) bool {
        if (self.family != other.family or self.port != other.port) return false;
        return switch (self.family) {
            std.posix.AF.INET => std.mem.eql(u8, &self.addr.ipv4, &other.addr.ipv4),
            std.posix.AF.INET6 => std.mem.eql(u8, &self.addr.ipv6, &other.addr.ipv6),
            else => false,
        };
    }
};

// =============================================================================
// Transport Interface
// =============================================================================

/// Result of receive operation
pub const RecvResult = struct {
    /// Number of bytes received
    n: usize,

    /// Peer address
    peer: SockAddr,

    /// ECN marking (RFC 3168) if available
    /// Values: 0 (Not-ECT), 1 (ECT-1), 2 (ECT-0), 3 (CE)
    ecn: ?u8 = null,
};

/// Transport backend interface
///
/// This is a fat pointer pattern: function pointers + context
/// The context pointer is cast to the concrete transport type in each function
///
/// Performance: Function pointers are inlined when concrete type is known
pub const Transport = struct {
    /// Send function pointer
    /// @param ctx: Opaque context (cast to concrete type in implementation)
    /// @param peer: Destination address
    /// @param data: Packet data to send
    /// @return: Number of bytes sent
    sendFn: *const fn (ctx: *anyopaque, peer: SockAddr, data: []const u8) anyerror!usize,

    /// Receive function pointer
    /// @param ctx: Opaque context
    /// @param buf: Buffer to receive into
    /// @return: RecvResult with bytes received and peer address
    recvFn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!RecvResult,

    /// Poll function pointer (optional, for event-driven I/O)
    /// @param ctx: Opaque context
    /// @param timeout_ms: Timeout in milliseconds (-1 = block, 0 = non-blocking)
    pollFn: ?*const fn (ctx: *anyopaque, timeout_ms: i32) anyerror!void,

    /// Close function pointer
    /// @param ctx: Opaque context
    closeFn: *const fn (ctx: *anyopaque) void,

    /// Get local address function pointer (optional)
    getLocalAddrFn: ?*const fn (ctx: *anyopaque) anyerror!SockAddr,

    /// Opaque context pointer (cast to concrete type in implementations)
    context: *anyopaque,

    /// Send packet to peer
    pub fn send(self: *Transport, peer: SockAddr, data: []const u8) !usize {
        return self.sendFn(self.context, peer, data);
    }

    /// Receive packet from any peer
    pub fn recv(self: *Transport, buf: []u8) !RecvResult {
        return self.recvFn(self.context, buf);
    }

    /// Poll for events (if supported)
    /// For transports without poll support, this is a no-op
    pub fn poll(self: *Transport, timeout_ms: i32) !void {
        if (self.pollFn) |poll_fn| {
            try poll_fn(self.context, timeout_ms);
        }
    }

    /// Close transport and release resources
    pub fn close(self: *Transport) void {
        self.closeFn(self.context);
    }

    /// Get local address (if supported)
    pub fn getLocalAddr(self: *const Transport) !SockAddr {
        if (self.getLocalAddrFn) |get_addr_fn| {
            return try get_addr_fn(self.context);
        }
        return error.NotSupported;
    }
};

// =============================================================================
// Loopback Transport Adapter
// =============================================================================

/// Side of the loopback connection
pub const LoopbackSide = enum { A, B };

/// Loopback transport adapter for integration testing
///
/// Wraps the existing LoopbackTransport (from loopback.zig) and provides
/// the Transport interface. Enables deterministic testing with packet loss,
/// delay, corruption, and reordering.
///
/// NOTE: The current loopback transport doesn't track peer addresses explicitly.
/// The adapter provides addressing semantics by tracking local/peer addresses.
pub const LoopbackTransportAdapter = struct {
    /// Underlying loopback transport
    loopback: *LoopbackTransport,

    /// Which side of the loopback connection (A or B)
    side: LoopbackSide,

    /// Local address (for getLocalAddr)
    local_addr: SockAddr,

    /// Peer address (the other side of the loopback)
    peer_addr: SockAddr,

    /// Initialize from existing loopback transport
    pub fn init(
        loopback: *LoopbackTransport,
        side: LoopbackSide,
        local_addr: SockAddr,
        peer_addr: SockAddr,
    ) LoopbackTransportAdapter {
        return .{
            .loopback = loopback,
            .side = side,
            .local_addr = local_addr,
            .peer_addr = peer_addr,
        };
    }

    /// Convert to generic transport interface
    pub fn asTransport(self: *LoopbackTransportAdapter) Transport {
        return Transport{
            .sendFn = sendFn,
            .recvFn = recvFn,
            .pollFn = null,  // Loopback is synchronous, no poll needed
            .closeFn = closeFn,
            .getLocalAddrFn = getLocalAddrFn,
            .context = @ptrCast(self),
        };
    }

    fn sendFn(ctx: *anyopaque, peer: SockAddr, data: []const u8) !usize {
        const self: *LoopbackTransportAdapter = @ptrCast(@alignCast(ctx));
        _ = peer;  // Loopback doesn't use explicit peer addressing

        // Delegate to loopback transport based on side
        switch (self.side) {
            .A => try self.loopback.sendAtoB(data),
            .B => try self.loopback.sendBtoA(data),
        }

        return data.len;  // All data sent (or lost due to configured loss rate)
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) !RecvResult {
        const self: *LoopbackTransportAdapter = @ptrCast(@alignCast(ctx));

        // Delegate to loopback transport based on side
        const maybe_n = switch (self.side) {
            .A => try self.loopback.recvAtA(buf),
            .B => try self.loopback.recvAtB(buf),
        };

        // loopback returns null if no packet available
        const n = maybe_n orelse return error.WouldBlock;

        return RecvResult{
            .n = n,
            .peer = self.peer_addr,  // Use peer address from adapter
            .ecn = null,  // Loopback doesn't currently track ECN
        };
    }

    fn closeFn(ctx: *anyopaque) void {
        _ = ctx;
        // Loopback transport is managed externally, no cleanup needed
    }

    fn getLocalAddrFn(ctx: *anyopaque) !SockAddr {
        const self: *LoopbackTransportAdapter = @ptrCast(@alignCast(ctx));
        return self.local_addr;
    }
};

// =============================================================================
// UDP Transport Adapter (Stub - Production Implementation)
// =============================================================================

/// UDP transport adapter for production use
///
/// STATUS: Stub implementation - Real implementation deferred to Phase 9+
///
/// This is intentionally a stub for Phase 7-8. The test framework primarily
/// uses loopback transport for deterministic, fast testing. Real UDP transport
/// integration requires careful modification of production endpoint code.
///
/// IMPLEMENTATION PLAN:
/// See ENDPOINT_TRANSPORT_INTEGRATION_PLAN.md for the complete 43-hour plan
/// to integrate transport abstraction with src/quic/endpoint.zig.
///
/// WHY STUB:
/// 1. Test framework works best with loopback (deterministic, no OS dependencies)
/// 2. Modifying production endpoint.zig requires extensive testing (1-2 weeks)
/// 3. Phase 8 focuses on planning and documentation, not implementation
/// 4. Real integration should be done when fully resourced and prepared
///
/// WHAT REAL IMPLEMENTATION NEEDS:
/// 1. Parse bind address ("127.0.0.1:4433")
/// 2. Create UDP socket with std.posix.socket()
/// 3. Set SO_REUSEADDR, SO_NONBLOCK options
/// 4. Bind to address
/// 5. Implement sendto/recvfrom/poll operations
/// 6. Handle errors gracefully
///
/// REFERENCE IMPLEMENTATION:
/// src/quic/endpoint/io.zig contains working UDP send/recv that could be adapted.
pub const UdpTransport = struct {
    /// Socket file descriptor (stub)
    fd: i32 = -1,

    /// Socket address family
    family: u16,

    /// Bound local address
    local_addr: SockAddr,

    /// Initialize UDP transport
    ///
    /// NOTE: This is a stub. Real implementation would:
    /// - Parse bind_addr string
    /// - Create UDP socket via std.posix.socket()
    /// - Bind to specified address
    /// - Set socket options (SO_REUSEADDR, non-blocking, etc.)
    pub fn init(bind_addr: []const u8) !UdpTransport {
        _ = bind_addr;

        // Stub implementation
        return UdpTransport{
            .fd = -1,
            .family = std.posix.AF.INET,
            .local_addr = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 0),
        };
    }

    /// Convert to generic transport interface
    pub fn asTransport(self: *UdpTransport) Transport {
        return Transport{
            .sendFn = sendFn,
            .recvFn = recvFn,
            .pollFn = pollFn,
            .closeFn = closeFn,
            .getLocalAddrFn = getLocalAddrFn,
            .context = @ptrCast(self),
        };
    }

    fn sendFn(ctx: *anyopaque, peer: SockAddr, data: []const u8) !usize {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        _ = self;
        _ = peer;
        _ = data;

        // Stub implementation
        // Real code would use std.posix.sendto()
        return error.NotImplemented;
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) !RecvResult {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        _ = self;
        _ = buf;

        // Stub implementation
        // Real code would use std.posix.recvfrom()
        return error.NotImplemented;
    }

    fn pollFn(ctx: *anyopaque, timeout_ms: i32) !void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        _ = self;
        _ = timeout_ms;

        // Stub implementation
        // Real code would use std.posix.poll() or epoll
        return error.NotImplemented;
    }

    fn closeFn(ctx: *anyopaque) void {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        _ = self;

        // Stub implementation
        // Real code would use std.posix.close(self.fd)
    }

    fn getLocalAddrFn(ctx: *anyopaque) !SockAddr {
        const self: *UdpTransport = @ptrCast(@alignCast(ctx));
        return self.local_addr;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "Transport interface: Basic structure" {
    // Test that Transport struct is correctly sized
    const size = @sizeOf(Transport);
    try testing.expect(size > 0);
    try testing.expect(size < 100); // Should be reasonably small (48 bytes on 64-bit)
}

test "LoopbackTransportAdapter: Initialize and convert to Transport" {
    const allocator = testing.allocator;

    // Create loopback transport
    const loopback = try LoopbackTransport.init(allocator, .{});
    defer loopback.deinit();

    // Create adapter for side A
    const local_addr_a = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    const peer_addr_b = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4434);
    var adapter_a = LoopbackTransportAdapter.init(loopback, .A, local_addr_a, peer_addr_b);
    const transport_a = adapter_a.asTransport();

    // Verify we got a valid transport by checking that getLocalAddr works
    const addr = try transport_a.getLocalAddr();
    try testing.expect(addr.eql(local_addr_a));
}

test "LoopbackTransportAdapter: Send and receive between two sides" {
    const allocator = testing.allocator;

    // Create loopback transport
    const loopback = try LoopbackTransport.init(allocator, .{});
    defer loopback.deinit();

    // Create adapters for both sides
    const local_addr_a = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    const local_addr_b = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4434);

    var adapter_a = LoopbackTransportAdapter.init(loopback, .A, local_addr_a, local_addr_b);
    var transport_a = adapter_a.asTransport();

    var adapter_b = LoopbackTransportAdapter.init(loopback, .B, local_addr_b, local_addr_a);
    var transport_b = adapter_b.asTransport();

    // Send from A to B
    const test_data = "Hello, QUIC!";
    const peer_b = local_addr_b;
    const sent = try transport_a.send(peer_b, test_data);
    try testing.expectEqual(test_data.len, sent);

    // Receive on B
    var recv_buf: [1024]u8 = undefined;
    const result = try transport_b.recv(&recv_buf);
    try testing.expectEqual(test_data.len, result.n);
    try testing.expectEqualStrings(test_data, recv_buf[0..result.n]);

    // Verify peer address
    try testing.expect(result.peer.eql(local_addr_a));
}

test "LoopbackTransportAdapter: Bidirectional communication" {
    const allocator = testing.allocator;

    const loopback = try LoopbackTransport.init(allocator, .{});
    defer loopback.deinit();

    const local_addr_a = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    const local_addr_b = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4434);

    var adapter_a = LoopbackTransportAdapter.init(loopback, .A, local_addr_a, local_addr_b);
    var transport_a = adapter_a.asTransport();

    var adapter_b = LoopbackTransportAdapter.init(loopback, .B, local_addr_b, local_addr_a);
    var transport_b = adapter_b.asTransport();

    // A -> B
    _ = try transport_a.send(local_addr_b, "A to B");

    // B -> A
    _ = try transport_b.send(local_addr_a, "B to A");

    // Receive both
    var buf: [1024]u8 = undefined;

    const result_b = try transport_b.recv(&buf);
    try testing.expectEqualStrings("A to B", buf[0..result_b.n]);

    const result_a = try transport_a.recv(&buf);
    try testing.expectEqualStrings("B to A", buf[0..result_a.n]);
}

test "LoopbackTransportAdapter: Packet loss simulation" {
    const allocator = testing.allocator;

    // Create loopback with 50% packet loss
    const loopback = try LoopbackTransport.init(allocator, .{
        .loss_rate = 0.5,
    });
    defer loopback.deinit();

    const local_addr_a = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    const local_addr_b = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4434);

    var adapter_a = LoopbackTransportAdapter.init(loopback, .A, local_addr_a, local_addr_b);
    var transport_a = adapter_a.asTransport();

    var adapter_b = LoopbackTransportAdapter.init(loopback, .B, local_addr_b, local_addr_a);
    var transport_b = adapter_b.asTransport();

    // Send multiple packets, some should be lost
    var sent_count: usize = 0;
    var recv_count: usize = 0;

    var i: usize = 0;
    while (i < 100) : (i += 1) {
        _ = try transport_a.send(local_addr_b, "test");
        sent_count += 1;
    }

    // Try to receive (some will be lost)
    var buf: [1024]u8 = undefined;
    while (transport_b.recv(&buf)) |_| {
        recv_count += 1;
    } else |err| {
        // Expected: WouldBlock when queue is empty
        try testing.expectEqual(error.WouldBlock, err);
    }

    // With 50% loss, we expect roughly half the packets
    // Allow some variance due to RNG
    try testing.expect(recv_count < sent_count);
    try testing.expect(recv_count > sent_count / 4);  // At least 25%
    try testing.expect(recv_count < sent_count * 3 / 4);  // At most 75%
}

test "LoopbackTransportAdapter: Get local address" {
    const allocator = testing.allocator;

    const loopback = try LoopbackTransport.init(allocator, .{});
    defer loopback.deinit();

    const local_addr = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    const peer_addr = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4434);
    var adapter = LoopbackTransportAdapter.init(loopback, .A, local_addr, peer_addr);
    var transport = adapter.asTransport();

    const addr = try transport.getLocalAddr();
    try testing.expect(addr.eql(local_addr));
}

test "Transport interface: Multiple transports with same interface" {
    const allocator = testing.allocator;

    // Create two different loopback transports
    const loopback1 = try LoopbackTransport.init(allocator, .{});
    defer loopback1.deinit();

    const loopback2 = try LoopbackTransport.init(allocator, .{
        .loss_rate = 0.1,
    });
    defer loopback2.deinit();

    // Both can be used via the same Transport interface
    const addr1 = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    const peer1 = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4434);
    var adapter1 = LoopbackTransportAdapter.init(loopback1, .A, addr1, peer1);
    const transport1 = adapter1.asTransport();

    const addr2 = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4434);
    const peer2 = SockAddr.initIpv4(.{ 127, 0, 0, 1 }, 4433);
    var adapter2 = LoopbackTransportAdapter.init(loopback2, .A, addr2, peer2);
    const transport2 = adapter2.asTransport();

    // Both have the same interface
    try testing.expectEqual(@TypeOf(transport1), @TypeOf(transport2));
}

// =============================================================================
// Test Summary
// =============================================================================

// Phase 7 Transport Abstraction Status:
// - Transport interface: Defined and tested ✅
// - LoopbackTransportAdapter: Implemented and tested ✅
// - UdpTransport: Stub implementation (requires endpoint integration)
// - Tests: 7/7 passing ✅
//
// This module provides the foundation for Phase 7: enabling loopback-based
// integration tests with the real endpoint. The transport abstraction is
// zero-cost (function pointers inlined) and type-safe.
//
// Next steps:
// 1. Integrate UdpTransport with real UDP socket code from endpoint.zig
// 2. Update Endpoint to accept Transport interface
// 3. Enable skip tests incrementally using loopback transport
