//! Loopback Transport Adapter
//!
//! Bridges the gap between the test LoopbackTransport and the production endpoint's
//! Transport interface. This adapter enables the production endpoint to use loopback
//! transport for deterministic integration testing.
//!
//! ## Design
//!
//! The test LoopbackTransport provides bidirectional queues (A↔B) for packet delivery.
//! The production Endpoint expects a Transport interface with send/recv methods.
//! This adapter wraps a LoopbackTransport and provides one "side" of the connection.
//!
//! ## Usage
//!
//! ```zig
//! // Create shared loopback transport
//! var loopback = try LoopbackTransport.init(allocator, .{ .loss_rate = 0.1 });
//! defer loopback.deinit();
//!
//! // Create two adapters (client and server sides)
//! var client_adapter = LoopbackTransportAdapter.init(loopback, .SideA);
//! var server_adapter = LoopbackTransportAdapter.init(loopback, .SideB);
//!
//! // Create endpoints with adapted transports
//! var client_ep = try Endpoint.initWithTransport(alloc, client_adapter.asTransport(), &cfg);
//! var server_ep = try Endpoint.initWithTransport(alloc, server_adapter.asTransport(), &cfg);
//! ```

const std = @import("std");
const loopback = @import("loopback.zig");

// Note: These imports require the test to be run via the build system
// For standalone testing, we define stub types
const has_quic_modules = @hasDecl(@This(), "testing") and false; // Disabled for now

// Stub SockAddr type for standalone testing (when not using build system)
pub const SockAddr = struct {
    storage: [128]u8 = [_]u8{0} ** 128,
    len: u32 = 0,

    pub fn ipv4(a: u8, b: u8, c: u8, d: u8, port: u16) SockAddr {
        var addr = SockAddr{};
        // Simplified IPv4 address creation
        addr.storage[0] = 2; // AF_INET
        addr.storage[2] = @intCast((port >> 8) & 0xFF);
        addr.storage[3] = @intCast(port & 0xFF);
        addr.storage[4] = a;
        addr.storage[5] = b;
        addr.storage[6] = c;
        addr.storage[7] = d;
        addr.len = 16;
        return addr;
    }

    pub fn getPort(self: *const SockAddr) u16 {
        if (self.len < 4) return 0;
        return (@as(u16, self.storage[2]) << 8) | @as(u16, self.storage[3]);
    }
};

// Stub RecvResult type for standalone testing
pub const RecvResult = struct {
    n: usize,
    peer: SockAddr,
    ecn: ?u8 = null,
};

// Stub Transport type for standalone testing
pub const Transport = struct {
    sendFn: *const fn (ctx: *anyopaque, peer: SockAddr, data: []const u8) anyerror!usize,
    recvFn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!RecvResult,
    pollFn: ?*const fn (ctx: *anyopaque, timeout_ms: i32) anyerror!void,
    closeFn: *const fn (ctx: *anyopaque) void,
    getLocalAddrFn: *const fn (ctx: *anyopaque) anyerror!SockAddr,
    context: *anyopaque,

    pub fn send(self: *Transport, peer: SockAddr, data: []const u8) !usize {
        return self.sendFn(self.context, peer, data);
    }

    pub fn recv(self: *Transport, buf: []u8) !RecvResult {
        return self.recvFn(self.context, buf);
    }

    pub fn poll(self: *Transport, timeout_ms: i32) !void {
        if (self.pollFn) |poll_fn| {
            try poll_fn(self.context, timeout_ms);
        }
    }

    pub fn close(self: *Transport) void {
        self.closeFn(self.context);
    }

    pub fn getLocalAddr(self: *Transport) !SockAddr {
        return self.getLocalAddrFn(self.context);
    }
};

/// Which side of the loopback connection this adapter represents
pub const Side = enum {
    SideA,  // Sends via queue_a_to_b, receives from queue_b_to_a
    SideB,  // Sends via queue_b_to_a, receives from queue_a_to_b
};

/// Adapter that implements Transport interface for LoopbackTransport
pub const LoopbackTransportAdapter = struct {
    /// Reference to shared loopback transport
    loopback: *loopback.LoopbackTransport,

    /// Which side of the connection we represent
    side: Side,

    /// Local address for this adapter (synthetic)
    local_addr: SockAddr,

    /// Peer address (synthetic)
    peer_addr: SockAddr,

    /// Initialize adapter
    pub fn init(
        lb: *loopback.LoopbackTransport,
        side: Side,
    ) LoopbackTransportAdapter {
        // Create synthetic addresses based on side
        const local_addr = if (side == .SideA)
            SockAddr.ipv4(127, 0, 0, 1, 4433)  // Client
        else
            SockAddr.ipv4(127, 0, 0, 1, 443);   // Server

        const peer_addr = if (side == .SideA)
            SockAddr.ipv4(127, 0, 0, 1, 443)    // Client sees server
        else
            SockAddr.ipv4(127, 0, 0, 1, 4433);  // Server sees client

        return LoopbackTransportAdapter{
            .loopback = lb,
            .side = side,
            .local_addr = local_addr,
            .peer_addr = peer_addr,
        };
    }

    /// Get Transport interface for this adapter
    pub fn asTransport(self: *LoopbackTransportAdapter) Transport {
        return Transport{
            .sendFn = sendFn,
            .recvFn = recvFn,
            .pollFn = pollFn,
            .closeFn = closeFn,
            .getLocalAddrFn = getLocalAddrFn,
            .context = @ptrCast(self),
        };
    }

    /// Send implementation
    fn sendFn(ctx: *anyopaque, peer: SockAddr, data: []const u8) anyerror!usize {
        const self: *LoopbackTransportAdapter = @ptrCast(@alignCast(ctx));
        _ = peer;  // Ignore peer, we know where to send based on our side

        // TODO: Implement actual send through loopback queues
        // if (self.side == .SideA) {
        //     try self.loopback.sendAtoB(data);
        // } else {
        //     try self.loopback.sendBtoA(data);
        // }

        // Stub: pretend we sent the data
        _ = self;
        return data.len;
    }

    /// Receive implementation
    fn recvFn(ctx: *anyopaque, buf: []u8) anyerror!RecvResult {
        const self: *LoopbackTransportAdapter = @ptrCast(@alignCast(ctx));

        // TODO: Implement actual receive from loopback queues
        // const received_data = if (self.side == .SideA)
        //     try self.loopback.recvAtA(buf)
        // else
        //     try self.loopback.recvAtB(buf);

        // Stub: return no data available
        _ = self;
        _ = buf;
        return error.WouldBlock;
    }

    /// Poll implementation (no-op for loopback)
    fn pollFn(ctx: *anyopaque, timeout_ms: i32) anyerror!void {
        _ = ctx;
        _ = timeout_ms;
        // TODO: Could implement mock time advancement here
        // For now, polling is a no-op since loopback is synchronous
    }

    /// Close implementation
    fn closeFn(ctx: *anyopaque) void {
        const self: *LoopbackTransportAdapter = @ptrCast(@alignCast(ctx));
        _ = self;
        // No-op: loopback transport is shared and closed by its owner
    }

    /// Get local address implementation
    fn getLocalAddrFn(ctx: *anyopaque) anyerror!SockAddr {
        const self: *LoopbackTransportAdapter = @ptrCast(@alignCast(ctx));
        return self.local_addr;
    }
};

// =============================================================================
// Integration Tests
// =============================================================================

const testing = std.testing;

test "LoopbackTransportAdapter initialization" {
    var lb = try loopback.LoopbackTransport.init(testing.allocator, .{});
    defer lb.deinit();

    var adapter_a = LoopbackTransportAdapter.init(lb, .SideA);
    var adapter_b = LoopbackTransportAdapter.init(lb, .SideB);

    // Verify addresses are set correctly
    try testing.expect(adapter_a.local_addr.getPort() == 4433);  // Client port
    try testing.expect(adapter_b.local_addr.getPort() == 443);    // Server port
}

test "LoopbackTransportAdapter asTransport" {
    var lb = try loopback.LoopbackTransport.init(testing.allocator, .{});
    defer lb.deinit();

    var adapter = LoopbackTransportAdapter.init(lb, .SideA);
    var transport = adapter.asTransport();

    // Verify transport interface is functional
    const local_addr = try transport.getLocalAddr();
    try testing.expect(local_addr.getPort() == 4433);

    // Verify close doesn't crash
    transport.close();
}

test "LoopbackTransportAdapter send stub" {
    var lb = try loopback.LoopbackTransport.init(testing.allocator, .{});
    defer lb.deinit();

    var adapter = LoopbackTransportAdapter.init(lb, .SideA);
    var transport = adapter.asTransport();

    const test_data = "test packet";
    const peer_addr = SockAddr.ipv4(127, 0, 0, 1, 443);

    // Send should succeed (stub implementation)
    const sent = try transport.send(peer_addr, test_data);
    try testing.expectEqual(@as(usize, test_data.len), sent);
}

test "LoopbackTransportAdapter recv stub" {
    var lb = try loopback.LoopbackTransport.init(testing.allocator, .{});
    defer lb.deinit();

    var adapter = LoopbackTransportAdapter.init(lb, .SideA);
    var transport = adapter.asTransport();

    var buf: [1500]u8 = undefined;

    // Recv should return WouldBlock (stub implementation)
    const result = transport.recv(&buf);
    try testing.expectError(error.WouldBlock, result);
}
