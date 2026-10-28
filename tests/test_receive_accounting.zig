// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 CodePros
// Deterministic receive accounting only: no Initial, Retry, tokens, or sessions.
const std = @import("std");
const endpoint = @import("quic_endpoint");
const transport = @import("transport");
const config = @import("config.zig");
const allocator = std.testing.allocator;
const short = [_]u8{0x40}; // Unroutable short header, safely consumed.
const long = [_]u8{ 0xe0, 0, 0, 0, 1, 0, 0, 1, 0 }; // Unroutable Handshake.

const Queue = struct {
    packets: []const []const u8,
    received: usize = 0,
    fn asTransport(self: *Queue) transport.Transport {
        return .{ .context = self, .sendFn = send, .recvFn = recv, .pollFn = null, .closeFn = close, .getLocalAddrFn = local };
    }
    fn send(_: *anyopaque, _: transport.SockAddr, bytes: []const u8) !usize {
        return bytes.len;
    }
    fn recv(ctx: *anyopaque, buf: []u8) !transport.RecvResult {
        const self: *Queue = @ptrCast(@alignCast(ctx));
        if (self.received == self.packets.len) return error.WouldBlock;
        const bytes = self.packets[self.received];
        if (bytes.len > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[0..bytes.len], bytes);
        self.received += 1;
        return .{ .n = bytes.len, .peer = transport.SockAddr.ipv4(127, 0, 0, 1, 12345) };
    }
    fn close(_: *anyopaque) void {}
    fn local(_: *anyopaque) !transport.SockAddr {
        return transport.SockAddr.ipv4(127, 0, 0, 1, 4433);
    }
};

fn assertDrained(burst: []const []const u8, expected_first: usize) !void {
    var alloc = allocator;
    var queue = Queue{ .packets = burst };
    var cfg = config.QuicConfig{ .alpn = &.{} };
    var ep = try endpoint.Endpoint.initWithTransport(&alloc, queue.asTransport(), &cfg, .Server);
    defer ep.deinit();
    const first = try ep.pollWithStats(0);
    try std.testing.expectEqual(expected_first, first.packets_processed);
    var processed = first.packets_processed;
    for (0..8) |_| {
        const next = try ep.pollWithStats(0);
        processed += next.packets_processed;
        if (next.packets_processed == 0) break;
    }
    try std.testing.expectEqual(burst.len, queue.received);
    try std.testing.expectEqual(burst.len, processed);
    try std.testing.expectEqual(@as(usize, 0), ep.conns.count());
}

test "aligned short-header batches remain bounded and fully accounted" {
    const burst = [_][]const u8{&short} ** 320;
    try assertDrained(&burst, 256);
}

test "long-header drain accounts every received datagram" {
    const burst = [_][]const u8{&long} ** 320;
    try assertDrained(&burst, 320);
}

test "master receive cap bounds mixed-batch reads" {
    endpoint.setServerSocketDrainPackets(129);
    defer endpoint.setServerSocketDrainPackets(0);
    const burst = [_][]const u8{&short} ** 320;
    try assertDrained(&burst, 129);
}

test "short-header budget must retain the already-received tail of a mixed batch" {
    // One Handshake ahead of 319 short headers shifts the256-short-header
    // boundary into the fifth64-datagram batch. The transport has delivered
    // all320 datagrams when processing stops at257;63 must remain accounted
    // for on later polls rather than disappearing with stack-local slots.
    var burst = [_][]const u8{&short} ** 320;
    burst[0] = &long;
    try assertDrained(&burst, 257);
}
