// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression tests (SONNY-6486 item 1): final-size handling against a
// hostile peer, driven through the real 1-RTT frame handlers under the
// strict testing allocator.
//
// RFC 9000 §4.5: a RESET_STREAM or FIN whose final size is below data
// already received, or that differs from an already known final size, and
// STREAM data beyond a known final size, are connection errors of type
// FINAL_SIZE_ERROR (0x06). v0.1.49/0.1.50 accepted a RESET_STREAM whose final
// size cut through a buffered out-of-order segment, shortened that
// segment's slice in place and later freed it with the shortened length.

const std = @import("std");
const testing = std.testing;
const conn_mod = @import("quic_conn");
const frame = @import("quic_frame");
const packet = @import("quic_packet");
const frame_handler = @import("frame_handler");
const cfg = @import("quic_config");

const keys = packet.AeadKeys{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };

/// Records every datagram the connection sends.
const Capture = struct {
    alloc: std.mem.Allocator,
    sent: std.ArrayList([]u8) = .empty,

    fn send(ctx: *anyopaque, _: *conn_mod.Connection, bytes: []const u8) !usize {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        try self.sent.append(self.alloc, try self.alloc.dupe(u8, bytes));
        return bytes.len;
    }

    fn deinit(self: *Capture) void {
        for (self.sent.items) |p| self.alloc.free(p);
        self.sent.deinit(self.alloc);
    }

    /// Error code of the CONNECTION_CLOSE the connection sent, if any.
    fn closeCode(self: *Capture) ?u64 {
        for (self.sent.items) |p| {
            const dec = packet.decodeShortProtected(self.alloc, p, 4, keys, 0) catch continue;
            defer self.alloc.free(dec.payload);
            var off: usize = 0;
            while (off < dec.payload.len) {
                const fr = frame.decodeOne(dec.payload[off..]) catch break;
                off += fr.n;
                if (fr.f == .connection_close) return fr.f.connection_close.error_code;
            }
        }
        return null;
    }
};

const Peer = struct {
    conn: *conn_mod.Connection,
    capture: Capture,
    alloc: std.mem.Allocator,
    test_cfg: cfg.QuicConfig = .{ .alpn = &[_][]const u8{} },

    fn create(alloc: std.mem.Allocator) !*Peer {
        const p = try alloc.create(Peer);
        p.* = .{ .conn = try alloc.create(conn_mod.Connection), .capture = .{ .alloc = alloc }, .alloc = alloc };
        p.conn.init(&p.alloc, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
        p.conn.app_tx_keys = keys;
        p.conn.peer_finished_verified = true;
        p.conn.address_validated = true;
        p.conn.peer_initial_scid.len = 4;
        @memcpy(p.conn.peer_initial_scid.bytes[0..4], "PEER");
        p.conn.setSender(@ptrCast(&p.capture), Capture.send);
        return p;
    }

    fn destroy(self: *Peer) void {
        self.conn.deinit();
        self.alloc.destroy(self.conn);
        self.capture.deinit();
        self.alloc.destroy(self);
    }

    /// Feed one frame through the real 1-RTT frame dispatcher.
    fn feed(self: *Peer, f: frame.Frame) !frame_handler.FrameResult {
        var ctx = frame_handler.FrameContext{
            .conn = self.conn,
            .allocator = &self.alloc,
            .send_fn = struct {
                fn s(_: conn_mod.SockAddr, d: []const u8) anyerror!usize {
                    return d.len;
                }
            }.s,
            .peer = .{},
            .space = .Application,
            .cfg = &self.test_cfg,
        };
        return frame_handler.processFrame(&ctx, f);
    }

    fn stream(self: *Peer, id: u64, off: u64, data: []const u8, fin: bool) !frame_handler.FrameResult {
        return self.feed(.{ .stream = .{ .stream_id = id, .offset = off, .fin = fin, .data = data } });
    }

    fn reset(self: *Peer, id: u64, final_size: u64) !frame_handler.FrameResult {
        return self.feed(.{ .reset_stream = .{ .stream_id = id, .error_code = 9, .final_size = final_size } });
    }
};

const FINAL_SIZE_ERROR: u64 = 0x06;

test "SONNY-6486 RESET_STREAM cutting through buffered data is FINAL_SIZE_ERROR, not a wrong-length free" {
    const peer = try Peer.create(testing.allocator);
    defer peer.destroy();
    // Bytes [100, 110) arrive ahead of a gap and are buffered.
    _ = try peer.stream(4, 100, "0123456789", false);
    // The peer then claims the stream ended at 105.
    const r = try peer.reset(4, 105);
    try testing.expect(r.saw_close);
    try testing.expectEqual(@as(?u64, FINAL_SIZE_ERROR), peer.capture.closeCode());
}

test "SONNY-6486 FIN below data already received is FINAL_SIZE_ERROR" {
    const peer = try Peer.create(testing.allocator);
    defer peer.destroy();
    _ = try peer.stream(4, 100, "0123456789", false);
    const r = try peer.stream(4, 0, "abc", true);
    try testing.expect(r.saw_close);
    try testing.expectEqual(@as(?u64, FINAL_SIZE_ERROR), peer.capture.closeCode());
}

test "SONNY-6486 data beyond a known final size is FINAL_SIZE_ERROR" {
    const peer = try Peer.create(testing.allocator);
    defer peer.destroy();
    _ = try peer.stream(4, 50, "xy", true); // final size 52
    const r = try peer.stream(4, 60, "zz", false);
    try testing.expect(r.saw_close);
    try testing.expectEqual(@as(?u64, FINAL_SIZE_ERROR), peer.capture.closeCode());
}

test "SONNY-6486 a consistent RESET_STREAM after buffered data is accepted" {
    const peer = try Peer.create(testing.allocator);
    defer peer.destroy();
    _ = try peer.stream(4, 100, "0123456789", false);
    const r = try peer.reset(4, 110);
    try testing.expect(!r.saw_close);
    try testing.expectEqual(@as(?u64, null), peer.capture.closeCode());
}

test "SONNY-6486 fuzzed STREAM/FIN/RESET_STREAM orderings: right error, no invalid free, no leak" {
    var prng = std.Random.DefaultPrng.init(0x6486_5eed);
    const rand = prng.random();
    var data: [64]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);

    var round: usize = 0;
    while (round < 400) : (round += 1) {
        const peer = try Peer.create(testing.allocator);
        defer peer.destroy();
        // Model of RFC 9000 §4.5 for two client bidi streams.
        var highest = [2]u64{ 0, 0 };
        var final_size = [2]?u64{ null, null };

        var step: usize = 0;
        while (step < 12) : (step += 1) {
            const k = rand.uintLessThan(usize, 2);
            const id: u64 = 4 + 4 * @as(u64, k);
            const off = rand.uintLessThan(u64, 200);
            const len = rand.uintLessThan(usize, data.len);
            const kind = rand.uintLessThan(u8, 4);
            const end = off + len;
            var expect_violation = false;
            if (final_size[k]) |f| {
                // Data past the final size, or a different final size, from
                // STREAM (with or without FIN) or RESET_STREAM.
                if (kind <= 1 and end > f) expect_violation = true;
                if (kind != 0 and end != f) expect_violation = true;
            } else if (kind != 0 and end < highest[k]) {
                // A final size below data already received.
                expect_violation = true;
            }
            if (!expect_violation) {
                highest[k] = @max(highest[k], end);
                if (kind != 0) final_size[k] = end;
            }
            const result = switch (kind) {
                0, 1 => try peer.stream(id, off, data[0..len], kind == 1),
                else => try peer.reset(id, end),
            };
            if (expect_violation) {
                try testing.expect(result.saw_close);
                try testing.expectEqual(@as(?u64, FINAL_SIZE_ERROR), peer.capture.closeCode());
                break;
            }
            try testing.expect(!result.saw_close);
        }
    }
}
