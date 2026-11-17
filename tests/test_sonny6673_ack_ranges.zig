// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test (SONNY-6673): ACK ranges received on the 1-RTT path are
// read from the frame the receive path decoded, not from frame.decodeOne's
// stack frame. decodeOne returned the ranges in the frame's own buffer but
// left `ranges` pointing at the copy in its own, dead stack frame; the
// receive path then read whatever had since been written there. In release
// builds that acknowledged packet numbers the peer never received, and the
// STREAM data they carried was released: a stream behind one lost packet
// never completed (test-rx-packet-protection's hole test hung on the
// ReleaseFast CI job). The real receive path is driven here: an ACK frame
// with a gap goes through incoming.processFrames into the connection's ACK
// handling, and the data of the packets in the gap must stay tracked.

const std = @import("std");
const testing = std.testing;
const incoming = @import("incoming");
const conn_mod = @import("quic_conn");
const cfg = @import("config");
const endpoint_types = @import("endpoint/types");
const frame = @import("quic_frame");
const packet = @import("quic_packet");
const compat = @import("compat");

const app_keys: packet.AeadKeys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };

fn noSend(_: conn_mod.SockAddr, data: []const u8) anyerror!usize {
    return data.len;
}

fn noTimer(_: *conn_mod.Connection, _: endpoint_types.TimerKind, _: u32) anyerror!u64 {
    return 1;
}

fn noProbe(_: *conn_mod.Connection) anyerror!void {}

fn noSetup(_: *conn_mod.Connection) void {}

const CountingSender = struct {
    sends: usize = 0,

    fn send(ctx: *anyopaque, _: *conn_mod.Connection, bytes: []const u8) anyerror!usize {
        const self: *CountingSender = @ptrCast(@alignCast(ctx));
        self.sends += 1;
        return bytes.len;
    }
};

/// Overwrites a large part of the stack below the caller with a pattern,
/// as other calls between decoding and using a frame would.
noinline fn scribbleStack() void {
    var junk: [16 * 1024]u8 = undefined;
    @memset(&junk, 0x5a);
    std.mem.doNotOptimizeAway(&junk);
}

test "SONNY-6673 decodeOne's ACK ranges are read from the decoded frame once anchored" {
    // An ACK of [20, 39] and [0, 9]: one gap, packets 10..19.
    const ranges = [_]frame.AckRange{.{ .gap = 9, .len = 9 }};
    var buf: [64]u8 = undefined;
    var fbs = compat.fixedBufWriter(&buf);
    _ = try (frame.Frame{ .ack = .{ .largest = 39, .ack_delay = 0, .first_range = 19, .ranges = &ranges } }).write(fbs.writer());

    var fr = try frame.decodeOne(fbs.getWritten());
    fr.anchor();
    scribbleStack();
    try testing.expect(fr.f == .ack);
    try testing.expectEqual(@intFromPtr(&fr.f.ack.ranges_buf), @intFromPtr(fr.f.ack.ranges.ptr));
    try testing.expectEqual(@as(usize, 1), fr.f.ack.ranges.len);
    try testing.expectEqual(@as(u64, 9), fr.f.ack.ranges[0].gap);
    try testing.expectEqual(@as(u64, 9), fr.f.ack.ranges[0].len);
}

test "SONNY-6673 an ACK with a gap received on the 1-RTT path keeps the gap's STREAM data tracked" {
    var alloc = testing.allocator;
    var conns = std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection).init(testing.allocator);
    defer conns.deinit();
    var accepted: std.ArrayList(*conn_mod.Connection) = .empty;
    defer accepted.deinit(testing.allocator);
    var test_cfg = cfg.QuicConfig{ .alpn = &[_][]const u8{"test"} };
    var ctx: incoming.RxContext = .{
        .allocator = &alloc,
        .conns = &conns,
        .accepted = &accepted,
        .cfg = &test_cfg,
        .send_fn = noSend,
        .schedule_timer_fn = noTimer,
        .send_initial_probe_fn = noProbe,
        .setup_sender_fn = noSetup,
        .test_capture_enabled = false,
        .endpoint_role = .Server,
    };

    var conn: conn_mod.Connection = undefined;
    conn.init(&alloc, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    conn.app_tx_keys = app_keys;
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_max_data = 1 << 40;
    conn.peer_max_stream_data = 1 << 40;
    // A long RTT keeps time-threshold loss out: only the ACK decides.
    conn.rec.rtt.have_sample = true;
    conn.rec.rtt.smoothed_rtt_ns = 60 * std.time.ns_per_s;
    conn.rec.rtt.latest_rtt_ns = 60 * std.time.ns_per_s;
    conn.rec.refreshAtomicMirrors();
    var sender: CountingSender = .{};
    conn.setSender(&sender, CountingSender.send);

    // 40 packets of 1000 bytes each (two never fit one retransmission).
    const chunk = [_]u8{'D'} ** 1000;
    for (0..40) |_| try testing.expectEqual(chunk.len, try conn.writeStream(0, &chunk, false));
    try testing.expectEqual(@as(usize, 40), conn.app_stream_retx.count());

    // The peer received [20, 39] and [0, 9]; packets 10..19 were lost.
    const ranges = [_]frame.AckRange{.{ .gap = 9, .len = 9 }};
    var buf: [64]u8 = undefined;
    var fbs = compat.fixedBufWriter(&buf);
    _ = try (frame.Frame{ .ack = .{ .largest = 39, .ack_delay = 0, .first_range = 19, .ranges = &ranges } }).write(fbs.writer());
    _ = try incoming.processFrames(&ctx, &conn, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433), fbs.getWritten(), noSend);

    // Every byte of the lost packets is still tracked, under its packet
    // number or a retransmission's; nothing acknowledged is.
    var covered = [_]u8{0} ** 40;
    var it = conn.app_stream_retx.iterator();
    while (it.next()) |e| {
        const first: usize = @intCast(e.value_ptr.offset / chunk.len);
        try testing.expectEqual(@as(usize, 0), e.value_ptr.offset % chunk.len);
        try testing.expectEqual(chunk.len, e.value_ptr.data.len);
        covered[first] += 1;
    }
    for (covered, 0..) |c, i| {
        const lost = i >= 10 and i < 20;
        try testing.expectEqual(@as(u8, if (lost) 1 else 0), c);
    }
}
