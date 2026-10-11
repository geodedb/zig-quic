const std = @import("std");
const conn_mod = @import("quic_conn");
const frame = @import("quic_frame");

test "SONNY-4797 ACK intervals preserve inclusive bounds and multiple gaps including packet zero" {
    const acked = try frame.AckIntervals.init(15, 2, &.{ .{ .gap = 2, .len = 3 }, .{ .gap = 4, .len = 0 } });
    var storage: [8]u64 = undefined;
    // [13,15], [6,9], [0,0]. Gap encodes the missing count minus one.
    try std.testing.expectEqualSlices(u64, &.{ 15, 14, 13, 9, 8, 7, 6, 0 }, acked.packetNumbers(&storage).?);
    for (0..17) |pn| {
        const expected = (pn >= 13 and pn <= 15) or (pn >= 6 and pn <= 9) or pn == 0;
        try std.testing.expectEqual(expected, acked.contains(pn));
    }
}

test "SONNY-4797 numeric ACK width cannot force expansion or partial output" {
    const largest = std.math.maxInt(u62);
    const acked = try frame.AckIntervals.init(largest, largest, &.{});
    var storage = [_]u64{123} ** 256;
    try std.testing.expectEqual(@as(?[]const u64, null), acked.packetNumbers(&storage));
    for (storage) |value| try std.testing.expectEqual(@as(u64, 123), value);
    try std.testing.expect(acked.contains(0));
    try std.testing.expect(acked.contains(largest));
    try std.testing.expect(!acked.contains(@as(u64, largest) + 1));
}

test "SONNY-4797 ACK validation rejects impossible ranges before unsigned arithmetic" {
    const intervals = frame.AckIntervals;
    try std.testing.expectError(error.InvalidAckRange, intervals.init(1, 2, &.{}));
    try std.testing.expectError(error.InvalidAckRange, intervals.init(std.math.maxInt(u64), 0, &.{}));
    try std.testing.expectError(error.InvalidAckRange, intervals.init(31, 0, &.{.{ .gap = std.math.maxInt(u64), .len = 0 }}));
    try std.testing.expectError(error.InvalidAckRange, intervals.init(31, 0, &.{.{ .gap = 0, .len = 30 }}));
    const too_many = [_]frame.AckRange{.{ .gap = 0, .len = 0 }} ** 65;
    try std.testing.expectError(error.InvalidAckRange, intervals.init(1000, 0, &too_many));
}

test "SONNY-4797 selective ACK preserves every unacknowledged STREAM chunk beyond the retransmit budget" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    const Sender = struct {
        fn send(_: *anyopaque, _: *conn_mod.Connection, data: []const u8) anyerror!usize {
            return data.len;
        }
    };
    var context: u8 = 0;
    conn.setSender(&context, Sender.send);
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_initial_scid.len = 4;
    std.mem.copyForwards(u8, conn.peer_initial_scid.bytes[0..4], "PEER");
    for (0..32) |i| {
        const data = [_]u8{@intCast(i)};
        try std.testing.expectEqual(@as(usize, 1), try conn.writeStream(0, &data, false));
    }
    try std.testing.expectEqual(@as(usize, 32), conn.app_stream_retx.count());
    // ACK only the last packet. The preceding 31 stream bytes are still owed
    // to the peer, regardless of recovery compaction or the per-ACK send cap.
    conn.onAckReceivedSpace(.Application, 31, 0, &.{}, null);
    try std.testing.expectEqual(@as(usize, 31), conn.app_stream_retx.count());
    var retained = [_]bool{false} ** 31;
    var it = conn.app_stream_retx.valueIterator();
    while (it.next()) |entry| {
        try std.testing.expectEqual(@as(usize, 1), entry.data.len);
        try std.testing.expect(entry.offset < retained.len);
        try std.testing.expectEqual(@as(u8, @intCast(entry.offset)), entry.data[0]);
        try std.testing.expect(!retained[@intCast(entry.offset)]);
        retained[@intCast(entry.offset)] = true;
    }
    for (retained) |present| try std.testing.expect(present);
}

const StreamAckSender = struct {
    fail: bool = false,

    fn send(ctx: *anyopaque, _: *conn_mod.Connection, data: []const u8) anyerror!usize {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (self.fail) return error.WouldBlock;
        return data.len;
    }
};

fn initStreamAckConnection(conn: *conn_mod.Connection, allocator: *std.mem.Allocator, sender: *StreamAckSender) void {
    conn.init(allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    conn.setSender(sender, StreamAckSender.send);
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_initial_scid.len = 4;
    std.mem.copyForwards(u8, conn.peer_initial_scid.bytes[0..4], "PEER");
}

fn writeNumberedChunks(conn: *conn_mod.Connection, count: usize) !void {
    for (0..count) |i| {
        const data = [_]u8{@truncate(i)};
        try std.testing.expectEqual(@as(usize, 1), try conn.writeStream(0, &data, false));
    }
}

test "SONNY-4797 complete ACK ranges reclaim data and recovery credit beyond 256 packets" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    var sender = StreamAckSender{};
    initStreamAckConnection(&conn, &allocator, &sender);
    defer conn.deinit();
    try writeNumberedChunks(&conn, 300);
    try std.testing.expect(conn.rec.getCongestionState().bytes_in_flight > 0);
    conn.onAckReceivedSpace(.Application, 299, 299, &.{}, null);
    try std.testing.expectEqual(@as(usize, 0), conn.app_stream_retx.count());
    try std.testing.expectEqual(@as(usize, 0), conn.rec.getCongestionState().bytes_in_flight);
    // A fully received window must not emit false retransmissions.
    try std.testing.expectEqual(@as(u64, 300), conn.pn_app_tx);
}

test "SONNY-4797 large selective ACK ranges reclaim acknowledged data and preserve their gap" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    var sender = StreamAckSender{};
    initStreamAckConnection(&conn, &allocator, &sender);
    defer conn.deinit();
    try writeNumberedChunks(&conn, 320);
    // [64, 319] and [0, 47] are acknowledged; [48, 63] is not.
    conn.onAckReceivedSpace(.Application, 319, 255, &.{.{ .gap = 15, .len = 47 }}, null);
    try std.testing.expectEqual(@as(usize, 16), conn.app_stream_retx.count());
    var present = [_]bool{false} ** 16;
    var it = conn.app_stream_retx.valueIterator();
    while (it.next()) |entry| {
        try std.testing.expect(entry.offset >= 48 and entry.offset < 64);
        const index: usize = @intCast(entry.offset - 48);
        try std.testing.expect(!present[index]);
        present[index] = true;
        try std.testing.expectEqualSlices(u8, &.{@intCast(entry.offset)}, entry.data);
    }
    for (present) |found| try std.testing.expect(found);
}

test "SONNY-4797 repeated selective ACKs cannot retire outstanding stream bytes" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    var sender = StreamAckSender{};
    initStreamAckConnection(&conn, &allocator, &sender);
    defer conn.deinit();
    try writeNumberedChunks(&conn, 32);
    for (0..20) |_| {
        conn.onAckReceivedSpace(.Application, 31, 0, &.{}, null);
        try std.testing.expectEqual(@as(usize, 31), conn.app_stream_retx.count());
    }
}

test "SONNY-4797 failed ACK-triggered retransmission retains payload and FIN for PTO" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    var sender = StreamAckSender{};
    initStreamAckConnection(&conn, &allocator, &sender);
    defer conn.deinit();
    try std.testing.expectEqual(@as(usize, 8), try conn.writeStream(0, "terminal", true));
    const sibling = try conn.openStream(true);
    for (0..32) |_| try std.testing.expectEqual(@as(usize, 1), try conn.writeStream(sibling, "X", false));
    sender.fail = true;
    conn.onAckReceivedSpace(.Application, 32, 0, &.{}, null);
    try std.testing.expectEqual(@as(usize, 32), conn.app_stream_retx.count());
    const retained = conn.app_stream_retx.get(0).?;
    try std.testing.expect(retained.fin);
    try std.testing.expectEqualStrings("terminal", retained.data);
    sender.fail = false;
    const next_pn = conn.pn_app_tx;
    conn.sendPtoProbeApp();
    try std.testing.expectEqual(next_pn + 1, conn.pn_app_tx);
    const retried = conn.app_stream_retx.get(next_pn).?;
    try std.testing.expect(retried.fin);
    try std.testing.expectEqual(@as(u64, 0), retried.stream_id);
    try std.testing.expectEqualStrings("terminal", retried.data);
    try std.testing.expectEqual(@as(usize, 32), conn.app_stream_retx.count());
}

test "SONNY-4797 malformed ACK ranges cannot mutate retained data or recovery" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    var sender = StreamAckSender{};
    initStreamAckConnection(&conn, &allocator, &sender);
    defer conn.deinit();
    try writeNumberedChunks(&conn, 32);
    const inflight = conn.rec.getCongestionState().bytes_in_flight;
    conn.onAckReceivedSpace(.Application, 31, 32, &.{}, null);
    conn.onAckReceivedSpace(.Application, 31, 0, &.{.{ .gap = std.math.maxInt(u64), .len = 0 }}, null);
    conn.onAckReceivedSpace(.Application, 31, 0, &.{.{ .gap = 0, .len = 30 }}, null);
    try std.testing.expectEqual(@as(usize, 32), conn.app_stream_retx.count());
    try std.testing.expectEqual(@as(u64, 32), conn.pn_app_tx);
    try std.testing.expectEqual(inflight, conn.rec.getCongestionState().bytes_in_flight);
}
