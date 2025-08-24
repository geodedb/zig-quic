const std = @import("std");
const conn_mod = @import("quic_conn");
const pkt = @import("quic_packet");
const fr = @import("quic_frame");

const Capture = struct {
    alloc: std.mem.Allocator,
    bufs: std.ArrayList([]u8),

    fn init(a: std.mem.Allocator) Capture {
        return .{ .alloc = a, .bufs = std.ArrayList([]u8).init(a) };
    }
    fn deinit(self: *Capture) void {
        for (self.bufs.items) |b| self.alloc.free(b);
        self.bufs.deinit();
    }
};

fn captureSender(ctx: *anyopaque, _: *conn_mod.Connection, data: []const u8) anyerror!usize {
    var cap: *Capture = @ptrCast(@alignCast(ctx));
    const owned = try cap.alloc.alloc(u8, data.len);
    @memcpy(owned, data);
    try cap.bufs.append(owned);
    return data.len;
}

fn makeConn(a: *std.mem.Allocator) conn_mod.Connection {
    var c: conn_mod.Connection = undefined;
    // sock_fd 0 is fine; we'll override sender
    c.init(a, .Server, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    // minimal SCID
    c.our_scid.len = 0;
    // install deterministic app keys (all-zero)
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    return c;
}

fn decodeFirstShortPayload(a: std.mem.Allocator, bytes: []const u8, dcid_len: usize, keys: pkt.AeadKeys) ![]u8 {
    const dec = try pkt.decodeShortProtected(a, bytes, dcid_len, keys);
    return dec.payload;
}

test "stop_sending triggers reset_stream with final_size" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var cap = Capture.init(A);
    defer cap.deinit();

    var c = makeConn(&gpa.allocator());
    defer c.deinit();

    // install capture sender
    c.setSender(@ptrCast(&cap), captureSender);

    // simulate having sent 9 bytes on stream 0
    c.stream_send_off = 9;
    try c.handleStopSending(0, 1337);

    try std.testing.expect(cap.bufs.items.len >= 1);
    const sent = cap.bufs.items[cap.bufs.items.len - 1];

    const payload = try decodeFirstShortPayload(A, sent, c.our_scid.len, c.app_tx_keys.?);
    defer A.free(payload);

    const dec = try fr.decodeOne(payload);
    switch (dec.f) {
        .reset_stream => |rs| {
            try std.testing.expectEqual(@as(u64, 0), rs.stream_id);
            try std.testing.expectEqual(@as(u64, 1337), rs.error_code);
            try std.testing.expectEqual(@as(u64, 9), rs.final_size);
        },
        else => return error.UnexpectedFrame,
    }
}

test "writeStream blocked sends STREAM_DATA_BLOCKED and DATA_BLOCKED" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var cap = Capture.init(A);
    defer cap.deinit();

    var c = makeConn(&gpa.allocator());
    defer c.deinit();
    c.setSender(@ptrCast(&cap), captureSender);

    // Open stream 0
    c.stream_opened = true;

    // Case 1: stream-level FC blocks
    c.peer_max_stream_data = 5;
    c.peer_max_data = 1_000_000;
    var err = c.writeStream(0, "0123456789") catch |e| e;
    try std.testing.expect(err == error.FlowControlBlocked);
    try std.testing.expect(cap.bufs.items.len >= 1);
    const sent1 = cap.bufs.items[cap.bufs.items.len - 1];
    const payload1 = try decodeFirstShortPayload(A, sent1, c.our_scid.len, c.app_tx_keys.?);
    defer A.free(payload1);
    const dec1 = try fr.decodeOne(payload1);
    switch (dec1.f) {
        .stream_data_blocked => |sdb| {
            try std.testing.expectEqual(@as(u64, 0), sdb.stream_id);
            try std.testing.expectEqual(@as(u64, 5), sdb.limit);
        },
        else => return error.UnexpectedFrame,
    }

    // Case 2: connection-level FC blocks
    c.peer_max_stream_data = 1_000_000;
    c.peer_max_data = 7;
    err = c.writeStream(0, "abcdefghij") catch |e| e;
    try std.testing.expect(err == error.FlowControlBlocked);
    try std.testing.expect(cap.bufs.items.len >= 2);
    const sent2 = cap.bufs.items[cap.bufs.items.len - 1];
    const payload2 = try decodeFirstShortPayload(A, sent2, c.our_scid.len, c.app_tx_keys.?);
    defer A.free(payload2);
    const dec2 = try fr.decodeOne(payload2);
    switch (dec2.f) {
        .data_blocked => |db| {
            try std.testing.expectEqual(@as(u64, 7), db.limit);
        },
        else => return error.UnexpectedFrame,
    }
}

test "MAX_* thresholds bump on receive" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var c = makeConn(&gpa.allocator());
    defer c.deinit();

    // initial limits
    const init_stream = c.local_max_stream_data;
    const init_conn = c.local_max_data;

    // Push > 1/2 of stream window in one go
    const half_stream = init_stream / 2;
    const big = try A.alloc(u8, half_stream + 1000);
    defer A.free(big);
    @memset(big, 0x42);
    try c.pushStreamFrame(0, 0, big, false);

    try std.testing.expectEqual(init_stream + half_stream, c.local_max_stream_data);

    // Push to bump connection-level as well
    const half_conn = init_conn / 2;
    const more = try A.alloc(u8, @intCast(half_conn));
    defer A.free(more);
    @memset(more, 0x24);
    try c.pushStreamFrame(0, big.len, more, false);

    try std.testing.expectEqual(init_conn + half_conn, c.local_max_data);
}
