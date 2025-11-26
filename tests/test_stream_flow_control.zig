const std = @import("std");
const conn_mod = @import("quic_conn");
const pkt = @import("quic_packet");
const fr = @import("quic_frame");
const endpoint = @import("quic_endpoint");

const Capture = struct {
    alloc: std.mem.Allocator,
    bufs: std.ArrayList([]u8),

    fn init(a: std.mem.Allocator) Capture {
        return .{ .alloc = a, .bufs = std.ArrayList([]u8){} };
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
    try cap.bufs.append(alloc, owned);
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

test "reset_stream rx trims buffered beyond final_size and finishes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var c = makeConn(&gpa.allocator());
    defer c.deinit();

    // Ensure stream 0 RX exists; insert out-of-order segment first so it stays buffered.
    const seg = try A.alloc(u8, 4);
    defer A.free(seg);
    @memset(seg, 'X');
    try c.pushStreamFrame(0, 5, seg, false); // offset 5, will not drain (recv_off=0)

    // Now deliver a RESET_STREAM with final_size=3
    c.handleResetStream(0, 999, 3);

    try std.testing.expect(c.stream_recv_aborted);
    try std.testing.expect(c.stream_recv_fin);

    // Nothing should be readable (inbox empty), but recv_off should be treated as final_size.
    var tmp: [16]u8 = undefined;
    const n = c.readStream(0, &tmp) catch |e| switch (e) {
        error.InvalidStream => 0, // if teardown happened elsewhere this would be fine too
        else => return e,
    };
    try std.testing.expectEqual(@as(usize, 0), n);

    // Further STREAM data must be ignored after reset
    const more = try A.alloc(u8, 10);
    defer A.free(more);
    @memset(more, 'Y');
    // pushStreamFrame returns error? It returns !void; our implementation early-returns when aborted.
    try c.pushStreamFrame(0, 0, more, false);
    const n2 = c.readStream(0, &tmp) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n2);
}

test "teardownStream clears RX state and flags allowing reopen" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var c = makeConn(&gpa.allocator());
    defer c.deinit();

    // Open stream 0 and send some bytes to set flags and counters
    c.stream_opened = true;
    c.stream_send_off = 42;
    try c.pushStreamFrame(0, 0, "hello", false);

    // Teardown
    c.teardownStream(0);

    // Reading now should report InvalidStream
    var buf: [8]u8 = undefined;
    const err = c.readStream(0, &buf) catch |e| e;
    try std.testing.expect(err == error.InvalidStream);

    // Flags reset and counters cleared for stream 0
    try std.testing.expect(!c.stream_opened);
    try std.testing.expect(!c.stream_recv_aborted);
    try std.testing.expect(!c.stream_recv_fin);
    try std.testing.expectEqual(@as(u64, 0), c.stream_send_off);

    // Re-open should succeed
    const sid = c.openStream(true) catch |e| return e;
    try std.testing.expectEqual(@as(u64, 0), sid);
}

test "fin-aware reassembly drains when hole filled and FIN marks completion" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var c = makeConn(&gpa.allocator());
    defer c.deinit();

    // Ensure RX stream exists; deliver out-of-order segment first, then in-order, then FIN.
    try c.pushStreamFrame(0, 5, "world", false); // buffered (recv_off=0)
    try c.pushStreamFrame(0, 0, "hello", false); // drains "hello" and then "world"

    // Before FIN, reading should yield the contiguous data only.
    var buf: [16]u8 = undefined;
    var n = try c.readStream(0, &buf);
    try std.testing.expectEqualStrings("helloworld", buf[0..n]);

    // Now mark FIN at final size (offset 10 with zero-length FIN).
    try c.pushStreamFrame(0, 10, &[_]u8{}, true);
    try std.testing.expect(c.stream_recv_fin);

    // No more data to read now; stream considered complete at recv_off == fin_off.
    n = try c.readStream(0, &buf);
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "endpoint ACK includes updated MAX_* after threshold bumps" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    // Spin up endpoint with capture
    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    // Create a client-side connection mapping and install all-zero 1-RTT keys for tests
    var c = try ep.connectClient("127.0.0.1:1");
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    const hp = [_]u8{0} ** 16;
    c.app_rx_keys = .{ .key = key, .iv = iv, .hp = hp };
    c.app_tx_keys = .{ .key = key, .iv = iv, .hp = hp };

    // Helper to encode and inject a single short packet containing given frames
    const inject = struct {
        fn go(alloc_: std.mem.Allocator, ep_: *endpoint.Endpoint, c_: *conn_mod.Connection, frames_bytes: []const u8) !void {
            const pkt_bytes = try pkt.encodeShortProtected(alloc_, c_.our_scid.bytes[0..c_.our_scid.len], 1, 2, frames_bytes, .{ .key = key, .iv = iv, .hp = hp }, false);
            defer alloc_.free(pkt_bytes);
            ep_.testInject(c_.peer, pkt_bytes);
        }
    }.go;

    // Record initial advertised maxima
    const init_stream_max = c.local_max_stream_data;
    const init_conn_max = c.local_max_data;

    // 1) Cross the stream-level half-window to trigger a MAX_STREAM_DATA bump, but keep below connection half-window.
    const half_stream: usize = @intCast(init_stream_max / 2);
    const payload1 = try A.alloc(u8, half_stream + 100);
    defer A.free(payload1);
    @memset(payload1, 'A');
    var fb1 = std.ArrayList(u8){};
    defer fb1.deinit(alloc);
    _ = (fr.Frame{ .stream = .{ .stream_id = 0, .offset = 0, .fin = false, .data = payload1 } }).write(fb1.writer(alloc)) catch 0;
    try inject(A, &ep, &c, fb1.items);

    // Expect a captured ACK+MAX_*; decode and assert max_stream_data matches connection's bumped value.
    try std.testing.expect(ep.captureLen() > 0);
    const cap1_opt = ep.capturePop();
    try std.testing.expect(cap1_opt != null);
    const cap1 = cap1_opt.?;
    defer A.free(cap1.bytes);
    const dec1 = try pkt.decodeShortProtected(A, cap1.bytes, c.our_scid.len, .{ .key = key, .iv = iv, .hp = hp });
    defer A.free(dec1.payload);
    var off: usize = 0;
    var saw_msd1 = false;
    var saw_md1 = false;
    while (off < dec1.payload.len) {
        const pr = try fr.decodeOne(dec1.payload[off..]);
        off += pr.n;
        switch (pr.f) {
            .max_stream_data => |msd| {
                if (msd.stream_id == 0) {
                    try std.testing.expectEqual(c.local_max_stream_data, msd.max);
                    saw_msd1 = true;
                }
            },
            .max_data => |md| {
                try std.testing.expectEqual(init_conn_max, md.max);
                saw_md1 = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_msd1 and saw_md1);

    // 2) Cross the connection-level half-window to trigger MAX_DATA; also advance stream offset.
    const half_conn: usize = @intCast(init_conn_max / 2);
    const payload2 = try A.alloc(u8, half_conn + 1024);
    defer A.free(payload2);
    @memset(payload2, 'B');
    var fb2 = std.ArrayList(u8){};
    defer fb2.deinit(alloc);
    _ = (fr.Frame{ .stream = .{ .stream_id = 0, .offset = payload1.len, .fin = false, .data = payload2 } }).write(fb2.writer(alloc)) catch 0;
    try inject(A, &ep, &c, fb2.items);

    // Inspect second captured packet
    try std.testing.expect(ep.captureLen() > 0);
    const cap2_opt = ep.capturePop();
    try std.testing.expect(cap2_opt != null);
    const cap2 = cap2_opt.?;
    defer A.free(cap2.bytes);
    const dec2 = try pkt.decodeShortProtected(A, cap2.bytes, c.our_scid.len, .{ .key = key, .iv = iv, .hp = hp });
    defer A.free(dec2.payload);
    off = 0;
    var saw_msd2 = false;
    var saw_md2 = false;
    while (off < dec2.payload.len) {
        const pr = try fr.decodeOne(dec2.payload[off..]);
        off += pr.n;
        switch (pr.f) {
            .max_stream_data => |msd| {
                if (msd.stream_id == 0) {
                    try std.testing.expectEqual(c.local_max_stream_data, msd.max);
                    saw_msd2 = true;
                }
            },
            .max_data => |md| {
                try std.testing.expectEqual(c.local_max_data, md.max);
                saw_md2 = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_msd2 and saw_md2);
}

test "sustained blocked coalesces STREAM_DATA_BLOCKED and DATA_BLOCKED until limits change" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var cap = Capture.init(A);
    defer cap.deinit();

    var c = makeConn(&gpa.allocator());
    defer c.deinit();
    c.setSender(@ptrCast(&cap), captureSender);
    c.stream_opened = true;

    // Stream-level block and coalescing
    c.peer_max_stream_data = 5;
    c.peer_max_data = 1_000_000;
    const _e1 = c.writeStream(0, "0123456789") catch {};
    _ = _e1; // ignore
    try std.testing.expect(cap.bufs.items.len >= 1);
    const first_count = cap.bufs.items.len;
    // Repeated attempts while limit unchanged should not send more *_BLOCKED
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        _ = c.writeStream(0, "xxxx") catch {};
    }
    try std.testing.expectEqual(first_count, cap.bufs.items.len);
    // Increase stream limit but still below data size; should re-send sdb at new limit
    c.peer_max_stream_data = 8;
    _ = c.writeStream(0, "abcdefghij") catch {};
    try std.testing.expect(cap.bufs.items.len >= first_count + 1);

    // Connection-level block and coalescing
    cap.bufs.clearRetainingCapacity();
    c.stream_send_off = 0;
    c.conn_send_off = 0;
    c.peer_max_stream_data = 1_000_000;
    c.peer_max_data = 7;
    const _e2 = c.writeStream(0, "abcdefghij") catch {};
    _ = _e2;
    try std.testing.expect(cap.bufs.items.len >= 1);
    const first2 = cap.bufs.items.len;
    // More attempts shouldn't add more frames until limit changes
    _ = c.writeStream(0, "moremore") catch {};
    _ = c.writeStream(0, "moremore") catch {};
    try std.testing.expectEqual(first2, cap.bufs.items.len);
    // Raise conn limit slightly; still blocked by stream window? Ensure another DATA_BLOCKED goes out
    c.peer_max_data = 9;
    _ = c.writeStream(0, "ABCDEFGHIJ") catch {};
    try std.testing.expect(cap.bufs.items.len >= first2 + 1);
}

test "endpoint ACK does not include redundant MAX_* when values unchanged" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    var c = try ep.connectClient("127.0.0.1:2");
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    const hp = [_]u8{0} ** 16;
    c.app_rx_keys = .{ .key = key, .iv = iv, .hp = hp };
    c.app_tx_keys = .{ .key = key, .iv = iv, .hp = hp };

    // Helper to inject frames
    const inject = struct {
        fn go(a: std.mem.Allocator, e: *endpoint.Endpoint, cn: *conn_mod.Connection, frames_bytes: []const u8) !void {
            const pkt_bytes = try pkt.encodeShortProtected(a, cn.our_scid.bytes[0..cn.our_scid.len], 1, 2, frames_bytes, .{ .key = key, .iv = iv, .hp = hp }, cn.rx_key_phase);
            defer a.free(pkt_bytes);
            e.testInject(cn.peer, pkt_bytes);
        }
    }.go;

    // Cross a threshold once to cause MAX emission
    const half_stream: usize = @intCast(c.local_max_stream_data / 2);
    var fb = std.ArrayList(u8){};
    defer fb.deinit(alloc);
    const payload = try A.alloc(u8, half_stream + 16);
    defer A.free(payload);
    @memset(payload, 'Z');
    _ = (fr.Frame{ .stream = .{ .stream_id = 0, .offset = 0, .fin = false, .data = payload } }).write(fb.writer(alloc)) catch 0;
    try inject(A, &ep, &c, fb.items);
    // Pop first captured ack (with MAX_*)
    const cap1 = ep.capturePop().?;
    A.free(cap1.bytes);

    // Send another small packet that doesn't increase windows
    fb.clearRetainingCapacity();
    _ = (fr.Frame{ .ping = {} }).write(fb.writer(alloc)) catch 0;
    try inject(A, &ep, &c, fb.items);
    const cap2 = ep.capturePop().?;
    defer A.free(cap2.bytes);
    const dec2 = try pkt.decodeShortProtected(A, cap2.bytes, c.our_scid.len, .{ .key = key, .iv = iv, .hp = hp });
    defer A.free(dec2.payload);
    var off: usize = 0;
    var saw_msd = false;
    var saw_md = false;
    while (off < dec2.payload.len) {
        const pr = try fr.decodeOne(dec2.payload[off..]);
        off += pr.n;
        switch (pr.f) {
            .max_stream_data => saw_msd = true,
            .max_data => saw_md = true,
            else => {},
        }
    }
    try std.testing.expect(!saw_msd and !saw_md);
}
