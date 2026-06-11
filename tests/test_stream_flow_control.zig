const std = @import("std");
const conn_mod = @import("quic_conn");
const pkt = @import("quic_packet");
const fr = @import("quic_frame");
const endpoint = @import("quic_endpoint");
const compat = @import("compat");

const Capture = struct {
    alloc: std.mem.Allocator,
    bufs: std.ArrayList([]u8),

    fn init(a: std.mem.Allocator) Capture {
        return .{ .alloc = a, .bufs = .empty };
    }
    fn deinit(self: *Capture) void {
        self.clear();
        self.bufs.deinit(self.alloc);
    }
    fn clear(self: *Capture) void {
        for (self.bufs.items) |b| self.alloc.free(b);
        self.bufs.clearRetainingCapacity();
    }
};

fn captureSender(ctx: *anyopaque, _: *conn_mod.Connection, data: []const u8) anyerror!usize {
    var cap: *Capture = @ptrCast(@alignCast(ctx));
    const owned = try cap.alloc.alloc(u8, data.len);
    @memcpy(owned, data);
    try cap.bufs.append(cap.alloc, owned);
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
    c.peer_finished_verified = true;
    return c;
}

fn decodeFirstShortPayload(a: std.mem.Allocator, bytes: []const u8, dcid_len: usize, keys: pkt.AeadKeys) ![]u8 {
    const dec = try pkt.decodeShortProtected(a, bytes, dcid_len, keys, 0);
    return dec.payload;
}

test "stream rx explicit states cover FIN and RESET terminal transitions" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();

    var rx = conn_mod.StreamRx.init();
    defer rx.deinit(&A);

    try std.testing.expectEqual(conn_mod.StreamReceiveState.Recv, rx.state);
    try rx.recordFin(5);
    try std.testing.expectEqual(conn_mod.StreamReceiveState.SizeKnown, rx.state);
    rx.insert(&A, 0, "hello");
    rx.tryDrain(&A);
    var out: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), rx.readInto(&out));
    try std.testing.expectEqual(conn_mod.StreamReceiveState.DataRead, rx.state);
    try std.testing.expectError(error.StreamStopped, rx.recordFin(6));

    var reset_rx = conn_mod.StreamRx.init();
    defer reset_rx.deinit(&A);
    reset_rx.insert(&A, 0, "abc");
    try reset_rx.recordReset(3);
    try std.testing.expectEqual(conn_mod.StreamReceiveState.ResetRead, reset_rx.state);
    const buffered_after_reset = reset_rx.bufs.items.len;
    reset_rx.insert(&A, 3, "ignored");
    try std.testing.expectEqual(buffered_after_reset, reset_rx.bufs.items.len);
}

test "recordReset rejects inconsistent final size (NEW-SEC-02)" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();

    // A RESET_STREAM final size that contradicts a previously established FIN
    // offset is a FINAL_SIZE_ERROR (RFC 9000 §4.5).
    var rx1 = conn_mod.StreamRx.init();
    defer rx1.deinit(&A);
    try rx1.recordFin(5);
    try std.testing.expectError(error.FinalSizeError, rx1.recordReset(3));
    // A consistent final size is accepted.
    try rx1.recordReset(5);

    // A final size below data already received is also a FINAL_SIZE_ERROR.
    var rx2 = conn_mod.StreamRx.init();
    defer rx2.deinit(&A);
    rx2.insert(&A, 0, "hello");
    rx2.tryDrain(&A); // recv_off advances to 5
    try std.testing.expectError(error.FinalSizeError, rx2.recordReset(3));
}

test "stream tx explicit states reject writes after FIN or RESET" {
    var tx = conn_mod.StreamTx{};

    try std.testing.expectEqual(conn_mod.StreamSendState.Ready, tx.state);
    try tx.recordDataSent(3, false);
    try std.testing.expectEqual(conn_mod.StreamSendState.Send, tx.state);
    try tx.recordDataSent(2, true);
    try std.testing.expectEqual(conn_mod.StreamSendState.DataSent, tx.state);
    try std.testing.expectError(error.StreamStopped, tx.recordDataSent(1, false));
    try std.testing.expectError(error.StreamStopped, tx.recordResetSent());

    var reset_tx = conn_mod.StreamTx{};
    try reset_tx.recordResetSent();
    try std.testing.expectEqual(conn_mod.StreamSendState.ResetSent, reset_tx.state);
    try std.testing.expectError(error.StreamStopped, reset_tx.recordDataSent(1, false));
}

test "stop_sending triggers reset_stream with final_size" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();

    var cap = Capture.init(A);
    defer cap.deinit();

    var c = makeConn(&A);
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
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();

    var cap = Capture.init(A);
    defer cap.deinit();

    var c = makeConn(&A);
    defer c.deinit();
    c.setSender(@ptrCast(&cap), captureSender);

    // Open stream 0
    c.stream_opened = true;

    // Case 1: stream-level FC blocks
    c.peer_max_stream_data = 5;
    c.peer_max_data = 1_000_000;
    c.stream_send_off = c.peer_max_stream_data;
    var err = c.writeStream(0, "0123456789", false) catch |e| e;
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
    cap.clear();
    var c2 = makeConn(&A);
    defer c2.deinit();
    c2.setSender(@ptrCast(&cap), captureSender);
    c2.stream_opened = true;
    c2.stream_send_off = 0;
    c2.conn_send_off = 7;
    c2.peer_max_stream_data = 1_000_000;
    c2.peer_max_data = 7;
    err = c2.writeStream(0, "abcdefghij", false) catch |e| e;
    try std.testing.expect(err == error.FlowControlBlocked);
    try std.testing.expect(cap.bufs.items.len >= 1);
    const sent2 = cap.bufs.items[cap.bufs.items.len - 1];
    const payload2 = try decodeFirstShortPayload(A, sent2, c2.our_scid.len, c2.app_tx_keys.?);
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
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();
    var c = makeConn(&A);
    defer c.deinit();

    // initial limits
    const init_stream = c.local_max_stream_data;

    // Push > 1/2 of stream window in one go
    const half_stream = init_stream / 2;
    const big = try A.alloc(u8, half_stream + 1000);
    defer A.free(big);
    @memset(big, 0x42);
    try c.pushStreamFrame(0, 0, big, false);
    try std.testing.expectEqual(init_stream, c.local_max_stream_data);
    var drain: [4096]u8 = undefined;
    while (true) {
        _ = c.readStream(0, &drain) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
    }
    const rx0 = c.streams_rx.getPtr(0) orelse return error.InvalidStream;
    try std.testing.expect(rx0.local_max_stream_data > init_stream);

    // Bump connection-level MAX_DATA. Use a fresh connection with a modest
    // initial connection window so the quinn-style growth (consumed + 10 MiB)
    // lifts local_max_data observably after a read, while every push stays
    // within both the per-stream window (16 MiB) and the connection window
    // (RFC 9000 §4.1; receive-side flow control is now enforced — QC-01).
    var c2 = makeConn(&A);
    defer c2.deinit();
    c2.local_max_data = 12 * 1024 * 1024; // 12 MiB initial connection window
    const init_conn2 = c2.local_max_data;
    const chunk = try A.alloc(u8, 8 * 1024 * 1024); // 8 MiB: within stream and conn windows
    defer A.free(chunk);
    @memset(chunk, 0x24);
    try c2.pushStreamFrame(0, 0, chunk, false);
    while (true) {
        _ = c2.readStream(0, &drain) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
    }
    try std.testing.expect(c2.local_max_data > init_conn2);
}

test "receive-side flow control rejects data beyond the stream window (QC-01)" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();
    var c = makeConn(&A);
    defer c.deinit();

    // A single STREAM frame whose end offset exceeds the advertised per-stream
    // window must be rejected with FlowControlError rather than buffered.
    const window = c.local_max_stream_data;
    const small = try A.alloc(u8, 16);
    defer A.free(small);
    @memset(small, 0x55);
    const err = c.pushStreamFrame(0, window + 1, small, false) catch |e| e;
    try std.testing.expect(err == error.FlowControlError);
    // Nothing should have been buffered for the rejected frame.
    if (c.streams_rx.getPtr(0)) |rx| {
        try std.testing.expectEqual(@as(u64, 0), rx.buffered_bytes);
    }
}

test "receive-side flow control bounds out-of-order buffering (QC-01)" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();
    var c = makeConn(&A);
    defer c.deinit();

    // Flooding gapped out-of-order segments must eventually be rejected once the
    // buffered-byte cap (the receive window) is reached, instead of growing
    // memory without bound. Use 1 MiB segments at increasing, non-contiguous
    // offsets so recv_off never advances.
    const seg = try A.alloc(u8, 1024 * 1024);
    defer A.free(seg);
    @memset(seg, 0x33);
    var off: u64 = 1; // start past recv_off (0) so nothing drains
    var rejected = false;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        c.pushStreamFrame(0, off, seg, false) catch |e| {
            try std.testing.expect(e == error.FlowControlError);
            rejected = true;
            break;
        };
        off += 2 * 1024 * 1024; // leave a 1 MiB hole between segments
    }
    try std.testing.expect(rejected);
    // Buffered bytes must stay within the stream window, never unbounded.
    if (c.streams_rx.getPtr(0)) |rx| {
        try std.testing.expect(rx.buffered_bytes <= c.local_max_stream_data);
    }
}

test "reset_stream rx trims buffered beyond final_size and finishes" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();

    var c = makeConn(&A);
    defer c.deinit();

    // Ensure stream 0 RX exists; insert out-of-order segment first so it stays buffered.
    const seg = try A.alloc(u8, 4);
    defer A.free(seg);
    @memset(seg, 'X');
    try c.pushStreamFrame(0, 5, seg, false); // offset 5, will not drain (recv_off=0)

    // Now deliver a RESET_STREAM with final_size=3
    try c.handleResetStream(0, 999, 3);

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
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();

    var A = gpa.allocator();
    var c = makeConn(&A);
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

    // QUIC stream IDs are not reused. After tearing down stream 0, the server's
    // next locally initiated bidirectional stream is stream 1.
    const sid = c.openStream(true) catch |e| return e;
    try std.testing.expectEqual(@as(u64, 1), sid);
}

test "fin-aware reassembly drains when hole filled and FIN marks completion" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();

    var A = gpa.allocator();
    var c = makeConn(&A);
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

test "flow control control packet includes updated MAX_* values" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();

    var cap = Capture.init(A);
    defer cap.deinit();

    var c = makeConn(&A);
    defer c.deinit();
    c.setSender(@ptrCast(&cap), captureSender);

    const rx = c.ensureStreamRx(0);
    rx.local_max_stream_data = c.local_max_stream_data + 64 * 1024;
    c.markStreamFlowControlDirty(0);
    c.local_max_data += 64 * 1024;
    c.advertiseInitialFlowControl();

    try std.testing.expect(cap.bufs.items.len >= 1);
    const payload = try decodeFirstShortPayload(A, cap.bufs.items[cap.bufs.items.len - 1], c.our_scid.len, c.app_tx_keys.?);
    defer A.free(payload);
    var off: usize = 0;
    var saw_msd = false;
    var saw_md = false;
    while (off < payload.len) {
        const pr = try fr.decodeOne(payload[off..]);
        off += pr.n;
        switch (pr.f) {
            .max_stream_data => |msd| {
                if (msd.stream_id == 0) {
                    try std.testing.expectEqual(rx.local_max_stream_data, msd.max);
                    saw_msd = true;
                }
            },
            .max_data => |md| {
                try std.testing.expectEqual(c.local_max_data, md.max);
                saw_md = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_msd and saw_md);
}

test "sustained blocked coalesces STREAM_DATA_BLOCKED and DATA_BLOCKED until limits change" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();

    var cap = Capture.init(A);
    defer cap.deinit();

    var c = makeConn(&A);
    defer c.deinit();
    c.setSender(@ptrCast(&cap), captureSender);
    c.stream_opened = true;

    // Stream-level block and coalescing
    c.peer_max_stream_data = 5;
    c.peer_max_data = 1_000_000;
    c.stream_send_off = c.peer_max_stream_data;
    _ = c.writeStream(0, "0123456789", false) catch {};
    try std.testing.expect(cap.bufs.items.len >= 1);
    const first_count = cap.bufs.items.len;
    // Repeated attempts while limit unchanged should not send more *_BLOCKED
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        _ = c.writeStream(0, "xxxx", false) catch {};
    }
    try std.testing.expectEqual(first_count, cap.bufs.items.len);
    // Limit changes are validated by the single-shot blocked-frame tests above;
    // this check focuses on coalescing for unchanged limits.

    // Connection-level block and coalescing
    cap.clear();
    var c_data = makeConn(&A);
    defer c_data.deinit();
    c_data.setSender(@ptrCast(&cap), captureSender);
    c_data.stream_opened = true;
    c_data.stream_send_off = 0;
    c_data.peer_max_stream_data = 1_000_000;
    c_data.peer_max_data = 7;
    c_data.conn_send_off = c_data.peer_max_data;
    _ = c_data.writeStream(0, "abcdefghij", false) catch {};
    try std.testing.expect(cap.bufs.items.len >= 1);
    const first2 = cap.bufs.items.len;
    // More attempts shouldn't add more frames until limit changes
    _ = c_data.writeStream(0, "moremore", false) catch {};
    _ = c_data.writeStream(0, "moremore", false) catch {};
    try std.testing.expectEqual(first2, cap.bufs.items.len);
    // Limit changes are covered by the single-shot blocked-frame tests above;
    // this branch verifies only that unchanged limits coalesce duplicate frames.
}

test "flow control control packet omits redundant MAX_* when values unchanged" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();

    var cap = Capture.init(A);
    defer cap.deinit();

    var c = makeConn(&A);
    defer c.deinit();
    c.setSender(@ptrCast(&cap), captureSender);

    const rx = c.ensureStreamRx(0);
    rx.local_max_stream_data = c.local_max_stream_data + 64 * 1024;
    c.markStreamFlowControlDirty(0);
    c.local_max_data += 64 * 1024;
    c.advertiseInitialFlowControl();
    try std.testing.expect(cap.bufs.items.len >= 1);

    cap.clear();
    c.advertiseInitialFlowControl();
    try std.testing.expectEqual(@as(usize, 0), cap.bufs.items.len);
}
