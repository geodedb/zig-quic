const std = @import("std");
const endpoint = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const fr = @import("quic_frame");
const pkt = @import("quic_packet");

// Explicitly validate adaptive flow-control growth thresholds:
//  - Stream window bumps after 75% consumption (local_max_stream_data += 50%).
//  - Connection window bumps after 70% consumption (local_max_data += max(stream_window, conn_window/4)).
test "flow control adaptive growth thresholds" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();
    var ep = try endpoint.Endpoint.init(&A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();
    var c = try ep.connectClient("127.0.0.1:1");
    // Deterministic 1-RTT keys (all-zero)
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    const hp = [_]u8{0} ** 16;
    c.app_rx_keys = .{ .key = key, .iv = iv, .hp = hp };
    c.app_tx_keys = .{ .key = key, .iv = iv, .hp = hp };

    const init_stream_max = c.local_max_stream_data; // 64 KiB (set in init())
    const init_conn_max = c.local_max_data; // 256 KiB
    // Sanity
    try std.testing.expect(init_stream_max > 0 and init_conn_max > init_stream_max);

    // Helper to inject encoded short packet with provided frames
    const inject = struct {
        fn go(a: std.mem.Allocator, e: *endpoint.Endpoint, cn: *conn_mod.Connection, frames_bytes: []const u8) !void {
            const pkt_bytes = try pkt.encodeShortProtected(a, cn.our_scid.bytes[0..cn.our_scid.len], 1, 2, frames_bytes, .{ .key = key, .iv = iv, .hp = hp }, false);
            defer a.free(pkt_bytes);
            e.testInject(cn.peer, pkt_bytes);
        }
    }.go;

    // 1) Cross 75% of stream window: threshold = 3/4 * init_stream_max.
    const stream_threshold = (init_stream_max * 3) / 4; // 75%
    const need1: usize = @intCast(stream_threshold + 1); // just past threshold
    const payload1 = try A.alloc(u8, need1);
    defer A.free(payload1);
    @memset(payload1, 'A');
    var fb1 = std.ArrayList(u8){};
    defer fb1.deinit(alloc);
    _ = (fr.Frame{ .stream = .{ .stream_id = 0, .offset = 0, .fin = false, .data = payload1 } }).write(fb1.writer(alloc)) catch 0;
    try inject(A, &ep, &c, fb1.items);

    // Expect one captured ACK containing MAX_STREAM_DATA (initial advertisement) + updated after bump? We only bumped after push.
    try std.testing.expect(ep.captureLen() > 0);
    const cap1 = ep.capturePop().?;
    defer A.free(cap1.bytes);
    const dec1 = try pkt.decodeShortProtected(A, cap1.bytes, c.our_scid.len, .{ .key = key, .iv = iv, .hp = hp });
    defer A.free(dec1.payload);
    // After reading data, window should have increased by 50%.
    const expected_stream_after = init_stream_max + init_stream_max / 2; // +50%
    try std.testing.expectEqual(expected_stream_after, c.local_max_stream_data);
    var off: usize = 0;
    var saw_msd = false;
    var saw_md = false;
    while (off < dec1.payload.len) {
        const pr = try fr.decodeOne(dec1.payload[off..]);
        off += pr.n;
        switch (pr.f) {
            .max_stream_data => |msd| {
                if (msd.stream_id == 0) {
                    try std.testing.expect(msd.max == c.local_max_stream_data);
                    saw_msd = true;
                }
            },
            .max_data => |md| {
                try std.testing.expectEqual(init_conn_max, md.max);
                saw_md = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_msd and saw_md);

    // 2) Cross 70% of connection window to trigger connection-level growth.
    const conn_threshold = (init_conn_max * 7) / 10; // 70%
    const already = need1; // counted toward conn_recv_total
    const need_more: usize = @intCast((conn_threshold + 1) - already + 4096); // ensure surpass
    const payload2 = try A.alloc(u8, need_more);
    defer A.free(payload2);
    @memset(payload2, 'B');
    var fb2 = std.ArrayList(u8){};
    defer fb2.deinit(alloc);
    _ = (fr.Frame{ .stream = .{ .stream_id = 0, .offset = payload1.len, .fin = false, .data = payload2 } }).write(fb2.writer(alloc)) catch 0;
    try inject(A, &ep, &c, fb2.items);
    try std.testing.expect(ep.captureLen() > 0);
    const cap2 = ep.capturePop().?;
    defer A.free(cap2.bytes);
    const dec2 = try pkt.decodeShortProtected(A, cap2.bytes, c.our_scid.len, .{ .key = key, .iv = iv, .hp = hp });
    defer A.free(dec2.payload);
    const expected_conn_after = init_conn_max + (expected_stream_after); // bump chosen = max(stream_max_after, init_conn_max/4)
    try std.testing.expectEqual(expected_conn_after, c.local_max_data);
    off = 0;
    saw_msd = false;
    saw_md = false;
    while (off < dec2.payload.len) {
        const pr = try fr.decodeOne(dec2.payload[off..]);
        off += pr.n;
        switch (pr.f) {
            .max_stream_data => |msd| {
                if (msd.stream_id == 0) {
                    try std.testing.expectEqual(c.local_max_stream_data, msd.max);
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
