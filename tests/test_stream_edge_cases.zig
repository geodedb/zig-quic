const std = @import("std");
const conn_mod = @import("quic_conn");

fn makeConn(a: *std.mem.Allocator) conn_mod.Connection {
    var c: conn_mod.Connection = undefined;
    c.init(a, .Server, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    c.our_scid.len = 0;
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    return c;
}

test "stream: overlapping segments prefer earliest arrival for duplicate bytes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var c = makeConn(&gpa.allocator());
    defer c.deinit();

    // Push first segment [0..5) = "hello"
    try c.pushStreamFrame(0, 0, "hello", false);
    // Now overlapping segment [3..8) = "loXXX" should not regress already-read bytes
    try c.pushStreamFrame(0, 3, "loXXX", false);

    var buf: [16]u8 = undefined;
    const n = try c.readStream(0, &buf);
    try std.testing.expectEqualStrings("hello", buf[0..n]);
}

test "stream: FIN before data gap holds completion until hole filled" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var c = makeConn(&gpa.allocator());
    defer c.deinit();

    // Deliver FIN at final size 6 while only 0..3 have arrived
    try c.pushStreamFrame(0, 0, "abc", false);
    try c.pushStreamFrame(0, 6, &[_]u8{}, true);
    try std.testing.expect(!c.stream_recv_fin);
    // Fill the hole [3..6)
    try c.pushStreamFrame(0, 3, "def", false);
    try std.testing.expect(c.stream_recv_fin);
}

test "stream: recovery interplay—acked stream bytes update send offset" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var c = makeConn(&gpa.allocator());
    defer c.deinit();
    // Simulate sent bytes
    c.stream_send_off = 10;
    // Recovery ack callback should not decrease offset; idempotent on duplicate ack
    c.onStreamAcked(0, 0, 10);
    try std.testing.expectEqual(@as(u64, 10), c.stream_send_off);
    c.onStreamAcked(0, 0, 10);
    try std.testing.expectEqual(@as(u64, 10), c.stream_send_off);
}
