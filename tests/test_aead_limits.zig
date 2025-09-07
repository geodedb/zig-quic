const std = @import("std");
const endpoint = @import("quic_endpoint");
const pkt = @import("quic_packet");
const fr = @import("quic_frame");
const conn_mod = @import("quic_conn");

// Test integrity limit enforcement: after N auth failures, endpoint sends CONNECTION_CLOSE AEAD_LIMIT_REACHED.
// We set the limit override to a tiny number to make this fast.

test "aead integrity limit triggers connection close" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var ep = try endpoint.Endpoint.init(&A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{}, .aead_integrity_limit_override = 2 });
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    // Create a client connection and install simple 1-RTT keys
    var c = try ep.connectClient("127.0.0.1:1");
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    const hp = [_]u8{0} ** 16;
    c.app_rx_keys = .{ .key = key, .iv = iv, .hp = hp };
    c.app_tx_keys = .{ .key = key, .iv = iv, .hp = hp };

    // Build two bogus short packets that won't authenticate: mutate ciphertext bytes randomly.
    var frames = std.ArrayList(u8){};
    defer frames.deinit(alloc);
    _ = (fr.Frame{ .ping = {} }).write(frames.writer(alloc)) catch 0;
    const good = try pkt.encodeShortProtected(A, c.our_scid.bytes[0..c.our_scid.len], 1, 2, frames.items, .{ .key = key, .iv = iv, .hp = hp }, false);
    defer A.free(good);

    // Corrupt a byte in ciphertext/tag area to cause auth failure
    var bad1 = try A.alloc(u8, good.len);
    defer A.free(bad1);
    @memcpy(bad1, good);
    bad1[bad1.len - 1] ^= 0xFF;

    var bad2 = try A.alloc(u8, good.len);
    defer A.free(bad2);
    @memcpy(bad2, good);
    bad2[bad2.len - 2] ^= 0xAA;

    // Inject two bad packets; second should push us to the limit and the endpoint should reply with CONNECTION_CLOSE
    ep.testInject(c.peer, bad1);
    ep.testInject(c.peer, bad2);

    // Endpoint should have captured at least one outgoing close packet
    try std.testing.expect(ep.captureLen() > 0);
    const cap = ep.capturePop() orelse return error.MissingCapture;
    defer A.free(cap.bytes);

    // Decode captured short packet payload and look for CONNECTION_CLOSE with error_code 0x0f
    const dec = try pkt.decodeShortProtected(A, cap.bytes, c.our_scid.len, .{ .key = key, .iv = iv, .hp = hp });
    defer A.free(dec.payload);
    var off: usize = 0;
    var saw_close = false;
    while (off < dec.payload.len) {
        const r = try fr.decodeOne(dec.payload[off..]);
        off += r.n;
        switch (r.f) {
            .connection_close => |cc| {
                try std.testing.expectEqual(@as(u64, 0x0f), cc.error_code);
                saw_close = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_close);
}
