const std = @import("std");
const endpoint = @import("quic_endpoint");
const fr = @import("quic_frame");
const pkt = @import("quic_packet");

test "key update harness basic" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();
    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:1");
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    const hp = [_]u8{0} ** 16;
    c.app_rx_keys = .{ .key = key, .iv = iv, .hp = hp };
    c.app_tx_keys = .{ .key = key, .iv = iv, .hp = hp };
    c.app_tx_secret = [_]u8{0} ** 32;
    c.app_rx_secret = [_]u8{0} ** 32;
    var frames = std.ArrayList(u8){};
    defer frames.deinit(alloc);
    _ = (fr.Frame{ .ping = {} }).write(frames.writer(alloc)) catch 0;
    const start_phase = c.tx_key_phase;
    var i: usize = 0;
    while (!c.tx_update_in_progress and i < 80) : (i += 1) {
        const sh = try pkt.encodeShortProtected(A, c.our_scid.bytes[0..c.our_scid.len], @as(u32, @truncate(c.pn_app_tx)), 2, frames.items, c.app_tx_keys.?, false);
        defer A.free(sh);
        c.onShortHeaderPacketSent(sh.len, true);
    }
    try std.testing.expect(c.tx_update_in_progress);
    try std.testing.expect(c.tx_key_phase != start_phase);
    c.maybeFinalizeKeyUpdateOnAck(c.tx_update_start_pn);
    try std.testing.expect(!c.tx_update_in_progress);
}
