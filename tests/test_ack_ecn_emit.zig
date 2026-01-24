const std = @import("std");
const endpoint = @import("quic_endpoint");
const packet = @import("quic_packet");
const frame = @import("quic_frame");

// Verify that when ECN is observed on RX, the endpoint emits ACK_ECN with counts.
test "endpoint emits ACK_ECN when ECN CE observed on incoming short packet" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var ep = try endpoint.Endpoint.init(alloc, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    // Create a client connection (mapping by our_scid) and install 1-RTT keys.
    var c = try ep.connectClient("127.0.0.1:1");
    // Static test keys (AES-128-GCM + AES-128 HP) — zeros are valid test vectors.
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    const hp = [_]u8{0} ** 16;
    c.app_rx_keys = .{ .key = key, .iv = iv, .hp = hp };
    c.app_tx_keys = .{ .key = key, .iv = iv, .hp = hp };

    // Build an incoming short header packet (PING) addressed to this connection (DCID = our_scid).
    var frames = std.ArrayList(u8){};
    defer frames.deinit(alloc);
    _ = (frame.Frame{ .ping = {} }).write(frames.writer(alloc)) catch {};
    const in_pkt = try packet.encodeShortProtected(
        alloc,
        c.our_scid.bytes[0..c.our_scid.len],
        1, // PN
        2, // PN len
        frames.items,
        .{ .key = key, .iv = iv, .hp = hp },
        false, // key_phase
    );
    defer alloc.free(in_pkt);

    // Inject with ECN CE (binary 11 -> 3).
    ep.testInjectWithEcn(c.peer, in_pkt, 0x03);

    // Expect an ACK packet captured; decrypt and assert ACK_ECN with ce=1.
    try std.testing.expect(ep.captureLen() > 0);
    const cap_opt = ep.capturePop();
    try std.testing.expect(cap_opt != null);
    const cap = cap_opt.?;
    defer alloc.free(cap.bytes);

    // Decode short header using the same keys (DCID length = our_scid len).
    const dcid_len: usize = c.our_scid.len;
    const dec = try packet.decodeShortProtected(alloc, cap.bytes, dcid_len, .{ .key = key, .iv = iv, .hp = hp });
    defer alloc.free(dec.payload);

    // First frame should be ACK, and it should be ACK_ECN with ce=1.
    const pr = try frame.decodeOne(dec.payload);
    try std.testing.expect(std.mem.eql(u8, @tagName(pr.f), "ack"));
    const a = pr.f.ack;
    try std.testing.expect(a.ecn != null);
    try std.testing.expectEqual(@as(u64, 1), a.ecn.?.ce);
    try std.testing.expectEqual(@as(u64, 0), a.ecn.?.ect0);
    try std.testing.expectEqual(@as(u64, 0), a.ecn.?.ect1);
}
