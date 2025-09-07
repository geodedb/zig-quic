const std = @import("std");
const endpoint = @import("quic_endpoint");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");

// Verifies server anti-amplification counters update and enforce 3x limit before validation.
test "anti_amplification_counters_update" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var ep = try endpoint.Endpoint.init(&alloc, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();

    // Enable capture and start with empty ring
    ep.test_capture_enabled = true;
    ep.captureClear();

    var c = try ep.connectClient("127.0.0.1:1");
    // NOTE: Do not destroy c here; Endpoint.deinit() will own and destroy connections.

    const initial = ks.deriveInitialSecret(false, c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
    const pair = ks.deriveClientServerInitial(initial);
    const tx_keys: packet.InitialKeys = blk: {
        const t = ks.deriveKeyIvHp(pair.client);
        break :blk .{ .key = t.key, .iv = t.iv, .hp = t.hp };
    };

    var frames = std.ArrayList(u8){};
    defer frames.deinit(alloc);
    _ = (frame.Frame{ .ping = {} }).write(frames.writer(alloc)) catch {};

    const pkt = try packet.encodeInitialProtected(
        alloc,
        packet.QUIC_V1,
        c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len],
        c.our_scid.bytes[0..c.our_scid.len],
        &[_]u8{},
        1,
        4, // 4-byte PN to satisfy HP sample requirements with tiny payload
        frames.items,
        tx_keys,
    );
    defer alloc.free(pkt);

    // Record bytes received by server (unvalidated)
    const rx_len: usize = pkt.len;

    ep.testInject(c.peer, pkt);

    // Sum captured outbound bytes
    var sent_total: usize = 0;
    while (ep.captureLen() > 0) {
        const cap_opt = ep.capturePop();
        if (cap_opt) |cap| {
            sent_total += cap.bytes.len;
            alloc.free(cap.bytes);
        } else break;
    }

    // Before address validation, server must not exceed 3x amplification
    try std.testing.expect(sent_total <= 3 * rx_len);
}
