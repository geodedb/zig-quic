const std = @import("std");
const endpoint = @import("quic_endpoint");
const packet = @import("quic_packet");
const frame = @import("quic_frame");

// End-to-end: when ECN CE is observed on a Handshake packet, server emits ACK_ECN in Handshake space.
test "handshake space: ECN CE triggers ACK_ECN in server Handshake ACK" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var ep = try endpoint.Endpoint.init(&A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    var c = try ep.connectClient("127.0.0.1:3456");

    // Install symmetric Handshake keys for RX/TX (zeros are fine for tests).
    const z16 = [_]u8{0} ** 16;
    const z12 = [_]u8{0} ** 12;
    c.hs_rx_keys = .{ .key = z16, .iv = z12, .hp = z16 };
    c.hs_tx_keys = c.hs_rx_keys;

    // Build a minimal incoming Handshake packet (PING) addressed to this connection (DCID = our_scid).
    var frames = std.ArrayList(u8){};
    defer frames.deinit(alloc);
    _ = (frame.Frame{ .ping = {} }).write(frames.writer(alloc)) catch {};
    const in_pkt = try packet.encodeHandshakeProtected(
        A,
        0x00000001,
        c.our_scid.bytes[0..c.our_scid.len], // DCID
        &[_]u8{}, // SCID arbitrary for test
        1, // PN
        2, // PN len
        frames.items,
        c.hs_rx_keys.?,
    );
    defer A.free(in_pkt);

    // Inject with ECN CE so server records CE and emits ACK_ECN in Handshake.
    ep.testInjectWithEcn(c.peer, in_pkt, 0x03);

    // Expect a captured Handshake ACK from server; decode with server Handshake keys and assert ACK_ECN.
    try std.testing.expect(ep.captureLen() > 0);
    const cap = ep.capturePop().?;
    defer A.free(cap.bytes);

    // Handshake decode (no dedicated helper): follow the pattern from initial_handshake_loop test.
    var i: usize = 0;
    try std.testing.expect((cap.bytes[0] & 0x80) != 0); // long header
    i = 1 + 4; // first + version
    const dlen = cap.bytes[i];
    i += 1 + dlen;
    const slen = cap.bytes[i];
    i += 1 + slen;
    const len_dec = try @import("quic_varint").decode(cap.bytes[i..]);
    i += len_dec.n;
    const pn_start = i;
    if (pn_start + 4 + 16 > cap.bytes.len) return error.TestFailed;

    var header_first_masked = cap.bytes[0];
    var pn_masked: [4]u8 = .{0} ** 4;
    const pn_avail = @min(@as(usize, 4), cap.bytes.len - pn_start);
    @memcpy(pn_masked[0..pn_avail], cap.bytes[pn_start .. pn_start + pn_avail]);
    var sample16: [16]u8 = undefined;
    @memcpy(sample16[0..], cap.bytes[pn_start + 4 .. pn_start + 4 + 16]);

    var header_tmp = header_first_masked;
    var pn_tmp = pn_masked;
    const pn_len = try @import("quic_crypto").unmaskLongHeaderAndPn(
        .aes_128_gcm,
        &c.hs_tx_keys.?.hp,
        &sample16,
        &header_tmp,
        &pn_tmp,
    );

    const header_prefix = cap.bytes[1..i];
    const ct = cap.bytes[pn_start + pn_len .. pn_start + @as(usize, len_dec.value)];
    if (ct.len < 16) return error.TestFailed;

    const pt = try A.alloc(u8, ct.len - 16);
    defer A.free(pt);
    _ = try @import("quic_crypto").unprotectInitial(
        .aes_128_gcm,
        &c.hs_tx_keys.?.key,
        &c.hs_tx_keys.?.iv,
        &c.hs_tx_keys.?.hp,
        &header_first_masked,
        pn_masked[0..pn_len],
        header_prefix,
        &sample16,
        ct,
        pt,
    );

    const pr = try frame.decodeOne(pt);
    try std.testing.expect(std.mem.eql(u8, @tagName(pr.f), "ack"));
    const ack = pr.f.ack;
    try std.testing.expect(ack.ecn != null);
    try std.testing.expectEqual(@as(u64, 1), ack.ecn.?.ce);
    try std.testing.expectEqual(@as(u64, 0), ack.ecn.?.ect0);
    try std.testing.expectEqual(@as(u64, 0), ack.ecn.?.ect1);
}
