const std = @import("std");
const endpoint = @import("quic_endpoint");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const varint = @import("quic_varint");
const ks = @import("quic_tls");

// This test synthesizes a client Initial without token to a server endpoint with retry enabled.
// Expect server to send a Retry.
test "server_issues_retry_and_client_retries" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    // Create server endpoint - use port 4433 to ensure it's recognized as a server
    var ep = try endpoint.Endpoint.init(alloc, "127.0.0.1:4433", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    ep.cfg.enable_retry = true;
    ep.cfg.token_secret = "test-secret";
    ep.cfg.token_expiry_ms = 60000;
    ep.test_capture_enabled = true;

    // Ensure capture ring is empty before starting
    ep.captureClear();

    // Build a synthetic client Initial probing packet.
    var c = try ep.connectClient("127.0.0.1:1");
    // NOTE: Do not destroy c here; Endpoint.deinit() will deinit & destroy owned connections.

    const v2 = false;
    const initial = ks.deriveInitialSecret(v2, c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
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
        &[_]u8{}, // no token
        1,
        4, // use 4-byte PN to ensure enough ciphertext for HP sample
        frames.items,
        tx_keys,
    );
    defer alloc.free(pkt);

    // Inject into endpoint
    ep.testInject(c.peer, pkt);

    // Assert a Retry was captured and validate basic fields
    try std.testing.expect(ep.captureLen() > 0);
    const cap_opt = ep.capturePop();
    try std.testing.expect(cap_opt != null);
    const cap = cap_opt.?;
    defer alloc.free(cap.bytes);

    const b = cap.bytes;
    try std.testing.expect(b.len >= 5);
    try std.testing.expect((b[0] & 0x80) != 0); // long header
    const ty: u2 = @intCast((b[0] >> 4) & 0x03);
    try std.testing.expect(ty == 3); // Retry
    const ver: u32 = (@as(u32, b[1]) << 24) | (@as(u32, b[2]) << 16) | (@as(u32, b[3]) << 8) | @as(u32, b[4]);
    try std.testing.expect(ver == packet.QUIC_V1);

    var i: usize = 5;
    try std.testing.expect(i < b.len);
    const dcid_len = b[i];
    i += 1;
    try std.testing.expect(i + dcid_len <= b.len);
    const dcid = b[i .. i + dcid_len];
    i += dcid_len;
    try std.testing.expect(i < b.len);
    const scid_len = b[i];
    i += 1;
    try std.testing.expect(i + scid_len <= b.len);
    const scid = b[i .. i + scid_len];
    _ = scid; // we don't know server SCID; just ensure bounds
    i += scid_len;

    // DCID in Retry must equal client's SCID
    try std.testing.expectEqual(@as(usize, c.our_scid.len), dcid.len);
    try std.testing.expect(std.mem.eql(u8, dcid, c.our_scid.bytes[0..c.our_scid.len]));

    // Token must be non-empty; last 16 bytes are the integrity tag (non-zero)
    try std.testing.expect(b.len >= 16 and i <= b.len - 16);
    const token_bytes = b[i .. b.len - 16];
    try std.testing.expect(token_bytes.len > 0);
    const tag = b[b.len - 16 .. b.len];
    // Tag should not be all zeros now that integrity is implemented
    try std.testing.expect(!std.mem.allEqual(u8, tag, 0));

    // Verify integrity using ODCID = client's Initial DCID
    const odcid = c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len];
    try std.testing.expect(packet.verifyRetry(odcid, b));
}
