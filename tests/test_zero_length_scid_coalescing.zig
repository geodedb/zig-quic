const std = @import("std");
const endpoint = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const varint = @import("quic_varint");
const ks = @import("quic_tls");
const test_certs = @import("test_certs");

// Verify that when a client Initial arrives with a zero-length Source Connection ID,
// the server responds with both Initial and Handshake packets that use a zero-length
// Destination Connection ID, preserving RFC 9000 §12.2 invariants for coalesced
// datagrams.
test "server coalesces zero-length DCID handshakes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var cfg = @import("config.zig").QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
    };
    var ep = try endpoint.Endpoint.init(alloc, "127.0.0.1:4434", &cfg);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    // Build a client Initial with zero-length SCID.
    const client_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = &[_]u8{};

    const initial_secret = ks.deriveInitialSecret(false, &client_dcid);
    const secret_pair = ks.deriveClientServerInitial(initial_secret);
    const client_keys = ks.deriveKeyIvHp(secret_pair.client);

    const ch_bytes = try buildStandardClientHello(alloc);
    defer alloc.free(ch_bytes);

    var crypto_payload = std.ArrayList(u8){};
    defer crypto_payload.deinit(alloc);
    const w = crypto_payload.writer(alloc);
    _ = try (frame.Frame{ .crypto = .{ .offset = 0, .data = ch_bytes } }).write(w);

    const initial_pkt = try packet.encodeInitialProtected(
        alloc,
        packet.QUIC_V1,
        &client_dcid,
        client_scid,
        &[_]u8{},
        1,
        2,
        crypto_payload.items,
        .{ .key = client_keys.key, .iv = client_keys.iv, .hp = client_keys.hp },
    );
    defer alloc.free(initial_pkt);

    const client_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 40000);
    var storage: std.posix.sockaddr.storage = undefined;
    @memset(@as([*]u8, @ptrCast(&storage))[0..@sizeOf(@TypeOf(storage))], 0);
    @memcpy(
        @as([*]u8, @ptrCast(&storage))[0..client_addr.getOsSockLen()],
        @as([*]const u8, @ptrCast(&client_addr.any)),
    );
    const peer = conn_mod.SockAddr{ .storage = storage, .len = client_addr.getOsSockLen() };

    ep.testInject(peer, initial_pkt);

    // Expect at least one captured datagram containing Initial + Handshake.
    try std.testing.expect(ep.captureLen() > 0);
    const cap_opt = ep.capturePop();
    try std.testing.expect(cap_opt != null);
    const captured = cap_opt.?;
    defer alloc.free(captured.bytes);

    var offset: usize = 0;
    var handshake_seen = false;
    const datagram = captured.bytes;
    while (offset < datagram.len) {
        const first = datagram[offset];
        if ((first & 0x80) == 0) break; // stop at short-header packets
        const packet_type = (first >> 4) & 0x03;
        const pn_len = ((first & 0x03) + 1);
        offset += 1;

        if (offset + 4 > datagram.len) break;
        offset += 4; // version

        if (offset >= datagram.len) break;
        const dcid_len = datagram[offset];
        offset += 1;
        if (offset + dcid_len > datagram.len) break;
        offset += dcid_len;

        if (offset >= datagram.len) break;
        const scid_len = datagram[offset];
        offset += 1;
        if (offset + scid_len > datagram.len) break;
        offset += scid_len;

        if (packet_type == 0) {
            const token_dec = varint.decode(datagram[offset..]) catch break;
            offset += token_dec.n;
            const token_len = @as(usize, @intCast(token_dec.value));
            if (offset + token_len > datagram.len) break;
            offset += token_len;
        }

        const len_dec = varint.decode(datagram[offset..]) catch break;
        offset += len_dec.n;
        const seg_len = @as(usize, @intCast(len_dec.value));
        if (seg_len < pn_len) break;
        if (offset + seg_len > datagram.len) break;

        if (packet_type == 2) {
            // Handshake packet must repeat zero-length DCID when client SCID was zero-length.
            try std.testing.expectEqual(@as(usize, 0), dcid_len);
            handshake_seen = true;
        }

        offset += seg_len;
    }

    try std.testing.expect(handshake_seen);
}

fn buildStandardClientHello(alloc: std.mem.Allocator) ![]u8 {
    var sk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    const pk = try std.crypto.dh.X25519.recoverPublicKey(sk);

    var body = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer body.deinit(alloc);

    try body.appendSlice(alloc, &.{ 0x03, 0x03 });

    var rnd: [32]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    try body.appendSlice(alloc, &rnd);

    try body.append(alloc, 0);
    try body.appendSlice(alloc, &.{ 0x00, 0x02, 0x13, 0x01 });
    try body.appendSlice(alloc, &.{ 0x01, 0x00 });

    var ext_buf = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer ext_buf.deinit(alloc);

    // supported_versions extension
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });

    // supported_groups extension
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });

    // signature_algorithms extension (expanded with more algorithms)
    try ext_buf.appendSlice(alloc, &.{
        0x00, 0x0d, // Extension type: signature_algorithms
        0x00, 0x08, // Extension length
        0x00, 0x06, // List length
        0x08, 0x04, // RSA-PSS-RSAE-SHA256
        0x04, 0x03, // ECDSA-secp256r1-sha256
        0x08, 0x07, // ED25519
    });

    // ALPN extension (16): Required for QUIC - advertise "h3"
    try ext_buf.appendSlice(alloc, &.{
        0x00, 0x10, // Extension type: ALPN
        0x00, 0x05, // Extension length
        0x00, 0x03, // ALPN list length
        0x02, // ALPN entry length
        'h', '3', // "h3" protocol
    });

    // QUIC transport parameters extension (57/0x39): Required for QUIC
    try ext_buf.appendSlice(alloc, &.{
        0x00, 0x39, // Extension type: quic_transport_params
        0x00, 0x0c, // Extension length (12 bytes)
        // Initial max data (param 0x04) = 1MB
        0x04, 0x04,
        0x80, 0x10,
        0x00, 0x00,
        // Initial max stream data bidi local (param 0x05) = 256KB
        0x05, 0x04,
        0x80, 0x04,
        0x00, 0x00,
    });

    // key_share extension
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x33 });
    const key_share_len: u16 = 2 + 2 + 32;
    const total_len: u16 = key_share_len + 2;
    try ext_buf.appendSlice(alloc, &.{ @intCast(total_len >> 8), @intCast(total_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ @intCast(key_share_len >> 8), @intCast(key_share_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x1d });
    try ext_buf.appendSlice(alloc, &.{ 0x00, 32 });
    try ext_buf.appendSlice(alloc, &pk);

    const exts_len: u16 = @intCast(ext_buf.items.len);
    try body.appendSlice(alloc, &.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
    try body.appendSlice(alloc, ext_buf.items);

    const body_len: u32 = @intCast(body.items.len);
    const result = try alloc.alloc(u8, 4 + body.items.len);
    result[0] = 0x01;
    result[1] = @intCast((body_len >> 16) & 0xff);
    result[2] = @intCast((body_len >> 8) & 0xff);
    result[3] = @intCast(body_len & 0xff);
    @memcpy(result[4..], body.items);

    return result;
}
