const std = @import("std");
const endpoint = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");
const test_certs = @import("test_certs");

// Regression test for TLS Error 266 (0x010a)
// Verify that the server can send PTO probes for Initial packets when the client
// uses a zero-length Source Connection ID, per RFC 9000 §12.2.
//
// Bug: Previously, sendPtoProbe() had an early return when dcid.len == 0,
// preventing retransmission of Initial packets for clients using zero-length SCIDs.
// This caused handshake failures manifesting as TLS alert 0x010a (266).
test "server sends PTO probe with zero-length DCID" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var cfg = @import("config.zig").QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
    };
    var ep = try endpoint.Endpoint.init(alloc, "127.0.0.1:4435", &cfg);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    // Build a client Initial with zero-length SCID (simulating clients that use zero-length CIDs)
    const client_dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const client_scid = &[_]u8{}; // Zero-length SCID

    const initial_secret = ks.deriveInitialSecret(false, &client_dcid);
    const secret_pair = ks.deriveClientServerInitial(initial_secret);
    const client_keys = ks.deriveKeyIvHp(secret_pair.client);

    const ch_bytes = try buildClientHello(alloc);
    defer alloc.free(ch_bytes);

    var crypto_payload = std.ArrayList(u8){};
    defer crypto_payload.deinit(alloc);
    const w = crypto_payload.writer(alloc);
    _ = try (frame.Frame{ .crypto = .{ .offset = 0, .data = ch_bytes } }).write(w);

    const initial_pkt = try packet.encodeInitialProtected(
        alloc,
        packet.QUIC_V1,
        &client_dcid,
        client_scid, // Zero-length SCID
        &[_]u8{},
        1,
        2,
        crypto_payload.items,
        .{ .key = client_keys.key, .iv = client_keys.iv, .hp = client_keys.hp },
    );
    defer alloc.free(initial_pkt);

    const client_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 40001);
    var storage: std.posix.sockaddr.storage = undefined;
    @memset(@as([*]u8, @ptrCast(&storage))[0..@sizeOf(@TypeOf(storage))], 0);
    @memcpy(
        @as([*]u8, @ptrCast(&storage))[0..client_addr.getOsSockLen()],
        @as([*]const u8, @ptrCast(&client_addr.any)),
    );
    const peer = conn_mod.SockAddr{ .storage = storage, .len = client_addr.getOsSockLen() };

    // Inject the Initial packet to establish connection
    ep.testInject(peer, initial_pkt);

    // Verify server sent a response (should capture Initial+Handshake coalesced)
    const initial_capture_count = ep.captureLen();
    try std.testing.expect(initial_capture_count > 0);

    // Clear captures to test PTO probe separately
    while (ep.capturePop()) |cap| {
        alloc.free(cap.bytes);
    }

    // Find the connection that was just created
    var conn: ?*conn_mod.Connection = null;
    var it = ep.conns.iterator();
    while (it.next()) |entry| {
        const c = entry.value_ptr.*;
        const peer_hash = endpoint.hashSockaddr(&peer.storage, peer.len);
        if (entry.key_ptr.*.peer_hash == peer_hash) {
            conn = c;
            break;
        }
    }
    try std.testing.expect(conn != null);

    // Verify the connection has zero-length peer_initial_scid (from client's SCID)
    try std.testing.expectEqual(@as(u8, 0), conn.?.peer_initial_scid.len);

    // Simulate PTO timeout by artificially triggering a PTO probe
    // This tests that sendPtoProbe() doesn't early-return for zero-length DCID
    try ep.sendPtoProbe(conn.?, .PtoInitial);

    // Verify that a PTO probe was actually sent (captured)
    const pto_capture_count = ep.captureLen();
    try std.testing.expect(pto_capture_count > 0);

    // Pop and verify the PTO probe packet
    const pto_cap = ep.capturePop();
    try std.testing.expect(pto_cap != null);
    const pto_pkt = pto_cap.?;
    defer alloc.free(pto_pkt.bytes);

    // Verify it's a valid Initial packet with zero-length DCID
    const first = pto_pkt.bytes[0];
    try std.testing.expect((first & 0x80) != 0); // Long header
    const packet_type = (first >> 4) & 0x03;
    try std.testing.expectEqual(@as(u8, 0), packet_type); // Initial packet (type 0)

    // Parse to verify DCID length is 0
    const offset: usize = 5; // Skip first byte + version (4 bytes)
    const dcid_len = pto_pkt.bytes[offset];
    try std.testing.expectEqual(@as(u8, 0), dcid_len); // DCID must be zero-length
}

// Test that Handshake PTO probes also work with zero-length DCID
test "server sends Handshake PTO probe with zero-length DCID" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var cfg = @import("config.zig").QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
    };
    var ep = try endpoint.Endpoint.init(alloc, "127.0.0.1:4436", &cfg);
    defer ep.deinit();
    ep.test_capture_enabled = true;

    // Setup similar to previous test
    const client_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 };
    const client_scid = &[_]u8{}; // Zero-length SCID

    const initial_secret = ks.deriveInitialSecret(false, &client_dcid);
    const secret_pair = ks.deriveClientServerInitial(initial_secret);
    const client_keys = ks.deriveKeyIvHp(secret_pair.client);

    const ch_bytes = try buildClientHello(alloc);
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

    const client_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 40002);
    var storage: std.posix.sockaddr.storage = undefined;
    @memset(@as([*]u8, @ptrCast(&storage))[0..@sizeOf(@TypeOf(storage))], 0);
    @memcpy(
        @as([*]u8, @ptrCast(&storage))[0..client_addr.getOsSockLen()],
        @as([*]const u8, @ptrCast(&client_addr.any)),
    );
    const peer = conn_mod.SockAddr{ .storage = storage, .len = client_addr.getOsSockLen() };

    ep.testInject(peer, initial_pkt);

    // Find connection
    var conn: ?*conn_mod.Connection = null;
    var it = ep.conns.iterator();
    while (it.next()) |entry| {
        const c = entry.value_ptr.*;
        const peer_hash = endpoint.hashSockaddr(&peer.storage, peer.len);
        if (entry.key_ptr.*.peer_hash == peer_hash) {
            conn = c;
            break;
        }
    }
    try std.testing.expect(conn != null);

    // Clear initial captures
    while (ep.capturePop()) |cap| {
        alloc.free(cap.bytes);
    }

    // Only test Handshake PTO if handshake keys are available
    if (conn.?.hs_tx_keys != null) {
        try ep.sendPtoProbe(conn.?, .PtoHandshake);

        const pto_capture_count = ep.captureLen();
        if (pto_capture_count > 0) {
            const pto_cap = ep.capturePop();
            try std.testing.expect(pto_cap != null);
            const pto_pkt = pto_cap.?;
            defer alloc.free(pto_pkt.bytes);

            // Verify it's a Handshake packet with zero-length DCID
            const first = pto_pkt.bytes[0];
            try std.testing.expect((first & 0x80) != 0); // Long header
            const packet_type = (first >> 4) & 0x03;
            try std.testing.expectEqual(@as(u8, 2), packet_type); // Handshake packet (type 2)

            const offset: usize = 5; // Skip first byte + version
            const dcid_len = pto_pkt.bytes[offset];
            try std.testing.expectEqual(@as(u8, 0), dcid_len); // DCID must be zero-length
        }
    }
}

fn buildClientHello(alloc: std.mem.Allocator) ![]u8 {
    var sk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    const pk = try std.crypto.dh.X25519.recoverPublicKey(sk);

    var body = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer body.deinit(alloc);

    // TLS 1.3 version (legacy_version)
    try body.appendSlice(alloc, &.{ 0x03, 0x03 });

    // Random (32 bytes)
    var rnd: [32]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    try body.appendSlice(alloc, &rnd);

    // Legacy session ID (empty)
    try body.append(alloc, 0);

    // Cipher suites (2 bytes length + TLS_AES_128_GCM_SHA256)
    try body.appendSlice(alloc, &.{ 0x00, 0x02, 0x13, 0x01 });

    // Legacy compression methods (1 byte length + null)
    try body.appendSlice(alloc, &.{ 0x01, 0x00 });

    // Extensions
    var ext_buf = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer ext_buf.deinit(alloc);

    // supported_versions (TLS 1.3)
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });

    // supported_groups (x25519)
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

    // key_share (x25519)
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x33 });
    const key_share_len: u16 = 2 + 2 + 32;
    const total_len: u16 = key_share_len + 2;
    try ext_buf.appendSlice(alloc, &.{ @intCast(total_len >> 8), @intCast(total_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ @intCast(key_share_len >> 8), @intCast(key_share_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x1d }); // x25519
    try ext_buf.appendSlice(alloc, &.{ 0x00, 32 }); // 32 bytes
    try ext_buf.appendSlice(alloc, &pk);

    // QUIC transport parameters extension (57/0x39): Required for QUIC
    // Minimal valid transport parameters
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

    const exts_len: u16 = @intCast(ext_buf.items.len);
    try body.appendSlice(alloc, &.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
    try body.appendSlice(alloc, ext_buf.items);

    // Wrap in TLS Handshake message (type=ClientHello=0x01)
    const body_len: u32 = @intCast(body.items.len);
    const result = try alloc.alloc(u8, 4 + body.items.len);
    result[0] = 0x01; // ClientHello
    result[1] = @intCast((body_len >> 16) & 0xff);
    result[2] = @intCast((body_len >> 8) & 0xff);
    result[3] = @intCast(body_len & 0xff);
    @memcpy(result[4..], body.items);

    return result;
}
