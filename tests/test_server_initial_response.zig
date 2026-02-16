const std = @import("std");
const testlog = @import("testlog");
const endpoint = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const varint = @import("quic_varint");
const ks = @import("quic_tls");
const test_certs = @import("test_certs");

test "server responds to client Initial" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    // Create server endpoint directly - use port 4433 to ensure it's recognized as a server
    var cfg = @import("config.zig").QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
    };
    var ep = try endpoint.Endpoint.init(alloc, "127.0.0.1:4433", &cfg);
    defer ep.deinit();
    ep.test_capture_enabled = true;

    // Clear capture ring before starting
    ep.captureClear();

    // Build a minimal Initial packet
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    // Derive Initial keys
    const initial = ks.deriveInitialSecret(false, &dcid);
    const pair = ks.deriveClientServerInitial(initial);
    const client_keys = ks.deriveKeyIvHp(pair.client);

    // Build standard TLS 1.3 ClientHello
    const ch_bytes = try buildStandardClientHello(alloc);
    defer alloc.free(ch_bytes);

    // Create CRYPTO frame
    var crypto_payload = std.ArrayList(u8){};
    defer crypto_payload.deinit(alloc);
    const w = crypto_payload.writer(alloc);
    _ = try (frame.Frame{ .crypto = .{ .offset = 0, .data = ch_bytes } }).write(w);

    // Encode Initial packet
    const initial_pkt = try packet.encodeInitialProtected(alloc, packet.QUIC_V1, &dcid, &scid, &[_]u8{}, // no token
        1, // packet number (starting at 1 to match implementation)
        2, // packet number length
        crypto_payload.items, .{ .key = client_keys.key, .iv = client_keys.iv, .hp = client_keys.hp });
    defer alloc.free(initial_pkt);

    // Create a fake client address
    const client_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 12345);
    var storage: std.posix.sockaddr.storage = undefined;
    @memset(@as([*]u8, @ptrCast(&storage))[0..@sizeOf(@TypeOf(storage))], 0);
    @memcpy(@as([*]u8, @ptrCast(&storage))[0..client_addr.getOsSockLen()], @as([*]const u8, @ptrCast(&client_addr.any)));
    const peer = conn_mod.SockAddr{
        .storage = storage,
        .len = client_addr.getOsSockLen(),
    };

    // Inject Initial packet into server endpoint
    ep.testInject(peer, initial_pkt);

    // Check if server queued a response
    try std.testing.expect(ep.captureLen() > 0);

    const cap_opt = ep.capturePop();
    try std.testing.expect(cap_opt != null);
    const cap = cap_opt.?;
    defer alloc.free(cap.bytes);

    // Verify response is an Initial or Handshake packet
    const response = cap.bytes;
    const first_byte = response[0];
    const is_long = (first_byte & 0x80) != 0;
    try std.testing.expect(is_long);
    const packet_type = (first_byte >> 4) & 0x03;
    try std.testing.expect(packet_type == 0 or packet_type == 2); // Initial or Handshake
    testlog.print("Server responded with packet type: {}\n", .{packet_type});
}

/// Build a standard TLS 1.3 ClientHello
fn buildStandardClientHello(alloc: std.mem.Allocator) ![]u8 {
    // Generate X25519 keypair
    var sk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    const pk = try std.crypto.dh.X25519.recoverPublicKey(sk);

    var body = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer body.deinit(alloc);

    // ClientHello structure (RFC 8446):
    // - legacy_version (2 bytes): 0x0303
    try body.appendSlice(alloc, &.{ 0x03, 0x03 });

    // - random (32 bytes)
    var rnd: [32]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    try body.appendSlice(alloc, &rnd);

    // - session_id (1 byte length + data): empty
    try body.append(alloc, 0);

    // - cipher_suites (2 bytes length + data): TLS_AES_128_GCM_SHA256 (0x1301)
    try body.appendSlice(alloc, &.{ 0x00, 0x02, 0x13, 0x01 });

    // - legacy_compression_methods (1 byte length + data): none
    try body.appendSlice(alloc, &.{ 0x01, 0x00 });

    // Build extensions
    var ext_buf = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer ext_buf.deinit(alloc);

    // supported_versions extension (43): TLS 1.3 (0x0304)
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });

    // supported_groups extension (10): x25519 (0x001d)
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });

    // signature_algorithms extension (13): Multiple algorithms for compatibility
    // Include RSA-PSS with SHA256 (0x0804), ECDSA with P256-SHA256 (0x0403), ED25519 (0x0807)
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

    // key_share extension (51): x25519 with generated public key
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x33 }); // extension type
    const key_share_len: u16 = 2 + 2 + 32; // group(2) + key_len(2) + key(32)
    const total_len: u16 = key_share_len + 2; // + vector length field
    try ext_buf.appendSlice(alloc, &.{ @intCast(total_len >> 8), @intCast(total_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ @intCast(key_share_len >> 8), @intCast(key_share_len & 0xff) });
    try ext_buf.appendSlice(alloc, &.{ 0x00, 0x1d }); // group x25519
    try ext_buf.appendSlice(alloc, &.{ 0x00, 32 }); // key length
    try ext_buf.appendSlice(alloc, &pk);

    // Write extensions length and data
    const exts_len: u16 = @intCast(ext_buf.items.len);
    try body.appendSlice(alloc, &.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
    try body.appendSlice(alloc, ext_buf.items);

    // Wrap in handshake message
    const body_len: u32 = @intCast(body.items.len);
    const result = try alloc.alloc(u8, 4 + body.items.len);
    result[0] = 0x01; // ClientHello type
    result[1] = @intCast((body_len >> 16) & 0xff);
    result[2] = @intCast((body_len >> 8) & 0xff);
    result[3] = @intCast(body_len & 0xff);
    @memcpy(result[4..], body.items);

    return result;
}
