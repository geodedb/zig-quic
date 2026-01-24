const std = @import("std");
const tls13 = @import("quic_tls13");

/// Test that TLS engine can parse standard TLS 1.3 ClientHello without explicit real_mode flag
test "TLS engine auto-detects and parses standard ClientHello" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Create server engine
    var engine = tls13.Engine.init(alloc, .Server);
    defer engine.deinit();

    // Build a standard TLS 1.3 ClientHello with X25519 key share
    const client_hello = try buildStandardClientHello(alloc);
    defer alloc.free(client_hello);

    // Ingest the ClientHello
    try engine.ingestCrypto(client_hello);

    // Verify that public key was extracted
    try std.testing.expect(engine.peer_pub != null);

    // 3. ClientHello was marked as seen
    try std.testing.expect(engine.ch_sent);
}

/// Test that minimal "CH1" format still works (backward compatibility)
test "TLS engine still accepts minimal CH1 format" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var engine = tls13.Engine.init(alloc, .Server);
    defer engine.deinit();

    // Generate a keypair for minimal format
    var client_priv: [32]u8 = undefined;
    std.crypto.random.bytes(&client_priv);
    const client_pub = try std.crypto.dh.X25519.recoverPublicKey(client_priv);

    // Build minimal "CH1" format
    const ch_body = [_]u8{ 'C', 'H', '1' } ++ client_pub;
    const ch_msg = try tls13.encodeHandshake(alloc, .client_hello, ch_body[0..]);
    defer alloc.free(ch_msg);

    // Ingest the minimal ClientHello
    try engine.ingestCrypto(ch_msg);

    // Verify it was accepted
    try std.testing.expect(engine.peer_pub != null);
    try std.testing.expect(engine.ch_sent);
}

/// Build a minimal but valid standard TLS 1.3 ClientHello
fn buildStandardClientHello(alloc: std.mem.Allocator) ![]u8 {
    // Generate X25519 keypair
    var sk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    const pk = try std.crypto.dh.X25519.recoverPublicKey(sk);

    var body = std.ArrayList(u8).init(alloc);
    defer body.deinit();

    // ClientHello structure (RFC 8446):
    // - legacy_version (2 bytes): 0x0303
    try body.appendSlice(&.{ 0x03, 0x03 });

    // - random (32 bytes)
    var rnd: [32]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    try body.appendSlice(&rnd);

    // - session_id (1 byte length + data): empty
    try body.append(0);

    // - cipher_suites (2 bytes length + data): TLS_AES_128_GCM_SHA256 (0x1301)
    try body.appendSlice(&.{ 0x00, 0x02, 0x13, 0x01 });

    // - legacy_compression_methods (1 byte length + data): none
    try body.appendSlice(&.{ 0x01, 0x00 });

    // Build extensions
    var ext_buf = std.ArrayList(u8).init(alloc);
    defer ext_buf.deinit();

    // supported_versions extension (43): TLS 1.3 (0x0304)
    try ext_buf.appendSlice(&.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });

    // supported_groups extension (10): x25519 (0x001d)
    try ext_buf.appendSlice(&.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });

    // signature_algorithms extension (13): ecdsa_secp256r1_sha256 (0x0403)
    try ext_buf.appendSlice(&.{ 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 });

    // key_share extension (51): x25519 with generated public key
    try ext_buf.appendSlice(&.{ 0x00, 0x33 }); // extension type
    const key_share_len: u16 = 2 + 2 + 32; // group(2) + key_len(2) + key(32)
    const total_len: u16 = key_share_len + 2; // + vector length field
    try ext_buf.appendSlice(&.{ @intCast(total_len >> 8), @intCast(total_len & 0xff) });
    try ext_buf.appendSlice(&.{ @intCast(key_share_len >> 8), @intCast(key_share_len & 0xff) });
    try ext_buf.appendSlice(&.{ 0x00, 0x1d }); // group x25519
    try ext_buf.appendSlice(&.{ 0x00, 32 }); // key length
    try ext_buf.appendSlice(&pk);

    // Write extensions length and data
    const exts_len: u16 = @intCast(ext_buf.items.len);
    try body.appendSlice(&.{ @intCast(exts_len >> 8), @intCast(exts_len & 0xff) });
    try body.appendSlice(ext_buf.items);

    // Wrap in handshake message
    return try tls13.encodeHandshake(alloc, .client_hello, body.items);
}
