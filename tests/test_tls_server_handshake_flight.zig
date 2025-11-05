const std = @import("std");
const tls = @import("quic_tls13");

// Ensure queueServerHandshakeFlight stages the server handshake flight exactly once
// and updates internal flags when Handshake secrets are available.
test "tls_engine_server_handshake_flight_single_enqueue" {
    const alloc = std.testing.allocator;

    var client = tls.Engine.init(alloc, .Client);
    defer client.deinit();
    client.allow_insecure = true;

    var server = tls.Engine.init(alloc, .Server);
    defer server.deinit();
    server.allow_insecure = true;

    // Client sends a full ClientHello so the server derives handshake secrets.
    try client.queueMinimalClientHello();
    var buf: [2048]u8 = undefined;
    const ch_len = client.popCrypto(buf[0..]);
    try std.testing.expect(ch_len > 0);
    server.onCryptoRecv(buf[0..ch_len]);

    // Server emits ServerHello, which should populate the Initial CRYPTO outbox
    // and derive handshake secrets needed for the Handshake flight.
    try server.queueRealServerHello();
    try std.testing.expect(server.handshake_server_secret != null);

    const before_len = server.outbox.items.len;
    try std.testing.expect(before_len > 0); // ServerHello is queued

    server.queueServerHandshakeFlight();
    try std.testing.expect(server.server_handshake_flight_enqueued);
    try std.testing.expect(server.finished_sent);
    try std.testing.expect(server.ee_sent);
    const after_len = server.outbox.items.len;
    try std.testing.expect(after_len > before_len);

    // Subsequent calls must be idempotent and not append duplicate messages.
    server.queueServerHandshakeFlight();
    try std.testing.expectEqual(after_len, server.outbox.items.len);
}

// Regression test for TLS Error 266 (unexpected_message)
// This test verifies that server handshake messages are sent in the correct RFC 8446 order:
// 1. ServerHello (Initial)
// 2. EncryptedExtensions (Handshake)
// 3. Certificate (Handshake) - if certificate configured
// 4. CertificateVerify (Handshake) - if certificate configured
// 5. Finished (Handshake) - MUST be last
// 
// Previous bug: Certificate/CertificateVerify were skipped or Finished was sent before them,
// causing clients to send unexpected_message alert (0x010a / 266).
test "tls_handshake_message_ordering_with_certificate_regression_266" {
    const alloc = std.testing.allocator;

    // Dummy certificate and key for testing (same as test_real_tls_full_handshake_auth.zig)
    const dummy_cert: []const u8 = &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 };
    const dummy_key: []const u8 = &[_]u8{
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x04, 0x22, 0x04, 0x20,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11,
    };

    var client = tls.Engine.init(alloc, .Client);
    defer client.deinit();
    client.allow_insecure = true;

    var server = tls.Engine.init(alloc, .Server);
    defer server.deinit();
    server.allow_insecure = true;

    // Set server certificate - this is required for Certificate/CertificateVerify to be sent
    try server.setServerCertificate(dummy_cert, dummy_key, .ecdsa_secp256r1_sha256);
    try std.testing.expect(server.server_cert_der != null);
    try std.testing.expect(server.server_priv_key != null);

    // Client sends ClientHello
    try client.queueMinimalClientHello();
    var buf: [4096]u8 = undefined;
    const ch_len = client.popCrypto(buf[0..]);
    try std.testing.expect(ch_len > 0);
    server.onCryptoRecv(buf[0..ch_len]);

    // Server emits ServerHello and derives handshake secrets
    try server.queueRealServerHello();
    try std.testing.expect(server.handshake_server_secret != null);

    const sh_len = server.outbox.items.len;
    try std.testing.expect(sh_len > 0); // ServerHello is queued

    // Queue the rest of the handshake flight
    server.queueServerHandshakeFlight();
    try std.testing.expect(server.server_handshake_flight_enqueued);
    try std.testing.expect(server.ee_sent);
    try std.testing.expect(server.finished_sent);

    const total_len = server.outbox.items.len;
    try std.testing.expect(total_len > sh_len);

    // Parse handshake messages from outbox to verify ordering
    // Skip ServerHello (Initial space), then check Handshake messages
    var offset: usize = sh_len; // Start after ServerHello
    var message_types = std.ArrayList(u8){};
    defer message_types.deinit(alloc);

    // Parse TLS handshake messages from outbox
    // Each message has: type (1 byte) + length (3 bytes) + body
    while (offset < total_len) {
        if (offset + 4 > total_len) break;
        const msg_type = server.outbox.items[offset];
        const msg_len_bytes = server.outbox.items[offset + 1..offset + 4];
        const msg_len = (@as(u32, msg_len_bytes[0]) << 16) | (@as(u32, msg_len_bytes[1]) << 8) | @as(u32, msg_len_bytes[2]);
        const msg_total_len = 4 + msg_len;
        
        if (offset + msg_total_len > total_len) break;
        
        // Record message type (only handshake messages)
        const type_name = switch (msg_type) {
            0x08 => "EncryptedExtensions",
            0x0B => "Certificate",
            0x0F => "CertificateVerify",
            0x14 => "Finished",
            else => "Unknown",
        };
        
        // Only track handshake flight messages (skip ServerHello which is in Initial space)
        if (msg_type == 0x08 or msg_type == 0x0B or msg_type == 0x0F or msg_type == 0x14) {
            try message_types.append(alloc, msg_type);
            std.debug.print("Found handshake message: {s} (0x{X:0>2})\n", .{ type_name, msg_type });
        }
        
        offset += msg_total_len;
    }

    // Verify message ordering: EE, Certificate, CertificateVerify, Finished
    try std.testing.expect(message_types.items.len >= 2); // At least EE and Finished
    
    // First message must be EncryptedExtensions
    try std.testing.expectEqual(@as(u8, 0x08), message_types.items[0]);
    
    // If certificate is configured, Certificate and CertificateVerify must be present
    if (server.server_cert_der != null and server.server_priv_key != null) {
        try std.testing.expect(message_types.items.len >= 4); // EE, Cert, CertVerify, Finished
        
        // Find positions
        var ee_pos: ?usize = null;
        var cert_pos: ?usize = null;
        var certverify_pos: ?usize = null;
        var finished_pos: ?usize = null;
        
        for (message_types.items, 0..) |msg_type, i| {
            switch (msg_type) {
                0x08 => ee_pos = i,
                0x0B => cert_pos = i,
                0x0F => certverify_pos = i,
                0x14 => finished_pos = i,
                else => {},
            }
        }
        
        // Verify ordering
        try std.testing.expect(ee_pos != null);
        try std.testing.expect(cert_pos != null);
        try std.testing.expect(certverify_pos != null);
        try std.testing.expect(finished_pos != null);
        
        try std.testing.expect(ee_pos.? < cert_pos.?);
        try std.testing.expect(cert_pos.? < certverify_pos.?);
        try std.testing.expect(certverify_pos.? < finished_pos.?);
        
        std.debug.print("✓ Message ordering correct: EE({}) -> Cert({}) -> CertVerify({}) -> Finished({})\n", .{
            ee_pos.?, cert_pos.?, certverify_pos.?, finished_pos.?,
        });
    } else {
        // Without certificate, only EE and Finished should be present
        try std.testing.expect(message_types.items.len == 2);
        try std.testing.expectEqual(@as(u8, 0x08), message_types.items[0]);
        try std.testing.expectEqual(@as(u8, 0x14), message_types.items[1]);
    }
    
    // Finished must always be last
    try std.testing.expectEqual(@as(u8, 0x14), message_types.items[message_types.items.len - 1]);
    
    std.debug.print("✓ TLS handshake message ordering test passed (regression for Error 266)\n", .{});
}
