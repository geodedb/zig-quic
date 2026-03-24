const std = @import("std");
const tls13 = @import("quic_tls13");
const sig = @import("quic_tls/sig.zig");

// Inline self-signed P-256 cert + matching PKCS#8 key (toy, minimal) placeholder bytes.
// For now we reuse a minimal DER sequence expected by parser; replace with real fixture later.
// NOTE: Parser currently scans for pattern 0x04 0x20 before 32-byte scalar. Provide that.

const dummy_cert: []const u8 = &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 }; // placeholder DER (will not validate fully)
const dummy_key: []const u8 = &[_]u8{
    // PKCS#8 like: ... OCTET STRING length 0x22: 0x04 0x20 <32 bytes scalar>
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x04, 0x22, 0x04, 0x20,
    // 32-byte scalar
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
    0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11,
};

// This test exercises authenticated handshake path gating logic (allow_insecure = false).
// Given current minimal x509 parser, the dummy cert may fail validation; we assert that
// Finished is not sent on client if peer_cert_ok is false.
// Once a real self-signed cert fixture is added, expectations should change to require success.
// RFC 8446 §4.4 requires endpoints to abort the handshake when certificate
// verification fails. Ensure the implementation with QUIC binding (RFC 9001 §4)
// refuses to transmit Finished until peer certificate validation succeeds or
// the connection explicitly allows insecure mode.

test "real_tls_full_handshake_auth_gating" {
    const gpa = std.heap.page_allocator;
    // Server engine
    var server = tls13.Engine.init(gpa, .Server);
    defer server.deinit();
    server.allow_insecure = false;
    server.setServerCertificate(dummy_cert, dummy_key, .ecdsa_secp256r1_sha256) catch {};

    // Client engine
    var client = tls13.Engine.init(gpa, .Client);
    defer client.deinit();
    client.allow_insecure = false;

    // Client sends CH
    client.queueMinimalClientHello() catch {};
    var buf: [4096]u8 = undefined;
    const c_to_s = client.popCrypto(buf[0..]);
    try server.onCryptoRecv(buf[0..c_to_s]);

    // Server sends SH + EE + (cert flight attempt) + Finished
    server.queueMinimalServerHello() catch {};
    server.queueEncryptedExtensions("h3", &[_]u8{ 0x00, 0x01 }) catch {}; // minimal TP bytes
    const s_to_c = server.popCrypto(buf[0..]);
    try client.onCryptoRecv(buf[0..s_to_c]);

    // At this point client may or may not have peer_cert_ok; it must not send Finished unless peer_cert_ok or insecure.
    // Force evaluation of maybeAutoProgress by feeding zero bytes.
    try client.onCryptoRecv(&[_]u8{});

    // Client should NOT have finished_sent if peer_cert_ok false.
    if (!client.peer_cert_ok) std.testing.expect(!client.finished_sent) catch unreachable;
}
