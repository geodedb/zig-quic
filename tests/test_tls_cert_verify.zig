const std = @import("std");
const tls13 = @import("quic_tls13");
const x509 = @import("x509");
const sig = @import("sig");

// Minimal certificate verification negative tests.
// NOTE: Uses existing parsed structures; does not perform full chain building.

test "reject self-signed cert without allow_insecure" {
    // Load embedded server cert (self-signed)
    const cert_pem = @embedFile("../../server.crt");
    // Extract base64 body
    var lines = std.mem.tokenizeAny(u8, cert_pem, "\n");
    var b64_buf = std.ArrayList(u8).init(std.testing.allocator);
    defer b64_buf.deinit();
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "---")) continue;
        b64_buf.appendSlice(std.testing.allocator, line) catch unreachable;
    }
    var der = std.base64.standard.Decoder.init().allocDecode(std.testing.allocator, b64_buf.items) catch unreachable;
    defer std.testing.allocator.free(der);
    const cert = x509.parseCert(std.testing.allocator, der) catch |e| {
        std.debug.print("parse failed: {}\n", .{e});
        return std.testing.expect(false);
    };
    defer cert.deinit(std.testing.allocator);
    // Self-signed: without allow_insecure, validity + chain checks should fail validateChain
    const now = std.time.timestamp();
    const chain_ok = x509.validateChain(std.testing.allocator, &[_][]const u8{der}, now, "localhost", false) catch null;
    try std.testing.expect(chain_ok == null);
}

test "certificate verify signature mismatch fails" {
    // Build fake transcript hash
    var hash: [tls13.H.digest_length]u8 = .{0xAA} ** tls13.H.digest_length;
    // Create fake signature bytes
    var bad_sig: [32]u8 = .{0x55} ** 32;
    // Use ed25519 scheme code path (sig length arbitrary for test harness)
    const alg = sig.SigAlg.ed25519;
    // Expect verification failure
    const ok = sig.verifyCertificateVerify(alg, &[_]u8{}, bad_sig[0..], "TLS 1.3, server CertificateVerify", &hash) catch false;
    try std.testing.expect(!ok);
}
