const std = @import("std");
const testlog = @import("testlog");
const tls13 = @import("quic_tls13");
const x509 = @import("x509");
const sig = @import("sig");

fn pemToDer(alloc: std.mem.Allocator, pem: []const u8) ![]u8 {
    var lines = std.mem.tokenizeAny(u8, pem, "\n");
    var body = std.ArrayList(u8).init(alloc);
    defer body.deinit();
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "---")) continue;
        try body.appendSlice(alloc, line);
    }
    return std.base64.standard.Decoder.init().allocDecode(alloc, body.items);
}

// Minimal certificate verification negative tests.
// NOTE: Uses existing parsed structures; does not perform full chain building.

test "reject self-signed cert without allow_insecure" {
    // Load embedded server cert (self-signed)
    const cert_pem = @embedFile("../../server.crt");
    const der = pemToDer(std.testing.allocator, cert_pem) catch unreachable;
    defer std.testing.allocator.free(der);
    const cert = x509.parseCert(std.testing.allocator, der) catch |e| {
        testlog.print("parse failed: {}\n", .{e});
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

test "infer signature algorithm from ECDSA P-256 certificate" {
    const cert_pem = @embedFile("../../server.crt");
    const der = pemToDer(std.testing.allocator, cert_pem) catch unreachable;
    defer std.testing.allocator.free(der);
    const alg = x509.inferSignatureAlgorithm(der) catch unreachable;
    try std.testing.expectEqual(sig.SigAlg.ecdsa_secp256r1_sha256, alg);
}

test "infer signature algorithm from RSA-PSS certificate" {
    const cert_pem = @embedFile("../../forks/boringssl/crypto/x509/test/pss_sha256_salt31.pem");
    const der = pemToDer(std.testing.allocator, cert_pem) catch unreachable;
    defer std.testing.allocator.free(der);
    const alg = x509.inferSignatureAlgorithm(der) catch unreachable;
    try std.testing.expectEqual(sig.SigAlg.rsa_pss_sha256, alg);
}
