const std = @import("std");
const asn1 = @import("asn1.zig");

pub const SigAlg = enum { ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, rsa_pss_sha256 };

pub fn verifyCertificateVerify(alg: SigAlg, pubkey_der: []const u8, sig: []const u8, context: []const u8, transcript_hash: []const u8) !bool {
    // Per TLS 1.3, signed data = 64 bytes of 0x20 || "TLS 1.3, ..." || 0x00 || transcript_hash
    var signed = std.ArrayList(u8).init(std.heap.page_allocator);
    defer signed.deinit();
    try signed.appendNTimes(0x20, 64);
    const label = if (context.len != 0) context else "TLS 1.3, server CertificateVerify";
    try signed.appendSlice(label);
    try signed.append(0x00);
    try signed.appendSlice(transcript_hash);

    switch (alg) {
        .ecdsa_secp256r1_sha256 => {
            var pk = try parseEcdsaSpki(.p256, pubkey_der);
            defer pk.deinit();
            return std.crypto.sign.ecdsa.EcdsaP256Sha256.verify(sig, pk.key, signed.items);
        },
        .ecdsa_secp384r1_sha384 => {
            var pk = try parseEcdsaSpki(.p384, pubkey_der);
            defer pk.deinit();
            return std.crypto.sign.ecdsa.EcdsaP384Sha384.verify(sig, pk.key, signed.items);
        },
        .rsa_pss_sha256 => {
            var rsa = try parseRsaSpki(pubkey_der);
            defer rsa.deinit();
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            var digest: [32]u8 = undefined;
            hasher.hash(signed.items, &digest, .{});
            const P = std.crypto.sign.rsa.RsaPssSha256; // uses MGF1-SHA256
            return P.verify(sig, digest[0..], rsa.key, .{});
        },
    }
}

const ParsedKey = struct {
    key: anyopaque,
    allocator: std.mem.Allocator,
    fn deinit(self: *ParsedKey) void {
        _ = self;
    }
};

fn parseEcdsaSpki(comptime curve: anytype, spki: []const u8) !ParsedKey {
    // Very small SPKI parse: SEQ { algo SEQ {id-ecPublicKey, namedCurve OID}, BIT STRING }
    _ = curve;
    _ = spki; // TODO: implement minimal parse; placeholder returns error for now
    return error.Unimplemented;
}

fn parseRsaSpki(spki: []const u8) !ParsedKey {
    _ = spki;
    return error.Unimplemented;
}
