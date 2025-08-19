const std = @import("std");
const asn1 = @import("asn1.zig");

pub const SigAlg = enum { ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, rsa_pss_sha256 };

/// Minimal ECDSA public key extracted from SubjectPublicKeyInfo
pub const EcdsaSpki = struct {
    curve_p256: bool, // true for P-256, false for P-384
    /// SEC1 uncompressed point (0x04 || X || Y)
    sec1_uncompressed: []const u8,
    allocator: std.mem.Allocator,
    pub fn deinit(self: *EcdsaSpki) void {
        self.allocator.free(self.sec1_uncompressed);
        self.* = undefined;
    }
};

/// Minimal RSA public key extracted from SubjectPublicKeyInfo
pub const RsaSpki = struct {
    modulus: []const u8, // big-endian
    exponent: u64,       // limited to 64-bit for simplicity
    allocator: std.mem.Allocator,
    pub fn deinit(self: *RsaSpki) void {
        self.allocator.free(self.modulus);
        self.* = undefined;
    }
};

/// Parse a DER-encoded SubjectPublicKeyInfo into ECDSA components.
pub fn parseEcdsaSpki(spki_der: []const u8, alloc: std.mem.Allocator) !EcdsaSpki {
    var d = asn1.Decoder.init(spki_der);
    const seq = try d.readSequence();
    var s1 = asn1.Decoder.init(seq);
    const algo_seq = try s1.readSequence();
    var a1 = asn1.Decoder.init(algo_seq);
    const algo_oid = try a1.readOID();
    // id-ecPublicKey: 1.2.840.10045.2.1 -> bytes 06 07 2A 86 48 CE 3D 02 01; match suffix 06 07 2A 86 48 CE 3D 02 01
    if (!(algo_oid.len >= 7 and algo_oid[0] == 0x2A and algo_oid[1] == 0x86)) return error.UnexpectedAlgorithm;
    // Parameters: namedCurve OID
    const curve_oid = try a1.readOID();
    var is_p256 = false;
    // secp256r1: 1.2.840.10045.3.1.7 -> 2A 86 48 CE 3D 03 01 07
    if (curve_oid.len >= 8 and std.mem.eql(u8, curve_oid[curve_oid.len - 8 ..], &[_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 })) {
        is_p256 = true;
    } else {
        // secp384r1: 1.3.132.0.34 -> 2B 81 04 00 22
        if (!(curve_oid.len >= 5 and std.mem.eql(u8, curve_oid[curve_oid.len - 5 ..], &[_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x22 })))
            return error.UnsupportedCurve;
    }
    // subjectPublicKey BIT STRING
    const bitstr = try s1.readBitString();
    if (bitstr.len == 0 or bitstr[0] != 0x04) return error.InvalidEcPoint; // require uncompressed
    const out = try alloc.dupe(u8, bitstr);
    return .{ .curve_p256 = is_p256, .sec1_uncompressed = out, .allocator = alloc };
}

/// Parse a DER-encoded SubjectPublicKeyInfo into RSA components.
pub fn parseRsaSpki(spki_der: []const u8, alloc: std.mem.Allocator) !RsaSpki {
    var d = asn1.Decoder.init(spki_der);
    const seq = try d.readSequence();
    var s1 = asn1.Decoder.init(seq);
    const algo_seq = try s1.readSequence();
    var a1 = asn1.Decoder.init(algo_seq);
    const algo_oid = try a1.readOID();
    // rsaEncryption: 1.2.840.113549.1.1.1 -> suffix: 2A 86 48 86 F7 0D 01 01 01
    if (!(algo_oid.len >= 9 and std.mem.eql(u8, algo_oid[algo_oid.len - 9 ..], &[_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 })))
        return error.UnexpectedAlgorithm;
    // Optional NULL params may follow; tolerate
    _ = a1.readTLV() catch null;
    const bitstr = try s1.readBitString();
    // Inside is RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    var d2 = asn1.Decoder.init(bitstr);
    const rsaseq = try d2.readSequence();
    var r = asn1.Decoder.init(rsaseq);
    // Read modulus as raw bytes via TLV to preserve leading 0x00
    const mod_tlv = try r.readTLV();
    if (asn1.tagClass(mod_tlv.tag) != .universal or asn1.tagNumber(mod_tlv.tag) != 2) return error.UnexpectedTag;
    const modulus = try alloc.dupe(u8, mod_tlv.val);
    const e_val = try r.readInteger();
    return .{ .modulus = modulus, .exponent = e_val, .allocator = alloc };
}

/// Verify TLS 1.3 CertificateVerify. Not yet implemented (key wiring to std.crypto pending).
pub fn verifyCertificateVerify(alg: SigAlg, pubkey_der: []const u8, sig: []const u8, context: []const u8, transcript_hash: []const u8) !bool {
    _ = alg;
    _ = pubkey_der;
    _ = sig;
    _ = context;
    _ = transcript_hash;
    return error.Unimplemented;
}
