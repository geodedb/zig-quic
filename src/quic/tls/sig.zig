const std = @import("std");
const asn1 = @import("asn1.zig");

/// Supported TLS 1.3 signature algorithms used by this implementation.
pub const SigAlg = enum { ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, rsa_pss_sha256 };

/// Minimal ECDSA public key extracted from SubjectPublicKeyInfo
pub const EcdsaSpki = struct {
    curve_p256: bool, // true for P-256, false for P-384
    /// SEC1 uncompressed point (0x04 || X || Y)
    sec1_uncompressed: []const u8,
    allocator: std.mem.Allocator,
    /// Free allocated buffers and invalidate the struct.
    pub fn deinit(self: *EcdsaSpki) void {
        self.allocator.free(self.sec1_uncompressed);
        self.* = undefined;
    }
};

/// Minimal RSA public key extracted from SubjectPublicKeyInfo
pub const RsaSpki = struct {
    modulus: []const u8, // big-endian
    exponent: u64, // limited to 64-bit for simplicity
    allocator: std.mem.Allocator,
    /// Free allocated buffers and invalidate the struct.
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
    // id-ecPublicKey: 1.2.840.10045.2.1
    if (!(algo_oid.len >= 7 and algo_oid[0] == 0x2A and algo_oid[1] == 0x86)) return error.UnexpectedAlgorithm;
    // Parameters: namedCurve OID
    const curve_oid = try a1.readOID();
    var is_p256 = false;
    // secp256r1: 1.2.840.10045.3.1.7
    if (curve_oid.len >= 8 and std.mem.eql(u8, curve_oid[curve_oid.len - 8 ..], &[_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 })) {
        is_p256 = true;
    } else {
        // secp384r1: 1.3.132.0.34
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
    // rsaEncryption: 1.2.840.113549.1.1.1
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

fn tls13_build_context_and_hash(alg: SigAlg, context: []const u8, th: []const u8) ![]u8 {
    _ = alg; // context depends only on TLS; alg included for future use
    // Per RFC8446 4.4.3: signed_content = 0x20 * 64 || context || 0x00 || transcript_hash
    const hash_len: usize = th.len; // sha256 or sha384 length
    const ctx_len: usize = context.len;
    var out = try std.heap.page_allocator.alloc(u8, 64 + ctx_len + 1 + hash_len);
    @memset(out[0..64], 0x20);
    @memcpy(out[64 .. 64 + ctx_len], context);
    out[64 + ctx_len] = 0x00;
    @memcpy(out[64 + ctx_len + 1 ..][0..hash_len], th);
    return out;
}

fn der_decode_ecdsa_sig(sig_der: []const u8, r_out: []u8, s_out: []u8) !void {
    // ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
    var d = asn1.Decoder.init(sig_der);
    const seq = try d.readSequence();
    var s1 = asn1.Decoder.init(seq);
    const r_tlv = try s1.readTLV();
    const s_tlv = try s1.readTLV();
    if (asn1.tagClass(r_tlv.tag) != .universal or asn1.tagNumber(r_tlv.tag) != 2) return error.UnexpectedTag;
    if (asn1.tagClass(s_tlv.tag) != .universal or asn1.tagNumber(s_tlv.tag) != 2) return error.UnexpectedTag;
    // Copy right aligned into fixed size buffers
    if (r_tlv.val.len > r_out.len or s_tlv.val.len > s_out.len) return error.InvalidSignature;
    const r_pad = r_out.len - r_tlv.val.len;
    const s_pad = s_out.len - s_tlv.val.len;
    @memset(r_out[0..r_pad], 0);
    @memcpy(r_out[r_pad..][0..r_tlv.val.len], r_tlv.val);
    @memset(s_out[0..s_pad], 0);
    @memcpy(s_out[s_pad..][0..s_tlv.val.len], s_tlv.val);
}

// ---- RSA-PSS (SHA-256) verification helpers ----

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

fn mgf1_sha256(seed: []const u8, out: []u8) void {
    var counter: u32 = 0;
    var off: usize = 0;
    while (off < out.len) : (counter += 1) {
        var hasher = Sha256.init(.{});
        hasher.update(seed);
        var cbe: [4]u8 = .{ 0, 0, 0, 0 };
        cbe[0] = @intCast((counter >> 24) & 0xff);
        cbe[1] = @intCast((counter >> 16) & 0xff);
        cbe[2] = @intCast((counter >> 8) & 0xff);
        cbe[3] = @intCast(counter & 0xff);
        hasher.update(&cbe);
        var digest: [Sha256.digest_length]u8 = undefined;
        hasher.final(&digest);
        const chunk = @min(digest.len, out.len - off);
        @memcpy(out[off..][0..chunk], digest[0..chunk]);
        off += chunk;
    }
}

// ---- Minimal big unsigned integer (big-endian bytes) helpers ----

fn beTrim(b: []const u8) []const u8 {
    var i: usize = 0;
    while (i < b.len and b[i] == 0) : (i += 1) {}
    if (i == b.len) return b[b.len - 1 ..]; // keep single 0
    return b[i..];
}

fn beCmp(a_in: []const u8, b_in: []const u8) std.math.Order {
    const a = beTrim(a_in);
    const b = beTrim(b_in);
    if (a.len < b.len) return .lt;
    if (a.len > b.len) return .gt;
    for (a, 0..) |av, i| {
        const bv = b[i];
        if (av < bv) return .lt;
        if (av > bv) return .gt;
    }
    return .eq;
}

fn bitLenFromBe(bytes: []const u8) usize {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    if (i == bytes.len) return 0;
    const first = bytes[i];
    var leading: u3 = 0;
    var b = first;
    while ((b & 0x80) == 0) : (leading += 1) b <<= 1;
    return (bytes.len - i) * 8 - leading;
}

fn beSubInPlace(dst: *std.ArrayList(u8), b: []const u8) void {
    // assumes dst >= b
    var i: isize = @as(isize, @intCast(dst.items.len)) - 1;
    var j: isize = @as(isize, @intCast(b.len)) - 1;
    var borrow: u16 = 0;
    while (i >= 0) : (i -= 1) {
        const ui: usize = @as(usize, @intCast(i));
        const a_byte: u16 = dst.items[ui];
        const bj_index: usize = if (j >= 0) @as(usize, @intCast(j)) else 0;
        const b_byte: u16 = if (j >= 0) @as(u16, b[bj_index]) else 0;
        var val: i32 = @as(i32, @intCast(a_byte)) - @as(i32, @intCast(b_byte)) - @as(i32, @intCast(borrow));
        if (val < 0) {
            val += 256;
            borrow = 1;
        } else borrow = 0;
        dst.items[ui] = @intCast(val);
        j -= 1;
    }
    // normalize
    var k: usize = 0;
    while (k + 1 < dst.items.len and dst.items[k] == 0) : (k += 1) {}
    if (k > 0) {
        // shift left by k bytes
        std.mem.copyForwards(u8, dst.items[0 .. dst.items.len - k], dst.items[k..]);
        _ = dst.resize(dst.items.len - k) catch {};
    }
}

fn beMul(a: []const u8, b: []const u8, alloc: std.mem.Allocator) ![]u8 {
    const at = beTrim(a);
    const bt = beTrim(b);
    const n = at.len;
    const m = bt.len;
    if (n == 1 and at[0] == 0) return alloc.dupe(u8, &[_]u8{0});
    if (m == 1 and bt[0] == 0) return alloc.dupe(u8, &[_]u8{0});
    var out = try alloc.alloc(u8, n + m);
    @memset(out, 0);
    var i: isize = @as(isize, @intCast(n)) - 1;
    while (i >= 0) : (i -= 1) {
        var carry: u32 = 0;
        var j: isize = @as(isize, @intCast(m)) - 1;
        while (j >= 0) : (j -= 1) {
            const ai: u32 = at[@as(usize, @intCast(i))];
            const bj: u32 = bt[@as(usize, @intCast(j))];
            const idx: usize = @as(usize, @intCast(i + j + 1));
            const cur: u32 = out[idx];
            const prod: u32 = ai * bj + cur + carry;
            out[idx] = @intCast(prod & 0xff);
            carry = prod >> 8;
        }
        // propagate remaining carry to the left
        var k: isize = i;
        var c: u32 = carry;
        while (c > 0 and k >= 0) : (k -= 1) {
            const idx2: usize = @as(usize, @intCast(k));
            const sum: u32 = @as(u32, out[idx2]) + (c & 0xff);
            out[idx2] = @intCast(sum & 0xff);
            c = sum >> 8;
        }
    }
    // trim
    var z: usize = 0;
    while (z + 1 < out.len and out[z] == 0) : (z += 1) {}
    if (z > 0) {
        const trimmed = try alloc.alloc(u8, out.len - z);
        @memcpy(trimmed, out[z..]);
        alloc.free(out);
        return trimmed;
    }
    return out;
}

fn modFromBytes(n: []const u8, value: []const u8, alloc: std.mem.Allocator) ![]u8 {
    var rem = std.ArrayList(u8).init(alloc);
    defer rem.deinit();
    // start with 0
    try rem.append(0);
    for (value) |byte| {
        // rem = rem * 256 + byte
        try rem.append(byte);
        // while rem >= n: rem -= n
        while (true) {
            const ord = beCmp(rem.items, n);
            if (ord == .lt) break;
            beSubInPlace(&rem, n);
        }
    }
    // ensure canonical single zero if empty
    if (rem.items.len == 0) try rem.append(0);
    return alloc.dupe(u8, rem.items);
}

fn modMul(n: []const u8, a: []const u8, b: []const u8, alloc: std.mem.Allocator) ![]u8 {
    const prod = try beMul(a, b, alloc);
    defer alloc.free(prod);
    return modFromBytes(n, prod, alloc);
}

fn modExpSmallE(n: []const u8, base: []const u8, e: u64, alloc: std.mem.Allocator) ![]u8 {
    var result = try alloc.dupe(u8, &[_]u8{1});
    defer alloc.free(result);
    var base_mod = try modFromBytes(n, base, alloc);
    defer alloc.free(base_mod);

    var exp = e;
    while (exp > 0) : (exp >>= 1) {
        if ((exp & 1) == 1) {
            const tmp = try modMul(n, result, base_mod, alloc);
            alloc.free(result);
            result = tmp;
        }
        if (exp > 1) {
            const sq = try modMul(n, base_mod, base_mod, alloc);
            alloc.free(base_mod);
            base_mod = sq;
        }
    }
    return alloc.dupe(u8, result);
}

fn rsa_pss_verify_sha256(pubkey_spki_der: []const u8, msg_signed_content: []const u8, sig: []const u8, salt_len: usize) !bool {
    // Parse SPKI
    var spki = try parseRsaSpki(pubkey_spki_der, std.heap.page_allocator);
    defer spki.deinit();
    const k: usize = spki.modulus.len; // modulus length in bytes (may include leading 0x00)
    if (sig.len != k) return false;

    // m = s^e mod n using minimal big integer
    const m_be = try modExpSmallE(spki.modulus, sig, spki.exponent, std.heap.page_allocator);
    defer std.heap.page_allocator.free(m_be);

    // EM = I2OSP(m, k)
    var EM = try std.heap.page_allocator.alloc(u8, k);
    defer std.heap.page_allocator.free(EM);
    @memset(EM, 0);
    const m_trim = beTrim(m_be);
    if (m_trim.len > k) return false;
    @memcpy(EM[k - m_trim.len ..], m_trim);

    // EMSA-PSS verify
    const hLen = Sha256.digest_length;
    if (k < hLen + salt_len + 2) return false;
    if (EM[k - 1] != 0xBC) return false;

    const emBits = bitLenFromBe(spki.modulus) - 1; // per spec
    const maskedDB = EM[0 .. k - hLen - 1];
    const H = EM[k - hLen - 1 .. k - 1];

    // dbMask = MGF1(H, k - hLen - 1)
    const dbMask = try std.heap.page_allocator.alloc(u8, maskedDB.len);
    defer std.heap.page_allocator.free(dbMask);
    mgf1_sha256(H, dbMask);

    // DB = maskedDB XOR dbMask
    const DB = try std.heap.page_allocator.alloc(u8, maskedDB.len);
    defer std.heap.page_allocator.free(DB);
    for (DB, 0..) |*b, i| b.* = maskedDB[i] ^ dbMask[i];

    // Set leftmost 8*k - emBits bits of DB[0] to zero
    const left_bits: usize = 8 * k - emBits;
    if (left_bits > 8) return false; // should be <= 8
    if (left_bits > 0) {
        // left_bits in 1..8; mask keeps lower (8 - left_bits) bits
        const masks = [_]u8{ 0x00, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01 };
        const idx = left_bits - 1;
        const invert: u8 = masks[idx];
        // We need to zero left_bits MSBs: DB[0] &= invert
        DB[0] &= invert;
    }

    // Check PS || 0x01 || salt structure
    const ps_len = k - hLen - salt_len - 2;
    if (ps_len > DB.len) return false;
    // PS must be all zeros
    if (ps_len == 0) return false;
    for (DB[0..ps_len]) |b| if (b != 0x00) return false;
    if (DB[ps_len] != 0x01) return false;
    const salt = DB[ps_len + 1 .. ps_len + 1 + salt_len];

    // H' = Hash(0x00*8 || Hash(M) || salt) where Hash(M) = sha256(signed_content)
    var mhash: [Sha256.digest_length]u8 = undefined;
    {
        var hh = Sha256.init(.{});
        hh.update(msg_signed_content);
        hh.final(&mhash);
    }
    var mprime = try std.heap.page_allocator.alloc(u8, 8 + mhash.len + salt_len);
    defer std.heap.page_allocator.free(mprime);
    @memset(mprime[0..8], 0);
    @memcpy(mprime[8 .. 8 + mhash.len], &mhash);
    @memcpy(mprime[8 + mhash.len ..][0..salt_len], salt);

    var Hp: [Sha256.digest_length]u8 = undefined;
    var hh2 = Sha256.init(.{});
    hh2.update(mprime);
    hh2.final(&Hp);

    return std.mem.eql(u8, H, &Hp);
}

/// Verify a TLS 1.3 CertificateVerify signature given algorithm, SPKI (DER), signature,
/// the TLS context string, and transcript hash; returns true on success.
pub fn verifyCertificateVerify(alg: SigAlg, pubkey_spki_der: []const u8, sig: []const u8, context: []const u8, transcript_hash: []const u8) !bool {
    switch (alg) {
        .rsa_pss_sha256 => {
            // Build TLS 1.3 signed content: 64 spaces || context || 0x00 || transcript_hash
            const sc = try tls13_build_context_and_hash(alg, context, transcript_hash);
            defer std.heap.page_allocator.free(sc);
            return rsa_pss_verify_sha256(pubkey_spki_der, sc, sig, 32);
        },
        .ecdsa_secp256r1_sha256 => {
            // Parse SPKI and use std.crypto ECDSA (P-256/SHA-256)
            var spki = try parseEcdsaSpki(pubkey_spki_der, std.heap.page_allocator);
            defer spki.deinit();
            if (!spki.curve_p256) return false;
            const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, Sha256);
            const signature = Ecdsa.Signature.fromDer(sig) catch return false;
            const pubkey = Ecdsa.PublicKey.fromSec1(spki.sec1_uncompressed) catch return false;
            const sc = try tls13_build_context_and_hash(alg, context, transcript_hash);
            defer std.heap.page_allocator.free(sc);
            signature.verify(sc, pubkey) catch return false;
            return true;
        },
        .ecdsa_secp384r1_sha384 => {
            // Parse SPKI and use std.crypto ECDSA (P-384/SHA-384)
            var spki = try parseEcdsaSpki(pubkey_spki_der, std.heap.page_allocator);
            defer spki.deinit();
            if (spki.curve_p256) return false; // expect P-384
            const Ecdsa384 = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P384, Sha384);
            const signature = Ecdsa384.Signature.fromDer(sig) catch return false;
            const pubkey = Ecdsa384.PublicKey.fromSec1(spki.sec1_uncompressed) catch return false;
            const sc = try tls13_build_context_and_hash(alg, context, transcript_hash);
            defer std.heap.page_allocator.free(sc);
            signature.verify(sc, pubkey) catch return false;
            return true;
        },
    }
}
