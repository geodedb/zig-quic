const std = @import("std");
const x509 = @import("quic_x509");

// RFC 8446 §4.2.6 requires clients to validate the "server_name" extension
// against the certificate Subject Alternative Name per RFC 5280 §4.2.1.6.
// These tests ensure SAN mismatches fail validation unless insecure mode is
// explicitly enabled.

fn putByte(buf: *std.ArrayList(u8), b: u8) void {
    buf.appendAssumeCapacity(b);
}

fn putLen(buf: *std.ArrayList(u8), len: usize) void {
    if (len < 128) {
        buf.appendAssumeCapacity(@intCast(len));
    } else {
        // very small lengths expected; fall back to minimal long form
        var tmp: [8]u8 = undefined;
        var n: usize = 0;
        var val: usize = len;
        while (val > 0) : (val >>= 8) {
            tmp[tmp.len - 1 - n] = @intCast(val & 0xff);
            n += 1;
        }
        buf.appendAssumeCapacity(0x80 | @as(u8, @intCast(n)));
        buf.appendSliceAssumeCapacity(tmp[tmp.len - n ..]);
    }
}

fn emitTLV(buf: *std.ArrayList(u8), tag: u8, val: []const u8) void {
    putByte(buf, tag);
    putLen(buf, val.len);
    buf.appendSliceAssumeCapacity(val);
}

fn makeSeq(alloc: std.mem.Allocator, inner: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    try out.ensureTotalCapacity(alloc, inner.len + 4);
    emitTLV(&out, 0x30, inner);
    return out.toOwnedSlice(alloc);
}

fn makeCtx(tagnum: u8, alloc: std.mem.Allocator, inner: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    try out.ensureTotalCapacity(alloc, inner.len + 4);
    emitTLV(&out, 0xA0 | (tagnum & 0x1f), inner);
    return out.toOwnedSlice(alloc);
}

fn makeOctet(alloc: std.mem.Allocator, inner: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    try out.ensureTotalCapacity(alloc, inner.len + 4);
    emitTLV(&out, 0x04, inner);
    return out.toOwnedSlice(alloc);
}

fn makeOID(alloc: std.mem.Allocator, oid_bytes: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    try out.ensureTotalCapacity(alloc, oid_bytes.len + 4);
    emitTLV(&out, 0x06, oid_bytes);
    return out.toOwnedSlice(alloc);
}

fn makeGeneralizedTime(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    try out.ensureTotalCapacity(alloc, s.len + 4);
    emitTLV(&out, 0x18, s);
    return out.toOwnedSlice(alloc);
}

fn makeInteger1(alloc: std.mem.Allocator, v: u8) ![]u8 {
    var out = std.ArrayList(u8){};
    try out.ensureTotalCapacity(alloc, 4);
    emitTLV(&out, 0x02, &[_]u8{v});
    return out.toOwnedSlice(alloc);
}

// Create AlgorithmIdentifier SEQUENCE with SHA256-RSA OID
fn makeAlgorithmIdentifier(alloc: std.mem.Allocator) ![]u8 {
    // sha256WithRSAEncryption OID: 1.2.840.113549.1.1.11
    const oid_bytes = &[_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
    const oid = try makeOID(alloc, oid_bytes);
    defer alloc.free(oid);
    // NULL parameters
    const null_tlv = &[_]u8{ 0x05, 0x00 };
    var inner = std.ArrayList(u8){};
    defer inner.deinit(alloc);
    try inner.ensureTotalCapacity(alloc, oid.len + null_tlv.len);
    inner.appendSliceAssumeCapacity(oid);
    inner.appendSliceAssumeCapacity(null_tlv);
    return makeSeq(alloc, inner.items);
}

fn buildCertWithSan(alloc: std.mem.Allocator, dns_name: []const u8) ![]u8 {
    var b = std.ArrayList(u8){};
    defer b.deinit(alloc);
    try b.ensureTotalCapacity(alloc, 512);

    // --- tbsCertificate ---
    var tbs = std.ArrayList(u8){};
    defer tbs.deinit(alloc);
    try tbs.ensureTotalCapacity(alloc, 512);

    // serial/signature algorithm
    const serial = try makeInteger1(alloc, 1);
    defer alloc.free(serial);
    const sig_alg = try makeAlgorithmIdentifier(alloc);
    defer alloc.free(sig_alg);
    tbs.appendSliceAssumeCapacity(serial);
    tbs.appendSliceAssumeCapacity(sig_alg);

    // issuer = SEQUENCE with one byte (to differentiate from subject)
    const issuer = try makeSeq(alloc, &[_]u8{0x00});
    defer alloc.free(issuer);
    tbs.appendSliceAssumeCapacity(issuer);

    // validity = SEQUENCE { notBefore, notAfter } using GeneralizedTime
    const nb = try makeGeneralizedTime(alloc, "20250101000000Z");
    defer alloc.free(nb);
    const na = try makeGeneralizedTime(alloc, "20300101000000Z");
    defer alloc.free(na);
    var validity_inner = std.ArrayList(u8){};
    defer validity_inner.deinit(alloc);
    try validity_inner.ensureTotalCapacity(alloc, nb.len + na.len + 4);
    validity_inner.appendSliceAssumeCapacity(nb);
    validity_inner.appendSliceAssumeCapacity(na);
    const validity = try makeSeq(alloc, validity_inner.items);
    defer alloc.free(validity);
    tbs.appendSliceAssumeCapacity(validity);

    // subject = empty SEQUENCE
    const subject = try makeSeq(alloc, &[_]u8{});
    defer alloc.free(subject);
    tbs.appendSliceAssumeCapacity(subject);

    // spki placeholder: empty SEQUENCE OK for our parser usage
    const spki = try makeSeq(alloc, &[_]u8{});
    defer alloc.free(spki);
    tbs.appendSliceAssumeCapacity(spki);

    // extensions: [3] EXPLICIT Extensions ::= SEQUENCE OF Extension
    // SAN OID 2.5.29.17 -> bytes: 55 1D 11
    const san_oid = &[_]u8{ 0x55, 0x1D, 0x11 };
    const oid = try makeOID(alloc, san_oid);
    defer alloc.free(oid);

    // GeneralNames ::= SEQUENCE { dNSName [2] IA5String }
    var gn = std.ArrayList(u8){};
    defer gn.deinit(alloc);
    try gn.ensureTotalCapacity(alloc, dns_name.len + 8);
    // context-specific primitive tag [2] is 0x82
    emitTLV(&gn, 0x82, dns_name);
    const gns = try makeSeq(alloc, gn.items);
    defer alloc.free(gns);

    const extn_val_octet = try makeOctet(alloc, gns);
    defer alloc.free(extn_val_octet);

    // Extension ::= SEQUENCE { extnID, extnValue }
    var ext_inner = std.ArrayList(u8){};
    defer ext_inner.deinit(alloc);
    try ext_inner.ensureTotalCapacity(alloc, oid.len + extn_val_octet.len + 8);
    ext_inner.appendSliceAssumeCapacity(oid);
    ext_inner.appendSliceAssumeCapacity(extn_val_octet);
    const one_ext = try makeSeq(alloc, ext_inner.items);
    defer alloc.free(one_ext);

    const exts_seq = try makeSeq(alloc, one_ext);
    defer alloc.free(exts_seq);

    const exts_ctx3 = try makeCtx(3, alloc, exts_seq);
    defer alloc.free(exts_ctx3);

    tbs.appendSliceAssumeCapacity(exts_ctx3);

    const tbs_seq = try makeSeq(alloc, tbs.items);
    defer alloc.free(tbs_seq);

    // --- outer Certificate ---
    // Append tbs, then minimal signatureAlgorithm SEQUENCE and empty BIT STRING
    var outer = std.ArrayList(u8){};
    defer outer.deinit(alloc);
    try outer.ensureTotalCapacity(alloc, tbs_seq.len + 16);
    outer.appendSliceAssumeCapacity(tbs_seq);
    const outer_sig_alg = try makeAlgorithmIdentifier(alloc);
    defer alloc.free(outer_sig_alg);
    outer.appendSliceAssumeCapacity(outer_sig_alg);
    // BIT STRING with 0 unused bits and empty content -> 0x03 0x01 0x00
    emitTLV(&outer, 0x03, &[_]u8{0x00});

    const cert = try makeSeq(alloc, outer.items);
    return cert;
}

fn now_unix() i64 {
    return @as(i64, @intCast(std.time.timestamp()));
}

test "tls_sni_mismatch_causes_validation_error" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const cert = try buildCertWithSan(alloc, "good.test");
    defer alloc.free(cert);

    var chain = [_][]const u8{cert};
    try std.testing.expectError(error.NameMismatch, x509.validateChain(alloc, &chain, now_unix(), "wrong.test", false));
}

test "tls_allow_insecure_bypasses_validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const cert = try buildCertWithSan(alloc, "good.test");
    defer alloc.free(cert);

    var chain = [_][]const u8{cert};
    try x509.validateChain(alloc, &chain, now_unix(), "wrong.test", true);
}
