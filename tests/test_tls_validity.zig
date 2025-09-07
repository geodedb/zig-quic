const std = @import("std");
const x509 = @import("quic_x509");

fn putByte(buf: *std.ArrayList(u8), b: u8) void {
    buf.appendAssumeCapacity(b);
}
fn putLen(buf: *std.ArrayList(u8), len: usize) void {
    if (len < 128) {
        buf.appendAssumeCapacity(@intCast(len));
    } else {
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

fn buildCertWithSanValidity(alloc: std.mem.Allocator, dns_name: []const u8, not_before: []const u8, not_after: []const u8) ![]u8 {
    var tbs = std.ArrayList(u8){};
    defer tbs.deinit(alloc);
    try tbs.ensureTotalCapacity(alloc, 512);
    const int1 = try makeInteger1(alloc, 1);
    defer alloc.free(int1);
    const int2 = try makeInteger1(alloc, 2);
    defer alloc.free(int2);
    const int3 = try makeInteger1(alloc, 3);
    defer alloc.free(int3);
    tbs.appendSliceAssumeCapacity(int1);
    tbs.appendSliceAssumeCapacity(int2);
    tbs.appendSliceAssumeCapacity(int3);
    const issuer = try makeSeq(alloc, &[_]u8{});
    defer alloc.free(issuer);
    tbs.appendSliceAssumeCapacity(issuer);
    const nb = try makeGeneralizedTime(alloc, not_before);
    defer alloc.free(nb);
    const na = try makeGeneralizedTime(alloc, not_after);
    defer alloc.free(na);
    var validity_inner = std.ArrayList(u8){};
    defer validity_inner.deinit(alloc);
    try validity_inner.ensureTotalCapacity(alloc, nb.len + na.len + 4);
    validity_inner.appendSliceAssumeCapacity(nb);
    validity_inner.appendSliceAssumeCapacity(na);
    const validity = try makeSeq(alloc, validity_inner.items);
    defer alloc.free(validity);
    tbs.appendSliceAssumeCapacity(validity);
    const subject = try makeSeq(alloc, &[_]u8{});
    defer alloc.free(subject);
    tbs.appendSliceAssumeCapacity(subject);
    const spki = try makeSeq(alloc, &[_]u8{});
    defer alloc.free(spki);
    tbs.appendSliceAssumeCapacity(spki);
    // SAN ext
    const san_oid = &[_]u8{ 0x55, 0x1D, 0x11 };
    const oid = try makeOID(alloc, san_oid);
    defer alloc.free(oid);
    var gn = std.ArrayList(u8){};
    defer gn.deinit(alloc);
    try gn.ensureTotalCapacity(alloc, dns_name.len + 8);
    emitTLV(&gn, 0x82, dns_name);
    const gns = try makeSeq(alloc, gn.items);
    defer alloc.free(gns);
    const extn_val_octet = try makeOctet(alloc, gns);
    defer alloc.free(extn_val_octet);
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
    var outer = std.ArrayList(u8){};
    defer outer.deinit(alloc);
    try outer.ensureTotalCapacity(alloc, tbs_seq.len + 16);
    outer.appendSliceAssumeCapacity(tbs_seq);
    const sig_alg = try makeSeq(alloc, &[_]u8{});
    defer alloc.free(sig_alg);
    outer.appendSliceAssumeCapacity(sig_alg);
    emitTLV(&outer, 0x03, &[_]u8{0x00});
    const cert = try makeSeq(alloc, outer.items);
    return cert;
}

// 2020-01-01 00:00:00Z
const TS_2020_01_01: i64 = 1_577_836_800;
// 2020-01-02 00:00:00Z
const TS_2020_01_02: i64 = 1_577_923_200;

test "tls_not_yet_valid_is_rejected" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const cert = try buildCertWithSanValidity(alloc, "good.test", "20300101000000Z", "20350101000000Z");
    defer alloc.free(cert);
    var chain = [_][]const u8{cert};
    try std.testing.expectError(error.NotYetValid, x509.validateChain(alloc, &chain, TS_2020_01_01, "good.test", false));
}

test "tls_expired_is_rejected" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const cert = try buildCertWithSanValidity(alloc, "good.test", "20200101000000Z", "20200102000000Z");
    defer alloc.free(cert);
    var chain = [_][]const u8{cert};
    // Use a timestamp strictly greater than notAfter to trigger Expired before signature parsing
    try std.testing.expectError(error.Expired, x509.validateChain(alloc, &chain, TS_2020_01_02 + 1, "good.test", false));
}
