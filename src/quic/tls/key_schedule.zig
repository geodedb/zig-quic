// MIT License
// QUIC-TLS Key Schedule (RFC 9001) — HKDF labels and exporter
const std = @import("std");

/// Hash used for TLS_AES_128_GCM_SHA256 and CHACHA20_POLY1305_SHA256
pub const H = std.crypto.hash.sha2.Sha256; // 32-byte digest
const HKDF = std.crypto.kdf.hkdf.Hkdf(H);

/// QUIC v1 Initial Salt (RFC 9001 §5.2, Appendix A.1 vectors use this)
/// 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
pub const initial_salt_v1: [20]u8 = .{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

fn toU8(v: usize) u8 {
    return @as(u8, @intCast(v));
}

fn hkdfLabel(alloc: std.mem.Allocator, label: []const u8, context: []const u8, out_len: u16) ![]u8 {
    // struct {
    //   uint16 length;
    //   opaque label<7..255>; // "tls13 " + label
    //   opaque context<0..255>;
    // } HkdfLabel;
    const prefix = "tls13 ";
    const full_label = try std.mem.concat(alloc, u8, &[_][]const u8{ prefix, label });
    defer alloc.free(full_label);
    const total = 2 + 1 + full_label.len + 1 + context.len;
    var out = try alloc.alloc(u8, total);
    var i: usize = 0;
    out[i] = @as(u8, (out_len >> 8) & 0xff);
    i += 1;
    out[i] = @as(u8, out_len & 0xff);
    i += 1;
    out[i] = toU8(full_label.len);
    i += 1;
    std.mem.copy(u8, out[i .. i + full_label.len], full_label);
    i += full_label.len;
    out[i] = toU8(context.len);
    i += 1;
    if (context.len != 0) std.mem.copy(u8, out[i .. i + context.len], context);
    return out;
}

/// HKDF-Expand-Label as per TLS 1.3 using H.
pub fn expandLabel(prk: [H.digest_length]u8, label: []const u8, context: []const u8, out: []u8) !void {
    var fbb: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fbb);
    const alloc = fba.allocator();
    const info = try hkdfLabel(alloc, label, context, @as(u16, @intCast(out.len)));
    defer alloc.free(info);
    try HKDF.expand(out, prk[0..], info);
}

/// HKDF-Extract
pub fn extract(salt: ?[]const u8, ikm: []const u8) [H.digest_length]u8 {
    var out: [H.digest_length]u8 = undefined;
    HKDF.extract(&out, salt orelse &[_]u8{}, ikm);
    return out;
}

/// Derive initial_secret from DCID for QUIC v1.
pub fn deriveInitialSecretV1(dcid: []const u8) [H.digest_length]u8 {
    return extract(&initial_salt_v1, dcid);
}

/// Derive client/server initial secrets from initial_secret.
pub fn deriveClientServerInitial(initial_secret: [H.digest_length]u8) struct { client: [H.digest_length]u8, server: [H.digest_length]u8 } {
    var client: [H.digest_length]u8 = undefined;
    var server: [H.digest_length]u8 = undefined;
    expandLabel(initial_secret, "client in", &[_]u8{}, &client) catch unreachable;
    expandLabel(initial_secret, "server in", &[_]u8{}, &server) catch unreachable;
    return .{ .client = client, .server = server };
}

/// Derive key (16), iv (12), hp (16) from a traffic secret.
pub fn deriveKeyIvHp(secret: [H.digest_length]u8) struct { key: [16]u8, iv: [12]u8, hp: [16]u8 } {
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;
    expandLabel(secret, "quic key", &[_]u8{}, &key) catch unreachable;
    expandLabel(secret, "quic iv", &[_]u8{}, &iv) catch unreachable;
    expandLabel(secret, "quic hp", &[_]u8{}, &hp) catch unreachable;
    return .{ .key = key, .iv = iv, .hp = hp };
}
