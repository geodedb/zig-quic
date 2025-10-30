// MIT License
// QUIC-TLS Key Schedule (RFC 9001/9369) — HKDF labels and exporter
const std = @import("std");

/// Hash used for TLS_AES_128_GCM_SHA256 and CHACHA20_POLY1305_SHA256
pub const H = std.crypto.hash.sha2.Sha256; // 32-byte digest

/// Use standard library HMAC and HKDF
const Hmac = std.crypto.auth.hmac.Hmac;
const Hkdf = std.crypto.kdf.hkdf.Hkdf;
const HmacSha256 = Hmac(H);
const HkdfSha256 = Hkdf(HmacSha256);

/// QUIC v1 Initial Salt (RFC 9001 §5.2, Appendix A.1 vectors use this)
/// 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
pub const initial_salt_v1: [20]u8 = .{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

/// QUIC v2 Initial Salt (RFC 9369 §A.1)
/// 0dede3def700a6db819381be6e269dcbf9bd2ed9
pub const initial_salt_v2: [20]u8 = .{
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
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
    out[i] = @as(u8, @truncate(out_len >> 8));
    i += 1;
    out[i] = @as(u8, @truncate(out_len));
    i += 1;
    out[i] = toU8(full_label.len);
    i += 1;
    @memcpy(out[i .. i + full_label.len], full_label);
    i += full_label.len;
    out[i] = toU8(context.len);
    i += 1;
    if (context.len != 0) @memcpy(out[i .. i + context.len], context);
    return out;
}

/// Public HMAC helper for TLS Finished and other KATs.
pub fn hmacSha256(key: []const u8, data: []const u8) [H.digest_length]u8 {
    var out: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&out, data, key);
    return out;
}

fn hkdfExtractRaw(salt: ?[]const u8, ikm: []const u8) [H.digest_length]u8 {
    return HkdfSha256.extract(salt orelse &[_]u8{}, ikm);
}

fn hkdfExpand(out: []u8, prk: [H.digest_length]u8, info: []const u8) void {
    HkdfSha256.expand(out, info, prk);
}

/// HKDF-Expand-Label as per TLS 1.3 using H.
pub fn expandLabel(prk: [H.digest_length]u8, label: []const u8, context: []const u8, out: []u8) !void {
    var fbb: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fbb);
    const alloc = fba.allocator();
    const info = try hkdfLabel(alloc, label, context, @as(u16, @intCast(out.len)));
    defer alloc.free(info);
    hkdfExpand(out, prk, info);
}

/// HKDF-Extract
pub fn extract(salt: ?[]const u8, ikm: []const u8) [H.digest_length]u8 {
    return hkdfExtractRaw(salt, ikm);
}

/// Derive initial_secret from DCID for QUIC v1.
pub fn deriveInitialSecretV1(dcid: []const u8) [H.digest_length]u8 {
    return extract(&initial_salt_v1, dcid);
}

/// Derive initial_secret from DCID for QUIC v2.
pub fn deriveInitialSecretV2(dcid: []const u8) [H.digest_length]u8 {
    return extract(&initial_salt_v2, dcid);
}

/// Derive initial_secret from DCID for the given QUIC version.
pub fn deriveInitialSecret(version_v2: bool, dcid: []const u8) [H.digest_length]u8 {
    return if (version_v2) deriveInitialSecretV2(dcid) else deriveInitialSecretV1(dcid);
}

/// Derive client/server initial secrets from initial_secret.
pub fn deriveClientServerInitial(initial_secret: [H.digest_length]u8) struct { client: [H.digest_length]u8, server: [H.digest_length]u8 } {
    var client: [H.digest_length]u8 = undefined;
    var server: [H.digest_length]u8 = undefined;
    expandLabel(initial_secret, "client in", &[_]u8{}, &client) catch unreachable;
    expandLabel(initial_secret, "server in", &[_]u8{}, &server) catch unreachable;
    return .{ .client = client, .server = server };
}

/// Derive key (16), iv (12), hp (16) from a traffic secret for QUIC v1.
pub fn deriveKeyIvHp(secret: [H.digest_length]u8) struct { key: [16]u8, iv: [12]u8, hp: [16]u8 } {
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;
    expandLabel(secret, "quic key", &[_]u8{}, &key) catch unreachable;
    expandLabel(secret, "quic iv", &[_]u8{}, &iv) catch unreachable;
    expandLabel(secret, "quic hp", &[_]u8{}, &hp) catch unreachable;

    // DIAGNOSTIC: Log the exact keys being derived
    std.log.debug("deriveKeyIvHp: secret[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{
        secret[0], secret[1], secret[2], secret[3]
    });
    std.log.debug("  -> key[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{
        key[0], key[1], key[2], key[3]
    });
    std.log.debug("  -> iv[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{
        iv[0], iv[1], iv[2], iv[3]
    });
    std.log.debug("  -> hp[0..4]={X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{
        hp[0], hp[1], hp[2], hp[3]
    });

    return .{ .key = key, .iv = iv, .hp = hp };
}

/// Derive key (16), iv (12), hp (16) from a traffic secret for QUIC v2.
pub fn deriveKeyIvHpV2(secret: [H.digest_length]u8) struct { key: [16]u8, iv: [12]u8, hp: [16]u8 } {
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;
    expandLabel(secret, "quicv2 key", &[_]u8{}, &key) catch unreachable;
    expandLabel(secret, "quicv2 iv", &[_]u8{}, &iv) catch unreachable;
    expandLabel(secret, "quicv2 hp", &[_]u8{}, &hp) catch unreachable;
    return .{ .key = key, .iv = iv, .hp = hp };
}

/// TLS 1.3 traffic secret update: Derive next application traffic secret.
/// next_secret = HKDF-Expand-Label(current_secret, "traffic upd", "")
pub fn updateTrafficSecret(current_secret: [H.digest_length]u8) [H.digest_length]u8 {
    var next: [H.digest_length]u8 = undefined;
    expandLabel(current_secret, "traffic upd", &[_]u8{}, &next) catch unreachable;
    return next;
}

/// Derive a secret using HKDF-Expand-Label
pub fn deriveSecret(secret: [H.digest_length]u8, label: []const u8, context: []const u8) [H.digest_length]u8 {
    var derived: [H.digest_length]u8 = undefined;
    expandLabel(secret, label, context, &derived) catch unreachable;
    return derived;
}
