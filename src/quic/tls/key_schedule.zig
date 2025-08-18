// MIT License
// QUIC-TLS Key Schedule (RFC 9001/9369) — HKDF labels and exporter
const std = @import("std");

/// Hash used for TLS_AES_128_GCM_SHA256 and CHACHA20_POLY1305_SHA256
pub const H = std.crypto.hash.sha2.Sha256; // 32-byte digest

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

// --- Minimal HMAC(SHA-256) + HKDF (RFC 5869) ---
fn sha256(data: []const u8) [H.digest_length]u8 {
    var hasher = H.init(.{});
    hasher.update(data);
    var out: [H.digest_length]u8 = undefined;
    hasher.final(&out);
    return out;
}

fn hmac_sha256(key: []const u8, data: []const u8) [H.digest_length]u8 {
    const block_len: usize = 64; // SHA-256 block size
    var k0: [block_len]u8 = .{0} ** block_len;
    if (key.len > block_len) {
        const d = sha256(key);
        @memcpy(k0[0..d.len], d[0..]);
    } else {
        @memcpy(k0[0..key.len], key);
    }
    var ipad: [block_len]u8 = undefined;
    var opad: [block_len]u8 = undefined;
    for (k0, 0..) |b, i| {
        ipad[i] = b ^ 0x36;
        opad[i] = b ^ 0x5c;
    }
    var buf_inner = std.ArrayList(u8).init(std.heap.page_allocator);
    defer buf_inner.deinit();
    buf_inner.appendSlice(&ipad) catch unreachable;
    buf_inner.appendSlice(data) catch unreachable;
    const inner = sha256(buf_inner.items);

    var buf_outer = std.ArrayList(u8).init(std.heap.page_allocator);
    defer buf_outer.deinit();
    buf_outer.appendSlice(&opad) catch unreachable;
    buf_outer.appendSlice(&inner) catch unreachable;
    return sha256(buf_outer.items);
}

fn hkdfExtractRaw(salt: ?[]const u8, ikm: []const u8) [H.digest_length]u8 {
    var zeros: [H.digest_length]u8 = .{0} ** H.digest_length;
    const s = salt orelse zeros[0..];
    return hmac_sha256(s, ikm);
}

fn hkdfExpand(out: []u8, prk: [H.digest_length]u8, info: []const u8) void {
    const hash_len: usize = H.digest_length;
    const n: usize = (out.len + hash_len - 1) / hash_len;
    var t_prev: [H.digest_length]u8 = undefined;
    var pos: usize = 0;
    var i: usize = 1;
    while (i <= n) : (i += 1) {
        // T(i) = HMAC(PRK, T(i-1) | info | i)
        var input = std.ArrayList(u8).init(std.heap.page_allocator);
        defer input.deinit();
        if (i > 1) input.appendSlice(&t_prev) catch unreachable;
        if (info.len != 0) input.appendSlice(info) catch unreachable;
        input.append(@as(u8, @intCast(i))) catch unreachable;
        const t = hmac_sha256(&prk, input.items);
        t_prev = t;
        const to_copy = @min(hash_len, out.len - pos);
        @memcpy(out[pos .. pos + to_copy], t_prev[0..to_copy]);
        pos += to_copy;
    }
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
