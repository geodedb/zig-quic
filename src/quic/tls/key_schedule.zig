// MIT License
// QUIC-TLS Key Schedule (RFC 9001) — HKDF labels and exporter
const std = @import("std");

pub const H = std.crypto.hash.sha2.Sha256; // for AES-128-GCM / CHACHA20-POLY1305 suites
const HKDF = std.crypto.kdf.hkdf.Hkdf(H);

fn hkdfLabel(alloc: std.mem.Allocator, label: []const u8, context: []const u8, out_len: u16) ![]u8 {
    // TLS 1.3 HKDF-Label = struct { length(2), label_len(1), "tls13 " + label, context_len(1), context }
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
    out[i] = @as(u8, full_label.len);
    i += 1;
    std.mem.copy(u8, out[i..][0..full_label.len], full_label);
    i += full_label.len;
    out[i] = @as(u8, context.len);
    i += 1;
    std.mem.copy(u8, out[i..][0..context.len], context);
    return out;
}

pub fn expandLabel(prk: [H.digest_length]u8, label: []const u8, context: []const u8, out: []u8) !void {
    var fba = std.heap.FixedBufferAllocator.init(&[_]u8{0} ** 256);
    const alloc = fba.allocator();
    const info = try hkdfLabel(alloc, label, context, @as(u16, @intCast(out.len)));
    defer alloc.free(info);
    try HKDF.expand(out, prk[0..], info);
}

pub fn extract(salt: ?[]const u8, ikm: []const u8) [H.digest_length]u8 {
    var out: [H.digest_length]u8 = undefined;
    HKDF.extract(&out, salt orelse &[_]u8{}, ikm);
    return out;
}

pub fn exporterSecret(early: bool, handshake_secret: [H.digest_length]u8) [H.digest_length]u8 {
    _ = early;
    // Placeholder for correct tree; returns handshake_secret for now.
    return handshake_secret;
}
