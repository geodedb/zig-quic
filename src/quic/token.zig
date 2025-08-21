// MIT License
// Stateless Retry token encode/verify (minimal HMAC-based implementation)
const std = @import("std");

const H = std.crypto.hash.sha2.Sha256;

/// Stateless Retry token view.
pub const Token = struct {
    bytes: []const u8,
};

fn hash64(input: []const u8) u64 {
    var wy = std.hash.Wyhash.init(0);
    wy.update(input);
    return wy.final();
}

inline fn writeLe64(out: *[8]u8, v: u64) void {
    const le = std.mem.nativeToLittle(u64, v);
    @memcpy(out, std.mem.asBytes(&le));
}

inline fn readLe64(in: *const [8]u8) u64 {
    var tmp: u64 = undefined;
    @memcpy(std.mem.asBytes(&tmp), in);
    return std.mem.littleToNative(u64, tmp);
}

/// Layout: [8 bytes expiry_ms_le] || [8 bytes odcid_hash_le] || [16 bytes tag]
/// tag = HMAC-SHA256(secret, client_ip || odcid_hash_le || expiry_ms_le)[0..16]
fn makeTag(secret: []const u8, client_ip: []const u8, odcid_hash_le: *const [8]u8, expiry_le: *const [8]u8, out: *[16]u8) void {
    var mac = std.crypto.auth.hmac.Hmac(H).init(secret);
    mac.update(client_ip);
    mac.update(odcid_hash_le);
    mac.update(expiry_le);
    var full: [H.digest_length]u8 = undefined;
    mac.final(&full);
    @memcpy(out, full[0..16]);
}

/// Encode a token bound to the client's IP and the client's Original DCID.
pub fn encode(alloc: std.mem.Allocator, client_ip: []const u8, odcid: []const u8, secret: []const u8, expiry_ms_from_now: u64) ![]u8 {
    // Compute absolute expiry in ms using monotonic now as base.
    const now_ns: i128 = std.time.nanoTimestamp();
    const now_ms: u64 = @intCast(if (now_ns > 0) @as(u128, @intCast(now_ns)) / std.time.ns_per_ms else 0);
    const exp_abs: u64 = now_ms + expiry_ms_from_now;
    var expiry_le: [8]u8 = undefined;
    writeLe64(&expiry_le, exp_abs);
    const h: u64 = hash64(odcid);
    var hash_le: [8]u8 = undefined;
    writeLe64(&hash_le, h);
    var tag: [16]u8 = undefined;
    makeTag(secret, client_ip, &hash_le, &expiry_le, &tag);
    var out = try alloc.alloc(u8, 8 + 8 + 16);
    @memcpy(out[0..8], &expiry_le);
    @memcpy(out[8..16], &hash_le);
    @memcpy(out[16..32], &tag);
    return out;
}

/// Verify a token under secret and client address at current time.
/// Returns true when the tag matches and token has not expired.
pub fn verify(token: []const u8, client_ip: []const u8, secret: []const u8, now_ms: u64) bool {
    if (token.len != 32) return false;
    var expiry_le: [8]u8 = undefined;
    @memcpy(&expiry_le, token[0..8]);
    const exp_abs = readLe64(&expiry_le);
    if (now_ms > exp_abs) return false;
    var hash_le: [8]u8 = undefined;
    @memcpy(&hash_le, token[8..16]);
    var want: [16]u8 = undefined;
    makeTag(secret, client_ip, &hash_le, &expiry_le, &want);
    var got: [16]u8 = undefined;
    @memcpy(&got, token[16..32]);
    return std.mem.eql(u8, &want, &got);
}
