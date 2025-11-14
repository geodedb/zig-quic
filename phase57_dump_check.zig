const std = @import("std");
const ks = @import("vendor/ztls/src/key_schedule.zig");
const Aes128 = std.crypto.core.aes.Aes128;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

const Meta = struct {
    pn_preview: u64,
    key_phase: bool,
    largest_pn: u64,
    header_first_masked: u8,
    dcid_len: usize,
    pn_len: usize,
    pn_start: usize,
};

const KeyMaterial = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const meta = try readMeta(allocator, "/tmp/phase57-short-header.meta");
    defer allocator.destroy(meta);

    const packet_bytes = try std.fs.cwd().readFileAlloc(allocator, "/tmp/phase57-short-header.bin", 4096);
    defer allocator.free(packet_bytes);

    const client_secret = try readClientSecret(allocator, "/tmp/tls_keys_comprehensive.log");
    const current_keys = keyMaterial(ks.deriveKeyIvHp(client_secret));
    const next_secret = ks.updateQuicSecret(client_secret);
    const next_keys = keyMaterial(ks.deriveKeyIvHp(next_secret));
    const tls_next_secret = ks.updateTrafficSecret(client_secret);
    const tls_next_keys = keyMaterial(ks.deriveKeyIvHp(tls_next_secret));

    printKeyMaterial("CURRENT", current_keys);
    printKeyMaterial("NEXT", next_keys);
    printKeyMaterial("TLS-NEXT", tls_next_keys);

    try attemptDecode("CURRENT", current_keys, meta.*, packet_bytes, allocator);
    try attemptDecode("NEXT", next_keys, meta.*, packet_bytes, allocator);
    try attemptDecode("TLS-NEXT", tls_next_keys, meta.*, packet_bytes, allocator);
}

fn keyMaterial(mat: anytype) KeyMaterial {
    return KeyMaterial{ .key = mat.key, .iv = mat.iv, .hp = mat.hp };
}

fn printKeyMaterial(label: []const u8, mat: KeyMaterial) void {
    std.debug.print("{s} key=", .{label});
    dumpHex(mat.key[0..]);
    std.debug.print(" iv=", .{});
    dumpHex(mat.iv[0..]);
    std.debug.print(" hp=", .{});
    dumpHex(mat.hp[0..]);
    std.debug.print("\n", .{});
}

fn dumpHex(bytes: []const u8) void {
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        std.debug.print("{X:0>2}", .{bytes[i]});
    }
}

fn attemptDecode(label: []const u8, keys: KeyMaterial, meta: Meta, packet_bytes: []const u8, allocator: std.mem.Allocator) !void {
    std.debug.print("\n========== {s} ==========" , .{label});
    const result = decryptShortHeader(keys, meta, packet_bytes, allocator) catch |err| {
        std.debug.print("\n[{s}] ❌ decrypt failed: {}\n", .{ label, err });
        return;
    };
    defer allocator.free(result.payload);
    std.debug.print("\n[{s}] ✅ pn={} key_phase={} payload_len={} bytes\n", .{ label, result.pn, result.key_phase, result.payload.len });
}

const DecryptResult = struct {
    pn: u64,
    key_phase: bool,
    payload: []u8,
};

fn decryptShortHeader(keys: KeyMaterial, meta: Meta, packet_bytes: []const u8, allocator: std.mem.Allocator) !DecryptResult {
    if (packet_bytes.len < 1 + meta.dcid_len + meta.pn_len + 16) return error.PacketTooShort;
    var header_first = packet_bytes[0];
    const dcid = packet_bytes[1 .. 1 + meta.dcid_len];
    const pn_start = 1 + meta.dcid_len;
    var pn_masked4: [4]u8 = .{0} ** 4;
    const avail = @min(@as(usize, 4), packet_bytes.len - pn_start);
    std.mem.copyForwards(u8, pn_masked4[0..avail], packet_bytes[pn_start .. pn_start + avail]);
    const sample_start = pn_start + 4;
    if (sample_start + 16 > packet_bytes.len) return error.SampleOutOfRange;
    var sample: [16]u8 = undefined;
    std.mem.copyForwards(u8, sample[0..], packet_bytes[sample_start .. sample_start + 16]);

    var pn_unmasked = pn_masked4;
    const pn_len = removeHeaderProtection(&keys.hp, &sample, &header_first, &pn_unmasked);
    if (pn_len != meta.pn_len) {
        std.debug.print("[WARN] pn_len from HP={} (meta={})\n", .{ pn_len, meta.pn_len });
    }

    var truncated: u64 = 0;
    var i: usize = 0;
    while (i < pn_len) : (i += 1) {
        truncated = (truncated << 8) | pn_unmasked[i];
    }
    const full_pn = expandPacketNumber(truncated, @intCast(pn_len), meta.largest_pn);
    const key_phase = (header_first & 0x04) != 0;

    const ct = packet_bytes[pn_start + pn_len ..];
    if (ct.len < 16) return error.TruncatedCiphertext;
    const aad_len = 1 + dcid.len + pn_len;
    const aad = try allocator.alloc(u8, aad_len);
    defer allocator.free(aad);
    aad[0] = header_first;
    std.mem.copyForwards(u8, aad[1 .. 1 + dcid.len], dcid);
    std.mem.copyForwards(u8, aad[1 + dcid.len .. aad_len], pn_unmasked[0..pn_len]);

    const plaintext = try allocator.alloc(u8, ct.len - 16);
    errdefer allocator.free(plaintext);

    var nonce = keys.iv;
    var pn_tmp = full_pn;
    var idx: usize = 0;
    while (idx < 8) : (idx += 1) {
        const pos = nonce.len - 1 - idx;
        nonce[pos] ^= @as(u8, @truncate(pn_tmp & 0xff));
        pn_tmp >>= 8;
    }

    var tag: [16]u8 = undefined;
    std.mem.copyForwards(u8, tag[0..], ct[ct.len - 16 ..]);
    Aes128Gcm.decrypt(plaintext, ct[0 .. ct.len - 16], tag, aad, nonce, keys.key) catch return error.AuthenticationFailed;

    return DecryptResult{ .pn = full_pn, .key_phase = key_phase, .payload = plaintext };
}

fn removeHeaderProtection(hp_key: *const [16]u8, sample16: *const [16]u8, header_first: *u8, pn_buf: *[4]u8) u3 {
    var mask: [16]u8 = undefined;
    var ctx = Aes128.initEnc(hp_key.*);
    ctx.encrypt(&mask, sample16);
    const is_long = (header_first.* & 0x80) != 0;
    const hdr_mask: u8 = if (is_long) 0x0f else 0x1f;
    header_first.* ^= (mask[0] & hdr_mask);
    var i: usize = 0;
    while (i < 4) : (i += 1) pn_buf.*[i] ^= mask[i + 1];
    return @as(u3, @intCast((header_first.* & 0x03))) + 1;
}

fn expandPacketNumber(truncated: u64, pn_len: u3, largest_pn: u64) u64 {
    const pn_nbits: u6 = @as(u6, pn_len) * 8;
    const pn_win: u64 = @as(u64, 1) << pn_nbits;
    const pn_hwin: u64 = pn_win / 2;
    const pn_mask: u64 = pn_win - 1;
    const expected_pn: u64 = largest_pn +% 1;
    var candidate: u64 = (expected_pn & ~pn_mask) | truncated;
    if (expected_pn >= pn_hwin) {
        if (candidate <= expected_pn - pn_hwin and candidate < (1 << 62)) {
            candidate += pn_win;
        }
    } else if (candidate > expected_pn + pn_hwin and candidate >= pn_win) {
        candidate -= pn_win;
    }
    return candidate;
}

fn readMeta(allocator: std.mem.Allocator, path: []const u8) !*Meta {
    const contents = try std.fs.cwd().readFileAlloc(allocator, path, 1024);
    defer allocator.free(contents);
    var meta = try allocator.create(Meta);
    meta.* = Meta{
        .pn_preview = 0,
        .key_phase = false,
        .largest_pn = 0,
        .header_first_masked = 0,
        .dcid_len = 0,
        .pn_len = 0,
        .pn_start = 0,
    };

    var it = std.mem.tokenizeScalar(u8, contents, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        var parts = std.mem.splitScalar(u8, line, '=');
        var key = parts.next() orelse continue;
        const value = parts.next() orelse continue;
        key = std.mem.trim(u8, key, " \t\r");
        const trimmed = std.mem.trim(u8, value, " \t\r");
        if (std.mem.eql(u8, key, "pn_preview")) {
            meta.pn_preview = try std.fmt.parseInt(u64, trimmed, 10);
        } else if (std.mem.eql(u8, key, "key_phase")) {
            meta.key_phase = std.mem.eql(u8, trimmed, "true");
        } else if (std.mem.eql(u8, key, "largest_pn")) {
            meta.largest_pn = try std.fmt.parseInt(u64, trimmed, 10);
        } else if (std.mem.eql(u8, key, "header_first_masked")) {
            meta.header_first_masked = try parseHexByte(trimmed);
        } else if (std.mem.eql(u8, key, "dcid_len")) {
            meta.dcid_len = try std.fmt.parseInt(usize, trimmed, 10);
        } else if (std.mem.eql(u8, key, "pn_len")) {
            meta.pn_len = try std.fmt.parseInt(usize, trimmed, 10);
        } else if (std.mem.eql(u8, key, "pn_start")) {
            meta.pn_start = try std.fmt.parseInt(usize, trimmed, 10);
        }
    }
    return meta;
}

fn parseHexByte(hex: []const u8) !u8 {
    if (hex.len < 3) return error.InvalidHex;
    return try std.fmt.parseInt(u8, hex[2..], 16);
}

fn readClientSecret(allocator: std.mem.Allocator, path: []const u8) ![32]u8 {
    const contents = try std.fs.cwd().readFileAlloc(allocator, path, 4096);
    defer allocator.free(contents);
    var it = std.mem.tokenizeScalar(u8, contents, '\n');
    var latest: ?[32]u8 = null;
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "CLIENT_TRAFFIC_SECRET_0")) continue;
        var parts = std.mem.tokenizeScalar(u8, line, ' ');
        _ = parts.next() orelse continue;
        _ = parts.next() orelse continue;
        const secret_hex = parts.next() orelse continue;
        const tmp = try hexToBytes(allocator, secret_hex);
        defer allocator.free(tmp);
        if (tmp.len != 32) return error.InvalidSecretLength;
        var secret: [32]u8 = undefined;
        std.mem.copyForwards(u8, &secret, tmp);
        latest = secret;
    }
    return latest orelse error.SecretNotFound;
}

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHex;
    const out = try allocator.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = try std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16);
    }
    return out;
}
