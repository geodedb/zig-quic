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
    attempt_label: ?[]u8 = null,
    dcid_candidate: ?u8 = null,
};

const KeyMaterial = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

const HeaderInfo = struct {
    header_first: u8,
    pn_len: usize,
    pn_bytes: [4]u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var dump_path: []const u8 = "/tmp/phase57-short-header.bin";
    var meta_path: []const u8 = "/tmp/phase57-short-header.meta";
    var dump_path_buf: ?[]u8 = null;
    var meta_path_buf: ?[]u8 = null;
    defer if (dump_path_buf) |buf| allocator.free(buf);
    defer if (meta_path_buf) |buf| allocator.free(buf);

    if (args.len > 1) {
        const id = try std.fmt.parseInt(u8, args[1], 10);
        dump_path_buf = try std.fmt.allocPrint(allocator, "/tmp/phase57-short-header-{}.bin", .{id});
        meta_path_buf = try std.fmt.allocPrint(allocator, "/tmp/phase57-short-header-{}.meta", .{id});
        dump_path = dump_path_buf.?;
        meta_path = meta_path_buf.?;
    }

    const meta = try readMeta(allocator, meta_path);
    defer {
        if (meta.attempt_label) |label| allocator.free(label);
        allocator.destroy(meta);
    }

    if (meta.attempt_label) |label| {
        std.debug.print("Loaded dump attempt_label={s} dcid_candidate={}\n", .{
            label,
            meta.dcid_candidate orelse 0xff,
        });
    }

    const packet_bytes = try std.fs.cwd().readFileAlloc(allocator, dump_path, 16384);
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

    try attemptCombination("CURRENT", current_keys, current_keys, meta.*, packet_bytes, allocator);
    try attemptCombination("NEXT", next_keys, next_keys, meta.*, packet_bytes, allocator);
    try attemptCombination("TLS-NEXT", tls_next_keys, tls_next_keys, meta.*, packet_bytes, allocator);
    try attemptCombination("HP-CURRENT + AEAD-NEXT", current_keys, next_keys, meta.*, packet_bytes, allocator);
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

fn attemptCombination(
    label: []const u8,
    hp_keys: KeyMaterial,
    aead_keys: KeyMaterial,
    meta: Meta,
    packet_bytes: []const u8,
    allocator: std.mem.Allocator,
) !void {
    std.debug.print("\n========== {s} ==========\n", .{label});
    const header = unmaskHeader(label, hp_keys, meta, packet_bytes) catch |err| {
        std.debug.print("[{s}] ❌ header decrypt failed: {}\n", .{ label, err });
        return;
    };
    try decryptWithHeader(label, header, aead_keys, meta, packet_bytes, allocator);
}

fn unmaskHeader(
    label: []const u8,
    keys: KeyMaterial,
    meta: Meta,
    packet_bytes: []const u8,
) !HeaderInfo {
    if (packet_bytes.len < 1 + meta.dcid_len + 4 + 16) return error.PacketTooShort;
    var header_first = packet_bytes[0];
    const pn_start = 1 + meta.dcid_len;
    var pn_masked: [4]u8 = .{0} ** 4;
    const avail = @min(@as(usize, 4), packet_bytes.len - pn_start);
    std.mem.copyForwards(u8, pn_masked[0..avail], packet_bytes[pn_start .. pn_start + avail]);
    const sample_start = pn_start + 4;
    if (sample_start + 16 > packet_bytes.len) return error.SampleOutOfRange;
    var sample: [16]u8 = undefined;
    std.mem.copyForwards(u8, sample[0..], packet_bytes[sample_start .. sample_start + 16]);

    var mask: [16]u8 = undefined;
    var ctx = Aes128.initEnc(keys.hp);
    ctx.encrypt(&mask, &sample);

    header_first ^= mask[0] & 0x1f;
    var pn_unmasked = pn_masked;
    var i: usize = 0;
    while (i < 4) : (i += 1) pn_unmasked[i] ^= mask[i + 1];
    const pn_len = @as(usize, (header_first & 0x03) + 1);
    std.debug.print("[{s}] header_first_after=0x{X:0>2} pn_len={} key_phase={}\n", .{
        label,
        header_first,
        pn_len,
        (header_first & 0x04) != 0,
    });
    return HeaderInfo{ .header_first = header_first, .pn_len = pn_len, .pn_bytes = pn_unmasked };
}

fn decryptWithHeader(
    label: []const u8,
    header: HeaderInfo,
    keys: KeyMaterial,
    meta: Meta,
    packet_bytes: []const u8,
    allocator: std.mem.Allocator,
) !void {
    const dcid = packet_bytes[1 .. 1 + meta.dcid_len];
    const pn_start = 1 + meta.dcid_len;
    const pn_len = header.pn_len;

    var truncated: u64 = 0;
    var i: usize = 0;
    while (i < pn_len) : (i += 1) {
        truncated = (truncated << 8) | header.pn_bytes[i];
    }
    const full_pn = expandPacketNumber(truncated, @intCast(pn_len), meta.largest_pn);

    const ct = packet_bytes[pn_start + pn_len ..];
    if (ct.len < 16) return error.TruncatedCiphertext;

    const aad_len = 1 + dcid.len + pn_len;
    const aad = try allocator.alloc(u8, aad_len);
    defer allocator.free(aad);
    aad[0] = header.header_first;
    std.mem.copyForwards(u8, aad[1 .. 1 + dcid.len], dcid);
    std.mem.copyForwards(u8, aad[1 + dcid.len .. aad_len], header.pn_bytes[0..pn_len]);

    const plaintext = try allocator.alloc(u8, ct.len - 16);
    defer allocator.free(plaintext);

    var nonce = keys.iv;
    var pn_tmp = full_pn;
    i = 0;
    while (i < 8) : (i += 1) {
        const pos = nonce.len - 1 - i;
        nonce[pos] ^= @as(u8, @truncate(pn_tmp & 0xff));
        pn_tmp >>= 8;
    }

    var tag: [16]u8 = undefined;
    std.mem.copyForwards(u8, tag[0..], ct[ct.len - 16 ..]);
    Aes128Gcm.decrypt(plaintext, ct[0 .. ct.len - 16], tag, aad, nonce, keys.key) catch |err| {
        std.debug.print("[{s}] ❌ decrypt failed: {}\n", .{ label, err });
        return;
    };

    std.debug.print(
        "[{s}] ✅ pn={} key_phase={} payload_len={} bytes\n",
        .{ label, full_pn, (header.header_first & 0x04) != 0, plaintext.len },
    );
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
        .attempt_label = null,
        .dcid_candidate = null,
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
        } else if (std.mem.eql(u8, key, "attempt_label")) {
            meta.attempt_label = try allocator.dupe(u8, trimmed);
        } else if (std.mem.eql(u8, key, "dcid_candidate")) {
            meta.dcid_candidate = try std.fmt.parseInt(u8, trimmed, 10);
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
