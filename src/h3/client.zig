// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const api = @import("quic_api");

/// Encode a QUIC varint into out, returning bytes written or 0 if out too small.
pub fn encodeVarint(v: u64, out: []u8) usize {
    if (v < (1 << 6)) {
        if (out.len < 1) return 0;
        out[0] = @as(u8, @intCast(v)) | 0b00 << 6;
        return 1;
    } else if (v < (1 << 14)) {
        if (out.len < 2) return 0;
        out[0] = @as(u8, @intCast(v >> 8)) | 0b01 << 6;
        out[1] = @as(u8, @intCast(v & 0xff));
        return 2;
    } else if (v < (1 << 30)) {
        if (out.len < 4) return 0;
        out[0] = @as(u8, @intCast(v >> 24)) | 0b10 << 6;
        out[1] = @as(u8, @intCast((v >> 16) & 0xff));
        out[2] = @as(u8, @intCast((v >> 8) & 0xff));
        out[3] = @as(u8, @intCast(v & 0xff));
        return 4;
    } else {
        if (out.len < 8) return 0;
        out[0] = @as(u8, @intCast(v >> 56)) | 0b11 << 6;
        out[1] = @as(u8, @intCast((v >> 48) & 0xff));
        out[2] = @as(u8, @intCast((v >> 40) & 0xff));
        out[3] = @as(u8, @intCast((v >> 32) & 0xff));
        out[4] = @as(u8, @intCast((v >> 24) & 0xff));
        out[5] = @as(u8, @intCast((v >> 16) & 0xff));
        out[6] = @as(u8, @intCast((v >> 8) & 0xff));
        out[7] = @as(u8, @intCast(v & 0xff));
        return 8;
    }
}

fn decodeVarint(h: []const u8, off: *usize) ?u64 {
    if (off.* >= h.len) return null;
    const first = h[off.*];
    const prefix = first >> 6;
    const len: usize = switch (prefix) {
        0 => 1,
        1 => 2,
        2 => 4,
        else => 8,
    };
    if (off.* + len > h.len) return null;
    var v: u64 = 0;
    switch (len) {
        1 => v = (first & 0x3f),
        2 => v = (@as(u64, first & 0x3f) << 8) | @as(u64, h[off.* + 1]),
        4 => v = (@as(u64, first & 0x3f) << 24) | (@as(u64, h[off.* + 1]) << 16) | (@as(u64, h[off.* + 2]) << 8) | @as(u64, h[off.* + 3]),
        else => v = (@as(u64, first & 0x3f) << 56) | (@as(u64, h[off.* + 1]) << 48) | (@as(u64, h[off.* + 2]) << 40) | (@as(u64, h[off.* + 3]) << 32) |
            (@as(u64, h[off.* + 4]) << 24) | (@as(u64, h[off.* + 5]) << 16) | (@as(u64, h[off.* + 6]) << 8) | @as(u64, h[off.* + 7]),
    }
    off.* += len;
    return v;
}

fn encodeIndexedStatic(index: u64, out: []u8) usize {
    if (out.len == 0) return 0;
    out[0] = 0b1100_0000; // Indexed Field Line, T=1 static
    if (index < 0x3f) {
        out[0] |= @as(u8, @intCast(index));
        return 1;
    } else {
        var k: usize = 1;
        out[0] |= 0x3f;
        var rem: u64 = index - 0x3f;
        while (k < out.len) : (k += 1) {
            var b: u8 = @intCast(rem & 0x7f);
            rem >>= 7;
            if (rem != 0) b |= 0x80;
            out[k] = b;
            if (rem == 0) break;
        }
        return k;
    }
}

fn encPref(val: u64, out: []u8, prefix_bits: u3) usize {
    const max: u8 = switch (prefix_bits) {
        1 => 0x01,
        2 => 0x03,
        3 => 0x07,
        4 => 0x0f,
        5 => 0x1f,
        6 => 0x3f,
        else => 0x7f,
    };
    var k: usize = 1;
    if (val < max) {
        out[0] |= @as(u8, @intCast(val));
        return 1;
    }
    out[0] |= max;
    var rem = val - max;
    while (true) {
        var b: u8 = @intCast(rem & 0x7f);
        rem >>= 7;
        if (rem != 0) b |= 0x80;
        out[k] = b;
        k += 1;
        if (rem == 0) break;
    }
    return k;
}

/// Build a minimal QPACK header block for an HTTP/3 GET to host/path.
pub fn buildSimpleGetHeaders(host: []const u8, path: []const u8, out: []u8) ?usize {
    var k: usize = 0;
    if (out.len < 2) return null;
    out[k] = 0;
    k += 1; // RIC=0
    out[k] = 0;
    k += 1; // Base=0
    // :method GET (static idx 17)
    k += encodeIndexedStatic(17, out[k..]);
    // :scheme https (static idx 23)
    k += encodeIndexedStatic(23, out[k..]);
    // :authority host (literal with name reference to static idx 0)
    if (out.len < k + 1) return null;
    out[k] = 0b0101_0000; // 01 N T with T=1 (static name reference), 4-bit prefix for name index
    const nk = encPref(0, out[k..], 4); // static index 0 = :authority
    k += nk;
    var vb_auth: [32]u8 = .{0} ** 32;
    vb_auth[0] = 0; // H=0
    const vk_auth = encPref(host.len, vb_auth[0..], 7);
    if (out.len < k + vk_auth) return null;
    @memcpy(out[k .. k + vk_auth], vb_auth[0..vk_auth]);
    k += vk_auth;
    if (out.len < k + host.len) return null;
    @memcpy(out[k .. k + host.len], host);
    k += host.len;
    // :path "/" or literal
    if (std.mem.eql(u8, path, "/")) {
        k += encodeIndexedStatic(1, out[k..]);
    } else {
        if (out.len < k + 1) return null;
        out[k] = 0b0101_0000; // literal with static name reference
        const nk2 = encPref(1, out[k..], 4); // static index 1 = :path
        k += nk2;
        var vb: [16]u8 = .{0} ** 16;
        vb[0] = 0; // H=0
        const vk = encPref(path.len, vb[0..], 7);
        if (out.len < k + vk) return null;
        @memcpy(out[k .. k + vk], vb[0..vk]);
        k += vk;
        if (out.len < k + path.len) return null;
        @memcpy(out[k .. k + path.len], path);
        k += path.len;
    }
    return k;
}

/// Build an HTTP/3 HEADERS frame carrying a simple GET header block.
pub fn buildRequestFrame(host: []const u8, path: []const u8, out: []u8) ?usize {
    var hdrs: [512]u8 = undefined;
    const hb = buildSimpleGetHeaders(host, path, hdrs[0..]) orelse return null;
    var k: usize = 0;
    k += encodeVarint(0x01, out[k..]);
    k += encodeVarint(hb, out[k..]);
    if (out.len < k + hb) return null;
    @memcpy(out[k .. k + hb], hdrs[0..hb]);
    k += hb;
    return k;
}

fn writeAll(ep: *api.QuicEndpoint, conn: *api.QuicConnection, sid: u64, data: []const u8) void {
    var off: usize = 0;
    while (off < data.len) {
        const n = api.writeStream(conn, sid, data[off..], false) catch 0;
        if (n == 0) {
            api.poll(ep, 1) catch {};
        } else {
            off += n;
        }
    }
}

fn writeFin(ep: *api.QuicEndpoint, conn: *api.QuicConnection, sid: u64) void {
    var spins: usize = 0;
    while (spins < 2048) : (spins += 1) {
        _ = api.writeStream(conn, sid, &[_]u8{}, true) catch |err| switch (err) {
            error.WouldBlock, error.FlowControlBlocked, error.OutOfStreams, error.KeysNotReady => {
                api.poll(ep, 1) catch {};
                continue;
            },
            error.StreamStopped => return,
            else => return,
        };
        return;
    }
}

/// Perform a minimal HTTP/3 GET over an existing QUIC connection and copy response body into out.
pub fn h3Get(ep: *api.QuicEndpoint, conn: *api.QuicConnection, host: []const u8, path: []const u8, out: []u8) !usize {
    var t: [16]u8 = undefined;
    var n: usize = 0;
    if (api.openUni(conn)) |sid| {
        // Control stream: type=0x00 followed by SETTINGS frame (id=0x04, len=0).
        n = encodeVarint(0x00, t[0..]);
        n += encodeVarint(0x04, t[n..]);
        n += encodeVarint(0x00, t[n..]);
        writeAll(ep, conn, sid, t[0..n]);
    } else |_| {}
    if (api.openUni(conn)) |sid| {
        n = encodeVarint(0x02, t[0..]);
        writeAll(ep, conn, sid, t[0..n]);
    } else |_| {}
    if (api.openUni(conn)) |sid| {
        n = encodeVarint(0x03, t[0..]);
        writeAll(ep, conn, sid, t[0..n]);
    } else |_| {}
    // Ensure control and QPACK stream prefaces are flushed before the request stream.
    api.flush(ep, 5);
    var settle: usize = 0;
    while (settle < 32) : (settle += 1) {
        api.poll(ep, 1) catch {};
    }

    const stream_id = try api.openStream(conn, true);
    var req: [512]u8 = undefined;
    const rn = buildRequestFrame(host, path, req[0..]) orelse return error.BuildRequestFailed;
    writeAll(ep, conn, stream_id, req[0..rn]);
    writeFin(ep, conn, stream_id);

    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.heap.page_allocator);
    var tmp: [2048]u8 = undefined;
    var idle_spins: usize = 0;
    while (idle_spins < 20_000) {
        const r = api.readStream(conn, stream_id, tmp[0..]) catch 0;
        if (r > 0) {
            _ = buf.appendSlice(std.heap.page_allocator, tmp[0..r]) catch {};
            idle_spins = 0;
            continue;
        }
        if (api.isStreamFinished(conn, stream_id)) {
            break;
        }
        api.poll(ep, 1) catch {};
        idle_spins += 1;
    }
    while (true) {
        const r = api.readStream(conn, stream_id, tmp[0..]) catch 0;
        if (r == 0) break;
        _ = buf.appendSlice(std.heap.page_allocator, tmp[0..r]) catch {};
    }
    const bytes = buf.toOwnedSlice(std.heap.page_allocator) catch try std.heap.page_allocator.dupe(u8, &[_]u8{});
    defer std.heap.page_allocator.free(bytes);
    if (bytes.len == 0) return 0;

    var off2: usize = 0;
    var copied: usize = 0;
    var parse_error: bool = false;
    while (off2 < bytes.len) {
        const typ = decodeVarint(bytes, &off2) orelse {
            parse_error = true;
            break;
        };
        const flen = decodeVarint(bytes, &off2) orelse {
            parse_error = true;
            break;
        };
        const end = off2 + @as(usize, @intCast(flen));
        if (end > bytes.len) {
            parse_error = true;
            break;
        }

        if (typ == 0x00 and copied < out.len) {
            const to_copy = @min(out.len - copied, @as(usize, @intCast(flen)));
            @memcpy(out[copied .. copied + to_copy], bytes[off2 .. off2 + to_copy]);
            copied += to_copy;
        }
        off2 = end;
    }

    if (copied > 0) return copied;
    if (parse_error) return error.ParseFailed;
    return 0;
}
