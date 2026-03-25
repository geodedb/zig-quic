// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const api = @import("quic_api");
const h3v = @import("h3_varint");

// Re-export for any external consumers.
pub const encodeVarint = h3v.encodeVarint;

const decodeVarint = h3v.decodeVarint;
const encodeIndexedStatic = h3v.encodeIndexedStatic;
const encPref = h3v.encPref;

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
    } else |err| {
        std.debug.print("[h3] failed to open control stream: {}\n", .{err});
    }
    if (api.openUni(conn)) |sid| {
        n = encodeVarint(0x02, t[0..]);
        writeAll(ep, conn, sid, t[0..n]);
    } else |err| {
        std.debug.print("[h3] failed to open QPACK encoder stream: {}\n", .{err});
    }
    if (api.openUni(conn)) |sid| {
        n = encodeVarint(0x03, t[0..]);
        writeAll(ep, conn, sid, t[0..n]);
    } else |err| {
        std.debug.print("[h3] failed to open QPACK decoder stream: {}\n", .{err});
    }
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
            buf.appendSlice(std.heap.page_allocator, tmp[0..r]) catch |err| {
                std.debug.print("[h3] appendSlice failed: {}\n", .{err});
                return error.OutOfMemory;
            };
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
        buf.appendSlice(std.heap.page_allocator, tmp[0..r]) catch |err| {
            std.debug.print("[h3] appendSlice failed: {}\n", .{err});
            return error.OutOfMemory;
        };
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
