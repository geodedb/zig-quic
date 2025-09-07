const std = @import("std");
const api = @import("quic_api");

pub const H3Server = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) H3Server {
        return .{ .allocator = allocator };
    }

    pub fn serveConnection(self: *H3Server, ep: *api.QuicEndpoint, conn: *api.QuicConnection) void {
        _ = self;
        // Control stream
        const ctrl = api.openUni(conn) catch return;
        var ctrl_buf: [24]u8 = undefined;
        var i: usize = 0;
        i += encodeVarint(0x00, ctrl_buf[i..]); // uni stream type: control
        i += encodeVarint(0x04, ctrl_buf[i..]); // SETTINGS
        i += encodeVarint(0, ctrl_buf[i..]);    // len=0
        _ = api.writeStream(conn, ctrl, ctrl_buf[0..i]) catch {};
        // QPACK encoder/decoder streams
        if (api.openUni(conn)) |sid| {
            var t: [1]u8 = .{0};
            _ = api.writeStream(conn, sid, t[0..encodeVarint(0x02, t[0..])]) catch {};
        } else |_| {}
        if (api.openUni(conn)) |sid| {
            var t: [1]u8 = .{0};
            _ = api.writeStream(conn, sid, t[0..encodeVarint(0x03, t[0..])]) catch {};
        } else |_| {}
        // Event loop: serve each bidi request once
        var tmp: [4096]u8 = undefined;
        var served: [64]u64 = .{0} ** 64;
        var served_len: usize = 0;
        var spins: usize = 0;
        while (spins < 4000) : (spins += 1) {
            api.poll(ep, 2) catch {};
            const got = readAny(conn, tmp[0..]) catch null;
            if (got) |pair| {
                var already: bool = false;
                var j: usize = 0;
                while (j < served_len) : (j += 1) {
                    if (served[j] == pair.id) { already = true; break; }
                }
                if (already) continue;
                served[served_len] = pair.id;
                served_len += 1;
                const path = parsePathFromHeadersFrame(tmp[0..pair.n]) orelse "/index.html";
                respondFile(ep, conn, pair.id, path) catch {};
            }
        }
    }

    fn respondFile(ep: *api.QuicEndpoint, conn: *api.QuicConnection, stream_id: u64, path: []const u8) !void {
        var hdr: [64]u8 = undefined;
        const qpack_len = encodeQpackStatus200WithContentType(hdr[0..]);
        var head: [40]u8 = undefined;
        var n: usize = 0;
        n += encodeVarint(0x01, head[n..]); // HEADERS
        n += encodeVarint(qpack_len, head[n..]);
        try writeAll(ep, conn, stream_id, head[0..n]);
        try writeAll(ep, conn, stream_id, hdr[0..qpack_len]);
        var file_bytes: []u8 = &[_]u8{};
        defer if (file_bytes.len > 0) std.heap.page_allocator.free(file_bytes);
        var full_path_buf: [512]u8 = undefined;
        var path_s = path;
        if (path_s.len == 0 or path_s[0] != '/') path_s = "/index.html";
        const full = std.fmt.bufPrint(&full_path_buf, "/www{s}", .{path_s}) catch "/www/index.html";
        if (std.fs.cwd().openFile(full, .{})) |f| {
            defer f.close();
            const sz = f.getEndPos() catch 0;
            if (sz > 0 and sz <= 4 * 1024 * 1024) {
                file_bytes = try std.heap.page_allocator.alloc(u8, @intCast(sz));
                const r = f.readAll(file_bytes) catch 0;
                file_bytes = file_bytes[0..r];
            }
        } else |_| {}
        var data_head: [24]u8 = undefined;
        var dn: usize = 0;
        dn += encodeVarint(0x00, data_head[dn..]); // DATA
        dn += encodeVarint(file_bytes.len, data_head[dn..]);
        try writeAll(ep, conn, stream_id, data_head[0..dn]);
        if (file_bytes.len > 0) try writeAll(ep, conn, stream_id, file_bytes);
        _ = api.closeStream(conn, stream_id, 0) catch {};
        api.flush(ep, 5);
    }

    fn encodeQpackStatus200WithContentType(out: []u8) usize {
        var k: usize = 0;
        if (out.len < 2) return 0;
        out[k] = 0; k += 1; // RIC
        out[k] = 0; k += 1; // Base
        // :status 200 (static idx 25)
        k += encodeIndexedStatic(25, out[k..]);
        // content-type: text/html; charset=utf-8 (static idx 52)
        k += encodeIndexedStatic(52, out[k..]);
        return k;
    }

    fn encodeIndexedStatic(index: u64, out: []u8) usize {
        if (out.len == 0) return 0;
        out[0] = 0b1100_0000; // 1 T prefix, T=1 static
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

    fn writeAll(ep: *api.QuicEndpoint, conn: *api.QuicConnection, sid: u64, data: []const u8) !void {
        var off: usize = 0;
        while (off < data.len) {
            const n = api.writeStream(conn, sid, data[off..]) catch 0;
            if (n == 0) {
                api.poll(ep, 1) catch {};
            } else {
                off += n;
            }
        }
    }

    fn readAny(conn: *api.QuicConnection, buf: []u8) !?struct { id: u64, n: usize } {
        const c: *@import("quic_conn").Connection = @ptrCast(@alignCast(conn));
        const res = c.readAnyStream(buf) catch |e| return e;
        return .{ .id = res.id, .n = res.n };
    }

    fn encodeVarint(v: u64, out: []u8) usize {
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

    pub fn parsePathFromHeadersFrame(data: []const u8) ?[]const u8 {
        var off: usize = 0;
        const t = decodeVarint(data, &off) orelse return null;
        if (t != 0x01) return null; // HEADERS
        const l = decodeVarint(data, &off) orelse return null;
        const end = off + @as(usize, @intCast(l));
        if (end > data.len) return null;
        return parsePathFromHeaders(data[off..end]);
    }

    pub fn parsePathFromHeaders(h: []const u8) ?[]const u8 {
        var off: usize = 0;
        _ = decodeVarint(h, &off) orelse return null; // RIC
        _ = decodeVarint(h, &off) orelse return null; // Base
        while (off < h.len) {
            const b = h[off];
            // Literal Field Line with Name Reference (01NT...)
            if ((b & 0b1100_0000) == 0b0100_0000) {
                const t_bit = (b & 0b0001_0000) != 0;
                off += 1;
                const name_index = decodePrefixedInt(h, &off, 4) orelse return null;
                if (t_bit and name_index == 1) {
                    // value string literal (8-bit prefix)
                    const hv = h[off];
                    const huff = (hv & 0x80) != 0;
                    var vlen_off = off;
                    const vlen = decodePrefixedInt(h, &vlen_off, 7) orelse return null;
                    off = vlen_off;
                    if (off + vlen > h.len) return null;
                    if (huff) return null; // TODO: Huffman decode if necessary
                    return h[off .. off + vlen];
                } else {
                    // Skip value literal
                    var vlen_off2 = off;
                    const vlen2 = decodePrefixedInt(h, &vlen_off2, 7) orelse return null;
                    off = vlen_off2 + @as(usize, @intCast(vlen2));
                    continue;
                }
            } else if ((b & 0b1111_0000) == 0b0001_0000) {
                // Indexed Field Line (T + index(6+)) — ignore
                off += 1;
                _ = decodePrefixedInt(h, &off, 6) orelse return null;
                continue;
            } else {
                break;
            }
        }
        return null;
    }

    fn decodeVarint(h: []const u8, off: *usize) ?u64 {
        if (off.* >= h.len) return null;
        const first = h[off.*];
        const prefix = first >> 6;
        const len: usize = switch (prefix) { 0 => 1, 1 => 2, 2 => 4, else => 8 };
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

    fn decodePrefixedInt(h: []const u8, off: *usize, prefix_bits: u4) ?u64 {
        if (off.* >= h.len) return null;
        const ShiftAmt = std.math.Log2Int(u8);
        const sh: ShiftAmt = @intCast(@as(u8, 8) - @as(u8, prefix_bits));
        const mask: u8 = (@as(u8, 1) << sh) - 1;
        var val: u64 = (h[off.*] & mask);
        var consumed: usize = 1;
        if (val == mask) {
            var m: u6 = 0;
            while (true) {
                if (off.* + consumed >= h.len) return null;
                const b = h[off.* + consumed];
                consumed += 1;
                val += (@as(u64, b & 0x7f)) << @as(u6, m);
                if ((b & 0x80) == 0) break;
                m += 7;
                if (m > 56) return null;
            }
        }
        off.* += consumed;
        return val;
    }
};
