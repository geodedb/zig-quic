// MIT License
// QUIC frame codec (subset) used by tests and initial handshake
const std = @import("std");
const varint = @import("quic_varint");

/// Known QUIC frame type bytes (subset).
pub const FrameType = enum(u8) {
    PADDING = 0x00,
    PING = 0x01,
    ACK = 0x02,
    RESET_STREAM = 0x04,
    STOP_SENDING = 0x05,
    CRYPTO = 0x06,
    NEW_TOKEN = 0x07,
    STREAM = 0x08, // 0x08-0x0f with flags
    MAX_DATA = 0x10,
    MAX_STREAM_DATA = 0x11,
    MAX_STREAMS_BIDI = 0x12,
    MAX_STREAMS_UNI = 0x13,
    DATA_BLOCKED = 0x14,
    STREAM_DATA_BLOCKED = 0x15,
    STREAMS_BLOCKED_BIDI = 0x16,
    STREAMS_BLOCKED_UNI = 0x17,
    NEW_CONNECTION_ID = 0x18,
    RETIRE_CONNECTION_ID = 0x19,
    PATH_CHALLENGE = 0x1a,
    PATH_RESPONSE = 0x1b,
    CONNECTION_CLOSE = 0x1c,
    HANDSHAKE_DONE = 0x1e,
    DATAGRAM = 0x30, // RFC 9221 (optional)
};

/// Ack range element used inside ACK frames (gap,len VarInts).
pub const AckRange = struct { gap: u64, len: u64 };

/// Frame union with encode helper for a subset used in tests/tools.
pub const Frame = union(enum) {
    padding: usize,
    ping: void,
    crypto: struct { offset: u64, data: []const u8 },
    stream: struct { stream_id: u64, offset: ?u64, fin: bool, data: []const u8 },
    ack: struct { largest: u64, ack_delay: u64, first_range: u64 = 0, ranges: []const AckRange = &[_]AckRange{} },
    datagram: struct { data: []const u8 },
    max_data: struct { max: u64 },
    max_stream_data: struct { stream_id: u64, max: u64 },
    max_streams_bidi: struct { max: u64 },
    max_streams_uni: struct { max: u64 },
    data_blocked: struct { limit: u64 },
    stream_data_blocked: struct { stream_id: u64, limit: u64 },
    streams_blocked_bidi: struct { max: u64 },
    streams_blocked_uni: struct { max: u64 },
    path_challenge: [8]u8,
    path_response: [8]u8,
    // NEW: server-issued token for future connections (1-RTT only)
    new_token: struct { token: []const u8 },
    // NEW: handshake done signal (server -> client, 1-RTT only)
    handshake_done: void,
    // NEW: transport CONNECTION_CLOSE (subset: transport close only, no application close here)
    connection_close: struct { error_code: u64, frame_type: u64 = 0, reason: []const u8 = &[_]u8{} },
    // ... more frames as needed ...

    /// Encode this frame to the writer. Returns bytes written.
    pub fn write(self: Frame, w: anytype) !usize {
        switch (self) {
            .padding => |count| {
                if (count == 0) return 0;
                var n: usize = 0;
                try w.writeByte(@intFromEnum(FrameType.PADDING));
                n += 1;
                var i: usize = 1;
                while (i < count) : (i += 1) {
                    try w.writeByte(@intFromEnum(FrameType.PADDING));
                    n += 1;
                }
                return n;
            },
            .ping => {
                try w.writeByte(@intFromEnum(FrameType.PING));
                return 1;
            },
            .crypto => |c| {
                try w.writeByte(@intFromEnum(FrameType.CRYPTO));
                var written: usize = 1;
                var tmp: [16]u8 = undefined;
                const off_len = try varint.encode(c.offset, &tmp);
                try w.writeAll(tmp[0..off_len]);
                written += off_len;
                const len_len = try varint.encode(c.data.len, &tmp);
                try w.writeAll(tmp[0..len_len]);
                written += len_len;
                try w.writeAll(c.data);
                written += c.data.len;
                return written;
            },
            .stream => |s| {
                const OFF: u8 = 0x04;
                const LEN: u8 = 0x02;
                const FIN: u8 = 0x01;
                var ty: u8 = @intFromEnum(FrameType.STREAM);
                if (s.offset != null) ty |= OFF;
                ty |= LEN;
                if (s.fin) ty |= FIN;
                try w.writeByte(ty);
                var written: usize = 1;
                var tmp: [16]u8 = undefined;
                // stream id
                const sid_len = try varint.encode(s.stream_id, &tmp);
                try w.writeAll(tmp[0..sid_len]);
                written += sid_len;
                // offset if present
                if (s.offset) |offv| {
                    const off_len = try varint.encode(offv, &tmp);
                    try w.writeAll(tmp[0..off_len]);
                    written += off_len;
                }
                // length is always present when LEN bit set
                const dl = try varint.encode(s.data.len, &tmp);
                try w.writeAll(tmp[0..dl]);
                written += dl;
                // data
                try w.writeAll(s.data);
                written += s.data.len;
                return written;
            },
            .ack => |a| {
                try w.writeByte(@intFromEnum(FrameType.ACK));
                var written: usize = 1;
                var tmp: [16]u8 = undefined;
                const la = try varint.encode(a.largest, &tmp);
                try w.writeAll(tmp[0..la]);
                written += la;
                const ad = try varint.encode(a.ack_delay, &tmp);
                try w.writeAll(tmp[0..ad]);
                written += ad;
                const rc_val: u64 = @intCast(a.ranges.len);
                const rc = try varint.encode(rc_val, &tmp);
                try w.writeAll(tmp[0..rc]);
                written += rc;
                const fr = try varint.encode(a.first_range, &tmp);
                try w.writeAll(tmp[0..fr]);
                written += fr;
                // additional ranges: each (gap, len)
                for (a.ranges) |r| {
                    const g = try varint.encode(r.gap, &tmp);
                    try w.writeAll(tmp[0..g]);
                    written += g;
                    const rl = try varint.encode(r.len, &tmp);
                    try w.writeAll(tmp[0..rl]);
                    written += rl;
                }
                return written;
            },
            .datagram => |d| {
                try w.writeByte(@intFromEnum(FrameType.DATAGRAM));
                var written: usize = 1;
                var tmp: [16]u8 = undefined;
                const dl = try varint.encode(d.data.len, &tmp);
                try w.writeAll(tmp[0..dl]);
                written += dl;
                try w.writeAll(d.data);
                written += d.data.len;
                return written;
            },
            .max_data => |m| {
                try w.writeByte(@intFromEnum(FrameType.MAX_DATA));
                var tmp: [16]u8 = undefined;
                const ml = try varint.encode(m.max, &tmp);
                try w.writeAll(tmp[0..ml]);
                return 1 + ml;
            },
            .max_stream_data => |m| {
                try w.writeByte(@intFromEnum(FrameType.MAX_STREAM_DATA));
                var tmp: [24]u8 = undefined;
                const idl = try varint.encode(m.stream_id, tmp[0..16]);
                const ml = try varint.encode(m.max, tmp[idl..]);
                try w.writeAll(tmp[0 .. idl + ml]);
                return 1 + idl + ml;
            },
            .max_streams_bidi => |m| {
                try w.writeByte(@intFromEnum(FrameType.MAX_STREAMS_BIDI));
                var tmp: [16]u8 = undefined;
                const ml = try varint.encode(m.max, &tmp);
                try w.writeAll(tmp[0..ml]);
                return 1 + ml;
            },
            .max_streams_uni => |m| {
                try w.writeByte(@intFromEnum(FrameType.MAX_STREAMS_UNI));
                var tmp: [16]u8 = undefined;
                const ml = try varint.encode(m.max, &tmp);
                try w.writeAll(tmp[0..ml]);
                return 1 + ml;
            },
            .data_blocked => |m| {
                try w.writeByte(@intFromEnum(FrameType.DATA_BLOCKED));
                var tmp: [16]u8 = undefined;
                const ml = try varint.encode(m.limit, &tmp);
                try w.writeAll(tmp[0..ml]);
                return 1 + ml;
            },
            .stream_data_blocked => |m| {
                try w.writeByte(@intFromEnum(FrameType.STREAM_DATA_BLOCKED));
                var tmp: [24]u8 = undefined;
                const idl = try varint.encode(m.stream_id, tmp[0..16]);
                const ml = try varint.encode(m.limit, tmp[idl..]);
                try w.writeAll(tmp[0 .. idl + ml]);
                return 1 + idl + ml;
            },
            .streams_blocked_bidi => |m| {
                try w.writeByte(@intFromEnum(FrameType.STREAMS_BLOCKED_BIDI));
                var tmp: [16]u8 = undefined;
                const ml = try varint.encode(m.max, &tmp);
                try w.writeAll(tmp[0..ml]);
                return 1 + ml;
            },
            .streams_blocked_uni => |m| {
                try w.writeByte(@intFromEnum(FrameType.STREAMS_BLOCKED_UNI));
                var tmp: [16]u8 = undefined;
                const ml = try varint.encode(m.max, &tmp);
                try w.writeAll(tmp[0..ml]);
                return 1 + ml;
            },
            .path_challenge => |v| {
                try w.writeByte(@intFromEnum(FrameType.PATH_CHALLENGE));
                try w.writeAll(&v);
                return 1 + 8;
            },
            .path_response => |v| {
                try w.writeByte(@intFromEnum(FrameType.PATH_RESPONSE));
                try w.writeAll(&v);
                return 1 + 8;
            },
            .new_token => |nt| {
                try w.writeByte(@intFromEnum(FrameType.NEW_TOKEN));
                var tmp: [16]u8 = undefined;
                const tl = try varint.encode(nt.token.len, &tmp);
                try w.writeAll(tmp[0..tl]);
                try w.writeAll(nt.token);
                return 1 + tl + nt.token.len;
            },
            .handshake_done => {
                try w.writeByte(@intFromEnum(FrameType.HANDSHAKE_DONE));
                return 1;
            },
            .connection_close => |cc| {
                try w.writeByte(@intFromEnum(FrameType.CONNECTION_CLOSE));
                var written: usize = 1;
                var tmp: [32]u8 = undefined;
                const el = try varint.encode(cc.error_code, &tmp);
                try w.writeAll(tmp[0..el]);
                written += el;
                const ft = try varint.encode(cc.frame_type, &tmp);
                try w.writeAll(tmp[0..ft]);
                written += ft;
                const rl = try varint.encode(cc.reason.len, &tmp);
                try w.writeAll(tmp[0..rl]);
                written += rl;
                if (cc.reason.len > 0) {
                    try w.writeAll(cc.reason);
                    written += cc.reason.len;
                }
                return written;
            },
        }
    }
};

/// Placeholder for a future streaming encoder API.
pub fn encode(frame: Frame, w: anytype) !void {
    _ = frame;
    _ = w;
    return error.NotImplemented;
}

/// Placeholder for a future streaming decoder API.
pub fn decode(r: anytype, alloc: std.mem.Allocator) !Frame {
    _ = r;
    _ = alloc;
    return error.NotImplemented;
}

/// Decode one frame from the front of `buf`, returning the frame and bytes consumed.
pub fn decodeOne(buf: []const u8) !struct { f: Frame, n: usize } {
    if (buf.len == 0) return error.Truncated;
    const t = buf[0];
    // PADDING may repeat; collapse contiguous run into a single padding frame
    if (t == @intFromEnum(FrameType.PADDING)) {
        var i: usize = 0;
        while (i < buf.len and buf[i] == @intFromEnum(FrameType.PADDING)) : (i += 1) {}
        return .{ .f = Frame{ .padding = i }, .n = i };
    }
    if (t == @intFromEnum(FrameType.PING)) {
        return .{ .f = Frame{ .ping = {} }, .n = 1 };
    }
    if (t == @intFromEnum(FrameType.CRYPTO)) {
        var i: usize = 1;
        const off_dec = try varint.decode(buf[i..]);
        i += off_dec.n;
        const len_dec = try varint.decode(buf[i..]);
        i += len_dec.n;
        const need: usize = i + @as(usize, len_dec.value);
        if (need > buf.len) return error.Truncated;
        const data = buf[i..need];
        return .{ .f = Frame{ .crypto = .{ .offset = off_dec.value, .data = data } }, .n = need };
    }
    // Minimal ACK (no ranges)
    if (t == @intFromEnum(FrameType.ACK)) {
        var i: usize = 1;
        const largest = try varint.decode(buf[i..]);
        i += largest.n;
        const ack_delay = try varint.decode(buf[i..]);
        i += ack_delay.n;
        const range_count = try varint.decode(buf[i..]);
        i += range_count.n;
        const first_range = try varint.decode(buf[i..]);
        i += first_range.n;
        // Skip any additional ack ranges if present (gap,len pairs)
        var rc_left: u64 = range_count.value;
        while (rc_left > 0) : (rc_left -= 1) {
            const gap = try varint.decode(buf[i..]);
            i += gap.n;
            const lenv = try varint.decode(buf[i..]);
            i += lenv.n;
            if (i > buf.len) return error.Truncated;
        }
        return .{ .f = Frame{ .ack = .{ .largest = largest.value, .ack_delay = ack_delay.value, .first_range = first_range.value, .ranges = &[_]AckRange{} } }, .n = i };
    }
    // STREAM frames 0x08..0x0f
    if ((t & 0xf8) == @intFromEnum(FrameType.STREAM)) {
        const OFF: u8 = 0x04;
        const LEN: u8 = 0x02;
        const FIN: u8 = 0x01;
        const has_off = (t & OFF) != 0;
        const has_len = (t & LEN) != 0;
        const fin = (t & FIN) != 0;
        var i: usize = 1;
        const id_dec = try varint.decode(buf[i..]);
        i += id_dec.n;
        var off_val: ?u64 = null;
        if (has_off) {
            const off_dec = try varint.decode(buf[i..]);
            i += off_dec.n;
            off_val = off_dec.value;
        }
        var data_len: usize = 0;
        if (has_len) {
            const dl = try varint.decode(buf[i..]);
            i += dl.n;
            data_len = @intCast(dl.value);
            if (i + data_len > buf.len) return error.Truncated;
            const data = buf[i .. i + data_len];
            return .{ .f = Frame{ .stream = .{ .stream_id = id_dec.value, .offset = off_val, .fin = fin, .data = data } }, .n = i + data_len };
        } else {
            // Until end of packet
            const data = buf[i..];
            return .{ .f = Frame{ .stream = .{ .stream_id = id_dec.value, .offset = off_val, .fin = fin, .data = data } }, .n = buf.len };
        }
    }
    // DATAGRAM (length-prefixed variant)
    if (t == @intFromEnum(FrameType.DATAGRAM)) {
        var i: usize = 1;
        const dl = try varint.decode(buf[i..]);
        i += dl.n;
        const nbytes: usize = @intCast(dl.value);
        if (i + nbytes > buf.len) return error.Truncated;
        const data = buf[i .. i + nbytes];
        return .{ .f = Frame{ .datagram = .{ .data = data } }, .n = i + nbytes };
    }
    // Flow control and blocked frames
    if (t == @intFromEnum(FrameType.MAX_DATA)) {
        var i: usize = 1;
        const max = try varint.decode(buf[i..]);
        i += max.n;
        return .{ .f = Frame{ .max_data = .{ .max = max.value } }, .n = i };
    }
    if (t == @intFromEnum(FrameType.MAX_STREAM_DATA)) {
        var i: usize = 1;
        const sid = try varint.decode(buf[i..]);
        i += sid.n;
        const max = try varint.decode(buf[i..]);
        i += max.n;
        return .{ .f = Frame{ .max_stream_data = .{ .stream_id = sid.value, .max = max.value } }, .n = i };
    }
    if (t == @intFromEnum(FrameType.MAX_STREAMS_BIDI)) {
        var i: usize = 1;
        const max = try varint.decode(buf[i..]);
        i += max.n;
        return .{ .f = Frame{ .max_streams_bidi = .{ .max = max.value } }, .n = i };
    }
    if (t == @intFromEnum(FrameType.MAX_STREAMS_UNI)) {
        var i: usize = 1;
        const max = try varint.decode(buf[i..]);
        i += max.n;
        return .{ .f = Frame{ .streams_blocked_uni = .{ .max = max.value } }, .n = i };
    }
    if (t == @intFromEnum(FrameType.DATA_BLOCKED)) {
        var i: usize = 1;
        const lim = try varint.decode(buf[i..]);
        i += lim.n;
        return .{ .f = Frame{ .data_blocked = .{ .limit = lim.value } }, .n = i };
    }
    if (t == @intFromEnum(FrameType.STREAM_DATA_BLOCKED)) {
        var i: usize = 1;
        const sid = try varint.decode(buf[i..]);
        i += sid.n;
        const lim = try varint.decode(buf[i..]);
        i += lim.n;
        return .{ .f = Frame{ .stream_data_blocked = .{ .stream_id = sid.value, .limit = lim.value } }, .n = i };
    }
    if (t == @intFromEnum(FrameType.STREAMS_BLOCKED_BIDI)) {
        var i: usize = 1;
        const max = try varint.decode(buf[i..]);
        i += max.n;
        return .{ .f = Frame{ .streams_blocked_bidi = .{ .max = max.value } }, .n = i };
    }
    if (t == @intFromEnum(FrameType.STREAMS_BLOCKED_UNI)) {
        var i: usize = 1;
        const max = try varint.decode(buf[i..]);
        i += max.n;
        return .{ .f = Frame{ .streams_blocked_uni = .{ .max = max.value } }, .n = i };
    }
    if (t == @intFromEnum(FrameType.PATH_CHALLENGE)) {
        if (buf.len < 1 + 8) return error.Truncated;
        var data8: [8]u8 = undefined;
        @memcpy(&data8, buf[1 .. 1 + 8]);
        return .{ .f = Frame{ .path_challenge = data8 }, .n = 1 + 8 };
    }
    if (t == @intFromEnum(FrameType.PATH_RESPONSE)) {
        if (buf.len < 1 + 8) return error.Truncated;
        var data8: [8]u8 = undefined;
        @memcpy(&data8, buf[1 .. 1 + 8]);
        return .{ .f = Frame{ .path_response = data8 }, .n = 1 + 8 };
    }
    if (t == @intFromEnum(FrameType.NEW_TOKEN)) {
        var i: usize = 1;
        const dl = try varint.decode(buf[i..]);
        i += dl.n;
        const nbytes: usize = @intCast(dl.value);
        if (i + nbytes > buf.len) return error.Truncated;
        const tok = buf[i .. i + nbytes];
        return .{ .f = Frame{ .new_token = .{ .token = tok } }, .n = i + nbytes };
    }
    if (t == @intFromEnum(FrameType.HANDSHAKE_DONE)) {
        return .{ .f = Frame{ .handshake_done = {} }, .n = 1 };
    }
    if (t == @intFromEnum(FrameType.CONNECTION_CLOSE)) {
        var i: usize = 1;
        const ec = try varint.decode(buf[i..]);
        i += ec.n;
        const ft = try varint.decode(buf[i..]);
        i += ft.n;
        const rl = try varint.decode(buf[i..]);
        i += rl.n;
        if (i + rl.value > buf.len) return error.Truncated;
        const reason = buf[i .. i + @as(usize, rl.value)];
        i += @as(usize, rl.value);
        return .{ .f = Frame{ .connection_close = .{ .error_code = ec.value, .frame_type = ft.value, .reason = reason } }, .n = i };
    }
    // Minimal support for now
    return error.Unsupported;
}

/// Compatibility wrapper for existing tests: parse returns { frame, n }.
pub fn parse(buf: []const u8) !struct { frame: Frame, n: usize } {
    const r = try decodeOne(buf);
    return .{ .frame = r.f, .n = r.n };
}
