// MIT License
// QUIC frame codec (subset) used by tests and initial handshake
const std = @import("std");
const varint = @import("quic_varint");

/// Known QUIC frame type bytes (subset).
pub const FrameType = enum(u8) {
    PADDING = 0x00,
    PING = 0x01,
    ACK = 0x02,
    ACK_ECN = 0x03,
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
/// ECN counters carried by ACK_ECN (RFC 9000 §19.3.2)
pub const EcnCounts = struct { ect0: u64, ect1: u64, ce: u64 };

/// Frame union with encode helper for a subset used in tests/tools.
pub const Frame = union(enum) {
    padding: usize,
    ping: void,
    crypto: struct { offset: u64, data: []const u8 },
    stream: struct { stream_id: u64, offset: ?u64, fin: bool, data: []const u8 },
    // NEW_CONNECTION_ID per RFC 9000 §19.15
    new_connection_id: struct {
        sequence: u64,
        retire_prior_to: u64,
        connection_id: []const u8,
        stateless_reset_token: [16]u8,
    },
    // RETIRE_CONNECTION_ID per RFC 9000 §19.16
    retire_connection_id: struct { sequence: u64 },
    ack: struct {
        largest: u64,
        ack_delay: u64,
        first_range: u64 = 0,
        ranges: []const AckRange = &[_]AckRange{},
        // When present, encode as ACK_ECN (0x03) and append ECT0/ECT1/CE counts
        ecn: ?EcnCounts = null,
        // Internal storage for parsed ranges (decodeOne fills this and points ranges to it)
        ranges_buf: [16]AckRange = undefined,
        ranges_len: usize = 0,
    },
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
    // NEW: stop sending (peer requests sender to stop), and reset stream (sender aborts stream)
    stop_sending: struct { stream_id: u64, error_code: u64 },
    reset_stream: struct { stream_id: u64, error_code: u64, final_size: u64 },
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
            .new_connection_id => |ncid| {
                try w.writeByte(@intFromEnum(FrameType.NEW_CONNECTION_ID));
                var written: usize = 1;
                var tmp: [32]u8 = undefined;
                const sl = try varint.encode(ncid.sequence, tmp[0..16]);
                try w.writeAll(tmp[0..sl]);
                written += sl;
                const rpl = try varint.encode(ncid.retire_prior_to, tmp[0..16]);
                try w.writeAll(tmp[0..rpl]);
                written += rpl;
                // Connection ID length (1 byte)
                try w.writeByte(@as(u8, @intCast(ncid.connection_id.len)));
                written += 1;
                // Connection ID bytes
                try w.writeAll(ncid.connection_id);
                written += ncid.connection_id.len;
                // Stateless reset token (16 bytes)
                try w.writeAll(&ncid.stateless_reset_token);
                written += 16;
                return written;
            },
            .retire_connection_id => |rc| {
                try w.writeByte(@intFromEnum(FrameType.RETIRE_CONNECTION_ID));
                var tmp: [16]u8 = undefined;
                const sl = try varint.encode(rc.sequence, &tmp);
                try w.writeAll(tmp[0..sl]);
                return 1 + sl;
            },
            .ack => |a| {
                // Choose type based on whether ECN counts are present
                const ty: u8 = if (a.ecn != null) @intFromEnum(FrameType.ACK_ECN) else @intFromEnum(FrameType.ACK);
                try w.writeByte(ty);
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
                // Optional ECN counts (when ACK_ECN)
                if (a.ecn) |e| {
                    const e0 = try varint.encode(e.ect0, &tmp);
                    try w.writeAll(tmp[0..e0]);
                    written += e0;
                    const e1 = try varint.encode(e.ect1, &tmp);
                    try w.writeAll(tmp[0..e1]);
                    written += e1;
                    const ce = try varint.encode(e.ce, &tmp);
                    try w.writeAll(tmp[0..ce]);
                    written += ce;
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
            .stop_sending => |s| {
                try w.writeByte(@intFromEnum(FrameType.STOP_SENDING));
                var tmp: [32]u8 = undefined;
                const idl = try varint.encode(s.stream_id, tmp[0..16]);
                const el = try varint.encode(s.error_code, tmp[idl..]);
                try w.writeAll(tmp[0 .. idl + el]);
                return 1 + idl + el;
            },
            .reset_stream => |r| {
                try w.writeByte(@intFromEnum(FrameType.RESET_STREAM));
                var tmp: [48]u8 = undefined;
                const idl = try varint.encode(r.stream_id, tmp[0..16]);
                const el = try varint.encode(r.error_code, tmp[idl..]);
                const fl = try varint.encode(r.final_size, tmp[idl + el ..]);
                try w.writeAll(tmp[0 .. idl + el + fl]);
                return 1 + idl + el + fl;
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
        if (len_dec.value > @as(u64, buf.len - i)) return error.Truncated;
        const need: usize = i + @as(usize, @intCast(len_dec.value));
        const data = buf[i..need];
        return .{ .f = Frame{ .crypto = .{ .offset = off_dec.value, .data = data } }, .n = need };
    }
    // ACK / ACK_ECN (with ranges)
    if (t == @intFromEnum(FrameType.ACK) or t == @intFromEnum(FrameType.ACK_ECN)) {
        var i: usize = 1;
        const largest = try varint.decode(buf[i..]);
        i += largest.n;
        const ack_delay = try varint.decode(buf[i..]);
        i += ack_delay.n;
        const range_count = try varint.decode(buf[i..]);
        i += range_count.n;
        const first_range = try varint.decode(buf[i..]);
        i += first_range.n;
        // Parse additional ack ranges if present (gap,len pairs) up to a small fixed cap
        var ranges_buf: [16]AckRange = undefined;
        var out_len: usize = 0;
        var rc_left: u64 = range_count.value;
        while (rc_left > 0) : (rc_left -= 1) {
            const gap = try varint.decode(buf[i..]);
            i += gap.n;
            const lenv = try varint.decode(buf[i..]);
            i += lenv.n;
            if (i > buf.len) return error.Truncated;
            if (out_len < ranges_buf.len) {
                ranges_buf[out_len] = .{ .gap = gap.value, .len = lenv.value };
                out_len += 1;
            }
        }
        var ecn_counts: ?EcnCounts = null;
        if (t == @intFromEnum(FrameType.ACK_ECN)) {
            const ect0 = try varint.decode(buf[i..]);
            i += ect0.n;
            const ect1 = try varint.decode(buf[i..]);
            i += ect1.n;
            const ce = try varint.decode(buf[i..]);
            i += ce.n;
            ecn_counts = .{ .ect0 = ect0.value, .ect1 = ect1.value, .ce = ce.value };
        }
        // Build frame with embedded ranges buffer populated; point ranges slice to that storage.
        var ackf = Frame{
            .ack = .{
                .largest = largest.value,
                .ack_delay = ack_delay.value,
                .first_range = first_range.value,
                .ranges = &[_]AckRange{}, // temporary; will be replaced after copying
                .ecn = ecn_counts,
            },
        };
        // Copy into embedded buffer and expose as slice
        var j: usize = 0;
        while (j < out_len) : (j += 1) ackf.ack.ranges_buf[j] = ranges_buf[j];
        ackf.ack.ranges_len = out_len;
        ackf.ack.ranges = ackf.ack.ranges_buf[0..out_len];
        return .{ .f = ackf, .n = i };
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
            if (dl.value > @as(u64, buf.len - i)) return error.Truncated;
            data_len = @intCast(dl.value);
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
        if (dl.value > @as(u64, buf.len - i)) return error.Truncated;
        const nbytes: usize = @intCast(dl.value);
        const data = buf[i .. i + nbytes];
        return .{ .f = Frame{ .datagram = .{ .data = data } }, .n = i + nbytes };
    }
    if (t == @intFromEnum(FrameType.NEW_CONNECTION_ID)) {
        var i: usize = 1;
        const seq = try varint.decode(buf[i..]);
        i += seq.n;
        const rpto = try varint.decode(buf[i..]);
        i += rpto.n;
        if (i >= buf.len) return error.Truncated;
        const cid_len: usize = buf[i];
        i += 1;
        if (i + cid_len + 16 > buf.len) return error.Truncated;
        const cid = buf[i .. i + cid_len];
        i += cid_len;
        var tok: [16]u8 = undefined;
        @memcpy(&tok, buf[i .. i + 16]);
        i += 16;
        return .{ .f = Frame{ .new_connection_id = .{ .sequence = seq.value, .retire_prior_to = rpto.value, .connection_id = cid, .stateless_reset_token = tok } }, .n = i };
    }
    if (t == @intFromEnum(FrameType.RETIRE_CONNECTION_ID)) {
        var i: usize = 1;
        const seq = try varint.decode(buf[i..]);
        i += seq.n;
        return .{ .f = Frame{ .retire_connection_id = .{ .sequence = seq.value } }, .n = i };
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
        if (dl.value > @as(u64, buf.len - i)) return error.Truncated;
        const nbytes: usize = @intCast(dl.value);
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
        if (rl.value > @as(u64, buf.len - i)) return error.Truncated;
        const rlen: usize = @intCast(rl.value);
        const reason = buf[i .. i + rlen];
        i += rlen;
        return .{ .f = Frame{ .connection_close = .{ .error_code = ec.value, .frame_type = ft.value, .reason = reason } }, .n = i };
    }
    if (t == @intFromEnum(FrameType.STOP_SENDING)) {
        var i: usize = 1;
        const sid = try varint.decode(buf[i..]);
        i += sid.n;
        const ec = try varint.decode(buf[i..]);
        i += ec.n;
        return .{ .f = Frame{ .stop_sending = .{ .stream_id = sid.value, .error_code = ec.value } }, .n = i };
    }
    if (t == @intFromEnum(FrameType.RESET_STREAM)) {
        var i: usize = 1;
        const sid = try varint.decode(buf[i..]);
        i += sid.n;
        const ec = try varint.decode(buf[i..]);
        i += ec.n;
        const fs = try varint.decode(buf[i..]);
        i += fs.n;
        return .{ .f = Frame{ .reset_stream = .{ .stream_id = sid.value, .error_code = ec.value, .final_size = fs.value } }, .n = i };
    }
    // Minimal support for now
    return error.Unsupported;
}

/// Compatibility wrapper for existing tests: parse returns { frame, n }.
pub fn parse(buf: []const u8) !struct { frame: Frame, n: usize } {
    const r = try decodeOne(buf);
    return .{ .frame = r.f, .n = r.n };
}
