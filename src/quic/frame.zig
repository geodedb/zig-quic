// MIT License
// QUIC frame model and encode/parse — RFC 9000 §19
const std = @import("std");
const varint = @import("varint.zig");

/// Frame type codes used on the wire (single-byte for spec-defined frames).
pub const FrameType = enum(u8) {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02, // 0x03 = ACK_ECN
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    StreamBase = 0x08, // 0x08..0x0f with flags OFF/LEN/FIN
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreamsBidi = 0x12,
    MaxStreamsUni = 0x13,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlockedBidi = 0x16,
    StreamsBlockedUni = 0x17,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionCloseTransport = 0x1c,
    ConnectionCloseApplication = 0x1d,
    HandshakeDone = 0x1e,
};

/// QUIC frame representation (subset sufficient for early transport work).
pub const Frame = union(enum) {
    padding,
    ping,
    ack: struct { largest: u64, delay: u64, first_range: u64 },
    reset_stream: struct { stream_id: u64, error_code: u64, final_size: u64 },
    stop_sending: struct { stream_id: u64, error_code: u64 },
    crypto: struct { offset: u64, data: []const u8 },
    new_token: struct { token: []const u8 },
    stream: struct { stream_id: u64, offset: ?u64, fin: bool, data: []const u8 },
    max_data: struct { maximum_data: u64 },
    max_stream_data: struct { stream_id: u64, maximum_stream_data: u64 },
    max_streams: struct { bidi: bool, maximum_streams: u64 },
    data_blocked: struct { limit: u64 },
    stream_data_blocked: struct { stream_id: u64, limit: u64 },
    streams_blocked: struct { bidi: bool, limit: u64 },
    new_connection_id: struct { sequence_number: u64, retire_prior_to: u64, connection_id: []const u8, stateless_reset_token: []const u8 },
    retire_connection_id: struct { sequence_number: u64 },
    path_challenge: struct { data: [8]u8 },
    path_response: struct { data: [8]u8 },
    connection_close: struct { application: bool, error_code: u64, frame_type: u64, reason: []const u8 },
    handshake_done,
};

/// Encode this frame to writer; returns bytes written. Not all variants are implemented for encode.
pub fn write(self: Frame, w: anytype) !usize {
    var total: usize = 0;
    switch (self) {
        .padding => {
            try w.writeByte(@intFromEnum(FrameType.Padding));
            total += 1;
        },
        .ping => {
            try w.writeByte(@intFromEnum(FrameType.Ping));
            total += 1;
        },
        .ack => |a| {
            try w.writeByte(@intFromEnum(FrameType.Ack));
            var buf: [8]u8 = undefined;
            const n1 = try varint.encode(a.largest, &buf);
            try w.writeAll(buf[0..n1]);
            total += 1 + n1;
            const n2 = try varint.encode(a.delay, &buf);
            try w.writeAll(buf[0..n2]);
            total += n2;
            const n3 = try varint.encode(0, &buf);
            try w.writeAll(buf[0..n3]);
            total += n3; // range count = 0
            const n4 = try varint.encode(a.first_range, &buf);
            try w.writeAll(buf[0..n4]);
            total += n4;
        },
        .reset_stream => |rs| {
            try w.writeByte(@intFromEnum(FrameType.ResetStream));
            var buf: [8]u8 = undefined;
            total += 1;
            const n1 = try varint.encode(rs.stream_id, &buf);
            try w.writeAll(buf[0..n1]);
            total += n1;
            const n2 = try varint.encode(rs.error_code, &buf);
            try w.writeAll(buf[0..n2]);
            total += n2;
            const n3 = try varint.encode(rs.final_size, &buf);
            try w.writeAll(buf[0..n3]);
            total += n3;
        },
        .stop_sending => |ss| {
            try w.writeByte(@intFromEnum(FrameType.StopSending));
            var buf: [8]u8 = undefined;
            total += 1;
            const n1 = try varint.encode(ss.stream_id, &buf);
            try w.writeAll(buf[0..n1]);
            total += n1;
            const n2 = try varint.encode(ss.error_code, &buf);
            try w.writeAll(buf[0..n2]);
            total += n2;
        },
        .crypto => |c| {
            try w.writeByte(@intFromEnum(FrameType.Crypto));
            var buf: [8]u8 = undefined;
            total += 1;
            const n1 = try varint.encode(c.offset, &buf);
            try w.writeAll(buf[0..n1]);
            total += n1;
            const n2 = try varint.encode(c.data.len, &buf);
            try w.writeAll(buf[0..n2]);
            total += n2;
            try w.writeAll(c.data);
            total += c.data.len;
        },
        .new_token => |nt| {
            try w.writeByte(@intFromEnum(FrameType.NewToken));
            var buf: [8]u8 = undefined;
            total += 1;
            const n1 = try varint.encode(nt.token.len, &buf);
            try w.writeAll(buf[0..n1]);
            total += n1;
            try w.writeAll(nt.token);
            total += nt.token.len;
        },
        .stream => |s| {
            var t: u8 = @intFromEnum(FrameType.StreamBase);
            t |= 0x02; // LEN present
            if (s.offset != null) t |= 0x04;
            if (s.fin) t |= 0x01;
            try w.writeByte(t);
            total += 1;
            var buf: [8]u8 = undefined;
            const n1 = try varint.encode(s.stream_id, &buf);
            try w.writeAll(buf[0..n1]);
            total += n1;
            if (s.offset) |off| {
                const n2 = try varint.encode(off, &buf);
                try w.writeAll(buf[0..n2]);
                total += n2;
            }
            const n3 = try varint.encode(s.data.len, &buf);
            try w.writeAll(buf[0..n3]);
            total += n3;
            try w.writeAll(s.data);
            total += s.data.len;
        },
        .max_data => |md| {
            try w.writeByte(@intFromEnum(FrameType.MaxData));
            var buf: [8]u8 = undefined;
            total += 1;
            const n = try varint.encode(md.maximum_data, &buf);
            try w.writeAll(buf[0..n]);
            total += n;
        },
        .max_stream_data => |msd| {
            try w.writeByte(@intFromEnum(FrameType.MaxStreamData));
            var buf: [8]u8 = undefined;
            total += 1;
            const n1 = try varint.encode(msd.stream_id, &buf);
            try w.writeAll(buf[0..n1]);
            total += n1;
            const n2 = try varint.encode(msd.maximum_stream_data, &buf);
            try w.writeAll(buf[0..n2]);
            total += n2;
        },
        .max_streams => |ms| {
            const ty: u8 = if (ms.bidi) @intFromEnum(FrameType.MaxStreamsBidi) else @intFromEnum(FrameType.MaxStreamsUni);
            try w.writeByte(ty);
            var buf: [8]u8 = undefined;
            total += 1;
            const n = try varint.encode(ms.maximum_streams, &buf);
            try w.writeAll(buf[0..n]);
            total += n;
        },
        .data_blocked => |db| {
            try w.writeByte(@intFromEnum(FrameType.DataBlocked));
            var buf: [8]u8 = undefined;
            total += 1;
            const n = try varint.encode(db.limit, &buf);
            try w.writeAll(buf[0..n]);
            total += n;
        },
        .stream_data_blocked => |sdb| {
            try w.writeByte(@intFromEnum(FrameType.StreamDataBlocked));
            var buf: [8]u8 = undefined;
            total += 1;
            const n1 = try varint.encode(sdb.stream_id, &buf);
            try w.writeAll(buf[0..n1]);
            total += n1;
            const n2 = try varint.encode(sdb.limit, &buf);
            try w.writeAll(buf[0..n2]);
            total += n2;
        },
        .streams_blocked => |sb| {
            const ty: u8 = if (sb.bidi) @intFromEnum(FrameType.StreamsBlockedBidi) else @intFromEnum(FrameType.StreamsBlockedUni);
            try w.writeByte(ty);
            var buf: [8]u8 = undefined;
            total += 1;
            const n = try varint.encode(sb.limit, &buf);
            try w.writeAll(buf[0..n]);
            total += n;
        },
        .new_connection_id => |nc| {
            try w.writeByte(@intFromEnum(FrameType.NewConnectionId));
            total += 1;
            var buf: [8]u8 = undefined;
            const n1 = try varint.encode(nc.sequence_number, &buf);
            try w.writeAll(buf[0..n1]);
            total += n1;
            const n2 = try varint.encode(nc.retire_prior_to, &buf);
            try w.writeAll(buf[0..n2]);
            total += n2;
            try w.writeByte(@as(u8, @intCast(nc.connection_id.len)));
            total += 1;
            try w.writeAll(nc.connection_id);
            total += nc.connection_id.len;
            try w.writeAll(nc.stateless_reset_token);
            total += nc.stateless_reset_token.len;
        },
        .retire_connection_id => |rc| {
            try w.writeByte(@intFromEnum(FrameType.RetireConnectionId));
            var buf: [8]u8 = undefined;
            total += 1;
            const n = try varint.encode(rc.sequence_number, &buf);
            try w.writeAll(buf[0..n]);
            total += n;
        },
        .path_challenge => |pc| {
            try w.writeByte(@intFromEnum(FrameType.PathChallenge));
            try w.writeAll(&pc.data);
            total += 1 + pc.data.len;
        },
        .path_response => |pr| {
            try w.writeByte(@intFromEnum(FrameType.PathResponse));
            try w.writeAll(&pr.data);
            total += 1 + pr.data.len;
        },
        .connection_close => |cc| {
            const ty: u8 = if (cc.application) @intFromEnum(FrameType.ConnectionCloseApplication) else @intFromEnum(FrameType.ConnectionCloseTransport);
            try w.writeByte(ty);
            total += 1;
            var buf: [8]u8 = undefined;
            const n1 = try varint.encode(cc.error_code, &buf);
            try w.writeAll(buf[0..n1]);
            total += n1;
            const n2 = try varint.encode(cc.frame_type, &buf);
            try w.writeAll(buf[0..n2]);
            total += n2;
            const n3 = try varint.encode(cc.reason.len, &buf);
            try w.writeAll(buf[0..n3]);
            total += n3;
            try w.writeAll(cc.reason);
            total += cc.reason.len;
        },
        .handshake_done => {
            try w.writeByte(@intFromEnum(FrameType.HandshakeDone));
            total += 1;
        },
    }
    return total;
}

/// Result of parsing a frame: the frame and the bytes consumed.
pub const ParseResult = struct { frame: Frame, n: usize };

/// Parse a single frame from data.
pub fn parse(data: []const u8) !ParseResult {
    if (data.len == 0) return error.EndOfStream;
    const t = data[0];
    // STREAM frames (0x08..0x0f)
    if (t >= 0x08 and t <= 0x0f) {
        var off: usize = 1;
        var res = try varint.decode(data[off..]);
        const stream_id = res.value;
        off += res.n;
        const has_off = (t & 0x04) != 0;
        const has_len = (t & 0x02) != 0;
        const fin = (t & 0x01) != 0;
        var offset_val: ?u64 = null;
        if (has_off) {
            res = try varint.decode(data[off..]);
            offset_val = res.value;
            off += res.n;
        }
        var data_len: usize = data.len - off;
        if (has_len) {
            res = try varint.decode(data[off..]);
            data_len = @as(usize, @intCast(res.value));
            off += res.n;
        }
        if (off + data_len > data.len) return error.EndOfStream;
        const payload = data[off .. off + data_len];
        return .{ .frame = .{ .stream = .{ .stream_id = stream_id, .offset = offset_val, .fin = fin, .data = payload } }, .n = off + data_len };
    }
    switch (t) {
        0x00 => return .{ .frame = .padding, .n = 1 },
        0x01 => return .{ .frame = .ping, .n = 1 },
        0x02, 0x03 => {
            var off: usize = 1;
            var r = try varint.decode(data[off..]);
            const largest = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const delay = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const range_count = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const first_range = r.value;
            off += r.n;
            // ignore any additional ranges; for ACK_ECN, skip 3 extra counts
            if (t == 0x03) {
                // ECN counts
                inline for (0..3) |_| {
                    r = try varint.decode(data[off..]);
                    off += r.n;
                }
            }
            if (range_count != 0) return error.Unsupported;
            return .{ .frame = .{ .ack = .{ .largest = largest, .delay = delay, .first_range = first_range } }, .n = off };
        },
        0x04 => {
            var off: usize = 1;
            var r = try varint.decode(data[off..]);
            const sid = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const ec = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const fs = r.value;
            off += r.n;
            return .{ .frame = .{ .reset_stream = .{ .stream_id = sid, .error_code = ec, .final_size = fs } }, .n = off };
        },
        0x05 => {
            var off: usize = 1;
            var r = try varint.decode(data[off..]);
            const sid = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const ec = r.value;
            off += r.n;
            return .{ .frame = .{ .stop_sending = .{ .stream_id = sid, .error_code = ec } }, .n = off };
        },
        0x06 => {
            var off: usize = 1;
            var r = try varint.decode(data[off..]);
            const ofs = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const l = @as(usize, @intCast(r.value));
            off += r.n;
            if (off + l > data.len) return error.EndOfStream;
            const payload = data[off .. off + l];
            return .{ .frame = .{ .crypto = .{ .offset = ofs, .data = payload } }, .n = off + l };
        },
        0x07 => {
            var off: usize = 1;
            const r = try varint.decode(data[off..]);
            const l = @as(usize, @intCast(r.value));
            off += r.n;
            if (off + l > data.len) return error.EndOfStream;
            const tok = data[off .. off + l];
            return .{ .frame = .{ .new_token = .{ .token = tok } }, .n = off + l };
        },
        0x10 => {
            const off: usize = 1;
            const r = try varint.decode(data[off..]);
            return .{ .frame = .{ .max_data = .{ .maximum_data = r.value } }, .n = off + r.n };
        },
        0x11 => {
            var off: usize = 1;
            var r = try varint.decode(data[off..]);
            const sid = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const m = r.value;
            off += r.n;
            return .{ .frame = .{ .max_stream_data = .{ .stream_id = sid, .maximum_stream_data = m } }, .n = off };
        },
        0x12, 0x13 => {
            var off: usize = 1;
            const r = try varint.decode(data[off..]);
            const m = r.value;
            off += r.n;
            return .{ .frame = .{ .max_streams = .{ .bidi = (t == 0x12), .maximum_streams = m } }, .n = off };
        },
        0x14 => {
            const off: usize = 1;
            const r = try varint.decode(data[off..]);
            return .{ .frame = .{ .data_blocked = .{ .limit = r.value } }, .n = off + r.n };
        },
        0x15 => {
            var off: usize = 1;
            var r = try varint.decode(data[off..]);
            const sid = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const lim = r.value;
            off += r.n;
            return .{ .frame = .{ .stream_data_blocked = .{ .stream_id = sid, .limit = lim } }, .n = off };
        },
        0x16, 0x17 => {
            var off: usize = 1;
            const r = try varint.decode(data[off..]);
            const lim = r.value;
            off += r.n;
            return .{ .frame = .{ .streams_blocked = .{ .bidi = (t == 0x16), .limit = lim } }, .n = off };
        },
        0x18 => {
            var off: usize = 1;
            var r = try varint.decode(data[off..]);
            const sn = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const rpt = r.value;
            off += r.n;
            if (off >= data.len) return error.EndOfStream;
            const cid_len = data[off];
            off += 1;
            if (off + cid_len + 16 > data.len) return error.EndOfStream;
            const cid = data[off .. off + cid_len];
            off += cid_len;
            const srt = data[off .. off + 16];
            off += 16;
            return .{ .frame = .{ .new_connection_id = .{ .sequence_number = sn, .retire_prior_to = rpt, .connection_id = cid, .stateless_reset_token = srt } }, .n = off };
        },
        0x19 => {
            const off: usize = 1;
            const r = try varint.decode(data[off..]);
            return .{ .frame = .{ .retire_connection_id = .{ .sequence_number = r.value } }, .n = off + r.n };
        },
        0x1a => {
            if (data.len < 1 + 8) return error.EndOfStream;
            var v: [8]u8 = undefined;
            @memcpy(v[0..], data[1..9]);
            return .{ .frame = .{ .path_challenge = .{ .data = v } }, .n = 9 };
        },
        0x1b => {
            if (data.len < 1 + 8) return error.EndOfStream;
            var v: [8]u8 = undefined;
            @memcpy(v[0..], data[1..9]);
            return .{ .frame = .{ .path_response = .{ .data = v } }, .n = 9 };
        },
        0x1c, 0x1d => {
            var off: usize = 1;
            var r = try varint.decode(data[off..]);
            const ec = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const ft = r.value;
            off += r.n;
            r = try varint.decode(data[off..]);
            const l = @as(usize, @intCast(r.value));
            off += r.n;
            if (off + l > data.len) return error.EndOfStream;
            const reason = data[off .. off + l];
            off += l;
            return .{ .frame = .{ .connection_close = .{ .application = (t == 0x1d), .error_code = ec, .frame_type = ft, .reason = reason } }, .n = off };
        },
        0x1e => return .{ .frame = .handshake_done, .n = 1 },
        else => return error.UnknownFrame,
    }
}
