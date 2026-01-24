// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC frame codec coordinator module.
//!
//! This module provides a unified Frame union and encoding/decoding functions
//! by combining specialized frame modules organized by RFC section.
//!
//! RFC 9000 §19: Frame Types and Formats
//! RFC 9221: DATAGRAM Extension

const std = @import("std");
const varint = @import("quic_varint");

// Import all specialized frame modules
const types = @import("types");
const misc = @import("misc");
const crypto_mod = @import("crypto");
const stream_mod = @import("stream");
const ack_mod = @import("ack");
const path_mod = @import("path");
const conn_mgmt = @import("connection_mgmt");
const flow_ctrl = @import("flow_control");
const datagram_mod = @import("datagram");

// Re-export types for convenience
pub const FrameType = types.FrameType;
pub const AckRange = types.AckRange;
pub const EcnCounts = types.EcnCounts;

// Type aliases for frame data structures (used by frame_handler.zig)
pub const Crypto = struct { offset: u64, data: []const u8 };
pub const Stream = struct { stream_id: u64, offset: ?u64, fin: bool, data: []const u8 };
pub const NewConnectionId = struct {
    sequence: u64,
    retire_prior_to: u64,
    connection_id: []const u8,
    stateless_reset_token: [16]u8,
};
pub const RetireConnectionId = struct { sequence: u64 };
pub const Ack = struct {
    largest: u64,
    ack_delay: u64,
    first_range: u64 = 0,
    ranges: []const AckRange = &[_]AckRange{},
    ecn: ?EcnCounts = null,
    ranges_buf: [16]AckRange = undefined,
    ranges_len: usize = 0,
};
pub const Datagram = struct { data: []const u8 };
pub const MaxData = struct { max: u64 };
pub const MaxStreamData = struct { stream_id: u64, max: u64 };
pub const MaxStreamsBidi = struct { max: u64 };
pub const MaxStreamsUni = struct { max: u64 };
pub const DataBlocked = struct { limit: u64 };
pub const StreamDataBlocked = struct { stream_id: u64, limit: u64 };
pub const StreamsBlockedBidi = struct { max: u64 };
pub const StreamsBlockedUni = struct { max: u64 };
pub const PathChallenge = [8]u8;
pub const PathResponse = [8]u8;
pub const NewToken = struct { token: []const u8 };
pub const ConnectionClose = struct { error_code: u64, frame_type: u64 = 0, reason: []const u8 = &[_]u8{} };
pub const StopSending = struct { stream_id: u64, error_code: u64 };
pub const ResetStream = struct { stream_id: u64, error_code: u64, final_size: u64 };

/// Frame union with encode helper for all supported QUIC frames.
/// Each case references the governing section in RFC 9000 unless noted.
pub const Frame = union(enum) {
    padding: usize,
    ping: void,
    crypto: Crypto,
    stream: Stream,
    new_connection_id: NewConnectionId,
    retire_connection_id: RetireConnectionId,
    ack: Ack,
    datagram: Datagram,
    max_data: MaxData,
    max_stream_data: MaxStreamData,
    max_streams_bidi: MaxStreamsBidi,
    max_streams_uni: MaxStreamsUni,
    data_blocked: DataBlocked,
    stream_data_blocked: StreamDataBlocked,
    streams_blocked_bidi: StreamsBlockedBidi,
    streams_blocked_uni: StreamsBlockedUni,
    path_challenge: PathChallenge,
    path_response: PathResponse,
    new_token: NewToken,
    handshake_done: void,
    connection_close: ConnectionClose,
    stop_sending: StopSending,
    reset_stream: ResetStream,

    /// Encode this frame to the writer. Returns bytes written.
    pub fn write(self: Frame, w: anytype) !usize {
        switch (self) {
            .padding => |count| return misc.writePadding(w, count),
            .ping => return misc.writePing(w),
            .crypto => |c| return crypto_mod.writeCrypto(w, c.offset, c.data),
            .stream => |s| return stream_mod.writeStream(w, s.stream_id, s.offset, s.fin, s.data),
            .new_connection_id => |ncid| return conn_mgmt.writeNewConnectionId(
                w,
                ncid.sequence,
                ncid.retire_prior_to,
                ncid.connection_id,
                ncid.stateless_reset_token,
            ),
            .retire_connection_id => |rc| return conn_mgmt.writeRetireConnectionId(w, rc.sequence),
            .ack => |a| return ack_mod.writeAck(w, a.largest, a.ack_delay, a.first_range, a.ranges, a.ecn),
            .datagram => |d| return datagram_mod.writeDatagram(w, d.data),
            .max_data => |m| return flow_ctrl.writeMaxData(w, m.max),
            .max_stream_data => |m| return flow_ctrl.writeMaxStreamData(w, m.stream_id, m.max),
            .max_streams_bidi => |m| return flow_ctrl.writeMaxStreamsBidi(w, m.max),
            .max_streams_uni => |m| return flow_ctrl.writeMaxStreamsUni(w, m.max),
            .data_blocked => |m| return flow_ctrl.writeDataBlocked(w, m.limit),
            .stream_data_blocked => |m| return flow_ctrl.writeStreamDataBlocked(w, m.stream_id, m.limit),
            .streams_blocked_bidi => |m| return flow_ctrl.writeStreamsBlockedBidi(w, m.max),
            .streams_blocked_uni => |m| return flow_ctrl.writeStreamsBlockedUni(w, m.max),
            .path_challenge => |v| return path_mod.writePathChallenge(w, v),
            .path_response => |v| return path_mod.writePathResponse(w, v),
            .new_token => |nt| return misc.writeNewToken(w, nt.token),
            .handshake_done => return misc.writeHandshakeDone(w),
            .connection_close => |cc| return conn_mgmt.writeConnectionClose(w, cc.error_code, cc.frame_type, cc.reason),
            .stop_sending => |s| return conn_mgmt.writeStopSending(w, s.stream_id, s.error_code),
            .reset_stream => |r| return conn_mgmt.writeResetStream(w, r.stream_id, r.error_code, r.final_size),
        }
    }
};

/// Decode one frame from the front of `buf`, returning the frame and bytes consumed.
pub fn decodeOne(buf: []const u8) !struct { f: Frame, n: usize } {
    if (buf.len == 0) return error.Truncated;

    const t = buf[0];

    // PADDING
    if (t == @intFromEnum(FrameType.PADDING)) {
        const result = try misc.decodePadding(buf);
        return .{ .f = Frame{ .padding = result.count }, .n = result.n };
    }

    // PING
    if (t == @intFromEnum(FrameType.PING)) {
        _ = try misc.decodePing(buf);
        return .{ .f = Frame{ .ping = {} }, .n = 1 };
    }

    // CRYPTO
    if (t == @intFromEnum(FrameType.CRYPTO)) {
        const result = try crypto_mod.decodeCrypto(buf);
        return .{
            .f = Frame{ .crypto = .{ .offset = result.offset, .data = result.data } },
            .n = result.n,
        };
    }

    // ACK / ACK_ECN
    if (t == @intFromEnum(FrameType.ACK) or t == @intFromEnum(FrameType.ACK_ECN)) {
        const result = try ack_mod.decodeAck(buf);
        var ackf = Frame{
            .ack = .{
                .largest = result.largest,
                .ack_delay = result.ack_delay,
                .first_range = result.first_range,
                .ranges = &[_]AckRange{},
                .ecn = result.ecn,
                .ranges_buf = result.ranges_buf,
                .ranges_len = result.ranges_len,
            },
        };
        ackf.ack.ranges = ackf.ack.ranges_buf[0..result.ranges_len];
        return .{ .f = ackf, .n = result.n };
    }

    // STREAM frames (0x08-0x0f)
    if ((t & 0xf8) == @intFromEnum(FrameType.STREAM)) {
        const result = try stream_mod.decodeStream(buf);
        return .{
            .f = Frame{ .stream = .{
                .stream_id = result.stream_id,
                .offset = result.offset,
                .fin = result.fin,
                .data = result.data,
            } },
            .n = result.n,
        };
    }

    // DATAGRAM
    if (t == @intFromEnum(FrameType.DATAGRAM)) {
        const result = try datagram_mod.decodeDatagram(buf);
        return .{ .f = Frame{ .datagram = .{ .data = result.data } }, .n = result.n };
    }

    // NEW_CONNECTION_ID
    if (t == @intFromEnum(FrameType.NEW_CONNECTION_ID)) {
        const result = try conn_mgmt.decodeNewConnectionId(buf);
        return .{
            .f = Frame{ .new_connection_id = .{
                .sequence = result.sequence,
                .retire_prior_to = result.retire_prior_to,
                .connection_id = result.connection_id,
                .stateless_reset_token = result.stateless_reset_token,
            } },
            .n = result.n,
        };
    }

    // RETIRE_CONNECTION_ID
    if (t == @intFromEnum(FrameType.RETIRE_CONNECTION_ID)) {
        const result = try conn_mgmt.decodeRetireConnectionId(buf);
        return .{
            .f = Frame{ .retire_connection_id = .{ .sequence = result.sequence } },
            .n = result.n,
        };
    }

    // Flow control frames
    if (t == @intFromEnum(FrameType.MAX_DATA)) {
        const result = try flow_ctrl.decodeMaxData(buf);
        return .{ .f = Frame{ .max_data = .{ .max = result.max } }, .n = result.n };
    }

    if (t == @intFromEnum(FrameType.MAX_STREAM_DATA)) {
        const result = try flow_ctrl.decodeMaxStreamData(buf);
        return .{
            .f = Frame{ .max_stream_data = .{ .stream_id = result.stream_id, .max = result.max } },
            .n = result.n,
        };
    }

    if (t == @intFromEnum(FrameType.MAX_STREAMS_BIDI)) {
        const result = try flow_ctrl.decodeMaxStreamsBidi(buf);
        return .{ .f = Frame{ .max_streams_bidi = .{ .max = result.max } }, .n = result.n };
    }

    if (t == @intFromEnum(FrameType.MAX_STREAMS_UNI)) {
        const result = try flow_ctrl.decodeMaxStreamsUni(buf);
        return .{ .f = Frame{ .max_streams_uni = .{ .max = result.max } }, .n = result.n };
    }

    if (t == @intFromEnum(FrameType.DATA_BLOCKED)) {
        const result = try flow_ctrl.decodeDataBlocked(buf);
        return .{ .f = Frame{ .data_blocked = .{ .limit = result.limit } }, .n = result.n };
    }

    if (t == @intFromEnum(FrameType.STREAM_DATA_BLOCKED)) {
        const result = try flow_ctrl.decodeStreamDataBlocked(buf);
        return .{
            .f = Frame{ .stream_data_blocked = .{ .stream_id = result.stream_id, .limit = result.limit } },
            .n = result.n,
        };
    }

    if (t == @intFromEnum(FrameType.STREAMS_BLOCKED_BIDI)) {
        const result = try flow_ctrl.decodeStreamsBlockedBidi(buf);
        return .{ .f = Frame{ .streams_blocked_bidi = .{ .max = result.max } }, .n = result.n };
    }

    if (t == @intFromEnum(FrameType.STREAMS_BLOCKED_UNI)) {
        const result = try flow_ctrl.decodeStreamsBlockedUni(buf);
        return .{ .f = Frame{ .streams_blocked_uni = .{ .max = result.max } }, .n = result.n };
    }

    // Path validation frames
    if (t == @intFromEnum(FrameType.PATH_CHALLENGE)) {
        const result = try path_mod.decodePathChallenge(buf);
        return .{ .f = Frame{ .path_challenge = result.data }, .n = result.n };
    }

    if (t == @intFromEnum(FrameType.PATH_RESPONSE)) {
        const result = try path_mod.decodePathResponse(buf);
        return .{ .f = Frame{ .path_response = result.data }, .n = result.n };
    }

    // Miscellaneous frames
    if (t == @intFromEnum(FrameType.NEW_TOKEN)) {
        const result = try misc.decodeNewToken(buf);
        return .{ .f = Frame{ .new_token = .{ .token = result.token } }, .n = result.n };
    }

    if (t == @intFromEnum(FrameType.HANDSHAKE_DONE)) {
        _ = try misc.decodeHandshakeDone(buf);
        return .{ .f = Frame{ .handshake_done = {} }, .n = 1 };
    }

    // Connection management frames
    if (t == @intFromEnum(FrameType.CONNECTION_CLOSE)) {
        const result = try conn_mgmt.decodeConnectionClose(buf);
        return .{
            .f = Frame{ .connection_close = .{
                .error_code = result.error_code,
                .frame_type = result.frame_type,
                .reason = result.reason,
            } },
            .n = result.n,
        };
    }

    // APPLICATION_CLOSE (0x1d) - similar to CONNECTION_CLOSE but no frame_type field
    if (t == @intFromEnum(FrameType.APPLICATION_CLOSE)) {
        const result = try conn_mgmt.decodeApplicationClose(buf);
        return .{
            .f = Frame{ .connection_close = .{
                .error_code = result.error_code,
                .frame_type = 0, // APPLICATION_CLOSE doesn't have frame_type
                .reason = result.reason,
            } },
            .n = result.n,
        };
    }

    if (t == @intFromEnum(FrameType.STOP_SENDING)) {
        const result = try conn_mgmt.decodeStopSending(buf);
        return .{
            .f = Frame{ .stop_sending = .{ .stream_id = result.stream_id, .error_code = result.error_code } },
            .n = result.n,
        };
    }

    if (t == @intFromEnum(FrameType.RESET_STREAM)) {
        const result = try conn_mgmt.decodeResetStream(buf);
        return .{
            .f = Frame{ .reset_stream = .{
                .stream_id = result.stream_id,
                .error_code = result.error_code,
                .final_size = result.final_size,
            } },
            .n = result.n,
        };
    }

    return error.Unsupported;
}

/// Compatibility wrapper for existing tests: parse returns { frame, n }.
pub fn parse(buf: []const u8) !struct { frame: Frame, n: usize } {
    const r = try decodeOne(buf);
    return .{ .frame = r.f, .n = r.n };
}

/// Placeholder for future streaming encoder API.
/// Encode this frame to the writer.
pub fn encode(frame: Frame, w: anytype) !void {
    _ = try frame.write(w);
}

/// Decode a frame from the reader. Allocates dynamic content using `alloc`.
pub fn decode(r: anytype, alloc: std.mem.Allocator) !Frame {
    const t = try r.readByte();

    // PADDING
    if (t == @intFromEnum(FrameType.PADDING)) {
        return Frame{ .padding = 1 };
    }

    // PING
    if (t == @intFromEnum(FrameType.PING)) {
        return Frame{ .ping = {} };
    }

    // CRYPTO
    if (t == @intFromEnum(FrameType.CRYPTO)) {
        const offset = try varint.decodeReader(r);
        const len = try varint.decodeReader(r);
        const data = try alloc.alloc(u8, @intCast(len));
        try r.readNoEof(data);
        return Frame{ .crypto = .{ .offset = offset, .data = data } };
    }

    // ACK / ACK_ECN
    if (t == @intFromEnum(FrameType.ACK) or t == @intFromEnum(FrameType.ACK_ECN)) {
        const largest = try varint.decodeReader(r);
        const ack_delay = try varint.decodeReader(r);
        const range_count = try varint.decodeReader(r);
        const first_range = try varint.decodeReader(r);

        // Allocate ranges
        const ranges = try alloc.alloc(AckRange, @intCast(range_count));
        var i: usize = 0;
        while (i < range_count) : (i += 1) {
            const gap = try varint.decodeReader(r);
            const len = try varint.decodeReader(r);
            ranges[i] = .{ .gap = gap, .len = len };
        }

        var ecn: ?EcnCounts = null;
        if (t == @intFromEnum(FrameType.ACK_ECN)) {
            const ect0 = try varint.decodeReader(r);
            const ect1 = try varint.decodeReader(r);
            const ce = try varint.decodeReader(r);
            ecn = .{ .ect0 = ect0, .ect1 = ect1, .ce = ce };
        }

        return Frame{
            .ack = .{
                .largest = largest,
                .ack_delay = ack_delay,
                .first_range = first_range,
                .ranges = ranges,
                .ecn = ecn,
            },
        };
    }

    // STREAM
    if ((t & 0xf8) == @intFromEnum(FrameType.STREAM)) {
        const OFF: u8 = 0x04;
        const LEN: u8 = 0x02;
        const FIN: u8 = 0x01;
        const has_off = (t & OFF) != 0;
        const has_len = (t & LEN) != 0;
        const fin = (t & FIN) != 0;

        const stream_id = try varint.decodeReader(r);
        const offset = if (has_off) try varint.decodeReader(r) else null;

        var data: []u8 = undefined;
        if (has_len) {
            const len = try varint.decodeReader(r);
            data = try alloc.alloc(u8, @intCast(len));
            try r.readNoEof(data);
        } else {
            // Read until EOF (bounded)
            data = try r.readAllAlloc(alloc, 65536);
        }

        return Frame{ .stream = .{ .stream_id = stream_id, .offset = offset, .fin = fin, .data = data } };
    }

    // DATAGRAM
    if (t == @intFromEnum(FrameType.DATAGRAM)) {
        const len = try varint.decodeReader(r);
        const data = try alloc.alloc(u8, @intCast(len));
        try r.readNoEof(data);
        return Frame{ .datagram = .{ .data = data } };
    }

    // NEW_CONNECTION_ID
    if (t == @intFromEnum(FrameType.NEW_CONNECTION_ID)) {
        const seq = try varint.decodeReader(r);
        const retire = try varint.decodeReader(r);
        const len = try r.readByte();
        const cid = try alloc.alloc(u8, len);
        try r.readNoEof(cid);
        var token: [16]u8 = undefined;
        try r.readNoEof(&token);
        return Frame{ .new_connection_id = .{
            .sequence = seq,
            .retire_prior_to = retire,
            .connection_id = cid,
            .stateless_reset_token = token,
        } };
    }

    // RETIRE_CONNECTION_ID
    if (t == @intFromEnum(FrameType.RETIRE_CONNECTION_ID)) {
        const seq = try varint.decodeReader(r);
        return Frame{ .retire_connection_id = .{ .sequence = seq } };
    }

    // PATH_CHALLENGE
    if (t == @intFromEnum(FrameType.PATH_CHALLENGE)) {
        var data: [8]u8 = undefined;
        try r.readNoEof(&data);
        return Frame{ .path_challenge = data };
    }

    // PATH_RESPONSE
    if (t == @intFromEnum(FrameType.PATH_RESPONSE)) {
        var data: [8]u8 = undefined;
        try r.readNoEof(&data);
        return Frame{ .path_response = data };
    }

    // HANDSHAKE_DONE
    if (t == @intFromEnum(FrameType.HANDSHAKE_DONE)) {
        return Frame{ .handshake_done = {} };
    }

    // CONNECTION_CLOSE
    if (t == @intFromEnum(FrameType.CONNECTION_CLOSE)) {
        const ec = try varint.decodeReader(r);
        const ft = try varint.decodeReader(r);
        const len = try varint.decodeReader(r);
        const reason = try alloc.alloc(u8, @intCast(len));
        try r.readNoEof(reason);
        return Frame{ .connection_close = .{ .error_code = ec, .frame_type = ft, .reason = reason } };
    }

    // Flow Control & Others
    if (t == @intFromEnum(FrameType.MAX_DATA)) {
        const max = try varint.decodeReader(r);
        return Frame{ .max_data = .{ .max = max } };
    }
    if (t == @intFromEnum(FrameType.MAX_STREAM_DATA)) {
        const sid = try varint.decodeReader(r);
        const max = try varint.decodeReader(r);
        return Frame{ .max_stream_data = .{ .stream_id = sid, .max = max } };
    }
    if (t == @intFromEnum(FrameType.MAX_STREAMS_BIDI)) {
        const max = try varint.decodeReader(r);
        return Frame{ .max_streams_bidi = .{ .max = max } };
    }
    if (t == @intFromEnum(FrameType.MAX_STREAMS_UNI)) {
        const max = try varint.decodeReader(r);
        return Frame{ .max_streams_uni = .{ .max = max } };
    }
    if (t == @intFromEnum(FrameType.DATA_BLOCKED)) {
        const limit = try varint.decodeReader(r);
        return Frame{ .data_blocked = .{ .limit = limit } };
    }
    if (t == @intFromEnum(FrameType.STREAM_DATA_BLOCKED)) {
        const sid = try varint.decodeReader(r);
        const limit = try varint.decodeReader(r);
        return Frame{ .stream_data_blocked = .{ .stream_id = sid, .limit = limit } };
    }
    if (t == @intFromEnum(FrameType.STREAMS_BLOCKED_BIDI)) {
        const max = try varint.decodeReader(r);
        return Frame{ .streams_blocked_bidi = .{ .max = max } };
    }
    if (t == @intFromEnum(FrameType.STREAMS_BLOCKED_UNI)) {
        const max = try varint.decodeReader(r);
        return Frame{ .streams_blocked_uni = .{ .max = max } };
    }
    if (t == @intFromEnum(FrameType.NEW_TOKEN)) {
        const len = try varint.decodeReader(r);
        const token = try alloc.alloc(u8, @intCast(len));
        try r.readNoEof(token);
        return Frame{ .new_token = .{ .token = token } };
    }
    if (t == @intFromEnum(FrameType.STOP_SENDING)) {
        const sid = try varint.decodeReader(r);
        const ec = try varint.decodeReader(r);
        return Frame{ .stop_sending = .{ .stream_id = sid, .error_code = ec } };
    }
    if (t == @intFromEnum(FrameType.RESET_STREAM)) {
        const sid = try varint.decodeReader(r);
        const ec = try varint.decodeReader(r);
        const fs = try varint.decodeReader(r);
        return Frame{ .reset_stream = .{ .stream_id = sid, .error_code = ec, .final_size = fs } };
    }

    return error.Unsupported;
}
