//! QUIC frame codec coordinator module.
//!
//! This module provides a unified Frame union and encoding/decoding functions
//! by combining specialized frame modules organized by RFC section.
//!
//! RFC 9000 §19: Frame Types and Formats
//! RFC 9221: DATAGRAM Extension

const std = @import("std");

// Import all specialized frame modules
const types = @import("types.zig");
const misc = @import("misc.zig");
const crypto_mod = @import("crypto.zig");
const stream_mod = @import("stream.zig");
const ack_mod = @import("ack.zig");
const path_mod = @import("path.zig");
const conn_mgmt = @import("connection_mgmt.zig");
const flow_ctrl = @import("flow_control.zig");
const datagram_mod = @import("datagram.zig");

// Re-export types for convenience
pub const FrameType = types.FrameType;
pub const AckRange = types.AckRange;
pub const EcnCounts = types.EcnCounts;

/// Frame union with encode helper for all supported QUIC frames.
/// Each case references the governing section in RFC 9000 unless noted.
pub const Frame = union(enum) {
    padding: usize,
    ping: void,
    crypto: struct { offset: u64, data: []const u8 },
    stream: struct { stream_id: u64, offset: ?u64, fin: bool, data: []const u8 },
    new_connection_id: struct {
        sequence: u64,
        retire_prior_to: u64,
        connection_id: []const u8,
        stateless_reset_token: [16]u8,
    },
    retire_connection_id: struct { sequence: u64 },
    ack: struct {
        largest: u64,
        ack_delay: u64,
        first_range: u64 = 0,
        ranges: []const AckRange = &[_]AckRange{},
        ecn: ?EcnCounts = null,
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
    new_token: struct { token: []const u8 },
    handshake_done: void,
    connection_close: struct { error_code: u64, frame_type: u64 = 0, reason: []const u8 = &[_]u8{} },
    stop_sending: struct { stream_id: u64, error_code: u64 },
    reset_stream: struct { stream_id: u64, error_code: u64, final_size: u64 },

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
pub fn encode(frame: Frame, w: anytype) !void {
    _ = frame;
    _ = w;
    return error.NotImplemented;
}

/// Placeholder for future streaming decoder API.
pub fn decode(r: anytype, alloc: std.mem.Allocator) !Frame {
    _ = r;
    _ = alloc;
    return error.NotImplemented;
}
