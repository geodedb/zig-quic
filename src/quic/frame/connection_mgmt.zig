// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Connection management frames: CID lifecycle, connection closure, stream control.
//!
//! RFC 9000 §19.15: NEW_CONNECTION_ID Frame
//! RFC 9000 §19.16: RETIRE_CONNECTION_ID Frame
//! RFC 9000 §19.19: CONNECTION_CLOSE Frame
//! RFC 9000 §19.4: RESET_STREAM Frame
//! RFC 9000 §19.5: STOP_SENDING Frame

const std = @import("std");
const types = @import("types");
const varint = @import("quic_varint");

// =============================================================================
// NEW_CONNECTION_ID Frame
// =============================================================================

/// Encode NEW_CONNECTION_ID frame.
/// RFC 9000 §19.15: Provides new connection IDs for migration and load balancing.
pub fn writeNewConnectionId(
    w: anytype,
    sequence: u64,
    retire_prior_to: u64,
    connection_id: []const u8,
    stateless_reset_token: [16]u8,
) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.NEW_CONNECTION_ID));
    var written: usize = 1;
    var tmp: [32]u8 = undefined;

    // Sequence Number
    const sl = try varint.encode(sequence, tmp[0..16]);
    try w.writeAll(tmp[0..sl]);
    written += sl;

    // Retire Prior To
    const rpl = try varint.encode(retire_prior_to, tmp[0..16]);
    try w.writeAll(tmp[0..rpl]);
    written += rpl;

    // Connection ID Length (1 byte)
    try w.writeByte(@as(u8, @intCast(connection_id.len)));
    written += 1;

    // Connection ID bytes
    try w.writeAll(connection_id);
    written += connection_id.len;

    // Stateless Reset Token (16 bytes)
    try w.writeAll(&stateless_reset_token);
    written += 16;

    return written;
}

/// Decode NEW_CONNECTION_ID frame.
/// RFC 9000 §19.15: Format is Type + Sequence + Retire + Len + CID + Token.
pub fn decodeNewConnectionId(buf: []const u8) !struct {
    sequence: u64,
    retire_prior_to: u64,
    connection_id: []const u8,
    stateless_reset_token: [16]u8,
    n: usize,
} {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.NEW_CONNECTION_ID)) return error.InvalidFrameType;

    var i: usize = 1;

    // Sequence Number
    const seq = try varint.decode(buf[i..]);
    i += seq.n;

    // Retire Prior To
    const rpto = try varint.decode(buf[i..]);
    i += rpto.n;

    // Connection ID Length
    if (i >= buf.len) return error.Truncated;
    const cid_len: usize = buf[i];
    i += 1;

    // Connection ID + Token
    if (i + cid_len + 16 > buf.len) return error.Truncated;
    const cid = buf[i .. i + cid_len];
    i += cid_len;

    var tok: [16]u8 = undefined;
    @memcpy(&tok, buf[i .. i + 16]);
    i += 16;

    return .{
        .sequence = seq.value,
        .retire_prior_to = rpto.value,
        .connection_id = cid,
        .stateless_reset_token = tok,
        .n = i,
    };
}

// =============================================================================
// RETIRE_CONNECTION_ID Frame
// =============================================================================

/// Encode RETIRE_CONNECTION_ID frame.
/// RFC 9000 §19.16: Indicates a connection ID is no longer in use.
pub fn writeRetireConnectionId(w: anytype, sequence: u64) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.RETIRE_CONNECTION_ID));
    var tmp: [16]u8 = undefined;
    const sl = try varint.encode(sequence, &tmp);
    try w.writeAll(tmp[0..sl]);
    return 1 + sl;
}

/// Decode RETIRE_CONNECTION_ID frame.
/// RFC 9000 §19.16: Format is Type (0x19) + Sequence Number (varint).
pub fn decodeRetireConnectionId(buf: []const u8) !struct { sequence: u64, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.RETIRE_CONNECTION_ID)) return error.InvalidFrameType;

    var i: usize = 1;
    const seq = try varint.decode(buf[i..]);
    i += seq.n;

    return .{ .sequence = seq.value, .n = i };
}

// =============================================================================
// CONNECTION_CLOSE Frame
// =============================================================================

/// Encode CONNECTION_CLOSE frame.
/// RFC 9000 §19.19: Signals connection termination with error code and reason.
pub fn writeConnectionClose(
    w: anytype,
    error_code: u64,
    frame_type: u64,
    reason: []const u8,
) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.CONNECTION_CLOSE));
    var written: usize = 1;
    var tmp: [32]u8 = undefined;

    // Error Code
    const el = try varint.encode(error_code, &tmp);
    try w.writeAll(tmp[0..el]);
    written += el;

    // Frame Type
    const ft = try varint.encode(frame_type, &tmp);
    try w.writeAll(tmp[0..ft]);
    written += ft;

    // Reason Phrase Length
    const rl = try varint.encode(reason.len, &tmp);
    try w.writeAll(tmp[0..rl]);
    written += rl;

    // Reason Phrase
    if (reason.len > 0) {
        try w.writeAll(reason);
        written += reason.len;
    }

    return written;
}

/// Decode CONNECTION_CLOSE frame.
/// RFC 9000 §19.19: Format is Type + Error Code + Frame Type + Reason Length + Reason.
pub fn decodeConnectionClose(buf: []const u8) !struct {
    error_code: u64,
    frame_type: u64,
    reason: []const u8,
    n: usize,
} {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.CONNECTION_CLOSE)) return error.InvalidFrameType;

    var i: usize = 1;

    // Error Code
    const ec = try varint.decode(buf[i..]);
    i += ec.n;

    // Frame Type
    const ft = try varint.decode(buf[i..]);
    i += ft.n;

    // Reason Phrase Length
    const rl = try varint.decode(buf[i..]);
    i += rl.n;

    // Reason Phrase
    if (rl.value > @as(u64, buf.len - i)) return error.Truncated;
    const rlen: usize = @intCast(rl.value);
    const reason = buf[i .. i + rlen];
    i += rlen;

    return .{
        .error_code = ec.value,
        .frame_type = ft.value,
        .reason = reason,
        .n = i,
    };
}

/// Decode APPLICATION_CLOSE frame (0x1d).
/// RFC 9000 §19.19: Format is Type + Error Code + Reason Length + Reason.
/// Unlike CONNECTION_CLOSE (0x1c), this does NOT include a Frame Type field.
pub fn decodeApplicationClose(buf: []const u8) !struct {
    error_code: u64,
    reason: []const u8,
    n: usize,
} {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.APPLICATION_CLOSE)) return error.InvalidFrameType;

    var i: usize = 1;

    // Error Code
    const ec = try varint.decode(buf[i..]);
    i += ec.n;

    // Reason Phrase Length
    const rl = try varint.decode(buf[i..]);
    i += rl.n;

    // Reason Phrase
    if (rl.value > @as(u64, buf.len - i)) return error.Truncated;
    const rlen: usize = @intCast(rl.value);
    const reason = buf[i .. i + rlen];
    i += rlen;

    return .{
        .error_code = ec.value,
        .reason = reason,
        .n = i,
    };
}

// =============================================================================
// STOP_SENDING Frame
// =============================================================================

/// Encode STOP_SENDING frame.
/// RFC 9000 §19.5: Requests peer stop sending on a stream.
pub fn writeStopSending(w: anytype, stream_id: u64, error_code: u64) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.STOP_SENDING));
    var tmp: [32]u8 = undefined;
    const idl = try varint.encode(stream_id, tmp[0..16]);
    const el = try varint.encode(error_code, tmp[idl..]);
    try w.writeAll(tmp[0 .. idl + el]);
    return 1 + idl + el;
}

/// Decode STOP_SENDING frame.
/// RFC 9000 §19.5: Format is Type (0x05) + Stream ID + Error Code.
pub fn decodeStopSending(buf: []const u8) !struct { stream_id: u64, error_code: u64, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.STOP_SENDING)) return error.InvalidFrameType;

    var i: usize = 1;

    const sid = try varint.decode(buf[i..]);
    i += sid.n;

    const ec = try varint.decode(buf[i..]);
    i += ec.n;

    return .{ .stream_id = sid.value, .error_code = ec.value, .n = i };
}

// =============================================================================
// RESET_STREAM Frame
// =============================================================================

/// Encode RESET_STREAM frame.
/// RFC 9000 §19.4: Abruptly terminates sending on a stream.
pub fn writeResetStream(w: anytype, stream_id: u64, error_code: u64, final_size: u64) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.RESET_STREAM));
    var tmp: [48]u8 = undefined;
    const idl = try varint.encode(stream_id, tmp[0..16]);
    const el = try varint.encode(error_code, tmp[idl..]);
    const fl = try varint.encode(final_size, tmp[idl + el ..]);
    try w.writeAll(tmp[0 .. idl + el + fl]);
    return 1 + idl + el + fl;
}

/// Decode RESET_STREAM frame.
/// RFC 9000 §19.4: Format is Type (0x04) + Stream ID + Error Code + Final Size.
pub fn decodeResetStream(buf: []const u8) !struct {
    stream_id: u64,
    error_code: u64,
    final_size: u64,
    n: usize,
} {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.RESET_STREAM)) return error.InvalidFrameType;

    var i: usize = 1;

    const sid = try varint.decode(buf[i..]);
    i += sid.n;

    const ec = try varint.decode(buf[i..]);
    i += ec.n;

    const fs = try varint.decode(buf[i..]);
    i += fs.n;

    return .{
        .stream_id = sid.value,
        .error_code = ec.value,
        .final_size = fs.value,
        .n = i,
    };
}
