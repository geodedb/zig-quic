// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Flow control frames: MAX_* frames and *_BLOCKED frames.
//!
//! RFC 9000 §19.10: MAX_DATA Frame
//! RFC 9000 §19.11: MAX_STREAM_DATA Frame
//! RFC 9000 §19.12: MAX_STREAMS Frame
//! RFC 9000 §19.13: DATA_BLOCKED Frame
//! RFC 9000 §19.14: STREAM_DATA_BLOCKED Frame
//! RFC 9000 §4: Flow Control

const std = @import("std");
const types = @import("types");
const varint = @import("quic_varint");

// =============================================================================
// MAX_DATA Frame
// =============================================================================

/// Encode MAX_DATA frame.
/// RFC 9000 §19.10: Informs peer of connection-level flow control limit.
pub fn writeMaxData(w: anytype, max: u64) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.MAX_DATA));
    var tmp: [16]u8 = undefined;
    const ml = try varint.encode(max, &tmp);
    try w.writeAll(tmp[0..ml]);
    return 1 + ml;
}

/// Decode MAX_DATA frame.
/// RFC 9000 §19.10: Format is Type (0x10) + Maximum Data (varint).
pub fn decodeMaxData(buf: []const u8) !struct { max: u64, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.MAX_DATA)) return error.InvalidFrameType;

    var i: usize = 1;
    const max = try varint.decode(buf[i..]);
    i += max.n;

    return .{ .max = max.value, .n = i };
}

// =============================================================================
// MAX_STREAM_DATA Frame
// =============================================================================

/// Encode MAX_STREAM_DATA frame.
/// RFC 9000 §19.11: Informs peer of stream-level flow control limit.
pub fn writeMaxStreamData(w: anytype, stream_id: u64, max: u64) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.MAX_STREAM_DATA));
    var tmp: [24]u8 = undefined;
    const idl = try varint.encode(stream_id, tmp[0..16]);
    const ml = try varint.encode(max, tmp[idl..]);
    try w.writeAll(tmp[0 .. idl + ml]);
    return 1 + idl + ml;
}

/// Decode MAX_STREAM_DATA frame.
/// RFC 9000 §19.11: Format is Type (0x11) + Stream ID + Maximum Data.
pub fn decodeMaxStreamData(buf: []const u8) !struct { stream_id: u64, max: u64, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.MAX_STREAM_DATA)) return error.InvalidFrameType;

    var i: usize = 1;

    const sid = try varint.decode(buf[i..]);
    i += sid.n;

    const max = try varint.decode(buf[i..]);
    i += max.n;

    return .{ .stream_id = sid.value, .max = max.value, .n = i };
}

// =============================================================================
// MAX_STREAMS Frames
// =============================================================================

/// Encode MAX_STREAMS (bidirectional) frame.
/// RFC 9000 §19.12: Informs peer of maximum number of bidirectional streams.
pub fn writeMaxStreamsBidi(w: anytype, max: u64) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.MAX_STREAMS_BIDI));
    var tmp: [16]u8 = undefined;
    const ml = try varint.encode(max, &tmp);
    try w.writeAll(tmp[0..ml]);
    return 1 + ml;
}

/// Decode MAX_STREAMS (bidirectional) frame.
/// RFC 9000 §19.12: Format is Type (0x12) + Maximum Streams (varint).
pub fn decodeMaxStreamsBidi(buf: []const u8) !struct { max: u64, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.MAX_STREAMS_BIDI)) return error.InvalidFrameType;

    var i: usize = 1;
    const max = try varint.decode(buf[i..]);
    i += max.n;

    return .{ .max = max.value, .n = i };
}

/// Encode MAX_STREAMS (unidirectional) frame.
/// RFC 9000 §19.12: Informs peer of maximum number of unidirectional streams.
pub fn writeMaxStreamsUni(w: anytype, max: u64) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.MAX_STREAMS_UNI));
    var tmp: [16]u8 = undefined;
    const ml = try varint.encode(max, &tmp);
    try w.writeAll(tmp[0..ml]);
    return 1 + ml;
}

/// Decode MAX_STREAMS (unidirectional) frame.
/// RFC 9000 §19.12: Format is Type (0x13) + Maximum Streams (varint).
pub fn decodeMaxStreamsUni(buf: []const u8) !struct { max: u64, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.MAX_STREAMS_UNI)) return error.InvalidFrameType;

    var i: usize = 1;
    const max = try varint.decode(buf[i..]);
    i += max.n;

    return .{ .max = max.value, .n = i };
}

// =============================================================================
// DATA_BLOCKED Frame
// =============================================================================

/// Encode DATA_BLOCKED frame.
/// RFC 9000 §19.13: Indicates sender is blocked due to connection flow control.
pub fn writeDataBlocked(w: anytype, limit: u64) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.DATA_BLOCKED));
    var tmp: [16]u8 = undefined;
    const ml = try varint.encode(limit, &tmp);
    try w.writeAll(tmp[0..ml]);
    return 1 + ml;
}

/// Decode DATA_BLOCKED frame.
/// RFC 9000 §19.13: Format is Type (0x14) + Data Limit (varint).
pub fn decodeDataBlocked(buf: []const u8) !struct { limit: u64, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.DATA_BLOCKED)) return error.InvalidFrameType;

    var i: usize = 1;
    const lim = try varint.decode(buf[i..]);
    i += lim.n;

    return .{ .limit = lim.value, .n = i };
}

// =============================================================================
// STREAM_DATA_BLOCKED Frame
// =============================================================================

/// Encode STREAM_DATA_BLOCKED frame.
/// RFC 9000 §19.14: Indicates sender is blocked due to stream flow control.
pub fn writeStreamDataBlocked(w: anytype, stream_id: u64, limit: u64) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.STREAM_DATA_BLOCKED));
    var tmp: [24]u8 = undefined;
    const idl = try varint.encode(stream_id, tmp[0..16]);
    const ml = try varint.encode(limit, tmp[idl..]);
    try w.writeAll(tmp[0 .. idl + ml]);
    return 1 + idl + ml;
}

/// Decode STREAM_DATA_BLOCKED frame.
/// RFC 9000 §19.14: Format is Type (0x15) + Stream ID + Stream Data Limit.
pub fn decodeStreamDataBlocked(buf: []const u8) !struct { stream_id: u64, limit: u64, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.STREAM_DATA_BLOCKED)) return error.InvalidFrameType;

    var i: usize = 1;

    const sid = try varint.decode(buf[i..]);
    i += sid.n;

    const lim = try varint.decode(buf[i..]);
    i += lim.n;

    return .{ .stream_id = sid.value, .limit = lim.value, .n = i };
}

// =============================================================================
// STREAMS_BLOCKED Frames
// =============================================================================

/// Encode STREAMS_BLOCKED (bidirectional) frame.
/// RFC 9000 §19.14: Indicates sender is blocked due to stream limit.
pub fn writeStreamsBlockedBidi(w: anytype, max: u64) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.STREAMS_BLOCKED_BIDI));
    var tmp: [16]u8 = undefined;
    const ml = try varint.encode(max, &tmp);
    try w.writeAll(tmp[0..ml]);
    return 1 + ml;
}

/// Decode STREAMS_BLOCKED (bidirectional) frame.
/// RFC 9000 §19.14: Format is Type (0x16) + Stream Limit (varint).
pub fn decodeStreamsBlockedBidi(buf: []const u8) !struct { max: u64, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.STREAMS_BLOCKED_BIDI)) return error.InvalidFrameType;

    var i: usize = 1;
    const max = try varint.decode(buf[i..]);
    i += max.n;

    return .{ .max = max.value, .n = i };
}

/// Encode STREAMS_BLOCKED (unidirectional) frame.
/// RFC 9000 §19.14: Indicates sender is blocked due to stream limit.
pub fn writeStreamsBlockedUni(w: anytype, max: u64) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.STREAMS_BLOCKED_UNI));
    var tmp: [16]u8 = undefined;
    const ml = try varint.encode(max, &tmp);
    try w.writeAll(tmp[0..ml]);
    return 1 + ml;
}

/// Decode STREAMS_BLOCKED (unidirectional) frame.
/// RFC 9000 §19.14: Format is Type (0x17) + Stream Limit (varint).
pub fn decodeStreamsBlockedUni(buf: []const u8) !struct { max: u64, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.STREAMS_BLOCKED_UNI)) return error.InvalidFrameType;

    var i: usize = 1;
    const max = try varint.decode(buf[i..]);
    i += max.n;

    return .{ .max = max.value, .n = i };
}
