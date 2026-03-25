// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Miscellaneous QUIC frames: PADDING, PING, NEW_TOKEN, HANDSHAKE_DONE
//!
//! RFC 9000 §19.1: PADDING Frame
//! RFC 9000 §19.2: PING Frame
//! RFC 9000 §19.7: NEW_TOKEN Frame
//! RFC 9000 §19.20: HANDSHAKE_DONE Frame

const std = @import("std");
const types = @import("types");
const varint = @import("quic_varint");

/// RFC 9000 §14: Recommended minimum QUIC packet size for Initial packets.
/// CWE-770 mitigation: Bound padding to prevent amplification attacks.
pub const MIN_INITIAL_PACKET_SIZE: usize = 1200;

/// Absolute maximum packet size (64KB UDP limit).
/// Used as a sanity check upper bound.
pub const MAX_PACKET_SIZE: usize = 65535;

/// Encode PADDING frame (one or more 0x00 bytes) with bounds checking.
/// RFC 9000 §19.1: PADDING frames increase packet size for PMTU discovery.
/// CWE-770 mitigation: Use writePaddingBounded for explicit size limits.
pub fn writePadding(w: anytype, count: usize) !usize {
    // Sanity check: reject obviously excessive padding requests
    if (count > MAX_PACKET_SIZE) {
        return error.PaddingTooLarge;
    }
    if (count == 0) return 0;
    var n: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        try w.writeByte(@intFromEnum(types.FrameType.PADDING));
        n += 1;
    }
    return n;
}

/// Encode PADDING frame with explicit maximum size limit.
/// RFC 9000 §14 recommends packets should not exceed 1200 bytes without PMTU discovery.
/// CWE-770 mitigation: Enforces caller-specified bounds on padding.
///
/// Parameters:
///   - w: Writer to write padding bytes to
///   - count: Requested number of padding bytes
///   - current_size: Current packet size before padding
///   - max_size: Maximum allowed packet size (default 1200)
///
/// Returns:
///   - Number of padding bytes actually written (may be less than requested if bounded)
///   - error.PaddingTooLarge if current_size already exceeds max_size
pub fn writePaddingBounded(w: anytype, count: usize, current_size: usize, max_size: usize) !usize {
    if (current_size >= max_size) {
        return error.PaddingTooLarge;
    }

    const available = max_size - current_size;
    const actual_count = @min(count, available);

    if (actual_count == 0) return 0;

    var n: usize = 0;
    var i: usize = 0;
    while (i < actual_count) : (i += 1) {
        try w.writeByte(@intFromEnum(types.FrameType.PADDING));
        n += 1;
    }
    return n;
}

/// Decode contiguous PADDING frames, returning count and bytes consumed.
/// RFC 9000 §19.1: Multiple PADDING frames may appear consecutively.
pub fn decodePadding(buf: []const u8) !struct { count: usize, n: usize } {
    var i: usize = 0;
    while (i < buf.len and buf[i] == @intFromEnum(types.FrameType.PADDING)) : (i += 1) {}
    return .{ .count = i, .n = i };
}

/// Encode PING frame (single 0x01 byte).
/// RFC 9000 §19.2: PING frames check reachability and reset idle timeout.
pub fn writePing(w: anytype) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.PING));
    return 1;
}

/// Decode PING frame.
/// RFC 9000 §19.2: PING frame has no payload.
pub fn decodePing(buf: []const u8) !struct { n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.PING)) return error.InvalidFrameType;
    return .{ .n = 1 };
}

/// Encode NEW_TOKEN frame.
/// RFC 9000 §19.7: Server sends NEW_TOKEN for future address validation.
pub fn writeNewToken(w: anytype, token: []const u8) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.NEW_TOKEN));
    var tmp: [16]u8 = undefined;
    const tl = try varint.encode(token.len, &tmp);
    try w.writeAll(tmp[0..tl]);
    try w.writeAll(token);
    return 1 + tl + token.len;
}

/// Decode NEW_TOKEN frame, returning token slice and bytes consumed.
/// RFC 9000 §19.7: Token is opaque byte sequence.
pub fn decodeNewToken(buf: []const u8) !struct { token: []const u8, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.NEW_TOKEN)) return error.InvalidFrameType;
    var i: usize = 1;
    const dl = try varint.decode(buf[i..]);
    i += dl.n;
    if (dl.value > @as(u64, buf.len - i)) return error.Truncated;
    const nbytes: usize = @intCast(dl.value);
    const tok = buf[i .. i + nbytes];
    return .{ .token = tok, .n = i + nbytes };
}

/// Encode HANDSHAKE_DONE frame.
/// RFC 9000 §19.20: Server signals handshake completion to client.
pub fn writeHandshakeDone(w: anytype) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.HANDSHAKE_DONE));
    return 1;
}

/// Decode HANDSHAKE_DONE frame.
/// RFC 9000 §19.20: HANDSHAKE_DONE has no payload.
pub fn decodeHandshakeDone(buf: []const u8) !struct { n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.HANDSHAKE_DONE)) return error.InvalidFrameType;
    return .{ .n = 1 };
}
