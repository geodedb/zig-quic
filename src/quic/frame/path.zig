// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! PATH_CHALLENGE and PATH_RESPONSE frames for path validation.
//!
//! RFC 9000 §19.17: PATH_CHALLENGE Frame
//! RFC 9000 §19.18: PATH_RESPONSE Frame
//! RFC 9000 §9: Connection Migration and Path Validation

const std = @import("std");
const types = @import("types");

/// Encode PATH_CHALLENGE frame.
/// RFC 9000 §19.17: PATH_CHALLENGE carries 8 random bytes for path validation.
pub fn writePathChallenge(w: anytype, data: [8]u8) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.PATH_CHALLENGE));
    try w.writeAll(&data);
    return 1 + 8;
}

/// Decode PATH_CHALLENGE frame, returning 8-byte data and bytes consumed.
/// RFC 9000 §19.17: Format is Type (0x1a) + Data (8 bytes).
pub fn decodePathChallenge(buf: []const u8) !struct { data: [8]u8, n: usize } {
    if (buf.len < 1 + 8) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.PATH_CHALLENGE)) return error.InvalidFrameType;

    var data: [8]u8 = undefined;
    @memcpy(&data, buf[1 .. 1 + 8]);

    return .{ .data = data, .n = 1 + 8 };
}

/// Encode PATH_RESPONSE frame.
/// RFC 9000 §19.18: PATH_RESPONSE echoes PATH_CHALLENGE data to validate path.
pub fn writePathResponse(w: anytype, data: [8]u8) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.PATH_RESPONSE));
    try w.writeAll(&data);
    return 1 + 8;
}

/// Decode PATH_RESPONSE frame, returning 8-byte data and bytes consumed.
/// RFC 9000 §19.18: Format is Type (0x1b) + Data (8 bytes).
pub fn decodePathResponse(buf: []const u8) !struct { data: [8]u8, n: usize } {
    if (buf.len < 1 + 8) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.PATH_RESPONSE)) return error.InvalidFrameType;

    var data: [8]u8 = undefined;
    @memcpy(&data, buf[1 .. 1 + 8]);

    return .{ .data = data, .n = 1 + 8 };
}
