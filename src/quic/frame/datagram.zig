// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DATAGRAM frame for unreliable datagrams.
//!
//! RFC 9221: An Unreliable Datagram Extension to QUIC

const std = @import("std");
const types = @import("types");
const varint = @import("quic_varint");

/// Encode DATAGRAM frame.
/// RFC 9221: DATAGRAM frames carry application data without reliability guarantees.
pub fn writeDatagram(w: anytype, data: []const u8) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.DATAGRAM));
    var written: usize = 1;
    var tmp: [16]u8 = undefined;

    // Length (varint)
    const dl = try varint.encode(data.len, &tmp);
    try w.writeAll(tmp[0..dl]);
    written += dl;

    // Data
    try w.writeAll(data);
    written += data.len;

    return written;
}

/// Decode DATAGRAM frame, returning data slice and bytes consumed.
/// RFC 9221: Format is Type (0x30) + Length (varint) + Data.
pub fn decodeDatagram(buf: []const u8) !struct { data: []const u8, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.DATAGRAM)) return error.InvalidFrameType;

    var i: usize = 1;

    // Length
    const dl = try varint.decode(buf[i..]);
    i += dl.n;

    // Validate we have enough data
    if (dl.value > @as(u64, buf.len - i)) return error.Truncated;

    const nbytes: usize = @intCast(dl.value);
    const data = buf[i .. i + nbytes];

    return .{
        .data = data,
        .n = i + nbytes,
    };
}
