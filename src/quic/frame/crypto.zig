// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! CRYPTO frame for TLS handshake data.
//!
//! RFC 9000 §19.6: CRYPTO Frame

const std = @import("std");
const types = @import("types");
const varint = @import("quic_varint");

/// Encode CRYPTO frame.
/// RFC 9000 §19.6: CRYPTO frames carry handshake data at a specific offset.
pub fn writeCrypto(w: anytype, offset: u64, data: []const u8) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.CRYPTO));
    var written: usize = 1;
    var tmp: [16]u8 = undefined;

    // Offset
    const off_len = try varint.encode(offset, &tmp);
    try w.writeAll(tmp[0..off_len]);
    written += off_len;

    // Length
    const len_len = try varint.encode(data.len, &tmp);
    try w.writeAll(tmp[0..len_len]);
    written += len_len;

    // Data
    try w.writeAll(data);
    written += data.len;

    return written;
}

/// Decode CRYPTO frame, returning offset, data slice, and bytes consumed.
/// RFC 9000 §19.6: Format is Type (0x06) + Offset (varint) + Length (varint) + Data.
pub fn decodeCrypto(buf: []const u8) !struct { offset: u64, data: []const u8, n: usize } {
    if (buf.len == 0) return error.Truncated;
    if (buf[0] != @intFromEnum(types.FrameType.CRYPTO)) return error.InvalidFrameType;

    var i: usize = 1;

    // Offset
    const off_dec = try varint.decode(buf[i..]);
    i += off_dec.n;

    // Length
    const len_dec = try varint.decode(buf[i..]);
    i += len_dec.n;

    // Validate we have enough data
    if (len_dec.value > @as(u64, buf.len - i)) return error.Truncated;

    const need: usize = i + @as(usize, @intCast(len_dec.value));
    const data = buf[i..need];

    return .{
        .offset = off_dec.value,
        .data = data,
        .n = need,
    };
}
