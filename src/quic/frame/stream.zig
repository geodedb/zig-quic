// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! STREAM frame for application data.
//!
//! RFC 9000 §19.8: STREAM Frame

const std = @import("std");
const types = @import("types");
const varint = @import("quic_varint");

/// STREAM frame flags (RFC 9000 §19.8)
pub const OFF: u8 = 0x04; // Offset present
pub const LEN: u8 = 0x02; // Length present
pub const FIN: u8 = 0x01; // FIN bit

/// Encode STREAM frame.
/// RFC 9000 §19.8: STREAM frames carry stream data with optional offset and FIN.
pub fn writeStream(
    w: anytype,
    stream_id: u64,
    offset: ?u64,
    fin: bool,
    data: []const u8,
) !usize {
    // Build type byte with flags
    var ty: u8 = @intFromEnum(types.FrameType.STREAM);
    if (offset != null) ty |= OFF;
    ty |= LEN; // Always include length
    if (fin) ty |= FIN;

    try w.writeByte(ty);
    var written: usize = 1;
    var tmp: [16]u8 = undefined;

    // Stream ID
    const sid_len = try varint.encode(stream_id, &tmp);
    try w.writeAll(tmp[0..sid_len]);
    written += sid_len;

    // Offset (if present)
    if (offset) |offv| {
        const off_len = try varint.encode(offv, &tmp);
        try w.writeAll(tmp[0..off_len]);
        written += off_len;
    }

    // Length (always present when LEN bit set)
    const dl = try varint.encode(data.len, &tmp);
    try w.writeAll(tmp[0..dl]);
    written += dl;

    // Data
    try w.writeAll(data);
    written += data.len;

    return written;
}

/// Decode STREAM frame, returning fields and bytes consumed.
/// RFC 9000 §19.8: Type (0x08-0x0f) + Stream ID + [Offset] + [Length] + Data
pub fn decodeStream(buf: []const u8) !struct {
    stream_id: u64,
    offset: ?u64,
    fin: bool,
    data: []const u8,
    n: usize,
} {
    if (buf.len == 0) return error.Truncated;

    const t = buf[0];
    // STREAM frames are 0x08-0x0f
    if ((t & 0xf8) != @intFromEnum(types.FrameType.STREAM)) return error.InvalidFrameType;

    // Parse flags
    const has_off = (t & OFF) != 0;
    const has_len = (t & LEN) != 0;
    const fin = (t & FIN) != 0;

    var i: usize = 1;

    // Stream ID
    const id_dec = try varint.decode(buf[i..]);
    i += id_dec.n;

    // Offset (optional)
    var off_val: ?u64 = null;
    if (has_off) {
        const off_dec = try varint.decode(buf[i..]);
        i += off_dec.n;
        off_val = off_dec.value;
    }

    // Data length and payload
    if (has_len) {
        const dl = try varint.decode(buf[i..]);
        i += dl.n;
        if (dl.value > @as(u64, buf.len - i)) return error.Truncated;
        const data_len: usize = @intCast(dl.value);
        const data = buf[i .. i + data_len];
        return .{
            .stream_id = id_dec.value,
            .offset = off_val,
            .fin = fin,
            .data = data,
            .n = i + data_len,
        };
    } else {
        // Data extends to end of packet
        const data = buf[i..];
        return .{
            .stream_id = id_dec.value,
            .offset = off_val,
            .fin = fin,
            .data = data,
            .n = buf.len,
        };
    }
}
