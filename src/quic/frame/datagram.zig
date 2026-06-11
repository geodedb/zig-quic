// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DATAGRAM frame for unreliable datagrams.
//!
//! RFC 9221: An Unreliable Datagram Extension to QUIC

const std = @import("std");
const types = @import("types");
const varint = @import("quic_varint");

/// Encode DATAGRAM frame.
/// RFC 9221 §4: emit the length-prefixed form (type 0x31) so the frame is
/// self-delimiting and may be coalesced with other frames. The 0x30 form (no
/// length, data to end of packet) is only valid as the last frame; the
/// length-prefixed form is always valid, so we always use it on the wire.
pub fn writeDatagram(w: anytype, data: []const u8) !usize {
    try w.writeByte(@intFromEnum(types.FrameType.DATAGRAM_LEN));
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

/// Decode a DATAGRAM frame, returning the data slice and bytes consumed.
/// RFC 9221 §4: the type's low bit (LEN) selects the format —
///   0x30 (LEN=0): no Length field; data runs to the end of the buffer/packet.
///   0x31 (LEN=1): an explicit Length varint precedes the data.
pub fn decodeDatagram(buf: []const u8) !struct { data: []const u8, n: usize } {
    if (buf.len == 0) return error.Truncated;
    const t = buf[0];
    if (t != @intFromEnum(types.FrameType.DATAGRAM) and
        t != @intFromEnum(types.FrameType.DATAGRAM_LEN))
    {
        return error.InvalidFrameType;
    }

    var i: usize = 1;
    const has_length = (t & 0x01) != 0; // 0x31

    if (!has_length) {
        // 0x30: data extends to the end of the QUIC packet (the rest of buf).
        return .{ .data = buf[i..], .n = buf.len };
    }

    const dl = try varint.decode(buf[i..]);
    i += dl.n;
    if (dl.value > @as(u64, buf.len - i)) return error.Truncated;
    const nbytes: usize = @intCast(dl.value);
    return .{ .data = buf[i .. i + nbytes], .n = i + nbytes };
}
