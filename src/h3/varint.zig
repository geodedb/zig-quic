// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Shared HTTP/3 QPACK / varint helpers.
//!
//! RFC 9000 §16 defines the variable-length integer encoding used throughout
//! QUIC and HTTP/3. This module provides encode/decode routines plus the
//! QPACK integer-prefix and indexed-static-field helpers needed by both the
//! H3 client and server.

/// Encode a QUIC varint into `out`, returning bytes written or 0 if `out` is too small.
pub fn encodeVarint(v: u64, out: []u8) usize {
    if (v < (1 << 6)) {
        if (out.len < 1) return 0;
        out[0] = @as(u8, @intCast(v)) | 0b00 << 6;
        return 1;
    } else if (v < (1 << 14)) {
        if (out.len < 2) return 0;
        out[0] = @as(u8, @intCast(v >> 8)) | 0b01 << 6;
        out[1] = @as(u8, @intCast(v & 0xff));
        return 2;
    } else if (v < (1 << 30)) {
        if (out.len < 4) return 0;
        out[0] = @as(u8, @intCast(v >> 24)) | 0b10 << 6;
        out[1] = @as(u8, @intCast((v >> 16) & 0xff));
        out[2] = @as(u8, @intCast((v >> 8) & 0xff));
        out[3] = @as(u8, @intCast(v & 0xff));
        return 4;
    } else {
        if (out.len < 8) return 0;
        out[0] = @as(u8, @intCast(v >> 56)) | 0b11 << 6;
        out[1] = @as(u8, @intCast((v >> 48) & 0xff));
        out[2] = @as(u8, @intCast((v >> 40) & 0xff));
        out[3] = @as(u8, @intCast((v >> 32) & 0xff));
        out[4] = @as(u8, @intCast((v >> 24) & 0xff));
        out[5] = @as(u8, @intCast((v >> 16) & 0xff));
        out[6] = @as(u8, @intCast((v >> 8) & 0xff));
        out[7] = @as(u8, @intCast(v & 0xff));
        return 8;
    }
}

/// Decode a QUIC varint from `h` at position `off`, advancing `off` past it.
pub fn decodeVarint(h: []const u8, off: *usize) ?u64 {
    if (off.* >= h.len) return null;
    const first = h[off.*];
    const prefix = first >> 6;
    const len: usize = switch (prefix) {
        0 => 1,
        1 => 2,
        2 => 4,
        else => 8,
    };
    if (off.* + len > h.len) return null;
    var v: u64 = 0;
    switch (len) {
        1 => v = (first & 0x3f),
        2 => v = (@as(u64, first & 0x3f) << 8) | @as(u64, h[off.* + 1]),
        4 => v = (@as(u64, first & 0x3f) << 24) | (@as(u64, h[off.* + 1]) << 16) | (@as(u64, h[off.* + 2]) << 8) | @as(u64, h[off.* + 3]),
        else => v = (@as(u64, first & 0x3f) << 56) | (@as(u64, h[off.* + 1]) << 48) | (@as(u64, h[off.* + 2]) << 40) | (@as(u64, h[off.* + 3]) << 32) |
            (@as(u64, h[off.* + 4]) << 24) | (@as(u64, h[off.* + 5]) << 16) | (@as(u64, h[off.* + 6]) << 8) | @as(u64, h[off.* + 7]),
    }
    off.* += len;
    return v;
}

/// Encode a QPACK indexed static field line (RFC 9204 §4.5.2).
pub fn encodeIndexedStatic(index: u64, out: []u8) usize {
    if (out.len == 0) return 0;
    out[0] = 0b1100_0000; // Indexed Field Line, T=1 static
    if (index < 0x3f) {
        out[0] |= @as(u8, @intCast(index));
        return 1;
    } else {
        var k: usize = 1;
        out[0] |= 0x3f;
        var rem: u64 = index - 0x3f;
        while (k < out.len) : (k += 1) {
            var b: u8 = @intCast(rem & 0x7f);
            rem >>= 7;
            if (rem != 0) b |= 0x80;
            out[k] = b;
            if (rem == 0) break;
        }
        return k;
    }
}

/// Encode an integer with a given HPACK/QPACK prefix width (RFC 7541 §5.1).
pub fn encPref(val: u64, out: []u8, prefix_bits: u3) usize {
    const max: u8 = switch (prefix_bits) {
        1 => 0x01,
        2 => 0x03,
        3 => 0x07,
        4 => 0x0f,
        5 => 0x1f,
        6 => 0x3f,
        else => 0x7f,
    };
    var k: usize = 1;
    if (val < max) {
        out[0] |= @as(u8, @intCast(val));
        return 1;
    }
    out[0] |= max;
    var rem = val - max;
    while (true) {
        var b: u8 = @intCast(rem & 0x7f);
        rem >>= 7;
        if (rem != 0) b |= 0x80;
        out[k] = b;
        k += 1;
        if (rem == 0) break;
    }
    return k;
}
