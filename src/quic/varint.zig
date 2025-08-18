// MIT License
// QUIC varint utilities (RFC 9000 §16)
const std = @import("std");

/// Errors for varint encoding/decoding.
pub const Error = error{ Truncated, Overflow };

/// Decode a QUIC varint from the front of data. Returns bytes consumed and value.
pub fn decode(data: []const u8) Error!struct { n: usize, value: u64 } {
    if (data.len == 0) return Error.Truncated;
    const first = data[0];
    const prefix = first >> 6;
    const len: usize = switch (prefix) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (data.len < len) return Error.Truncated;
    var v: u64 = 0;
    switch (len) {
        1 => v = (first & 0x3f),
        2 => v = (@as(u64, first & 0x3f) << 8) | @as(u64, data[1]),
        4 => v = (@as(u64, first & 0x3f) << 24) | (@as(u64, data[1]) << 16) | (@as(u64, data[2]) << 8) | @as(u64, data[3]),
        8 => v = (@as(u64, first & 0x3f) << 56) | (@as(u64, data[1]) << 48) | (@as(u64, data[2]) << 40) | (@as(u64, data[3]) << 32) |
            (@as(u64, data[4]) << 24) | (@as(u64, data[5]) << 16) | (@as(u64, data[6]) << 8) | @as(u64, data[7]),
        else => unreachable,
    }
    return .{ .n = len, .value = v };
}

/// Encode value using QUIC varint into out. Returns bytes written.
pub fn encode(value: u64, out: []u8) Error!usize {
    if (value > ((1 << 62) - 1)) return Error.Overflow;
    const len: usize = if (value < (1 << 6)) 1 else if (value < (1 << 14)) 2 else if (value < (1 << 30)) 4 else 8;
    if (out.len < len) return Error.Truncated;
    const toU8 = struct {
        fn f(v: u64) u8 {
            return @as(u8, @intCast(v));
        }
    }.f;
    switch (len) {
        1 => out[0] = toU8(value) | @as(u8, 0b00 << 6),
        2 => {
            out[0] = toU8((value >> 8) & 0x3f) | @as(u8, 0b01 << 6);
            out[1] = toU8(value & 0xff);
        },
        4 => {
            out[0] = toU8((value >> 24) & 0x3f) | @as(u8, 0b10 << 6);
            out[1] = toU8((value >> 16) & 0xff);
            out[2] = toU8((value >> 8) & 0xff);
            out[3] = toU8(value & 0xff);
        },
        8 => {
            out[0] = toU8((value >> 56) & 0x3f) | @as(u8, 0b11 << 6);
            out[1] = toU8((value >> 48) & 0xff);
            out[2] = toU8((value >> 40) & 0xff);
            out[3] = toU8((value >> 32) & 0xff);
            out[4] = toU8((value >> 24) & 0xff);
            out[5] = toU8((value >> 16) & 0xff);
            out[6] = toU8((value >> 8) & 0xff);
            out[7] = toU8(value & 0xff);
        },
        else => unreachable,
    }
    return len;
}
