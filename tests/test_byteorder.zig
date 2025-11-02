const std = @import("std");
const byteorder = @import("byteorder");

test "encode/decode big-endian u32 round-trip" {
    var buf: [4]u8 = undefined;
    const rest = try byteorder.encode(u32, .big, @as(u32, 0x10203040), buf[0..]);
    try std.testing.expectEqual(@as(usize, 0), rest.len);

    const decoded = try byteorder.decode(u32, .big, buf[0..]);
    try std.testing.expectEqual(@as(u32, 0x10203040), decoded.value);
    try std.testing.expectEqual(@as(usize, 0), decoded.rest.len);
}

test "encode/decode little-endian u64 round-trip" {
    var buf: [8]u8 = undefined;
    _ = try byteorder.encode(u64, .little, @as(u64, 0x0f1e2d3c4b5a6978), buf[0..]);
    const decoded = try byteorder.decode(u64, .little, buf[0..]);
    try std.testing.expectEqual(@as(u64, 0x0f1e2d3c4b5a6978), decoded.value);
}

test "toEndian/fromEndian value helpers" {
    const be_u16 = byteorder.toEndian(u16, .big, 0x1234);
    try std.testing.expectEqual(@as(u16, 0x1234), byteorder.fromEndian(u16, .big, be_u16));

    const le_i32 = byteorder.toEndian(i32, .little, -0x01020304);
    try std.testing.expectEqual(@as(i32, -0x01020304), byteorder.fromEndian(i32, .little, le_i32));
}

test "encode/decode signed big-endian i16" {
    var buf: [2]u8 = undefined;
    _ = try byteorder.encode(i16, .big, @as(i16, -12345), buf[0..]);
    const decoded = try byteorder.decode(i16, .big, buf[0..]);
    try std.testing.expectEqual(@as(i16, -12345), decoded.value);
}

test "encode returns slice remainder" {
    var buf: [6]u8 = undefined;
    const rest = try byteorder.encode(u16, .little, @as(u16, 0x7788), buf[0..]);
    try std.testing.expect(rest.ptr == buf[2..].ptr);
    try std.testing.expectEqual(@as(usize, 4), rest.len);
}

test "decode returns slice remainder" {
    const data = [_]u8{ 0x12, 0x34, 0xaa, 0xbb, 0xcc };
    const decoded = try byteorder.decode(u16, .big, data[0..]);
    try std.testing.expectEqual(@as(u16, 0x1234), decoded.value);
    try std.testing.expect(decoded.rest.ptr == data[2..].ptr);
    try std.testing.expectEqual(@as(usize, 3), decoded.rest.len);
}

test "encode detects insufficient buffer" {
    var buf: [1]u8 = undefined;
    try std.testing.expectError(byteorder.Error.BufferTooSmall, byteorder.encode(u32, .big, @as(u32, 1), buf[0..]));
}

test "decode detects insufficient data" {
    const data = [_]u8{0x00};
    try std.testing.expectError(byteorder.Error.BufferTooShort, byteorder.decode(u32, .big, data[0..]));
}
