const std = @import("std");
const frame = @import("../src/quic/frame.zig");
const varint = @import("../src/quic/varint.zig");

test "parse ping and padding" {
    var buf = [_]u8{ 0x00, 0x01 };
    var r = try frame.parse(buf[0..]);
    try std.testing.expect(std.mem.eql(u8, @tagName(r.frame), "padding"));
    r = try frame.parse(buf[1..]);
    try std.testing.expect(std.mem.eql(u8, @tagName(r.frame), "ping"));
}

test "encode+parse stream with len and fin" {
    const payload = "hi";
    var fb: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&fb);
    const f = frame.Frame{ .stream = .{ .stream_id = 4, .offset = null, .fin = true, .data = payload } };
    const n = try f.write(fbs.writer(alloc));
    const pr = try frame.parse(fb[0..n]);
    try std.testing.expect(std.mem.eql(u8, @tagName(pr.frame), "stream"));
}
