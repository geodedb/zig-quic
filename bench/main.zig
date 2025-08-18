const std = @import("std");
const varint = @import("quic_varint");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var timer = try std.time.Timer.start();
    var buf: [8]u8 = undefined;
    var total: usize = 0;
    const iters: usize = 100_000;
    for (0..iters) |_| {
        total += try varint.encode(16383, &buf);
    }
    const dt = timer.read();
    const per = @as(f64, @floatFromInt(dt)) / @as(f64, @floatFromInt(iters));
    _ = alloc;
    try std.io.getStdOut().writer().print("varint encode: {d} ns/op\n", .{per});
}
