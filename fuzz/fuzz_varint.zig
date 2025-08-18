const std = @import("std");
const varint = @import("quic_varint");

pub fn main() !void {
    // Simple standalone fuzzer harness compatible with libFuzzer-like runners.
    // Reads stdin to a buffer and attempts varint decode.
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const buf = try std.io.getStdIn().readToEndAlloc(alloc, 4096);
    defer alloc.free(buf);
    _ = varint.decode(buf) catch {};
}
