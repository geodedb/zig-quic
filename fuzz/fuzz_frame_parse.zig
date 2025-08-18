const std = @import("std");
const frame = @import("../src/quic/frame.zig");
const varint = @import("../src/quic/varint.zig");

// Minimal parser for the subset we write (padding/ping/stream)
fn parseFrame(data: []const u8) void {
    if (data.len == 0) return;
    const t = data[0];
    switch (t) {
        0x00, 0x01 => return, // padding/ping
        0x08...0x0f => {
            const off: usize = 1;
            _ = varint.decode(data[off..]) catch return; // stream_id
        },
        else => return,
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const buf = try std.io.getStdIn().readToEndAlloc(alloc, 4096);
    defer alloc.free(buf);
    parseFrame(buf);
}
