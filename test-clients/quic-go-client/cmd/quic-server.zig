const std = @import("std");
const quic = @import("quic_api");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: {} <bind_address:port>\n", .{args[0]});
        return;
    }

    try quic.runServer(allocator, args[1]);
}
