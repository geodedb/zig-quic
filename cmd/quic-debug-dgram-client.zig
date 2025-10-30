const std = @import("std");
const api = @import("quic_api");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var args = try std.process.argsWithAllocator(alloc); defer args.deinit();
    _ = args.skip();
    var server: []const u8 = "127.0.0.1:4433";
    if (args.next()) |a| server = a;

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"}, .allow_insecure = true, .enable_datagram = true };
    const ep = try api.endpointInit(&alloc, "0.0.0.0:0", &cfg); defer api.endpointDeinit(ep);
    const conn = try api.connect(ep, server, "localhost");
    std.debug.print("debug-dgram-client: connecting to {s}\n", .{server});

    var loops: usize = 0;
    var sent: usize = 0;
    var buf: [1500]u8 = undefined;
    while (loops < 5000) : (loops += 1) {
        api.poll(ep, 10) catch {};
        if (sent < 5) {
            const payload = "dg" ++ [_]u8{ @intCast(u8, sent) };
            _ = api.sendDatagram(conn, &payload) catch 0;
            sent += 1;
        }
        const n = api.recvDatagram(conn, &buf) catch 0;
        if (n > 0) {
            std.debug.print("received datagram {d} bytes\n", .{n});
            if (n >= 1 and buf[0] == 'd') break; // arbitrary condition
        }
    }
    std.debug.print("debug-dgram-client: done\n", .{});
}
