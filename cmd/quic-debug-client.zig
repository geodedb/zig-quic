const std = @import("std");
const api = @import("quic_api");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();
    _ = args.skip();

    var server: []const u8 = "127.0.0.1:4433";
    var insecure = false;

    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--insecure")) {
            insecure = true;
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            std.debug.print("Usage: quic-debug-client [host:port] [--insecure]\n", .{});
            std.debug.print("  --insecure  Skip TLS certificate validation (TESTING ONLY)\n", .{});
            return;
        } else {
            server = a;
        }
    }

    // Security warning when insecure mode is enabled
    if (insecure) {
        std.debug.print("\n", .{});
        std.debug.print("WARNING: TLS certificate validation DISABLED (--insecure)\n", .{});
        std.debug.print("         DO NOT use in production - connections may be intercepted!\n", .{});
        std.debug.print("\n", .{});
    }

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"}, .allow_insecure = insecure };
    const ep = try api.endpointInit(@constCast(&alloc), "0.0.0.0:0", &cfg);
    defer api.endpointDeinit(ep);
    const conn = try api.connect(ep, server, "localhost");
    std.debug.print("debug-client: connecting to {s}\n", .{server});

    var buf: [2048]u8 = undefined;
    var sent_init = false;
    var loops: usize = 0;
    while (loops < 5000) : (loops += 1) {
        api.poll(ep, 10) catch {};
        if (!sent_init) {
            const msg = "ping";
            _ = api.writeStream(conn, 0, msg, true) catch 0;
            sent_init = true;
        }
        const rn = api.readStream(conn, 0, buf[0..]) catch 0;
        if (rn > 0) {
            std.debug.print("received {d} bytes: {s}\n", .{ rn, buf[0..rn] });
            break;
        }
    }
    std.debug.print("debug-client: done\n", .{});
}
