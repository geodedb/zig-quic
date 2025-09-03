const std = @import("std");
const api = @import("quic_api");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    var bind: []const u8 = "127.0.0.1:4433";
    var alpn: []const u8 = "h3";
    var insecure = false;
    var cert_path: ?[]const u8 = null;
    var key_path: ?[]const u8 = null;
    
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--bind")) {
            bind = args.next().?;
        } else if (std.mem.eql(u8, a, "--alpn")) {
            alpn = args.next().?;
        } else if (std.mem.eql(u8, a, "--insecure")) {
            insecure = true;
        } else if (std.mem.eql(u8, a, "--cert")) {
            cert_path = args.next().?;
        } else if (std.mem.eql(u8, a, "--key")) {
            key_path = args.next().?;
        }
    }

    var cfg = api.QuicConfig{
        .alpn = &[_][]const u8{alpn},
        .allow_insecure = insecure,
        .cert_path = cert_path,
        .key_path = key_path,
    };
    
    const ep = try api.endpointInit(&alloc, bind, &cfg);
    defer api.endpointDeinit(ep);

    std.debug.print("Server listening on {s}\n", .{bind});

    // Accept connections in a loop
    while (true) {
        // Poll to process incoming packets
        try api.poll(ep, 10);
        
        // Check if there's an accepted connection
        if (ep.popAccepted()) |conn| {
            std.debug.print("Accepted connection\n", .{});
            // For now, just acknowledge we got a connection
            // In a real server, we'd handle streams here
        }
    }
}