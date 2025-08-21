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
    var datagram = false;
    var compat_vn = false;
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
        } else if (std.mem.eql(u8, a, "--datagram")) {
            const v = args.next().?;
            datagram = std.mem.eql(u8, v, "true");
        } else if (std.mem.eql(u8, a, "--compatible-vn")) {
            compat_vn = true;
        }
    }

    var cfg = api.QuicConfig{
        .alpn = &[_][]const u8{alpn},
        .allow_insecure = insecure,
        .cert_path = cert_path,
        .key_path = key_path,
        .enable_datagram = datagram,
        .compatible_vn = compat_vn,
    };
    const ep = try api.endpointInit(&alloc, bind, &cfg);
    defer api.endpointDeinit(ep);

    // Minimal loop: just poll with a timeout to drive timers/IO.
    while (true) {
        try api.poll(ep, 10);
    }
}
