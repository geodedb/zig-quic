const std = @import("std");
const api = @import("quic_api");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    var connect: []const u8 = "127.0.0.1:4433";
    var sni: []const u8 = "test.local";
    var alpn: []const u8 = "h3";
    var insecure = false;
    var datagram = false;
    var compat_vn = false;
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--connect")) {
            connect = args.next().?;
        } else if (std.mem.eql(u8, a, "--sni")) {
            sni = args.next().?;
        } else if (std.mem.eql(u8, a, "--alpn")) {
            alpn = args.next().?;
        } else if (std.mem.eql(u8, a, "--insecure")) {
            insecure = true;
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
        .enable_datagram = datagram,
        .compatible_vn = compat_vn,
    };
    const ep = try api.endpointInit(&alloc, "0.0.0.0:0", &cfg);
    defer api.endpointDeinit(ep);

    // Establish connection (opaque handle)
    const conn = try api.connect(ep, connect, sni);

    if (datagram) {
        // Send one datagram and wait for echo
        const msg = "hello-dgram";
        try api.sendDatagram(conn, msg);
        var buf: [256]u8 = undefined;
        var attempts: usize = 0;
        while (attempts < 200) : (attempts += 1) {
            try api.poll(ep, 10);
            const n = api.recvDatagram(conn, &buf) catch 0;
            if (n > 0) {
                const out = buf[0..n];
                try std.io.getStdOut().writer().print("{s}\n", .{out});
                break;
            }
        }
    } else {
        // Just drive IO briefly
        var count: usize = 0;
        while (count < 100) : (count += 1) {
            try api.poll(ep, 10);
        }
    }
}
