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
    var enable_retry = false;
    var token_secret: ?[]const u8 = null;
    var token_expiry_ms: u32 = 60000;
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
        } else if (std.mem.eql(u8, a, "--retry")) {
            const v = args.next().?;
            enable_retry = std.mem.eql(u8, v, "true");
        } else if (std.mem.eql(u8, a, "--token-secret")) {
            token_secret = args.next().?;
        } else if (std.mem.eql(u8, a, "--token-expiry-ms")) {
            const v = args.next().?;
            token_expiry_ms = std.fmt.parseInt(u32, v, 10) catch token_expiry_ms;
        }
    }

    var cfg = api.QuicConfig{
        .alpn = &[_][]const u8{alpn},
        .allow_insecure = insecure,
        .cert_path = cert_path,
        .key_path = key_path,
        .enable_datagram = datagram,
        .compatible_vn = compat_vn,
        .enable_retry = enable_retry,
        .token_secret = token_secret,
        .token_expiry_ms = token_expiry_ms,
    };
    const ep = try api.endpointInit(&alloc, bind, &cfg);
    defer api.endpointDeinit(ep);

    std.debug.print("listening on {s}\n", .{bind});

    while (true) {
        try api.poll(ep, 10);
        if (api.accept(ep) catch null) |conn| {
            std.debug.print("accepted connection\n", .{});
            var stream_opened = false;
            var dgram_buf: [2048]u8 = undefined;
            var buf: [4096]u8 = undefined;
            var iter: usize = 0;
            while (iter < 10000) : (iter += 1) {
                try api.poll(ep, 5);
                if (datagram) {
                    const dn = api.recvDatagram(conn, &dgram_buf) catch 0;
                    if (dn > 0) {
                        _ = api.sendDatagram(conn, dgram_buf[0..dn]) catch 0;
                    }
                }
                if (!stream_opened) {
                    // Client-initiated bidi stream 0
                    const n = api.readStream(conn, 0, buf[0..]) catch 0;
                    if (n > 0) {
                        stream_opened = true;
                        _ = api.writeStream(conn, 0, buf[0..n]) catch 0;
                    }
                } else {
                    const n = api.readStream(conn, 0, buf[0..]) catch 0;
                    if (n > 0) {
                        _ = api.writeStream(conn, 0, buf[0..n]) catch 0;
                    }
                }
            }
        }
    }
}
