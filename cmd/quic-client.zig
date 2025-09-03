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
    var msg: []const u8 = "hello";
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
        } else if (std.mem.eql(u8, a, "--msg")) {
            msg = args.next().?;
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

    const conn = try api.connect(ep, connect, sni);

    if (datagram) {
        try api.sendDatagram(conn, msg);
        var buf: [1024]u8 = undefined;
        var attempts: usize = 0;
        while (attempts < 500) : (attempts += 1) {
            try api.poll(ep, 10);
            const n = api.recvDatagram(conn, &buf) catch 0;
            if (n > 0) {
                try std.io.getStdOut().writer().print("dgram: {s}\n", .{buf[0..n]});
                return;
            }
        }
        return;
    }

    // stream echo on client-initiated stream 0: write then read
    var wrote: bool = false;
    var attempts: usize = 0;
    while (!wrote and attempts < 1000) : (attempts += 1) {
        // try to write; if keys not ready, poll and retry
        const wn = api.writeStream(conn, 0, msg) catch |err| switch (err) {
            error.KeysNotReady => blk: { try api.poll(ep, 10); break :blk 0; },
            error.OutOfStreams => blk2: { try api.poll(ep, 10); break :blk2 0; },
            error.FlowControlBlocked => blk3: { try api.poll(ep, 10); break :blk3 0; },
            else => return err,
        };
        if (wn > 0) wrote = true;
        if (!wrote) try api.poll(ep, 10);
    }
    var rbuf: [4096]u8 = undefined;
    var total: usize = 0;
    var polls: usize = 0;
    while (polls < 1000 and total == 0) : (polls += 1) {
        try api.poll(ep, 10);
        const n = api.readStream(conn, 0, rbuf[0..]) catch 0;
        if (n > 0) total = n;
    }
    if (total > 0) {
        try std.io.getStdOut().writer().print("echo: {s}\n", .{rbuf[0..total]});
    }
}
