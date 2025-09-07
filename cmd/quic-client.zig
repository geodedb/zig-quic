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
    var real_tls = false;
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
        } else if (std.mem.eql(u8, a, "--real-tls")) {
            real_tls = true;
        }
    }

    var cfg = api.QuicConfig{
        .alpn = &[_][]const u8{alpn},
        .allow_insecure = insecure,
        .enable_datagram = datagram,
        .compatible_vn = compat_vn,
        .real_tls = real_tls,
    };
    const ep = try api.endpointInit(&alloc, "0.0.0.0:0", &cfg);
    defer api.endpointDeinit(ep);

    const conn = try api.connect(ep, connect, sni);
    std.debug.print("connecting to {s}\n", .{connect});

    if (datagram) {
        try api.sendDatagram(conn, msg);
        var buf: [1024]u8 = undefined;
        var attempts: usize = 0;
        while (attempts < 500) : (attempts += 1) {
            try api.poll(ep, 10);
            const n = api.recvDatagram(conn, &buf) catch 0;
            if (n > 0) {
                std.debug.print("dgram: {s}\n", .{buf[0..n]});
                return;
            }
        }
        return;
    }

    // stream echo on client-initiated stream 0: write then read
    var wrote: bool = false;
    var attempts: usize = 0;
    while (!wrote and attempts < 5000) : (attempts += 1) {
        // Require HANDSHAKE_DONE before sending application data to reduce early loss risk.
        if (!api.handshakeDoneSeen(conn)) {
            try api.poll(ep, 10);
            continue;
        }
        // try to write; if keys not ready, poll and retry
        const wn = api.writeStream(conn, 0, msg) catch |err| switch (err) {
            error.KeysNotReady => blk: {
                // Drive timers and inbound CRYPTO while waiting for keys to be ready.
                // We deliberately avoid calling api.isHandshakeConfirmed() here to
                // prevent dereferencing a potentially stale connection pointer.  The
                // client will simply continue polling until writeStream succeeds.
                try api.poll(ep, 10);
                break :blk 0;
            },
            error.OutOfStreams => blk2: {
                try api.poll(ep, 10);
                break :blk2 0;
            },
            error.FlowControlBlocked => blk3: {
                try api.poll(ep, 10);
                break :blk3 0;
            },
            else => return err,
        };
        if (wn > 0) wrote = true;
        if (!wrote) try api.poll(ep, 10);
    }
    if (wrote) std.debug.print("wrote initial message on stream 0 ({d} bytes)\n", .{msg.len});
    var rbuf: [4096]u8 = undefined;
    var total: usize = 0;
    var polls: usize = 0;
    while (polls < 5000 and total == 0) : (polls += 1) {
        try api.poll(ep, 10);
        const n = api.readStream(conn, 0, rbuf[0..]) catch 0;
        if (n > 0) total = n;
    }
    if (total > 0) {
        std.debug.print("echo: {s}\n", .{rbuf[0..total]});
        std.debug.print("received echo ({d} bytes)\n", .{total});
    }
    // Attempt graceful close so any pending allocation owned by connection is released before endpoint deinit.
    api.close(conn, 0, "bye") catch {};
    // Drive a few polls to flush CONNECTION_CLOSE
    api.flush(ep, 5);
    var spins: usize = 0;
    while (spins < 50 and !api.isDrained(conn)) : (spins += 1) {
        api.poll(ep, 5) catch break;
    }
    api.destroy(ep, conn);
}
