const std = @import("std");
const quic = @import("quic");

fn writeIndexHtml() void {
    const cwd = std.fs.cwd();
    _ = cwd.makeDir("www") catch {};
    if (cwd.createFile("www/index.html", .{ .truncate = true })) |f| {
        defer f.close();
        _ = f.writeAll("<html>ok</html>") catch {};
    } else |_| {}
}

fn spawnServer(alloc: *std.mem.Allocator, bind: []const u8) !struct { ep: *quic.QuicEndpoint, th: std.Thread } {
    var cfg = quic.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .enable_datagram = false,
        .compatible_vn = true,
        .enable_retry = false,
        .token_secret = null,
        .token_expiry_ms = 60000,
    };
    const ep = try quic.endpointInit(alloc, bind, &cfg);
    const th = try std.Thread.spawn(.{}, struct {
        fn run(eptr: *quic.QuicEndpoint) void {
            var server = quic.h3.server.H3Server.init(std.heap.page_allocator);
            const conn = quic.accept(eptr) catch return;
            server.serveConnection(eptr, conn);
        }
    }.run, .{ep});
    return .{ .ep = ep, .th = th };
}

test "public quic exports expose server/client helpers" {
    writeIndexHtml();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var srv = try spawnServer(&alloc, "127.0.0.1:4444");
    defer quic.endpointDeinit(srv.ep);
    defer srv.th.join();

    var cfg = quic.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .enable_datagram = false,
        .compatible_vn = true,
    };
    const cli_ep = try quic.endpointInit(&alloc, "0.0.0.0:0", &cfg);
    defer quic.endpointDeinit(cli_ep);

    const conn = try quic.connect(cli_ep, "127.0.0.1:4444", "test.local");

    var out: [4096]u8 = undefined;
    const n = try quic.h3.client.h3Get(cli_ep, conn, "test.local", "/index.html", out[0..]);
    try std.testing.expect(n > 0);
}
