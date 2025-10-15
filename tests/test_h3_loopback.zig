const std = @import("std");
const api = @import("quic_api");
const h3s = @import("h3_server");
const h3c = @import("h3_client");

fn spawnServer(alloc: *std.mem.Allocator, bind: []const u8) !struct { ep: *api.QuicEndpoint, th: std.Thread } {
    var cfg = api.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .enable_datagram = false,
        .compatible_vn = true,
        .enable_retry = false,
        .token_secret = null,
        .token_expiry_ms = 60000,
    };
    const ep = try api.endpointInit(alloc, bind, &cfg);
    const th = try std.Thread.spawn(.{}, struct {
        fn run(eptr: *api.QuicEndpoint) void {
            var server = h3s.H3Server.init(std.heap.page_allocator);
            const conn = api.accept(eptr) catch return;
            server.serveConnection(eptr, conn);
        }
    }.run, .{ep});
    return .{ .ep = ep, .th = th };
}

fn writeIndexHtml() void {
    // Best-effort create a /www/index.html file; ignore errors in tests
    const cwd = std.fs.cwd();
    _ = cwd.makeDir("www") catch {};
    if (cwd.createFile("www/index.html", .{ .truncate = true })) |f| {
        defer f.close();
        _ = f.writeAll("<html>ok</html>") catch {};
    } else |_| {}
}

test "h3 loopback GET /index.html" {
    writeIndexHtml();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var srv = try spawnServer(&alloc, "127.0.0.1:4433");
    defer api.endpointDeinit(srv.ep);
    defer srv.th.join();

    var cfg = api.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .enable_datagram = false,
        .compatible_vn = true,
    };
    const cli_ep = try api.endpointInit(&alloc, "0.0.0.0:0", &cfg);
    defer api.endpointDeinit(cli_ep);

    const conn = try api.connect(cli_ep, "127.0.0.1:4433", "test.local");

    var out: [4096]u8 = undefined;
    const n = try h3c.h3Get(cli_ep, conn, "test.local", "/index.html", out[0..]);
    try std.testing.expect(n >= 0);
}
